"""Persistent cache of Merkle internal nodes for the WOTS+ keypair tree.

Without this cache, `_compute_auth_path` in keys.py re-derives 2^(height-1)
leaf public keys on every signature — ~1 billion SHA3-256 ops at height=20,
which is several minutes per block on a modest CPU.  That's lethal at
production block time (600 s) with a real attester workload.

The cache memoizes every internal Merkle node (including the leaf hashes)
so an auth path is `height` slice reads (microseconds).  The cache is a
pure function of `(seed, height)`, so it never needs invalidation — once
built it is read-only.

On-chain formats are unchanged: the tree root (= public key) and the
signature bytes are byte-for-byte identical with or without the cache.
Disk blobs are HMAC-SHA3-256 authenticated with a key derived from the
WOTS+ seed, so a tampered cache file cannot silently direct the signer
to a wrong auth path.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional

from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import _derive_leaf_pubkey


_MAGIC = b"MCMT"
_FORMAT_VERSION = 1
_HMAC_SIZE = 32
_NODE_SIZE = 32

# Domain separator distinct from the keypair-cache MAC domain in server.py
# so the two MACs cannot be cross-replayed.
_MAC_DOMAIN = b"messagechain-merkle-cache-v1|"


def _mac_key(private_key: bytes) -> bytes:
    return hashlib.sha3_256(_MAC_DOMAIN + private_key).digest()


class MerkleNodeCache:
    """In-memory cache of every node of a WOTS+ Merkle tree.

    Internal layout is a flat bytearray using a heap-array index:

        root                                at  index 0                 level = height
        level-(height-1) pair               at  indices 1..2            level = height-1
        ...
        leaves                              at  indices (num_leaves-1) ..
                                                (2*num_leaves-2)        level = 0

    Total slots = 2*num_leaves - 1; each slot is 32 bytes.  At height=20
    that is 67,108,832 bytes (~64 MiB) — acceptable for a validator.
    """

    __slots__ = ("height", "num_leaves", "_blob")

    def __init__(self, height: int, blob: Optional[bytearray] = None):
        if height < 1 or height > 24:
            # 24 is a soft cap: 2^25 slots = 1 GB which is more than any
            # validator should be allocating to a local cache.  Raise loudly
            # instead of OOMing.
            raise ValueError(f"height out of range: {height}")
        self.height = height
        self.num_leaves = 1 << height
        total_slots = 2 * self.num_leaves - 1
        if blob is None:
            self._blob = bytearray(total_slots * _NODE_SIZE)
        else:
            if len(blob) != total_slots * _NODE_SIZE:
                raise ValueError(
                    f"blob size mismatch: got {len(blob)}, "
                    f"expected {total_slots * _NODE_SIZE}"
                )
            self._blob = blob

    # ── Flat-index helpers ───────────────────────────────────────────

    def _flat_index(self, level: int, node_index: int) -> int:
        """level=0 → leaves (num_leaves entries);
        level=height → root (1 entry).
        """
        if level < 0 or level > self.height:
            raise IndexError(f"level {level} out of range")
        level_count = self.num_leaves >> level
        if node_index < 0 or node_index >= level_count:
            raise IndexError(f"node_index {node_index} out of range at level {level}")
        # Heap layout: level-height (root) at flat 0, level-(height-1) at 1..2, ...
        # Total nodes ABOVE this level = 1 + 2 + ... + 2^(height-level-1)
        #                              = 2^(height-level) - 1
        # Flat offset of this level's first node = (2^(height-level)) - 1
        level_start = (1 << (self.height - level)) - 1
        return level_start + node_index

    def get(self, level: int, node_index: int) -> bytes:
        idx = self._flat_index(level, node_index)
        start = idx * _NODE_SIZE
        return bytes(self._blob[start:start + _NODE_SIZE])

    def set(self, level: int, node_index: int, value: bytes) -> None:
        if len(value) != _NODE_SIZE:
            raise ValueError(f"node value must be {_NODE_SIZE} bytes")
        idx = self._flat_index(level, node_index)
        start = idx * _NODE_SIZE
        self._blob[start:start + _NODE_SIZE] = value

    # ── Public API ───────────────────────────────────────────────────

    def root(self) -> bytes:
        return self.get(self.height, 0)

    def auth_path(self, leaf_index: int) -> list[bytes]:
        """Sibling-at-each-level from the leaf up to (but not including)
        the root.  Returns exactly `self.height` 32-byte hashes.
        """
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError(f"leaf_index {leaf_index} out of range")
        path: list[bytes] = []
        idx = leaf_index
        for level in range(self.height):
            sibling = idx ^ 1
            path.append(self.get(level, sibling))
            idx >>= 1
        return path

    @classmethod
    def build_from_seed(
        cls,
        seed: bytes,
        height: int,
        progress=None,
    ) -> "MerkleNodeCache":
        """Derive every leaf public key and every internal node.

        Single-pass: leaves first (each is O(~1000 hashes) via
        wots_keygen), then internal nodes pairwise upward.  Uses the
        same `_derive_leaf_pubkey` and `_hash(left + right)` as the
        reference code in keys.py, so the resulting root is byte-
        identical to what `_subtree_root` would produce.
        """
        cache = cls(height)
        num_leaves = 1 << height

        # Level 0: leaves
        for i in range(num_leaves):
            pk = _derive_leaf_pubkey(seed, i)
            cache.set(0, i, pk)
            if progress is not None:
                progress(i)

        # Levels 1..height: pairwise hashing
        for level in range(1, height + 1):
            count = num_leaves >> level
            for i in range(count):
                left = cache.get(level - 1, 2 * i)
                right = cache.get(level - 1, 2 * i + 1)
                cache.set(level, i, _hash(left + right))

        return cache

    # ── Disk format ──────────────────────────────────────────────────
    #
    # Layout:
    #   [4 B magic "MCMT"] [1 B version] [1 B height] [2 B reserved=0]
    #   [32 B HMAC-SHA3-256 over (magic || version || height || reserved || blob)]
    #   [ node blob ]

    def to_bytes(self, private_key: bytes) -> bytes:
        header = _MAGIC + bytes([_FORMAT_VERSION, self.height, 0, 0])
        mac = hmac.new(
            _mac_key(private_key),
            header + bytes(self._blob),
            hashlib.sha3_256,
        ).digest()
        return header + mac + bytes(self._blob)

    @classmethod
    def from_bytes(
        cls, data: bytes, private_key: bytes, expected_height: int,
    ) -> Optional["MerkleNodeCache"]:
        """Return a cache on success, None on any authentication or
        decoding failure.  Every rejection path returns None silently:
        the caller deletes the blob and regenerates.  No partial or
        differential information leaks from the loader.
        """
        header_len = len(_MAGIC) + 4
        min_len = header_len + _HMAC_SIZE
        if len(data) < min_len:
            return None
        if not data.startswith(_MAGIC):
            return None
        version = data[4]
        height = data[5]
        if version != _FORMAT_VERSION:
            return None
        if height != expected_height:
            return None
        header = data[:header_len]
        mac_stored = data[header_len:header_len + _HMAC_SIZE]
        blob = data[header_len + _HMAC_SIZE:]
        expected_total = (2 * (1 << height) - 1) * _NODE_SIZE
        if len(blob) != expected_total:
            return None
        mac_expected = hmac.new(
            _mac_key(private_key),
            header + blob,
            hashlib.sha3_256,
        ).digest()
        if not hmac.compare_digest(mac_stored, mac_expected):
            return None
        try:
            return cls(height, bytearray(blob))
        except ValueError:
            return None
