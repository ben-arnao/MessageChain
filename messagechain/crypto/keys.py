"""
Merkle tree of WOTS+ keypairs for multi-use quantum-resistant signatures.

A single WOTS+ key can only sign once safely. This module builds a Merkle tree
over many WOTS+ public keys, giving a single long-lived root public key that
supports up to 2^height signatures.

Key generation is lazy: leaf keypairs are derived on demand from a seed,
so even large trees (height=40 → ~1 trillion signatures) have near-instant
creation time and constant memory overhead.
"""

import hashlib
import hmac
import json
import logging
import os
import struct
from dataclasses import dataclass, field
from messagechain.config import (
    HASH_ALGO, MERKLE_TREE_HEIGHT, WOTS_KEY_CHAINS,
    SIG_VERSION_CURRENT, validate_sig_version,
)
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash

logger = logging.getLogger(__name__)

# WOTS+ leaf-usage thresholds (percent of capacity) at which sign() emits
# an operator-visible WARNING.  The footgun these guard against: a
# wallet or validator that never submits a KeyRotationTransaction will
# silently brick its funds the instant leaf #(num_leaves) is requested.
# 80% is the "plan a rotation" line; 95% is "do it TODAY".
_SIG_WARN_PERCENTS = (80, 95)

# Tracks which (keypair_root, threshold_pct) pairs have already emitted
# a warning in this process run.  Module-level so the dedup survives
# across sign() calls, but deliberately keyed on the Merkle root so two
# different keypairs warn independently — a rotated key does NOT inherit
# the pre-rotation silence, and two validators on the same host do not
# cross-suppress each other.  Cleared only on process restart.
_warned_thresholds: set[tuple[bytes, int]] = set()

# Hash output size for SHA3-256, used for strict size validation on signatures.
_HASH_SIZE = 32

# Upper bound on the Merkle auth_path length a deserialized Signature
# may carry.  Every extra element costs a hash op in verify_signature, so
# an unbounded path is a trivial DoS.  64 covers 2^64 leaves per key —
# well beyond any sane MERKLE_TREE_HEIGHT (current prod = 20) and still
# small enough that the verify loop stays cheap on adversarial input.
MAX_AUTH_PATH_LEN = 64


@dataclass
class Signature:
    """A complete signature: WOTS+ sig + Merkle authentication path.

    `sig_version` is a crypto-agility register: carried on every signature,
    committed into the signable_data of every transaction, and rejected by
    validators when it doesn't match SIG_VERSION_CURRENT. See config.py
    (`SIG_VERSION_*`, `validate_sig_version`) for the migration design.
    """
    wots_signature: list[bytes]
    leaf_index: int
    auth_path: list[bytes]  # sibling hashes from leaf to root
    wots_public_key: bytes  # the leaf's WOTS+ public key
    wots_public_seed: bytes
    sig_version: int = SIG_VERSION_CURRENT

    def canonical_bytes(self) -> bytes:
        """Canonical byte representation of the signature.

        Deterministic serialization used for witness_hash computation
        and relay-level deduplication. Prevents malleability from
        non-canonical encodings of the same signature.

        M23: Includes length prefixes for variable-length lists to prevent
        ambiguous concatenation between different element counts.
        """
        parts = []
        # M23: Length prefix for WOTS+ signature list
        parts.append(struct.pack(">I", len(self.wots_signature)))
        for s in self.wots_signature:
            parts.append(s)
        # Leaf index as big-endian 4 bytes
        parts.append(struct.pack(">I", self.leaf_index))
        # M23: Length prefix for auth path list
        parts.append(struct.pack(">I", len(self.auth_path)))
        for h in self.auth_path:
            parts.append(h)
        # Public key and seed
        parts.append(self.wots_public_key)
        parts.append(self.wots_public_seed)
        # Crypto-agility: sig_version trails the existing fields so the
        # canonical form is a superset of the pre-migration bytes.  The
        # witness_hash therefore commits to the signer's chosen scheme.
        parts.append(struct.pack(">B", self.sig_version))
        return b"".join(parts)

    def serialize(self) -> dict:
        return {
            "wots_signature": [s.hex() for s in self.wots_signature],
            "leaf_index": self.leaf_index,
            "auth_path": [h.hex() for h in self.auth_path],
            "wots_public_key": self.wots_public_key.hex(),
            "wots_public_seed": self.wots_public_seed.hex(),
            "sig_version": self.sig_version,
        }

    def to_bytes(self) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (all unsigned big-endian):
            u16  wots_chain_count
            N x  32-byte chain hashes  (where N = wots_chain_count)
            u32  leaf_index
            u8   auth_path_len
            M x  32-byte path hashes   (where M = auth_path_len)
            32   wots_public_key
            32   wots_public_seed
            u8   sig_version             <- crypto-agility register

        Every variable-length section is length-prefixed to prevent
        ambiguous concatenation (same defense as canonical_bytes uses).
        Hash elements are fixed-size (SHA3-256 = 32 bytes) so we encode
        only the count, not each element's length.

        sig_version is appended after the pre-migration fields so the
        blob is a strict extension: a pre-migration parser would fail
        fast on the trailing byte rather than mis-decode into a valid-
        looking sig.  (That is what we want — silently accepting a
        pre-migration blob as a post-migration signature would let an
        attacker forge a sig_version of their choosing via truncation.)
        """
        # Placeholder / witness-stripped sentinel: empty signature encodes
        # as zero bytes.  from_bytes(b"") decodes back to the placeholder.
        # This enables stripped transactions to round-trip through binary
        # serialization without carrying witness data.
        if not self.wots_signature and not self.wots_public_key:
            return b""
        parts = [struct.pack(">H", len(self.wots_signature))]
        parts.extend(self.wots_signature)
        parts.append(struct.pack(">I", self.leaf_index))
        parts.append(struct.pack(">B", len(self.auth_path)))
        parts.extend(self.auth_path)
        parts.append(self.wots_public_key)
        parts.append(self.wots_public_seed)
        parts.append(struct.pack(">B", self.sig_version))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Signature":
        """Decode a Signature from its compact binary form.

        Matches the structural validation in deserialize(dict): all size
        checks happen here before any hash work runs, so malformed blobs
        cannot burn CPU on wots_verify.
        """
        # Placeholder-signature carve-out: empty blob decodes to the
        # placeholder used during transaction construction (see
        # `Signature([], 0, [], b"", b"")`).  Only relevant for in-memory
        # round-trips that embed unsigned placeholders; stored blocks
        # always carry a real signature.
        if len(data) == 0:
            return cls([], 0, [], b"", b"")

        offset = 0
        if len(data) < 2:
            raise ValueError("Signature blob too short for chain count")
        chain_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if chain_count != WOTS_KEY_CHAINS:
            raise ValueError(
                f"WOTS signature must have exactly {WOTS_KEY_CHAINS} chains, "
                f"got {chain_count}"
            )
        wots_sig = []
        for _ in range(chain_count):
            if offset + _HASH_SIZE > len(data):
                raise ValueError("Signature blob truncated in wots chains")
            wots_sig.append(bytes(data[offset:offset + _HASH_SIZE]))
            offset += _HASH_SIZE

        if offset + 4 > len(data):
            raise ValueError("Signature blob truncated at leaf_index")
        leaf_index = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        if offset + 1 > len(data):
            raise ValueError("Signature blob truncated at auth_path length")
        auth_len = struct.unpack_from(">B", data, offset)[0]
        offset += 1
        if auth_len > MAX_AUTH_PATH_LEN:
            raise ValueError(
                f"Auth path too long: {auth_len} > {MAX_AUTH_PATH_LEN}"
            )
        auth_path = []
        for _ in range(auth_len):
            if offset + _HASH_SIZE > len(data):
                raise ValueError("Signature blob truncated in auth_path")
            auth_path.append(bytes(data[offset:offset + _HASH_SIZE]))
            offset += _HASH_SIZE

        if offset + _HASH_SIZE > len(data):
            raise ValueError("Signature blob truncated at wots_public_key")
        pub_key = bytes(data[offset:offset + _HASH_SIZE])
        offset += _HASH_SIZE

        if offset + _HASH_SIZE > len(data):
            raise ValueError("Signature blob truncated at wots_public_seed")
        pub_seed = bytes(data[offset:offset + _HASH_SIZE])
        offset += _HASH_SIZE

        # Crypto-agility register: reject unknown versions at decode time so
        # malformed or future-version blobs never reach wots_verify.  A
        # missing byte here is a truncation; a non-current value is either
        # a byte flip in transit or a too-new peer — either way, not ours.
        if offset + 1 > len(data):
            raise ValueError("Signature blob truncated at sig_version")
        sig_version = struct.unpack_from(">B", data, offset)[0]
        offset += 1
        ok, reason = validate_sig_version(sig_version)
        if not ok:
            raise ValueError(f"Invalid signature: {reason}")

        # leaf_index must be a valid index into a tree of height = auth_len.
        max_leaf_index = (1 << auth_len) - 1 if auth_len > 0 else 0
        if leaf_index > max_leaf_index:
            raise ValueError(
                f"leaf_index {leaf_index} outside tree coverage "
                f"(auth_path len {auth_len} → max index {max_leaf_index})"
            )

        return cls(
            wots_signature=wots_sig,
            leaf_index=leaf_index,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
            sig_version=sig_version,
        )

    @classmethod
    def deserialize(cls, data: dict) -> "Signature":
        wots_sig = [bytes.fromhex(s) for s in data["wots_signature"]]
        leaf_index = data["leaf_index"]
        auth_path = [bytes.fromhex(h) for h in data["auth_path"]]
        pub_key = bytes.fromhex(data["wots_public_key"])
        pub_seed = bytes.fromhex(data["wots_public_seed"])
        # Crypto-agility: default to SIG_VERSION_CURRENT when the field is
        # absent so pre-migration dicts (mempool dumps, test fixtures) load
        # cleanly.  A PRESENT-but-unknown value is a clear error and rejected.
        sig_version = data.get("sig_version", SIG_VERSION_CURRENT)
        ok, reason = validate_sig_version(sig_version)
        if not ok:
            raise ValueError(f"Invalid signature: {reason}")

        # M4: Structural validation on deserialization.  Every check here
        # runs BEFORE verify_signature sees the input, so malformed blobs
        # never reach the hash-heavy verify path — a cheap DoS guard.
        if not isinstance(leaf_index, int) or leaf_index < 0:
            raise ValueError(f"Invalid leaf_index: {leaf_index}")
        # WOTS+ signatures always carry exactly WOTS_KEY_CHAINS chains.
        # Anything else cannot be a valid signature under this scheme —
        # rejecting here prevents wasted hashing in wots_verify.
        if len(wots_sig) != WOTS_KEY_CHAINS:
            raise ValueError(
                f"WOTS signature must have exactly {WOTS_KEY_CHAINS} chains, "
                f"got {len(wots_sig)}"
            )
        for i, s in enumerate(wots_sig):
            if len(s) != _HASH_SIZE:
                raise ValueError(f"WOTS signature element {i} has wrong size: {len(s)}")
        # auth_path length is unbounded by the wire format — cap it before
        # verify runs a rehash-per-level loop on adversarial input.
        if len(auth_path) > MAX_AUTH_PATH_LEN:
            raise ValueError(
                f"Auth path too long: {len(auth_path)} > {MAX_AUTH_PATH_LEN}"
            )
        for i, h in enumerate(auth_path):
            if len(h) != _HASH_SIZE:
                raise ValueError(f"Auth path element {i} has wrong size: {len(h)}")
        # A path of length N addresses exactly 2^N leaves; any leaf_index
        # outside that range cannot point at a real position in the tree.
        max_leaf_index = (1 << len(auth_path)) - 1
        if leaf_index > max_leaf_index:
            raise ValueError(
                f"leaf_index {leaf_index} outside tree coverage "
                f"(auth_path len {len(auth_path)} → max index {max_leaf_index})"
            )
        if len(pub_key) != _HASH_SIZE:
            raise ValueError(f"Public key has wrong size: {len(pub_key)}")
        if len(pub_seed) != _HASH_SIZE:
            raise ValueError(f"Public seed has wrong size: {len(pub_seed)}")

        return cls(
            wots_signature=wots_sig,
            leaf_index=leaf_index,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
            sig_version=sig_version,
        )


def _derive_leaf(seed: bytes, leaf_index: int) -> tuple[list[bytes], bytes, bytes]:
    """Derive a full WOTS+ keypair (private + public) for a single leaf."""
    leaf_seed = _hash(seed + struct.pack(">Q", leaf_index))
    return wots_keygen(leaf_seed)


def _derive_leaf_pubkey(seed: bytes, leaf_index: int) -> bytes:
    """Derive just the WOTS+ public key for a leaf (discards private keys)."""
    _, pub, _ = _derive_leaf(seed, leaf_index)
    return pub


def _subtree_root(seed: bytes, start: int, count: int, progress=None) -> bytes:
    """Compute the Merkle root hash over a contiguous range of leaves.

    If `progress` is provided, it is called after each leaf derivation
    with the leaf index that just completed. The callback is expected to
    do its own throttling.
    """
    if count == 1:
        pk = _derive_leaf_pubkey(seed, start)
        if progress is not None:
            progress(start)
        return pk
    half = count >> 1
    left = _subtree_root(seed, start, half, progress)
    right = _subtree_root(seed, start + half, half, progress)
    return _hash(left + right)


def _compute_auth_path(seed: bytes, height: int, leaf_index: int) -> list[bytes]:
    """Compute the Merkle authentication path for a leaf on demand.

    For each tree level, computes the sibling subtree root. This is
    O(2^height) work total but requires no stored tree — all hashes
    are recomputed from the seed.
    """
    path = []
    for level in range(height):
        # At this level, blocks are 2^(level+1) leaves wide
        block_size = 1 << (level + 1)
        half = block_size >> 1
        block_start = (leaf_index >> (level + 1)) << (level + 1)

        if (leaf_index >> level) & 1 == 0:
            # We're on the left; sibling is the right half
            sibling_start = block_start + half
        else:
            # We're on the right; sibling is the left half
            sibling_start = block_start

        path.append(_subtree_root(seed, sibling_start, half))
    return path


class KeyPair:
    """
    Merkle tree of WOTS+ keypairs with lazy leaf derivation.

    The root hash is the long-lived public key. Each leaf is a one-time WOTS+
    key derived on demand from the seed. No private keys or tree nodes are
    stored persistently, so large trees (height=40) use constant memory.
    """

    def __init__(
        self,
        seed: bytes,
        height: int | None = None,
        start_leaf: int = 0,
        progress=None,
    ):
        if height is None:
            import messagechain.config
            height = messagechain.config.MERKLE_TREE_HEIGHT
        self.height = height
        self.num_leaves = 1 << height
        self._seed = seed
        self._next_leaf = start_leaf

        # Optional path for persistent leaf-index tracking.  When set,
        # sign() writes the updated _next_leaf to this file BEFORE
        # returning the signature (write-ahead), preventing WOTS+ leaf
        # reuse after a process restart.
        self.leaf_index_path: str | None = None

        # Compute the Merkle root (the public key) by building the tree
        # bottom-up over derived leaf public keys. This is the only expensive
        # operation — O(2^height) leaf derivations, done once at creation.
        # No private keys or intermediate tree nodes are retained.
        #
        # `progress`, if provided, is called with the leaf index each time a
        # leaf is derived. Long-running keygen (height >= 20) can show a
        # status indicator without the caller needing to know tree internals.
        self.public_key = _subtree_root(seed, 0, self.num_leaves, progress)

    @classmethod
    def generate(
        cls,
        seed: bytes,
        height: int | None = None,
        start_leaf: int = 0,
        progress=None,
    ) -> "KeyPair":
        return cls(seed, height, start_leaf=start_leaf, progress=progress)

    @classmethod
    def _from_trusted_root(
        cls,
        seed: bytes,
        height: int,
        public_key: bytes,
        start_leaf: int = 0,
    ) -> "KeyPair":
        """Construct a KeyPair with a pre-computed Merkle root.

        Skips the O(2^height) leaf derivation that __init__ performs —
        the caller supplies a previously-computed public_key from
        trusted storage (e.g. an HMAC-authenticated cache file).

        The root is NOT re-derived, so the caller is responsible for
        making sure the supplied public_key actually corresponds to
        `seed` and `height`.  Passing a forged root produces a signer
        whose signatures will never verify against the claimed root —
        a local DoS, not a forgery vector — but callers must still
        authenticate the source before taking this path.
        """
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes (SHA3-256 output)")
        if height <= 0:
            raise ValueError(f"height must be positive, got {height}")
        kp = cls.__new__(cls)
        kp.height = height
        kp.num_leaves = 1 << height
        kp._seed = seed
        kp._next_leaf = start_leaf
        kp.leaf_index_path = None
        kp.public_key = bytes(public_key)
        return kp

    def advance_to_leaf(self, leaf_index: int):
        """Advance the next-leaf pointer to skip already-used leaves.

        Used when reconstructing a keypair (e.g., from private key) to avoid
        reusing one-time WOTS+ keys. The caller should set this based on
        the on-chain nonce or signature count.

        Valid leaf indices are [0, num_leaves). A value equal to or greater
        than num_leaves is invalid — WOTS+ keys are one-time, and allowing
        leaf_index == num_leaves would permit a subsequent out-of-bounds
        access in sign() or wrap-around key reuse.
        """
        if leaf_index < 0:
            raise RuntimeError(f"Leaf index {leaf_index} must be non-negative")
        if leaf_index >= self.num_leaves:
            raise RuntimeError(f"Leaf index {leaf_index} exceeds tree capacity {self.num_leaves}")
        self._next_leaf = max(self._next_leaf, leaf_index)

    def sign(self, message_hash: bytes) -> Signature:
        """Sign using the next available WOTS+ leaf key (derived on demand)."""
        if self._next_leaf >= self.num_leaves:
            raise RuntimeError("Key exhausted: all one-time keys have been used")

        leaf_idx = self._next_leaf
        self._next_leaf += 1

        # Derive the leaf keypair on demand — no private keys stored
        priv_keys, pub_key, pub_seed = _derive_leaf(self._seed, leaf_idx)
        try:
            wots_sig = wots_sign(message_hash, priv_keys, pub_seed)
            auth_path = _compute_auth_path(self._seed, self.height, leaf_idx)
        finally:
            # Best-effort private key zeroing.  priv_keys are bytearray
            # (mutable), so we can overwrite the buffer contents in-place.
            # This limits the window in which key material sits in memory.
            for pk in priv_keys:
                if isinstance(pk, bytearray):
                    for j in range(len(pk)):
                        pk[j] = 0

        # Write-ahead persistence: commit the new _next_leaf to disk
        # BEFORE returning the signature, so a crash after signing but
        # before the caller processes the result cannot cause leaf reuse.
        if self.leaf_index_path is not None:
            self.persist_leaf_index(self.leaf_index_path)

        # Exhaustion-visibility warnings.  Emit at 80% and 95% usage so
        # operators notice in their normal log pipeline long before the
        # hard wall at 100% (after which funds are locked unless the
        # user previously submitted a KeyRotationTransaction).  Deduped
        # per (root, threshold) to avoid flooding logs on every slot.
        self._maybe_warn_exhaustion()

        return Signature(
            wots_signature=wots_sig,
            leaf_index=leaf_idx,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
        )

    def _maybe_warn_exhaustion(self) -> None:
        """Emit a WARNING log when leaf usage first crosses 80% and 95%.

        Called from sign() after _next_leaf has been incremented so the
        percentage reflects the signature just produced.  Uses integer
        math to avoid float drift at very large num_leaves (production
        is 2^20 = 1,048,576 and we must not miss the threshold due to
        rounding).
        """
        # Scale by 100 for integer comparison: used_pct_x100 is
        # (used * 100) // num_leaves, which is exact for all finite
        # tree heights we support.
        used = self._next_leaf
        total = self.num_leaves
        if total <= 0:
            return
        used_pct = (used * 100) // total
        for threshold in _SIG_WARN_PERCENTS:
            if used_pct < threshold:
                continue
            key = (bytes(self.public_key), threshold)
            if key in _warned_thresholds:
                continue
            _warned_thresholds.add(key)
            remaining = total - used
            logger.warning(
                "WOTS+ one-time signatures at %d%% capacity "
                "(%d used / %d total, %d remaining) for key %s. "
                "Run `messagechain rotate-key` before exhaustion — "
                "past 100%% the key is bricked and funds lock until "
                "a previously-signed KeyRotationTransaction is submitted.",
                threshold,
                used,
                total,
                remaining,
                self.public_key.hex()[:16],
            )

    @property
    def remaining_signatures(self) -> int:
        return self.num_leaves - self._next_leaf

    def persist_leaf_index(self, path: str) -> None:
        """Write the current _next_leaf to disk (atomic via tmp + rename).

        The file is a small JSON object so it is human-inspectable and
        trivially portable across platforms.
        """
        # Symlink traversal guard: refuse to write through symlinks.
        real_path = os.path.realpath(path)
        if real_path != os.path.abspath(path):
            raise ValueError(f"Refusing to write through symlink: {path}")

        data = {"next_leaf": self._next_leaf}
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        # Atomic rename — on POSIX this is guaranteed atomic; on Windows
        # os.replace is as close as we get.
        os.replace(tmp_path, path)

    def load_leaf_index(self, path: str) -> None:
        """Restore _next_leaf from a previously-persisted file.

        If the file does not exist, _next_leaf is left unchanged (safe
        default: a fresh KeyPair starts at 0).

        The loaded value is never allowed to move _next_leaf backwards —
        this prevents a stale backup from causing WOTS+ leaf reuse.
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return  # no file or corrupt — use current _next_leaf
        stored = data.get("next_leaf", 0)
        if not isinstance(stored, int) or stored < 0:
            return  # ignore corrupt data
        if stored >= self.num_leaves:
            raise ValueError(
                f"Corrupted leaf index file: next_leaf={stored} >= num_leaves={self.num_leaves}"
            )
        if stored > self._next_leaf:
            self._next_leaf = stored


def verify_signature(message_hash: bytes, signature: Signature, root_public_key: bytes) -> bool:
    """
    Verify a signature against a Merkle-tree root public key.

    1. Structural validation of the signature (sizes, counts, ranges)
    2. Verify the WOTS+ signature against the leaf public key
    3. Verify the leaf public key is in the Merkle tree (via auth path)

    Returns False on any structural defect or verification failure. Never
    raises on malformed input — all rejection is via False return.
    """
    # Step 0: Structural validation. A malformed signature must be rejected
    # cleanly rather than producing an IndexError or allowing truncated
    # authentication paths to compute a spurious root.
    if not isinstance(root_public_key, (bytes, bytearray)) or len(root_public_key) != _HASH_SIZE:
        return False
    if not isinstance(message_hash, (bytes, bytearray)) or len(message_hash) != _HASH_SIZE:
        return False
    if not isinstance(signature, Signature):
        return False
    if len(signature.wots_signature) != WOTS_KEY_CHAINS:
        return False
    for part in signature.wots_signature:
        if not isinstance(part, (bytes, bytearray)) or len(part) != _HASH_SIZE:
            return False
    if not isinstance(signature.wots_public_key, (bytes, bytearray)) or len(signature.wots_public_key) != _HASH_SIZE:
        return False
    if not isinstance(signature.wots_public_seed, (bytes, bytearray)) or len(signature.wots_public_seed) != _HASH_SIZE:
        return False
    tree_height = len(signature.auth_path)
    if tree_height <= 0 or tree_height > 64:
        return False
    for sibling in signature.auth_path:
        if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != _HASH_SIZE:
            return False
    if not isinstance(signature.leaf_index, int):
        return False
    num_leaves = 1 << tree_height
    if signature.leaf_index < 0 or signature.leaf_index >= num_leaves:
        return False

    # Step 1: Verify WOTS+ signature
    if not wots_verify(message_hash, signature.wots_signature,
                       signature.wots_public_key, signature.wots_public_seed):
        return False

    # Step 2: Verify Merkle path from leaf to root
    current = signature.wots_public_key
    idx = signature.leaf_index
    for sibling in signature.auth_path:
        if idx & 1 == 0:
            current = _hash(current + sibling)
        else:
            current = _hash(sibling + current)
        idx >>= 1

    # Constant-time comparison to avoid timing side-channels.
    return hmac.compare_digest(current, root_public_key)
