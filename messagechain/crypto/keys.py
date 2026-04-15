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
import struct
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO, MERKLE_TREE_HEIGHT, WOTS_KEY_CHAINS
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash

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
    """A complete signature: WOTS+ sig + Merkle authentication path."""
    wots_signature: list[bytes]
    leaf_index: int
    auth_path: list[bytes]  # sibling hashes from leaf to root
    wots_public_key: bytes  # the leaf's WOTS+ public key
    wots_public_seed: bytes

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
        return b"".join(parts)

    def serialize(self) -> dict:
        return {
            "wots_signature": [s.hex() for s in self.wots_signature],
            "leaf_index": self.leaf_index,
            "auth_path": [h.hex() for h in self.auth_path],
            "wots_public_key": self.wots_public_key.hex(),
            "wots_public_seed": self.wots_public_seed.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "Signature":
        wots_sig = [bytes.fromhex(s) for s in data["wots_signature"]]
        leaf_index = data["leaf_index"]
        auth_path = [bytes.fromhex(h) for h in data["auth_path"]]
        pub_key = bytes.fromhex(data["wots_public_key"])
        pub_seed = bytes.fromhex(data["wots_public_seed"])

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
        wots_sig = wots_sign(message_hash, priv_keys, pub_seed)
        auth_path = _compute_auth_path(self._seed, self.height, leaf_idx)

        return Signature(
            wots_signature=wots_sig,
            leaf_index=leaf_idx,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
        )

    @property
    def remaining_signatures(self) -> int:
        return self.num_leaves - self._next_leaf


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
