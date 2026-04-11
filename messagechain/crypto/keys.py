"""
Merkle tree of WOTS+ keypairs for multi-use quantum-resistant signatures.

A single WOTS+ key can only sign once safely. This module builds a Merkle tree
over many WOTS+ public keys, giving a single long-lived root public key that
supports up to 2^height signatures.
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO, MERKLE_TREE_HEIGHT, WOTS_KEY_CHAINS
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash

# Hash output size for SHA3-256, used for strict size validation on signatures.
_HASH_SIZE = 32


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
        """
        parts = []
        # WOTS+ signature chains (sorted order guaranteed by list)
        for s in self.wots_signature:
            parts.append(s)
        # Leaf index as big-endian 4 bytes
        parts.append(struct.pack(">I", self.leaf_index))
        # Auth path
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
        return cls(
            wots_signature=[bytes.fromhex(s) for s in data["wots_signature"]],
            leaf_index=data["leaf_index"],
            auth_path=[bytes.fromhex(h) for h in data["auth_path"]],
            wots_public_key=bytes.fromhex(data["wots_public_key"]),
            wots_public_seed=bytes.fromhex(data["wots_public_seed"]),
        )


class KeyPair:
    """
    Merkle tree of WOTS+ keypairs.

    The root hash is the long-lived public key. Each leaf is a one-time WOTS+ key.
    """

    def __init__(self, seed: bytes, height: int | None = None, start_leaf: int = 0):
        if height is None:
            import messagechain.config
            height = messagechain.config.MERKLE_TREE_HEIGHT
        self.height = height
        self.num_leaves = 2 ** height
        self._seed = seed
        self._next_leaf = start_leaf

        # Generate all WOTS+ keypairs and build the Merkle tree
        self._wots_keys = []  # (private_keys, public_key, public_seed) per leaf
        leaf_hashes = []

        for i in range(self.num_leaves):
            leaf_seed = _hash(seed + struct.pack(">Q", i))
            priv, pub, pub_seed = wots_keygen(leaf_seed)
            self._wots_keys.append((priv, pub, pub_seed))
            leaf_hashes.append(pub)

        # Build Merkle tree bottom-up
        # tree[0] = leaves, tree[height] = [root]
        self._tree = [leaf_hashes]
        current = leaf_hashes
        for level in range(height):
            next_level = []
            for j in range(0, len(current), 2):
                combined = _hash(current[j] + current[j + 1])
                next_level.append(combined)
            self._tree.append(next_level)
            current = next_level

        self.public_key = self._tree[height][0]

    @classmethod
    def generate(cls, seed: bytes, height: int | None = None, start_leaf: int = 0) -> "KeyPair":
        return cls(seed, height, start_leaf=start_leaf)

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

    def _auth_path(self, leaf_index: int) -> list[bytes]:
        """Get the Merkle authentication path for a leaf."""
        if leaf_index < 0 or leaf_index >= self.num_leaves:
            raise IndexError(f"leaf_index {leaf_index} out of range [0, {self.num_leaves})")
        path = []
        idx = leaf_index
        for level in range(self.height):
            sibling_idx = idx ^ 1  # flip last bit to get sibling
            path.append(self._tree[level][sibling_idx])
            idx >>= 1
        return path

    def sign(self, message_hash: bytes) -> Signature:
        """Sign using the next available WOTS+ leaf key."""
        if self._next_leaf >= self.num_leaves:
            raise RuntimeError("Key exhausted: all one-time keys have been used")

        leaf_idx = self._next_leaf
        self._next_leaf += 1

        priv_keys, pub_key, pub_seed = self._wots_keys[leaf_idx]
        wots_sig = wots_sign(message_hash, priv_keys, pub_seed)
        auth_path = self._auth_path(leaf_idx)

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
    # Determine the expected tree height from the root length and auth path length;
    # we derive it from root tree depth by the auth path size check below, and
    # clamp leaf_index to the corresponding tree size.
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
