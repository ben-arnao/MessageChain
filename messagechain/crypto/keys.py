"""
Merkle tree of WOTS+ keypairs for multi-use quantum-resistant signatures.

A single WOTS+ key can only sign once safely. This module builds a Merkle tree
over many WOTS+ public keys, giving a single long-lived root public key that
supports up to 2^height signatures.
"""

import hashlib
import struct
import json
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO, MERKLE_TREE_HEIGHT
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash


@dataclass
class Signature:
    """A complete signature: WOTS+ sig + Merkle authentication path."""
    wots_signature: list[bytes]
    leaf_index: int
    auth_path: list[bytes]  # sibling hashes from leaf to root
    wots_public_key: bytes  # the leaf's WOTS+ public key
    wots_public_seed: bytes

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

        Used when reconstructing a keypair (e.g., from biometrics) to avoid
        reusing one-time WOTS+ keys. The caller should set this based on
        the on-chain nonce or signature count.
        """
        if leaf_index > self.num_leaves:
            raise RuntimeError(f"Leaf index {leaf_index} exceeds tree capacity {self.num_leaves}")
        self._next_leaf = max(self._next_leaf, leaf_index)

    def _auth_path(self, leaf_index: int) -> list[bytes]:
        """Get the Merkle authentication path for a leaf."""
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

    1. Verify the WOTS+ signature against the leaf public key
    2. Verify the leaf public key is in the Merkle tree (via auth path)
    """
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

    return current == root_public_key
