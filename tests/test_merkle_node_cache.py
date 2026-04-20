"""Regression tests for messagechain.crypto.merkle_cache.MerkleNodeCache.

The cache is the O(log n) replacement for _compute_auth_path's O(2^h)
per-signature recomputation.  Correctness is critical: a wrong auth path
produces a signature that fails verification against the on-chain root,
silently bricking the validator.  These tests pin:

1. The cache's tree root matches _subtree_root (the reference).
2. Signatures produced via the cache match signatures produced via the
   reference, byte-for-byte (auth_path + Signature.to_bytes).
3. Cached signatures verify against the root for every leaf index.
4. HMAC authentication: any tamper → load fails.
5. Wrong-key rejection: cache built for key A can't load under key B.
6. Height mismatch: cache blob for height X rejected when expected Y.
7. Round-trip: to_bytes → from_bytes returns an equivalent cache.
"""

from __future__ import annotations

import os
import unittest

from messagechain.crypto.keys import (
    KeyPair, _subtree_root, _compute_auth_path, verify_signature,
)
from messagechain.crypto.merkle_cache import MerkleNodeCache


# Use a tiny height (h=5 = 32 leaves) so exhaustive tests are fast.
# h=5 still exercises every level of the tree (including non-leaf internal
# nodes across 5 layers) so flat-index and off-by-one bugs remain caught;
# dropping from h=6 shaves ~4× off the reference O(2^h)-per-leaf walk and
# was the critical-path test in the parallel suite.
_H = 5
_SEED = b"\xa7" * 32


class TestRootEquivalence(unittest.TestCase):
    def test_cache_root_matches_subtree_root(self):
        cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        ref_root = _subtree_root(_SEED, 0, 1 << _H)
        self.assertEqual(cache.root(), ref_root)

    def test_cache_root_matches_keypair_public_key(self):
        cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        kp = KeyPair(_SEED, height=_H)
        self.assertEqual(cache.root(), kp.public_key)


class TestAuthPathEquivalence(unittest.TestCase):
    """Exhaustively assert auth_path equality vs reference for every leaf
    at h=6.  This catches off-by-one and flat-index bugs."""

    def test_every_leaf_auth_path_matches_reference(self):
        cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        for leaf_idx in range(1 << _H):
            cached = cache.auth_path(leaf_idx)
            reference = _compute_auth_path(_SEED, _H, leaf_idx)
            self.assertEqual(
                cached, reference,
                f"auth_path mismatch at leaf {leaf_idx}",
            )


class TestSignVerifyViaCache(unittest.TestCase):
    """End-to-end: sign with the cache, verify against the root."""

    def test_signatures_via_cache_verify(self):
        cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        kp_cached = KeyPair(_SEED, height=_H)
        kp_cached._node_cache = cache

        kp_ref = KeyPair(_SEED, height=_H)
        for i in range(8):  # a handful of sequential leaves
            msg_hash = (b"msg_" + i.to_bytes(4, "big")) * 4
            msg_hash = msg_hash[:32]
            sig_cached = kp_cached.sign(msg_hash)
            sig_ref = kp_ref.sign(msg_hash)
            # The two keypairs should produce identical signatures.
            self.assertEqual(
                sig_cached.auth_path, sig_ref.auth_path,
                "cached and reference auth_paths diverged",
            )
            self.assertEqual(sig_cached.leaf_index, sig_ref.leaf_index)
            # And both verify under the same root.
            self.assertTrue(verify_signature(msg_hash, sig_cached, kp_cached.public_key))
            self.assertTrue(verify_signature(msg_hash, sig_ref, kp_ref.public_key))


class TestHMACAuthentication(unittest.TestCase):
    def setUp(self):
        self.cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        self.blob = self.cache.to_bytes(_SEED)

    def test_round_trip(self):
        reloaded = MerkleNodeCache.from_bytes(self.blob, _SEED, _H)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.root(), self.cache.root())
        for i in range(1 << _H):
            self.assertEqual(reloaded.auth_path(i), self.cache.auth_path(i))

    def test_tampered_node_blob_rejected(self):
        tampered = bytearray(self.blob)
        # Flip one bit in the node payload area.
        tampered[-1] ^= 0x01
        self.assertIsNone(
            MerkleNodeCache.from_bytes(bytes(tampered), _SEED, _H),
            "tampered node bytes must fail HMAC check",
        )

    def test_tampered_header_rejected(self):
        tampered = bytearray(self.blob)
        # Flip a bit in the version byte.
        tampered[4] ^= 0x01
        self.assertIsNone(
            MerkleNodeCache.from_bytes(bytes(tampered), _SEED, _H),
        )

    def test_truncated_blob_rejected(self):
        short = self.blob[:100]
        self.assertIsNone(
            MerkleNodeCache.from_bytes(short, _SEED, _H),
        )

    def test_wrong_key_rejected(self):
        wrong_key = b"\xbb" * 32
        self.assertIsNone(
            MerkleNodeCache.from_bytes(self.blob, wrong_key, _H),
            "blob signed with key A must not load under key B",
        )

    def test_height_mismatch_rejected(self):
        self.assertIsNone(
            MerkleNodeCache.from_bytes(self.blob, _SEED, _H + 1),
        )


class TestBuildFromSeedStructuralInvariants(unittest.TestCase):
    def test_number_of_leaves_matches_height(self):
        cache = MerkleNodeCache.build_from_seed(_SEED, _H)
        self.assertEqual(cache.num_leaves, 1 << _H)

    def test_get_set_inverse(self):
        cache = MerkleNodeCache(_H)
        value = b"\xde\xad\xbe\xef" * 8  # 32 bytes
        cache.set(2, 3, value)
        self.assertEqual(cache.get(2, 3), value)

    def test_out_of_range_raises(self):
        cache = MerkleNodeCache(_H)
        with self.assertRaises(IndexError):
            cache.auth_path(-1)
        with self.assertRaises(IndexError):
            cache.auth_path(1 << _H)
        with self.assertRaises(IndexError):
            cache.get(_H + 1, 0)


class TestHeightGuardrails(unittest.TestCase):
    def test_reject_zero_or_negative_height(self):
        with self.assertRaises(ValueError):
            MerkleNodeCache(0)
        with self.assertRaises(ValueError):
            MerkleNodeCache(-1)

    def test_reject_absurd_height(self):
        # Soft cap at 24 prevents a 1-GB allocation from a typo.
        with self.assertRaises(ValueError):
            MerkleNodeCache(25)


if __name__ == "__main__":
    unittest.main()
