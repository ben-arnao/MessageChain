"""Tests for lazy (on-demand) key generation.

The KeyPair class should derive WOTS+ leaf keypairs on demand from a seed
rather than generating them all upfront. This allows arbitrarily large trees
(height=40 → 1 trillion signatures) without memory or time cost at creation.

Covers:
- Determinism: same seed + same leaf index → same keys
- Correctness: signatures from lazy tree verify against the root public key
- Consistency: lazy tree produces the same root as the old eager tree (for small heights)
- Exhaustion boundary: signing past capacity raises RuntimeError
- Auth path correctness for various leaf indices
- On-demand derivation doesn't store all keys in memory
- advance_to_leaf still works correctly
- Multiple sequential signatures all verify
"""

import struct
import unittest

from messagechain.crypto.hash_sig import wots_keygen, _hash
from messagechain.crypto.keys import KeyPair, Signature, verify_signature


class TestLazyKeyGenDeterminism(unittest.TestCase):
    """Same seed and height must produce the same root public key."""

    def test_same_seed_same_root(self):
        seed = b"determinism-test-seed".ljust(32, b"\x00")
        kp1 = KeyPair(seed, height=4)
        kp2 = KeyPair(seed, height=4)
        self.assertEqual(kp1.public_key, kp2.public_key)

    def test_different_seeds_different_roots(self):
        kp1 = KeyPair(b"seed-a".ljust(32, b"\x00"), height=4)
        kp2 = KeyPair(b"seed-b".ljust(32, b"\x00"), height=4)
        self.assertNotEqual(kp1.public_key, kp2.public_key)


class TestLazyKeyGenSignVerify(unittest.TestCase):
    """Signatures from lazily-generated keys must verify correctly."""

    def setUp(self):
        self.seed = b"sign-verify-test".ljust(32, b"\x00")
        self.kp = KeyPair(self.seed, height=4)

    def test_first_signature_verifies(self):
        msg = _hash(b"hello world")
        sig = self.kp.sign(msg)
        self.assertTrue(verify_signature(msg, sig, self.kp.public_key))

    def test_multiple_sequential_signatures_verify(self):
        for i in range(5):
            msg = _hash(f"message-{i}".encode())
            sig = self.kp.sign(msg)
            self.assertTrue(
                verify_signature(msg, sig, self.kp.public_key),
                f"Signature {i} failed verification",
            )

    def test_all_leaves_sign_and_verify(self):
        """Every leaf in a small tree should produce a valid signature."""
        kp = KeyPair(b"all-leaves".ljust(32, b"\x00"), height=3)  # 8 leaves
        for i in range(8):
            msg = _hash(f"leaf-{i}".encode())
            sig = kp.sign(msg)
            self.assertTrue(verify_signature(msg, sig, kp.public_key))
            self.assertEqual(sig.leaf_index, i)

    def test_wrong_message_fails_verification(self):
        msg = _hash(b"correct message")
        sig = self.kp.sign(msg)
        wrong_msg = _hash(b"wrong message")
        self.assertFalse(verify_signature(wrong_msg, sig, self.kp.public_key))

    def test_wrong_root_fails_verification(self):
        msg = _hash(b"test message")
        sig = self.kp.sign(msg)
        wrong_root = b"\x00" * 32
        self.assertFalse(verify_signature(msg, sig, wrong_root))


class TestLazyKeyGenExhaustion(unittest.TestCase):
    """Exhaustion must be detected and raised cleanly."""

    def test_exhaustion_raises(self):
        kp = KeyPair(b"exhaust-test".ljust(32, b"\x00"), height=2)  # 4 leaves
        for _ in range(4):
            kp.sign(_hash(b"msg"))
        with self.assertRaises(RuntimeError):
            kp.sign(_hash(b"one too many"))

    def test_remaining_signatures_decrements(self):
        kp = KeyPair(b"remaining-test".ljust(32, b"\x00"), height=2)
        self.assertEqual(kp.remaining_signatures, 4)
        kp.sign(_hash(b"msg"))
        self.assertEqual(kp.remaining_signatures, 3)


class TestLazyKeyGenAdvanceLeaf(unittest.TestCase):
    """advance_to_leaf must work for skipping already-used leaves."""

    def test_advance_skips_leaves(self):
        kp = KeyPair(b"advance-test".ljust(32, b"\x00"), height=4)
        kp.advance_to_leaf(5)
        sig = kp.sign(_hash(b"after advance"))
        self.assertEqual(sig.leaf_index, 5)
        self.assertTrue(verify_signature(_hash(b"after advance"), sig, kp.public_key))

    def test_advance_past_capacity_raises(self):
        kp = KeyPair(b"advance-fail".ljust(32, b"\x00"), height=2)
        with self.assertRaises(RuntimeError):
            kp.advance_to_leaf(4)  # num_leaves=4, so index 4 is out of range

    def test_advance_negative_raises(self):
        kp = KeyPair(b"advance-neg".ljust(32, b"\x00"), height=2)
        with self.assertRaises(RuntimeError):
            kp.advance_to_leaf(-1)


class TestLazyKeyGenMemoryEfficiency(unittest.TestCase):
    """Lazy generation should not store private keys or tree nodes in memory."""

    def test_no_wots_keys_stored(self):
        """KeyPair must not retain a list of all leaf private keys."""
        kp = KeyPair(b"no-store-test".ljust(32, b"\x00"), height=4)
        self.assertFalse(hasattr(kp, '_wots_keys'),
                         "Lazy KeyPair should not store _wots_keys")

    def test_no_tree_stored(self):
        """KeyPair must not retain the full Merkle tree."""
        kp = KeyPair(b"no-tree-test".ljust(32, b"\x00"), height=4)
        self.assertFalse(hasattr(kp, '_tree'),
                         "Lazy KeyPair should not store _tree")


class TestLazyKeyGenConsistency(unittest.TestCase):
    """Lazy tree must produce the same root as computing it explicitly."""

    def test_root_matches_manual_computation(self):
        """Verify root matches a manually-computed Merkle tree for height=3."""
        seed = b"consistency-check".ljust(32, b"\x00")
        kp = KeyPair(seed, height=3)

        # Manually compute: generate all 8 leaf public keys, build tree
        leaf_pubs = []
        for i in range(8):
            leaf_seed = _hash(seed + struct.pack(">Q", i))
            _, pub, _ = wots_keygen(leaf_seed)
            leaf_pubs.append(pub)

        # Build Merkle tree bottom-up
        current = leaf_pubs
        for _ in range(3):
            next_level = []
            for j in range(0, len(current), 2):
                next_level.append(_hash(current[j] + current[j + 1]))
            current = next_level
        manual_root = current[0]

        self.assertEqual(kp.public_key, manual_root)


class TestLazyKeyGenSerialization(unittest.TestCase):
    """Signatures from lazy keys must serialize/deserialize correctly."""

    def test_signature_round_trip(self):
        kp = KeyPair(b"serialize-test".ljust(32, b"\x00"), height=4)
        msg = _hash(b"round trip test")
        sig = kp.sign(msg)

        # Serialize and deserialize
        data = sig.serialize()
        sig2 = Signature.deserialize(data)

        # Deserialized signature must still verify
        self.assertTrue(verify_signature(msg, sig2, kp.public_key))


if __name__ == "__main__":
    unittest.main()
