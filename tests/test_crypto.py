"""Tests for quantum-resistant cryptography."""

import unittest
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash
from messagechain.crypto.keys import KeyPair, verify_signature


class TestWOTS(unittest.TestCase):
    def test_sign_and_verify(self):
        seed = b"test-seed-12345"
        priv, pub, pub_seed = wots_keygen(seed)
        msg = _hash(b"hello world")

        sig = wots_sign(msg, priv, pub_seed)
        self.assertTrue(wots_verify(msg, sig, pub, pub_seed))

    def test_reject_tampered_message(self):
        seed = b"test-seed-12345"
        priv, pub, pub_seed = wots_keygen(seed)
        msg = _hash(b"hello world")
        wrong_msg = _hash(b"goodbye world")

        sig = wots_sign(msg, priv, pub_seed)
        self.assertFalse(wots_verify(wrong_msg, sig, pub, pub_seed))

    def test_reject_tampered_signature(self):
        seed = b"test-seed-12345"
        priv, pub, pub_seed = wots_keygen(seed)
        msg = _hash(b"hello world")

        sig = wots_sign(msg, priv, pub_seed)
        sig[0] = b"\x00" * 32  # tamper
        self.assertFalse(wots_verify(msg, sig, pub, pub_seed))

    def test_different_seeds_different_keys(self):
        _, pub1, _ = wots_keygen(b"seed-a")
        _, pub2, _ = wots_keygen(b"seed-b")
        self.assertNotEqual(pub1, pub2)


class TestKeyPair(unittest.TestCase):
    def setUp(self):
        # Use small tree for fast tests
        self.kp = KeyPair.generate(b"test-keypair-seed", height=3)  # 8 leaves

    def test_sign_and_verify(self):
        msg = _hash(b"test message")
        sig = self.kp.sign(msg)
        self.assertTrue(verify_signature(msg, sig, self.kp.public_key))

    def test_multiple_signatures(self):
        """Can sign multiple messages with same keypair."""
        for i in range(4):
            msg = _hash(f"message {i}".encode())
            sig = self.kp.sign(msg)
            self.assertTrue(verify_signature(msg, sig, self.kp.public_key))

    def test_remaining_signatures(self):
        self.assertEqual(self.kp.remaining_signatures, 8)
        self.kp.sign(_hash(b"msg"))
        self.assertEqual(self.kp.remaining_signatures, 7)

    def test_key_exhaustion(self):
        kp = KeyPair.generate(b"exhaust-test", height=2)  # 4 leaves
        for i in range(4):
            kp.sign(_hash(f"msg{i}".encode()))
        with self.assertRaises(RuntimeError):
            kp.sign(_hash(b"one too many"))

    def test_signature_serialization(self):
        msg = _hash(b"serialize me")
        sig = self.kp.sign(msg)
        data = sig.serialize()
        restored = type(sig).deserialize(data)
        self.assertTrue(verify_signature(msg, restored, self.kp.public_key))

    def test_wrong_public_key_rejects(self):
        kp2 = KeyPair.generate(b"different-seed", height=3)
        msg = _hash(b"test")
        sig = self.kp.sign(msg)
        self.assertFalse(verify_signature(msg, sig, kp2.public_key))


if __name__ == "__main__":
    unittest.main()
