"""Tests for three HIGH crypto security fixes.

1. Constant-time WOTS+ verification (dummy chain work normalizes timing)
2. Private key material zeroed after signing
3. Persistent leaf-index tracking to prevent WOTS+ leaf reuse on restart
"""

import os
import json
import tempfile
import unittest

from messagechain.crypto.hash_sig import (
    wots_keygen, wots_sign, wots_verify, _hash, _chain,
)
from messagechain.crypto.keys import KeyPair, verify_signature, _derive_leaf
from messagechain.config import WOTS_CHAIN_LENGTH, WOTS_KEY_CHAINS


# ---------------------------------------------------------------------------
# Finding 1: Constant-time WOTS+ verification
# ---------------------------------------------------------------------------

class TestConstantTimeWotsVerify(unittest.TestCase):
    """Verify that wots_verify still produces correct results after the
    constant-time dummy-work fix is applied."""

    def setUp(self):
        self.seed = b"constant-time-test-seed"
        self.priv, self.pub, self.pub_seed = wots_keygen(self.seed)

    def test_valid_signature_still_verifies(self):
        msg = _hash(b"constant-time message")
        sig = wots_sign(msg, self.priv, self.pub_seed)
        self.assertTrue(wots_verify(msg, sig, self.pub, self.pub_seed))

    def test_tampered_signature_still_rejected(self):
        msg = _hash(b"constant-time message")
        sig = wots_sign(msg, self.priv, self.pub_seed)
        sig[0] = b"\xff" * 32
        self.assertFalse(wots_verify(msg, sig, self.pub, self.pub_seed))

    def test_wrong_message_still_rejected(self):
        msg = _hash(b"real message")
        sig = wots_sign(msg, self.priv, self.pub_seed)
        wrong = _hash(b"wrong message")
        self.assertFalse(wots_verify(wrong, sig, self.pub, self.pub_seed))

    def test_multiple_messages_verify(self):
        """Different message hashes exercise different digit distributions."""
        for i in range(5):
            msg = _hash(f"message-{i}".encode())
            sig = wots_sign(msg, self.priv, self.pub_seed)
            self.assertTrue(wots_verify(msg, sig, self.pub, self.pub_seed))


# ---------------------------------------------------------------------------
# Finding 2: Private key zeroing after signing
# ---------------------------------------------------------------------------

class TestPrivateKeyZeroing(unittest.TestCase):
    """Verify that sign() still works correctly after the key-zeroing change,
    and that _derive_leaf returns bytearray (mutable) private keys."""

    def setUp(self):
        self.kp = KeyPair.generate(b"zeroing-test-seed", height=3)

    def test_derive_leaf_returns_bytearrays(self):
        """Private keys from _derive_leaf must be bytearray for zeroing."""
        priv_keys, _pub, _seed = _derive_leaf(b"any-seed", 0)
        for pk in priv_keys:
            self.assertIsInstance(pk, bytearray,
                                 "Private keys must be bytearray for safe zeroing")

    def test_sign_verify_still_works_after_zeroing(self):
        """Signing produces valid signatures even though keys are zeroed after."""
        msg = _hash(b"zeroing test msg")
        sig = self.kp.sign(msg)
        self.assertTrue(verify_signature(msg, sig, self.kp.public_key))

    def test_multiple_signs_still_work(self):
        """Each leaf derivation + zeroing is independent; later signs work."""
        for i in range(4):
            msg = _hash(f"zeroing-{i}".encode())
            sig = self.kp.sign(msg)
            self.assertTrue(verify_signature(msg, sig, self.kp.public_key))


# ---------------------------------------------------------------------------
# Finding 3: Persistent leaf-index tracking
# ---------------------------------------------------------------------------

class TestLeafIndexPersistence(unittest.TestCase):
    """Leaf index must be persisted to disk and restored on restart."""

    def setUp(self):
        self.seed = b"persist-test-seed"
        self.height = 3
        self.tmpdir = tempfile.mkdtemp()
        self.index_path = os.path.join(self.tmpdir, "leaf_index.json")

    def tearDown(self):
        # Cross-process advisory lock leaves a sibling .lock file next
        # to the cursor; sweep any stragglers so rmdir doesn't fail.
        for fn in os.listdir(self.tmpdir):
            try:
                os.remove(os.path.join(self.tmpdir, fn))
            except OSError:
                pass
        os.rmdir(self.tmpdir)

    def test_persist_and_load_leaf_index(self):
        """After signing, persist_leaf_index writes the current index."""
        kp = KeyPair.generate(self.seed, height=self.height)
        msg = _hash(b"persist test")
        kp.sign(msg)
        # _next_leaf should now be 1
        kp.persist_leaf_index(self.index_path)

        kp2 = KeyPair.generate(self.seed, height=self.height)
        kp2.load_leaf_index(self.index_path)
        self.assertEqual(kp2._next_leaf, 1)

    def test_restored_keypair_refuses_reused_leaf(self):
        """A restored KeyPair starts at the persisted index, not zero."""
        kp = KeyPair.generate(self.seed, height=self.height)
        # Sign 3 times
        for i in range(3):
            kp.sign(_hash(f"msg-{i}".encode()))
        kp.persist_leaf_index(self.index_path)

        kp2 = KeyPair.generate(self.seed, height=self.height)
        kp2.load_leaf_index(self.index_path)
        self.assertEqual(kp2._next_leaf, 3)

        # Next sign should use leaf 3, not 0
        sig = kp2.sign(_hash(b"new message"))
        self.assertEqual(sig.leaf_index, 3)
        self.assertTrue(verify_signature(_hash(b"new message"), sig, kp2.public_key))

    def test_sign_auto_persists_when_path_set(self):
        """When leaf_index_path is configured, sign() auto-persists."""
        kp = KeyPair.generate(self.seed, height=self.height)
        kp.leaf_index_path = self.index_path
        kp.sign(_hash(b"auto-persist"))

        # Read the file to verify
        with open(self.index_path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["next_leaf"], 1)

    def test_persist_before_return(self):
        """Persistence is write-ahead: index on disk reflects the NEXT leaf
        to use (after the sign), not the one just consumed."""
        kp = KeyPair.generate(self.seed, height=self.height)
        kp.leaf_index_path = self.index_path
        kp.sign(_hash(b"first"))
        kp.sign(_hash(b"second"))

        with open(self.index_path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["next_leaf"], 2)

    def test_load_nonexistent_file_starts_at_zero(self):
        """Loading from a missing file is fine -- starts at 0."""
        kp = KeyPair.generate(self.seed, height=self.height)
        kp.load_leaf_index("/tmp/nonexistent_leaf_idx_12345.json")
        self.assertEqual(kp._next_leaf, 0)

    def test_load_refuses_backward_index(self):
        """load_leaf_index must never move the index backwards."""
        kp = KeyPair.generate(self.seed, height=self.height)
        kp.sign(_hash(b"advance"))  # _next_leaf = 1

        # Write a stale index (0)
        with open(self.index_path, "w") as f:
            json.dump({"next_leaf": 0}, f)

        kp.load_leaf_index(self.index_path)
        # Must remain at 1, not go back to 0
        self.assertEqual(kp._next_leaf, 1)


if __name__ == "__main__":
    unittest.main()
