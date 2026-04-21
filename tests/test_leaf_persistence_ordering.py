"""Persist-before-sign ordering for WOTS+ leaf index.

Original bug: sign() incremented the in-memory counter, called wots_sign(),
THEN persisted _next_leaf to disk.  A crash between wots_sign() returning
and persist_leaf_index() completing left the broadcast signature already
emitted but the on-disk counter stale — a restart would reuse the same
WOTS+ leaf, which reveals the one-time private key.

The fix is persist-first: write the advanced leaf index to disk and fsync
it BEFORE wots_sign() runs.  A leaf burned without a corresponding sign
is cheap; a leaf signed twice leaks the key.  These tests lock in that
ordering.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from messagechain.crypto import keys as keys_module
from messagechain.crypto.keys import KeyPair


def _make_persistent_keypair(tmpdir, height=4):
    """Build a small KeyPair wired to a leaf-index file under tmpdir."""
    seed = b"\x11" * 32
    kp = KeyPair(seed, height=height)
    kp.leaf_index_path = os.path.join(tmpdir, "leaf.json")
    return kp


def _read_persisted_leaf(path):
    with open(path, "r") as f:
        return json.load(f)["next_leaf"]


class TestPersistBeforeSign(unittest.TestCase):
    # ------------------------------------------------------------------
    # Test A: wots_sign() raising must NOT rewind the persisted leaf.
    #
    # Proves the persist happens first: the sign blew up, but the
    # on-disk counter has already advanced.  That leaf is "burned"
    # forever, which is the safe direction.
    # ------------------------------------------------------------------
    def test_persist_happens_before_sign_on_failure(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path

            with mock.patch.object(
                keys_module, "wots_sign",
                side_effect=RuntimeError("boom — simulated mid-sign crash"),
            ):
                with self.assertRaises(RuntimeError):
                    kp.sign(b"\xaa" * 32)

            # Persisted leaf MUST have advanced to 1 even though
            # sign failed — this is what prevents reuse after a real
            # crash at the same point.
            self.assertTrue(os.path.exists(leaf_path))
            self.assertEqual(_read_persisted_leaf(leaf_path), 1)

    # ------------------------------------------------------------------
    # Test B: Normal happy path still works end-to-end, and the disk
    # state matches the in-memory state after a successful sign.
    # ------------------------------------------------------------------
    def test_normal_sign_persists_and_matches_memory(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            sig = kp.sign(b"\xbb" * 32)

            self.assertEqual(sig.leaf_index, 0)
            self.assertEqual(kp._next_leaf, 1)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 1)

            # Second sign advances both to 2.
            sig2 = kp.sign(b"\xcc" * 32)
            self.assertEqual(sig2.leaf_index, 1)
            self.assertEqual(kp._next_leaf, 2)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 2)

    # ------------------------------------------------------------------
    # Test C: A sign that crashes mid-way must not allow a subsequent
    # fresh KeyPair (simulating restart) to reuse the same leaf.
    # ------------------------------------------------------------------
    def test_no_leaf_reuse_across_simulated_crash(self):
        seed = b"\x22" * 32
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")

            # Startup 1: sign raises mid-way.  Persisted leaf should
            # still advance.
            kp1 = KeyPair(seed, height=4)
            kp1.leaf_index_path = leaf_path
            with mock.patch.object(
                keys_module, "wots_sign",
                side_effect=RuntimeError("simulated crash"),
            ):
                with self.assertRaises(RuntimeError):
                    kp1.sign(b"\xdd" * 32)

            self.assertEqual(_read_persisted_leaf(leaf_path), 1)

            # Startup 2: fresh KeyPair reloads the persisted counter.
            # The next sign MUST go to leaf 1, never back to leaf 0 —
            # that would be the catastrophic WOTS+ reuse case.
            kp2 = KeyPair(seed, height=4)
            kp2.leaf_index_path = leaf_path
            kp2.load_leaf_index(leaf_path)
            sig = kp2.sign(b"\xee" * 32)
            self.assertNotEqual(sig.leaf_index, 0)
            self.assertEqual(sig.leaf_index, 1)

    # ------------------------------------------------------------------
    # Test D: Persist failure must prevent sign() from emitting a
    # signature.  If we can't durably record the leaf as burned, we
    # must not expose the signature to the network.
    # ------------------------------------------------------------------
    def test_persist_failure_aborts_sign(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)

            with mock.patch.object(
                KeyPair, "persist_leaf_index",
                side_effect=OSError("disk full"),
            ):
                with self.assertRaises(OSError):
                    kp.sign(b"\xff" * 32)

            # Memory counter must NOT have advanced past what's on disk
            # (there is no on-disk file yet — persist failed on first write).
            # The invariant we're guarding: memory <= disk at all times.
            self.assertEqual(kp._next_leaf, 0)


if __name__ == "__main__":
    unittest.main()
