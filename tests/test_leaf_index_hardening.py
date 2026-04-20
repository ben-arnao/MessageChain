"""Tests for leaf-index persistence hardening (symlink, bounds, TOCTOU)."""

import json
import os
import tempfile
import unittest

from messagechain.crypto.keys import KeyPair


def _make_keypair(height=4):
    """Create a small KeyPair for testing (16 leaves)."""
    seed = b"\x01" * 32
    return KeyPair(seed, height=height)


class TestLeafIndexHardening(unittest.TestCase):

    # ------------------------------------------------------------------
    # Bug 1: Symlink traversal
    # ------------------------------------------------------------------
    @unittest.skipUnless(
        hasattr(os, "symlink"), "symlinks not available"
    )
    def test_symlink_traversal_rejected(self):
        """persist_leaf_index must refuse to write through a symlink."""
        kp = _make_keypair()
        kp._next_leaf = 3

        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "target.json")
            # Create the target with known content
            with open(target, "w") as f:
                f.write("ORIGINAL")

            link = os.path.join(td, "link.json")
            try:
                os.symlink(target, link)
            except OSError:
                self.skipTest("Cannot create symlinks on this system")

            with self.assertRaises(ValueError, msg="should reject symlink"):
                kp.persist_leaf_index(link)

            # Target must be untouched
            with open(target) as f:
                self.assertEqual(f.read(), "ORIGINAL")

    # ------------------------------------------------------------------
    # Bug 2: Bounds checks on loaded leaf index
    # ------------------------------------------------------------------
    def test_bounds_check_on_corrupted_leaf_index(self):
        """A next_leaf >= num_leaves must raise ValueError."""
        kp = _make_keypair(height=4)  # num_leaves = 16

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "leaf.json")
            with open(path, "w") as f:
                json.dump({"next_leaf": 999999999}, f)

            with self.assertRaises(ValueError):
                kp.load_leaf_index(path)

    def test_bounds_check_negative_leaf_index(self):
        """A negative next_leaf must be silently ignored."""
        kp = _make_keypair(height=4)
        original = kp._next_leaf

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "leaf.json")
            with open(path, "w") as f:
                json.dump({"next_leaf": -1}, f)

            kp.load_leaf_index(path)  # should not raise
            self.assertEqual(kp._next_leaf, original)

    def test_type_validation(self):
        """A non-integer next_leaf must be silently ignored."""
        kp = _make_keypair(height=4)
        original = kp._next_leaf

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "leaf.json")
            with open(path, "w") as f:
                json.dump({"next_leaf": "not_an_int"}, f)

            kp.load_leaf_index(path)  # should not raise
            self.assertEqual(kp._next_leaf, original)

    # ------------------------------------------------------------------
    # Bug 3: TOCTOU
    # ------------------------------------------------------------------
    def test_toctou_missing_file(self):
        """load_leaf_index on a nonexistent path must return silently."""
        kp = _make_keypair()
        kp.load_leaf_index("/tmp/does_not_exist_leaf_index.json")
        # No exception = pass

    def test_toctou_corrupt_json(self):
        """load_leaf_index with invalid JSON must return silently."""
        kp = _make_keypair()
        original = kp._next_leaf

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "leaf.json")
            with open(path, "w") as f:
                f.write("{corrupt json!!")

            kp.load_leaf_index(path)  # should not raise
            self.assertEqual(kp._next_leaf, original)

    # ------------------------------------------------------------------
    # Regression: normal persistence still works
    # ------------------------------------------------------------------
    def test_normal_persistence_still_works(self):
        """sign -> persist -> load -> sign cycle must work correctly."""
        seed = b"\x01" * 32
        kp1 = _make_keypair(height=4)
        msg = b"\xaa" * 32

        # Sign once to advance leaf
        kp1.sign(msg)
        self.assertEqual(kp1._next_leaf, 1)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "leaf.json")
            kp1.persist_leaf_index(path)

            # New keypair, load state
            kp2 = KeyPair(seed, height=4)
            self.assertEqual(kp2._next_leaf, 0)
            kp2.load_leaf_index(path)
            self.assertEqual(kp2._next_leaf, 1)

            # Sign should use leaf 1, not leaf 0
            sig = kp2.sign(msg)
            self.assertEqual(sig.leaf_index, 1)


if __name__ == "__main__":
    unittest.main()
