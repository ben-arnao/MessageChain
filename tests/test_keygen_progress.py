"""Tests for the progress callback in KeyPair generation."""

import os
import unittest

from messagechain.crypto.keys import KeyPair


class TestKeygenProgress(unittest.TestCase):
    def test_progress_called_once_per_leaf(self):
        """The callback is invoked exactly num_leaves times."""
        seed = os.urandom(32)
        count = [0]

        def cb(_leaf_index):
            count[0] += 1

        kp = KeyPair.generate(seed, height=3, progress=cb)
        self.assertEqual(count[0], 1 << 3)

    def test_progress_sees_all_leaf_indices(self):
        """Every leaf index from 0 to num_leaves-1 is reported."""
        seed = os.urandom(32)
        seen = []

        def cb(leaf_index):
            seen.append(leaf_index)

        KeyPair.generate(seed, height=3, progress=cb)
        self.assertEqual(sorted(seen), list(range(1 << 3)))

    def test_no_progress_works_normally(self):
        """Omitting the callback must not change behavior."""
        seed = os.urandom(32)
        kp1 = KeyPair.generate(seed, height=3)
        kp2 = KeyPair.generate(seed, height=3, progress=None)
        self.assertEqual(kp1.public_key, kp2.public_key)

    def test_progress_does_not_affect_public_key(self):
        """Providing a callback must not change the derived public key."""
        seed = os.urandom(32)
        kp1 = KeyPair.generate(seed, height=3)
        kp2 = KeyPair.generate(seed, height=3, progress=lambda _i: None)
        self.assertEqual(kp1.public_key, kp2.public_key)


if __name__ == "__main__":
    unittest.main()
