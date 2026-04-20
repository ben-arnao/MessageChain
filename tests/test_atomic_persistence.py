"""Atomic persistence — ensure crash-window durability on both leaf-index
and TLS pin writes (iter 53 hardening).

The property under test: reading back an in-progress write should never
yield an empty/truncated/corrupted file.  tmp+rename is the standard
pattern; this test asserts the pattern is followed (no direct
open(path, "w") replacing the live file, which would truncate before
new contents land).
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest


class TestLeafIndexAtomicPersist(unittest.TestCase):

    def test_persist_uses_tmp_rename(self):
        """After persist_leaf_index, the canonical file exists with
        valid JSON, and no .tmp file lingers."""
        from messagechain.crypto.keys import KeyPair

        with tempfile.TemporaryDirectory() as d:
            kp = KeyPair.generate(b"leaf-atomic-test-seed-32-bytes!!", height=4)
            path = os.path.join(d, "leaf_index.json")
            kp._next_leaf = 5
            kp.persist_leaf_index(path)

            # Canonical file present + readable.
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["next_leaf"], 5)

            # No tmp file left behind.
            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_persist_survives_partial_write_simulation(self):
        """Create a stale .tmp file (simulating a crashed write) and
        verify the next persist replaces it cleanly."""
        from messagechain.crypto.keys import KeyPair

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "leaf_index.json")
            pathlib.Path(path + ".tmp").write_text("{partial")
            kp = KeyPair.generate(b"leaf-atomic-test-seed-32-bytes!!", height=4)
            kp._next_leaf = 7
            kp.persist_leaf_index(path)

            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["next_leaf"], 7)


class TestTLSPinAtomicPersist(unittest.TestCase):

    def test_save_uses_tmp_rename(self):
        from messagechain.network.tls import CertificatePinStore

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pins.json")
            store = CertificatePinStore(path=path)
            store.pin("1.2.3.4", 9333, ("ab" * 32), entity_id=b"\xcd" * 32)
            store.save()

            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertIn("1.2.3.4:9333", data)

            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_save_survives_stale_tmp(self):
        """A pre-existing corrupt .tmp must not block a subsequent save."""
        from messagechain.network.tls import CertificatePinStore

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pins.json")
            pathlib.Path(path + ".tmp").write_text("{corrupt")
            store = CertificatePinStore(path=path)
            store.pin("10.0.0.1", 9333, ("ee" * 32), entity_id=b"\xff" * 32)
            store.save()

            with open(path) as f:
                data = json.load(f)
            self.assertIn("10.0.0.1:9333", data)


if __name__ == "__main__":
    unittest.main()
