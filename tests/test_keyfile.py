"""Tests for --keyfile flag: load validator private key from a file.

Required for auto-restart / systemd scenarios where no human is
available to type the key at startup.
"""

import os
import stat
import tempfile
import unittest

from messagechain.identity.key_encoding import encode_private_key
from messagechain.cli import _load_key_from_file, KeyFileError


class TestLoadKeyFromFile(unittest.TestCase):
    def test_loads_checksummed_key(self):
        """A file containing a checksummed key returns the 32 raw bytes."""
        key = os.urandom(32)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            f.write(encode_private_key(key))
            path = f.name
        try:
            loaded = _load_key_from_file(path)
            self.assertEqual(loaded, key)
        finally:
            os.unlink(path)

    def test_tolerates_trailing_newline(self):
        """Editors often add a trailing newline — that must be accepted."""
        key = os.urandom(32)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            f.write(encode_private_key(key) + "\n")
            path = f.name
        try:
            loaded = _load_key_from_file(path)
            self.assertEqual(loaded, key)
        finally:
            os.unlink(path)

    def test_rejects_missing_file(self):
        with self.assertRaises(KeyFileError):
            _load_key_from_file("/nonexistent/path/to/key.file")

    def test_rejects_empty_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            path = f.name
        try:
            with self.assertRaises(KeyFileError):
                _load_key_from_file(path)
        finally:
            os.unlink(path)

    def test_rejects_bad_checksum(self):
        """A corrupted key file must fail loudly, not silently load wrong key."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        # Flip a character
        tampered = ("0" if encoded[0] != "0" else "1") + encoded[1:]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            f.write(tampered)
            path = f.name
        try:
            with self.assertRaises(KeyFileError):
                _load_key_from_file(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
