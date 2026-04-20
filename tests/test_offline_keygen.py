"""Tests for offline key pair generation."""

import io
import os
import unittest
from unittest.mock import patch

from messagechain.cli import cmd_generate_key


class TestOfflineKeyPairGeneration(unittest.TestCase):
    """Verify that generate-key produces a full key pair offline."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_shows_public_key(self, mock_stdout):
        """generate-key should display the public key (Merkle root)."""
        # Use a fixed seed for determinism
        fixed_key = os.urandom(32)
        with patch("os.urandom", return_value=fixed_key):
            cmd_generate_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Recovery phrase", output)
        self.assertIn("Public key:", output)
        # Public key should be a 64-char hex string (32 bytes)
        for line in output.splitlines():
            if "Public key:" in line:
                pub_hex = line.split("Public key:")[1].strip()
                self.assertEqual(len(pub_hex), 64, f"Public key hex wrong length: {pub_hex}")
                bytes.fromhex(pub_hex)  # must be valid hex

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_shows_entity_id(self, mock_stdout):
        """generate-key should display the entity ID (wallet address)."""
        fixed_key = os.urandom(32)
        with patch("os.urandom", return_value=fixed_key):
            cmd_generate_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Entity ID:", output)
        for line in output.splitlines():
            if "Entity ID:" in line:
                eid_hex = line.split("Entity ID:")[1].strip()
                self.assertEqual(len(eid_hex), 64)
                bytes.fromhex(eid_hex)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_deterministic(self, mock_stdout):
        """Same private key should always produce the same public key and entity ID."""
        fixed_key = os.urandom(32)

        with patch("os.urandom", return_value=fixed_key):
            cmd_generate_key(None)
        output1 = mock_stdout.getvalue()

        mock_stdout.truncate(0)
        mock_stdout.seek(0)

        with patch("os.urandom", return_value=fixed_key):
            cmd_generate_key(None)
        output2 = mock_stdout.getvalue()

        # Extract public keys and entity IDs
        def extract(output, label):
            for line in output.splitlines():
                if label in line:
                    return line.split(label)[1].strip()
            return None

        self.assertEqual(extract(output1, "Public key:"), extract(output2, "Public key:"))
        self.assertEqual(extract(output1, "Entity ID:"), extract(output2, "Entity ID:"))

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_no_network(self, mock_stdout):
        """Key generation must work without any network calls."""
        # Patch socket to ensure no network access
        with patch("socket.socket") as mock_socket:
            mock_socket.side_effect = RuntimeError("No network allowed")
            cmd_generate_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Recovery phrase", output)
        self.assertIn("Public key:", output)
        self.assertIn("Entity ID:", output)


if __name__ == "__main__":
    unittest.main()
