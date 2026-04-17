"""Tests for the complete cold storage workflow.

Workflow:
1. Generate key pair offline (no network)
2. Verify backup offline (re-derive from private key, confirm match)
3. Register account using only public info + registration proof
4. Receive funds using entity ID
5. Sign transactions with private key (briefly online)
"""

import hashlib
import io
import os
import unittest
from unittest.mock import patch

from messagechain.config import HASH_ALGO
from messagechain.crypto.keys import KeyPair, verify_signature
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity, derive_entity_id
from messagechain.cli import cmd_generate_key, cmd_verify_key, _collect_private_key


class TestOfflineKeyGeneration(unittest.TestCase):
    """Step 1: Generate full key pair with no network access."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_works_offline(self, mock_stdout):
        """generate-key produces private key, public key, and entity ID."""
        with patch("socket.socket") as mock_socket:
            mock_socket.side_effect = RuntimeError("No network")
            cmd_generate_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Recovery phrase", output)
        self.assertIn("Public key:", output)
        self.assertIn("Entity ID:", output)


class TestVerifyBackup(unittest.TestCase):
    """Step 2: Re-derive identity from private key to verify backup."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_verify_key_shows_derived_identity(self, mock_stdout):
        """verify-key should derive and display public key + entity ID."""
        from messagechain.identity.key_encoding import encode_private_key
        private_key = os.urandom(32)
        with patch("getpass.getpass", return_value=encode_private_key(private_key)):
            cmd_verify_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Public key:", output)
        self.assertIn("Entity ID:", output)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_verify_key_matches_generate_key(self, mock_stdout):
        """verify-key output should match what generate-key produced."""
        from messagechain.identity.key_encoding import encode_private_key
        private_key = os.urandom(32)

        # Generate
        with patch("os.urandom", return_value=private_key):
            cmd_generate_key(None)
        gen_output = mock_stdout.getvalue()

        mock_stdout.truncate(0)
        mock_stdout.seek(0)

        # Verify
        with patch("getpass.getpass", return_value=encode_private_key(private_key)):
            cmd_verify_key(None)
        verify_output = mock_stdout.getvalue()

        def extract(output, label):
            for line in output.splitlines():
                if label in line:
                    return line.split(label)[1].strip()
            return None

        self.assertEqual(
            extract(gen_output, "Public key:"),
            extract(verify_output, "Public key:"),
        )
        self.assertEqual(
            extract(gen_output, "Entity ID:"),
            extract(verify_output, "Entity ID:"),
        )

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_verify_key_works_offline(self, mock_stdout):
        """verify-key must work without any network access."""
        from messagechain.identity.key_encoding import encode_private_key
        private_key = os.urandom(32)
        with patch("socket.socket") as mock_socket:
            mock_socket.side_effect = RuntimeError("No network")
            with patch("getpass.getpass", return_value=encode_private_key(private_key)):
                cmd_verify_key(None)
        output = mock_stdout.getvalue()
        self.assertIn("Public key:", output)
        self.assertIn("Entity ID:", output)


class TestRegistrationProof(unittest.TestCase):
    """Step 3: Registration with a signed proof of key ownership."""

    def test_registration_proof_can_be_generated_offline(self):
        """A registration proof is just a signature — no network needed."""
        private_key = os.urandom(32)
        entity = Entity.create(private_key)
        proof_msg = _hash(b"register" + entity.entity_id)
        proof = entity.keypair.sign(proof_msg)

        # Proof should verify against the public key
        self.assertTrue(
            verify_signature(proof_msg, proof, entity.public_key)
        )

    def test_registration_proof_matches_blockchain_expectation(self):
        """The proof format must match what blockchain._install_pubkey_direct expects."""
        from messagechain.core.blockchain import Blockchain
        private_key = os.urandom(32)
        entity = Entity.create(private_key)

        proof_msg = _hash(b"register" + entity.entity_id)
        proof = entity.keypair.sign(proof_msg)

        bc = Blockchain()
        bc.initialize_genesis(entity)

        # Register a second entity with proof
        other_key = os.urandom(32)
        other = Entity.create(other_key)
        other_proof_msg = _hash(b"register" + other.entity_id)
        other_proof = other.keypair.sign(other_proof_msg)

        success, msg = bc._install_pubkey_direct(
            other.entity_id, other.public_key, registration_proof=other_proof
        )
        self.assertTrue(success, msg)

    def test_registration_rejects_wrong_proof(self):
        """A proof signed by a different key must be rejected."""
        from messagechain.core.blockchain import Blockchain
        private_key = os.urandom(32)
        entity = Entity.create(private_key)

        bc = Blockchain()
        bc.initialize_genesis(entity)

        # Try to register with a proof signed by the wrong key
        other_key = os.urandom(32)
        other = Entity.create(other_key)

        # Sign with the genesis key instead of other's key
        wrong_proof_msg = _hash(b"register" + other.entity_id)
        wrong_proof = entity.keypair.sign(wrong_proof_msg)

        success, msg = bc._install_pubkey_direct(
            other.entity_id, other.public_key, registration_proof=wrong_proof
        )
        self.assertFalse(success)
        self.assertIn("Invalid registration proof", msg)


class TestRoundTrip(unittest.TestCase):
    """The entity shown by generate-key must match what you get when you type
    the displayed key into any other command."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_entity_shown_matches_entity_from_collect(self, mock_stdout):
        """
        User runs generate-key, sees Entity ID X.
        Types the displayed private key into a command that calls
        _collect_private_key, derives entity from that. Must be Entity ID X.
        """
        fixed_key = os.urandom(32)

        # Run generate-key and capture the shown entity_id
        with patch("os.urandom", return_value=fixed_key):
            cmd_generate_key(None)
        out = mock_stdout.getvalue()

        shown_entity_id = None
        shown_hex_key = None
        for line in out.splitlines():
            if "Entity ID:" in line:
                shown_entity_id = line.split("Entity ID:")[1].strip()
            if "Hex form" in line:
                shown_hex_key = line.split("Hex form (alternative):")[1].strip()

        self.assertIsNotNone(shown_entity_id)
        self.assertIsNotNone(shown_hex_key)

        # Now simulate user typing the displayed key into a command
        with patch("getpass.getpass", return_value=shown_hex_key):
            key_bytes = _collect_private_key()
        entity = Entity.create(key_bytes)

        self.assertEqual(
            entity.entity_id_hex, shown_entity_id,
            "Entity shown by generate-key must match entity derived when the "
            "same printed key is typed into another command."
        )


class TestDeterministicDerivation(unittest.TestCase):
    """The same private key must always produce the same identity."""

    def test_same_key_same_identity(self):
        """Deterministic derivation: private key -> public key -> entity ID."""
        private_key = os.urandom(32)
        entity1 = Entity.create(private_key)
        entity2 = Entity.create(private_key)

        self.assertEqual(entity1.public_key, entity2.public_key)
        self.assertEqual(entity1.entity_id, entity2.entity_id)

    def test_nonce_tracks_leaf_usage(self):
        """After signing, re-deriving from private key + nonce resumes correctly."""
        private_key = os.urandom(32)

        # First session: sign 3 messages
        entity1 = Entity.create(private_key)
        for _ in range(3):
            entity1.keypair.sign(_hash(b"test"))

        # Second session: re-derive and advance past used leaves
        entity2 = Entity.create(private_key)
        entity2.keypair.advance_to_leaf(3)  # nonce = 3 from chain

        # Should use leaf 3, not 0
        sig = entity2.keypair.sign(_hash(b"test"))
        self.assertEqual(sig.leaf_index, 3)


if __name__ == "__main__":
    unittest.main()
