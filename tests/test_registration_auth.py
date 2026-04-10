"""Tests for authenticated entity registration.

Registration must prove the registrant controls the keypair matching
the entity_id, preventing arbitrary fabricated identities.
"""

import unittest
import hashlib
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import verify_signature, KeyPair
from messagechain.config import HASH_ALGO


class TestRegistrationAuth(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)

    def test_registration_with_valid_proof(self):
        """Registration with a valid binding signature succeeds."""
        bob = Entity.create(b"bob-private-key")
        # Create registration proof: sign entity_id with keypair
        msg = hashlib.new(HASH_ALGO, b"register" + bob.entity_id).digest()
        proof = bob.keypair.sign(msg)

        success, reason = self.chain.register_entity(bob.entity_id, bob.public_key, registration_proof=proof)
        self.assertTrue(success, reason)

    def test_registration_without_proof_rejected(self):
        """Registration without a binding signature is rejected."""
        bob = Entity.create(b"bob-private-key")
        success, reason = self.chain.register_entity(bob.entity_id, bob.public_key)
        self.assertFalse(success)
        self.assertIn("proof", reason.lower())

    def test_registration_with_wrong_key_rejected(self):
        """Registration with a proof from a different keypair is rejected."""
        bob = Entity.create(b"bob-private-key")
        eve = Entity.create(b"eve-private-key")

        # Eve signs Bob's entity_id — proof doesn't match bob's public_key
        msg = hashlib.new(HASH_ALGO, b"register" + bob.entity_id).digest()
        fake_proof = eve.keypair.sign(msg)

        success, reason = self.chain.register_entity(bob.entity_id, bob.public_key, registration_proof=fake_proof)
        self.assertFalse(success)
        self.assertIn("proof", reason.lower())

    def test_genesis_entity_already_registered(self):
        """Genesis entity doesn't need a separate registration call."""
        self.assertIn(self.alice.entity_id, self.chain.public_keys)


if __name__ == "__main__":
    unittest.main()
