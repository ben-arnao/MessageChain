"""Tests for private key authentication.

Security model: sending a message requires a private key.
The private key deterministically derives the signing keypair.
Entity ID is derived from the public key.
"""

import unittest
from messagechain.identity.identity import Entity


class TestPrivateKeyEntityCreation(unittest.TestCase):
    """Entity.create() requires a private key."""

    def test_create_requires_private_key(self):
        """Entity.create() must accept a private_key parameter."""
        entity = Entity.create(b"my-secret-key")
        self.assertIsNotNone(entity.entity_id)
        self.assertEqual(len(entity.entity_id), 32)

    def test_different_key_different_entity(self):
        """Different private keys produce different entities."""
        e1 = Entity.create(b"key-1")
        e2 = Entity.create(b"key-2")
        self.assertNotEqual(e1.entity_id, e2.entity_id)
        self.assertNotEqual(e1.public_key, e2.public_key)

    def test_same_key_deterministic(self):
        """Same private key = identical entity every time."""
        e1 = Entity.create(b"key")
        e2 = Entity.create(b"key")
        self.assertEqual(e1.entity_id, e2.entity_id)
        self.assertEqual(e1.public_key, e2.public_key)
        self.assertEqual(e1._seed, e2._seed)

    def test_empty_private_key_rejected(self):
        """Private key must not be empty."""
        with self.assertRaises(ValueError):
            Entity.create(b"")


class TestPrivateKeySecurity(unittest.TestCase):
    """Verify that only the correct private key can produce valid signatures."""

    def test_wrong_key_cannot_sign(self):
        """With the wrong private key, signature verification fails
        against the registered public key."""
        from messagechain.core.transaction import create_transaction, verify_transaction

        # Register with key-1
        real = Entity.create(b"real-key")

        # Attacker uses a different private key
        attacker = Entity.create(b"wrong-key")

        # Different entity_id and different signing key
        self.assertNotEqual(real.entity_id, attacker.entity_id)

        # Attacker signs a transaction
        tx = create_transaction(
            attacker, "Fraudulent message",
            fee=5, nonce=0,
        )

        # Verification against the real public key should fail
        self.assertFalse(verify_transaction(tx, real.public_key))

    def test_correct_key_signs_successfully(self):
        """With the correct private key, signing works."""
        from messagechain.core.transaction import create_transaction, verify_transaction

        entity = Entity.create(b"my-key")
        tx = create_transaction(
            entity, "Legitimate message",
            fee=5, nonce=0,
        )
        self.assertTrue(verify_transaction(tx, entity.public_key))


if __name__ == "__main__":
    unittest.main()
