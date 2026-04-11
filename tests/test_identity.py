"""Tests for private-key identity system."""

import unittest
from messagechain.identity.identity import Entity, derive_entity_id


class TestEntity(unittest.TestCase):
    def test_create_entity(self):
        entity = Entity.create(b"my-private-key".ljust(32, b"\x00"))
        self.assertIsNotNone(entity.entity_id)
        self.assertEqual(len(entity.entity_id), 32)  # SHA3-256

    def test_deterministic_id(self):
        """Same private key = same entity = same wallet = same keys."""
        e1 = Entity.create(b"my-key".ljust(32, b"\x00"))
        e2 = Entity.create(b"my-key".ljust(32, b"\x00"))
        self.assertEqual(e1.entity_id, e2.entity_id)
        self.assertEqual(e1.public_key, e2.public_key)

    def test_different_keys_different_id(self):
        e1 = Entity.create(b"key-a".ljust(32, b"\x00"))
        e2 = Entity.create(b"key-b".ljust(32, b"\x00"))
        self.assertNotEqual(e1.entity_id, e2.entity_id)

    def test_entity_id_derived_from_public_key(self):
        """Entity ID is derived from the public key."""
        entity = Entity.create(b"my-key".ljust(32, b"\x00"))
        expected_id = derive_entity_id(entity.public_key)
        self.assertEqual(entity.entity_id, expected_id)

    def test_empty_private_key_rejected(self):
        """Private key must not be empty."""
        with self.assertRaises(ValueError):
            Entity.create(b"")

    def test_same_key_deterministic_seed(self):
        """Same private key produces identical seed."""
        e1 = Entity.create(b"my-key".ljust(32, b"\x00"))
        e2 = Entity.create(b"my-key".ljust(32, b"\x00"))
        self.assertEqual(e1._seed, e2._seed)

    def test_different_keys_different_seed(self):
        """Different private keys produce different seeds."""
        e1 = Entity.create(b"key-a".ljust(32, b"\x00"))
        e2 = Entity.create(b"key-b".ljust(32, b"\x00"))
        self.assertNotEqual(e1._seed, e2._seed)


if __name__ == "__main__":
    unittest.main()
