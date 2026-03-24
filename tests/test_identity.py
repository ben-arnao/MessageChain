"""Tests for biometric identity system."""

import unittest
from messagechain.identity.biometrics import Entity, BiometricType, derive_entity_id


class TestEntity(unittest.TestCase):
    def test_create_entity(self):
        entity = Entity.create(b"dna1", b"finger1", b"iris1")
        self.assertIsNotNone(entity.entity_id)
        self.assertEqual(len(entity.entity_id), 32)  # SHA3-256

    def test_deterministic_id(self):
        e1 = Entity.create(b"dna", b"finger", b"iris")
        e2 = Entity.create(b"dna", b"finger", b"iris")
        self.assertEqual(e1.entity_id, e2.entity_id)
        self.assertEqual(e1.public_key, e2.public_key)

    def test_different_biometrics_different_id(self):
        e1 = Entity.create(b"dna-a", b"finger", b"iris")
        e2 = Entity.create(b"dna-b", b"finger", b"iris")
        self.assertNotEqual(e1.entity_id, e2.entity_id)

    def test_biometric_verification(self):
        entity = Entity.create(b"my-dna", b"my-finger", b"my-iris")
        self.assertTrue(entity.verify_biometric(BiometricType.DNA, b"my-dna"))
        self.assertTrue(entity.verify_biometric(BiometricType.FINGERPRINT, b"my-finger"))
        self.assertTrue(entity.verify_biometric(BiometricType.IRIS, b"my-iris"))
        self.assertFalse(entity.verify_biometric(BiometricType.DNA, b"wrong-dna"))

    def test_one_wallet_per_person(self):
        """Same biometrics always produce the same keypair (one wallet per person)."""
        e1 = Entity.create(b"dna", b"finger", b"iris")
        e2 = Entity.create(b"dna", b"finger", b"iris")
        self.assertEqual(e1.public_key, e2.public_key)


if __name__ == "__main__":
    unittest.main()
