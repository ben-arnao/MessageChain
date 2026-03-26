"""Tests for two-factor authentication: biometric + private key.

Security model: sending a message requires BOTH:
1. Biometric data (something you are) - determines your entity_id (wallet address)
2. A private key (something you know) - combined with biometrics to derive signing key

Entity ID is still derived from biometrics alone (one person = one wallet).
But the signing keypair requires both factors, so stolen biometrics alone
cannot sign transactions.
"""

import unittest
from messagechain.identity.biometrics import Entity, BiometricType


class TestTwoFactorEntityCreation(unittest.TestCase):
    """Entity.create() requires biometrics + private_key."""

    def test_create_requires_private_key(self):
        """Entity.create() must accept a private_key parameter."""
        entity = Entity.create(b"dna", b"finger", b"iris", private_key=b"my-secret-key")
        self.assertIsNotNone(entity.entity_id)
        self.assertEqual(len(entity.entity_id), 32)

    def test_entity_id_independent_of_private_key(self):
        """Entity ID (wallet address) is derived from biometrics only.
        Same biometrics = same wallet, regardless of private key."""
        e1 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-1")
        e2 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-2")
        self.assertEqual(e1.entity_id, e2.entity_id)

    def test_different_private_key_different_signing_key(self):
        """Different private keys produce different signing keypairs,
        even with the same biometrics."""
        e1 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-1")
        e2 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-2")
        # Same entity_id (same wallet) but different public keys
        self.assertEqual(e1.entity_id, e2.entity_id)
        self.assertNotEqual(e1.public_key, e2.public_key)

    def test_same_factors_deterministic(self):
        """Same biometrics + same private key = identical entity every time."""
        e1 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key")
        e2 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key")
        self.assertEqual(e1.entity_id, e2.entity_id)
        self.assertEqual(e1.public_key, e2.public_key)
        self.assertEqual(e1._biometric_seed, e2._biometric_seed)

    def test_private_key_affects_seed(self):
        """The biometric seed must incorporate the private key."""
        e1 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-a")
        e2 = Entity.create(b"dna", b"finger", b"iris", private_key=b"key-b")
        self.assertNotEqual(e1._biometric_seed, e2._biometric_seed)

    def test_empty_private_key_rejected(self):
        """Private key must not be empty — it's a required security factor."""
        with self.assertRaises(ValueError):
            Entity.create(b"dna", b"finger", b"iris", private_key=b"")

    def test_from_hashes_requires_private_key(self):
        """from_hashes() also requires a private_key."""
        import hashlib
        from messagechain.config import HASH_ALGO
        h = hashlib.new
        dna_hash = h(HASH_ALGO, b"dna").digest()
        fp_hash = h(HASH_ALGO, b"finger").digest()
        iris_hash = h(HASH_ALGO, b"iris").digest()
        entity = Entity.from_hashes(dna_hash, fp_hash, iris_hash, private_key=b"my-key")
        self.assertIsNotNone(entity.entity_id)


class TestTwoFactorSecurity(unittest.TestCase):
    """Verify that both factors are required for valid signatures."""

    def test_biometrics_alone_cannot_sign(self):
        """With the wrong private key, signature verification fails
        against the registered public key."""
        from messagechain.core.transaction import create_transaction, verify_transaction

        # Register with key-1
        real = Entity.create(b"dna", b"finger", b"iris", private_key=b"real-key")

        # Attacker has biometrics but uses wrong private key
        attacker = Entity.create(b"dna", b"finger", b"iris", private_key=b"wrong-key")

        # Same entity_id, but different signing key
        self.assertEqual(real.entity_id, attacker.entity_id)

        # Attacker signs a transaction
        tx = create_transaction(
            attacker, "Fraudulent message", BiometricType.FINGERPRINT,
            fee=5, nonce=0,
        )

        # Verification against the real public key should fail
        self.assertFalse(verify_transaction(tx, real.public_key))

    def test_correct_factors_sign_successfully(self):
        """With correct biometrics + correct private key, signing works."""
        from messagechain.core.transaction import create_transaction, verify_transaction

        entity = Entity.create(b"dna", b"finger", b"iris", private_key=b"my-key")
        tx = create_transaction(
            entity, "Legitimate message", BiometricType.FINGERPRINT,
            fee=5, nonce=0,
        )
        self.assertTrue(verify_transaction(tx, entity.public_key))


if __name__ == "__main__":
    unittest.main()
