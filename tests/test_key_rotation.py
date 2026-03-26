"""Tests for key rotation — entities can rotate to fresh WOTS+ Merkle trees."""

import unittest
from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.core.key_rotation import (
    KeyRotationTransaction,
    create_key_rotation,
    verify_key_rotation,
    derive_rotated_keypair,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.config import KEY_ROTATION_FEE


class TestKeyRotation(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        self.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris", private_key=b"bob-private-key")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.register_entity(self.bob.entity_id, self.bob.public_key)
        # Fund test entities so they can pay fees
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000

    def test_derive_rotated_keypair_deterministic(self):
        """Same biometrics + same rotation number = same new keys."""
        kp1 = derive_rotated_keypair(self.alice, rotation_number=0)
        kp2 = derive_rotated_keypair(self.alice, rotation_number=0)
        self.assertEqual(kp1.public_key, kp2.public_key)

    def test_derive_rotated_keypair_different_from_original(self):
        """Rotated keypair must differ from the original."""
        kp = derive_rotated_keypair(self.alice, rotation_number=0)
        self.assertNotEqual(kp.public_key, self.alice.public_key)

    def test_different_rotation_numbers_different_keys(self):
        kp0 = derive_rotated_keypair(self.alice, rotation_number=0)
        kp1 = derive_rotated_keypair(self.alice, rotation_number=1)
        self.assertNotEqual(kp0.public_key, kp1.public_key)

    def test_create_and_verify_rotation_tx(self):
        """A valid key rotation tx is created and verified."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)

        self.assertEqual(tx.entity_id, self.alice.entity_id)
        self.assertEqual(tx.old_public_key, self.alice.public_key)
        self.assertEqual(tx.new_public_key, new_kp.public_key)

        valid = verify_key_rotation(tx, self.alice.public_key)
        self.assertTrue(valid)

    def test_rotation_rejected_wrong_old_key(self):
        """Rotation fails if old_public_key doesn't match."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)

        # Verify against wrong key
        valid = verify_key_rotation(tx, self.bob.public_key)
        self.assertFalse(valid)

    def test_rotation_rejected_same_key(self):
        """Cannot rotate to the same key."""
        tx = KeyRotationTransaction(
            entity_id=self.alice.entity_id,
            old_public_key=self.alice.public_key,
            new_public_key=self.alice.public_key,  # same!
            rotation_number=0,
            timestamp=0,
            fee=KEY_ROTATION_FEE,
            signature=self.alice.keypair.sign(b"\x00" * 32),
        )
        valid = verify_key_rotation(tx, self.alice.public_key)
        self.assertFalse(valid)

    def test_blockchain_apply_key_rotation(self):
        """Blockchain accepts a valid key rotation and updates public key."""
        old_pk = self.chain.public_keys[self.alice.entity_id]
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)

        valid, reason = self.chain.validate_key_rotation(tx)
        self.assertTrue(valid, reason)

        success, msg = self.chain.apply_key_rotation(tx, self.bob.entity_id)
        self.assertTrue(success, msg)

        # Public key should now be the new one
        self.assertEqual(self.chain.public_keys[self.alice.entity_id], new_kp.public_key)
        self.assertNotEqual(self.chain.public_keys[self.alice.entity_id], old_pk)

    def test_rotation_counter_enforced(self):
        """Rotation number must match expected sequence."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=1)  # wrong: should be 0

        valid, reason = self.chain.validate_key_rotation(tx)
        self.assertFalse(valid)
        self.assertIn("rotation number", reason.lower())

    def test_sequential_rotations(self):
        """Can rotate multiple times sequentially."""
        # First rotation
        new_kp0 = derive_rotated_keypair(self.alice, rotation_number=0)
        tx0 = create_key_rotation(self.alice, new_kp0, rotation_number=0)
        success, _ = self.chain.apply_key_rotation(tx0, self.bob.entity_id)
        self.assertTrue(success)
        self.assertEqual(self.chain.key_rotation_counts[self.alice.entity_id], 1)

        # Second rotation — need to use new keypair to sign
        # Simulate entity with new keypair
        alice_rotated = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        alice_rotated.keypair = new_kp0  # swap in the rotated keypair

        new_kp1 = derive_rotated_keypair(self.alice, rotation_number=1)
        tx1 = create_key_rotation(alice_rotated, new_kp1, rotation_number=1)
        success, _ = self.chain.apply_key_rotation(tx1, self.bob.entity_id)
        self.assertTrue(success)
        self.assertEqual(self.chain.public_keys[self.alice.entity_id], new_kp1.public_key)

    def test_rotation_fee_deducted(self):
        """Fee is deducted from entity and paid to proposer."""
        alice_bal_before = self.chain.supply.get_balance(self.alice.entity_id)
        bob_bal_before = self.chain.supply.get_balance(self.bob.entity_id)

        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0, fee=KEY_ROTATION_FEE)
        self.chain.apply_key_rotation(tx, self.bob.entity_id)

        alice_bal_after = self.chain.supply.get_balance(self.alice.entity_id)
        bob_bal_after = self.chain.supply.get_balance(self.bob.entity_id)

        self.assertEqual(alice_bal_after, alice_bal_before - KEY_ROTATION_FEE)
        self.assertEqual(bob_bal_after, bob_bal_before + KEY_ROTATION_FEE)

    def test_rotation_insufficient_balance_rejected(self):
        """Rotation rejected if entity can't afford the fee."""
        # Drain Alice's balance
        self.chain.supply.balances[self.alice.entity_id] = 0

        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)
        valid, reason = self.chain.validate_key_rotation(tx)
        self.assertFalse(valid)
        self.assertIn("insufficient", reason.lower())

    def test_rotation_serialization_roundtrip(self):
        """Key rotation tx survives serialization/deserialization."""
        new_kp = derive_rotated_keypair(self.alice, rotation_number=0)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=0)

        data = tx.serialize()
        restored = KeyRotationTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.entity_id, tx.entity_id)
        self.assertEqual(restored.new_public_key, tx.new_public_key)


if __name__ == "__main__":
    unittest.main()
