"""Tests for the attestation layer and finality mechanism."""

import unittest
import time
from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import (
    Attestation,
    FinalityTracker,
    create_attestation,
    verify_attestation,
)
from tests import register_entity_for_test
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashTransaction,
    create_slash_transaction,
    verify_attestation_slashing_evidence,
)
from messagechain.config import FINALITY_THRESHOLD


class TestAttestation(unittest.TestCase):
    """Test basic attestation creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        cls.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris", private_key=b"bob-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def test_create_attestation(self):
        """An attestation can be created and has correct fields."""
        block_hash = _hash(b"test_block")
        att = create_attestation(self.alice, block_hash, block_number=5)
        self.assertEqual(att.validator_id, self.alice.entity_id)
        self.assertEqual(att.block_hash, block_hash)
        self.assertEqual(att.block_number, 5)

    def test_verify_valid_attestation(self):
        """A properly signed attestation verifies successfully."""
        block_hash = _hash(b"test_block")
        att = create_attestation(self.alice, block_hash, block_number=5)
        self.assertTrue(verify_attestation(att, self.alice.public_key))

    def test_wrong_public_key_rejects(self):
        """Attestation verified against wrong key is rejected."""
        block_hash = _hash(b"test_block")
        att = create_attestation(self.alice, block_hash, block_number=5)
        self.assertFalse(verify_attestation(att, self.bob.public_key))

    def test_attestation_serialization_roundtrip(self):
        """Attestation survives serialization/deserialization."""
        block_hash = _hash(b"test_block")
        att = create_attestation(self.alice, block_hash, block_number=5)
        data = att.serialize()
        restored = Attestation.deserialize(data)
        self.assertEqual(restored.validator_id, att.validator_id)
        self.assertEqual(restored.block_hash, att.block_hash)
        self.assertEqual(restored.block_number, att.block_number)


class TestFinalityTracker(unittest.TestCase):
    """Test the finality tracking mechanism."""

    def setUp(self):
        self.tracker = FinalityTracker()

    def test_block_not_finalized_by_default(self):
        self.assertFalse(self.tracker.is_finalized(b"any_hash"))

    def test_block_finalized_at_threshold(self):
        """Block becomes finalized when 2/3+ of stake attests."""
        block_hash = _hash(b"block1")
        # 200/300 = 0.6667 which is < 0.67, so need 3/3 or uneven stakes
        att1 = Attestation(b"v1", block_hash, 1, None)
        att2 = Attestation(b"v2", block_hash, 1, None)

        total_stake = 300
        # 1/3 - not finalized
        self.tracker.add_attestation(att1, 100, total_stake)
        self.assertFalse(self.tracker.is_finalized(block_hash))

        # 200/300 = 0.667 < 0.67 - still not finalized
        self.tracker.add_attestation(att2, 100, total_stake)
        self.assertFalse(self.tracker.is_finalized(block_hash))

        # 3/3 = 1.0 >= 0.67 - finalized
        att3 = Attestation(b"v3", block_hash, 1, None)
        self.tracker.add_attestation(att3, 100, total_stake)
        self.assertTrue(self.tracker.is_finalized(block_hash))

    def test_block_not_finalized_below_threshold(self):
        """Block stays unfinalized below 2/3 threshold."""
        block_hash = _hash(b"block1")
        att1 = Attestation(b"v1", block_hash, 1, None)

        total_stake = 300
        self.tracker.add_attestation(att1, 100, total_stake)
        self.assertFalse(self.tracker.is_finalized(block_hash))

    def test_duplicate_attestation_not_counted(self):
        """Same validator attesting twice doesn't double-count."""
        block_hash = _hash(b"block1")
        att1 = Attestation(b"v1", block_hash, 1, None)

        total_stake = 300
        self.tracker.add_attestation(att1, 100, total_stake)
        # Same validator again
        self.tracker.add_attestation(att1, 100, total_stake)
        # Still only 100/300 = 0.33
        self.assertFalse(self.tracker.is_finalized(block_hash))

    def test_finalized_height_tracked(self):
        """Finalized height updates when a block is justified."""
        block_hash = _hash(b"block1")
        att1 = Attestation(b"v1", block_hash, 10, None)
        att2 = Attestation(b"v2", block_hash, 10, None)

        self.tracker.add_attestation(att1, 200, 300)
        self.tracker.add_attestation(att2, 100, 300)
        self.assertEqual(self.tracker.finalized_height, 10)

    def test_attested_stake_ratio(self):
        """Can query the fraction of stake that has attested."""
        block_hash = _hash(b"block1")
        att1 = Attestation(b"v1", block_hash, 1, None)
        self.tracker.add_attestation(att1, 100, 400)
        self.assertAlmostEqual(
            self.tracker.get_attested_stake_ratio(block_hash, 400),
            0.25,
        )


class TestAttestationsInBlocks(unittest.TestCase):
    """Test attestations flowing through the block pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        cls.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris", private_key=b"bob-private-key")
        cls.carol = Entity.create(b"carol-dna", b"carol-finger", b"carol-iris", private_key=b"carol-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.chain.supply.balances[self.carol.entity_id] = 10000
        self.consensus = ProofOfStake()

    def test_block_with_valid_attestations(self):
        """Block containing valid attestations for parent is accepted."""
        # Create block 1 (no attestations — genesis has none to vote on)
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        success, _ = self.chain.add_block(block1)
        self.assertTrue(success)

        # Create attestations for block1
        att_bob = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att_carol = create_attestation(self.carol, block1.block_hash, block1.header.block_number)

        # Create block 2 carrying attestations for block 1
        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att_bob, att_carol]
        )
        success, reason = self.chain.add_block(block2)
        self.assertTrue(success, reason)

    def test_block_with_wrong_target_attestation_rejected(self):
        """Attestation referencing wrong block is rejected."""
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        self.chain.add_block(block1)

        # Attestation for a different block
        wrong_hash = _hash(b"wrong_block")
        att = create_attestation(self.bob, wrong_hash, block1.header.block_number)

        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att]
        )
        success, reason = self.chain.add_block(block2)
        self.assertFalse(success)
        self.assertIn("wrong block", reason.lower())

    def test_block_with_invalid_attestation_signature_rejected(self):
        """Attestation with forged signature is rejected."""
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        self.chain.add_block(block1)

        # Create attestation signed by bob but claim it's from carol
        att = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att.validator_id = self.carol.entity_id  # forge the validator_id

        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att]
        )
        success, reason = self.chain.add_block(block2)
        self.assertFalse(success)
        self.assertIn("invalid attestation signature", reason.lower())

    def test_duplicate_attestation_in_block_rejected(self):
        """Same validator attesting twice in one block is rejected."""
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        self.chain.add_block(block1)

        att1 = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att2 = create_attestation(self.bob, block1.block_hash, block1.header.block_number)

        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att1, att2]
        )
        success, reason = self.chain.add_block(block2)
        self.assertFalse(success)
        self.assertIn("duplicate attestation", reason.lower())

    def test_attestation_from_unknown_entity_rejected(self):
        """Attestation from unregistered entity is rejected."""
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        self.chain.add_block(block1)

        stranger = Entity.create(b"stranger-dna", b"stranger-finger", b"stranger-iris", private_key=b"stranger-private-key")
        att = create_attestation(stranger, block1.block_hash, block1.header.block_number)

        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att]
        )
        success, reason = self.chain.add_block(block2)
        self.assertFalse(success)
        self.assertIn("unknown entity", reason.lower())

    def test_block_serialization_with_attestations(self):
        """Block with attestations survives serialization roundtrip."""
        prev = self.chain.get_latest_block()
        block1 = self.consensus.create_block(self.alice, [], prev)
        self.chain.add_block(block1)

        att = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        block2 = self.consensus.create_block(
            self.alice, [], block1, attestations=[att]
        )

        data = block2.serialize()
        restored = Block.deserialize(data)
        self.assertEqual(len(restored.attestations), 1)
        self.assertEqual(restored.attestations[0].validator_id, self.bob.entity_id)
        self.assertEqual(restored.attestations[0].block_hash, block1.block_hash)


class TestFinality(unittest.TestCase):
    """Test that finalized blocks cannot be reverted."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        cls.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris", private_key=b"bob-private-key")
        cls.carol = Entity.create(b"carol-dna", b"carol-finger", b"carol-iris", private_key=b"carol-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.chain.supply.balances[self.carol.entity_id] = 10000
        # Stake validators so they have weight
        self.chain.supply.stake(self.alice.entity_id, 1000)
        self.chain.supply.stake(self.bob.entity_id, 1000)
        self.chain.supply.stake(self.carol.entity_id, 1000)
        self.consensus = ProofOfStake()

    def test_block_finalized_with_sufficient_attestations(self):
        """Block becomes finalized when 2/3+ stake attests."""
        block1 = self.chain.propose_block(self.consensus, self.alice, [])
        self.chain.add_block(block1)

        # All 3 validators attest (3000/3000 = 1.0 >= 0.67)
        # Note: 2/3 = 0.6667 < 0.67 threshold, so need all 3
        att_alice = create_attestation(self.alice, block1.block_hash, block1.header.block_number)
        att_bob = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att_carol = create_attestation(self.carol, block1.block_hash, block1.header.block_number)

        block2 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=[att_alice, att_bob, att_carol]
        )
        self.chain.add_block(block2)

        self.assertTrue(self.chain.finality.is_finalized(block1.block_hash))

    def test_block_not_finalized_with_insufficient_attestations(self):
        """Block stays unfinalized with less than 2/3 attestation."""
        prev = self.chain.get_latest_block()
        block1 = self.consensus.create_block(self.alice, [], prev)
        self.chain.add_block(block1)

        # Only 1 of 3 validators attests (1000/3000 = 0.33)
        att_bob = create_attestation(self.bob, block1.block_hash, block1.header.block_number)

        block2 = self.consensus.create_block(
            self.alice, [], block1, attestations=[att_bob]
        )
        self.chain.add_block(block2)

        self.assertFalse(self.chain.finality.is_finalized(block1.block_hash))


class TestDoubleAttestationSlashing(unittest.TestCase):
    """Test slashing for double-attestation (nothing-at-stake attack)."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris", private_key=b"alice-private-key")
        cls.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris", private_key=b"bob-private-key")
        cls.carol = Entity.create(b"carol-dna", b"carol-finger", b"carol-iris", private_key=b"carol-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.chain.supply.balances[self.carol.entity_id] = 10000
        self.chain.supply.stake(self.alice.entity_id, 1000)

    def test_valid_double_attestation_evidence(self):
        """Two attestations for different blocks at same height = valid evidence."""
        block_hash_a = _hash(b"block_a")
        block_hash_b = _hash(b"block_b")

        att_a = create_attestation(self.alice, block_hash_a, block_number=5)
        att_b = create_attestation(self.alice, block_hash_b, block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        valid, reason = verify_attestation_slashing_evidence(evidence, self.alice.public_key)
        self.assertTrue(valid, reason)

    def test_same_block_attestation_not_evidence(self):
        """Two attestations for the same block are not conflicting."""
        block_hash = _hash(b"same_block")
        att_a = create_attestation(self.alice, block_hash, block_number=5)
        att_b = create_attestation(self.alice, block_hash, block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        valid, reason = verify_attestation_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("not conflicting", reason)

    def test_different_heights_not_evidence(self):
        """Attestations at different heights are not double-attestation."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=6)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        valid, reason = verify_attestation_slashing_evidence(evidence, self.alice.public_key)
        self.assertFalse(valid)
        self.assertIn("different heights", reason)

    def test_wrong_validator_rejected(self):
        """Evidence naming wrong offender is rejected."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.bob.entity_id,  # wrong
            attestation_a=att_a,
            attestation_b=att_b,
        )

        valid, reason = verify_attestation_slashing_evidence(evidence, self.bob.public_key)
        self.assertFalse(valid)
        self.assertIn("does not match offender", reason)

    def test_forged_signature_rejected(self):
        """Evidence with invalid signatures is rejected."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        # Verify against wrong key
        valid, reason = verify_attestation_slashing_evidence(evidence, self.bob.public_key)
        self.assertFalse(valid)
        self.assertIn("signature is invalid", reason)

    def test_double_attestation_slash_on_chain(self):
        """Double-attestation evidence can slash a validator via the blockchain."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        slash_tx = create_slash_transaction(self.bob, evidence, fee=1)
        success, msg = self.chain.apply_slash_transaction(slash_tx, self.carol.entity_id)
        self.assertTrue(success, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)
        self.assertIn(self.alice.entity_id, self.chain.slashed_validators)

    def test_attestation_slash_evidence_serialization(self):
        """AttestationSlashingEvidence survives serialization roundtrip."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )

        data = evidence.serialize()
        restored = AttestationSlashingEvidence.deserialize(data)
        self.assertEqual(restored.offender_id, evidence.offender_id)
        self.assertEqual(restored.evidence_hash, evidence.evidence_hash)

    def test_slash_tx_with_attestation_evidence_serialization(self):
        """SlashTransaction with attestation evidence serializes correctly."""
        att_a = create_attestation(self.alice, _hash(b"a"), block_number=5)
        att_b = create_attestation(self.alice, _hash(b"b"), block_number=5)

        evidence = AttestationSlashingEvidence(
            offender_id=self.alice.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=5)

        data = slash_tx.serialize()
        restored = SlashTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, slash_tx.tx_hash)
        self.assertIsInstance(restored.evidence, AttestationSlashingEvidence)
        self.assertEqual(restored.evidence.offender_id, self.alice.entity_id)


if __name__ == "__main__":
    unittest.main()
