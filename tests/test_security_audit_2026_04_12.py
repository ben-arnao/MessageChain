"""
Security audit test suite — Full codebase audit 2026-04-12.

Tests for all Critical, High, and selected Medium/Low findings.
Written FIRST per TDD — these tests define the expected behavior.
"""

import copy
import os
import struct
import time
import unittest

from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    GOVERNANCE_PROPOSAL_FEE,
    MIN_FEE,
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
    UNBONDING_PERIOD,
    WOTS_KEY_CHAINS,
    WOTS_CHAIN_LENGTH,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    TreasurySpendTransaction,
    create_proposal,
    create_vote,
    create_treasury_spend_proposal,
    ProposalStatus,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.sig_cache import SignatureCache
from messagechain.crypto.hash_sig import _message_to_base_w, _chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entity():
    return Entity.create(os.urandom(32))


def _setup_chain():
    from messagechain.core.blockchain import Blockchain
    bc = Blockchain()
    entity = _make_entity()
    bc.initialize_genesis(entity)
    return bc, entity


def _hash(data: bytes) -> bytes:
    import hashlib
    return hashlib.new("sha3_256", data).digest()


# ===========================================================================
# C1-C3: Negative/zero amount checks in transfer/stake/unstake
# ===========================================================================


class TestNegativeAmountChecks(unittest.TestCase):

    def setUp(self):
        self.supply = SupplyTracker()
        self.a = b"\x01" * 32
        self.b = b"\x02" * 32
        self.supply.balances[self.a] = 10_000
        self.supply.balances[self.b] = 5_000

    def test_transfer_rejects_negative(self):
        self.assertFalse(self.supply.transfer(self.a, self.b, -1000))
        self.assertEqual(self.supply.get_balance(self.a), 10_000)

    def test_transfer_rejects_zero(self):
        self.assertFalse(self.supply.transfer(self.a, self.b, 0))

    def test_stake_rejects_negative(self):
        self.assertFalse(self.supply.stake(self.a, -500))
        self.assertEqual(self.supply.get_staked(self.a), 0)

    def test_stake_rejects_zero(self):
        self.assertFalse(self.supply.stake(self.a, 0))

    def test_unstake_rejects_negative(self):
        self.supply.stake(self.a, 5000)
        self.assertFalse(self.supply.unstake(self.a, -100))
        self.assertEqual(self.supply.get_staked(self.a), 5000)

    def test_unstake_rejects_zero(self):
        self.supply.stake(self.a, 5000)
        self.assertFalse(self.supply.unstake(self.a, 0))


# ===========================================================================
# C4-C5: Treasury spend requires vote approval
# ===========================================================================


class TestTreasuryVoteRequired(unittest.TestCase):

    def setUp(self):
        self.supply = SupplyTracker()
        self.supply.balances[TREASURY_ENTITY_ID] = 40_000_000
        self.gov = GovernanceTracker()
        self.voter = _make_entity()
        self.supply.balances[self.voter.entity_id] = 100_000
        self.supply.staked[self.voter.entity_id] = 50_000

    def _make_spend(self, amount=1000):
        return create_treasury_spend_proposal(
            self.voter, self.voter.entity_id, amount,
            "Fund project", "For the good of the chain",
        )

    def test_rejected_without_proposal(self):
        tx = self._make_spend()
        self.assertFalse(self.gov.execute_treasury_spend(
            tx, self.supply, current_block=9999))

    def test_rejected_while_voting_open(self):
        tx = self._make_spend()
        self.gov.add_proposal(tx, 100, self.supply)
        self.assertFalse(self.gov.execute_treasury_spend(
            tx, self.supply, current_block=100))

    def test_rejected_without_majority_yes(self):
        tx = self._make_spend()
        self.gov.add_proposal(tx, 100, self.supply)
        vote = create_vote(self.voter, tx.proposal_id, approve=False)
        self.gov.add_vote(vote, 101)
        closed = 100 + GOVERNANCE_VOTING_WINDOW + 1
        self.assertFalse(self.gov.execute_treasury_spend(
            tx, self.supply, current_block=closed))

    def test_accepted_with_majority_yes(self):
        tx = self._make_spend(1000)
        self.gov.add_proposal(tx, 100, self.supply)
        vote = create_vote(self.voter, tx.proposal_id, approve=True)
        self.gov.add_vote(vote, 101)
        closed = 100 + GOVERNANCE_VOTING_WINDOW + 1
        self.assertTrue(self.gov.execute_treasury_spend(
            tx, self.supply, current_block=closed))
        self.assertEqual(
            self.supply.get_balance(TREASURY_ENTITY_ID), 40_000_000 - 1000)


# ===========================================================================
# C7: Genesis block validation
# ===========================================================================


class TestGenesisValidation(unittest.TestCase):

    def test_rejects_nongenesis_as_first_block(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.block import Block, BlockHeader
        bc = Blockchain()
        header = BlockHeader(
            version=1, block_number=5,
            prev_hash=b"\xab" * 32,
            merkle_root=_hash(b"fake"),
            timestamp=time.time(),
            proposer_id=b"\x01" * 32,
        )
        fake = Block(header=header, transactions=[])
        ok, _ = bc.add_block(fake)
        self.assertFalse(ok)


# ===========================================================================
# C8-C9: Snapshot completeness
# ===========================================================================


class TestSnapshotCompleteness(unittest.TestCase):

    def test_processed_evidence_in_snapshot(self):
        bc, e = _setup_chain()
        bc._processed_evidence.add(b"\xaa" * 32)
        snap = bc._snapshot_memory_state()
        self.assertIn(b"\xaa" * 32, snap["processed_evidence"])

    def test_processed_evidence_restored(self):
        bc, e = _setup_chain()
        bc._processed_evidence.add(b"\xaa" * 32)
        snap = bc._snapshot_memory_state()
        bc._processed_evidence.clear()
        bc._restore_memory_snapshot(snap)
        self.assertIn(b"\xaa" * 32, bc._processed_evidence)

    def test_pending_unstakes_in_snapshot(self):
        bc, e = _setup_chain()
        bc.supply.pending_unstakes[e.entity_id] = [(500, 100)]
        snap = bc._snapshot_memory_state()
        self.assertEqual(snap["pending_unstakes"][e.entity_id], [(500, 100)])

    def test_pending_unstakes_restored(self):
        bc, e = _setup_chain()
        bc.supply.pending_unstakes[e.entity_id] = [(500, 100)]
        snap = bc._snapshot_memory_state()
        bc.supply.pending_unstakes.clear()
        bc._restore_memory_snapshot(snap)
        self.assertEqual(bc.supply.pending_unstakes[e.entity_id], [(500, 100)])


# ===========================================================================
# H3: Signature cache — no False caching (poison resistance)
# ===========================================================================


class TestSigCacheNoFalseCaching(unittest.TestCase):

    def test_false_not_cached(self):
        c = SignatureCache(100)
        c.store(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, False)
        self.assertIsNone(c.lookup(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32))

    def test_true_is_cached(self):
        c = SignatureCache(100)
        c.store(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, True)
        self.assertTrue(c.lookup(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32))


# ===========================================================================
# H2: Entity repr must not leak seed
# ===========================================================================


class TestEntityReprSafe(unittest.TestCase):

    def test_repr_hides_seed(self):
        e = _make_entity()
        self.assertNotIn(e._seed.hex(), repr(e))

    def test_str_hides_seed(self):
        e = _make_entity()
        self.assertNotIn(e._seed.hex(), str(e))


# ===========================================================================
# H8: Merkle duplicate-padding (CVE-2012-2459)
# ===========================================================================


class TestMerklePadding(unittest.TestCase):

    def test_no_collision_with_duplicated_last(self):
        from messagechain.core.block import compute_merkle_root
        a, b, c = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        self.assertNotEqual(
            compute_merkle_root([a, b, c]),
            compute_merkle_root([a, b, c, c]),
        )


# ===========================================================================
# H10: Block version must be validated
# ===========================================================================


class TestBlockVersionCheck(unittest.TestCase):

    def test_rejects_unknown_version(self):
        bc, entity = _setup_chain()
        from messagechain.core.block import Block, BlockHeader
        genesis = bc.get_latest_block()
        header = BlockHeader(
            version=999, block_number=1,
            prev_hash=genesis.block_hash,
            merkle_root=_hash(b"empty"),
            timestamp=time.time() + 1,
            proposer_id=entity.entity_id,
        )
        header_hash = _hash(header.signable_data())
        header.proposer_signature = entity.keypair.sign(header_hash)
        blk = Block(header=header, transactions=[])
        blk.block_hash = blk._compute_hash()
        valid, reason = bc.validate_block(blk)
        self.assertFalse(valid)


# ===========================================================================
# M2: _chain uses proper exceptions (not assert)
# ===========================================================================


class TestChainBoundsExceptions(unittest.TestCase):

    def test_negative_start(self):
        with self.assertRaises(ValueError):
            _chain(b"\x00" * 32, -1, 1, b"\x00" * 32, 0)

    def test_overflow(self):
        with self.assertRaises(ValueError):
            _chain(b"\x00" * 32, 10, 10, b"\x00" * 32, 0)

    def test_negative_steps(self):
        with self.assertRaises(ValueError):
            _chain(b"\x00" * 32, 0, -1, b"\x00" * 32, 0)


# ===========================================================================
# M1: WOTS+ checksum digit count
# ===========================================================================


class TestWOTSChecksumDigits(unittest.TestCase):

    def test_digit_count_equals_key_chains(self):
        digits = _message_to_base_w(b"\xff" * 32)
        self.assertEqual(len(digits), WOTS_KEY_CHAINS)

    def test_checksum_covers_full_range(self):
        """The number of checksum digits must cover max checksum value."""
        # msg_digits count
        msg_digit_count = WOTS_KEY_CHAINS - 4  # currently 60
        max_checksum = msg_digit_count * WOTS_CHAIN_LENGTH  # 900
        # Minimum nibbles needed to represent max_checksum in base-16
        import math
        min_nibbles = math.ceil(math.log(max_checksum + 1, 16)) if max_checksum > 0 else 1
        checksum_slots = WOTS_KEY_CHAINS - msg_digit_count
        self.assertGreaterEqual(checksum_slots, min_nibbles)


# ===========================================================================
# L3: WOTS+ private key zeroization after use
# ===========================================================================


class TestKeyZeroization(unittest.TestCase):

    def test_used_leaf_zeroed(self):
        e = _make_entity()
        idx = e.keypair._next_leaf
        e.keypair.sign(b"\xab" * 32)
        priv = e.keypair._wots_keys[idx][0]
        self.assertIsNone(priv, "Used WOTS+ private keys should be None after signing")


# ===========================================================================
# H9: Key rotation rejects duplicate public key
# ===========================================================================


class TestKeyRotationNoDuplicatePK(unittest.TestCase):

    def test_blockchain_rejects_rotation_to_existing_pk(self):
        bc, entity_a = _setup_chain()
        entity_b = _make_entity()
        proof = entity_b.keypair.sign(_hash(b"register" + entity_b.entity_id))
        bc.register_entity(entity_b.entity_id, entity_b.public_key, proof)
        # The public_keys dict should contain both keys
        self.assertIn(entity_a.public_key, bc.public_keys.values())
        self.assertIn(entity_b.public_key, bc.public_keys.values())
        # Attempting to rotate entity_a's key to entity_b's key
        # should be blocked by validate_key_rotation
        from messagechain.core.key_rotation import KeyRotationTransaction
        from messagechain.crypto.keys import Signature
        fake_tx = KeyRotationTransaction(
            entity_id=entity_a.entity_id,
            old_public_key=entity_a.public_key,
            new_public_key=entity_b.public_key,
            rotation_number=0,
            fee=1000,
            timestamp=time.time(),
            signature=Signature([], 0, [], b"\x00" * 32, b"\x00" * 32),
        )
        valid, reason = bc.validate_key_rotation(fake_tx)
        self.assertFalse(valid)
        self.assertIn("already", reason.lower())


# ===========================================================================
# M12: Default delegation should not auto-assign passive stake
# ===========================================================================


class TestNoDefaultDelegation(unittest.TestCase):

    def test_passive_stake_not_auto_delegated(self):
        supply = SupplyTracker()
        gov = GovernanceTracker()
        voter = _make_entity()
        passive = _make_entity()
        supply.staked[voter.entity_id] = 100
        supply.staked[passive.entity_id] = 10_000

        tx = create_proposal(voter, "test", "desc")
        gov.add_proposal(tx, 0, supply)
        vote = create_vote(voter, tx.proposal_id, approve=True)
        gov.add_vote(vote, 1)

        yes, total = gov.tally(tx.proposal_id)
        # Only the voter's stake should count — passive entity should NOT
        # have their weight auto-distributed
        self.assertEqual(yes, 100)
        self.assertEqual(total, 100)


if __name__ == "__main__":
    unittest.main()
