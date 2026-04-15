"""Tests for genesis allocation table and treasury.

The genesis block distributes tokens according to a hardcoded allocation
table instead of giving everything to a single entity. A governance-
controlled treasury receives the bulk of the non-validator allocation.
"""

import hashlib
import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    GENESIS_SUPPLY, GENESIS_ALLOCATION, VALIDATOR_MIN_STAKE,
    HASH_ALGO,
)
from tests import register_entity_for_test


class TestGenesisAllocationTable(unittest.TestCase):
    """Genesis block distributes tokens to multiple recipients."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0

    def test_single_entity_backward_compat(self):
        """Calling initialize_genesis with one entity still works as before."""
        chain = Blockchain()
        chain.initialize_genesis(self.alice)
        self.assertEqual(chain.supply.get_balance(self.alice.entity_id), GENESIS_ALLOCATION)

    def test_allocation_table_distributes_to_multiple_entities(self):
        """An allocation table distributes tokens to all listed entities."""
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 5000,
            self.bob.entity_id: 3000,
        }
        chain.initialize_genesis(self.alice, allocation_table=allocation)

        self.assertEqual(chain.supply.get_balance(self.alice.entity_id), 5000)
        self.assertEqual(chain.supply.get_balance(self.bob.entity_id), 3000)

    def test_allocation_table_total_cannot_exceed_genesis_supply(self):
        """Allocation table total must not exceed GENESIS_SUPPLY."""
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: GENESIS_SUPPLY + 1,
        }
        with self.assertRaises(ValueError):
            chain.initialize_genesis(self.alice, allocation_table=allocation)

    def test_allocation_table_preserves_total_supply(self):
        """Total supply remains GENESIS_SUPPLY regardless of allocation."""
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 5000,
            self.bob.entity_id: 3000,
        }
        chain.initialize_genesis(self.alice, allocation_table=allocation)
        self.assertEqual(chain.supply.total_supply, GENESIS_SUPPLY)

    def test_allocation_rejects_zero_amount(self):
        """Zero-amount allocations are rejected."""
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 0,
        }
        with self.assertRaises(ValueError):
            chain.initialize_genesis(self.alice, allocation_table=allocation)

    def test_allocation_rejects_negative_amount(self):
        """Negative allocations are rejected."""
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: -100,
        }
        with self.assertRaises(ValueError):
            chain.initialize_genesis(self.alice, allocation_table=allocation)


class TestTreasuryEntity(unittest.TestCase):
    """Treasury is a special entity whose funds are governance-controlled."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def test_treasury_entity_id_is_deterministic(self):
        """TREASURY_ENTITY_ID is a well-known constant."""
        from messagechain.config import TREASURY_ENTITY_ID
        # Must be 32 bytes (SHA3-256 output)
        self.assertEqual(len(TREASURY_ENTITY_ID), 32)

    def test_treasury_receives_allocation(self):
        """Treasury receives its allocation in genesis."""
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 5000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(self.alice, allocation_table=allocation)
        self.assertEqual(
            chain.supply.get_balance(TREASURY_ENTITY_ID),
            TREASURY_ALLOCATION,
        )

    def test_treasury_cannot_be_spent_via_normal_transfer(self):
        """Treasury funds cannot move via regular transfer transactions."""
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 5000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(self.alice, allocation_table=allocation)

        # Direct supply.transfer from treasury should be blocked
        result = chain.supply.transfer(TREASURY_ENTITY_ID, self.alice.entity_id, 100)
        self.assertFalse(result)

    def test_default_allocation_table_includes_treasury(self):
        """The default allocation table includes treasury and genesis validator."""
        from messagechain.config import (
            TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
            DEFAULT_GENESIS_ALLOCATIONS,
        )
        self.assertIn(TREASURY_ENTITY_ID, DEFAULT_GENESIS_ALLOCATIONS)
        self.assertEqual(DEFAULT_GENESIS_ALLOCATIONS[TREASURY_ENTITY_ID], TREASURY_ALLOCATION)


class TestTreasurySpend(unittest.TestCase):
    """Treasury funds can only move via approved governance proposals."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0

    def _setup_chain_with_treasury(self):
        """Create a chain with treasury allocation and staked validators."""
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        chain = Blockchain()
        allocation = {
            self.alice.entity_id: 100_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(self.alice, allocation_table=allocation)
        return chain

    def test_create_treasury_spend_proposal(self):
        """A treasury spend proposal specifies recipient and amount."""
        from messagechain.governance.governance import create_treasury_spend_proposal
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 1000,
            "Fund development", "Pay Bob for protocol work",
        )
        self.assertEqual(tx.recipient_id, self.bob.entity_id)
        self.assertEqual(tx.amount, 1000)
        self.assertTrue(len(tx.tx_hash) == 32)

    def test_verify_treasury_spend_proposal(self):
        """Treasury spend proposals must have valid signatures."""
        from messagechain.governance.governance import (
            create_treasury_spend_proposal, verify_treasury_spend,
        )
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 1000,
            "Fund dev", "Pay Bob",
        )
        self.assertTrue(verify_treasury_spend(tx, self.alice.public_key))

    def test_treasury_spend_rejects_zero_amount(self):
        """Treasury spend with zero amount is invalid."""
        from messagechain.governance.governance import (
            create_treasury_spend_proposal, verify_treasury_spend,
        )
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 0,
            "Bad proposal", "Zero amount",
        )
        self.assertFalse(verify_treasury_spend(tx, self.alice.public_key))

    def _approve_treasury_spend(self, tracker, tx, chain):
        """Helper: register treasury spend as proposal, vote yes, close window."""
        from messagechain.config import GOVERNANCE_VOTING_WINDOW
        from messagechain.governance.governance import (
            VoteTransaction, ProposalTransaction,
        )
        # Register the spend as a proposal so execute can find it
        proposal_block = 10
        # Stake alice so she has voting power
        chain.supply.staked[self.alice.entity_id] = chain.supply.get_balance(self.alice.entity_id)
        tracker.add_proposal(tx, block_height=proposal_block, supply_tracker=chain.supply)
        # Cast a yes vote from alice
        vote = VoteTransaction(
            voter_id=self.alice.entity_id,
            proposal_id=tx.proposal_id,
            approve=True,
            timestamp=1.0,
            fee=100,
            signature=None,
        )
        vote.tx_hash = vote._compute_hash()
        tracker.add_vote(vote, current_block=proposal_block + 1)
        # Return a block number after the voting window closes
        return proposal_block + GOVERNANCE_VOTING_WINDOW + 1

    def test_treasury_spend_rejects_exceeding_balance(self):
        """Cannot spend more than treasury holds."""
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        chain = self._setup_chain_with_treasury()
        tracker = GovernanceTracker()

        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, TREASURY_ALLOCATION + 1,
            "Too much", "Exceeds treasury",
        )
        closed_block = self._approve_treasury_spend(tracker, tx, chain)
        result = tracker.execute_treasury_spend(tx, chain.supply, current_block=closed_block)
        self.assertFalse(result)

    def test_treasury_spend_executes_after_approval(self):
        """Approved treasury spend transfers funds to recipient."""
        from messagechain.config import TREASURY_ENTITY_ID, TREASURY_ALLOCATION
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        chain = self._setup_chain_with_treasury()
        tracker = GovernanceTracker()

        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5000,
            "Fund dev", "Pay Bob",
        )
        closed_block = self._approve_treasury_spend(tracker, tx, chain)
        result = tracker.execute_treasury_spend(tx, chain.supply, current_block=closed_block)
        self.assertTrue(result)
        self.assertEqual(chain.supply.get_balance(self.bob.entity_id), 5000)
        self.assertEqual(
            chain.supply.get_balance(TREASURY_ENTITY_ID),
            TREASURY_ALLOCATION - 5000,
        )

    def test_treasury_spend_cannot_execute_twice(self):
        """A treasury spend can only be executed once."""
        from messagechain.config import TREASURY_ENTITY_ID
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        chain = self._setup_chain_with_treasury()
        tracker = GovernanceTracker()

        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 1000,
            "Fund dev", "Pay Bob",
        )
        closed_block = self._approve_treasury_spend(tracker, tx, chain)
        self.assertTrue(tracker.execute_treasury_spend(tx, chain.supply, current_block=closed_block))
        self.assertFalse(tracker.execute_treasury_spend(tx, chain.supply, current_block=closed_block))

    def test_treasury_single_voter_capture_prevented(self):
        """A lone validator cannot drain the treasury by harvesting silence.

        The binding tally requires yes to clear 2/3 of TOTAL eligible
        stake (all snapshotted validators, voter or silent).  Silence
        counts as "no".  Without this, a single voter during apathy could
        pass any treasury spend unilaterally.
        """
        from messagechain.config import TREASURY_ENTITY_ID, GOVERNANCE_VOTING_WINDOW
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal, VoteTransaction,
        )
        chain = self._setup_chain_with_treasury()
        tracker = GovernanceTracker()
        # Three validators, only alice votes yes.  Bob and carol stay silent.
        # Under stakers-only tally: alice has 1/3 of eligible stake -> FAILS.
        chain.supply.staked[self.alice.entity_id] = 1000
        chain.supply.staked[self.bob.entity_id] = 1000
        chain.supply.staked[self.carol.entity_id] = 1000

        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 500, "Drain", "Capture attempt",
        )
        proposal_block = 5
        tracker.add_proposal(tx, block_height=proposal_block, supply_tracker=chain.supply)
        vote = VoteTransaction(
            voter_id=self.alice.entity_id,
            proposal_id=tx.proposal_id,
            approve=True,
            timestamp=1.0,
            fee=100,
            signature=None,
        )
        vote.tx_hash = vote._compute_hash()
        tracker.add_vote(vote, current_block=proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        result = tracker.execute_treasury_spend(tx, chain.supply, current_block=closed_block)
        self.assertFalse(result)

    def test_treasury_spend_serialization_roundtrip(self):
        """Treasury spend proposals serialize and deserialize correctly."""
        from messagechain.governance.governance import (
            create_treasury_spend_proposal, TreasurySpendTransaction,
        )
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5000,
            "Fund dev", "Pay Bob",
        )
        data = tx.serialize()
        restored = TreasurySpendTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.recipient_id, tx.recipient_id)
        self.assertEqual(restored.amount, tx.amount)


if __name__ == "__main__":
    unittest.main()
