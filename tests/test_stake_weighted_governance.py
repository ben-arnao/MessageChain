"""Tests for stake-weighted voting.

Voting power is determined by staked tokens, not wallet balance.
Only entities with skin in the game (staked tokens) can influence votes.
Voting power is snapshotted at proposal creation time.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    ProposalStatus,
    create_proposal,
    create_vote,
)
from messagechain.config import GOVERNANCE_VOTING_WINDOW
from messagechain.core.block import _hash


class TestStakeWeightedVoting(unittest.TestCase):
    """Voting power must come from staked tokens, not wallet balance."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")
        cls.carol = Entity.create(b"carol-private-key")
        cls.dave = Entity.create(b"dave-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.dave.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Alice: rich wallet but no stake
        self.supply.balances[self.alice.entity_id] = 10_000
        self.supply.staked[self.alice.entity_id] = 0
        # Bob: small wallet but large stake
        self.supply.balances[self.bob.entity_id] = 100
        self.supply.staked[self.bob.entity_id] = 5000
        # Carol: moderate wallet and moderate stake
        self.supply.balances[self.carol.entity_id] = 2000
        self.supply.staked[self.carol.entity_id] = 3000
        # Dave: some wallet, some stake
        self.supply.balances[self.dave.entity_id] = 500
        self.supply.staked[self.dave.entity_id] = 1000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(
            self.alice, "Stake-weighted governance", "Test stake weighting",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100, supply_tracker=self.supply)

    def test_unstaked_entity_has_zero_voting_power(self):
        """An entity with tokens but no stake has zero voting power."""
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        self.assertEqual(yes_weight, 0)
        self.assertEqual(total_weight, 0)

    def test_staked_entity_voting_power_equals_stake(self):
        """Voting power equals staked amount, not wallet balance."""
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Passive carol(3000) + dave(1000) default-delegate to bob
        self.assertEqual(yes_weight, 9000)
        self.assertEqual(total_weight, 9000)

    def test_stake_weighted_majority(self):
        """Tally reflects stake-weighted majority correctly."""
        vote_yes = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes, current_block=101)
        self.tracker.add_vote(vote_no, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Passive dave(1000) sqrt-distributed to bob & carol
        self.assertEqual(yes_weight, 5564)
        self.assertEqual(total_weight, 9000)

    def test_stake_weighted_rejection(self):
        """Tally reflects stake-weighted rejection correctly."""
        vote_yes = create_vote(self.dave, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes, current_block=101)
        self.tracker.add_vote(vote_no, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Passive bob(5000) sqrt-distributed to dave & carol
        self.assertEqual(yes_weight, 2824)
        self.assertEqual(total_weight, 9000)

    def test_high_balance_low_stake_loses_to_low_balance_high_stake(self):
        """Balance is irrelevant — only stake determines voting power."""
        vote_alice = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)
        vote_bob = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote_alice, current_block=101)
        self.tracker.add_vote(vote_bob, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Alice has 0 stake, passive carol(3000) + dave(1000) go to bob
        self.assertEqual(yes_weight, 9000)
        self.assertEqual(total_weight, 9000)


class TestStakeWeightedDelegation(unittest.TestCase):
    """Delegation carries delegator's staked amount, not balance."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")
        cls.carol = Entity.create(b"carol-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 10_000
        self.supply.staked[self.alice.entity_id] = 2000
        self.supply.balances[self.bob.entity_id] = 100
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.carol.entity_id] = 50
        self.supply.staked[self.carol.entity_id] = 3000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(
            self.alice, "Test delegation", "Test delegation mechanics",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=50, supply_tracker=self.supply)

    def test_delegation_carries_stake_not_balance(self):
        """Delegated voting power is the delegator's stake, not balance."""
        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])

        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Bob(500) + alice delegation(2000) + passive carol(3000)
        self.assertEqual(yes_weight, 5500)
        self.assertEqual(total_weight, 5500)

    def test_direct_vote_overrides_delegation_with_stake(self):
        """Direct vote uses voter's own stake, overriding delegation."""
        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])

        vote_bob = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_alice = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_bob, current_block=51)
        self.tracker.add_vote(vote_alice, current_block=51)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Bob(500) yes + alice(2000) no (override) + passive carol(3000) sqrt-distributed
        self.assertEqual(yes_weight, 1500)
        self.assertEqual(total_weight, 5500)

    def test_unstaked_delegator_adds_zero_weight(self):
        """Delegator with no stake adds zero to delegate's voting power."""
        self.supply.staked[self.alice.entity_id] = 0

        # Re-create proposal with updated supply (Alice now has 0 stake in snapshot)
        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(
            self.alice, "Test delegation", "Test delegation mechanics",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=50, supply_tracker=self.supply)

        self.tracker.set_delegation(self.alice.entity_id, [(self.carol.entity_id, 100)])

        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Carol(3000) + alice delegation(0) + passive bob(500)
        self.assertEqual(yes_weight, 3500)
        self.assertEqual(total_weight, 3500)


class TestStakeWeightedProposalStatus(unittest.TestCase):
    """Proposal status transitions."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 100
        self.supply.staked[self.alice.entity_id] = 5000
        self.supply.balances[self.bob.entity_id] = 100
        self.supply.staked[self.bob.entity_id] = 1000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(
            self.alice, "Status test", "Test proposal status",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100, supply_tracker=self.supply)

    def test_open_during_voting_window(self):
        """Proposal is OPEN during voting window regardless of votes."""
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        status = self.tracker.get_proposal_status(self.proposal_tx.proposal_id, 150)
        self.assertEqual(status, ProposalStatus.OPEN)

    def test_closed_after_window(self):
        """Proposal is CLOSED after voting window ends."""
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(self.proposal_tx.proposal_id, expired_block)
        self.assertEqual(status, ProposalStatus.CLOSED)

    def test_closed_when_only_unstaked_voted(self):
        """Proposal closes normally even if only unstaked entities voted."""
        self.supply.staked[self.alice.entity_id] = 0

        # Need fresh proposal to snapshot the 0 stake
        tracker = GovernanceTracker()
        proposal_tx = create_proposal(self.alice, "Status test 2", "desc")
        tracker.add_proposal(proposal_tx, block_height=100, supply_tracker=self.supply)

        vote = create_vote(self.alice, proposal_tx.proposal_id, approve=True)
        tracker.add_vote(vote, current_block=101)

        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = tracker.get_proposal_status(proposal_tx.proposal_id, expired_block)
        self.assertEqual(status, ProposalStatus.CLOSED)


if __name__ == "__main__":
    unittest.main()
