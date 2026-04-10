"""Tests for stake-weighted governance voting.

Voting power is determined by staked tokens, not wallet balance.
Only entities with skin in the game (staked tokens) can influence governance.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
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
        content_hash = _hash(b"diff contents")
        self.proposal_tx = create_proposal(
            self.alice, "https://github.com/user/repo/pull/1",
            content_hash, "Stake-weighted governance",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100)

    def test_unstaked_entity_has_zero_voting_power(self):
        """An entity with tokens but no stake has zero voting power."""
        # Alice has 10,000 balance but 0 stake
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        self.assertEqual(yes_weight, 0)
        self.assertEqual(total_weight, 0)

    def test_staked_entity_voting_power_equals_stake(self):
        """Voting power equals staked amount, not wallet balance."""
        # Bob has 100 balance but 5000 stake
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        self.assertEqual(yes_weight, 5000)
        self.assertEqual(total_weight, 5000)

    def test_stake_weighted_majority(self):
        """Proposal passes when majority of participating stake votes yes."""
        # Bob (5000 stake) votes yes, Carol (3000 stake) votes no
        vote_yes = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes)
        self.tracker.add_vote(vote_no)

        # 5000 / 8000 = 62.5% > 50%
        self.assertTrue(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_stake_weighted_rejection(self):
        """Proposal rejected when majority of participating stake votes no."""
        # Dave (1000 stake) votes yes, Carol (3000 stake) votes no
        vote_yes = create_vote(self.dave, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes)
        self.tracker.add_vote(vote_no)

        # 1000 / 4000 = 25% < 50%
        self.assertFalse(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_high_balance_low_stake_loses_to_low_balance_high_stake(self):
        """Balance is irrelevant — only stake determines outcome."""
        # Alice (10k balance, 0 stake) votes no
        # Bob (100 balance, 5k stake) votes yes
        vote_alice = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)
        vote_bob = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote_alice)
        self.tracker.add_vote(vote_bob)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Alice contributes 0 (no stake), Bob contributes 5000
        self.assertEqual(yes_weight, 5000)
        self.assertEqual(total_weight, 5000)


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
        content_hash = _hash(b"diff")
        self.proposal_tx = create_proposal(
            self.alice, "https://github.com/user/repo/pull/2",
            content_hash, "Test delegation",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=50)

    def test_delegation_carries_stake_not_balance(self):
        """Delegated voting power is the delegator's stake, not balance."""
        # Alice (2000 stake, 10k balance) delegates to Bob (500 stake)
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)

        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Bob's stake (500) + Alice's delegated stake (2000) = 2500
        self.assertEqual(yes_weight, 2500)
        self.assertEqual(total_weight, 2500)

    def test_direct_vote_overrides_delegation_with_stake(self):
        """Direct vote uses voter's own stake, overriding delegation."""
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)

        vote_bob = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_alice = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_bob)
        self.tracker.add_vote(vote_alice)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Bob: 500 yes. Alice: 2000 no (direct override). Total: 2500.
        self.assertEqual(yes_weight, 500)
        self.assertEqual(total_weight, 2500)

    def test_unstaked_delegator_adds_zero_weight(self):
        """Delegator with no stake adds zero to delegate's voting power."""
        # Give Alice zero stake
        self.supply.staked[self.alice.entity_id] = 0

        self.tracker.set_delegation(self.alice.entity_id, self.carol.entity_id)

        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Only Carol's stake (3000), Alice's 0 stake adds nothing
        self.assertEqual(yes_weight, 3000)
        self.assertEqual(total_weight, 3000)


class TestStakeWeightedProposalStatus(unittest.TestCase):
    """Proposal status uses stake-weighted tally."""

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
        content_hash = _hash(b"diff")
        self.proposal_tx = create_proposal(
            self.alice, "https://github.com/user/repo/pull/3",
            content_hash, "Status test",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100)

    def test_approved_after_window_by_stake_majority(self):
        """Proposal approved after voting window if stake majority voted yes."""
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)
        # Alice: 5000 stake yes, Bob didn't vote -> 5000/5000 = 100%

        from messagechain.governance.governance import ProposalStatus
        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block, self.supply,
        )
        self.assertEqual(status, ProposalStatus.APPROVED)

    def test_expired_when_only_unstaked_voted(self):
        """Proposal expires if only unstaked entities voted (zero weight)."""
        # Remove Alice's stake
        self.supply.staked[self.alice.entity_id] = 0

        vote = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        from messagechain.governance.governance import ProposalStatus
        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block, self.supply,
        )
        # total_weight = 0, so EXPIRED
        self.assertEqual(status, ProposalStatus.EXPIRED)


if __name__ == "__main__":
    unittest.main()
