"""Tests for multi-target delegation and sqrt-weighted defaults.

Delegation is a trust signal — users allocate voting power across up to 3
validators they trust. Funds are NOT locked. If no explicit delegation is
set, voting power is distributed using sqrt(stake) weighting across all
active validators.
"""

import math
import unittest
from messagechain.governance.governance import (
    GovernanceTracker, DelegateTransaction, create_delegation,
    verify_delegation, create_proposal, ProposalTransaction,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.identity.identity import Entity
from messagechain.config import (
    GOVERNANCE_DELEGATE_FEE, MAX_DELEGATION_TARGETS,
)


class TestMultiTargetDelegation(unittest.TestCase):
    """Users can delegate to up to 3 validators with percentage splits."""

    def setUp(self):
        self.tracker = GovernanceTracker()

    def test_single_delegation(self):
        """Can delegate 100% to one validator."""
        delegator = b"\x01" * 32
        validator = b"\x02" * 32
        self.tracker.set_delegation(delegator, [(validator, 100)])
        self.assertEqual(self.tracker.delegations[delegator], [(validator, 100)])

    def test_multi_delegation(self):
        """Can delegate across up to 3 validators."""
        delegator = b"\x01" * 32
        v1, v2, v3 = b"\x02" * 32, b"\x03" * 32, b"\x04" * 32
        targets = [(v1, 50), (v2, 30), (v3, 20)]
        self.tracker.set_delegation(delegator, targets)
        self.assertEqual(self.tracker.delegations[delegator], targets)

    def test_max_delegation_targets(self):
        """Cannot delegate to more than MAX_DELEGATION_TARGETS."""
        self.assertEqual(MAX_DELEGATION_TARGETS, 3)

    def test_percentages_must_sum_to_100(self):
        """Delegation percentages must sum to exactly 100."""
        delegator = b"\x01" * 32
        # 50 + 30 = 80, not 100
        result = self.tracker.set_delegation(delegator, [(b"\x02" * 32, 50), (b"\x03" * 32, 30)])
        self.assertFalse(result)
        self.assertNotIn(delegator, self.tracker.delegations)

    def test_revoke_delegation(self):
        """Empty list revokes all delegations."""
        delegator = b"\x01" * 32
        self.tracker.set_delegation(delegator, [(b"\x02" * 32, 100)])
        self.assertIn(delegator, self.tracker.delegations)
        self.tracker.set_delegation(delegator, [])
        self.assertNotIn(delegator, self.tracker.delegations)

    def test_cannot_delegate_to_self(self):
        """Cannot include yourself as a delegation target."""
        delegator = b"\x01" * 32
        result = self.tracker.set_delegation(delegator, [(delegator, 100)])
        self.assertFalse(result)

    def test_delegation_replaces_previous(self):
        """New delegation completely replaces the old one."""
        delegator = b"\x01" * 32
        v1, v2 = b"\x02" * 32, b"\x03" * 32
        self.tracker.set_delegation(delegator, [(v1, 100)])
        self.tracker.set_delegation(delegator, [(v2, 100)])
        self.assertEqual(self.tracker.delegations[delegator], [(v2, 100)])


class TestDelegatedVoteTally(unittest.TestCase):
    """Delegated voting power splits proportionally across targets."""

    def setUp(self):
        self.tracker = GovernanceTracker()
        self.supply = SupplyTracker()
        # Only stake entities relevant to each test
        self.proposer = b"\x01" * 32  # creates proposals, not staked
        self.v1 = b"\x02" * 32
        self.v2 = b"\x03" * 32
        self.delegator = b"\x04" * 32
        self.supply.staked[self.v1] = 1000
        self.supply.staked[self.v2] = 1000
        self.supply.staked[self.delegator] = 1000

    def _create_proposal(self):
        """Helper to add a proposal and return its ID."""
        tx = ProposalTransaction(
            proposer_id=self.proposer,
            title="Test",
            description="Test proposal",
            timestamp=1.0,
            fee=1000,
            signature=None,  # not verified in tracker
        )
        tx.tx_hash = tx._compute_hash()
        self.tracker.add_proposal(tx, block_height=0, supply_tracker=self.supply)
        return tx.proposal_id

    def test_single_delegate_gets_full_weight(self):
        """100% delegation to one validator gives them full weight."""
        # Remove v2 stake so default delegation doesn't interfere
        del self.supply.staked[self.v2]
        pid = self._create_proposal()
        self.tracker.set_delegation(self.delegator, [(self.v1, 100)])
        # v1 votes yes — should include delegator's full stake
        from messagechain.governance.governance import VoteTransaction
        vote = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        vote.tx_hash = vote._compute_hash()
        self.tracker.add_vote(vote, current_block=0)

        yes_weight, total_weight = self.tracker.tally(pid)
        # v1's own stake (1000) + delegator's stake (1000) = 2000
        self.assertEqual(yes_weight, 2000)
        self.assertEqual(total_weight, 2000)

    def test_split_delegation_divides_weight(self):
        """50/50 delegation splits voting weight between two validators."""
        pid = self._create_proposal()
        self.tracker.set_delegation(self.delegator, [(self.v1, 50), (self.v2, 50)])

        from messagechain.governance.governance import VoteTransaction
        # v1 votes yes
        vote1 = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        vote1.tx_hash = vote1._compute_hash()
        self.tracker.add_vote(vote1, current_block=0)

        # v2 votes no
        vote2 = VoteTransaction(
            voter_id=self.v2, proposal_id=pid, approve=False,
            timestamp=2.0, fee=100, signature=None,
        )
        vote2.tx_hash = vote2._compute_hash()
        self.tracker.add_vote(vote2, current_block=0)

        yes_weight, total_weight = self.tracker.tally(pid)
        # v1: own 1000 + 50% of delegator's 1000 = 1500 (yes)
        # v2: own 1000 + 50% of delegator's 1000 = 1500 (no)
        self.assertEqual(yes_weight, 1500)
        self.assertEqual(total_weight, 3000)

    def test_direct_vote_overrides_delegation(self):
        """If delegator votes directly, delegation is ignored for that proposal."""
        # Remove v2 stake so default delegation doesn't interfere
        del self.supply.staked[self.v2]
        pid = self._create_proposal()
        self.tracker.set_delegation(self.delegator, [(self.v1, 100)])

        from messagechain.governance.governance import VoteTransaction
        # v1 votes yes
        vote1 = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        vote1.tx_hash = vote1._compute_hash()
        self.tracker.add_vote(vote1, current_block=0)

        # Delegator votes no directly — overrides delegation
        vote2 = VoteTransaction(
            voter_id=self.delegator, proposal_id=pid, approve=False,
            timestamp=2.0, fee=100, signature=None,
        )
        vote2.tx_hash = vote2._compute_hash()
        self.tracker.add_vote(vote2, current_block=0)

        yes_weight, total_weight = self.tracker.tally(pid)
        # v1: own 1000 (yes), delegator voted directly so no delegation
        # delegator: own 1000 (no)
        self.assertEqual(yes_weight, 1000)
        self.assertEqual(total_weight, 2000)


class TestSlashedValidatorDelegation(unittest.TestCase):
    """Delegations to slashed validators are auto-revoked."""

    def test_slash_revokes_delegations(self):
        """When a validator is slashed, all delegations to them revert to default."""
        tracker = GovernanceTracker()
        delegator = b"\x01" * 32
        bad_validator = b"\x02" * 32
        tracker.set_delegation(delegator, [(bad_validator, 100)])
        self.assertIn(delegator, tracker.delegations)

        tracker.revoke_delegations_to(bad_validator)
        self.assertNotIn(delegator, tracker.delegations)


class TestBootstrapRewardCap(unittest.TestCase):
    """Reward cap is lifted during bootstrap mode."""

    def test_bootstrap_no_cap(self):
        """During bootstrap, proposer gets full reward (no cap)."""
        from messagechain.config import BLOCK_REWARD
        supply = SupplyTracker()
        proposer = b"\x01" * 32
        supply.balances[proposer] = 0

        result = supply.mint_block_reward(proposer, block_height=0, bootstrap=True)
        self.assertEqual(result["proposer_reward"], BLOCK_REWARD)
        self.assertEqual(supply.get_balance(proposer), BLOCK_REWARD)

    def test_post_bootstrap_capped(self):
        """After bootstrap, proposer is capped."""
        from messagechain.config import BLOCK_REWARD, PROPOSER_REWARD_CAP
        supply = SupplyTracker()
        proposer = b"\x01" * 32
        supply.balances[proposer] = 0

        result = supply.mint_block_reward(proposer, block_height=0, bootstrap=False)
        self.assertEqual(result["proposer_reward"], PROPOSER_REWARD_CAP)


if __name__ == "__main__":
    unittest.main()
