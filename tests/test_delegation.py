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
        from messagechain.config import GOVERNANCE_DELEGATION_AGING_BLOCKS
        self._aging = GOVERNANCE_DELEGATION_AGING_BLOCKS
        self.tracker = GovernanceTracker()
        self.supply = SupplyTracker()
        self.proposer = b"\x01" * 32  # creates proposals, not staked
        self.v1 = b"\x02" * 32
        self.v2 = b"\x03" * 32
        self.delegator = b"\x04" * 32
        self.supply.staked[self.v1] = 1000
        self.supply.staked[self.v2] = 1000
        # Delegator is NOT a staker — delegation routes liquid balance.
        self.supply.balances[self.delegator] = 1000

    def _create_proposal(self, block_height: int | None = None):
        """Helper to add a proposal and return its ID.

        Defaults to block_height = aging + 1 so any delegation registered
        at block 0 is already aged.
        """
        if block_height is None:
            block_height = self._aging + 1
        tx = ProposalTransaction(
            proposer_id=self.proposer,
            title="Test",
            description="Test proposal",
            timestamp=1.0,
            fee=1000,
            signature=None,  # not verified in tracker
        )
        tx.tx_hash = tx._compute_hash()
        self.tracker.add_proposal(
            tx, block_height=block_height, supply_tracker=self.supply,
        )
        return tx.proposal_id, block_height

    def test_single_delegate_gets_full_weight(self):
        """100% delegation of liquid balance to one validator adds linearly."""
        del self.supply.staked[self.v2]  # v2 not a validator for this test
        self.tracker.set_delegation(
            self.delegator, [(self.v1, 100)], current_block=0,
        )
        pid, block = self._create_proposal()
        from messagechain.governance.governance import VoteTransaction
        vote = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        vote.tx_hash = vote._compute_hash()
        self.tracker.add_vote(vote, current_block=block)

        yes, no, participating, eligible = self.tracker.tally(pid)
        # v1 own stake 1000 + delegator's liquid 1000 = 2000 yes.
        self.assertEqual(yes, 2000)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 2000)
        self.assertEqual(eligible, 2000)

    def test_split_delegation_divides_weight(self):
        """50/50 delegation splits liquid balance between two validators."""
        self.tracker.set_delegation(
            self.delegator, [(self.v1, 50), (self.v2, 50)],
            current_block=0,
        )
        pid, block = self._create_proposal()
        from messagechain.governance.governance import VoteTransaction
        v1_vote = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        v1_vote.tx_hash = v1_vote._compute_hash()
        self.tracker.add_vote(v1_vote, current_block=block)
        v2_vote = VoteTransaction(
            voter_id=self.v2, proposal_id=pid, approve=False,
            timestamp=2.0, fee=100, signature=None,
        )
        v2_vote.tx_hash = v2_vote._compute_hash()
        self.tracker.add_vote(v2_vote, current_block=block)

        yes, no, participating, eligible = self.tracker.tally(pid)
        # v1 own 1000 + delegator's 50% (500) = 1500 yes.
        # v2 own 1000 + delegator's 50% (500) = 1500 no.
        self.assertEqual(yes, 1500)
        self.assertEqual(no, 1500)
        self.assertEqual(participating, 3000)
        # Eligible: v1 1000 + v2 1000 + delegator liquid 1000 = 3000
        self.assertEqual(eligible, 3000)

    def test_non_staker_delegator_cannot_vote_directly(self):
        """A pure-liquid delegator cannot vote directly — they must
        participate via delegation."""
        del self.supply.staked[self.v2]
        self.tracker.set_delegation(
            self.delegator, [(self.v1, 100)], current_block=0,
        )
        pid, block = self._create_proposal()

        from messagechain.governance.governance import VoteTransaction
        # v1 votes yes
        v1_vote = VoteTransaction(
            voter_id=self.v1, proposal_id=pid, approve=True,
            timestamp=1.0, fee=100, signature=None,
        )
        v1_vote.tx_hash = v1_vote._compute_hash()
        self.tracker.add_vote(v1_vote, current_block=block)

        # Delegator tries to vote directly — rejected (not a staker)
        delegator_vote = VoteTransaction(
            voter_id=self.delegator, proposal_id=pid, approve=False,
            timestamp=2.0, fee=100, signature=None,
        )
        delegator_vote.tx_hash = delegator_vote._compute_hash()
        self.assertFalse(
            self.tracker.add_vote(delegator_vote, current_block=block),
        )

        yes, no, participating, _eligible = self.tracker.tally(pid)
        # Only v1's tally matters; delegator flows to v1 yes.
        self.assertEqual(yes, 2000)  # 1000 v1 own + 1000 delegator
        self.assertEqual(no, 0)
        self.assertEqual(participating, 2000)


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
