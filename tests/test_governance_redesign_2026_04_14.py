"""Tests for the 2026-04-14 governance redesign.

New rules:
1. Voting power = staked + isqrt(unstaked_balance).  Staked tokens count
   linearly; unstaked tokens count sqrt-dampened.
2. Balance snapshot captured at proposal creation (above dust threshold).
3. Tally rules:
   - Direct vote: voter's full voting power counts.
   - Explicit delegation: split across chosen validators per declared %s.
   - Auto (default): sqrt(validator_stake)-weighted distribution across
     validators who actually voted.
4. Approval threshold = 2/3 supermajority.
5. Slashing a validator auto-revokes explicit delegations pointing to them.
"""

import math
import unittest

from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
    voting_power,
)
from messagechain.config import (
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    GOVERNANCE_BALANCE_SNAPSHOT_DUST,
)


def _entity(label: str) -> Entity:
    return Entity.create(label.encode().ljust(32, b"\x00"))


class TestVotingPowerFormula(unittest.TestCase):
    """staked + isqrt(unstaked) — staked linear, unstaked sqrt-dampened."""

    def test_only_staked(self):
        self.assertEqual(voting_power(1000, 0), 1000)

    def test_only_unstaked_is_sqrt_dampened(self):
        # 1,000,000 unstaked tokens → voting power = 1000 (sqrt)
        self.assertEqual(voting_power(0, 1_000_000), 1000)

    def test_combined_linear_plus_sqrt(self):
        # 1M staked → 1M voting; 1M unstaked → 1000 voting; total = 1_001_000
        self.assertEqual(voting_power(1_000_000, 1_000_000), 1_001_000)

    def test_zero_zero(self):
        self.assertEqual(voting_power(0, 0), 0)

    def test_negative_ignored_defensively(self):
        # Defensive: negative values shouldn't crash or produce negative power
        self.assertEqual(voting_power(-5, 100), 10)   # staked clamped to 0
        self.assertEqual(voting_power(50, -10), 50)   # unstaked clamped to 0

    def test_small_unstaked_dust_rounds_to_zero(self):
        # isqrt(0) = 0; isqrt(1) = 1; isqrt(3) = 1
        self.assertEqual(voting_power(0, 0), 0)
        self.assertEqual(voting_power(0, 1), 1)
        self.assertEqual(voting_power(0, 3), 1)
        self.assertEqual(voting_power(0, 4), 2)

    def test_whale_dampening(self):
        # Whale with 1B unstaked gets sqrt(1B) ≈ 31,622 voting power.
        # A validator with 1M staked gets 1M voting power.
        # Whale's unstaked is dampened >30x vs. validator's staked.
        whale_vp = voting_power(0, 1_000_000_000)
        validator_vp = voting_power(1_000_000, 0)
        self.assertGreater(validator_vp, whale_vp)


class TestBalanceSnapshot(unittest.TestCase):
    """Proposal creation snapshots balances above dust threshold."""

    def setUp(self):
        self.alice = _entity("alice")
        self.bob = _entity("bob")
        self.carol = _entity("carol")
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 5000
        self.supply.balances[self.bob.entity_id] = GOVERNANCE_BALANCE_SNAPSHOT_DUST  # at dust
        self.supply.balances[self.carol.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 100

        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "Test", "description")
        self.tracker.add_proposal(self.prop, block_height=10, supply_tracker=self.supply)

    def test_balances_above_dust_snapshotted(self):
        state = self.tracker.proposals[self.prop.proposal_id]
        self.assertIn(self.alice.entity_id, state.balance_snapshot)
        self.assertEqual(state.balance_snapshot[self.alice.entity_id], 5000)

    def test_dust_balance_excluded(self):
        state = self.tracker.proposals[self.prop.proposal_id]
        # bob at exactly dust threshold should be excluded (uses > dust, not >=)
        self.assertNotIn(self.bob.entity_id, state.balance_snapshot)
        # carol with 0 balance also excluded
        self.assertNotIn(self.carol.entity_id, state.balance_snapshot)

    def test_stake_snapshot_still_captured(self):
        state = self.tracker.proposals[self.prop.proposal_id]
        self.assertEqual(state.stake_snapshot.get(self.alice.entity_id), 100)

    def test_post_creation_balance_change_does_not_affect_snapshot(self):
        # Move all of alice's balance after proposal was created
        self.supply.balances[self.alice.entity_id] = 0
        state = self.tracker.proposals[self.prop.proposal_id]
        # Snapshot still reflects the pre-change value
        self.assertEqual(state.balance_snapshot[self.alice.entity_id], 5000)


class TestTallyWithNewVotingPower(unittest.TestCase):
    """Tally uses staked + sqrt(unstaked) voting power."""

    def setUp(self):
        self.alice = _entity("alice-1")
        self.bob = _entity("bob-1")
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Alice: 100 staked, 10000 unstaked → voting power = 100 + sqrt(10000) = 200
        self.supply.staked[self.alice.entity_id] = 100
        self.supply.balances[self.alice.entity_id] = 10000
        # Bob: 0 staked, 10000 unstaked → voting power = 0 + sqrt(10000) = 100
        self.supply.balances[self.bob.entity_id] = 10000

        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "Test", "d")
        self.tracker.add_proposal(self.prop, block_height=10, supply_tracker=self.supply)

    def test_direct_voter_gets_full_voting_power(self):
        # Alice (validator) votes yes; voting power = 100 + 100 = 200
        vote = create_vote(self.alice, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # Only Alice voted directly; Bob has no validators to auto-delegate to
        # other than Alice, so Bob's 100 voting power flows to Alice (who voted yes)
        # Expected: alice direct (200) + bob auto-to-alice (100) = 300 yes, 300 total
        self.assertEqual(yes, 300)
        self.assertEqual(total, 300)

    def test_non_validator_vote_has_only_sqrt_balance_power(self):
        # Bob (non-validator) votes yes; voting power = 0 + 100 = 100
        vote = create_vote(self.bob, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=11)
        yes, total = self.tracker.tally(self.prop.proposal_id)
        # Bob voted directly (100). Alice didn't vote and has no explicit
        # delegation. Auto-delegation goes only to validators who voted —
        # alice didn't vote, so no validator voted → alice's power doesn't flow.
        self.assertEqual(yes, 100)
        self.assertEqual(total, 100)


class TestAutoDelegation(unittest.TestCase):
    """Passive entities auto-delegate to validators via sqrt(stake) weighting."""

    def setUp(self):
        self.alice = _entity("alice-auto")
        self.bob = _entity("bob-auto")
        self.carol = _entity("carol-auto")
        self.dave = _entity("dave-auto")
        for e in (self.alice, self.bob, self.carol, self.dave):
            e.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Alice: validator with 100 staked
        self.supply.staked[self.alice.entity_id] = 100
        # Bob: validator with 400 staked — 2x sqrt-weight vs. Alice (sqrt(400)=20 vs sqrt(100)=10)
        self.supply.staked[self.bob.entity_id] = 400
        # Carol: passive, 10000 unstaked → voting power = 100
        self.supply.balances[self.carol.entity_id] = 10000
        # Dave: passive, 0 tokens
        self.supply.balances[self.dave.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "Test", "d")
        self.tracker.add_proposal(self.prop, block_height=10, supply_tracker=self.supply)

    def test_both_validators_vote_yes_auto_splits_sqrt_weighted(self):
        # Alice and Bob both vote yes. Carol is passive (100 voting power).
        # sqrt weights: alice=10, bob=20; total=30.
        # Carol's power splits: alice gets 100*10/30=33, bob gets 100*20/30=66.
        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        vb = create_vote(self.bob, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(va, current_block=11)
        self.tracker.add_vote(vb, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # alice direct = 100, bob direct = 400, carol auto = 33+66 = 99
        # Expected yes = 100 + 400 + 99 = 599
        self.assertEqual(yes, 599)
        self.assertEqual(total, 599)

    def test_only_one_validator_votes_passive_flows_there(self):
        # Only alice votes; all passive power flows to alice (the only voting validator)
        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(va, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # alice direct = 100, carol auto-to-alice = 100, bob didn't vote (passive → skipped since bob IS a validator who didn't vote)
        # But bob IS a validator so his balance would also auto-delegate... except he has no balance
        # Bob is a validator with 0 unstaked balance, so voting_power(400, 0) = 400
        # Bob didn't vote and isn't explicitly delegated → he auto-delegates
        # All auto-delegation goes to alice (only validator who voted)
        # alice_direct(100) + carol_auto(100) + bob_auto(400) = 600
        self.assertEqual(yes, 600)
        self.assertEqual(total, 600)

    def test_no_validators_vote_passive_power_does_not_count(self):
        # No one votes → tally is (0, 0)
        yes, total = self.tracker.tally(self.prop.proposal_id)
        self.assertEqual((yes, total), (0, 0))

    def test_mixed_yes_no_splits_correctly(self):
        # Alice votes yes, Bob votes no.
        # Carol (passive, 100 power) splits: 33 to alice(yes), 66 to bob(no)
        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        vb = create_vote(self.bob, self.prop.proposal_id, approve=False)
        self.tracker.add_vote(va, current_block=11)
        self.tracker.add_vote(vb, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # alice(100, yes) + bob(400, no) + carol-auto-to-alice(33, yes) + carol-auto-to-bob(66, no)
        # yes = 100 + 33 = 133
        # total = 100 + 400 + 33 + 66 = 599
        self.assertEqual(yes, 133)
        self.assertEqual(total, 599)


class TestExplicitDelegationOverridesAuto(unittest.TestCase):
    """Explicit delegation bypasses sqrt-weighted auto."""

    def setUp(self):
        self.alice = _entity("alice-expl")
        self.bob = _entity("bob-expl")
        self.carol = _entity("carol-expl")
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.staked[self.alice.entity_id] = 100
        self.supply.staked[self.bob.entity_id] = 400
        self.supply.balances[self.carol.entity_id] = 10000  # voting power = 100

        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "Test", "d")
        self.tracker.add_proposal(self.prop, block_height=10, supply_tracker=self.supply)

    def test_explicit_delegation_sends_full_power_to_chosen(self):
        # Carol explicitly delegates 100% to alice (overriding auto)
        self.tracker.set_delegation(self.carol.entity_id, [(self.alice.entity_id, 100)])

        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        vb = create_vote(self.bob, self.prop.proposal_id, approve=False)
        self.tracker.add_vote(va, current_block=11)
        self.tracker.add_vote(vb, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # alice(100, yes) + bob(400, no) + carol->alice(100, yes)
        # yes = 100 + 100 = 200
        # total = 100 + 400 + 100 = 600
        self.assertEqual(yes, 200)
        self.assertEqual(total, 600)

    def test_explicit_delegation_to_non_voter_portion_lost(self):
        # Carol delegates 50/50 between alice (votes yes) and bob (doesn't vote)
        self.tracker.set_delegation(
            self.carol.entity_id,
            [(self.alice.entity_id, 50), (self.bob.entity_id, 50)],
        )
        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(va, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # alice(100, yes) + carol->alice (100*50/100=50, yes); carol->bob portion lost
        # Also bob didn't vote → bob's validator power does NOT auto-delegate (bob
        # IS a validator but only VOTING validators receive auto-delegation)
        # No one voted except alice, so all auto flows to alice
        # BUT carol has explicit delegation so she doesn't auto
        # bob (passive, stake=400) auto-delegates to voting validators = just alice
        # bob_auto_power = 400, all goes to alice
        # yes = alice(100) + carol->alice(50) + bob_auto_to_alice(400) = 550
        self.assertEqual(yes, 550)

    def test_direct_vote_overrides_explicit_delegation(self):
        # Carol explicitly delegates to alice, but then votes directly NO
        self.tracker.set_delegation(self.carol.entity_id, [(self.alice.entity_id, 100)])
        vc = create_vote(self.carol, self.prop.proposal_id, approve=False)
        va = create_vote(self.alice, self.prop.proposal_id, approve=True)
        self.tracker.add_vote(vc, current_block=11)
        self.tracker.add_vote(va, current_block=11)

        yes, total = self.tracker.tally(self.prop.proposal_id)
        # carol direct(100, no) + alice direct(100, yes)
        # Bob (passive validator) auto-delegates to alice (only voting validator)
        # bob_auto = 400 to alice(yes)
        # yes = alice(100) + bob_auto(400) = 500
        # total = alice(100) + carol(100) + bob_auto(400) = 600
        self.assertEqual(yes, 500)
        self.assertEqual(total, 600)


class TestSlashRevokesDelegations(unittest.TestCase):
    """Slashing a validator revokes all explicit delegations to them."""

    def test_slash_triggers_revocation(self):
        tracker = GovernanceTracker()
        alice_id = b"\x01" * 32
        bob_id = b"\x02" * 32
        carol_id = b"\x03" * 32

        # Alice and Carol delegate to Bob
        tracker.set_delegation(alice_id, [(bob_id, 100)])
        tracker.set_delegation(carol_id, [(bob_id, 100)])
        self.assertIn(alice_id, tracker.delegations)
        self.assertIn(carol_id, tracker.delegations)

        # Bob is "kicked" (slashed)
        tracker.revoke_delegations_to(bob_id)

        # Both delegations are removed — alice and carol revert to auto
        self.assertNotIn(alice_id, tracker.delegations)
        self.assertNotIn(carol_id, tracker.delegations)


class TestSupermajorityThreshold(unittest.TestCase):
    """Approval threshold is 2/3 supermajority, not simple majority."""

    def test_threshold_is_two_thirds(self):
        self.assertEqual(GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR, 2)
        self.assertEqual(GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR, 3)

    def test_sixty_percent_yes_fails_supermajority(self):
        # Build a tally where yes=60, total=100 — fails 2/3 (requires >= 66.67%)
        # Simulating via the threshold arithmetic used in execute_treasury_spend:
        # approval requires: yes * 3 > total * 2
        yes = 60
        total = 100
        passes = yes * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR > (
            total * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR
        )
        self.assertFalse(passes)

    def test_seventy_percent_yes_passes_supermajority(self):
        yes = 70
        total = 100
        passes = yes * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR > (
            total * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR
        )
        self.assertTrue(passes)


if __name__ == "__main__":
    unittest.main()
