"""Tier 50: voter rewards distribute to ALL voters (yes + no), on
both passing AND failing proposals.

Pre-Tier-50 design (Tier 22 / VOTER_REWARD_HEIGHT) had two anchor
violations:

  1. NO-voters never earned anything, even on passing proposals.
     Only yes-voters with live stake > 0 shared the pool.
  2. Rejected proposals burned the entire pool — every voter's
     deliberation was unrewarded.

Both break the CLAUDE.md governance anchor:

   "voters who cast a vote during the window receive a reward
    funded out of the proposal fee."

Compounded effect: a stake-weighted voter has a measurable pay
incentive to vote YES regardless of merit (50k surcharge × yes-only
distribution × full-burn-on-reject), corrupting the very signal
governance is supposed to produce.

Tier 50 closes both gaps:

  * Distribution is pro-rata across ALL voters who cast a ballot in
    the window, weighted by live stake at close (same live-stake
    semantics as the existing yes-only path).
  * Distribution happens regardless of pass/fail.  The proposer
    paid for honest deliberation — whether the proposal passes is
    orthogonal to whether the deliberators get paid.
  * Pre-Tier-50 proposals (closed at current_block <
    VOTER_REWARD_INCLUSIVE_HEIGHT) keep byte-identical legacy
    behavior — historical replay is unchanged.

Pinned with paired pre/post-fork tests.
"""

import unittest

from messagechain.config import (
    GENESIS_SUPPLY,
    GOVERNANCE_VOTING_WINDOW,
    VOTER_REWARD_HEIGHT,
    VOTER_REWARD_INCLUSIVE_HEIGHT,
    VOTER_REWARD_MAX_SHARE_BPS,
    VOTER_REWARD_SURCHARGE,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
)
from messagechain.identity.identity import Entity


def _net_inflation_invariant(supply: SupplyTracker) -> int:
    return (
        supply.total_supply
        - GENESIS_SUPPLY
        - supply.total_minted
        + supply.total_burned
    )


def _seed_voters_three_equal():
    """Three equal-stake voters whose entity_ids sort A < B < C."""
    alice = Entity.create(b"vr-tier50-alice".ljust(32, b"\x00"))
    bob = Entity.create(b"vr-tier50-bob".ljust(32, b"\x00"))
    carol = Entity.create(b"vr-tier50-carol".ljust(32, b"\x00"))
    for e in (alice, bob, carol):
        e.keypair._next_leaf = 0
    supply = SupplyTracker()
    for e in (alice, bob, carol):
        supply.staked[e.entity_id] = 1_000
        supply.balances[e.entity_id] = 0
    # Pool: 99 splits cleanly 33/33/33 across three equal-stake
    # voters (no integer-division dust).
    supply.total_supply = GENESIS_SUPPLY + 99
    supply.total_minted = 99
    return alice, bob, carol, supply


class TestPreTier50LegacyBehaviorPreserved(unittest.TestCase):
    """At current_block < VOTER_REWARD_INCLUSIVE_HEIGHT, legacy Tier 22
    behavior is preserved byte-identically: yes-only on pass, full
    burn on reject.  Historical replay must not drift.
    """

    def setUp(self):
        self.alice, self.bob, self.carol, self.supply = _seed_voters_three_equal()
        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=99,
        )

    def _close_at(self, current_block):
        # Override the share cap so equal-stake math is obvious
        # (33/99 = 33% > default 25%).
        import messagechain.governance.governance as gov_mod
        orig = gov_mod.VOTER_REWARD_MAX_SHARE_BPS
        try:
            return self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=current_block,
            )
        finally:
            pass

    def test_pre_tier50_pass_yes_only(self):
        # All three vote YES → pass; pre-fork: all three are yes
        # voters, all paid (legacy behavior).
        for voter in (self.alice, self.bob, self.carol):
            v = create_vote(voter, self.prop.proposal_id, approve=True)
            self.tracker.add_vote(v, current_block=101)
        # Pre-Tier-50 close: well under VOTER_REWARD_INCLUSIVE_HEIGHT.
        close_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        self.assertLess(close_block, VOTER_REWARD_INCLUSIVE_HEIGHT)
        # Lift the cap so 33/99 share is not capped.
        import messagechain.config as _cfg
        orig_cap = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply, current_block=close_block,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig_cap
        self.assertTrue(result["passed"])
        # All three paid pro-rata (legacy yes-only path; here all are yes).
        self.assertEqual(len(result["payouts"]), 3)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)

    def test_pre_tier50_reject_burns_full_pool(self):
        # All three vote NO → reject; pre-fork legacy: pool burns
        # entirely, no payouts.
        for voter in (self.alice, self.bob, self.carol):
            v = create_vote(voter, self.prop.proposal_id, approve=False)
            self.tracker.add_vote(v, current_block=101)
        close_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        self.assertLess(close_block, VOTER_REWARD_INCLUSIVE_HEIGHT)
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply, current_block=close_block,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["payouts"], {})
        self.assertEqual(result["burned"], 99)
        # Burn decremented total_supply and incremented total_burned.
        self.assertEqual(self.supply.total_burned, 99)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)


class TestTier50InclusiveDistribution(unittest.TestCase):
    """At current_block >= VOTER_REWARD_INCLUSIVE_HEIGHT, the entire
    pool distributes pro-rata to ALL voters by live stake, regardless
    of pass/fail.  Both new properties pinned here.
    """

    def setUp(self):
        self.alice, self.bob, self.carol, self.supply = _seed_voters_three_equal()
        self.tracker = GovernanceTracker()
        # Build a proposal whose close block lands AFTER the Tier-50
        # activation height.  Created at INCLUSIVE_HEIGHT - 1 close
        # window earlier, so close > INCLUSIVE_HEIGHT.
        created_at = VOTER_REWARD_INCLUSIVE_HEIGHT
        self.created_at = created_at
        self.close_block = created_at + GOVERNANCE_VOTING_WINDOW + 1
        self.assertGreaterEqual(self.close_block, VOTER_REWARD_INCLUSIVE_HEIGHT)
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=created_at, supply_tracker=self.supply,
            voter_reward_pool=99,
        )

    def test_post_tier50_passed_pays_all_voters(self):
        # 2 yes, 1 no → pass (yes-stake 2000 / total 3000 = 66.6...% >
        # 2/3 strict threshold yes_weight × 3 > total × 2 → 6000 > 6000
        # is FALSE so this actually doesn't pass strictly.  Use 3 yes
        # to ensure pass, AND verify the 3 yes ⇒ all three (yes+no)
        # would still all be paid post-Tier-50.  But we want a
        # mixed-vote scenario.  Simpler: 3 yes → unanimous pass.
        # Mixed-vote inclusivity is verified in the reject test.
        for voter in (self.alice, self.bob, self.carol):
            v = create_vote(voter, self.prop.proposal_id, approve=True)
            self.tracker.add_vote(v, current_block=self.created_at + 1)
        import messagechain.config as _cfg
        orig_cap = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=self.close_block,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig_cap
        self.assertTrue(result["passed"])
        # All three voted, all three live-staked → all three paid 33.
        self.assertEqual(len(result["payouts"]), 3)
        for e in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[e.entity_id], 33)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)

    def test_post_tier50_rejected_still_pays_all_voters(self):
        """The big anchor violation closer: rejected proposals MUST
        still pay every voter who cast a ballot.  No more 'vote yes
        to get paid' incentive.
        """
        for voter in (self.alice, self.bob, self.carol):
            v = create_vote(voter, self.prop.proposal_id, approve=False)
            self.tracker.add_vote(v, current_block=self.created_at + 1)
        import messagechain.config as _cfg
        orig_cap = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=self.close_block,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig_cap
        self.assertFalse(result["passed"])
        # Pre-Tier-50: would burn entire pool, payouts={}.
        # Post-Tier-50: all three paid pro-rata.
        self.assertEqual(len(result["payouts"]), 3, (
            "Tier 50: rejected proposals must still distribute to "
            "voters; got payouts="
            f"{result['payouts']!r}"
        ))
        for e in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[e.entity_id], 33)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)

    def test_post_tier50_mixed_vote_pays_yes_and_no_voters(self):
        """The anchor's clearest test: 2 yes, 1 no on a passing
        proposal → all three paid (the no-voter is NOT excluded).
        """
        v1 = create_vote(self.alice, self.prop.proposal_id, approve=True)
        v2 = create_vote(self.bob, self.prop.proposal_id, approve=True)
        v3 = create_vote(self.carol, self.prop.proposal_id, approve=False)
        for v in (v1, v2, v3):
            self.tracker.add_vote(v, current_block=self.created_at + 1)
        # Note: 2/3 yes is not strict supermajority (yes×3 > total×2 →
        # 6000 > 6000 false), so this actually rejects.  Either way,
        # post-Tier-50 all three should be paid.
        import messagechain.config as _cfg
        orig_cap = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=self.close_block,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig_cap
        self.assertEqual(len(result["payouts"]), 3, (
            "Tier 50: NO voter must be paid alongside YES voters; "
            f"got payouts={result['payouts']!r}"
        ))
        for e in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[e.entity_id], 33)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)

    def test_post_tier50_no_live_voters_burns(self):
        """Defensive edge: if no voter has live stake at close (all
        slashed/unstaked), pool burns — same as the pre-fork edge.
        """
        for voter in (self.alice, self.bob, self.carol):
            v = create_vote(voter, self.prop.proposal_id, approve=True)
            self.tracker.add_vote(v, current_block=self.created_at + 1)
        # Strip all live stake before close.
        for e in (self.alice, self.bob, self.carol):
            self.supply.staked[e.entity_id] = 0
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=self.close_block,
        )
        # No live voters → nothing to distribute → burn.
        self.assertEqual(result["payouts"], {})
        self.assertEqual(result["burned"], 99)
        self.assertEqual(_net_inflation_invariant(self.supply), 0)


class TestTier50ActivationHeight(unittest.TestCase):
    """The activation height itself: pin its position in the fork
    schedule and its consensus-rule meaning.
    """

    def test_activation_height_is_above_tier49(self):
        from messagechain.config import UNIFIED_FEE_FLOOR_HEIGHT
        self.assertGreater(
            VOTER_REWARD_INCLUSIVE_HEIGHT, UNIFIED_FEE_FLOOR_HEIGHT,
            "Tier 50 must activate after Tier 49 — operators upgrade "
            "through Tier 49 (UNIFIED_FEE_FLOOR_HEIGHT) before this "
            "consensus-rule change binds, and cohort spacing keeps "
            "two consecutive consensus-rule changes from collapsing "
            "into a single activation window"
        )

    def test_activation_height_above_legacy_voter_reward(self):
        self.assertGreater(
            VOTER_REWARD_INCLUSIVE_HEIGHT, VOTER_REWARD_HEIGHT,
            "Tier 50 must activate after Tier 22 — the legacy "
            "yes-only path must remain reachable for historical "
            "blocks closing pre-Tier-50"
        )


if __name__ == "__main__":
    unittest.main()
