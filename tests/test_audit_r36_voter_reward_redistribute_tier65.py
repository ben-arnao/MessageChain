"""Tier 65 -- voter-reward cap-overflow redistributes to non-cap voters
before the burn fallback.

Pre-fix ``Governance.finalize_voter_rewards`` distributed pro-rata by
live stake, capped each voter at
``VOTER_REWARD_MAX_SHARE_BPS / 10_000`` of the pool, and BURNED both
cap_excess and integer-division dust.  At today's bootstrap (founder
≈ 100% of active stake) the founder hits the 25% cap on every
proposal and the other 75% of the per-proposal pool burns.  After
seed-divestment to a 10M founder + 90M elsewhere distribution, a
small voter with 10K stake on a 100M-staked network earns
50000 × 10K / 100M = 5 tokens -- below the vote-tx fee floor of 100.
The mechanism currently *demotivates* voting at the small end while
burning the surcharge that was supposed to motivate it.

CLAUDE.md anchor at risk: governance economics anchor -- "voters who
cast a vote during the window receive a reward funded *out of the
proposal fee* -- the proposer pays the voters they're asking to
evaluate the proposal."  When ≥75% of every proposal's voter pool
incinerates instead of paying voters, the anchor is materially
inverted.

Tier 65 fix: post-activation, cap_excess (the per-voter overflow
above the per-voter cap) is REDISTRIBUTED to non-cap voters before
the burn fallback.  The redistribution iterates: each round, fill
non-cap voters pro-rata-by-stake from the remaining excess; voters
that hit the cap during a round drop out for the next round.  When
no progress can be made (all voters at cap, OR only one voter
exists), the residual burns -- but in practice on any non-degenerate
distribution the redistribute loop converts most of the would-be
burn into voter payouts.

Hard fork at activation height (consensus-visible balance writes
shift between the legacy single-pass-and-burn path and the iterative
redistribute path), gated by ``VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT``.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT,
    GOVERNANCE_VOTING_WINDOW,
    VOTER_REWARD_MAX_SHARE_BPS,
    VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
)
from messagechain.identity.identity import Entity


_OPEN_HEIGHT = 100  # proposal block_height for add_proposal calls


def _close_pre_fork() -> int:
    return _OPEN_HEIGHT + GOVERNANCE_VOTING_WINDOW + 1


def _close_post_fork() -> int:
    """A close height >= activation gate so the fix path runs."""
    return max(
        _OPEN_HEIGHT + GOVERNANCE_VOTING_WINDOW + 1,
        VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT + 1,
    )


class TestActivationConstantOrdering(unittest.TestCase):
    """Tier 65 activates above the most-recent prior tier (64)."""

    def test_height_above_tier_64(self):
        self.assertGreater(
            VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT,
            FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT,
        )

    def test_cohort_spacing_matches_tier_pattern(self):
        gap = (
            VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT
            - FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
        )
        self.assertGreaterEqual(gap, 50)


# ── Shared two-voter skewed-stake fixture ────────────────────────────


class _TwoVoterSkewed(unittest.TestCase):
    """Whale + small voter, both vote yes, very skewed stake.

    Pool = 100, cap = 25 (25% of 100, the default).
    Whale stake = 99, small stake = 1.

    Pre-fix:
      whale uncapped share = 100 * 99 / 100 = 99 → capped to 25 → 74 excess BURNS
      small share         = 100 * 1  / 100 = 1   → 1
      distributed = 26, burned = 74

    Post-fix:
      Round 1: whale capped at 25, small gets 1, capped_excess = 74, remaining = 74
      Round 2: only `small` is uncapped.  small can absorb up to (cap=25) - (current=1) = 24.
               small takes 24, remaining = 50.  small now at cap.
      All voters capped → remaining = 50 burns.
      distributed = 50 (whale 25 + small 25), burned = 50.
    """

    def setUp(self):
        self.whale = Entity.create(b"r36-vr-whale".ljust(32, b"\x00"))
        self.small = Entity.create(b"r36-vr-small".ljust(32, b"\x00"))
        for e in (self.whale, self.small):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.whale.entity_id] = 99
        self.supply.staked[self.small.entity_id] = 1
        self.supply.balances[self.whale.entity_id] = 0
        self.supply.balances[self.small.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.whale, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )
        self.tracker.add_vote(
            create_vote(self.whale, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        self.tracker.add_vote(
            create_vote(self.small, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        # Sanity: cap is at the default 25%
        self.assertEqual(VOTER_REWARD_MAX_SHARE_BPS, 2_500)


class TestPreForkLegacyBurn(_TwoVoterSkewed):
    """Pre-fork (close height < activation) cap-overflow burns -- byte-
    identical legacy behavior so historical proposals replay
    unchanged."""

    def test_pre_fork_cap_overflow_burns(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_pre_fork(),
        )
        self.assertTrue(result["passed"])
        # Whale capped at 25% of 100 = 25.  Small gets 1.
        self.assertEqual(self.supply.balances[self.whale.entity_id], 25)
        self.assertEqual(self.supply.balances[self.small.entity_id], 1)
        # 74 (cap_excess) burns.  Total distributed = 26.
        self.assertEqual(result["burned"], 74)
        self.assertEqual(
            self.supply.total_burned, burned_before + 74,
        )


class TestPostForkRedistributeCapExcess(_TwoVoterSkewed):
    """Post-fork cap-overflow REDISTRIBUTES to the non-cap voter before
    the burn fallback.  The whale stays capped at 25; the small voter
    rises from 1 to the cap (25); the residual 50 burns."""

    def test_post_fork_redistribute_lifts_small_voter_to_cap(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_fork(),
        )
        self.assertTrue(result["passed"])
        # Whale capped at the per-voter cap (25).
        self.assertEqual(self.supply.balances[self.whale.entity_id], 25)
        # Small lifted to the cap by redistributed cap_excess.
        self.assertEqual(self.supply.balances[self.small.entity_id], 25)
        # Residual 50 (both at cap, nothing else to redistribute to)
        # still burns.
        self.assertEqual(result["burned"], 50)
        self.assertEqual(
            self.supply.total_burned, burned_before + 50,
        )

    def test_post_fork_more_distribute_less_burn_vs_pre_fork(self):
        """The fix invariant: post-fork distributed sum >= pre-fork
        distributed sum, post-fork burned <= pre-fork burned."""
        # Run twice on isolated tracker copies via deepcopy of the
        # supply state.
        import copy
        # Pre-fork branch
        supply_pre = copy.deepcopy(self.supply)
        tracker_pre = GovernanceTracker()
        prop_pre = create_proposal(self.whale, "t1", "d1")
        tracker_pre.add_proposal(
            prop_pre, block_height=_OPEN_HEIGHT,
            supply_tracker=supply_pre, voter_reward_pool=self.pool,
        )
        tracker_pre.add_vote(
            create_vote(self.whale, prop_pre.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        tracker_pre.add_vote(
            create_vote(self.small, prop_pre.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        result_pre = tracker_pre.finalize_voter_rewards(
            prop_pre.proposal_id, supply_pre,
            current_block=_close_pre_fork(),
        )

        # Post-fork branch (use this test's self.supply / self.tracker)
        result_post = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_fork(),
        )

        distributed_pre = self.pool - result_pre["burned"]
        distributed_post = self.pool - result_post["burned"]
        self.assertGreaterEqual(distributed_post, distributed_pre)
        self.assertLessEqual(result_post["burned"], result_pre["burned"])


class TestPostForkSingleVoterStillBurns(unittest.TestCase):
    """Degenerate case: only one voter exists.  Cap binds (≤25% of
    pool), nobody to redistribute to -- residual burns identically to
    pre-fork.  No regression on this path."""

    def setUp(self):
        self.solo = Entity.create(b"r36-vr-solo".ljust(32, b"\x00"))
        self.solo.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.solo.entity_id] = 100
        self.supply.balances[self.solo.entity_id] = 0
        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.solo, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )
        self.tracker.add_vote(
            create_vote(self.solo, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )

    def test_single_voter_capped_residual_burns(self):
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_fork(),
        )
        self.assertTrue(result["passed"])
        # Cap binds at 25% of 100 = 25.  No one else to redistribute
        # to -> 75 burns.
        self.assertEqual(self.supply.balances[self.solo.entity_id], 25)
        self.assertEqual(result["burned"], 75)


class TestPostForkUncappedDistributesFully(unittest.TestCase):
    """Four voters each holding 25% of stake -- nobody hits the cap
    on the first pass -- distribute fully with only integer-division
    dust burning.  Verifies the redistribute path doesn't mistakenly
    over-pay or under-pay when the cap doesn't bind."""

    def setUp(self):
        self.voters = [
            Entity.create(f"r36-vr-quad-{i}".encode().ljust(32, b"\x00"))
            for i in range(4)
        ]
        for e in self.voters:
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        for e in self.voters:
            self.supply.staked[e.entity_id] = 1_000
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        # 100 splits cleanly 25/25/25/25 with 0 dust.
        self.pool = 100
        self.prop = create_proposal(self.voters[0], "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )
        for v in self.voters:
            self.tracker.add_vote(
                create_vote(v, self.prop.proposal_id, True),
                current_block=_OPEN_HEIGHT + 1,
            )

    def test_equal_quartile_split(self):
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_fork(),
        )
        self.assertTrue(result["passed"])
        # 25 each, 0 burn (4 × 25 = 100).
        for v in self.voters:
            self.assertEqual(self.supply.balances[v.entity_id], 25)
        self.assertEqual(result["burned"], 0)


if __name__ == "__main__":
    unittest.main()
