"""Audit r37 #3 -- voter-reward per-voter cap is adaptive in N_voters
post-Tier-66 so the surcharge actually reaches voters at small voter
sets (the bootstrap case).

Pre-fix Tier 65 (1.66.0) made cap-overflow REDISTRIBUTE to non-cap
voters before the burn fallback.  That fix is correct and load-
bearing for skewed-stake distributions.  But the redistribute loop
can only redistribute *within voters present* -- it cannot break the
per-voter ``VOTER_REWARD_MAX_SHARE_BPS`` cap.  When every voter is
already at the cap, the residual burns.  At N=1 voter the lone
voter caps at 25% of pool and 75% burns; at N=2 voters with equal
stake each caps at 25% of pool, 50% distributed and 50% burns.

On today's two-validator bootstrap mainnet (founder ≈ 100% of stake;
typical participating-voter set is N=1 or N=2) every governance
proposal STILL burns 50-75% of the voter surcharge after Tier 65.

CLAUDE.md anchor at risk: governance economics anchor -- "voters
who cast a vote during the window receive a reward funded *out of
the proposal fee* -- the proposer pays the voters they're asking
to evaluate the proposal."  When the cap binds for every voter,
the surcharge isn't going to voters at all -- it's just supply-
deflation.  This is the same anchor Tier 65 was protecting, viewed
from a different angle: Tier 65 closed the skewed-stake leak; Tier
66 closes the small-N leak.

Tier 66 fix: make the per-voter cap adaptive in voter count.
Post-activation::

    effective_cap_bps = max(
        VOTER_REWARD_MAX_SHARE_BPS,   # legacy floor (25%)
        10_000 // num_voters,         # mathematical "even share"
    )
    cap = pool * effective_cap_bps // 10_000

  N=1: max(2_500, 10_000) = 10_000 → cap = 100% of pool (lone voter
       gets everything).
  N=2: max(2_500, 5_000)  = 5_000  → cap = 50% (two voters fully
       split the pool when equal-stake).
  N=3: max(2_500, 3_333)  = 3_333  → cap = 33.3%.
  N=4: max(2_500, 2_500)  = 2_500  → cap = 25% (legacy floor binds).
  N=5+: max(2_500, ≤2_000) = 2_500 → cap = 25% (legacy floor binds).

For N >= 4 the legacy 25% cap is preserved exactly, so the anchored
"large-N anti-whale" shape is unchanged.  The Tier 65 redistribute
loop runs unchanged on top of the new cap value -- a skewed N=2
distribution (whale=99, small=1, pool=100) goes whale capped at 50
+ small lifted to 50 by redistribute → 100 distributed, 0 burned.

Hard fork: balance writes shift between the legacy cap and the
adaptive cap, which is consensus-visible.  Pre-fork (close-block
height < activation) the legacy code runs byte-for-byte so
historical proposals replay identically.  Activation height 2550
sits 50 blocks above Tier 65 (2500) -- ~8.3h cohort spacing matching
the Tier 49-65 pattern.  No new wire format, no new tx kinds, no
state-tree changes -- pure function-shape change inside
``Governance.finalize_voter_rewards``.
"""

from __future__ import annotations

import copy
import inspect
import unittest

from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW,
    VOTER_REWARD_ADAPTIVE_CAP_HEIGHT,
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


def _close_pre_tier66() -> int:
    """Close height between Tier 65 activation and Tier 66 activation
    -- exercises the Tier 65 redistribute path under the LEGACY 25%
    cap (so the small-N burn-fraction issue is observable)."""
    # Make sure we're past the voting window AND below Tier 66.
    needed = _OPEN_HEIGHT + GOVERNANCE_VOTING_WINDOW + 1
    return max(needed, VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT + 1)


def _close_post_tier66() -> int:
    needed = _OPEN_HEIGHT + GOVERNANCE_VOTING_WINDOW + 1
    return max(needed, VOTER_REWARD_ADAPTIVE_CAP_HEIGHT + 1)


# ---------------------------------------------------------------------------
# Activation-constant ordering pin
# ---------------------------------------------------------------------------


class TestTier66ActivationOrdering(unittest.TestCase):
    """Tier 66 activates above the most recent prior tier (65)."""

    def test_height_above_tier_65(self):
        self.assertGreater(
            VOTER_REWARD_ADAPTIVE_CAP_HEIGHT,
            VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT,
        )

    def test_cohort_spacing_matches_tier_pattern(self):
        gap = (
            VOTER_REWARD_ADAPTIVE_CAP_HEIGHT
            - VOTER_REWARD_REDISTRIBUTE_CAP_EXCESS_HEIGHT
        )
        self.assertGreaterEqual(gap, 50)


# ---------------------------------------------------------------------------
# Source pin -- finalize_voter_rewards must consult the new gate
# ---------------------------------------------------------------------------


class TestSourcePinAdaptiveCapGate(unittest.TestCase):
    def test_finalize_voter_rewards_references_tier_66_gate(self):
        from messagechain.governance.governance import GovernanceTracker
        src = inspect.getsource(GovernanceTracker.finalize_voter_rewards)
        self.assertIn(
            "VOTER_REWARD_ADAPTIVE_CAP_HEIGHT", src,
            "finalize_voter_rewards must consult the Tier-66 activation "
            "gate so the per-voter cap becomes adaptive in N_voters "
            "post-activation -- without this, N=1 and N=2 voter sets "
            "still burn 50-75% of every proposal's voter surcharge",
        )


# ---------------------------------------------------------------------------
# N=1 lone voter -- pre-fork burns 75%, post-fork keeps 100%
# ---------------------------------------------------------------------------


class _LoneVoterFixture(unittest.TestCase):
    """Single voter (founder bootstrap case): pool 100, voter stake
    is the only stake, cap (legacy 25%) burns 75% of the pool."""

    def setUp(self):
        self.lone = Entity.create(b"r37-vr-lone".ljust(32, b"\x00"))
        self.lone.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.lone.entity_id] = 100
        self.supply.balances[self.lone.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.lone, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )
        self.tracker.add_vote(
            create_vote(self.lone, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        # Sanity: legacy cap is at the 25% default.
        self.assertEqual(VOTER_REWARD_MAX_SHARE_BPS, 2_500)


class TestLoneVoterPreTier66LegacyBurn(_LoneVoterFixture):
    """Pre-Tier-66 (Tier 65 redistribute path active, but adaptive cap
    not yet active): the lone voter caps at 25 and 75 burns -- this
    is the leak Tier 66 closes."""

    def test_pre_tier66_lone_voter_burns_75pct(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_pre_tier66(),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(self.supply.balances[self.lone.entity_id], 25)
        self.assertEqual(result["burned"], 75)
        self.assertEqual(
            self.supply.total_burned, burned_before + 75,
        )


class TestLoneVoterPostTier66KeepsFullPool(_LoneVoterFixture):
    """Post-Tier-66: cap = max(2500, 10000//1) = 10000 = 100% pool, so
    the lone voter receives the entire pool and 0 burns."""

    def test_post_tier66_lone_voter_keeps_full_pool(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_tier66(),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(self.supply.balances[self.lone.entity_id], 100)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(self.supply.total_burned, burned_before)


# ---------------------------------------------------------------------------
# N=2 equal-stake -- pre-fork burns 50%, post-fork keeps 100%
# ---------------------------------------------------------------------------


class _TwoVoterEqualFixture(unittest.TestCase):
    """Two voters at equal stake: pool 100, each stake 50.  Legacy cap
    25% binds for both → 50 distributed, 50 burns."""

    def setUp(self):
        self.a = Entity.create(b"r37-vr-2eq-a".ljust(32, b"\x00"))
        self.b = Entity.create(b"r37-vr-2eq-b".ljust(32, b"\x00"))
        for e in (self.a, self.b):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.a.entity_id] = 50
        self.supply.staked[self.b.entity_id] = 50
        self.supply.balances[self.a.entity_id] = 0
        self.supply.balances[self.b.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.a, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )
        self.tracker.add_vote(
            create_vote(self.a, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        self.tracker.add_vote(
            create_vote(self.b, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )


class TestTwoEqualPreTier66Burns50pct(_TwoVoterEqualFixture):
    def test_pre_tier66_two_equal_voters_burn_50pct(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_pre_tier66(),
        )
        self.assertTrue(result["passed"])
        # Each capped at 25% of 100 = 25; total distributed = 50, burned 50.
        self.assertEqual(self.supply.balances[self.a.entity_id], 25)
        self.assertEqual(self.supply.balances[self.b.entity_id], 25)
        self.assertEqual(result["burned"], 50)
        self.assertEqual(self.supply.total_burned, burned_before + 50)


class TestTwoEqualPostTier66KeepsFullPool(_TwoVoterEqualFixture):
    def test_post_tier66_two_equal_voters_each_get_50(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_tier66(),
        )
        self.assertTrue(result["passed"])
        # cap = max(2500, 5000) = 5000 = 50% of 100.  Each gets 50, 0 burn.
        self.assertEqual(self.supply.balances[self.a.entity_id], 50)
        self.assertEqual(self.supply.balances[self.b.entity_id], 50)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(self.supply.total_burned, burned_before)


# ---------------------------------------------------------------------------
# N=2 skewed-stake -- redistribute interaction with adaptive cap
# ---------------------------------------------------------------------------


class TestTwoSkewedPostTier66RedistributeUnderAdaptiveCap(unittest.TestCase):
    """Whale + small voter, both vote: pool 100, whale stake 99,
    small stake 1.  Adaptive cap = 50%.

    Round 1: whale raw share = 99 → capped at 50, excess 49.
             small raw share = 1.
             distributed = 51, capped_excess = 49.
    Tier 65 redistribute: only `small` is uncapped.  small absorbs
    up to (50 - 1) = 49 headroom → small lifted from 1 to 50.
             distributed = 100, burned = 0.

    Compared to the same fixture pre-Tier-66 (legacy 25% cap):
      whale capped at 25, small lifted to 25 by redistribute → 50
      distributed, 50 burned.  Adaptive cap closes the residual leak.
    """

    def setUp(self):
        self.whale = Entity.create(b"r37-vr-skw-w".ljust(32, b"\x00"))
        self.small = Entity.create(b"r37-vr-skw-s".ljust(32, b"\x00"))
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
            supply_tracker=self.supply, voter_reward_pool=self.pool,
        )
        self.tracker.add_vote(
            create_vote(self.whale, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )
        self.tracker.add_vote(
            create_vote(self.small, self.prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )

    def test_post_tier66_skewed_n2_no_burn(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_tier66(),
        )
        self.assertTrue(result["passed"])
        self.assertEqual(self.supply.balances[self.whale.entity_id], 50)
        self.assertEqual(self.supply.balances[self.small.entity_id], 50)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(self.supply.total_burned, burned_before)


# ---------------------------------------------------------------------------
# N=4 equal -- adaptive cap collapses to legacy 25%, behavior unchanged
# ---------------------------------------------------------------------------


class TestFourEqualPostTier66LegacyCapBinds(unittest.TestCase):
    """4 voters at equal stake: pool 100, each stake 25.  Adaptive cap
    formula = max(2500, 10000//4) = 2500 = 25% (the legacy floor).
    Each voter's pro-rata share is exactly 25, which equals the cap;
    no overflow, no redistribute, all distributed.  Demonstrates
    the anchored "large-N anti-whale" 25% shape is preserved
    unchanged at N >= 4."""

    def setUp(self):
        self.voters = []
        self.supply = SupplyTracker()
        for i in range(4):
            e = Entity.create(f"r37-vr-4eq-{i}".encode().ljust(32, b"\x00"))
            e.keypair._next_leaf = 0
            self.voters.append(e)
            self.supply.staked[e.entity_id] = 25
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.voters[0], "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=_OPEN_HEIGHT,
            supply_tracker=self.supply, voter_reward_pool=self.pool,
        )
        for v in self.voters:
            self.tracker.add_vote(
                create_vote(v, self.prop.proposal_id, True),
                current_block=_OPEN_HEIGHT + 1,
            )

    def test_n4_equal_each_gets_25(self):
        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=_close_post_tier66(),
        )
        self.assertTrue(result["passed"])
        for v in self.voters:
            self.assertEqual(self.supply.balances[v.entity_id], 25)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(self.supply.total_burned, burned_before)


# ---------------------------------------------------------------------------
# Pre-fork byte-identity invariant
# ---------------------------------------------------------------------------


class TestPreTier66LegacyByteIdentity(unittest.TestCase):
    """Pre-fork (close-block height < VOTER_REWARD_ADAPTIVE_CAP_HEIGHT)
    the cap stays at the legacy 25%.  This pin asserts that running
    the lone-voter fixture before activation produces the legacy
    burn-75% outcome -- i.e. the new code path does NOT engage on
    historical proposals, preserving byte-for-byte replay through
    Tier 66 -1.
    """

    def test_pre_activation_lone_voter_still_burns_75pct(self):
        lone = Entity.create(b"r37-vr-lone-pre".ljust(32, b"\x00"))
        lone.keypair._next_leaf = 0
        supply = SupplyTracker()
        supply.staked[lone.entity_id] = 100
        supply.balances[lone.entity_id] = 0

        tracker = GovernanceTracker()
        pool = 100
        prop = create_proposal(lone, "t", "d")
        tracker.add_proposal(
            prop, block_height=_OPEN_HEIGHT,
            supply_tracker=supply, voter_reward_pool=pool,
        )
        tracker.add_vote(
            create_vote(lone, prop.proposal_id, True),
            current_block=_OPEN_HEIGHT + 1,
        )

        burned_before = supply.total_burned
        # Close at exactly Tier 66 activation height MINUS 1 -- adaptive
        # cap must NOT be active here.  Tier 65 redistribute IS active
        # at this height (it activates earlier), but with N=1 voter the
        # redistribute path has nowhere to put the excess so the legacy
        # 75% burn is preserved.
        close = max(
            _OPEN_HEIGHT + GOVERNANCE_VOTING_WINDOW + 1,
            VOTER_REWARD_ADAPTIVE_CAP_HEIGHT - 1,
        )
        result = tracker.finalize_voter_rewards(
            prop.proposal_id, supply, current_block=close,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(supply.balances[lone.entity_id], 25)
        self.assertEqual(result["burned"], 75)
        self.assertEqual(supply.total_burned, burned_before + 75)


# ---------------------------------------------------------------------------
# Invariant: post-fork distributed >= pre-fork distributed for any N<=3
# (the small-N regime where adaptive cap actively raises the cap).
# ---------------------------------------------------------------------------


class TestAdaptiveCapMonotonicallyIncreasesDistributed(unittest.TestCase):
    """For N in {1,2,3} the adaptive cap is strictly above the legacy
    25% cap, so post-fork distributed sum >= pre-fork distributed sum
    on the same fixture.  This is the load-bearing invariant: the fix
    only ever pays more to voters; it never pays less."""

    def _run_n_voters(self, n: int, close_height: int) -> tuple[int, int]:
        voters = []
        supply = SupplyTracker()
        per_stake = 100 // n  # equal stakes summing to 100 (or close)
        for i in range(n):
            e = Entity.create(
                f"r37-vr-{n}eq-{i}".encode().ljust(32, b"\x00"),
            )
            e.keypair._next_leaf = 0
            voters.append(e)
            supply.staked[e.entity_id] = per_stake
            supply.balances[e.entity_id] = 0

        tracker = GovernanceTracker()
        pool = 100
        prop = create_proposal(voters[0], "t", "d")
        tracker.add_proposal(
            prop, block_height=_OPEN_HEIGHT,
            supply_tracker=supply, voter_reward_pool=pool,
        )
        for v in voters:
            tracker.add_vote(
                create_vote(v, prop.proposal_id, True),
                current_block=_OPEN_HEIGHT + 1,
            )

        result = tracker.finalize_voter_rewards(
            prop.proposal_id, supply, current_block=close_height,
        )
        distributed = pool - result["burned"]
        return distributed, result["burned"]

    def test_post_fork_distributed_at_least_pre_fork(self):
        for n in (1, 2, 3):
            with self.subTest(n=n):
                pre_d, _ = self._run_n_voters(n, _close_pre_tier66())
                post_d, _ = self._run_n_voters(n, _close_post_tier66())
                self.assertGreaterEqual(
                    post_d, pre_d,
                    f"N={n}: post-Tier-66 distributed ({post_d}) must be "
                    f">= pre-Tier-66 distributed ({pre_d}) -- the fix "
                    f"only ever pays more to voters",
                )

    def test_post_fork_n1_zero_burn(self):
        d, b = self._run_n_voters(1, _close_post_tier66())
        self.assertEqual(d, 100)
        self.assertEqual(b, 0)

    def test_post_fork_n2_zero_burn_with_equal_stake(self):
        d, b = self._run_n_voters(2, _close_post_tier66())
        self.assertEqual(d, 100)
        self.assertEqual(b, 0)


if __name__ == "__main__":
    unittest.main()
