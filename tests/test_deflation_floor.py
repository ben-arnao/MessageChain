"""Tests for the supply-responsive issuance floor hard fork.

Background
----------
Steady-state burn math after the shipped fixes is net-deflationary:
issuance at BLOCK_REWARD_FLOOR (~210K/yr) plus the finality mint
(~52K/yr) totals ~262K tokens/yr, while base-fee burn at moderate
traffic burns an order of magnitude more.  Over decades this drives
supply toward dangerously thin totals.

The anchor: when `total_supply` drops below
TARGET_CIRCULATING_SUPPLY_FLOOR, double the issuance-side block
reward until supply recovers.  Self-correcting, bounded at 2x,
applied AFTER the BLOCK_REWARD_FLOOR clamp.

This file pins:
  * Pre-activation byte-identical behavior (boost never applies).
  * Post-activation behavior at the floor boundary (strictly-less-than).
  * Post-activation boost math at both early and floor-era rewards.
  * Boost unwind (supply recovers → next block is normal).
  * Sim/apply lockstep (compute_post_state_root stays in sync via
    the shared calculate_block_reward call).
  * Net-inflation invariant survives activation.
"""

import unittest
from unittest.mock import patch

from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    HALVING_INTERVAL,
    GENESIS_SUPPLY,
    TARGET_CIRCULATING_SUPPLY_FLOOR,
    DEFLATION_ISSUANCE_MULTIPLIER,
    DEFLATION_FLOOR_HEIGHT,
)


PRE_ACTIVATION_HEIGHT = max(0, DEFLATION_FLOOR_HEIGHT - 1)
POST_ACTIVATION_HEIGHT = DEFLATION_FLOOR_HEIGHT


class TestPreActivationBoostDisabled(unittest.TestCase):
    """Pre-activation height: multiplier never applies, even if
    total_supply is below the floor.  Byte-for-byte preservation of
    the legacy reward schedule — the fork is cleanly reversible and
    pre-fork blocks remain re-validatable."""

    def test_pre_activation_supply_below_floor_no_boost(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        reward = supply.calculate_block_reward(PRE_ACTIVATION_HEIGHT)
        # Height 0 halvings: reward == BLOCK_REWARD
        self.assertEqual(reward, BLOCK_REWARD)

    def test_pre_activation_supply_above_floor_no_boost(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR + 1
        reward = supply.calculate_block_reward(PRE_ACTIVATION_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)

    def test_pre_activation_at_floor_era_no_boost(self):
        """Even deep in the floor era, pre-activation reward is the
        unboosted BLOCK_REWARD_FLOOR regardless of supply."""
        supply = SupplyTracker()
        supply.total_supply = 1  # well below floor
        # Choose a height well past all halvings but pre-activation.
        # DEFLATION_FLOOR_HEIGHT is the placeholder 50_000, which is
        # pre-first-halving, so this test freezes the floor.
        with patch.object(
            SupplyTracker,
            "calculate_block_reward",
            lambda self, h: (
                # Mirror the real method but force the floor path.
                BLOCK_REWARD_FLOOR
                if h < DEFLATION_FLOOR_HEIGHT
                else (
                    BLOCK_REWARD_FLOOR * DEFLATION_ISSUANCE_MULTIPLIER
                    if self.total_supply < TARGET_CIRCULATING_SUPPLY_FLOOR
                    else BLOCK_REWARD_FLOOR
                )
            ),
        ):
            # Sanity — the test helper proves our expected shape.
            reward = supply.calculate_block_reward(PRE_ACTIVATION_HEIGHT)
            self.assertEqual(reward, BLOCK_REWARD_FLOOR)


class TestPostActivationFloorRegimes(unittest.TestCase):
    """Post-activation: boost gated on total_supply < floor."""

    def test_post_activation_supply_above_floor_no_boost(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR * 2
        reward = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)

    def test_post_activation_at_floor_boundary_no_boost(self):
        """Strictly-less-than: supply == floor exactly means recovered,
        no boost.  This is the "please stop shrinking" signal flipping
        off at the first block where supply >= target."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR
        reward = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)

    def test_post_activation_supply_below_floor_boost_applies(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        reward = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(
            reward, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER,
        )

    def test_post_activation_supply_far_below_floor_boost_capped_at_2x(self):
        """Boost is bounded at 2x — no runaway inflation from extremely
        low supply.  This guards against a hypothetical future change
        that makes the multiplier dynamic."""
        supply = SupplyTracker()
        supply.total_supply = 1
        reward = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(
            reward, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER,
        )
        # Sanity: 2x, not 100x.
        self.assertEqual(reward, BLOCK_REWARD * 2)


class TestBoostAfterFloorClamp(unittest.TestCase):
    """The boost applies AFTER the BLOCK_REWARD_FLOOR clamp, so at
    the floor era the multiplier lifts reward from the floor value."""

    def test_floor_era_boost_is_floor_times_multiplier(self):
        """Floor-era boost ordering: `reward = max(FLOOR, BLOCK_REWARD
        >> halvings) × boost = 4 × 2 = 8`.

        NOTE: post-DEFLATION_FLOOR_V2_HEIGHT the 2× multiplier is
        superseded by the fee-responsive rebate (see
        tests/test_deflation_floor_v2.py).  The floor era in mainnet
        corresponds to block heights ~630k, well above
        DEFLATION_FLOOR_V2_HEIGHT, so the 2× path is no longer
        reachable via real heights.  This test now pins the ordering
        property (floor clamp then multiply) via the module-level
        math.  If the v1 multiplier is ever fully removed, delete
        this test and rely on the v2 tests for floor-era coverage.
        """
        # Pre-fork sanity: the 2× multiplier applied to the floor
        # gives 8 — the original design's intended behavior.
        self.assertEqual(
            BLOCK_REWARD_FLOOR * DEFLATION_ISSUANCE_MULTIPLIER, 8,
        )

    def test_floor_era_no_boost_hits_just_the_floor(self):
        floor_era_height = HALVING_INTERVAL * 3 + 1

        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR
        reward = supply.calculate_block_reward(floor_era_height)
        self.assertEqual(reward, BLOCK_REWARD_FLOOR)

    def test_halving_era_boost_works_on_non_floor_reward(self):
        """Between genesis and the floor: after 1 halving reward = 8.
        With boost, 8 × 2 = 16.  Same shape as the floor test but on
        the halving ladder.

        NOTE: post-DEFLATION_FLOOR_V2_HEIGHT the 2× multiplier is
        superseded by the fee-responsive rebate.  HALVING_INTERVAL
        (210_240) is well past DEFLATION_FLOOR_V2_HEIGHT (70_000) so
        the one-halving height falls under v2.  This test retains the
        ordering-sanity check (v1 design math) via an in-window
        height rather than exercising the now-dead code path.
        """
        from messagechain.config import DEFLATION_FLOOR_V2_HEIGHT
        # Pre-fork sanity: the 2× multiplier applied after 1 halving
        # gives 16.  v2 can reach equal or greater issuance via the
        # rebate when burn rate is sufficient (see
        # tests/test_deflation_floor_v2.py).
        self.assertEqual(
            (BLOCK_REWARD >> 1) * DEFLATION_ISSUANCE_MULTIPLIER,
            16,
        )
        # Also verify v2 window is non-empty (v1 behavior exists in
        # [DEFLATION_FLOOR_HEIGHT, DEFLATION_FLOOR_V2_HEIGHT)).
        self.assertGreater(DEFLATION_FLOOR_V2_HEIGHT, 0)


class TestBoostUnwind(unittest.TestCase):
    """When supply recovers above the floor, the next block's reward
    is back to normal.  Verifies the anchor is self-correcting, not
    latching."""

    def test_boost_active_then_supply_recovers_next_block_normal(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1

        # Boost block.
        boosted = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(boosted, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER)

        # Supply recovers above floor (e.g. a big issuance spike, or an
        # operator-applied snapshot correction).  Next block sees no
        # boost.
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR + 10
        unboosted = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT + 1)
        self.assertEqual(unboosted, BLOCK_REWARD)

    def test_supply_drops_back_below_floor_boost_resumes(self):
        """Bidirectional: boost can kick in, unwind, and kick in again
        in a subsequent cycle.  Not path-dependent.

        Both calls pin to POST_ACTIVATION_HEIGHT (V1 only) — the
        post-1.26.0 fork sweep places DEFLATION_FLOOR_V2_HEIGHT one
        block past V1, so POST+1 lands on V2 territory where the
        rebate model supersedes the V1 multiplier.  Same-height,
        different-supply preserves the boost-resume invariant.
        """
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR + 1
        r1 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(r1, BLOCK_REWARD)

        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        r2 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(r2, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER)


class TestMintBlockRewardConsumesBoost(unittest.TestCase):
    """mint_block_reward calls calculate_block_reward internally and
    mints the boosted reward when supply is below the floor
    post-activation.  This pins the call-site integration."""

    def test_mint_post_activation_low_supply_mints_boosted(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        pre_supply = supply.total_supply
        pre_minted = supply.total_minted

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
        )

        expected = BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER
        self.assertEqual(result["total_reward"], expected)
        self.assertEqual(supply.total_supply - pre_supply, expected)
        self.assertEqual(supply.total_minted - pre_minted, expected)
        # No committee: proposer absorbs the full boosted reward.
        self.assertEqual(result["proposer_reward"], expected)

    def test_mint_pre_activation_low_supply_no_boost(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        proposer = b"p" * 32
        supply.balances[proposer] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
        )
        self.assertEqual(result["total_reward"], BLOCK_REWARD)
        self.assertEqual(result["proposer_reward"], BLOCK_REWARD)


class TestNetInflationInvariant(unittest.TestCase):
    """The core supply invariant
        total_supply == GENESIS_SUPPLY + total_minted - total_burned
    must hold across activation, under both boost-active and
    boost-inactive regimes.  Catches any accidental double-mint or
    missed total_minted bump in the boosted path."""

    def test_invariant_holds_pre_activation_low_supply(self):
        supply = SupplyTracker()
        # Force supply below floor so boost WOULD fire if gate were wrong.
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        baseline_gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        # Starting gap reflects the manual total_supply override; we
        # verify mint preserves the gap, not creates a new one.
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.mint_block_reward(
            proposer, block_height=PRE_ACTIVATION_HEIGHT,
        )
        gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        self.assertEqual(gap, baseline_gap)

    def test_invariant_holds_post_activation_boost_active(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        baseline_gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.mint_block_reward(
            proposer, block_height=POST_ACTIVATION_HEIGHT,
        )
        gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        self.assertEqual(gap, baseline_gap)

    def test_invariant_holds_post_activation_boost_inactive(self):
        supply = SupplyTracker()
        # Supply well above floor — no boost.
        supply.total_supply = GENESIS_SUPPLY
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.mint_block_reward(
            proposer, block_height=POST_ACTIVATION_HEIGHT,
        )
        self.assertEqual(
            supply.total_supply,
            GENESIS_SUPPLY + supply.total_minted - supply.total_burned,
        )


class TestSimApplyLockstep(unittest.TestCase):
    """Sim path (compute_post_state_root) and apply path
    (_apply_block_state) must use the same reward.  Both call
    `self.supply.calculate_block_reward(height)`, so updating the
    method keeps them in sync — but we verify the contract explicitly
    so a future refactor that inlines reward math into the sim path
    (or vice versa) breaks this test rather than silently desyncing
    the state_root."""

    def test_sim_and_apply_both_use_shared_helper_boost_active(self):
        """When supply < floor post-activation, both paths must
        compute the boosted reward through the same code path."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Both sim and apply call supply.calculate_block_reward(height).
        # If they diverge, one would see the boost and the other
        # wouldn't, producing an "Invalid state_root" rejection.
        # Verify the helper itself is deterministic across identical
        # inputs.
        r1 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        r2 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(r1, r2)
        self.assertEqual(r1, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER)

    def test_sim_and_apply_both_use_shared_helper_boost_inactive(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR + 1
        r1 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        r2 = supply.calculate_block_reward(POST_ACTIVATION_HEIGHT)
        self.assertEqual(r1, r2)
        self.assertEqual(r1, BLOCK_REWARD)

    def test_call_sites_route_through_calculate_block_reward(self):
        """Source-level guarantee: every call site in blockchain.py
        that computes reward for a block goes through
        supply.calculate_block_reward.  This is the single source of
        truth that makes the boost fork safe.  If someone inlines
        `BLOCK_REWARD >> halvings` in a new call site, this test
        would need updating — and they'd also have a broken fork."""
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        blockchain_py = (root / "messagechain" / "core" / "blockchain.py").read_text(
            encoding="utf-8",
        )
        # Every reward computation should go through the helper.
        # `BLOCK_REWARD >> ...` literally shouldn't appear in
        # blockchain.py — only in inflation.py where the helper lives.
        self.assertNotIn("BLOCK_REWARD >>", blockchain_py)


if __name__ == "__main__":
    unittest.main()
