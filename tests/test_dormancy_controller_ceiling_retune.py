"""Regression tests for the Tier-47 dormancy-controller ceiling/gain
retune.

Audit finding (2026-05-05): the original (K=1/100_000, MAX=64) tuning
left the controller saturated under the codebase's own documented burn
rate (10–15M tokens/yr per the TARGET_CIRCULATING_SUPPLY_FLOOR
commentary in config.py).  At MAX=64 tokens/block × 52,560 blocks/yr
the ceiling pegged annual issuance at ~3.37M — 3-5x below the burn —
so net active supply continued falling indefinitely once gap ≥ 6.4M
(~4.6% of the 140M target).  Retune lifts MAX → 500 (~26.3M/yr,
~2× burn) and tightens K → 1/20_000 so the controller actually closes
the gap quarterly rather than every 16 months.

These tests assert the *post-retune* behavior:
  * Steady-state burn (gap ≈ 12M, mid-range): annual issuance ≥ burn.
  * Tail event (gap = 100M, founder dormancy): controller is at the
    new ceiling (the only sensible answer when gap exceeds what the
    proportional term can produce in one block).
  * Anchor preservation: gap=0 → 0, monotone non-decreasing, pre-
    activation no-op.

They are sized off the constants directly so a future re-tune that
changes the numbers but preserves the shape leaves them passing.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_CONTROLLER_K_DEN,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
)
from messagechain.economics.inflation import SupplyTracker

BLOCKS_PER_YEAR = 52_560  # 600s blocks


class TestSteadyStateBurnCoverage(unittest.TestCase):
    """At a representative mid-range annual gap (~12M tokens, the
    midpoint of the 10–15M/yr documented burn estimate), the
    controller's annual output must MEET OR EXCEED the burn rate.
    Pre-retune (MAX=64) this fails by ~3-5x; post-retune it passes
    with margin.
    """

    def test_annual_issuance_covers_documented_burn(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_HEIGHT + 100
        documented_burn_per_year = 12_000_000
        s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - documented_burn_per_year,
        }
        s.bump_active(b"X" * 32, h)

        per_block = s.compute_dormancy_issuance(h)
        annual = per_block * BLOCKS_PER_YEAR
        self.assertGreaterEqual(
            annual,
            documented_burn_per_year,
            f"annual issuance {annual:,} < documented burn "
            f"{documented_burn_per_year:,} — controller cannot close the gap",
        )


class TestFounderDormancyTailEvent(unittest.TestCase):
    """The largest plausible gap the controller will see: founder
    (~71% of genesis supply) goes dormant for the 25-year window.
    Post-taper, active_supply collapses from 140M → ~40M, gap ≈ 100M.
    The controller saturates at MAX (the proportional term wants
    1000 tokens/block at K=1/20_000 vs MAX=500, so MAX binds), and
    we want MAX itself to be a meaningful refill rate.
    """

    def test_founder_dormancy_pegs_at_max(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_HEIGHT + 100
        # 100M gap: 71% of supply (founder) tapered out.
        s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - 100_000_000}
        s.bump_active(b"X" * 32, h)

        per_block = s.compute_dormancy_issuance(h)
        # The proportional term at gap=100M, K=1/20_000 is 5000, so
        # the ceiling binds.  Asserting ==MAX rather than >=MAX so a
        # future retune that raises MAX without raising K notices the
        # rebalance.
        self.assertEqual(per_block, DORMANCY_MAX_ISSUANCE_PER_BLOCK)


class TestAnchorPreservation(unittest.TestCase):
    """The retune must not change the controller's shape — only its
    parameters.  These assertions encode the shape itself."""

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_HEIGHT + 100

    def test_at_target_zero_issuance(self):
        # Anchor: at target the controller mints zero — validators
        # run on fees alone, issuance is for supply integrity.
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY}
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_above_target_zero_issuance(self):
        # Anchor: gap clamped at zero — controller never burns to
        # reduce supply.
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY * 2}
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_monotone_non_decreasing_in_gap(self):
        # Anchor: larger gap → at-least-as-large issuance, up to the
        # ceiling.  Sample a wide range of gaps, including ones that
        # straddle the saturation boundary.
        target = DORMANCY_TARGET_ACTIVE_SUPPLY
        gaps = [
            0,
            DORMANCY_CONTROLLER_K_DEN,
            DORMANCY_CONTROLLER_K_DEN * 100,
            DORMANCY_MAX_ISSUANCE_PER_BLOCK
            * DORMANCY_CONTROLLER_K_DEN
            // DORMANCY_CONTROLLER_K_NUM,
            target // 2,
            target,
        ]
        prev = -1
        for gap in gaps:
            self.s.balances = {b"X" * 32: target - gap}
            self.s.bump_active(b"X" * 32, self.h)
            cur = self.s.compute_dormancy_issuance(self.h)
            self.assertGreaterEqual(
                cur, prev, f"non-monotone at gap={gap}: {cur} < {prev}",
            )
            prev = cur

    def test_pre_activation_controller_does_not_run(self):
        # Anchor: pre-DORMANCY_CONTROLLER_HEIGHT, calculate_block_reward
        # routes through the legacy halving + deflation-floor schedule,
        # NOT through the controller.  This is what makes the in-place
        # constant retune safe — historical blocks below the activation
        # height keep their byte-for-byte legacy reward.
        s = SupplyTracker()
        legacy = s._calculate_legacy_block_reward(DORMANCY_CONTROLLER_HEIGHT - 1)
        dispatched = s.calculate_block_reward(DORMANCY_CONTROLLER_HEIGHT - 1)
        self.assertEqual(dispatched, legacy)


if __name__ == "__main__":
    unittest.main()
