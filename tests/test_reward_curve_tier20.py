"""Tier 20: sigmoid validator-reward curve helper.

Tier 20 introduces a piecewise-constant multiplier on per-attester
rewards based on the validator's stake share of total active stake:

    share <  SMALL_THRESHOLD                → SMALL multiplier (<1.0)
    SMALL_THRESHOLD ≤ share < MID_THRESHOLD → MID multiplier   (>1.0)
    share ≥ MID_THRESHOLD                   → 1/1 baseline

This file covers the pure helper `reward_curve_multiplier` only — the
mint-side wiring, sim-mirror, and apply/sim parity tests live in a
separate test module that lands together with the consensus-path
change.  Keeping the helper-level tests here means the helper can be
reviewed in isolation and the wiring change has its own focused diff.
"""

import unittest

from messagechain.config import (
    REWARD_CURVE_HEIGHT,
    REWARD_CURVE_SMALL_THRESHOLD_BPS,
    REWARD_CURVE_MID_THRESHOLD_BPS,
    REWARD_CURVE_SMALL_NUMERATOR,
    REWARD_CURVE_SMALL_DENOMINATOR,
    REWARD_CURVE_MID_NUMERATOR,
    REWARD_CURVE_MID_DENOMINATOR,
    PROPOSAL_FEE_TIER19_HEIGHT,
)
from messagechain.economics.inflation import reward_curve_multiplier


class TestRewardCurveActivation(unittest.TestCase):
    """Activation height must follow Tier 19 with runway."""

    def test_activation_after_tier_19(self):
        # Tier ordering invariant — the asserts in config.py already
        # enforce this at module-import time, but a test makes the
        # invariant visible to anyone reading the test suite.
        self.assertGreater(REWARD_CURVE_HEIGHT, PROPOSAL_FEE_TIER19_HEIGHT)

    def test_runway_at_least_2000_blocks(self):
        # ~14 days at 600 s/block — operators need time to upgrade
        # past the prior fork before the new reward distribution
        # starts biting.  The 2000-block runway is the same shape
        # used for Tier 18 → Tier 19.
        self.assertGreaterEqual(
            REWARD_CURVE_HEIGHT - PROPOSAL_FEE_TIER19_HEIGHT, 2000,
        )


class TestRewardCurveBands(unittest.TestCase):
    """Three regions: small (<1.0), mid (>1.0), large (1.0)."""

    def test_zero_stake_falls_into_small_band(self):
        # bps = 0 is well below SMALL_THRESHOLD (50) — small multiplier.
        # Note: total_active_stake = 0 must be short-circuited to (1, 1)
        # by the caller before invoking the helper; this test exercises
        # the in-band case where a validator simply has very little
        # stake relative to the network.
        self.assertEqual(
            reward_curve_multiplier(0),
            (REWARD_CURVE_SMALL_NUMERATOR, REWARD_CURVE_SMALL_DENOMINATOR),
        )

    def test_small_band_just_under_threshold(self):
        bps = REWARD_CURVE_SMALL_THRESHOLD_BPS - 1
        self.assertEqual(
            reward_curve_multiplier(bps),
            (REWARD_CURVE_SMALL_NUMERATOR, REWARD_CURVE_SMALL_DENOMINATOR),
        )

    def test_small_band_returns_lt_one_multiplier(self):
        # The whole point of the small band is suppression.  Verify
        # the encoded ratio is strictly < 1 by cross-multiplication.
        num, den = reward_curve_multiplier(0)
        self.assertLess(num * 1, den * 1)

    def test_mid_band_at_lower_threshold(self):
        bps = REWARD_CURVE_SMALL_THRESHOLD_BPS  # exactly 50 bp = 0.5%
        self.assertEqual(
            reward_curve_multiplier(bps),
            (REWARD_CURVE_MID_NUMERATOR, REWARD_CURVE_MID_DENOMINATOR),
        )

    def test_mid_band_middle(self):
        # Halfway through the mid band.
        bps = (
            REWARD_CURVE_SMALL_THRESHOLD_BPS
            + REWARD_CURVE_MID_THRESHOLD_BPS
        ) // 2
        self.assertEqual(
            reward_curve_multiplier(bps),
            (REWARD_CURVE_MID_NUMERATOR, REWARD_CURVE_MID_DENOMINATOR),
        )

    def test_mid_band_just_under_upper_threshold(self):
        bps = REWARD_CURVE_MID_THRESHOLD_BPS - 1
        self.assertEqual(
            reward_curve_multiplier(bps),
            (REWARD_CURVE_MID_NUMERATOR, REWARD_CURVE_MID_DENOMINATOR),
        )

    def test_mid_band_returns_gt_one_multiplier(self):
        num, den = reward_curve_multiplier(
            REWARD_CURVE_SMALL_THRESHOLD_BPS,
        )
        self.assertGreater(num * 1, den * 1)

    def test_large_band_at_upper_threshold(self):
        bps = REWARD_CURVE_MID_THRESHOLD_BPS  # exactly 500 bp = 5%
        self.assertEqual(reward_curve_multiplier(bps), (1, 1))

    def test_large_band_well_above_threshold(self):
        # 50% stake share — clearly large region.
        self.assertEqual(reward_curve_multiplier(5_000), (1, 1))

    def test_large_band_at_full_share(self):
        # 100% stake share (10_000 bp) — degenerate single-validator
        # network.  Must still return baseline; the curve is a multiplier
        # on the existing distribution, not an additional cap.
        self.assertEqual(reward_curve_multiplier(10_000), (1, 1))


class TestRewardCurveBoundaryOrdering(unittest.TestCase):
    """The piecewise function must be monotone-by-band: small < mid > large."""

    def test_small_lt_mid_at_threshold_crossing(self):
        # Crossing from small (just below 50 bp) to mid (at 50 bp) is
        # the discontinuity from <1.0 to >1.0.  Verify direction.
        small_num, small_den = reward_curve_multiplier(
            REWARD_CURVE_SMALL_THRESHOLD_BPS - 1,
        )
        mid_num, mid_den = reward_curve_multiplier(
            REWARD_CURVE_SMALL_THRESHOLD_BPS,
        )
        self.assertLess(small_num * mid_den, mid_num * small_den)

    def test_mid_gt_large_at_threshold_crossing(self):
        # Crossing from mid (just below 500 bp) to large (at 500 bp)
        # is the discontinuity from >1.0 back down to 1.0.  Verify
        # direction.
        mid_num, mid_den = reward_curve_multiplier(
            REWARD_CURVE_MID_THRESHOLD_BPS - 1,
        )
        large_num, large_den = reward_curve_multiplier(
            REWARD_CURVE_MID_THRESHOLD_BPS,
        )
        self.assertGreater(mid_num * large_den, large_num * mid_den)

    def test_small_lt_large_overall(self):
        # End-to-end: a tiny-stake validator earns LESS per unit reward
        # than a baseline (large) validator.  This is the headline
        # invariant the curve exists to express.
        small_num, small_den = reward_curve_multiplier(0)
        large_num, large_den = reward_curve_multiplier(10_000)
        self.assertLess(small_num * large_den, large_num * small_den)


class TestRewardCurveAppliedToReward(unittest.TestCase):
    """Verify caller-side `reward * num // den` produces the intended bands."""

    BASE_REWARD = 1_000

    def _apply(self, bps: int) -> int:
        num, den = reward_curve_multiplier(bps)
        return self.BASE_REWARD * num // den

    def test_small_validator_earns_less(self):
        small = self._apply(0)
        baseline = self._apply(10_000)
        self.assertLess(small, baseline)
        # 80/100 of base = 800
        self.assertEqual(
            small,
            self.BASE_REWARD
            * REWARD_CURVE_SMALL_NUMERATOR
            // REWARD_CURVE_SMALL_DENOMINATOR,
        )

    def test_mid_validator_earns_more(self):
        mid = self._apply(REWARD_CURVE_SMALL_THRESHOLD_BPS)
        baseline = self._apply(10_000)
        self.assertGreater(mid, baseline)
        # 125/100 of base = 1250
        self.assertEqual(
            mid,
            self.BASE_REWARD
            * REWARD_CURVE_MID_NUMERATOR
            // REWARD_CURVE_MID_DENOMINATOR,
        )

    def test_large_validator_earns_baseline(self):
        # Large band is byte-identical to legacy distribution.
        baseline = self._apply(10_000)
        self.assertEqual(baseline, self.BASE_REWARD)

    def test_integer_arithmetic_only(self):
        # Helper must return ints — consensus path is float-free.
        for bps in (0, 49, 50, 100, 499, 500, 5_000, 10_000):
            num, den = reward_curve_multiplier(bps)
            self.assertIsInstance(num, int)
            self.assertIsInstance(den, int)
            self.assertGreater(den, 0)


if __name__ == "__main__":
    unittest.main()
