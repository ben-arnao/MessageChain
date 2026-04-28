"""Tier 37 — reward-curve large band saturates downward.

CLAUDE.md anchors the stake reward curve as small < middle > large, with
"large saturating to flat/linear past a cap point."  The pre-Tier-37
curve was piecewise-constant 0.80 / 1.25 / 1.00 — a 5%-stake mid-tier
validator and a 40%-stake whale earned at the *same* per-token rate, so
the "large saturating" anchor was not satisfied.  The large band was
just a flat extension of the baseline, never compressing downward.

Tier 37 adds a fourth band: between LARGE_THRESHOLD_BPS and
LARGE_FLOOR_THRESHOLD_BPS the multiplier interpolates linearly from
1.00 down to LARGE_FLOOR_NUM / LARGE_FLOOR_DEN, then flat at the floor
past LARGE_FLOOR_THRESHOLD_BPS.  Pre-fork the legacy 0.80/1.25/1.00
behavior must be byte-identical for historical replay determinism.

This file pins three properties:

  1. POST-FORK monotone non-increasing per-unit-stake yield for stake
     shares ≥ MID_THRESHOLD (the broken band today).  Specifically:
       yield(15%) >= yield(20%) >= yield(30%)  and  yield(30%) > 0.
     The 5%→15% transition stays at 1.0 (preserves current behavior in
     the active stake range), the 15%→30% transition compresses
     downward.

  2. PRE-FORK byte-identical legacy behavior at the same input grid.

  3. Pure-integer determinism — the consensus hot path never coerces
     any input through float().  Mirrors the _NoFloatInt sentinel
     pattern from the 1.35.0 honesty-curve work.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    REWARD_CURVE_HEIGHT,
    REWARD_CURVE_LARGE_BAND_HEIGHT,
    REWARD_CURVE_LARGE_FLOOR_DEN,
    REWARD_CURVE_LARGE_FLOOR_NUM,
    REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
    REWARD_CURVE_LARGE_THRESHOLD_BPS,
    REWARD_CURVE_MID_DENOMINATOR,
    REWARD_CURVE_MID_NUMERATOR,
    REWARD_CURVE_MID_THRESHOLD_BPS,
    REWARD_CURVE_SMALL_DENOMINATOR,
    REWARD_CURVE_SMALL_NUMERATOR,
    REWARD_CURVE_SMALL_THRESHOLD_BPS,
)
from messagechain.economics.inflation import (
    reward_curve_multiplier,
    reward_curve_multiplier_v2,
)


# Stake shares (in bps) we test the curve at.  These map to:
#   10  bp =  0.1%   (small)
#   100 bp =  1%     (mid)
#   500 bp =  5%     (mid→large transition)
#   1000 bp= 10%     (large flat)
#   1500 bp= 15%     (large→saturation start)
#   2000 bp= 20%     (in the saturation slope)
#   2500 bp= 25%     (deeper saturation)
#   3000 bp= 30%     (floor boundary)
#   4000 bp= 40%     (well past floor)
_STAKE_GRID_BPS = [10, 100, 500, 1000, 1500, 2000, 2500, 3000, 4000]


class TestActivationOrdering(unittest.TestCase):
    """Tier 37 must follow the existing reward-curve fork (Tier 20)."""

    def test_activation_after_tier_20(self):
        # The new large-band gate cannot fire before the original
        # small/mid/large piecewise curve activated, otherwise pre-Tier-
        # 20 history would suddenly grow a multiplier path that never
        # existed there.
        self.assertGreater(
            REWARD_CURVE_LARGE_BAND_HEIGHT, REWARD_CURVE_HEIGHT,
        )

    def test_threshold_ordering(self):
        # Large saturation starts at LARGE_THRESHOLD_BPS and bottoms at
        # LARGE_FLOOR_THRESHOLD_BPS.  The two must straddle MID_THRESHOLD
        # (5% — the legacy "large" band starts) and stay strictly < 100%.
        self.assertGreater(
            REWARD_CURVE_LARGE_THRESHOLD_BPS,
            REWARD_CURVE_MID_THRESHOLD_BPS,
        )
        self.assertGreater(
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
            REWARD_CURVE_LARGE_THRESHOLD_BPS,
        )
        self.assertLess(REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS, 10_000)

    def test_floor_strictly_below_baseline(self):
        # Multiplier at the floor must be strictly less than 1.0,
        # otherwise the large band saturates back to baseline (the bug
        # we're fixing).  Cross-multiply to keep the check integer.
        self.assertLess(
            REWARD_CURVE_LARGE_FLOOR_NUM,
            REWARD_CURVE_LARGE_FLOOR_DEN,
        )
        self.assertGreater(REWARD_CURVE_LARGE_FLOOR_NUM, 0)


class TestPreForkLegacyByteIdentical(unittest.TestCase):
    """Pre-fork callers MUST see the legacy 0.80 / 1.25 / 1.00 curve."""

    def test_pre_fork_uses_legacy_helper(self):
        # The legacy `reward_curve_multiplier` helper is unchanged.
        # Pre-fork callers continue to call it directly; the v2 helper
        # is only invoked at heights >= REWARD_CURVE_LARGE_BAND_HEIGHT.
        for bps in _STAKE_GRID_BPS:
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier(bps)
                if bps < REWARD_CURVE_SMALL_THRESHOLD_BPS:
                    self.assertEqual(
                        (num, den),
                        (
                            REWARD_CURVE_SMALL_NUMERATOR,
                            REWARD_CURVE_SMALL_DENOMINATOR,
                        ),
                    )
                elif bps < REWARD_CURVE_MID_THRESHOLD_BPS:
                    self.assertEqual(
                        (num, den),
                        (
                            REWARD_CURVE_MID_NUMERATOR,
                            REWARD_CURVE_MID_DENOMINATOR,
                        ),
                    )
                else:
                    self.assertEqual((num, den), (1, 1))


class TestPostForkBands(unittest.TestCase):
    """Post-fork curve has small / mid / flat-large / sloped / floor bands."""

    def test_small_band_matches_legacy(self):
        # Small band (<0.5%) is unchanged at 80/100.
        num, den = reward_curve_multiplier_v2(10)  # 0.1%
        self.assertEqual(
            (num, den),
            (REWARD_CURVE_SMALL_NUMERATOR, REWARD_CURVE_SMALL_DENOMINATOR),
        )

    def test_mid_band_matches_legacy(self):
        # Mid band (0.5%–5%) is unchanged at 125/100.
        num, den = reward_curve_multiplier_v2(100)  # 1%
        self.assertEqual(
            (num, den),
            (REWARD_CURVE_MID_NUMERATOR, REWARD_CURVE_MID_DENOMINATOR),
        )

    def test_flat_large_band_at_baseline(self):
        # Between MID_THRESHOLD and LARGE_THRESHOLD the multiplier stays
        # at 1.0 — preserves current real-network behavior in the active
        # stake range (5%–15%) and only compresses the upper tail.
        for bps in (
            REWARD_CURVE_MID_THRESHOLD_BPS,
            (
                REWARD_CURVE_MID_THRESHOLD_BPS
                + REWARD_CURVE_LARGE_THRESHOLD_BPS
            ) // 2,
            REWARD_CURVE_LARGE_THRESHOLD_BPS - 1,
        ):
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier_v2(bps)
                self.assertEqual(num, den)  # 1.0 in any int form

    def test_saturation_floor_at_and_past_floor_threshold(self):
        # At and past LARGE_FLOOR_THRESHOLD the multiplier sits at the
        # floor.
        for bps in (
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS + 1,
            10_000,
        ):
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier_v2(bps)
                # num/den == LARGE_FLOOR_NUM/LARGE_FLOOR_DEN.  Compare
                # by cross-multiply to keep integer-only.
                self.assertEqual(
                    num * REWARD_CURVE_LARGE_FLOOR_DEN,
                    den * REWARD_CURVE_LARGE_FLOOR_NUM,
                )


class TestPostForkMonotoneSaturation(unittest.TestCase):
    """Per-unit-stake yield must be monotone non-increasing for share >= 5%."""

    BASE_REWARD = 1_000_000

    def _yield_per_bp(self, bps: int) -> tuple[int, int]:
        """Return (yield_num, yield_den) such that the apply step's
        per-bp yield equals BASE_REWARD * num / (den * bps).

        We keep this as a rational so the monotonicity check stays
        integer-arithmetic.
        """
        if bps == 0:
            # Avoid division by zero — caller never tests bps=0 in this
            # class.
            raise ValueError("bps must be > 0")
        num, den = reward_curve_multiplier_v2(bps)
        # yield-per-bp = (BASE_REWARD * num) / (den * bps)
        return (self.BASE_REWARD * num, den * bps)

    def _yield_le(
        self, a: tuple[int, int], b: tuple[int, int],
    ) -> bool:
        """True if a <= b, both as positive rationals (num/den)."""
        return a[0] * b[1] <= b[0] * a[1]

    def test_monotone_non_increasing_above_mid_threshold(self):
        # Sample at 5%, 10%, 15%, 20%, 25%, 30%, 40%.  Per-unit-stake
        # yield must be monotone non-increasing across the whole sweep
        # — the headline anchor.
        sample_bps = [500, 1000, 1500, 2000, 2500, 3000, 4000]
        prev = self._yield_per_bp(sample_bps[0])
        for bps in sample_bps[1:]:
            cur = self._yield_per_bp(bps)
            with self.subTest(bps=bps):
                self.assertTrue(
                    self._yield_le(cur, prev),
                    f"per-bp yield NOT non-increasing at {bps}: "
                    f"prev_num/den = {prev}, cur_num/den = {cur}",
                )
            prev = cur

    def test_yield_at_15pct_geq_yield_at_20pct_geq_yield_at_30pct(self):
        # Explicit checkpoint from the prompt: yield(15%) >= yield(20%)
        # >= yield(30%) and yield(30%) > 0.
        y15 = self._yield_per_bp(1500)
        y20 = self._yield_per_bp(2000)
        y30 = self._yield_per_bp(3000)
        self.assertTrue(self._yield_le(y20, y15))
        self.assertTrue(self._yield_le(y30, y20))
        # y30 > 0
        self.assertGreater(y30[0], 0)
        self.assertGreater(y30[1], 0)

    def test_yield_at_15pct_strictly_greater_than_yield_at_30pct(self):
        # Compression actually happens: y15 > y30 strictly.  Cross-
        # multiply to stay integer.
        y15 = self._yield_per_bp(1500)
        y30 = self._yield_per_bp(3000)
        self.assertGreater(
            y15[0] * y30[1], y30[0] * y15[1],
            f"y15={y15} should strictly exceed y30={y30}; "
            "the saturating-large band is not compressing",
        )


class TestPostForkLinearInterpolation(unittest.TestCase):
    """Saturation slope between LARGE_THRESHOLD and LARGE_FLOOR_THRESHOLD
    interpolates linearly from 1.0 down to LARGE_FLOOR_NUM/DEN."""

    def test_at_lower_kink_multiplier_is_one(self):
        num, den = reward_curve_multiplier_v2(
            REWARD_CURVE_LARGE_THRESHOLD_BPS,
        )
        self.assertEqual(num, den)

    def test_at_upper_kink_multiplier_is_floor(self):
        num, den = reward_curve_multiplier_v2(
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
        )
        self.assertEqual(
            num * REWARD_CURVE_LARGE_FLOOR_DEN,
            den * REWARD_CURVE_LARGE_FLOOR_NUM,
        )

    def test_midpoint_is_halfway(self):
        # At the bps midpoint between LARGE_THRESHOLD and
        # LARGE_FLOOR_THRESHOLD the multiplier should be the midpoint
        # between 1.0 and floor — i.e. (1 + floor) / 2.
        mid_bps = (
            REWARD_CURVE_LARGE_THRESHOLD_BPS
            + REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS
        ) // 2
        num, den = reward_curve_multiplier_v2(mid_bps)
        # Expected (1.0 + LARGE_FLOOR_NUM/DEN) / 2
        # = (DEN + LARGE_FLOOR_NUM) / (2 * DEN)
        expected_num = (
            REWARD_CURVE_LARGE_FLOOR_DEN + REWARD_CURVE_LARGE_FLOOR_NUM
        )
        expected_den = 2 * REWARD_CURVE_LARGE_FLOOR_DEN
        # Cross-multiply.  Allow off-by-one floor in either direction
        # because the implementation uses integer floor division — at
        # the midpoint either rounding is acceptable so long as the
        # result is in [floor, 1.0] and close to the midpoint.
        # Specifically: |num*expected_den - den*expected_num| should be
        # small relative to den*expected_den (well under 1%).
        diff = abs(num * expected_den - den * expected_num)
        bound = den * expected_den // 100  # 1% tolerance
        self.assertLessEqual(
            diff, bound,
            f"midpoint multiplier drift too large: {num}/{den} vs "
            f"{expected_num}/{expected_den}",
        )


class TestPostForkPureIntegerDeterminism(unittest.TestCase):
    """Mirror the _NoFloatInt sentinel pattern from the 1.35.0 honesty-
    curve work — the consensus hot path must never invoke float()."""

    def test_helper_uses_no_float_arithmetic(self):
        class _NoFloatInt(int):
            def __float__(self):  # pragma: no cover - sentinel
                raise AssertionError(
                    "reward_curve_multiplier_v2 must not invoke float() "
                    "on consensus inputs",
                )

        # Sweep representative bps — small, mid, both flat-large bands,
        # the saturation slope (multiple sample points), the floor, and
        # past the floor.
        for raw_bps in _STAKE_GRID_BPS + [
            REWARD_CURVE_LARGE_THRESHOLD_BPS,
            REWARD_CURVE_LARGE_THRESHOLD_BPS + 1,
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS - 1,
            REWARD_CURVE_LARGE_FLOOR_THRESHOLD_BPS,
            10_000,
        ]:
            with self.subTest(bps=raw_bps):
                num, den = reward_curve_multiplier_v2(_NoFloatInt(raw_bps))
                self.assertIsInstance(num, int)
                self.assertIsInstance(den, int)
                self.assertGreater(den, 0)
                self.assertGreater(num, 0)


if __name__ == "__main__":
    unittest.main()
