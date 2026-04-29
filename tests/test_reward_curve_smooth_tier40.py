"""Tier 40 — smooth concave reward curve.

CLAUDE.md anchors the new shape: a single rational function whose
per-unit-stake yield decreases monotonically from a peak at near-zero
stake toward a floor as stake grows large, asymptotically approaching
the floor without ever reaching it.  Replaces the piecewise
small/mid/baseline/saturating-tail shape of Tiers 20+38 with one
continuous concave function and removes the small-end depression and
mid-tier hump entirely.

This file pins five properties:

  1. Activation ordering: Tier 40 follows Tier 38 follows Tier 20.

  2. Multiplier monotonicity (per-unit yield strictly decreases in
     stake share across the full bps range).  No internal kinks.

  3. Peak at small stake / asymptote toward floor at large stake —
     the shape that compresses share over time without nuking whales.

  4. Absolute reward (= stake_bps * multiplier(stake_bps)) is strictly
     increasing in stake — adding stake always pays more in absolute
     terms (the "always earn more" anchor).  AND concave — diminishing
     returns (each additional unit pays less than the last).

  5. Pre-Tier-40 callers see the v2/v1 curves byte-for-byte; v3 is only
     invoked at heights >= REWARD_CURVE_SMOOTH_HEIGHT.  Replay
     determinism preserved across the entire fork ladder.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    ACK_BACKDATING_DEFENSE_HEIGHT,
    REWARD_CURVE_HEIGHT,
    REWARD_CURVE_LARGE_BAND_HEIGHT,
    REWARD_CURVE_SMOOTH_FLOOR_NUM,
    REWARD_CURVE_SMOOTH_HEIGHT,
    REWARD_CURVE_SMOOTH_MULT_DEN,
    REWARD_CURVE_SMOOTH_PEAK_NUM,
    REWARD_CURVE_SMOOTH_SCALE_BPS,
)
from messagechain.economics.inflation import (
    reward_curve_multiplier,
    reward_curve_multiplier_v2,
    reward_curve_multiplier_v3,
)


# Dense stake-share grid in bps.  Covers tiny → 100% with extra
# resolution near the bend (around SCALE_BPS = 300).  Monotonicity must
# hold at every consecutive pair; no kinks anywhere in the range.
_STAKE_GRID_BPS = [
    0, 1, 5, 10, 25, 50, 100, 150, 200, 250, 300, 400, 500, 750,
    1000, 1500, 2000, 2500, 3000, 4000, 5000, 7500, 10_000,
]


def _ratio_lt(a_num: int, a_den: int, b_num: int, b_den: int) -> bool:
    """Cross-multiplication comparison — pure-int, never float()."""
    return a_num * b_den < b_num * a_den


def _ratio_le(a_num: int, a_den: int, b_num: int, b_den: int) -> bool:
    return a_num * b_den <= b_num * a_den


class TestActivationOrdering(unittest.TestCase):
    """Tier 40 must follow Tier 39 (ack-backdating, height 802) which
    follows Tier 38 (large-band, height 801) which follows Tier 20."""

    def test_activation_after_tier_39(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_HEIGHT, ACK_BACKDATING_DEFENSE_HEIGHT,
        )

    def test_activation_after_tier_38(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_HEIGHT, REWARD_CURVE_LARGE_BAND_HEIGHT,
        )

    def test_activation_after_tier_20(self):
        self.assertGreater(REWARD_CURVE_SMOOTH_HEIGHT, REWARD_CURVE_HEIGHT)


class TestShapeInvariants(unittest.TestCase):
    """Properties of the smooth concave curve, derived purely from
    the tuning constants and the helper formula — no magic numbers."""

    def test_floor_below_peak(self):
        # Floor must be strictly below peak; otherwise the curve is
        # flat or inverted and there are no diminishing returns.
        self.assertLess(
            REWARD_CURVE_SMOOTH_FLOOR_NUM,
            REWARD_CURVE_SMOOTH_PEAK_NUM,
        )
        self.assertGreater(REWARD_CURVE_SMOOTH_FLOOR_NUM, 0)

    def test_peak_at_zero_stake(self):
        # At stake_bps=0 the multiplier MUST equal exactly PEAK/MULT_DEN.
        # This is the highest per-unit yield in the entire range.
        num, den = reward_curve_multiplier_v3(0)
        # PEAK/MULT_DEN == num/den  ⇔  PEAK*den == MULT_DEN*num.
        self.assertEqual(
            REWARD_CURVE_SMOOTH_PEAK_NUM * den,
            REWARD_CURVE_SMOOTH_MULT_DEN * num,
        )

    def test_floor_is_asymptote_never_reached_in_range(self):
        # Multiplier at every reachable stake_bps must be strictly
        # ABOVE the floor — the floor is an asymptote, not a value the
        # curve attains in [0, 10_000] (or even past it).  This is the
        # "soft cap, no hard cap" anchor: a whale at 100% stake still
        # earns at a multiplier strictly greater than the floor.
        for bps in _STAKE_GRID_BPS:
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier_v3(bps)
                # FLOOR/MULT_DEN < num/den  ⇔  FLOOR*den < MULT_DEN*num.
                self.assertTrue(
                    _ratio_lt(
                        REWARD_CURVE_SMOOTH_FLOOR_NUM,
                        REWARD_CURVE_SMOOTH_MULT_DEN,
                        num,
                        den,
                    ),
                    f"multiplier at bps={bps} must be > FLOOR (asymptote)",
                )

    def test_multiplier_strictly_decreasing(self):
        # Per-unit yield monotonicity: for any two stake levels with
        # s1 < s2, multiplier(s1) > multiplier(s2).  No flat region,
        # no hump, no kink — strict decrease everywhere.
        for s1, s2 in zip(_STAKE_GRID_BPS, _STAKE_GRID_BPS[1:]):
            with self.subTest(s1=s1, s2=s2):
                n1, d1 = reward_curve_multiplier_v3(s1)
                n2, d2 = reward_curve_multiplier_v3(s2)
                # Want n1/d1 > n2/d2  ⇔  n1*d2 > n2*d1.
                self.assertGreater(n1 * d2, n2 * d1)

    def test_midpoint_at_scale_bps(self):
        # Algebraic identity: at stake_bps = SCALE_BPS, the multiplier
        # is exactly (PEAK + FLOOR) / (2 * MULT_DEN) — the midpoint
        # between peak and floor.  Useful as a sanity-check anchor for
        # operators reading the constants.
        s = REWARD_CURVE_SMOOTH_SCALE_BPS
        num, den = reward_curve_multiplier_v3(s)
        # (PEAK + FLOOR) / (2 * MULT_DEN) == num/den.
        expected_num = (
            REWARD_CURVE_SMOOTH_PEAK_NUM + REWARD_CURVE_SMOOTH_FLOOR_NUM
        )
        expected_den = 2 * REWARD_CURVE_SMOOTH_MULT_DEN
        self.assertEqual(expected_num * den, num * expected_den)


class TestAbsoluteRewardConcavity(unittest.TestCase):
    """The crux of the user's intent: rich keep getting richer (always
    earn more in absolute terms for more stake), but with diminishing
    returns (concave in stake)."""

    @staticmethod
    def _absolute_reward(stake_bps: int) -> tuple[int, int]:
        """Return (num, den) of stake_bps * multiplier(stake_bps), in
        rational form so monotonicity / concavity comparisons stay
        pure-int."""
        num, den = reward_curve_multiplier_v3(stake_bps)
        return stake_bps * num, den

    def test_absolute_reward_strictly_increasing(self):
        # Adding stake ALWAYS pays more in absolute terms, even at the
        # tail where per-unit yield is approaching the asymptote.
        # This is the "always earn more" anchor — no cliff, no cap, no
        # point where adding stake stops paying you something extra.
        for s1, s2 in zip(_STAKE_GRID_BPS, _STAKE_GRID_BPS[1:]):
            if s1 == 0:
                # Skip stake_bps=0 for the strict-increase check —
                # absolute reward at 0 is trivially 0; the next grid
                # point picks up the strictly-increasing chain.
                continue
            with self.subTest(s1=s1, s2=s2):
                n1, d1 = self._absolute_reward(s1)
                n2, d2 = self._absolute_reward(s2)
                # Want n2/d2 > n1/d1  ⇔  n2*d1 > n1*d2.
                self.assertGreater(n2 * d1, n1 * d2)

    def test_absolute_reward_concave(self):
        # Concavity: for three points s1 < s2 < s3 evenly spaced, the
        # absolute reward at s2 must lie ABOVE the chord from
        # (s1, R(s1)) to (s3, R(s3)).  Equivalently, the second
        # forward-difference R(s3) - 2*R(s2) + R(s1) is negative.
        # Diminishing returns = concave R = each marginal stake unit
        # adds less reward than the previous one.
        evenly_spaced = [50, 100, 150, 200, 300, 500, 750, 1000,
                         1500, 2000, 3000, 5000, 10_000]
        for i in range(len(evenly_spaced) - 2):
            s1 = evenly_spaced[i]
            s2 = evenly_spaced[i + 1]
            s3 = evenly_spaced[i + 2]
            with self.subTest(s1=s1, s2=s2, s3=s3):
                n1, d1 = self._absolute_reward(s1)
                n2, d2 = self._absolute_reward(s2)
                n3, d3 = self._absolute_reward(s3)
                # The triple-spacing here is *not* uniform (we're using
                # a coarse grid), so cast concavity as: the per-unit
                # marginal reward (R(s_{k+1}) - R(s_k)) / (s_{k+1} - s_k)
                # is non-increasing.  Cross-multiply to keep int-only:
                #   marg_12 = (R2 - R1) / (s2 - s1)
                #   marg_23 = (R3 - R2) / (s3 - s2)
                # Want marg_12 >= marg_23.
                # R2 - R1 = n2/d2 - n1/d1 = (n2*d1 - n1*d2) / (d1*d2)
                # R3 - R2 = n3/d3 - n2/d2 = (n3*d2 - n2*d3) / (d2*d3)
                gap_12 = s2 - s1
                gap_23 = s3 - s2
                # marg_12 = (n2*d1 - n1*d2) / (d1*d2*gap_12)
                # marg_23 = (n3*d2 - n2*d3) / (d2*d3*gap_23)
                # marg_12 >= marg_23  ⇔
                #   (n2*d1 - n1*d2) * d3 * gap_23
                #   >= (n3*d2 - n2*d3) * d1 * gap_12
                lhs = (n2 * d1 - n1 * d2) * d3 * gap_23
                rhs = (n3 * d2 - n2 * d3) * d1 * gap_12
                self.assertGreaterEqual(
                    lhs, rhs,
                    f"R must be concave (non-increasing marginal "
                    f"reward) at s1={s1}, s2={s2}, s3={s3}",
                )


class TestPureIntDeterminism(unittest.TestCase):
    """The consensus hot path must never coerce an input through
    float().  Mirrors the _NoFloatInt sentinel pattern from prior
    rational-rewrites (Tier 23 honesty curve, Tier 38 large band)."""

    def test_no_float_in_helper(self):

        class _NoFloatInt(int):
            def __float__(self) -> float:  # pragma: no cover
                raise AssertionError(
                    "reward_curve_multiplier_v3 must not call float() "
                    "on any input — consensus determinism requires "
                    "pure-int arithmetic"
                )

        for bps in _STAKE_GRID_BPS:
            with self.subTest(bps=bps):
                # Wrap input in the sentinel; helper must complete
                # without ever calling __float__.
                num, den = reward_curve_multiplier_v3(_NoFloatInt(bps))
                self.assertIsInstance(num, int)
                self.assertIsInstance(den, int)
                self.assertGreater(den, 0)


class TestPreForkLegacyByteIdentical(unittest.TestCase):
    """Pre-Tier-40 callers see v2/v1 curves byte-for-byte; v3 is only
    invoked at heights >= REWARD_CURVE_SMOOTH_HEIGHT.  This test exists
    to guard against accidental edits to v1/v2 helpers when adding v3."""

    def test_v1_unchanged_at_grid(self):
        # Sample a few well-known v1 values and pin them.  Magic
        # numbers here ARE intentional — the v1 helper is frozen
        # consensus; if these change the test should fail loudly.
        cases = {
            10:    (80, 100),     # < SMALL_THRESHOLD (50): 0.80x
            100:   (125, 100),    # < MID_THRESHOLD (500): 1.25x
            1000:  (1, 1),        # >= MID_THRESHOLD: 1.0x baseline
        }
        for bps, expected in cases.items():
            with self.subTest(bps=bps):
                self.assertEqual(reward_curve_multiplier(bps), expected)

    def test_v2_unchanged_at_floor(self):
        # v2 floor at >= 30% stake is 0.5x.  Pin it so v3's addition
        # doesn't accidentally edit v2.
        num, den = reward_curve_multiplier_v2(3000)
        # 50/100 == num/den.
        self.assertEqual(50 * den, 100 * num)


class TestDispatcherGate(unittest.TestCase):
    """The dispatcher in inflation.mint_block_reward (and its sim
    mirror in core.blockchain) must select v3 only at and above
    REWARD_CURVE_SMOOTH_HEIGHT, v2 between LARGE_BAND and SMOOTH, and
    v1 between Tier 20 and LARGE_BAND.

    We assert this structurally: the dispatcher source must mention
    all three helpers and the height gates in the documented order.
    Direct functional dispatch tests live in the existing curve-tier
    integration suites; this test guards the wiring boilerplate."""

    def test_inflation_dispatcher_mentions_v3(self):
        import inspect
        from messagechain.economics import inflation
        src = inspect.getsource(inflation)
        # The v3 helper must be defined and the dispatcher path must
        # gate on REWARD_CURVE_SMOOTH_HEIGHT.
        self.assertIn("def reward_curve_multiplier_v3", src)
        self.assertIn("REWARD_CURVE_SMOOTH_HEIGHT", src)
        self.assertIn("curve_v3_active", src)

    def test_blockchain_sim_mirror_mentions_v3(self):
        import inspect
        from messagechain.core import blockchain
        src = inspect.getsource(blockchain)
        # Sim mirror must call v3 helper under the same height gate so
        # state-root commitment reproduces the apply path bit-for-bit.
        self.assertIn("_reward_curve_multiplier_v3", src)
        self.assertIn("REWARD_CURVE_SMOOTH_HEIGHT", src)
        self.assertIn("_curve_v3_active", src)


if __name__ == "__main__":
    unittest.main()
