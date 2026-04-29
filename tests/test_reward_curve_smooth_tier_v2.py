"""Tier 42 — smooth concave reward-curve V2 retune.

Background: the Tier 40 (REWARD_CURVE_SMOOTH_HEIGHT) constants
(PEAK=150, FLOOR=40, SCALE_BPS=300) bend the curve hard at small-stake
(midpoint at 3% stake) and asymptote to 0.40× very fast.  At today's
mainnet bootstrap concentrations (2 validators ≈ 50% each) the multiplier
sits at ~0.46×, which means ~50–67% of the attester pool burns every
block (integer-rounding short of the pool at inflation.py's
attester_tokens_paid < attester_pool branch).  That violates two
CLAUDE.md anchors at once: the bootstrap-arc anchor (issuance must be
calibrated so the founder can credibly secure the network solo while
it has only a handful of nodes) and the "low steady perpetual inflation
funds the security budget forever" anchor.

The CLAUDE.md-anchored shape (concave / monotone-decreasing per-unit
yield / asymptotic soft cap / no hard cap / strictly-increasing absolute
reward / concave absolute reward / pure-int) is preserved.  Only the
TUNING knobs change (peak / floor / curve-bend point), per the explicit
CLAUDE.md anchor that "exact constants ... are tuning knobs."

V2 target shape (multiplier at given stake share):
  - 50% (5000 bps): ~0.85×  (was 0.46× under V1)
  - 25% (2500 bps): ~0.95×
  - 10% (1000 bps): ~1.05×
  -  5% ( 500 bps): ~1.10×
  - near-zero peak: ~1.30×

This file pins six properties on V2:

  1. Activation ordering: Tier 42 follows Tier 41 follows Tier 40 follows
     Tier 38 follows Tier 20.
  2. The chosen V2 constants produce the target multiplier values
     (within tolerance) at the canonical stake levels.
  3. Multiplier monotonicity (per-unit yield strictly decreases in
     stake share across the full bps range under V2).
  4. Peak at small stake / asymptote toward floor at large stake under
     V2 — the soft-cap shape preserved.
  5. Absolute reward (= stake_bps * multiplier(stake_bps)) is strictly
     increasing AND concave in stake under V2 ("always earn more" +
     "diminishing returns").
  6. Pre-Tier-42 callers see V1 (and v2/v1 below it) byte-for-byte; v4
     is only invoked at heights >= REWARD_CURVE_SMOOTH_V2_HEIGHT.
     Replay determinism preserved.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
    REWARD_CURVE_HEIGHT,
    REWARD_CURVE_LARGE_BAND_HEIGHT,
    REWARD_CURVE_SMOOTH_FLOOR_NUM,
    REWARD_CURVE_SMOOTH_HEIGHT,
    REWARD_CURVE_SMOOTH_MULT_DEN,
    REWARD_CURVE_SMOOTH_PEAK_NUM,
    REWARD_CURVE_SMOOTH_SCALE_BPS,
    REWARD_CURVE_SMOOTH_V2_FLOOR_NUM,
    REWARD_CURVE_SMOOTH_V2_HEIGHT,
    REWARD_CURVE_SMOOTH_V2_PEAK_NUM,
    REWARD_CURVE_SMOOTH_V2_SCALE_BPS,
)
from messagechain.economics.inflation import (
    reward_curve_multiplier,
    reward_curve_multiplier_v2,
    reward_curve_multiplier_v3,
    reward_curve_multiplier_v4,
)


# Dense stake-share grid in bps for monotonicity / asymptote checks.
# Includes stake levels well past 100% (10_000 bps) to verify the
# asymptote behavior holds even at unreachable concentrations — the
# helper is total — defined for any non-negative bps.
_STAKE_GRID_BPS = [
    0, 1, 5, 10, 25, 50, 100, 150, 200, 250, 300, 400, 500, 750,
    1000, 1500, 2000, 2500, 3000, 4000, 5000, 7500, 10_000,
]


# Target shape (CLAUDE.md anchor preserved; tuning-knob change only).
# Stake share in bps -> target multiplier (float, 1.0 = baseline).
# Tolerance is the per-target acceptable absolute deviation.
_TARGET_SHAPE = [
    (   0, 1.30),  # near-zero peak
    ( 500, 1.10),  # 5% stake
    (1000, 1.05),  # 10% stake
    (2500, 0.95),  # 25% stake
    (5000, 0.85),  # 50% stake (today's mainnet concentration)
]
_TARGET_TOLERANCE = 0.05  # ±0.05× tolerance — generous for round-number
                          # constants while still pinning the shape.


def _ratio_lt(a_num: int, a_den: int, b_num: int, b_den: int) -> bool:
    """Cross-multiplication comparison — pure-int, never float()."""
    return a_num * b_den < b_num * a_den


class TestActivationOrdering(unittest.TestCase):
    """Tier 42 (V2 retune) must follow Tier 41 (ack-deadline-grace,
    height 1640) which follows Tier 40 (smooth-curve V1, 1634) which
    follows Tier 38 (large-band, 1535) which follows Tier 20."""

    def test_v2_activation_after_tier_41(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_V2_HEIGHT,
            ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
        )

    def test_v2_activation_after_tier_40(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_V2_HEIGHT, REWARD_CURVE_SMOOTH_HEIGHT,
        )

    def test_v2_activation_after_tier_38(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_V2_HEIGHT, REWARD_CURVE_LARGE_BAND_HEIGHT,
        )

    def test_v2_activation_after_tier_20(self):
        self.assertGreater(
            REWARD_CURVE_SMOOTH_V2_HEIGHT, REWARD_CURVE_HEIGHT,
        )


class TestTargetShape(unittest.TestCase):
    """The chosen V2 constants must produce multiplier values close to
    the target shape at canonical stake levels.  Pins the bootstrap-arc
    anchor: a 50% mainnet validator earns ~0.85×, not ~0.46×."""

    def test_target_shape_at_canonical_stake_levels(self):
        for bps, target in _TARGET_SHAPE:
            with self.subTest(bps=bps, target=target):
                num, den = reward_curve_multiplier_v4(bps)
                # Compute the float multiplier purely for the assertion;
                # the helper itself stays pure-int.
                actual = num / den
                self.assertAlmostEqual(
                    actual, target, delta=_TARGET_TOLERANCE,
                    msg=(
                        f"V2 multiplier at bps={bps} is {actual:.4f}, "
                        f"target {target:.2f} ± {_TARGET_TOLERANCE} — "
                        f"the chosen V2 constants miss the anchored "
                        f"target shape"
                    ),
                )

    def test_v2_lifts_50pct_validator_substantially_above_v1(self):
        # Sanity check that the retune actually moves the needle for
        # today's mainnet concentration: V1 yields ~0.46× at 50% stake,
        # V2 must yield substantially higher.  Pin a floor of 0.75×
        # (well below the 0.85 target, well above the V1 0.46) so the
        # test doesn't drift if the targets are re-tuned within reason.
        v1_num, v1_den = reward_curve_multiplier_v3(5000)
        v2_num, v2_den = reward_curve_multiplier_v4(5000)
        # v2/v1 > 1 ⇔ v2_num * v1_den > v1_num * v2_den
        self.assertGreater(
            v2_num * v1_den, v1_num * v2_den,
            "V2 must lift the 50%-stake multiplier above V1",
        )
        # And specifically it must be at/above 0.75 (75/100):
        self.assertTrue(
            _ratio_lt(75, 100, v2_num, v2_den),
            f"V2 multiplier at bps=5000 must exceed 0.75 — got "
            f"{v2_num}/{v2_den}",
        )


class TestShapeInvariants(unittest.TestCase):
    """The CLAUDE.md-anchored shape MUST hold under V2: concave /
    monotonically decreasing per-unit yield / asymptote never reached /
    floor strictly between 0 and peak.  These are the SAME invariants
    pinned for V1 (Tier 40); they describe the anchored *shape*, which
    a tuning-knob change does not get to break."""

    def test_floor_below_peak(self):
        self.assertLess(
            REWARD_CURVE_SMOOTH_V2_FLOOR_NUM,
            REWARD_CURVE_SMOOTH_V2_PEAK_NUM,
        )
        self.assertGreater(REWARD_CURVE_SMOOTH_V2_FLOOR_NUM, 0)

    def test_peak_at_zero_stake(self):
        # At stake_bps=0 the V2 multiplier MUST equal exactly
        # PEAK_V2 / MULT_DEN.  Highest per-unit yield in the range.
        num, den = reward_curve_multiplier_v4(0)
        self.assertEqual(
            REWARD_CURVE_SMOOTH_V2_PEAK_NUM * den,
            REWARD_CURVE_SMOOTH_MULT_DEN * num,
        )

    def test_floor_is_asymptote_never_reached_in_range(self):
        # Multiplier at every reachable stake_bps must be strictly
        # ABOVE the V2 floor — soft cap, no hard cap.
        for bps in _STAKE_GRID_BPS:
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier_v4(bps)
                # FLOOR_V2/MULT_DEN < num/den ⇔ FLOOR*den < MULT_DEN*num
                self.assertTrue(
                    _ratio_lt(
                        REWARD_CURVE_SMOOTH_V2_FLOOR_NUM,
                        REWARD_CURVE_SMOOTH_MULT_DEN,
                        num, den,
                    ),
                    f"V2 multiplier at bps={bps} must be > FLOOR "
                    f"asymptote — got {num}/{den}",
                )

    def test_multiplier_strictly_decreasing(self):
        # Per-unit yield monotonicity under V2: no flat region, no
        # hump, no kink — strict decrease everywhere.
        for s1, s2 in zip(_STAKE_GRID_BPS, _STAKE_GRID_BPS[1:]):
            with self.subTest(s1=s1, s2=s2):
                n1, d1 = reward_curve_multiplier_v4(s1)
                n2, d2 = reward_curve_multiplier_v4(s2)
                # Want n1/d1 > n2/d2 ⇔ n1*d2 > n2*d1.
                self.assertGreater(n1 * d2, n2 * d1)

    def test_midpoint_at_scale_bps(self):
        # Algebraic identity preserved under V2: at stake_bps=SCALE_V2
        # the multiplier equals exactly (PEAK_V2 + FLOOR_V2) /
        # (2 * MULT_DEN).  Useful sanity-check anchor.
        s = REWARD_CURVE_SMOOTH_V2_SCALE_BPS
        num, den = reward_curve_multiplier_v4(s)
        expected_num = (
            REWARD_CURVE_SMOOTH_V2_PEAK_NUM
            + REWARD_CURVE_SMOOTH_V2_FLOOR_NUM
        )
        expected_den = 2 * REWARD_CURVE_SMOOTH_MULT_DEN
        self.assertEqual(expected_num * den, num * expected_den)


class TestAbsoluteRewardConcavity(unittest.TestCase):
    """The crux of the anchored shape: rich keep getting richer (always
    earn more in absolute terms for more stake), but with diminishing
    returns (concave in stake).  Mirrors the V1 (Tier 40) test."""

    @staticmethod
    def _absolute_reward(stake_bps: int) -> tuple[int, int]:
        """Return (num, den) of stake_bps * multiplier(stake_bps)."""
        num, den = reward_curve_multiplier_v4(stake_bps)
        return stake_bps * num, den

    def test_absolute_reward_strictly_increasing(self):
        for s1, s2 in zip(_STAKE_GRID_BPS, _STAKE_GRID_BPS[1:]):
            if s1 == 0:
                continue
            with self.subTest(s1=s1, s2=s2):
                n1, d1 = self._absolute_reward(s1)
                n2, d2 = self._absolute_reward(s2)
                # Want n2/d2 > n1/d1 ⇔ n2*d1 > n1*d2.
                self.assertGreater(n2 * d1, n1 * d2)

    def test_absolute_reward_concave(self):
        # Concavity under V2: the per-unit marginal reward
        # (R(s_{k+1}) - R(s_k)) / (s_{k+1} - s_k) is non-increasing.
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
                gap_12 = s2 - s1
                gap_23 = s3 - s2
                # marg_12 = (n2*d1 - n1*d2) / (d1*d2*gap_12)
                # marg_23 = (n3*d2 - n2*d3) / (d2*d3*gap_23)
                # marg_12 >= marg_23 ⇔
                #   (n2*d1 - n1*d2) * d3 * gap_23
                #   >= (n3*d2 - n2*d3) * d1 * gap_12
                lhs = (n2 * d1 - n1 * d2) * d3 * gap_23
                rhs = (n3 * d2 - n2 * d3) * d1 * gap_12
                self.assertGreaterEqual(
                    lhs, rhs,
                    f"R must be concave (non-increasing marginal "
                    f"reward) under V2 at s1={s1}, s2={s2}, s3={s3}",
                )


class TestPureIntDeterminism(unittest.TestCase):
    """The consensus hot path must never coerce an input through
    float().  Same _NoFloatInt sentinel as V1 (Tier 40)."""

    def test_no_float_in_helper(self):

        class _NoFloatInt(int):
            def __float__(self) -> float:  # pragma: no cover
                raise AssertionError(
                    "reward_curve_multiplier_v4 must not call float() "
                    "on any input — consensus determinism requires "
                    "pure-int arithmetic"
                )

        for bps in _STAKE_GRID_BPS:
            with self.subTest(bps=bps):
                num, den = reward_curve_multiplier_v4(_NoFloatInt(bps))
                self.assertIsInstance(num, int)
                self.assertIsInstance(den, int)
                self.assertGreater(den, 0)


class TestPreForkLegacyByteIdentical(unittest.TestCase):
    """Pre-Tier-42 callers see V1 (and v2/v1 below it) byte-for-byte;
    v4 is only invoked at heights >= REWARD_CURVE_SMOOTH_V2_HEIGHT.
    Guards against accidental edits to the older helpers when adding v4."""

    def test_v1_unchanged_at_grid(self):
        # Sample well-known v1 (Tier 20) values and pin them.
        cases = {
            10:    (80, 100),     # < SMALL_THRESHOLD: 0.80x
            100:   (125, 100),    # < MID_THRESHOLD: 1.25x
            1000:  (1, 1),        # >= MID_THRESHOLD: 1.0x baseline
        }
        for bps, expected in cases.items():
            with self.subTest(bps=bps):
                self.assertEqual(reward_curve_multiplier(bps), expected)

    def test_v2_unchanged_at_floor(self):
        # v2 (Tier 38) floor at >= 30% stake is 0.5x.
        num, den = reward_curve_multiplier_v2(3000)
        self.assertEqual(50 * den, 100 * num)

    def test_v3_byte_identical_pre_fork(self):
        # The Tier 40 V1 helper (v3) must continue to produce the
        # same outputs as before V2 lands — its constants are the
        # original PEAK=150 / FLOOR=40 / SCALE=300 set.  Pin the
        # peak (bps=0) and the algebraic midpoint (bps=SCALE).
        num0, den0 = reward_curve_multiplier_v3(0)
        # PEAK / MULT_DEN = 150/100
        self.assertEqual(150 * den0, 100 * num0)
        # midpoint at SCALE_BPS = 300: (150+40)/(2*100) = 0.95
        num_s, den_s = reward_curve_multiplier_v3(
            REWARD_CURVE_SMOOTH_SCALE_BPS,
        )
        self.assertEqual(
            (REWARD_CURVE_SMOOTH_PEAK_NUM
             + REWARD_CURVE_SMOOTH_FLOOR_NUM) * den_s,
            (2 * REWARD_CURVE_SMOOTH_MULT_DEN) * num_s,
        )


class TestDispatcherGate(unittest.TestCase):
    """The dispatcher in inflation.mint_block_reward (and its sim
    mirror in core.blockchain) must select v4 only at and above
    REWARD_CURVE_SMOOTH_V2_HEIGHT, v3 between SMOOTH and SMOOTH_V2, v2
    between LARGE_BAND and SMOOTH, and v1 between Tier 20 and
    LARGE_BAND.  Asserted structurally — direct dispatch tests live in
    the curve-tier integration suites."""

    def test_inflation_dispatcher_mentions_v4(self):
        import inspect
        from messagechain.economics import inflation
        src = inspect.getsource(inflation)
        self.assertIn("def reward_curve_multiplier_v4", src)
        self.assertIn("REWARD_CURVE_SMOOTH_V2_HEIGHT", src)
        self.assertIn("curve_v4_active", src)

    def test_blockchain_sim_mirror_mentions_v4(self):
        import inspect
        from messagechain.core import blockchain
        src = inspect.getsource(blockchain)
        self.assertIn("_reward_curve_multiplier_v4", src)
        self.assertIn("REWARD_CURVE_SMOOTH_V2_HEIGHT", src)
        self.assertIn("_curve_v4_active", src)


if __name__ == "__main__":
    unittest.main()
