"""Regression tests for Tier 54 — dormancy-controller K_DEN retune
(audit r29 top-3 #2, 1.59.1).

Pre-fix the controller's gain (K = 1 / 20_000) saturated the
DORMANCY_MAX_ISSUANCE_PER_BLOCK = 500 ceiling at gap = 10M tokens.
Combined with the scheduled seed-divestment burn (~85M of founder
stake, 4 yr), mid-divestment gaps land in the 10–80M range — every
one of which would peg the controller at MAX = 500/block ≈ 26.3M
tokens/yr ≈ 26%/yr of TARGET sustained until active recovers.  That
inverts CLAUDE.md's "stable active supply" anchor (the chain's
nominal token unit must hold its real economic weight across
centuries) and the "issuance's purpose is supply replenishment, not
security-funding" intent.

Tier 54 widens K_DEN to 200_000 so the linear band reaches MAX only
at gap = 100M (the founder-fully-dormant catastrophic case).  At
gap = 10M, raw = 50/block ≈ 2.6M tokens/yr — order of the
documented burn rate, no saturation.

Pre-fork blocks replay byte-identically via the in-function
height-gate; only post-fork heights see the new K_DEN.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_CONTROLLER_K_DEN,
    DORMANCY_CONTROLLER_K_DEN_POST_RETUNE,
    DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
    PROPOSER_CAP_REDISTRIBUTE_HEIGHT,
)
from messagechain.economics.inflation import SupplyTracker


BLOCKS_PER_YEAR = 52_560  # 600s blocks


class TestTier54ConstantShape(unittest.TestCase):
    """Shape pins -- a future retune that bumps the value can keep
    these passing only by preserving the relationships the anchor
    depends on."""

    def test_k_den_post_retune_is_strictly_larger(self):
        # Tier 54's intent is to TIGHTEN the gain (larger denominator
        # = smaller gain = longer linear band before saturation).
        # A future retune that lowers K_DEN below the legacy value
        # would re-introduce the saturation problem and trip this.
        self.assertGreater(
            DORMANCY_CONTROLLER_K_DEN_POST_RETUNE,
            DORMANCY_CONTROLLER_K_DEN,
        )

    def test_activation_height_follows_tier53(self):
        self.assertGreater(
            DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
            PROPOSER_CAP_REDISTRIBUTE_HEIGHT,
        )

    def test_activation_height_follows_tier47(self):
        self.assertGreater(
            DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
            DORMANCY_CONTROLLER_HEIGHT,
        )

    def test_linear_band_reaches_max_at_realistic_crisis_scale(self):
        # Post-retune the linear band's saturation point is
        # K_DEN * MAX / K_NUM tokens.  This must be at the
        # catastrophic-event scale (~100M = founder fully dormant),
        # not the routine mid-divestment scale (10M).
        saturation_gap = (
            DORMANCY_MAX_ISSUANCE_PER_BLOCK
            * DORMANCY_CONTROLLER_K_DEN_POST_RETUNE
            // DORMANCY_CONTROLLER_K_NUM
        )
        # 100M is the founder-fully-dormant scale; allow slack for
        # future retunes that adjust MAX or K_NUM around 100M.
        self.assertGreaterEqual(saturation_gap, 50_000_000)
        # Sanity: the saturation gap must NOT have collapsed back
        # into the routine-divestment band (the bug Tier 54 fixes).
        self.assertGreater(saturation_gap, 10_000_000)


class TestPreActivationByteIdenticalLegacyBehavior(unittest.TestCase):
    """At and above Tier 47 but below Tier 54, the controller MUST
    use the legacy K_DEN = 20_000.  Without this guarantee, mainnet
    blocks 1710..1949 (already minted under K_DEN = 20_000) re-
    validate to a different reward and the chain forks under upgrade.
    """

    def test_pre_retune_height_uses_legacy_k_den(self):
        # Pick a height inside the [Tier 47, Tier 54) window and
        # verify the issuance matches the legacy K_DEN formula
        # exactly.
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT - 1
        self.assertGreaterEqual(h, DORMANCY_CONTROLLER_HEIGHT)
        gap = 5_000_000
        s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - gap,
        }
        s.bump_active(b"X" * 32, h)
        per_block = s.compute_dormancy_issuance(h)
        # Legacy formula: gap * 1 // 20_000 = 250 for gap=5M.
        expected = (
            gap
            * DORMANCY_CONTROLLER_K_NUM
            // DORMANCY_CONTROLLER_K_DEN
        )
        self.assertEqual(per_block, expected)

    def test_pre_retune_saturation_at_legacy_threshold(self):
        # At the legacy saturation gap (10M for K=1/20_000, MAX=500),
        # pre-retune still saturates exactly as before.  This is the
        # byte-identical pin.
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT - 1
        s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - 10_000_000,
        }
        s.bump_active(b"X" * 32, h)
        per_block = s.compute_dormancy_issuance(h)
        self.assertEqual(per_block, DORMANCY_MAX_ISSUANCE_PER_BLOCK)


class TestPostRetuneLinearBandExtends(unittest.TestCase):
    """Post-Tier-54 the linear band extends out to 100M gap, so
    routine mid-divestment gaps no longer peg the controller at MAX.
    """

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT + 100

    def _set_gap(self, gap: int) -> None:
        self.s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - gap,
        }
        self.s.bump_active(b"X" * 32, self.h)

    def test_routine_gap_does_not_saturate(self):
        # Mid-divestment gap = 10M.  Pre-fix this saturated at MAX =
        # 500/block ≈ 26.3M/yr.  Post-fix it lands in the linear
        # band: raw = 50/block ≈ 2.6M/yr.
        self._set_gap(10_000_000)
        per_block = self.s.compute_dormancy_issuance(self.h)
        self.assertLess(
            per_block,
            DORMANCY_MAX_ISSUANCE_PER_BLOCK,
            "10M gap saturates the controller post-Tier-54 — the "
            "retune did not actually widen the linear band",
        )
        # Order of magnitude: 50 tokens/block at gap=10M, K=1/200_000.
        expected = (
            10_000_000
            * DORMANCY_CONTROLLER_K_NUM
            // DORMANCY_CONTROLLER_K_DEN_POST_RETUNE
        )
        self.assertEqual(per_block, expected)

    def test_mid_divestment_gap_is_proportional(self):
        # Plausible mid-divestment gap: 45M (founder burned ~85M of
        # 100M stake; active supply ≈ 55M).  Pre-fix saturated at
        # MAX.  Post-fix: raw = 225/block ≈ 11.8M/yr — order of the
        # documented 10–15M/yr burn estimate.
        self._set_gap(45_000_000)
        per_block = self.s.compute_dormancy_issuance(self.h)
        self.assertLess(
            per_block,
            DORMANCY_MAX_ISSUANCE_PER_BLOCK,
            "45M gap saturates post-retune — linear band must "
            "extend to at least the founder-fully-dormant scale",
        )
        annual = per_block * BLOCKS_PER_YEAR
        # Annual issuance at 45M gap should be in the ballpark of
        # the documented burn rate, not 5× over it.
        self.assertLess(
            annual,
            20_000_000,
            "45M gap mints over 20M/yr post-retune — controller is "
            "still over-replenishing relative to documented burn",
        )

    def test_catastrophic_gap_pegs_at_max(self):
        # Founder fully dormant: gap = 100M.  Linear term reaches
        # exactly MAX (500/block).  Post-retune the ceiling still
        # binds for a real worst case — MAX is the worst-case-crisis
        # response capacity, preserved.
        self._set_gap(100_000_000)
        per_block = self.s.compute_dormancy_issuance(self.h)
        self.assertEqual(per_block, DORMANCY_MAX_ISSUANCE_PER_BLOCK)

    def test_super_catastrophic_gap_clipped_to_max(self):
        # Adversarial scenario: active_supply = 0 (gap = TARGET =
        # 100M).  Controller still respects MAX as the absolute
        # ceiling regardless of the proportional term.
        self._set_gap(DORMANCY_TARGET_ACTIVE_SUPPLY)
        per_block = self.s.compute_dormancy_issuance(self.h)
        self.assertLessEqual(
            per_block, DORMANCY_MAX_ISSUANCE_PER_BLOCK,
        )


class TestActivationBoundary(unittest.TestCase):
    """The activation height is inclusive: at exactly
    DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT the new K_DEN binds.
    One block earlier the legacy K_DEN binds.  Pin the boundary so
    a fence-post bug doesn't drift the cutover by 1 block."""

    def test_just_below_activation_uses_legacy(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT - 1
        s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - 5_000_000,
        }
        s.bump_active(b"X" * 32, h)
        per_block = s.compute_dormancy_issuance(h)
        # Legacy: 5M / 20_000 = 250 per block.
        self.assertEqual(
            per_block,
            5_000_000 * DORMANCY_CONTROLLER_K_NUM // DORMANCY_CONTROLLER_K_DEN,
        )

    def test_at_activation_uses_post_retune(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT
        s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - 5_000_000,
        }
        s.bump_active(b"X" * 32, h)
        per_block = s.compute_dormancy_issuance(h)
        # Post-retune: 5M / 200_000 = 25 per block.
        self.assertEqual(
            per_block,
            5_000_000
            * DORMANCY_CONTROLLER_K_NUM
            // DORMANCY_CONTROLLER_K_DEN_POST_RETUNE,
        )

    def test_post_retune_value_strictly_lower_at_routine_gap(self):
        # Flip-the-switch sanity: at the same gap, the at-activation
        # block mints strictly less than the just-below block.  This
        # is the entire point of the retune.
        s = SupplyTracker()
        gap = 5_000_000
        s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - gap}
        s.bump_active(b"X" * 32, DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT)
        post = s.compute_dormancy_issuance(
            DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
        )
        s.bump_active(
            b"X" * 32, DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT - 1,
        )
        pre = s.compute_dormancy_issuance(
            DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT - 1,
        )
        self.assertLess(post, pre)


class TestAnchorPreservation(unittest.TestCase):
    """The retune must not change the controller's shape, only its
    parameters at and above the activation height."""

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT + 100

    def test_at_target_zero_issuance_post_retune(self):
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY}
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_above_target_zero_issuance_post_retune(self):
        self.s.balances = {
            b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY * 2,
        }
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_monotone_non_decreasing_in_gap_post_retune(self):
        target = DORMANCY_TARGET_ACTIVE_SUPPLY
        gaps = [
            0, 1_000_000, 5_000_000, 10_000_000, 25_000_000,
            50_000_000, 100_000_000, target,
        ]
        prev = -1
        for gap in gaps:
            self.s.balances = {b"X" * 32: max(0, target - gap)}
            self.s.bump_active(b"X" * 32, self.h)
            cur = self.s.compute_dormancy_issuance(self.h)
            self.assertGreaterEqual(
                cur, prev,
                f"non-monotone post-retune at gap={gap}: "
                f"{cur} < {prev}",
            )
            prev = cur


if __name__ == "__main__":
    unittest.main()
