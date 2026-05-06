"""Tier 47 — DORMANCY_TARGET_ACTIVE_SUPPLY retune (140M → 100M).

Surfaced by audit r24 top-3 #1.  After 1.58.1 excluded the treasury
from ``compute_active_supply``, the controller's TARGET no longer
matched its definition: TARGET=140M was the genesis *total* (founder
100M + treasury 40M) but the new ``active`` measure only counts
non-treasury holders, so at mainnet activation
``active=100M``, ``gap=40M``, the controller pegs at
``DORMANCY_MAX_ISSUANCE_PER_BLOCK=500`` for ~60K blocks (~1.14 yr)
until founder balance grows to ~130M.  Net flow over the bind window
is ~30M new tokens, ~99.99% of which accrue to the founder via the
sole-proposer share + stake-pro-rata attester pool — founder share
ratchets 71.4% → 79.2%, the *opposite* direction the
stake-concentration soft-cap anchor wants.

The fix is a definitional realignment, not a shape change: TARGET
must equal the *active* portion of genesis supply, which is
``GENESIS_SUPPLY - TREASURY_ALLOCATION = 100M``.  At mainnet
activation, gap=0, controller mints zero — and only mints as real
dormancy or burns open the gap, exactly as the anchor intends.

Pre-fork heights replay byte-identically (the controller is height-
gated and has not yet activated on mainnet at edit time, so no
historical block-replay output changes).  No new tier height; the
retune rides under the existing Tier 47.
"""

import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_CONTROLLER_K_DEN,
    GENESIS_SUPPLY,
    TREASURY_ALLOCATION,
    TREASURY_ENTITY_ID,
)
from messagechain.economics.inflation import SupplyTracker


# ─────────────────────────────────────────────────────────────────────
# 1. Definitional alignment: TARGET excludes treasury
# ─────────────────────────────────────────────────────────────────────

class TestTargetMatchesActiveSupplyDefinition(unittest.TestCase):
    """The TARGET must equal the *active* portion of genesis supply.

    ``compute_active_supply`` skips ``TREASURY_ENTITY_ID``; the
    controller's TARGET must use the same definition or the gap
    perma-binds at one or the other extreme.  ``GENESIS_SUPPLY -
    TREASURY_ALLOCATION = 100M`` is the unique value that aligns the
    two and matches the anchored "stable active supply" intent.
    """

    def test_target_equals_genesis_minus_treasury(self):
        self.assertEqual(
            DORMANCY_TARGET_ACTIVE_SUPPLY,
            GENESIS_SUPPLY - TREASURY_ALLOCATION,
        )

    def test_target_is_100m_at_mainnet_genesis(self):
        # Pin the absolute value so a future GENESIS_SUPPLY rebase
        # forces the operator to re-derive the target deliberately
        # rather than silently shift via a constant arithmetic.
        self.assertEqual(DORMANCY_TARGET_ACTIVE_SUPPLY, 100_000_000)


# ─────────────────────────────────────────────────────────────────────
# 2. Mainnet shape at activation: zero gap, zero issuance
# ─────────────────────────────────────────────────────────────────────

class TestMainnetShapeAtActivation(unittest.TestCase):
    """At mainnet activation the chain has founder=100M + treasury=40M,
    every entity stamped active by the one-shot backfill at
    DORMANCY_CONTROLLER_HEIGHT.  Active supply (treasury excluded)
    must equal TARGET → gap=0 → issuance=0.

    This is the headline post-fix invariant.  Pre-fix, the same shape
    pegged at MAX=500/block for ~60K blocks; this test fails before
    the retune and passes after.
    """

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_HEIGHT + 100
        founder = b"F" * 32
        self.s.balances = {
            founder: 100_000_000,
            TREASURY_ENTITY_ID: 40_000_000,
        }
        # Both stamped active by the activation backfill.
        self.s.bump_active(founder, self.h)
        self.s.bump_active(TREASURY_ENTITY_ID, self.h)

    def test_active_supply_equals_target_at_mainnet_genesis(self):
        active = self.s.compute_active_supply(self.h)
        self.assertEqual(active, DORMANCY_TARGET_ACTIVE_SUPPLY)
        self.assertEqual(active, 100_000_000)

    def test_gap_is_zero_at_mainnet_genesis(self):
        active = self.s.compute_active_supply(self.h)
        gap = DORMANCY_TARGET_ACTIVE_SUPPLY - active
        self.assertEqual(gap, 0)

    def test_controller_mints_zero_at_mainnet_genesis(self):
        # The headline regression: pre-fix this returned
        # DORMANCY_MAX_ISSUANCE_PER_BLOCK=500 perpetually; post-fix
        # it must return 0 because the chain is at-target.
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)


# ─────────────────────────────────────────────────────────────────────
# 3. Real dormancy still drives positive issuance
# ─────────────────────────────────────────────────────────────────────

class TestRealDormancyDrivesIssuance(unittest.TestCase):
    """The retune must NOT defang the controller — when real dormancy
    or burns drop ``active_supply`` below TARGET, the controller must
    still mint proportionally.  Tests pin two regimes: small gap
    (proportional, below the cap) and large gap (clamped at MAX).
    """

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_HEIGHT + 100

    def test_small_gap_yields_proportional_issuance(self):
        # Founder holds 95M (5M burned vs the 100M genesis allocation),
        # treasury 40M (excluded).  Active = 95M, TARGET = 100M,
        # gap = 5M.  raw issuance = 5M / 20_000 = 250 — below MAX=500,
        # so the cap should NOT bind.
        founder = b"F" * 32
        self.s.balances = {
            founder: 95_000_000,
            TREASURY_ENTITY_ID: 40_000_000,
        }
        self.s.bump_active(founder, self.h)
        self.s.bump_active(TREASURY_ENTITY_ID, self.h)
        active = self.s.compute_active_supply(self.h)
        self.assertEqual(active, 95_000_000)
        gap = DORMANCY_TARGET_ACTIVE_SUPPLY - active
        self.assertEqual(gap, 5_000_000)
        expected_raw = (
            gap * DORMANCY_CONTROLLER_K_NUM
        ) // DORMANCY_CONTROLLER_K_DEN
        self.assertLess(expected_raw, DORMANCY_MAX_ISSUANCE_PER_BLOCK)
        self.assertEqual(
            self.s.compute_dormancy_issuance(self.h),
            expected_raw,
        )

    def test_very_large_gap_still_clamps_at_max(self):
        # Pathological: active=0, gap=TARGET=100M, raw=5000, clamped
        # to MAX=500.  Confirms the cap still binds for runaway-low
        # active_supply (e.g. catastrophic slash, treasury rebase,
        # bug).  Same shape as the prior at-zero-supply test.
        self.s.balances = {}
        self.s.staked = {}
        self.assertEqual(
            self.s.compute_dormancy_issuance(self.h),
            DORMANCY_MAX_ISSUANCE_PER_BLOCK,
        )


if __name__ == "__main__":
    unittest.main()
