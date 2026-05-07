"""Audit r32 #3 -- Dormancy controller TARGET retune.

Pre-fix ``DORMANCY_TARGET_ACTIVE_SUPPLY = 100_000_000`` exactly
matches the founder's genesis balance (100M; treasury 40M is
excluded from active-supply per ``compute_active_supply`` lines
779-780).  While the founder signs blocks (validator-1's hot key
signs every block), ``last_active`` bumps each block, weight =
10000 bps, contribution = 100M.  ``gap = 100M - 100M = 0`` →
``compute_dormancy_issuance`` returns 0/block, indefinitely.  The
legacy halving-floor was short-circuited at
``DORMANCY_CONTROLLER_HEIGHT`` (Tier 47).  Validators currently
earn ~0/block of issuance during the entire 25-year DORMANCY_
WINDOW (or until the founder transfers tokens to other signing
holders, which keeps gap≈0 because receivers also become active).

CLAUDE.md anchor: founder-bootstrap arc -- "early-phase issuance
is calibrated so the founder can credibly secure the network solo
while it has only a handful of nodes, and progressively dilutes
toward broad democratization as more validators stake in".  The
0/block delivery contradicts the front-loaded shape the anchor
calls for.

Tier 60 (height 2250) raises ``DORMANCY_TARGET_ACTIVE_SUPPLY`` to
``DORMANCY_TARGET_ACTIVE_SUPPLY_V2 = 110_000_000`` so gap is
positive even when the founder is fully active.  Per-block raw
issuance ≈ 10M / 200_000 = 50 tokens/block; ~2.6M tokens/yr split
across validators -- comparable to legacy halving floor era
(4/block = ~210k/yr), generously front-loaded for the bootstrap
arc without overshooting.

Pre-fork blocks replay byte-identically via the height gate; the
legacy 100M target is preserved on the pre-fork branch so every
historical block under the controller (heights 1710..2249) replays
exactly.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_CONTROLLER_K_DEN_POST_RETUNE,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
    DORMANCY_TARGET_ACTIVE_SUPPLY_V2,
    DORMANCY_TARGET_RETUNE_HEIGHT,
    INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
)
from messagechain.economics.inflation import (
    SupplyTracker,
)


class TestActivationHeightConstant(unittest.TestCase):
    """Source pin: ``DORMANCY_TARGET_RETUNE_HEIGHT`` exists and sits
    above Tier 59 (cohort spacing) and above Tier 47 (the controller
    Tier 60 retunes)."""

    def test_constant_above_tier_59(self):
        self.assertGreater(
            DORMANCY_TARGET_RETUNE_HEIGHT,
            INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
            "Tier 60 must follow Tier 59 -- cohort spacing keeps "
            "consecutive consensus-rule changes from collapsing into "
            "a single activation window.",
        )

    def test_constant_above_dormancy_controller(self):
        self.assertGreater(
            DORMANCY_TARGET_RETUNE_HEIGHT,
            DORMANCY_CONTROLLER_HEIGHT,
            "Tier 60 must follow Tier 47 (DORMANCY_CONTROLLER_HEIGHT) "
            "-- Tier 60 retunes the controller Tier 47 introduced, "
            "so Tier 47 must already be live.",
        )


class TestTargetV2Higher(unittest.TestCase):
    """Source pin: V2 target is strictly greater than the legacy
    100M.  The bootstrap-arc anchor calls for non-zero front-loaded
    issuance, achieved by raising the target so gap > 0 even when
    the founder is fully active."""

    def test_v2_strictly_greater_than_legacy(self):
        self.assertGreater(
            DORMANCY_TARGET_ACTIVE_SUPPLY_V2,
            DORMANCY_TARGET_ACTIVE_SUPPLY,
            "V2 target must be strictly greater than the legacy 100M "
            "so gap > 0 at founder=100M-active.",
        )


class TestPreForkLegacyTarget(unittest.TestCase):
    """Replay determinism: pre-Tier-60 the controller MUST use the
    legacy ``DORMANCY_TARGET_ACTIVE_SUPPLY = 100_000_000`` target,
    byte-identically.  Without this branch every historical block
    under the controller (heights 1710..2249) would re-validate to
    a different issuance and the chain forks at the first contested
    in-controller block.
    """

    def test_pre_tier_60_target_is_legacy_100m(self):
        """At founder-fully-active (active = TARGET = 100M), pre-fork
        the controller mints 0/block.  This is the bug Tier 60 fixes,
        but the pre-fork branch MUST preserve it byte-identically for
        replay determinism."""
        supply = SupplyTracker()
        # Set up: active_supply == legacy TARGET.  Plant a single
        # entity with balance == TARGET that's "active" at the
        # current height.
        active_eid = b"founder_test_eid" + b"\x00" * 16
        supply.balances[active_eid] = DORMANCY_TARGET_ACTIVE_SUPPLY
        # Pin chain height pre-Tier-60 but post-Tier-47.  Activation
        # of the controller is at height 1710; pin to 1750 (well
        # past Tier 47, well before Tier 60 = 2250).
        pre_fork_height = DORMANCY_TARGET_RETUNE_HEIGHT - 100
        supply.last_active_heights[active_eid] = pre_fork_height
        # Active supply at pre_fork_height with founder fully active
        # equals TARGET; gap = 0.
        active = supply.compute_active_supply(pre_fork_height)
        self.assertEqual(active, DORMANCY_TARGET_ACTIVE_SUPPLY)
        # Pre-fork issuance MUST be 0 at gap=0.  This is the legacy
        # behavior we preserve byte-identically.
        issuance = supply.compute_dormancy_issuance(pre_fork_height)
        self.assertEqual(
            issuance, 0,
            "Pre-Tier-60 issuance at founder-fully-active MUST "
            "remain 0 -- the legacy 100M target produced gap=0 here, "
            "and replay determinism requires the same output.",
        )


class TestPostForkRetunedTarget(unittest.TestCase):
    """Behavioral pin: post-Tier-60 the controller uses the V2
    target (110M), so at founder-fully-active gap = 10M, raw
    issuance = (10M * K_NUM) // K_DEN ≈ 50 tokens/block at K_DEN_V2
    = 200_000 (capped at MAX_ISSUANCE_PER_BLOCK).  The bootstrap
    arc anchor is restored: validators earn non-zero baseline
    issuance during bootstrap."""

    def test_post_fork_gap_positive_at_founder_active(self):
        """Post-fork at founder=100M-active: gap = 110M - 100M =
        10M.  Issuance becomes positive."""
        supply = SupplyTracker()
        active_eid = b"founder_test_eid" + b"\x00" * 16
        supply.balances[active_eid] = DORMANCY_TARGET_ACTIVE_SUPPLY  # 100M
        post_fork_height = DORMANCY_TARGET_RETUNE_HEIGHT + 1
        supply.last_active_heights[active_eid] = post_fork_height
        active = supply.compute_active_supply(post_fork_height)
        self.assertEqual(active, DORMANCY_TARGET_ACTIVE_SUPPLY)
        # Post-fork: gap = V2 - 100M = 10M.  Issuance > 0.
        issuance = supply.compute_dormancy_issuance(post_fork_height)
        self.assertGreater(
            issuance, 0,
            "Post-Tier-60 issuance at founder-fully-active MUST be "
            "non-zero -- the V2 target makes gap = V2 - founder > 0, "
            "restoring the bootstrap-arc anchor.",
        )

    def test_post_fork_at_target_v2_zero_issuance(self):
        """Post-fork with active_supply == V2 target: gap = 0,
        issuance = 0.  Controller still does the right thing at the
        new equilibrium point -- shape-preserving."""
        supply = SupplyTracker()
        active_eid = b"founder_test_eid" + b"\x00" * 16
        supply.balances[active_eid] = DORMANCY_TARGET_ACTIVE_SUPPLY_V2
        post_fork_height = DORMANCY_TARGET_RETUNE_HEIGHT + 1
        supply.last_active_heights[active_eid] = post_fork_height
        active = supply.compute_active_supply(post_fork_height)
        self.assertEqual(active, DORMANCY_TARGET_ACTIVE_SUPPLY_V2)
        issuance = supply.compute_dormancy_issuance(post_fork_height)
        self.assertEqual(
            issuance, 0,
            "Post-Tier-60 issuance at active_supply == V2 target "
            "MUST be 0 -- shape-preserving; controller still zeros "
            "at gap=0, only the equilibrium point moves.",
        )

    def test_post_fork_gap_size_matches_calibration(self):
        """At founder=100M-active, gap = 10M, raw issuance ≈ 50/block
        with K_DEN_V2=200_000.  Bound: between 30 and 100/block --
        a sanity range that catches off-by-an-order-of-magnitude
        regressions in the calibration without pinning to a single
        magic number."""
        supply = SupplyTracker()
        active_eid = b"founder_test_eid" + b"\x00" * 16
        supply.balances[active_eid] = DORMANCY_TARGET_ACTIVE_SUPPLY  # 100M
        post_fork_height = DORMANCY_TARGET_RETUNE_HEIGHT + 1
        supply.last_active_heights[active_eid] = post_fork_height
        issuance = supply.compute_dormancy_issuance(post_fork_height)
        self.assertGreaterEqual(issuance, 30, f"got {issuance}")
        self.assertLessEqual(issuance, 100, f"got {issuance}")


if __name__ == "__main__":
    unittest.main()
