"""Tests for the BLOCK_BYTES_RAISE_HEIGHT fork (Tier 9).

At/after BLOCK_BYTES_RAISE_HEIGHT the per-block throughput budgets
widen in lockstep:

    MAX_TXS_PER_BLOCK        20    -> 45
    MAX_BLOCK_MESSAGE_BYTES  15_000 -> 45_000
    MAX_BLOCK_SIG_COST       100   -> 250
    FEE_PER_STORED_BYTE      1     -> 3   (via FEE_PER_STORED_BYTE_POST_RAISE)
    TARGET_BLOCK_SIZE        10    -> 22  (via TARGET_BLOCK_SIZE_POST_RAISE)

Per-message cap stays at MAX_MESSAGE_CHARS=1024 — this is a throughput
raise, not a message-size raise.  The three MAX_* constants are
monotone-safe direct bumps (pre-fork blocks that satisfied the stricter
cap trivially still satisfy the looser one).  The fee-per-byte and
EIP-1559 target are height-gated so pre-fork blocks replay under their
original rule.
"""

import unittest

from messagechain.config import (
    BASE_TX_FEE,
    BLOCK_BYTES_RAISE_HEIGHT,
    FEE_PER_STORED_BYTE,
    FEE_PER_STORED_BYTE_POST_RAISE,
    LINEAR_FEE_HEIGHT,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_BLOCK_SIG_COST,
    MAX_MESSAGE_BYTES,
    MAX_MESSAGE_CHARS,
    MAX_TXS_PER_BLOCK,
    MIN_FEE,
    TARGET_BLOCK_SIZE,
    TARGET_BLOCK_SIZE_POST_RAISE,
)
from messagechain.consensus.bootstrap_gradient import BOOTSTRAP_END_HEIGHT
from messagechain.core.transaction import calculate_min_fee
from messagechain.economics.inflation import SupplyTracker


class TestTier9Constants(unittest.TestCase):
    """The fork raises three capacity constants and adds three new knobs."""

    def test_block_bytes_raise_height_exists_after_linear_fee(self):
        self.assertGreater(BLOCK_BYTES_RAISE_HEIGHT, LINEAR_FEE_HEIGHT)

    def test_block_bytes_raise_height_inside_bootstrap_window(self):
        self.assertLess(BLOCK_BYTES_RAISE_HEIGHT, BOOTSTRAP_END_HEIGHT)

    def test_max_txs_per_block_raised_to_45(self):
        self.assertEqual(MAX_TXS_PER_BLOCK, 45)

    def test_max_block_message_bytes_raised_to_45000(self):
        self.assertEqual(MAX_BLOCK_MESSAGE_BYTES, 45_000)

    def test_max_block_sig_cost_raised_to_250(self):
        self.assertEqual(MAX_BLOCK_SIG_COST, 250)

    def test_fee_per_stored_byte_post_raise_is_3(self):
        self.assertEqual(FEE_PER_STORED_BYTE_POST_RAISE, 3)

    def test_target_block_size_post_raise_is_22(self):
        self.assertEqual(TARGET_BLOCK_SIZE_POST_RAISE, 22)

    def test_target_post_raise_fits_under_new_cap(self):
        """EIP-1559 target must leave headroom for 'above target' blocks."""
        self.assertLess(TARGET_BLOCK_SIZE_POST_RAISE, MAX_TXS_PER_BLOCK)

    def test_per_byte_rate_strictly_rises(self):
        """The fork must raise (not lower) the per-byte floor."""
        self.assertGreater(FEE_PER_STORED_BYTE_POST_RAISE, FEE_PER_STORED_BYTE)

    def test_message_cap_unchanged_by_tier9(self):
        """Per-message cap stays at 1024 — Tier 9 is a throughput raise."""
        self.assertEqual(MAX_MESSAGE_CHARS, 1024)
        self.assertEqual(MAX_MESSAGE_BYTES, MAX_MESSAGE_CHARS)

    def test_fork_heights_registry_contains_tier9(self):
        """The bootstrap-window registry must list BLOCK_BYTES_RAISE_HEIGHT.

        We re-parse the module source (the registry is a locally-scoped
        loop tuple that isn't exported).  Presence there is what drives
        the 'activate inside bootstrap' load-time assert, so losing the
        entry silently removes the guard.
        """
        import messagechain.config as cfg_mod
        import inspect

        source = inspect.getsource(cfg_mod)
        self.assertIn(
            '("BLOCK_BYTES_RAISE_HEIGHT", BLOCK_BYTES_RAISE_HEIGHT)',
            source,
            "BLOCK_BYTES_RAISE_HEIGHT must appear in the fork-heights "
            "registry so its bootstrap-window invariant is enforced",
        )


class TestTier9FeeFormula(unittest.TestCase):
    """calculate_min_fee routes to the raised per-byte rate post-fork."""

    def test_pre_fork_height_uses_tier8_rate(self):
        """At BLOCK_BYTES_RAISE_HEIGHT - 1: tier-8 rate (=1) still applies."""
        height = BLOCK_BYTES_RAISE_HEIGHT - 1
        floor = calculate_min_fee(b"x" * 100, current_height=height)
        self.assertEqual(floor, BASE_TX_FEE + FEE_PER_STORED_BYTE * 100)

    def test_at_fork_height_uses_raised_rate(self):
        """At BLOCK_BYTES_RAISE_HEIGHT: tier-9 rate (=3) applies."""
        height = BLOCK_BYTES_RAISE_HEIGHT
        floor = calculate_min_fee(b"x" * 100, current_height=height)
        self.assertEqual(floor, BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * 100)

    def test_max_size_message_floor_at_fork(self):
        """A 1024-byte message post-fork: fee == BASE_TX_FEE + 3 * 1024."""
        floor = calculate_min_fee(
            b"x" * 1024,
            current_height=BLOCK_BYTES_RAISE_HEIGHT,
        )
        self.assertEqual(floor, BASE_TX_FEE + 3 * 1024)

    def test_fee_jumps_at_boundary(self):
        """Boundary test: fee at fork-1 uses 1x, at fork uses 3x."""
        n = 500
        pre = calculate_min_fee(b"x" * n, current_height=BLOCK_BYTES_RAISE_HEIGHT - 1)
        at = calculate_min_fee(b"x" * n, current_height=BLOCK_BYTES_RAISE_HEIGHT)
        self.assertEqual(pre, BASE_TX_FEE + 1 * n)
        self.assertEqual(at, BASE_TX_FEE + 3 * n)
        self.assertGreater(at, pre)

    def test_legacy_linear_window_unchanged(self):
        """[LINEAR_FEE_HEIGHT, BLOCK_BYTES_RAISE_HEIGHT) keeps tier-8 rate."""
        height = LINEAR_FEE_HEIGHT + 1  # safely inside the tier-8 window
        floor = calculate_min_fee(b"x" * 100, current_height=height)
        self.assertEqual(floor, BASE_TX_FEE + FEE_PER_STORED_BYTE * 100)


class TestTier9BaseFeeTargetSwitch(unittest.TestCase):
    """update_base_fee honors the raised target at/after the fork."""

    def _supply(self) -> SupplyTracker:
        """A fresh SupplyTracker with base_fee starting at MIN_FEE."""
        sup = SupplyTracker()
        # Force a known starting base_fee so deltas are predictable.
        sup.base_fee = MIN_FEE * 10  # well above MIN_FEE so decreases show
        return sup

    def test_default_height_uses_legacy_target(self):
        """current_height=None (default) keeps TARGET_BLOCK_SIZE=10."""
        sup = self._supply()
        before = sup.base_fee
        # 10 txs is exactly legacy target — no change expected.
        sup.update_base_fee(TARGET_BLOCK_SIZE)
        self.assertEqual(sup.base_fee, before)

    def test_post_fork_height_treats_22_as_target(self):
        """At/after BLOCK_BYTES_RAISE_HEIGHT, 22 txs is at target → no change."""
        sup = self._supply()
        before = sup.base_fee
        sup.update_base_fee(
            TARGET_BLOCK_SIZE_POST_RAISE,
            current_height=BLOCK_BYTES_RAISE_HEIGHT,
        )
        self.assertEqual(sup.base_fee, before)

    def test_post_fork_height_treats_10_as_below_target(self):
        """10 txs at height=fork is well below the new target (22) → decrease."""
        sup = self._supply()
        before = sup.base_fee
        sup.update_base_fee(10, current_height=BLOCK_BYTES_RAISE_HEIGHT)
        # Must strictly decrease (or clamp to MIN_FEE); "no change" would
        # mean the old target is still in effect.
        self.assertLess(sup.base_fee, before)
        self.assertGreaterEqual(sup.base_fee, MIN_FEE)

    def test_post_fork_height_treats_30_as_above_target(self):
        """30 txs at height=fork is above the new target (22) → increase."""
        sup = self._supply()
        before = sup.base_fee
        sup.update_base_fee(30, current_height=BLOCK_BYTES_RAISE_HEIGHT)
        self.assertGreater(sup.base_fee, before)

    def test_default_path_sees_10_as_at_target(self):
        """With current_height=None, 10 txs is AT legacy target → no change.

        This is the cross-check for test_post_fork_height_treats_10_as_
        below_target: same tx_count, different height context, different
        verdict.  Confirms the height parameter really is what's driving
        the branch.
        """
        sup = self._supply()
        before = sup.base_fee
        sup.update_base_fee(10)  # current_height=None
        self.assertEqual(sup.base_fee, before)


class TestTier9MonotoneReplay(unittest.TestCase):
    """Old-cap-compliant blocks remain valid under the new cap."""

    def test_old_cap_block_fits_new_txs_cap(self):
        """A 14-tx block (old cap = 20) trivially fits under new cap (45)."""
        old_tx_count = 14
        self.assertLessEqual(old_tx_count, 20)  # fit legacy cap
        self.assertLessEqual(old_tx_count, MAX_TXS_PER_BLOCK)  # fit new cap

    def test_old_cap_block_fits_new_bytes_cap(self):
        """A 14_000-byte block (old cap = 15_000) fits new cap (45_000)."""
        old_payload = 14_000
        self.assertLessEqual(old_payload, 15_000)  # fit legacy cap
        self.assertLessEqual(old_payload, MAX_BLOCK_MESSAGE_BYTES)  # fit new cap

    def test_old_cap_block_fits_new_sig_cost_cap(self):
        """A 90-unit sig cost (old cap = 100) fits new cap (250)."""
        old_sig_cost = 90
        self.assertLessEqual(old_sig_cost, 100)  # fit legacy cap
        self.assertLessEqual(old_sig_cost, MAX_BLOCK_SIG_COST)  # fit new cap


if __name__ == "__main__":
    unittest.main()
