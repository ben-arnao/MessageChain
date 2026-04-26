"""Tests for Tier 16 — MARKET_FEE_FLOOR_HEIGHT (market-driven fee floor).

At/after MARKET_FEE_FLOOR_HEIGHT the per-tx fee floor for
MessageTransactions collapses to a flat MARKET_FEE_FLOOR=1 token,
regardless of message size.  Bloat discipline is now delivered by:

  * MAX_BLOCK_MESSAGE_BYTES — hard ceiling on bytes pinned per block,
    a rate-limit independent of fee paid.
  * EIP-1559 base fee — automatically rises under congestion and
    decays during quiet periods, pricing the marginal byte at the
    market-clearing rate.

Pre-fork heights still replay under the rule current at their height
(linear-in-stored-bytes, flat MIN_FEE_POST_FLAT, or legacy quadratic).

Type-specific surcharges (NEW_ACCOUNT_FEE, GOVERNANCE_PROPOSAL_FEE,
KEY_ROTATION_FEE, etc.) are unaffected — they price externalities
specific to those tx types and continue to apply above the protocol
floor.
"""

import unittest

from messagechain.config import (
    BASE_TX_FEE,
    BLOCK_BYTES_RAISE_HEIGHT,
    FEE_PER_STORED_BYTE_POST_RAISE,
    FLAT_FEE_HEIGHT,
    GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT,
    LINEAR_FEE_HEIGHT,
    MARKET_FEE_FLOOR,
    MARKET_FEE_FLOOR_HEIGHT,
    MAX_MESSAGE_CHARS,
    MIN_FEE,
    MIN_FEE_POST_FLAT,
)
from messagechain.consensus.bootstrap_gradient import BOOTSTRAP_END_HEIGHT
from messagechain.core.transaction import calculate_min_fee


class TestMarketFeeFloorConstants(unittest.TestCase):

    def test_floor_is_one(self):
        self.assertEqual(MARKET_FEE_FLOOR, 1)

    def test_floor_is_strictly_positive(self):
        # A zero floor reopens the zero-fee mempool-DoS path; the
        # protocol floor only exists to keep that closed.
        self.assertGreaterEqual(MARKET_FEE_FLOOR, 1)

    def test_activation_height_above_prior_tier(self):
        # Tier 16 must follow the established fork schedule.
        self.assertGreater(
            MARKET_FEE_FLOOR_HEIGHT, GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT,
        )

    def test_activation_height_within_bootstrap(self):
        self.assertLess(MARKET_FEE_FLOOR_HEIGHT, BOOTSTRAP_END_HEIGHT)


class TestCalculateMinFeeAtTier16(unittest.TestCase):
    """At/after activation the floor is flat 1, regardless of size."""

    def test_empty_message_floor_is_one(self):
        fee = calculate_min_fee(b"", current_height=MARKET_FEE_FLOOR_HEIGHT)
        self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_short_message_floor_is_one(self):
        fee = calculate_min_fee(b"hello", current_height=MARKET_FEE_FLOOR_HEIGHT)
        self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_long_message_floor_is_one(self):
        # A full 1024-byte payload still pays only the flat floor.
        fee = calculate_min_fee(
            b"x" * MAX_MESSAGE_CHARS,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
        )
        self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_prev_pointer_does_not_raise_floor(self):
        # Pre-Tier-16 the prev pointer added 33 bytes × per-byte rate.
        # Post-Tier-16 the market prices it via base_fee, not the floor.
        fee_no_prev = calculate_min_fee(
            b"x" * 100, current_height=MARKET_FEE_FLOOR_HEIGHT, prev_bytes=0,
        )
        fee_with_prev = calculate_min_fee(
            b"x" * 100, current_height=MARKET_FEE_FLOOR_HEIGHT, prev_bytes=33,
        )
        self.assertEqual(fee_no_prev, MARKET_FEE_FLOOR)
        self.assertEqual(fee_with_prev, MARKET_FEE_FLOOR)

    def test_signature_bytes_does_not_raise_floor(self):
        # The market prices the witness via base_fee; the flat floor
        # is uniform per tx.
        fee = calculate_min_fee(
            b"x" * 100,
            signature_bytes=2700,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
        )
        self.assertEqual(fee, MARKET_FEE_FLOOR)


class TestPreTier16ReplayUnchanged(unittest.TestCase):
    """Pre-fork heights must replay under the rule at their height —
    historical determinism."""

    def test_block_bytes_raise_rule_unchanged(self):
        # Just below MARKET_FEE_FLOOR_HEIGHT the Tier 9 linear rule
        # still applies for replay determinism.
        height = MARKET_FEE_FLOOR_HEIGHT - 1
        msg = b"x" * 200
        expected = BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * len(msg)
        self.assertEqual(
            calculate_min_fee(msg, current_height=height), expected,
        )

    def test_linear_window_rule_unchanged(self):
        # In [LINEAR_FEE_HEIGHT, BLOCK_BYTES_RAISE_HEIGHT) the Tier 8
        # rate (FEE_PER_STORED_BYTE=1) applies — replay must still work.
        from messagechain.config import FEE_PER_STORED_BYTE
        height = LINEAR_FEE_HEIGHT
        if height >= BLOCK_BYTES_RAISE_HEIGHT:
            self.skipTest("compressed schedule: Tier 8 window has zero width")
        msg = b"x" * 200
        expected = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(msg)
        self.assertEqual(
            calculate_min_fee(msg, current_height=height), expected,
        )

    def test_legacy_default_rule_unchanged(self):
        # ``current_height=None`` — the legacy default for isolated
        # tests and non-consensus call sites — still hits the
        # legacy quadratic formula.
        # Just check that current_height=None does NOT route to Tier 16.
        fee_at_none = calculate_min_fee(b"")
        # Legacy quadratic formula: MIN_FEE + 0 + 0 = MIN_FEE for empty msg.
        self.assertEqual(fee_at_none, MIN_FEE)
        self.assertNotEqual(fee_at_none, MARKET_FEE_FLOOR)


class TestEnforceSignatureAwareMinFeeAtTier16(unittest.TestCase):
    """Non-message tx types route through enforce_signature_aware_min_fee.
    At/after Tier 16 the protocol baseline is MARKET_FEE_FLOOR; type-
    specific surcharges (passed as ``flat_floor``) still apply."""

    def test_below_market_floor_rejected(self):
        from messagechain.core.transaction import enforce_signature_aware_min_fee
        accepted = enforce_signature_aware_min_fee(
            tx_fee=0,
            signature_bytes=0,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
            flat_floor=0,
        )
        self.assertFalse(accepted)

    def test_at_market_floor_accepted_when_flat_floor_zero(self):
        from messagechain.core.transaction import enforce_signature_aware_min_fee
        accepted = enforce_signature_aware_min_fee(
            tx_fee=MARKET_FEE_FLOOR,
            signature_bytes=0,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
            flat_floor=0,
        )
        self.assertTrue(accepted)

    def test_type_specific_surcharge_still_binds(self):
        # If the tx type's flat_floor is e.g. KEY_ROTATION_FEE > 1,
        # the MARKET_FEE_FLOOR baseline is irrelevant — the surcharge
        # is the binding floor.
        from messagechain.core.transaction import enforce_signature_aware_min_fee
        type_specific_floor = 500
        # Below the type-specific floor — rejected.
        self.assertFalse(enforce_signature_aware_min_fee(
            tx_fee=type_specific_floor - 1,
            signature_bytes=0,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
            flat_floor=type_specific_floor,
        ))
        # At the type-specific floor — accepted.
        self.assertTrue(enforce_signature_aware_min_fee(
            tx_fee=type_specific_floor,
            signature_bytes=0,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
            flat_floor=type_specific_floor,
        ))

    def test_signature_size_does_not_raise_baseline(self):
        # Pre-Tier-7 the witness was priced separately; Tier 7+ the
        # flat floor subsumed it; Tier 16 keeps that property —
        # the signature bytes do not raise the protocol baseline.
        from messagechain.core.transaction import enforce_signature_aware_min_fee
        accepted = enforce_signature_aware_min_fee(
            tx_fee=MARKET_FEE_FLOOR,
            signature_bytes=2700,  # full WOTS+ witness
            current_height=MARKET_FEE_FLOOR_HEIGHT,
            flat_floor=0,
        )
        self.assertTrue(accepted)

    def test_pre_tier16_path_unchanged(self):
        # Just below activation, the Tier 7+ flat MIN_FEE_POST_FLAT
        # rule still applies — replay determinism.
        from messagechain.core.transaction import enforce_signature_aware_min_fee
        height = MARKET_FEE_FLOOR_HEIGHT - 1
        if height < FLAT_FEE_HEIGHT:
            self.skipTest("compressed schedule: pre-FLAT window")
        # Below MIN_FEE_POST_FLAT — rejected.
        self.assertFalse(enforce_signature_aware_min_fee(
            tx_fee=MIN_FEE_POST_FLAT - 1,
            signature_bytes=0,
            current_height=height,
            flat_floor=0,
        ))


class TestBaseFeeFloorAtTier16(unittest.TestCase):
    """EIP-1559 base_fee can decay to MARKET_FEE_FLOOR (=1) post-fork,
    not the legacy MIN_FEE (=100)."""

    def _fresh_ledger(self):
        from messagechain.economics.inflation import SupplyTracker
        return SupplyTracker()

    def test_market_floor_does_not_go_below_one_post_fork(self):
        # An under-target block at post-fork height must not drive
        # base_fee below MARKET_FEE_FLOOR.
        ledger = self._fresh_ledger()
        ledger.base_fee = MARKET_FEE_FLOOR
        ledger.update_base_fee(
            parent_tx_count=0,
            current_height=MARKET_FEE_FLOOR_HEIGHT,
        )
        self.assertEqual(ledger.base_fee, MARKET_FEE_FLOOR)
        self.assertGreaterEqual(ledger.base_fee, MARKET_FEE_FLOOR)

    def test_pre_fork_clamps_up_to_min_fee(self):
        # Pre-Tier-16 the floor is MIN_FEE — a base_fee somehow set
        # below MIN_FEE must clamp up at the next under-target update.
        # (In practice this branch is unreachable because MIN_FEE is
        # the only path that sets base_fee, but the clamp itself is
        # the contract being asserted for replay determinism.)
        ledger = self._fresh_ledger()
        ledger.base_fee = MARKET_FEE_FLOOR  # below MIN_FEE
        height = MARKET_FEE_FLOOR_HEIGHT - 1
        if height < BLOCK_BYTES_RAISE_HEIGHT:
            self.skipTest("compressed schedule: pre-Tier-9 window")
        ledger.update_base_fee(
            parent_tx_count=0,
            current_height=height,
        )
        self.assertEqual(ledger.base_fee, MIN_FEE)
        self.assertNotEqual(ledger.base_fee, MARKET_FEE_FLOOR)

    def test_post_fork_below_min_fee_stays_below(self):
        # Symmetric to the pre-fork test: post-fork the floor is
        # MARKET_FEE_FLOOR (=1), so a base_fee at 1 stays at 1 across
        # under-target updates rather than being clamped up to MIN_FEE.
        ledger = self._fresh_ledger()
        ledger.base_fee = MARKET_FEE_FLOOR
        for _ in range(50):
            ledger.update_base_fee(
                parent_tx_count=0,
                current_height=MARKET_FEE_FLOOR_HEIGHT,
            )
        self.assertEqual(ledger.base_fee, MARKET_FEE_FLOOR)
        self.assertLess(ledger.base_fee, MIN_FEE)


if __name__ == "__main__":
    unittest.main()
