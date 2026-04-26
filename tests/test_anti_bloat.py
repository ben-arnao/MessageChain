"""Tests for anti-bloat parameter tuning and size-based fees.

Validates the parameter changes that differentiate MessageChain from BTC:
- Slower block time (600s / 10 min) to reduce header chain growth
- Non-linear size-based fees (quadratic) to punish large messages
- Per-block byte budget (MAX_BLOCK_MESSAGE_BYTES) to cap storage per block
- Higher dynamic fee ceiling to punish congestion-era spam
- Dependent parameter recalculation (halving, unbonding, governance)
"""

import unittest
from messagechain.config import (
    BLOCK_TIME_TARGET,
    MIN_FEE,
    MAX_TXS_PER_BLOCK,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_MESSAGE_BYTES,
    MEMPOOL_PER_SENDER_LIMIT,
    MEMPOOL_MAX_ANCESTORS,
    HALVING_INTERVAL,
    UNBONDING_PERIOD,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    KEY_ROTATION_FEE,
    FEE_PER_BYTE,
    FEE_QUADRATIC_COEFF,
    BLOCK_REWARD,
)
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.core.transaction import (
    create_transaction,
    verify_transaction,
    calculate_min_fee,
)
from messagechain.identity.identity import Entity


class TestBlockTimeParameters(unittest.TestCase):
    """Block time is 600s (10 min, same as BTC) — speed is not a priority."""

    def test_block_time_is_600_seconds(self):
        self.assertEqual(BLOCK_TIME_TARGET, 600)

    def test_halving_interval_is_4_years_at_600s(self):
        """~4 years of blocks at 600s/block."""
        blocks_per_year = 365.25 * 24 * 3600 / BLOCK_TIME_TARGET
        years = HALVING_INTERVAL / blocks_per_year
        self.assertAlmostEqual(years, 4.0, delta=0.1)

    def test_unbonding_period_covers_evidence_window(self):
        """Post slash-evasion fix, the unbonding period must cover the
        evidence window (~14 days) plus maturity delay plus margin —
        originally 7 days, now ~15 days.  The invariant-style assertion
        lives in tests/test_unbonding_evidence_invariant.py; this test
        anchors the at-600s duration for operator-facing tooling."""
        from messagechain.config import (
            EVIDENCE_EXPIRY_BLOCKS, EVIDENCE_MATURITY_BLOCKS,
        )
        blocks_per_day = 24 * 3600 / BLOCK_TIME_TARGET
        days = UNBONDING_PERIOD / blocks_per_day
        # ~15.1 days = 2176 blocks at 600 s/block.
        self.assertAlmostEqual(days, 15.1, delta=0.2)
        # Structural: the value tracks the evidence-window invariant.
        self.assertGreaterEqual(
            UNBONDING_PERIOD,
            EVIDENCE_EXPIRY_BLOCKS + EVIDENCE_MATURITY_BLOCKS,
        )

    def test_governance_voting_window_is_7_days_at_600s(self):
        """~7 days of blocks at 600s/block."""
        blocks_per_day = 24 * 3600 / BLOCK_TIME_TARGET
        days = GOVERNANCE_VOTING_WINDOW / blocks_per_day
        self.assertAlmostEqual(days, 7.0, delta=0.1)


class TestNonLinearFees(unittest.TestCase):
    """Fees use quadratic pricing — larger messages cost disproportionately more."""

    def test_fee_per_byte_raised(self):
        self.assertGreaterEqual(FEE_PER_BYTE, 3)

    def test_quadratic_coefficient_exists(self):
        self.assertGreater(FEE_QUADRATIC_COEFF, 0)

    def test_empty_message_costs_min_fee(self):
        self.assertEqual(calculate_min_fee(b""), MIN_FEE)

    def test_fee_formula(self):
        """Fee = MIN_FEE + (bytes * FEE_PER_BYTE) + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000."""
        msg = b"Hello, world!"
        size = len(msg)
        expected = MIN_FEE + size * FEE_PER_BYTE + (size * size * FEE_QUADRATIC_COEFF) // 1000
        self.assertEqual(calculate_min_fee(msg), expected)

    def test_fee_grows_super_linearly(self):
        """Doubling message size more than doubles the fee increase."""
        fee_100 = calculate_min_fee(b"x" * 100)
        fee_200 = calculate_min_fee(b"x" * 200)
        fee_400 = calculate_min_fee(b"x" * 400)
        delta_small = fee_200 - fee_100
        delta_large = fee_400 - fee_200
        self.assertGreater(delta_large, delta_small)

    def test_max_message_fee_is_substantial(self):
        """Max-size message (280 bytes) should cost more than MIN_FEE."""
        fee = calculate_min_fee(b"x" * 280)
        self.assertGreater(fee, MIN_FEE * 5)

    def test_small_message_still_affordable(self):
        """Short messages (50 bytes) should be reasonably priced."""
        fee = calculate_min_fee(b"x" * 50)
        # Should be modest — base fee + small linear + negligible quadratic
        self.assertLess(fee, MIN_FEE * 5)


class TestSizeBasedFeeIntegration(unittest.TestCase):
    """Transaction creation/verification respects non-linear fees."""

    def setUp(self):
        self.alice = Entity.create(b"alice-key-for-fee-tests".ljust(32, b"\x00"))

    def test_create_transaction_rejects_fee_below_nonlinear_minimum(self):
        # Fees are charged on the STORED (canonical) size after compression,
        # not the raw plaintext. Use a short incompressible message so the
        # stored size equals the plaintext size and the test is exercising
        # the non-linear fee formula directly.
        msg = "hi there, friend!"  # short enough to stay raw
        min_required = calculate_min_fee(msg.encode("ascii"))
        with self.assertRaises(ValueError):
            create_transaction(self.alice, msg, fee=min_required - 1, nonce=0)

    def test_create_transaction_accepts_fee_at_nonlinear_minimum(self):
        msg = "A" * 100
        # Compressible — fee must exceed calculate_min_fee(stored), not plaintext.
        from messagechain.core.compression import encode_payload
        stored, _ = encode_payload(msg.encode("ascii"))
        min_required = calculate_min_fee(stored)
        tx = create_transaction(self.alice, msg, fee=min_required, nonce=0)
        self.assertEqual(tx.fee, min_required)

    def test_verify_transaction_with_valid_fee(self):
        msg = "B" * 200
        from messagechain.core.compression import encode_payload
        stored, _ = encode_payload(msg.encode("ascii"))
        min_required = calculate_min_fee(stored)
        tx = create_transaction(self.alice, msg, fee=min_required, nonce=0)
        self.assertTrue(verify_transaction(tx, self.alice.keypair.public_key))


class TestBlockByteBudget(unittest.TestCase):
    """MAX_BLOCK_MESSAGE_BYTES caps total message payload per block."""

    def test_byte_budget_exists(self):
        self.assertGreater(MAX_BLOCK_MESSAGE_BYTES, 0)

    def test_byte_budget_is_15kb(self):
        # Raised 10_000 → 15_000 at LINEAR_FEE_HEIGHT (Tier 8) alongside
        # the per-message cap raise, then 15_000 → 45_000 at
        # BLOCK_BYTES_RAISE_HEIGHT (Tier 9) to widen per-block throughput.
        # See test_tier9_throughput for the post-fork block-budget invariants.
        self.assertEqual(MAX_BLOCK_MESSAGE_BYTES, 45_000)

    def test_typical_messages_fit_within_budget(self):
        """20 short (280 B) messages still fit comfortably in the budget."""
        total = MAX_TXS_PER_BLOCK * 280
        self.assertLess(total, MAX_BLOCK_MESSAGE_BYTES)

    def test_small_messages_fit_within_budget(self):
        """20 small messages (50 bytes each = 1000) fit within the budget."""
        total = MAX_TXS_PER_BLOCK * 50
        self.assertLess(total, MAX_BLOCK_MESSAGE_BYTES)

    def test_byte_budget_holds_some_max_size_messages(self):
        """At 1024 bytes each, at least 14 max-size messages fit in the 15KB budget.

        Worst-case 20 max-size messages intentionally exceed the budget —
        the per-message cap is a ceiling, not a guarantee that 20 of them
        fit. Validators pack greedily by fee-per-byte; oversized blocks
        face the byte-budget wall naturally.
        """
        max_fit = MAX_BLOCK_MESSAGE_BYTES // MAX_MESSAGE_BYTES
        self.assertGreaterEqual(max_fit, 14)


class TestBlockSizeParameters(unittest.TestCase):
    """Block capacity limits daily throughput to combat bloat."""

    def test_max_txs_per_block(self):
        # Raised 20 → 45 at BLOCK_BYTES_RAISE_HEIGHT (Tier 9) to widen
        # per-block throughput toward ~24 GB/yr on-disk at 100-validator
        # saturation.
        self.assertEqual(MAX_TXS_PER_BLOCK, 45)

    def test_daily_throughput_cap(self):
        """With 600s blocks and 45 txs/block, daily throughput is ~6,480."""
        blocks_per_day = 24 * 3600 / BLOCK_TIME_TARGET
        daily_txs = blocks_per_day * MAX_TXS_PER_BLOCK
        self.assertLessEqual(daily_txs, 7000)


class TestMempoolParameters(unittest.TestCase):
    """Per-sender limits prevent burst spam."""

    def test_per_sender_limit_reduced(self):
        self.assertEqual(MEMPOOL_PER_SENDER_LIMIT, 5)

    def test_max_ancestors_reduced(self):
        self.assertEqual(MEMPOOL_MAX_ANCESTORS, 5)


class TestDynamicFeeNoOpShim(unittest.TestCase):
    """DynamicFeePolicy is a no-op shim — relay floor is flat MARKET_FEE_FLOOR.

    The fee model deliberately does NOT scale per-tx fees with mempool
    pressure: the spam ceiling is delivered by block cadence + per-block
    byte budget, not fee inflation.  See CLAUDE.md "Fee model — minimum
    fee is 1, never 0; spam ceiling is block timing, not per-tx fee
    inflation."  These tests pin the no-op behavior so a future change
    that re-introduces dynamic scaling fails loudly.
    """

    def test_full_mempool_fee_is_market_floor(self):
        from messagechain.config import MARKET_FEE_FLOOR
        policy = DynamicFeePolicy()
        fee = policy.get_min_relay_fee(5000, 5000)
        self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_empty_mempool_fee_is_market_floor(self):
        from messagechain.config import MARKET_FEE_FLOOR
        policy = DynamicFeePolicy()
        fee = policy.get_min_relay_fee(0, 5000)
        self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_constructor_args_have_no_effect(self):
        """base_fee and max_fee constructor args are accepted but ignored."""
        from messagechain.config import MARKET_FEE_FLOOR
        policy = DynamicFeePolicy(base_fee=999, max_fee=99_999)
        self.assertEqual(policy.get_min_relay_fee(2500, 5000), MARKET_FEE_FLOOR)


class TestGovernanceFees(unittest.TestCase):
    """Governance fees scaled appropriately."""

    def test_governance_proposal_fee(self):
        # Raised from 1000 to 10_000 in the 2026-04-15 redesign:
        # anyone can propose (no validator gate), so the spam brake is
        # priced at the fee instead.
        self.assertEqual(GOVERNANCE_PROPOSAL_FEE, 10_000)

    def test_governance_vote_fee(self):
        self.assertEqual(GOVERNANCE_VOTE_FEE, 100)

    def test_key_rotation_fee(self):
        self.assertEqual(KEY_ROTATION_FEE, 1000)


class TestHalvingStillWorks(unittest.TestCase):
    """Halving schedule should still produce meaningful halvings."""

    def test_halvings_with_floor(self):
        from messagechain.economics.inflation import SupplyTracker
        from messagechain.config import BLOCK_REWARD_FLOOR
        tracker = SupplyTracker()
        self.assertEqual(tracker.calculate_block_reward(0), 16)
        self.assertEqual(tracker.calculate_block_reward(HALVING_INTERVAL), 8)
        self.assertEqual(tracker.calculate_block_reward(HALVING_INTERVAL * 2), BLOCK_REWARD_FLOOR)
        # After hitting floor, reward stays at floor
        self.assertEqual(tracker.calculate_block_reward(HALVING_INTERVAL * 3), BLOCK_REWARD_FLOOR)
        self.assertEqual(tracker.calculate_block_reward(HALVING_INTERVAL * 100), BLOCK_REWARD_FLOOR)


class TestChainGrowthAnalysis(unittest.TestCase):
    """Verify storage growth is bounded for the 1000-year design goal."""

    def test_daily_message_bytes_bounded(self):
        """Daily max message payload should be reasonable."""
        blocks_per_day = 24 * 3600 / BLOCK_TIME_TARGET  # 144
        daily_message_bytes = blocks_per_day * MAX_BLOCK_MESSAGE_BYTES
        # 144 blocks * 45KB = 6.48MB/day max message payload (post-Tier-9)
        self.assertLess(daily_message_bytes, 10_000_000)  # under 10MB/day

    def test_annual_growth_bounded(self):
        """Annual max storage should stay reasonable."""
        blocks_per_year = 365.25 * 24 * 3600 / BLOCK_TIME_TARGET
        annual_bytes = blocks_per_year * MAX_BLOCK_MESSAGE_BYTES
        # ~52,560 blocks * 45KB ≈ ~2.37GB/year max message payload (post-Tier-9)
        self.assertLess(annual_bytes, 3_000_000_000)  # under 3GB/year

    def test_1000_year_projection(self):
        """Over 1000 years, permanent-message storage stays bounded by the
        per-block byte budget — no pruning, no deletion, ever."""
        blocks_per_year = 365.25 * 24 * 3600 / BLOCK_TIME_TARGET
        annual_bytes = blocks_per_year * MAX_BLOCK_MESSAGE_BYTES
        # Permanent storage: ~2.37TB over 1000 years at the byte-budget
        # ceiling (post-Tier-9).  Fees, size caps, compression, and
        # witness separation are the only bloat levers — the chain
        # itself is append-only forever.
        thousand_year_bytes = 1000 * annual_bytes
        self.assertLess(thousand_year_bytes, 3_000_000_000_000)  # under 3TB over 1000 years


if __name__ == "__main__":
    unittest.main()
