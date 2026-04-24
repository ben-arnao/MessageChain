"""Tests for the LINEAR_FEE_HEIGHT fork.

At/after LINEAR_FEE_HEIGHT the per-tx flat floor is replaced by a
linear-in-stored-bytes formula:

    fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(stored_message)

This is paired with a raised per-message cap (MAX_MESSAGE_CHARS=1024)
and a raised per-block payload budget (MAX_BLOCK_MESSAGE_BYTES=15_000)
so longer-form posts are admissible — and pay proportionally for the
permanent storage they consume.

Pre-LINEAR_FEE_HEIGHT replay paths (flat floor, legacy quadratic) keep
their semantics so historical blocks validate unchanged.
"""

import unittest

from messagechain.config import (
    BASE_TX_FEE,
    FEE_PER_STORED_BYTE,
    FLAT_FEE_HEIGHT,
    LINEAR_FEE_HEIGHT,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_MESSAGE_BYTES,
    MAX_MESSAGE_CHARS,
    MAX_TXS_PER_BLOCK,
    MIN_FEE,
    MIN_FEE_POST_FLAT,
)
from messagechain.consensus.bootstrap_gradient import BOOTSTRAP_END_HEIGHT
from messagechain.core.compression import encode_payload
from messagechain.core.transaction import (
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestLinearFeeConstants(unittest.TestCase):
    """The fork introduces three new constants and raises two caps."""

    def test_max_message_chars_raised_to_1024(self):
        self.assertEqual(MAX_MESSAGE_CHARS, 1024)

    def test_max_message_bytes_matches_chars(self):
        self.assertEqual(MAX_MESSAGE_BYTES, MAX_MESSAGE_CHARS)

    def test_max_block_message_bytes_raised_to_15000(self):
        self.assertEqual(MAX_BLOCK_MESSAGE_BYTES, 15_000)

    def test_base_tx_fee_default(self):
        self.assertEqual(BASE_TX_FEE, 10)

    def test_fee_per_stored_byte_default(self):
        self.assertEqual(FEE_PER_STORED_BYTE, 1)

    def test_linear_fee_height_after_flat_fee_height(self):
        self.assertGreater(LINEAR_FEE_HEIGHT, FLAT_FEE_HEIGHT)

    def test_linear_fee_height_inside_bootstrap_window(self):
        self.assertLess(LINEAR_FEE_HEIGHT, BOOTSTRAP_END_HEIGHT)


class TestLinearFeeFormula(unittest.TestCase):
    """At/after LINEAR_FEE_HEIGHT, fee floor = BASE + N * stored bytes."""

    def _expected(self, n_bytes: int) -> int:
        return BASE_TX_FEE + FEE_PER_STORED_BYTE * n_bytes

    def test_one_byte_floor(self):
        self.assertEqual(
            calculate_min_fee(b"x", current_height=LINEAR_FEE_HEIGHT),
            self._expected(1),
        )

    def test_280_byte_floor(self):
        self.assertEqual(
            calculate_min_fee(b"x" * 280, current_height=LINEAR_FEE_HEIGHT),
            self._expected(280),
        )

    def test_max_size_floor(self):
        self.assertEqual(
            calculate_min_fee(b"x" * MAX_MESSAGE_BYTES, current_height=LINEAR_FEE_HEIGHT),
            self._expected(MAX_MESSAGE_BYTES),
        )

    def test_floor_is_strictly_monotonic(self):
        """Adding a byte always raises the floor by FEE_PER_STORED_BYTE."""
        sizes = [1, 50, 100, 280, 512, 1024]
        floors = [
            calculate_min_fee(b"x" * n, current_height=LINEAR_FEE_HEIGHT)
            for n in sizes
        ]
        for prev, curr in zip(floors, floors[1:]):
            self.assertGreater(curr, prev)
        # And the slope is exactly FEE_PER_STORED_BYTE.
        self.assertEqual(
            floors[-1] - floors[0],
            FEE_PER_STORED_BYTE * (sizes[-1] - sizes[0]),
        )

    def test_floor_scales_with_stored_bytes_not_plaintext(self):
        """A compressible payload pays for stored (post-compression) bytes.

        Two plaintexts that canonicalize to the same stored size must pay
        the same floor — the fee follows what's actually written to chain.
        """
        plain_a = b"A" * 500
        plain_b = b"B" * 500
        stored_a, _ = encode_payload(plain_a)
        stored_b, _ = encode_payload(plain_b)
        # Both highly compressible, should land on the same stored size.
        self.assertEqual(len(stored_a), len(stored_b))
        fee_a = calculate_min_fee(stored_a, current_height=LINEAR_FEE_HEIGHT)
        fee_b = calculate_min_fee(stored_b, current_height=LINEAR_FEE_HEIGHT)
        self.assertEqual(fee_a, fee_b)
        # And the fee is meaningfully cheaper than charging on plaintext —
        # this is the storage-incentive property in action.
        self.assertLess(
            fee_a,
            calculate_min_fee(b"x" * 500, current_height=LINEAR_FEE_HEIGHT),
        )


class TestLegacyFeeRulesUnchanged(unittest.TestCase):
    """Pre-LINEAR_FEE_HEIGHT heights replay under their original rules."""

    def test_flat_window_still_returns_flat_floor(self):
        """[FLAT_FEE_HEIGHT, LINEAR_FEE_HEIGHT) keeps the flat per-tx floor."""
        height = FLAT_FEE_HEIGHT  # exactly at activation of flat fee
        self.assertEqual(
            calculate_min_fee(b"x" * 280, current_height=height),
            MIN_FEE_POST_FLAT,
        )
        self.assertEqual(
            calculate_min_fee(b"x", current_height=height),
            MIN_FEE_POST_FLAT,
        )

    def test_pre_flat_height_uses_legacy_quadratic(self):
        """Heights before FLAT_FEE_HEIGHT keep the legacy quadratic floor."""
        height = FLAT_FEE_HEIGHT - 1
        # Legacy formula: MIN_FEE + bytes*FEE_PER_BYTE + bytes^2 * coeff // 1000.
        # We don't recompute it here — just assert the floor exceeds MIN_FEE
        # and is independent of the linear-fee rule.
        floor = calculate_min_fee(b"x" * 100, current_height=height)
        self.assertGreater(floor, MIN_FEE)
        self.assertNotEqual(
            floor,
            BASE_TX_FEE + FEE_PER_STORED_BYTE * 100,
        )

    def test_no_height_context_falls_through_to_legacy(self):
        """Callers without height context (legacy default) get legacy pricing."""
        floor = calculate_min_fee(b"x" * 100)
        # Must not be the linear formula.
        self.assertNotEqual(
            floor,
            BASE_TX_FEE + FEE_PER_STORED_BYTE * 100,
        )


class TestLinearFeeVerification(unittest.TestCase):
    """verify_transaction routes to the linear rule at/after LINEAR_FEE_HEIGHT."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-linear-fee".ljust(32, b"\x00"))

    def test_tx_at_exact_linear_floor_validates(self):
        msg = "x" * 400  # incompressible (single distinct char compresses; use varied)
        # Use varied content so compression doesn't shrink it dramatically;
        # for the edge-case test we want stored ≈ plaintext.
        msg = "".join(chr(33 + (i % 90)) for i in range(400))
        stored, _ = encode_payload(msg.encode("ascii"))
        floor = calculate_min_fee(stored, current_height=LINEAR_FEE_HEIGHT)
        tx = create_transaction(
            self.alice, msg, fee=floor, nonce=0, current_height=LINEAR_FEE_HEIGHT,
        )
        self.assertTrue(
            verify_transaction(
                tx,
                self.alice.keypair.public_key,
                current_height=LINEAR_FEE_HEIGHT,
            )
        )

    def test_tx_below_linear_floor_rejected(self):
        msg = "".join(chr(33 + (i % 90)) for i in range(400))
        stored, _ = encode_payload(msg.encode("ascii"))
        floor = calculate_min_fee(stored, current_height=LINEAR_FEE_HEIGHT)
        # Build a tx that pays floor (so create_transaction accepts it),
        # then mutate the fee field downward and re-sign so verify can
        # exercise the pure fee-floor check at LINEAR_FEE_HEIGHT.
        tx = create_transaction(
            self.alice, msg, fee=floor, nonce=1, current_height=LINEAR_FEE_HEIGHT,
        )
        # Stamp a too-low fee and re-sign.
        from messagechain.crypto.hashing import default_hash

        tx.fee = floor - 1
        tx.signature = self.alice.keypair.sign(default_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        self.assertFalse(
            verify_transaction(
                tx,
                self.alice.keypair.public_key,
                current_height=LINEAR_FEE_HEIGHT,
            )
        )

    def test_long_message_accepted_at_or_above_floor(self):
        """A 1024-char message — previously over-cap — is now valid."""
        msg = "".join(chr(33 + (i % 90)) for i in range(1024))
        stored, _ = encode_payload(msg.encode("ascii"))
        floor = calculate_min_fee(stored, current_height=LINEAR_FEE_HEIGHT)
        tx = create_transaction(
            self.alice, msg, fee=floor, nonce=2, current_height=LINEAR_FEE_HEIGHT,
        )
        self.assertEqual(tx.char_count, 1024)
        self.assertTrue(
            verify_transaction(
                tx,
                self.alice.keypair.public_key,
                current_height=LINEAR_FEE_HEIGHT,
            )
        )

    def test_oversize_message_rejected(self):
        """Messages above MAX_MESSAGE_CHARS (1024) are still rejected."""
        msg = "a" * (MAX_MESSAGE_CHARS + 1)
        with self.assertRaises(ValueError):
            create_transaction(self.alice, msg, fee=10_000, nonce=3)


class TestBlockBudgetAfterFork(unittest.TestCase):
    """Per-block byte budget still bounds total payload, just at a higher cap."""

    def test_max_size_messages_dont_all_fit_in_budget(self):
        """20 max-size (1024 B) messages exceed MAX_BLOCK_MESSAGE_BYTES (15_000).

        This is intentional: the cap raise is a per-message ceiling, not a
        commitment that 20 max-size messages fit. Validators pack greedily
        by fee-per-byte; oversized blocks naturally pressure the byte budget.
        """
        worst_case = MAX_TXS_PER_BLOCK * MAX_MESSAGE_BYTES
        self.assertGreater(worst_case, MAX_BLOCK_MESSAGE_BYTES)

    def test_typical_load_fits(self):
        """20 short (280 B) messages still fit comfortably."""
        typical = MAX_TXS_PER_BLOCK * 280
        self.assertLess(typical, MAX_BLOCK_MESSAGE_BYTES)

    def test_some_max_size_messages_fit(self):
        """At least 14 max-size messages fit in the byte budget."""
        max_fit = MAX_BLOCK_MESSAGE_BYTES // MAX_MESSAGE_BYTES
        self.assertGreaterEqual(max_fit, 14)


if __name__ == "__main__":
    unittest.main()
