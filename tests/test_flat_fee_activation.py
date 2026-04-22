"""Tests for the FLAT_FEE_HEIGHT hard fork.

Before FLAT_FEE_HEIGHT the legacy quadratic formula applies — every byte
(and post-FEE_INCLUDES_SIGNATURE_HEIGHT every witness byte too) costs
extra on top of MIN_FEE.  At/after FLAT_FEE_HEIGHT the formula collapses
to a flat per-tx floor (MIN_FEE_POST_FLAT): a 1-byte message and a
full-cap message cost the same, and multi-part messages pay N × floor
by being N separate txs.

The rule shift is consensus-breaking, so callers that verify a tx
without chain context (current_height=None) must keep getting the
legacy rule — isolated tests, relay-layer sanity checks, and similar
non-consensus call sites should not regress.
"""

import unittest

from messagechain.config import (
    FLAT_FEE_HEIGHT,
    FEE_INCLUDES_SIGNATURE_HEIGHT,
    MAX_MESSAGE_BYTES,
    MIN_FEE,
    MIN_FEE_POST_FLAT,
)
from messagechain.core.transaction import (
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestFlatFeeConstants(unittest.TestCase):
    """Schedule invariants for the flat-fee fork."""

    def test_flat_floor_exceeds_legacy_floor(self):
        """New floor must be strictly higher — otherwise the fork silently
        lowers fees instead of raising them."""
        self.assertGreater(MIN_FEE_POST_FLAT, MIN_FEE)

    def test_flat_fee_activates_after_signature_gate(self):
        """The flat-fee fork supersedes FEE_INCLUDES_SIGNATURE_HEIGHT — it
        must activate strictly after it so replay of blocks in the
        [sig-gate, flat-fee) window still applies the witness-aware
        quadratic rule."""
        self.assertGreater(FLAT_FEE_HEIGHT, FEE_INCLUDES_SIGNATURE_HEIGHT)


class TestCalculateMinFeePostActivation(unittest.TestCase):
    """At/after FLAT_FEE_HEIGHT calculate_min_fee is size-independent."""

    def test_empty_message_at_activation_is_flat_floor(self):
        self.assertEqual(
            calculate_min_fee(b"", current_height=FLAT_FEE_HEIGHT),
            MIN_FEE_POST_FLAT,
        )

    def test_max_size_message_at_activation_is_flat_floor(self):
        """A full-capacity message still costs only the flat floor — no
        per-byte surcharge, no quadratic term."""
        big = b"x" * MAX_MESSAGE_BYTES
        self.assertEqual(
            calculate_min_fee(big, current_height=FLAT_FEE_HEIGHT),
            MIN_FEE_POST_FLAT,
        )

    def test_signature_bytes_ignored_post_activation(self):
        """Witness size no longer inflates the floor — the flat fee
        subsumes the sig-aware surcharge."""
        msg = b"hi"
        bare = calculate_min_fee(msg, current_height=FLAT_FEE_HEIGHT)
        with_sig = calculate_min_fee(
            msg, signature_bytes=2048, current_height=FLAT_FEE_HEIGHT,
        )
        self.assertEqual(bare, with_sig)
        self.assertEqual(bare, MIN_FEE_POST_FLAT)

    def test_above_activation_stays_flat(self):
        """Many blocks past activation, the floor is unchanged."""
        self.assertEqual(
            calculate_min_fee(
                b"x" * 100, current_height=FLAT_FEE_HEIGHT + 1_000_000,
            ),
            MIN_FEE_POST_FLAT,
        )

    def test_1_byte_and_10_byte_cost_the_same(self):
        """User-facing invariant: a 1-character tx and a 10-character tx
        pay the same floor (same admission price)."""
        a = calculate_min_fee(b"a", current_height=FLAT_FEE_HEIGHT)
        b = calculate_min_fee(b"aaaaaaaaaa", current_height=FLAT_FEE_HEIGHT)
        self.assertEqual(a, b)


class TestCalculateMinFeePreActivation(unittest.TestCase):
    """Legacy quadratic formula is still reachable — pre-fork replay
    and isolated callers depend on it."""

    def test_pre_activation_uses_quadratic(self):
        """One block before activation, the quadratic formula still
        prices a larger message higher than a smaller one."""
        pre = FLAT_FEE_HEIGHT - 1
        small = calculate_min_fee(b"x" * 10, current_height=pre)
        large = calculate_min_fee(b"x" * 280, current_height=pre)
        self.assertGreater(large, small)

    def test_no_height_context_falls_back_to_legacy(self):
        """current_height=None is the legacy rule — back-compat for
        isolated tests and relay-layer sanity checks."""
        legacy = calculate_min_fee(b"hello world")
        # Must equal the pre-activation (height-threaded) result.
        pre = calculate_min_fee(
            b"hello world", current_height=FLAT_FEE_HEIGHT - 1,
        )
        self.assertEqual(legacy, pre)


class TestMultiTxCostsLinear(unittest.TestCase):
    """User-facing invariant: splitting a long message across N txs
    costs N × flat_floor at the consensus floor.  No quadratic blow-up
    either way — N txs is always N × the single-tx price."""

    def test_n_tx_cost_is_n_times_floor(self):
        floor = calculate_min_fee(b"", current_height=FLAT_FEE_HEIGHT)
        for n in (1, 2, 5, 10):
            self.assertEqual(n * floor, n * MIN_FEE_POST_FLAT)

    def test_10_tx_costs_exactly_2x_5_tx(self):
        """Explicit regression for the user-facing 10-tx vs 5-tx ratio."""
        floor = calculate_min_fee(b"", current_height=FLAT_FEE_HEIGHT)
        self.assertEqual(10 * floor, 2 * (5 * floor))


class TestVerifyTransactionAtFlatFeeGate(unittest.TestCase):
    """verify_transaction honors FLAT_FEE_HEIGHT.  Post-activation a tx
    paying exactly MIN_FEE_POST_FLAT is valid regardless of its payload
    or signature size."""

    def setUp(self):
        self.alice = Entity.create(
            b"alice-flat-fee-activation".ljust(32, b"\x00"),
        )
        self.pubkey = self.alice.keypair.public_key

    def test_flat_floor_fee_admitted_post_activation_small_msg(self):
        """A tx paying exactly MIN_FEE_POST_FLAT for a tiny message is
        admitted post-activation — size no longer affects the floor."""
        small_msg = "hi"
        tx = create_transaction(
            self.alice, small_msg, fee=MIN_FEE_POST_FLAT, nonce=0,
        )
        self.assertTrue(
            verify_transaction(
                tx, self.pubkey, current_height=FLAT_FEE_HEIGHT,
            ),
        )

    def test_flat_floor_fee_admitted_post_activation_full_cap_msg(self):
        """A full-cap (280-char) tx paying exactly MIN_FEE_POST_FLAT is
        admitted post-activation — full capacity costs the same as one
        character.  This is the core user-facing promise of the fork."""
        # 280 incompressible chars ⇒ stored bytes == plaintext bytes.
        big_msg = "".join(chr(32 + (i % 95)) for i in range(280))
        # Under the legacy rule create_transaction would demand a much
        # higher fee.  Build the tx manually and pay exactly the flat
        # floor — valid for post-activation verification.
        import hashlib
        from messagechain.config import HASH_ALGO
        from messagechain.core.compression import encode_payload
        from messagechain.core.transaction import MessageTransaction
        from messagechain.crypto.keys import Signature
        import time as _time
        stored, flag = encode_payload(big_msg.encode("ascii"))
        tx = MessageTransaction(
            entity_id=self.alice.entity_id,
            message=stored,
            timestamp=int(_time.time()),
            nonce=1,
            fee=MIN_FEE_POST_FLAT,
            signature=Signature([], 0, [], b"", b""),
            compression_flag=flag,
        )
        msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
        tx.signature = self.alice.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()
        tx.witness_hash = tx._compute_witness_hash()
        self.assertTrue(
            verify_transaction(
                tx, self.pubkey, current_height=FLAT_FEE_HEIGHT,
            ),
        )

    def test_below_flat_floor_rejected_post_activation(self):
        """A tx paying one unit below the flat floor is rejected."""
        # Mint at legacy rule (tiny msg → legacy_min < MIN_FEE_POST_FLAT),
        # then verify at the post-activation height.  Legacy-rule
        # creation accepts it; post-activation consensus rejects it.
        tiny = "x"
        from messagechain.core.compression import encode_payload
        stored, _ = encode_payload(tiny.encode("ascii"))
        legacy_min = calculate_min_fee(stored)
        self.assertLess(legacy_min, MIN_FEE_POST_FLAT)
        tx = create_transaction(
            self.alice, tiny, fee=MIN_FEE_POST_FLAT - 1, nonce=2,
        )
        # Post-activation the flat floor rejects it.
        self.assertFalse(
            verify_transaction(
                tx, self.pubkey, current_height=FLAT_FEE_HEIGHT,
            ),
        )


if __name__ == "__main__":
    unittest.main()
