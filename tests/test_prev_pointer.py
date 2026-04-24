"""Tests for the Tier 10 `prev` pointer feature.

At/after PREV_POINTER_HEIGHT, message transactions may opt into tx
version 2 and attach a single optional 32-byte `prev` pointer to a
prior tx_hash, forming a single-linked list of prior messages.  The
feature is deliberately protocol-agnostic: `prev` simply means "this
message references a prior message" — whether that's a reply, a
continuation of a longer chained document, a citation, or anything
else is app-layer interpretation.

Strict validation: when a `prev` is set, it must resolve to a
MessageTransaction that appears in a strictly earlier persisted
block.  Dangling or forward references are rejected.  Self-reference
is rejected unconditionally.

Fee treatment: the 33 raw bytes (1B presence flag + 32B hash) are
priced at the live per-stored-byte rate, so pointer-bearing txs pay
uniformly for their on-chain footprint.  They do NOT count against
`MAX_MESSAGE_CHARS` — the cap is a human-content constraint, the
pointer is structural metadata.
"""

import unittest

from messagechain.config import (
    BASE_TX_FEE,
    BLOCK_BYTES_RAISE_HEIGHT,
    FEE_PER_STORED_BYTE,
    FEE_PER_STORED_BYTE_POST_RAISE,
    LINEAR_FEE_HEIGHT,
    MAX_MESSAGE_CHARS,
    PREV_POINTER_HEIGHT,
)
from messagechain.core.transaction import (
    MessageTransaction,
    PREV_POINTER_STORED_BYTES,
    TX_VERSION_PREV_POINTER,
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


def _min_fee(msg_bytes: int, height: int, prev: bool) -> int:
    prev_n = PREV_POINTER_STORED_BYTES if prev else 0
    return calculate_min_fee(
        b"x" * msg_bytes, current_height=height, prev_bytes=prev_n,
    )


class TestPrevPointerConstants(unittest.TestCase):
    """Protocol constants for the fork."""

    def test_prev_pointer_height_after_block_bytes_raise(self):
        self.assertGreater(PREV_POINTER_HEIGHT, BLOCK_BYTES_RAISE_HEIGHT)

    def test_tx_version_prev_pointer_is_2(self):
        self.assertEqual(TX_VERSION_PREV_POINTER, 2)

    def test_prev_stored_bytes_is_33(self):
        # 1-byte presence flag + 32-byte tx_hash — matches the wire
        # form and the signing payload.
        self.assertEqual(PREV_POINTER_STORED_BYTES, 33)


class TestPrevPointerFee(unittest.TestCase):
    """`prev` bytes are priced at the live per-stored-byte rate."""

    def test_fee_adds_33_bytes_linear_era(self):
        h = LINEAR_FEE_HEIGHT
        # A 100-byte message with no prev pays (10 + 100 * 1) = 110.
        base = _min_fee(100, h, prev=False)
        self.assertEqual(base, BASE_TX_FEE + FEE_PER_STORED_BYTE * 100)
        # Same message with prev set pays (10 + 133 * 1) = 143.
        with_prev = _min_fee(100, h, prev=True)
        self.assertEqual(
            with_prev,
            BASE_TX_FEE
            + FEE_PER_STORED_BYTE * (100 + PREV_POINTER_STORED_BYTES),
        )
        # The premium is exactly PREV_POINTER_STORED_BYTES × rate.
        self.assertEqual(
            with_prev - base,
            FEE_PER_STORED_BYTE * PREV_POINTER_STORED_BYTES,
        )

    def test_fee_adds_33_bytes_post_raise_era(self):
        # At/after Tier 9, per-byte rate triples — prev overhead
        # scales accordingly.
        h = BLOCK_BYTES_RAISE_HEIGHT
        base = _min_fee(100, h, prev=False)
        with_prev = _min_fee(100, h, prev=True)
        self.assertEqual(
            with_prev - base,
            FEE_PER_STORED_BYTE_POST_RAISE * PREV_POINTER_STORED_BYTES,
        )

    def test_fee_uniform_between_prev_and_inline_hex(self):
        # Core economic argument: a user who references a prior tx
        # via `prev` pays ~half what they'd pay for 64-char inline hex.
        # Inline: 64-char hex in the text payload.
        # Via prev: 33 raw bytes, text payload unchanged.
        h = BLOCK_BYTES_RAISE_HEIGHT
        text_budget = 200  # arbitrary human-content budget
        inline = calculate_min_fee(
            b"x" * (text_budget + 64), current_height=h,
        )
        via_prev = calculate_min_fee(
            b"x" * text_budget,
            current_height=h,
            prev_bytes=PREV_POINTER_STORED_BYTES,
        )
        # Pointer form wins on fee — exactly (64 - 33) * rate cheaper.
        self.assertEqual(
            inline - via_prev,
            FEE_PER_STORED_BYTE_POST_RAISE * (64 - PREV_POINTER_STORED_BYTES),
        )
        self.assertLess(via_prev, inline)


class TestPrevPointerSigningAndWire(unittest.TestCase):
    """Hash stability, roundtrip, and version gating at the format layer."""

    def setUp(self):
        self.entity = Entity.create(b"prev-pointer-test-seed-padded-to-32b!")

    def test_version_1_hash_unchanged_by_prev_field(self):
        # Backward compat: a version=1 tx's _signable_data must not
        # change byte-for-byte when `prev` happens to be None — the
        # field was added as a dataclass default, so the legacy hash
        # must keep reproducing without the new bytes.
        tx = create_transaction(
            self.entity, "hello", fee=1000, nonce=0, current_height=PREV_POINTER_HEIGHT,
        )
        self.assertEqual(tx.version, 1)
        self.assertIsNone(tx.prev)
        # Re-hash after construction — should match the stored hash.
        self.assertEqual(tx.tx_hash, tx._compute_hash())

    def test_create_transaction_with_prev_bumps_version(self):
        prev_hash = b"\x11" * 32
        tx = create_transaction(
            self.entity,
            "reply",
            fee=10_000,
            nonce=0,
            current_height=PREV_POINTER_HEIGHT,
            prev=prev_hash,
        )
        self.assertEqual(tx.version, TX_VERSION_PREV_POINTER)
        self.assertEqual(tx.prev, prev_hash)

    def test_create_transaction_rejects_non_32_byte_prev(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                create_transaction(
                    self.entity, "x", fee=10_000, nonce=0,
                    current_height=PREV_POINTER_HEIGHT, prev=bad,
                )

    def test_prev_changes_signed_payload(self):
        # Setting prev must flip tx_hash — a reader who sees the tx
        # can't claim "I thought there was no prev pointer".
        tx_no = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT,
        )
        tx_yes = create_transaction(
            self.entity, "x", fee=10_000, nonce=1,
            current_height=PREV_POINTER_HEIGHT, prev=b"\x22" * 32,
        )
        self.assertNotEqual(tx_no.tx_hash, tx_yes.tx_hash)

    def test_wire_roundtrip_version_1(self):
        # Pre-fork wire format: no prev bytes in to_bytes output.
        tx = create_transaction(
            self.entity, "hello", fee=1000, nonce=0,
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, 1)
        self.assertIsNone(restored.prev)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_wire_roundtrip_version_2_with_prev(self):
        prev_hash = b"\x33" * 32
        tx = create_transaction(
            self.entity, "hello", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=prev_hash,
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, TX_VERSION_PREV_POINTER)
        self.assertEqual(restored.prev, prev_hash)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_roundtrip_version_2(self):
        prev_hash = b"\x44" * 32
        tx = create_transaction(
            self.entity, "hello", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=prev_hash,
        )
        d = tx.serialize()
        self.assertEqual(d["prev"], prev_hash.hex())
        restored = MessageTransaction.deserialize(d)
        self.assertEqual(restored.prev, prev_hash)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_omits_prev_when_absent(self):
        tx = create_transaction(
            self.entity, "hello", fee=1000, nonce=0,
        )
        d = tx.serialize()
        self.assertNotIn("prev", d)


class TestPrevPointerVerifyGate(unittest.TestCase):
    """verify_transaction enforces the fork gate and shape rules."""

    def setUp(self):
        self.entity = Entity.create(b"prev-verify-seed-padded-to-32-bytes!!")
        self.pk = self.entity.keypair.public_key

    def test_version_2_rejected_pre_activation(self):
        # A v2 tx submitted for inclusion before the fork activates
        # must be rejected.  Construct by hand because
        # create_transaction's fee floor assumes the current height.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=b"\x55" * 32,
        )
        self.assertEqual(tx.version, TX_VERSION_PREV_POINTER)
        # Verify at a pre-activation height.
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=PREV_POINTER_HEIGHT - 1,
            )
        )
        # And at activation height — strict-prev is not checked
        # (no prev_lookup passed) so the signature path resolves and
        # the tx validates structurally.
        self.assertTrue(
            verify_transaction(
                tx, self.pk, current_height=PREV_POINTER_HEIGHT,
            )
        )

    def test_version_1_with_prev_rejected(self):
        # A malformed tx claiming version=1 but carrying a prev field
        # must be rejected — the signed payload doesn't include prev
        # at v1, so this would be a signature-committing-to-different-
        # bytes attack.
        tx = create_transaction(
            self.entity, "x", fee=1000, nonce=0,
        )
        tx.prev = b"\x66" * 32  # tamper post-signing
        self.assertEqual(tx.version, 1)
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=PREV_POINTER_HEIGHT,
            )
        )

    def test_self_reference_rejected(self):
        # A tx pointing at its own tx_hash is nonsense — can't precede
        # itself.  Construct then tamper prev to equal tx_hash.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=b"\x77" * 32,
        )
        tx.prev = tx.tx_hash
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=PREV_POINTER_HEIGHT,
            )
        )

    def test_strict_prev_rejects_dangling(self):
        # prev_lookup returns None for unknown tx_hash — reject.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=b"\x88" * 32,
        )
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=PREV_POINTER_HEIGHT,
                prev_lookup=lambda h: None,
            )
        )

    def test_strict_prev_rejects_forward_reference(self):
        # prev resolves to a block at or after current_height — reject.
        # The referent must precede the current block.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=b"\x99" * 32,
        )
        # Referent at the same height as the applying block.
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=PREV_POINTER_HEIGHT,
                prev_lookup=lambda h: (PREV_POINTER_HEIGHT, 0),
            )
        )

    def test_strict_prev_accepts_prior_block(self):
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=PREV_POINTER_HEIGHT, prev=b"\xaa" * 32,
        )
        self.assertTrue(
            verify_transaction(
                tx, self.pk,
                current_height=PREV_POINTER_HEIGHT,
                prev_lookup=lambda h: (PREV_POINTER_HEIGHT - 1, 0),
            )
        )


class TestPrevPointerDoesNotEatTextBudget(unittest.TestCase):
    """MAX_MESSAGE_CHARS applies only to the human text payload."""

    def setUp(self):
        self.entity = Entity.create(b"budget-seed-padded-out-to-32-bytes!!!")

    def test_max_chars_message_with_prev_accepted(self):
        # A full 1024-char message PLUS a prev pointer is admissible —
        # the cap governs the plaintext, not the on-wire tx.
        max_msg = "a" * MAX_MESSAGE_CHARS
        # Fee must cover 1024 text bytes + 33 prev bytes at Tier 9 rate.
        need = calculate_min_fee(
            max_msg.encode("ascii"),
            current_height=PREV_POINTER_HEIGHT,
            prev_bytes=PREV_POINTER_STORED_BYTES,
        )
        tx = create_transaction(
            self.entity,
            max_msg,
            fee=need,
            nonce=0,
            current_height=PREV_POINTER_HEIGHT,
            prev=b"\xbb" * 32,
        )
        self.assertEqual(len(tx.plaintext), MAX_MESSAGE_CHARS)
        self.assertEqual(tx.prev, b"\xbb" * 32)


class TestTxLocationsIndex(unittest.TestCase):
    """ChainDB's tx_locations index powers O(1) strict-prev resolution."""

    def test_record_and_lookup_roundtrip(self):
        import tempfile
        import os
        from messagechain.storage.chaindb import ChainDB

        tmpdir = tempfile.mkdtemp()
        try:
            db = ChainDB(os.path.join(tmpdir, "test.db"))
            tx_hash = b"\xcc" * 32
            block_hash = b"\xdd" * 32
            db.record_tx_location(tx_hash, block_hash, block_height=42, tx_index=3)
            self.assertEqual(db.get_tx_location(tx_hash), (42, 3))
            # Unknown tx_hash yields None (not an exception).
            self.assertIsNone(db.get_tx_location(b"\xee" * 32))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_lookup_picks_earliest_block_on_duplicate(self):
        # Same tx_hash recorded in two blocks (fork replay) — lookup
        # returns the earliest.
        import tempfile
        import os
        from messagechain.storage.chaindb import ChainDB

        tmpdir = tempfile.mkdtemp()
        try:
            db = ChainDB(os.path.join(tmpdir, "test.db"))
            tx_hash = b"\xff" * 32
            db.record_tx_location(tx_hash, b"\xaa" * 32, block_height=50, tx_index=0)
            db.record_tx_location(tx_hash, b"\xbb" * 32, block_height=10, tx_index=7)
            self.assertEqual(db.get_tx_location(tx_hash), (10, 7))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
