"""Tests for the Tier 25 `community_id` feature (ASCII handle form).

At/after COMMUNITY_ID_HEIGHT, MessageTransactions may opt into tx
version 5 and attach an optional short ASCII handle grouping the
post into a Reddit-style community/topic.  No on-chain registry,
no claim mechanism, no entity owns a community — first-poster-
creates semantics for spelling, with the (handle → display name /
description) mapping living at L2/app layer.

Handle rule (anchored — see config.MAX_COMMUNITY_ID_LEN comment):
    * ASCII bytes only.
    * Charset [a-z0-9_-].
    * Length 1..MAX_COMMUNITY_ID_LEN bytes.
    * First and last byte in [a-z0-9] (no leading/trailing punctuation).

Wire form: 1B presence flag + (when set) 1B length + N ASCII bytes.
Excluded from MAX_MESSAGE_CHARS; counted toward stored bytes for the
per-stored-byte fee floor and proposer fee-per-byte ranking.
"""

import unittest

from messagechain.config import (
    COMMUNITY_ID_HEIGHT,
    MAX_COMMUNITY_ID_LEN,
    MAX_MESSAGE_CHARS,
    MESSAGE_TX_LENGTH_PREFIX_HEIGHT,
    PROPOSAL_FEE_TIER19_HEIGHT,
)
from messagechain.core.transaction import (
    MAX_COMMUNITY_ID_STORED_BYTES,
    MessageTransaction,
    PREV_POINTER_STORED_BYTES,
    SENDER_PUBKEY_STORED_BYTES,
    TX_VERSION_COMMUNITY_ID,
    TX_VERSION_LENGTH_PREFIX,
    _community_id_stored_bytes,
    _validate_community_id,
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestCommunityIdConstants(unittest.TestCase):
    def test_tier_25_height_after_tier_19(self):
        self.assertGreater(COMMUNITY_ID_HEIGHT, PROPOSAL_FEE_TIER19_HEIGHT)

    def test_tier_25_height_after_tier_14(self):
        # v5 inherits the v4 (length-prefix) wire layout.
        self.assertGreater(COMMUNITY_ID_HEIGHT, MESSAGE_TX_LENGTH_PREFIX_HEIGHT)

    def test_max_community_id_len_is_32(self):
        self.assertEqual(MAX_COMMUNITY_ID_LEN, 32)

    def test_max_stored_bytes_matches_formula(self):
        # 1B presence flag + 1B length + MAX_COMMUNITY_ID_LEN bytes.
        self.assertEqual(
            MAX_COMMUNITY_ID_STORED_BYTES, 2 + MAX_COMMUNITY_ID_LEN
        )

    def test_tx_version_community_id_is_5(self):
        self.assertEqual(TX_VERSION_COMMUNITY_ID, 5)


class TestValidateCommunityId(unittest.TestCase):
    """The handle validator is the single source of truth for charset,
    length, and edge-byte rules; both create_transaction and
    verify_transaction call it.  Direct tests pin every reject path."""

    def test_accepts_minimal_handle(self):
        ok, _ = _validate_community_id("a")
        self.assertTrue(ok)

    def test_accepts_typical_handles(self):
        for h in ("art", "messagechain", "r-art", "art_2026", "z9"):
            ok, reason = _validate_community_id(h)
            self.assertTrue(ok, f"{h!r}: {reason}")

    def test_accepts_max_length_handle(self):
        ok, _ = _validate_community_id("a" * MAX_COMMUNITY_ID_LEN)
        self.assertTrue(ok)

    def test_rejects_empty(self):
        ok, _ = _validate_community_id("")
        self.assertFalse(ok)

    def test_rejects_too_long(self):
        ok, _ = _validate_community_id("a" * (MAX_COMMUNITY_ID_LEN + 1))
        self.assertFalse(ok)

    def test_rejects_uppercase(self):
        # Case-insensitivity by construction — no "Art" / "art" fragmentation.
        for h in ("Art", "ART", "aRt"):
            ok, _ = _validate_community_id(h)
            self.assertFalse(ok, f"{h!r} should be rejected")

    def test_rejects_whitespace(self):
        for h in (" art", "art ", "ar t", "art\n", "\tart"):
            ok, _ = _validate_community_id(h)
            self.assertFalse(ok, f"{h!r} should be rejected")

    def test_rejects_non_ascii(self):
        # Homoglyph case: Cyrillic 'а' (U+0430) looks like Latin 'a' but
        # is a distinct codepoint.  The whole point of strict ASCII is
        # to make this attack impossible at the protocol level.
        for h in ("аrt", "café", "art‍", "中文"):
            ok, _ = _validate_community_id(h)
            self.assertFalse(ok, f"{h!r} should be rejected")

    def test_rejects_special_chars(self):
        for h in ("art!", "r/art", "a.b", "a@b", "a#b", "a+b", "a=b"):
            ok, _ = _validate_community_id(h)
            self.assertFalse(ok, f"{h!r} should be rejected")

    def test_rejects_leading_or_trailing_hyphen(self):
        # DNS-label rule — prevents `art` / `-art` / `art-` fragmentation.
        for h in ("-art", "art-", "-art-", "_art", "art_", "_a_"):
            ok, _ = _validate_community_id(h)
            self.assertFalse(ok, f"{h!r} should be rejected")

    def test_accepts_internal_hyphen_and_underscore(self):
        for h in ("a-b", "a_b", "art-2026", "msg_chain", "a-b_c-d"):
            ok, _ = _validate_community_id(h)
            self.assertTrue(ok, f"{h!r} should be accepted")

    def test_rejects_non_str_input(self):
        for bad in (b"art", 123, None, ["art"]):
            ok, _ = _validate_community_id(bad)
            self.assertFalse(ok)


class TestCommunityIdFee(unittest.TestCase):
    """Community_id bytes are priced at the live per-stored-byte rate.
    Length is variable, so callers compute overhead per-tx; the helper
    `_community_id_stored_bytes(handle, version)` returns the exact cost."""

    def test_overhead_helper_pre_v5(self):
        for v in (1, 2, 3, 4):
            self.assertEqual(_community_id_stored_bytes("art", v), 0)
            self.assertEqual(_community_id_stored_bytes(None, v), 0)

    def test_overhead_helper_v5_none(self):
        # v5 with no community_id still pays the 1-byte presence flag.
        self.assertEqual(
            _community_id_stored_bytes(None, TX_VERSION_COMMUNITY_ID), 1
        )

    def test_overhead_helper_v5_set(self):
        # 1B presence flag + 1B length + N handle bytes.
        for handle, expected in (("a", 3), ("art", 5), ("messagechain", 14)):
            self.assertEqual(
                _community_id_stored_bytes(handle, TX_VERSION_COMMUNITY_ID),
                expected,
            )

    def test_calculate_min_fee_accepts_combined_overhead(self):
        # Stacks with prev/pubkey overhead in the calculator.
        h = COMMUNITY_ID_HEIGHT
        combined = (
            PREV_POINTER_STORED_BYTES
            + SENDER_PUBKEY_STORED_BYTES
            + MAX_COMMUNITY_ID_STORED_BYTES
        )
        floor = calculate_min_fee(
            b"x" * 50,
            current_height=h,
            prev_bytes=combined,
        )
        self.assertGreater(floor, 0)


class TestCommunityIdSigningAndWire(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"community-id-handle-seed-padded-32b!")

    def test_pre_activation_message_unchanged_by_field(self):
        # Backward compat: a non-community-id tx's _signable_data must
        # not change byte-for-byte when community_id happens to be None.
        tx = create_transaction(self.entity, "hello", fee=1_000, nonce=0)
        self.assertEqual(tx.version, 1)
        self.assertIsNone(tx.community_id)
        self.assertEqual(tx.tx_hash, tx._compute_hash())

    def test_create_with_community_id_bumps_to_v5(self):
        tx = create_transaction(
            self.entity, "post", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(tx.community_id, "art")

    def test_create_rejects_invalid_community_id(self):
        for bad in ("", "Art", "-art", "art ", "аrt", "a" * 33, "r/art"):
            with self.assertRaises(ValueError, msg=f"expected reject of {bad!r}"):
                create_transaction(
                    self.entity, "x", fee=10_000, nonce=0,
                    current_height=COMMUNITY_ID_HEIGHT, community_id=bad,
                )

    def test_create_rejects_community_id_pre_activation(self):
        with self.assertRaises(ValueError):
            create_transaction(
                self.entity, "x", fee=10_000, nonce=0,
                current_height=COMMUNITY_ID_HEIGHT - 1,
                community_id="art",
            )

    def test_setting_community_id_changes_signed_payload(self):
        tx_no = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
        )
        tx_yes = create_transaction(
            self.entity, "x", fee=10_000, nonce=1,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        self.assertNotEqual(tx_no.tx_hash, tx_yes.tx_hash)

    def test_different_community_ids_produce_different_hashes(self):
        a = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        b = create_transaction(
            self.entity, "x", fee=10_000, nonce=1,
            current_height=COMMUNITY_ID_HEIGHT, community_id="music",
        )
        self.assertNotEqual(a.tx_hash, b.tx_hash)

    def test_wire_roundtrip_v5_short_handle(self):
        tx = create_transaction(
            self.entity, "hello world", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(restored.community_id, "art")
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_wire_roundtrip_v5_max_length_handle(self):
        max_handle = "a" * MAX_COMMUNITY_ID_LEN
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id=max_handle,
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.community_id, max_handle)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_wire_roundtrip_v5_with_prev_and_community_id(self):
        prev = b"\x66" * 32
        tx = create_transaction(
            self.entity, "reply", fee=20_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            prev=prev, community_id="messagechain",
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.community_id, "messagechain")
        self.assertEqual(restored.prev, prev)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_roundtrip_v5(self):
        tx = create_transaction(
            self.entity, "hello", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        d = tx.serialize()
        # Emitted as plain string, not hex.
        self.assertEqual(d["community_id"], "art")
        restored = MessageTransaction.deserialize(d)
        self.assertEqual(restored.community_id, "art")
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_omits_community_id_when_absent(self):
        tx = create_transaction(self.entity, "hello", fee=1_000, nonce=0)
        d = tx.serialize()
        self.assertNotIn("community_id", d)


class TestCommunityIdVerifyGate(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"community-verify-seed-padded32bytesS")
        self.pk = self.entity.keypair.public_key

    def test_v5_rejected_pre_activation(self):
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=COMMUNITY_ID_HEIGHT - 1)
        )
        self.assertTrue(
            verify_transaction(tx, self.pk, current_height=COMMUNITY_ID_HEIGHT)
        )

    def test_lower_version_with_community_id_rejected(self):
        # A v1 tx that smuggles a community_id field via post-tampering
        # must be rejected — sub-v5 doesn't sign over the field, so
        # grafting it would be a tampering attempt.
        tx = create_transaction(self.entity, "x", fee=1_000, nonce=0)
        tx.community_id = "art"
        self.assertEqual(tx.version, 1)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=COMMUNITY_ID_HEIGHT)
        )

    def test_v5_with_invalid_handle_rejected(self):
        # Construct a real v5 then post-tamper to an invalid handle.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        for bad in ("", "Art", "-art", "art ", "аrt", "a" * 33):
            tx.community_id = bad
            self.assertFalse(
                verify_transaction(
                    tx, self.pk, current_height=COMMUNITY_ID_HEIGHT
                ),
                f"verify should reject post-tampered community_id={bad!r}",
            )

    def test_v5_without_community_id_accepted(self):
        # A v5 tx with community_id=None (presence flag = 0) is wasteful
        # but legal.  Verify path must accept it.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        from messagechain.crypto.hashing import default_hash
        tx.community_id = None
        msg_hash = default_hash(tx._signable_data())
        tx.signature = self.entity.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertIsNone(tx.community_id)
        self.assertTrue(
            verify_transaction(tx, self.pk, current_height=COMMUNITY_ID_HEIGHT)
        )


class TestCommunityIdContentBudget(unittest.TestCase):
    """community_id is structural metadata; it does NOT eat MAX_MESSAGE_CHARS."""

    def test_full_content_budget_with_max_handle(self):
        entity = Entity.create(b"community-budget-seed-padded32bytes!")
        full_text = "x" * MAX_MESSAGE_CHARS
        max_handle = "a" * MAX_COMMUNITY_ID_LEN
        tx = create_transaction(
            entity, full_text, fee=1_000_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id=max_handle,
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(tx.char_count, MAX_MESSAGE_CHARS)
        self.assertEqual(tx.community_id, max_handle)


class TestCommunityIdWireMalformed(unittest.TestCase):
    """from_bytes rejects structurally malformed v5 community_id blobs.

    Locates the cid block by forward-parsing the wire layout (the
    block sits between sender_pubkey and the trailing sig_len /
    sig_blob / tx_hash).  Helper avoids hard-coding offsets that
    move whenever the layout changes upstream.
    """

    def setUp(self):
        self.entity = Entity.create(b"community-malformed-seed-padded32by!")

    def _v5_blob_with_handle(self, handle: str) -> bytes:
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id=handle,
        )
        # Force the legacy 32-byte entity_ref form by passing state=None
        # so _cid_offset's parse stays on the well-known path.
        return tx.to_bytes(state=None)

    def _cid_offset(self, blob: bytes) -> int:
        """Return the byte offset of the cid presence flag in `blob`.

        Mirrors the relevant prefix of MessageTransaction.from_bytes
        (only the parts before the cid block) so the test is robust
        to layout shifts elsewhere in the blob.
        """
        import struct
        offset = 0
        offset += 1  # ser_version
        offset += 4  # tx version
        # entity_ref: state=None forces the 1B tag (0x00) + 32B id form.
        tag = blob[offset]
        self.assertEqual(tag, 0x00, "test requires legacy 32B entity_ref")
        offset += 1 + 32
        offset += 1  # compression_flag
        msg_len = struct.unpack_from(">H", blob, offset)[0]
        offset += 2 + msg_len
        offset += 8 + 8 + 8  # timestamp, nonce, fee
        # prev block: presence flag + optional 32B.
        offset += 33 if blob[offset] == 0x01 else 1
        # sender_pubkey block: same shape.
        offset += 33 if blob[offset] == 0x01 else 1
        return offset  # cid presence flag lives here

    def test_v5_no_cid_roundtrips(self):
        # Sanity baseline: a v5 tx whose cid was cleared post-construction
        # round-trips cleanly with presence flag = 0.
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT, community_id="art",
        )
        from messagechain.crypto.hashing import default_hash
        tx.community_id = None
        msg_hash = default_hash(tx._signable_data())
        tx.signature = self.entity.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()
        blob = tx.to_bytes(state=None)
        self.assertIsNone(MessageTransaction.from_bytes(blob).community_id)

    def test_length_zero_rejected_at_parse(self):
        blob = bytearray(self._v5_blob_with_handle("a"))
        cid_off = self._cid_offset(blob)
        self.assertEqual(blob[cid_off], 0x01)      # presence=1
        self.assertEqual(blob[cid_off + 1], 0x01)  # length=1
        self.assertEqual(blob[cid_off + 2], 0x61)  # 'a'
        blob[cid_off + 1] = 0x00  # corrupt length to 0
        with self.assertRaises(ValueError):
            MessageTransaction.from_bytes(bytes(blob))

    def test_length_too_large_rejected_at_parse(self):
        blob = bytearray(self._v5_blob_with_handle("a"))
        cid_off = self._cid_offset(blob)
        blob[cid_off + 1] = MAX_COMMUNITY_ID_LEN + 1
        with self.assertRaises(ValueError):
            MessageTransaction.from_bytes(bytes(blob))

    def test_bad_presence_flag_rejected_at_parse(self):
        blob = bytearray(self._v5_blob_with_handle("a"))
        cid_off = self._cid_offset(blob)
        blob[cid_off] = 0x02  # not 0 or 1
        with self.assertRaises(ValueError):
            MessageTransaction.from_bytes(bytes(blob))


if __name__ == "__main__":
    unittest.main()
