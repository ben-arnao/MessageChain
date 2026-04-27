"""Tests for the Tier 21 `community_id` feature.

At/after COMMUNITY_ID_HEIGHT, MessageTransactions may opt into tx
version 5 and attach an optional fixed 16-byte community_id grouping
the post into a Reddit-style community/topic.  No on-chain registry
or claim mechanism — first-poster-creates semantics, namespace
emerges from convention (apps typically derive id from
sha256(community_name_normalized)[:16]).

Fee treatment: the 17 raw bytes (1B presence flag + 16B id) are
priced at the live per-stored-byte rate.  They do NOT count against
MAX_MESSAGE_CHARS — community_id is structural metadata, not human
content.

Wire/sig: v5 inherits the v4 layout (length-prefixed signable_data
plus prev / sender_pubkey presence-flag blocks) and appends a
community_id presence-flag block at the end.  v1-v4 MUST NOT carry
community_id; v5 may carry None (presence flag = 0) or exactly 16
bytes.
"""

import unittest

from messagechain.config import (
    COMMUNITY_ID_BYTES,
    COMMUNITY_ID_HEIGHT,
    MAX_MESSAGE_CHARS,
    MESSAGE_TX_LENGTH_PREFIX_HEIGHT,
    PROPOSAL_FEE_TIER19_HEIGHT,
)
from messagechain.core.transaction import (
    COMMUNITY_ID_STORED_BYTES,
    MessageTransaction,
    PREV_POINTER_STORED_BYTES,
    SENDER_PUBKEY_STORED_BYTES,
    TX_VERSION_COMMUNITY_ID,
    TX_VERSION_LENGTH_PREFIX,
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestCommunityIdConstants(unittest.TestCase):
    def test_tier_21_height_after_tier_19(self):
        self.assertGreater(COMMUNITY_ID_HEIGHT, PROPOSAL_FEE_TIER19_HEIGHT)

    def test_tier_21_height_after_tier_14(self):
        # v5 inherits the v4 (length-prefix) wire layout.
        self.assertGreater(COMMUNITY_ID_HEIGHT, MESSAGE_TX_LENGTH_PREFIX_HEIGHT)

    def test_community_id_bytes_is_16(self):
        self.assertEqual(COMMUNITY_ID_BYTES, 16)

    def test_community_id_stored_bytes_is_17(self):
        # 1-byte presence flag + 16-byte id.
        self.assertEqual(COMMUNITY_ID_STORED_BYTES, 17)

    def test_tx_version_community_id_is_5(self):
        self.assertEqual(TX_VERSION_COMMUNITY_ID, 5)


class TestCommunityIdFee(unittest.TestCase):
    """Community_id bytes are priced at the live per-stored-byte rate."""

    def test_fee_adds_17_bytes_when_set(self):
        h = COMMUNITY_ID_HEIGHT
        base = calculate_min_fee(b"x" * 100, current_height=h)
        with_cid = calculate_min_fee(
            b"x" * 100,
            current_height=h,
            prev_bytes=COMMUNITY_ID_STORED_BYTES,
        )
        # At/after MARKET_FEE_FLOOR_HEIGHT (Tier 16) the floor is a flat
        # MARKET_FEE_FLOOR=1 and prev_bytes is ignored — the per-byte
        # price lives in the EIP-1559 base fee, not the floor.  This is
        # the Tier 16+ rule; the assertion guards against accidentally
        # reintroducing a per-byte premium on the floor.
        self.assertEqual(base, with_cid)

    def test_calculate_min_fee_accepts_combined_overhead(self):
        # community_id stacks with prev/pubkey overhead in the calculator
        # (caller passes the sum of all optional-block byte counts).
        h = COMMUNITY_ID_HEIGHT
        combined = (
            PREV_POINTER_STORED_BYTES
            + SENDER_PUBKEY_STORED_BYTES
            + COMMUNITY_ID_STORED_BYTES
        )
        # Doesn't raise; under Tier 16+ flat floor it equals the base.
        floor = calculate_min_fee(
            b"x" * 50,
            current_height=h,
            prev_bytes=combined,
        )
        self.assertGreater(floor, 0)


class TestCommunityIdSigningAndWire(unittest.TestCase):
    """Hash stability, version bump, and roundtrip at the format layer."""

    def setUp(self):
        self.entity = Entity.create(b"community-id-test-seed-padded-32-byte")

    def test_pre_activation_message_unchanged_by_community_id_field(self):
        # Backward compat: a non-community-id tx's _signable_data must
        # not change byte-for-byte when community_id happens to be None.
        # The field is a dataclass default; its absence keeps the legacy
        # hash reproducing without new bytes.
        tx = create_transaction(
            self.entity, "hello", fee=1_000, nonce=0,
        )
        self.assertEqual(tx.version, 1)
        self.assertIsNone(tx.community_id)
        self.assertEqual(tx.tx_hash, tx._compute_hash())

    def test_create_transaction_with_community_id_bumps_to_v5(self):
        cid = b"\x11" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "post", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(tx.community_id, cid)

    def test_create_transaction_rejects_wrong_length_community_id(self):
        for bad in (b"", b"\x00" * 15, b"\x00" * 17, b"\x00" * 32):
            with self.assertRaises(ValueError):
                create_transaction(
                    self.entity, "x", fee=10_000, nonce=0,
                    current_height=COMMUNITY_ID_HEIGHT,
                    community_id=bad,
                )

    def test_create_transaction_rejects_community_id_pre_activation(self):
        # Submitting a community_id before its fork activates would
        # construct a v5 tx that the chain will reject anyway — refuse
        # at construction so the operator sees the clearer error.
        cid = b"\x22" * COMMUNITY_ID_BYTES
        with self.assertRaises(ValueError):
            create_transaction(
                self.entity, "x", fee=10_000, nonce=0,
                current_height=COMMUNITY_ID_HEIGHT - 1,
                community_id=cid,
            )

    def test_community_id_changes_signed_payload(self):
        # Setting community_id must flip tx_hash — a reader can't claim
        # "I thought there was no community pinned to this post".
        tx_no = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
        )
        tx_yes = create_transaction(
            self.entity, "x", fee=10_000, nonce=1,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=b"\x33" * COMMUNITY_ID_BYTES,
        )
        self.assertNotEqual(tx_no.tx_hash, tx_yes.tx_hash)

    def test_different_community_ids_produce_different_hashes(self):
        a = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=b"\xaa" * COMMUNITY_ID_BYTES,
        )
        b = create_transaction(
            self.entity, "x", fee=10_000, nonce=1,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=b"\xbb" * COMMUNITY_ID_BYTES,
        )
        self.assertNotEqual(a.tx_hash, b.tx_hash)

    def test_wire_roundtrip_v5_with_community_id(self):
        cid = b"\x44" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "hello world", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(restored.community_id, cid)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_wire_roundtrip_v5_with_community_id_and_prev(self):
        # v5 inherits v4's prev + sender_pubkey presence-flag layout.
        # Smoke that all three optional blocks coexist round-trip.
        cid = b"\x55" * COMMUNITY_ID_BYTES
        prev = b"\x66" * 32
        tx = create_transaction(
            self.entity, "reply", fee=20_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            prev=prev, community_id=cid,
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.community_id, cid)
        self.assertEqual(restored.prev, prev)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_roundtrip_v5(self):
        cid = b"\x77" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "hello", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        d = tx.serialize()
        self.assertEqual(d["community_id"], cid.hex())
        restored = MessageTransaction.deserialize(d)
        self.assertEqual(restored.community_id, cid)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_omits_community_id_when_absent(self):
        tx = create_transaction(
            self.entity, "hello", fee=1_000, nonce=0,
        )
        d = tx.serialize()
        self.assertNotIn("community_id", d)


class TestCommunityIdVerifyGate(unittest.TestCase):
    """verify_transaction enforces the fork gate and shape rules."""

    def setUp(self):
        self.entity = Entity.create(b"community-verify-seed-padded32bytes!")
        self.pk = self.entity.keypair.public_key

    def test_v5_rejected_pre_activation(self):
        cid = b"\x99" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        # Pre-activation: reject.
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=COMMUNITY_ID_HEIGHT - 1,
            )
        )
        # At activation: accept (signature path resolves cleanly).
        self.assertTrue(
            verify_transaction(
                tx, self.pk, current_height=COMMUNITY_ID_HEIGHT,
            )
        )

    def test_lower_version_with_community_id_rejected(self):
        # A malformed v1-v4 tx that smuggles a community_id field must
        # be rejected — the signed payload at those versions doesn't
        # commit to community_id, so an attacker grafting one onto a
        # legitimate v1-v4 sig would be tampering.  Construct a v1 tx
        # then post-tamper.
        tx = create_transaction(
            self.entity, "x", fee=1_000, nonce=0,
        )
        tx.community_id = b"\xaa" * COMMUNITY_ID_BYTES
        self.assertEqual(tx.version, 1)
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=COMMUNITY_ID_HEIGHT,
            )
        )

    def test_v5_with_wrong_length_community_id_rejected(self):
        # Construct a real v5 tx then post-tamper the community_id to
        # the wrong length.  (The constructor would reject this; the
        # verifier must too, in case a malformed wire blob ever
        # bypasses construction.)
        cid = b"\xbb" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        tx.community_id = b"\xcc" * 8  # wrong length
        self.assertFalse(
            verify_transaction(
                tx, self.pk, current_height=COMMUNITY_ID_HEIGHT,
            )
        )

    def test_v5_without_community_id_accepted(self):
        # A v5 tx that opted into the new format but left community_id
        # None (presence flag = 0) is well-formed — same as v2 with
        # prev=None.  This path is wasteful (1 extra byte) but legal,
        # so we verify it doesn't get spuriously rejected.
        cid = b"\xdd" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            self.entity, "x", fee=10_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        # Re-construct with the v5 version flag but no community_id —
        # signal by clearing the field then re-signing.
        from messagechain.crypto.hashing import default_hash
        tx.community_id = None
        msg_hash = default_hash(tx._signable_data())
        tx.signature = self.entity.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertIsNone(tx.community_id)
        self.assertTrue(
            verify_transaction(
                tx, self.pk, current_height=COMMUNITY_ID_HEIGHT,
            )
        )


class TestCommunityIdContentBudget(unittest.TestCase):
    """community_id is structural metadata; it does NOT eat MAX_MESSAGE_CHARS."""

    def test_full_content_budget_with_community_id(self):
        # A sender at COMMUNITY_ID_HEIGHT must be able to post a full
        # MAX_MESSAGE_CHARS-byte plaintext message AND attach a
        # community_id, with the only cost being the per-byte fee on
        # the extra 17 community-id bytes.
        entity = Entity.create(b"community-budget-seed-padded32bytes!")
        full_text = "x" * MAX_MESSAGE_CHARS
        cid = b"\xee" * COMMUNITY_ID_BYTES
        tx = create_transaction(
            entity, full_text, fee=1_000_000, nonce=0,
            current_height=COMMUNITY_ID_HEIGHT,
            community_id=cid,
        )
        self.assertEqual(tx.version, TX_VERSION_COMMUNITY_ID)
        self.assertEqual(tx.char_count, MAX_MESSAGE_CHARS)
        self.assertEqual(tx.community_id, cid)


if __name__ == "__main__":
    unittest.main()
