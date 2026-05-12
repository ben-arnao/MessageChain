"""Tests for the Tier 72 poll + vote feature (TX_VERSION_POLL).

At/after POLL_HEIGHT, MessageTransactions may opt into tx version 6
and attach EITHER an optional ``poll_options`` field (poll-creating
mode) OR an optional ``vote_target`` field (vote-casting mode).
Mutually exclusive; a single tx is never both.

Poll option rule (anchored — see config.POLL_HEIGHT comment block):
    * 1..MAX_POLL_OPTIONS options.
    * Each option is non-empty NFC UTF-8 passing the Tier 12
      L/M/N/P/Zs whitelist (same charset as message body).
    * Each option fits in MAX_POLL_OPTION_BYTES UTF-8 bytes.
    * Options are pairwise distinct.

Vote rule:
    * vote_target is (poll_txid: bytes32, option_index: int).
    * option_index in [0, MAX_POLL_OPTIONS) structurally; refined to
      [0, len(target_poll.options)) by the chain-level poll_lookup.
    * Vote references a poll in a strictly EARLIER block.
    * Self-reference (poll_txid == tx.tx_hash) is rejected.
    * Voter is NOT the poll's author (no self-vote on own poll).
    * One vote per (entity, poll) at consensus — second vote from
      same entity on same poll is rejected at admission.  First
      vote is binding forever.
"""

import unittest

from messagechain.config import (
    POLL_HEIGHT,
    MAX_POLL_OPTIONS,
    MAX_POLL_OPTION_BYTES,
    COMMUNITY_ID_HEIGHT,
    MESSAGE_TX_LENGTH_PREFIX_HEIGHT,
    MAX_MESSAGE_CHARS,
)
from messagechain.core.transaction import (
    MessageTransaction,
    TX_VERSION_POLL,
    TX_VERSION_COMMUNITY_ID,
    VOTE_TARGET_STORED_BYTES,
    _poll_options_stored_bytes,
    _vote_target_stored_bytes,
    _validate_poll_options,
    _validate_vote_target,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


# ─── Constants ─────────────────────────────────────────────────────────


class TestPollConstants(unittest.TestCase):
    def test_tx_version_poll_is_6(self):
        self.assertEqual(TX_VERSION_POLL, 6)

    def test_poll_height_after_community_id(self):
        self.assertGreater(POLL_HEIGHT, COMMUNITY_ID_HEIGHT)

    def test_poll_height_after_length_prefix(self):
        # v6 inherits the v5 (length-prefix + community_id) layout.
        self.assertGreater(POLL_HEIGHT, MESSAGE_TX_LENGTH_PREFIX_HEIGHT)

    def test_max_poll_options_is_4(self):
        self.assertEqual(MAX_POLL_OPTIONS, 4)

    def test_max_poll_option_bytes_positive(self):
        self.assertGreaterEqual(MAX_POLL_OPTION_BYTES, 1)
        self.assertLessEqual(MAX_POLL_OPTION_BYTES, 64)

    def test_vote_target_stored_bytes_formula(self):
        # 1B presence flag + 32B poll_txid + 1B option_index.
        self.assertEqual(VOTE_TARGET_STORED_BYTES, 34)


# ─── _validate_poll_options direct ─────────────────────────────────────


class TestValidatePollOptions(unittest.TestCase):
    def test_accepts_two_short_options(self):
        ok, _ = _validate_poll_options(("Yes", "No"))
        self.assertTrue(ok)

    def test_accepts_one_option(self):
        # 1 is the minimum — a 1-option "poll" is wasteful but legal.
        ok, _ = _validate_poll_options(("Only",))
        self.assertTrue(ok)

    def test_accepts_max_options(self):
        ok, _ = _validate_poll_options(tuple(f"opt{i}" for i in range(MAX_POLL_OPTIONS)))
        self.assertTrue(ok)

    def test_rejects_empty(self):
        ok, _ = _validate_poll_options(())
        self.assertFalse(ok)

    def test_rejects_too_many(self):
        ok, _ = _validate_poll_options(
            tuple(f"opt{i}" for i in range(MAX_POLL_OPTIONS + 1))
        )
        self.assertFalse(ok)

    def test_rejects_empty_option_string(self):
        ok, _ = _validate_poll_options(("Yes", ""))
        self.assertFalse(ok)

    def test_rejects_oversized_option(self):
        ok, _ = _validate_poll_options(("Yes", "a" * (MAX_POLL_OPTION_BYTES + 1)))
        self.assertFalse(ok)

    def test_rejects_duplicate_options(self):
        ok, _ = _validate_poll_options(("Yes", "No", "Yes"))
        self.assertFalse(ok)

    def test_rejects_non_tuple(self):
        ok, _ = _validate_poll_options(["Yes", "No"])
        self.assertFalse(ok)

    def test_rejects_non_str_element(self):
        ok, _ = _validate_poll_options(("Yes", 1))
        self.assertFalse(ok)

    def test_rejects_bidi_override(self):
        # Tier 12 bidi-override blocklist must apply to option text too.
        ok, _ = _validate_poll_options(("Yes", "No‮"))
        self.assertFalse(ok)

    def test_rejects_emoji(self):
        # Tier 12 symbol-category reject (emoji is S*); option text
        # follows the same whitelist as message body.
        ok, _ = _validate_poll_options(("Yes", "👍"))
        self.assertFalse(ok)


# ─── _validate_vote_target direct ──────────────────────────────────────


class TestValidateVoteTarget(unittest.TestCase):
    def test_accepts_valid(self):
        ok, _ = _validate_vote_target((b"\x00" * 32, 0))
        self.assertTrue(ok)

    def test_accepts_max_index(self):
        ok, _ = _validate_vote_target((b"\x00" * 32, MAX_POLL_OPTIONS - 1))
        self.assertTrue(ok)

    def test_rejects_short_txid(self):
        ok, _ = _validate_vote_target((b"\x00" * 31, 0))
        self.assertFalse(ok)

    def test_rejects_long_txid(self):
        ok, _ = _validate_vote_target((b"\x00" * 33, 0))
        self.assertFalse(ok)

    def test_rejects_negative_index(self):
        ok, _ = _validate_vote_target((b"\x00" * 32, -1))
        self.assertFalse(ok)

    def test_rejects_out_of_range_index(self):
        ok, _ = _validate_vote_target((b"\x00" * 32, MAX_POLL_OPTIONS))
        self.assertFalse(ok)

    def test_rejects_non_tuple(self):
        ok, _ = _validate_vote_target([b"\x00" * 32, 0])
        self.assertFalse(ok)

    def test_rejects_wrong_arity(self):
        ok, _ = _validate_vote_target((b"\x00" * 32,))
        self.assertFalse(ok)


# ─── Stored-byte accounting ────────────────────────────────────────────


class TestPollStoredBytes(unittest.TestCase):
    def test_poll_overhead_pre_v6_is_zero(self):
        for v in (1, 2, 3, 4, 5):
            self.assertEqual(
                _poll_options_stored_bytes(("Yes", "No"), v), 0
            )
            self.assertEqual(_poll_options_stored_bytes(None, v), 0)

    def test_poll_overhead_v6_none(self):
        self.assertEqual(_poll_options_stored_bytes(None, TX_VERSION_POLL), 1)

    def test_poll_overhead_v6_set(self):
        # 1B flag + 1B count + per-opt [1B len + N UTF-8 bytes].
        # ("Yes", "No") → 1 + 1 + (1+3) + (1+2) = 9
        self.assertEqual(
            _poll_options_stored_bytes(("Yes", "No"), TX_VERSION_POLL), 9
        )

    def test_vote_overhead_pre_v6_is_zero(self):
        for v in (1, 2, 3, 4, 5):
            self.assertEqual(
                _vote_target_stored_bytes((b"\x00" * 32, 0), v), 0
            )

    def test_vote_overhead_v6_none(self):
        self.assertEqual(_vote_target_stored_bytes(None, TX_VERSION_POLL), 1)

    def test_vote_overhead_v6_set(self):
        self.assertEqual(
            _vote_target_stored_bytes((b"\x00" * 32, 0), TX_VERSION_POLL),
            VOTE_TARGET_STORED_BYTES,
        )


# ─── create_transaction: poll-creating mode ────────────────────────────


class TestCreatePoll(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"poll-create-seed-padded-32-bytes!1")

    def test_create_poll_bumps_to_v6(self):
        tx = create_transaction(
            self.entity, "What's your favorite color?", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("Red", "Blue", "Green"),
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertEqual(tx.poll_options, ("Red", "Blue", "Green"))
        self.assertIsNone(tx.vote_target)

    def test_create_poll_rejects_pre_activation(self):
        with self.assertRaises(ValueError):
            create_transaction(
                self.entity, "x", fee=100_000, nonce=0,
                current_height=POLL_HEIGHT - 1,
                poll_options=("Yes", "No"),
            )

    def test_create_poll_rejects_invalid_options(self):
        for bad in (
            (),                               # empty
            ("a" * (MAX_POLL_OPTION_BYTES + 1),),  # too long
            ("Yes", "Yes"),                   # duplicate
            tuple(f"opt{i}" for i in range(MAX_POLL_OPTIONS + 1)),  # too many
            ("Yes", ""),                      # empty option
        ):
            with self.assertRaises(ValueError, msg=f"expected reject of {bad!r}"):
                create_transaction(
                    self.entity, "x", fee=100_000, nonce=0,
                    current_height=POLL_HEIGHT,
                    poll_options=bad,
                )

    def test_setting_poll_changes_signed_payload(self):
        tx_no = create_transaction(
            self.entity, "x", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
        )
        tx_yes = create_transaction(
            self.entity, "x", fee=100_000, nonce=1,
            current_height=POLL_HEIGHT,
            poll_options=("Yes", "No"),
        )
        self.assertNotEqual(tx_no.tx_hash, tx_yes.tx_hash)

    def test_different_options_produce_different_hashes(self):
        a = create_transaction(
            self.entity, "x", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT, poll_options=("Yes", "No"),
        )
        b = create_transaction(
            self.entity, "x", fee=100_000, nonce=1,
            current_height=POLL_HEIGHT, poll_options=("No", "Yes"),
        )
        self.assertNotEqual(a.tx_hash, b.tx_hash)


# ─── create_transaction: vote-casting mode ─────────────────────────────


class TestCreateVote(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"poll-vote-create-seed-padded-32by!")

    def test_create_vote_bumps_to_v6(self):
        tx = create_transaction(
            self.entity, "", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            vote_target=(b"\x11" * 32, 1),
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertEqual(tx.vote_target, (b"\x11" * 32, 1))
        self.assertIsNone(tx.poll_options)

    def test_create_vote_rejects_pre_activation(self):
        with self.assertRaises(ValueError):
            create_transaction(
                self.entity, "", fee=100_000, nonce=0,
                current_height=POLL_HEIGHT - 1,
                vote_target=(b"\x11" * 32, 0),
            )

    def test_create_vote_rejects_invalid_target(self):
        for bad in (
            (b"\x00" * 31, 0),                 # short txid
            (b"\x00" * 32, -1),                # negative index
            (b"\x00" * 32, MAX_POLL_OPTIONS),  # out-of-range index
        ):
            with self.assertRaises(ValueError, msg=f"expected reject of {bad!r}"):
                create_transaction(
                    self.entity, "", fee=100_000, nonce=0,
                    current_height=POLL_HEIGHT,
                    vote_target=bad,
                )


# ─── Mutual exclusivity ────────────────────────────────────────────────


class TestPollVoteMutex(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"poll-mutex-seed-padded-32-bytes!ab")

    def test_create_rejects_both_poll_and_vote(self):
        with self.assertRaises(ValueError):
            create_transaction(
                self.entity, "x", fee=100_000, nonce=0,
                current_height=POLL_HEIGHT,
                poll_options=("Yes", "No"),
                vote_target=(b"\x11" * 32, 0),
            )


# ─── Wire format round-trip ────────────────────────────────────────────


class TestPollWireRoundtrip(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"poll-wire-rt-seed-padded-32-byte!1")

    def test_to_from_bytes_poll(self):
        tx = create_transaction(
            self.entity, "Pick one", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("Yes", "No", "Maybe", "Skip"),
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, TX_VERSION_POLL)
        self.assertEqual(restored.poll_options, ("Yes", "No", "Maybe", "Skip"))
        self.assertIsNone(restored.vote_target)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_to_from_bytes_vote(self):
        tx = create_transaction(
            self.entity, "voting", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            vote_target=(b"\xab" * 32, 2),
        )
        blob = tx.to_bytes()
        restored = MessageTransaction.from_bytes(blob)
        self.assertEqual(restored.version, TX_VERSION_POLL)
        self.assertEqual(restored.vote_target, (b"\xab" * 32, 2))
        self.assertIsNone(restored.poll_options)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_to_from_bytes_neither(self):
        # A v6 tx with neither poll nor vote rides at v5's footprint
        # for the trailers; verify_transaction still accepts it.
        # We force v6 here only via create_transaction passing both
        # None at a height past POLL_HEIGHT — the create path won't
        # auto-bump, so we test the v6 layout via post-tampering
        # below.  Skip this test as a placeholder for symmetry.
        pass

    def test_dict_roundtrip_poll(self):
        tx = create_transaction(
            self.entity, "Pick", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("A", "B"),
        )
        d = tx.serialize()
        self.assertEqual(d["poll_options"], ["A", "B"])
        self.assertNotIn("vote_target", d)
        restored = MessageTransaction.deserialize(d)
        self.assertEqual(restored.poll_options, ("A", "B"))
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_roundtrip_vote(self):
        tx = create_transaction(
            self.entity, "voting", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            vote_target=(b"\xcd" * 32, 3),
        )
        d = tx.serialize()
        self.assertNotIn("poll_options", d)
        self.assertEqual(d["vote_target"]["poll_txid"], "cd" * 32)
        self.assertEqual(d["vote_target"]["option_index"], 3)
        restored = MessageTransaction.deserialize(d)
        self.assertEqual(restored.vote_target, (b"\xcd" * 32, 3))
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_dict_omits_poll_fields_when_absent(self):
        tx = create_transaction(self.entity, "hello", fee=1_000, nonce=0)
        d = tx.serialize()
        self.assertNotIn("poll_options", d)
        self.assertNotIn("vote_target", d)


# ─── verify_transaction: version gates and tampering ───────────────────


class TestPollVerifyGate(unittest.TestCase):
    def setUp(self):
        self.entity = Entity.create(b"poll-verify-seed-padded-32-bytes!1")
        self.pk = self.entity.keypair.public_key

    def test_v6_rejected_pre_activation(self):
        tx = create_transaction(
            self.entity, "Pick", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("Yes", "No"),
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT - 1)
        )
        self.assertTrue(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_lower_version_with_poll_options_rejected(self):
        # A v1 tx that smuggles poll_options via post-tampering must
        # be rejected — sub-v6 doesn't sign over the field.
        tx = create_transaction(self.entity, "x", fee=1_000, nonce=0)
        tx.poll_options = ("Yes", "No")
        self.assertEqual(tx.version, 1)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_lower_version_with_vote_target_rejected(self):
        tx = create_transaction(self.entity, "x", fee=1_000, nonce=0)
        tx.vote_target = (b"\x11" * 32, 0)
        self.assertEqual(tx.version, 1)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_v6_with_invalid_options_rejected(self):
        # Construct a real v6 poll, then post-tamper to invalid options.
        tx = create_transaction(
            self.entity, "x", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("Yes", "No"),
        )
        tx.poll_options = ("Yes", "Yes")  # duplicate
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_v6_with_both_fields_rejected(self):
        # Real v6 poll, post-tamper to also set vote_target → mutex reject.
        tx = create_transaction(
            self.entity, "x", fee=100_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=("Yes", "No"),
        )
        tx.vote_target = (b"\x11" * 32, 0)
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )


# ─── verify_transaction: chain-level poll_lookup ───────────────────────


class TestPollLookupChainGate(unittest.TestCase):
    """The chain-level poll_lookup resolves vote→poll references.

    Without poll_lookup, vote is treated as structurally valid but
    unresolved (so isolated unit tests keep working).  With one, a
    vote MUST resolve to a confirmed poll in a strictly earlier block
    AND the option_index must be within that poll's option count.
    """

    def setUp(self):
        self.entity = Entity.create(b"poll-lookup-seed-padded-32-byte!12")
        self.pk = self.entity.keypair.public_key

    def _make_vote(self, target_txid: bytes, option_index: int, nonce: int = 0):
        return create_transaction(
            self.entity, "vote", fee=100_000, nonce=nonce,
            current_height=POLL_HEIGHT,
            vote_target=(target_txid, option_index),
        )

    def test_vote_accepted_without_lookup(self):
        # No chain context → structurally valid but unresolved.
        tx = self._make_vote(b"\x11" * 32, 0)
        self.assertTrue(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_vote_rejected_when_poll_missing(self):
        tx = self._make_vote(b"\x22" * 32, 0)
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 1,
                poll_lookup=lambda h: None,
            )
        )

    def test_vote_accepted_when_poll_resolves_earlier(self):
        tx = self._make_vote(b"\x33" * 32, 1)
        # Poll at earlier height with 2 options; index 1 is valid.
        # poll_lookup contract: (block_height, option_count, author_entity_id).
        # A "different author" entity_id keeps the self-vote rule satisfied.
        other_author = b"\xee" * 32
        self.assertTrue(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 5,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, other_author),
            )
        )

    def test_vote_rejected_when_index_out_of_range(self):
        tx = self._make_vote(b"\x44" * 32, 3)
        other_author = b"\xee" * 32
        # Poll has 2 options; index 3 is past the end.
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 5,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, other_author),
            )
        )

    def test_vote_rejected_when_poll_at_or_after_current_height(self):
        tx = self._make_vote(b"\x55" * 32, 0)
        other_author = b"\xee" * 32
        # Same-block reference → reject.
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, other_author),
            )
        )

    def test_vote_self_reference_rejected(self):
        tx = self._make_vote(b"\x66" * 32, 0)
        tx.vote_target = (tx.tx_hash, 0)
        # No poll_lookup needed — self-reference is unconditional reject.
        self.assertFalse(
            verify_transaction(tx, self.pk, current_height=POLL_HEIGHT)
        )

    def test_vote_on_own_poll_rejected(self):
        # No self-vote on own poll: when the resolved poll's
        # author_entity_id equals the voter's entity_id, reject.
        tx = self._make_vote(b"\x77" * 32, 0)
        # Author == this voter's entity_id.
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 5,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, tx.entity_id),
            )
        )

    def test_vote_rejected_when_already_voted(self):
        # vote_check returns True → canonical chain already has a
        # vote from this entity on this poll → reject (one vote per
        # (entity, poll)).
        tx = self._make_vote(b"\x88" * 32, 0)
        other_author = b"\xee" * 32
        self.assertFalse(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 5,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, other_author),
                vote_check=lambda p, v: True,
            )
        )

    def test_vote_accepted_when_not_yet_voted(self):
        # vote_check returns False → no prior vote in canonical → accept.
        tx = self._make_vote(b"\x99" * 32, 0)
        other_author = b"\xee" * 32
        self.assertTrue(
            verify_transaction(
                tx, self.pk,
                current_height=POLL_HEIGHT + 5,
                poll_lookup=lambda h: (POLL_HEIGHT, 2, other_author),
                vote_check=lambda p, v: False,
            )
        )


# ─── ChainDB has_voted_canonical: schema + filter ──────────────────────


class TestVoteRecordsChainDB(unittest.TestCase):
    """ChainDB.has_voted_canonical filters orphaned-branch rows so
    a vote that landed in a now-non-canonical block does NOT block
    a re-vote on the new canonical chain.
    """

    def _fresh_db(self):
        import tempfile
        import os
        from messagechain.storage.chaindb import ChainDB
        tmpdir = tempfile.mkdtemp()
        return ChainDB(os.path.join(tmpdir, "test.db")), tmpdir

    def test_empty_db_returns_false(self):
        db, tmpdir = self._fresh_db()
        try:
            self.assertFalse(
                db.has_voted_canonical(b"\x11" * 32, b"\x22" * 32)
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_orphaned_row_does_not_count(self):
        # A row in vote_records whose block_hash is NOT on the canonical
        # chain must be filtered out — the row is from an orphaned fork.
        db, tmpdir = self._fresh_db()
        try:
            poll_txid = b"\x33" * 32
            voter_id = b"\x44" * 32
            # Insert directly without storing a block — no canonical
            # chain exists, so the row's block_hash can't match.
            db._conn.execute(
                "INSERT INTO vote_records "
                "(poll_txid, voter_id, block_hash, block_height, tx_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (poll_txid, voter_id, b"\x55" * 32, 10, b"\x66" * 32),
            )
            db._conn.commit()
            # Canonical map is empty (no chain_tips row), so this filters
            # out and returns False.
            self.assertFalse(db.has_voted_canonical(poll_txid, voter_id))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ─── Poll fields do NOT eat MAX_MESSAGE_CHARS budget ───────────────────


class TestPollContentBudget(unittest.TestCase):
    """poll_options is structural metadata; it does NOT eat
    MAX_MESSAGE_CHARS — same rule as community_id.
    """

    def test_full_content_budget_with_max_options(self):
        entity = Entity.create(b"poll-budget-seed-padded-32-byte!12")
        full_text = "x" * MAX_MESSAGE_CHARS
        max_options = tuple(
            "a" * MAX_POLL_OPTION_BYTES for _ in range(MAX_POLL_OPTIONS)
        )
        # All 4 options at max length and unique requires distinct suffixes.
        max_options = tuple(
            ("a" * (MAX_POLL_OPTION_BYTES - 1)) + chr(ord("a") + i)
            for i in range(MAX_POLL_OPTIONS)
        )
        tx = create_transaction(
            entity, full_text, fee=10_000_000, nonce=0,
            current_height=POLL_HEIGHT,
            poll_options=max_options,
        )
        self.assertEqual(tx.version, TX_VERSION_POLL)
        self.assertEqual(tx.char_count, MAX_MESSAGE_CHARS)
        self.assertEqual(tx.poll_options, max_options)


if __name__ == "__main__":
    unittest.main()
