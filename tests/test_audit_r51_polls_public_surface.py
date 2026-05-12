"""Audit r51 #2 — Tier 72 polls + structured votes shipped dead on
every public surface.  TX_VERSION_POLL (v6) and the consensus rules
landed in 1.77.0 / 1.78.0, the CLI has ``--poll-option`` /
``--vote-target``, but the public JSON shim (``/v1/latest``,
``/v1/entity_messages``, ``/v1/tx_status``), the feed renderer, the
receipt page, the README, COMPARISON.md, and the forum-primitives
guide all have zero awareness of polls.

Exact repeat of the Tier 25 community-handle ship-dead pattern flagged
in earlier audit rounds, one tier later.  CLAUDE.md positioning anchor
at risk: "decentralized reddit/twitter core" framing of the public
surface — a Hive/Nostr defector expects structured polls as a
platform primitive; making the feature invisible erases the
just-paid hard-fork differentiator.

Abstraction fix: a single helper on Blockchain that returns the
poll/vote shape for a tx (the ``kind`` discriminator + poll_options /
vote_target / tally fields).  All three JSON surfaces consume it
(``get_recent_messages``, ``get_recent_messages_by_entity``,
``get_tx_status_public``), and Server._build_included_status mirrors
the same fields for JSON-RPC.  The HTML render branches in feed.html
and receipt.html dispatch on ``kind``.  Adding a new structured-tx
kind in the future then surfaces on every UI by extending the same
helper.

These tests pin the JSON schema; the HTML render branches are
asserted via source-string matching on the static files (the existing
audit r43 pattern).
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from messagechain.config import (
    TREASURY_ENTITY_ID,
)
from messagechain.core.transaction import (
    MessageTransaction, RAW_FLAG, TX_VERSION_POLL,
)
from messagechain.crypto.keys import Signature


# ── Real, validate-bypassing MessageTransaction builders ─────────────


def _empty_sig() -> Signature:
    return Signature(
        wots_signature=[], leaf_index=0, auth_path=[],
        wots_public_key=b"\x00" * 32, wots_public_seed=b"\x00" * 32,
    )


def _make_poll_tx(
    *,
    entity_id: bytes,
    question: str,
    options: tuple[str, ...],
    nonce: int = 0,
    timestamp: float = 1_700_000_500.0,
) -> MessageTransaction:
    return MessageTransaction(
        entity_id=entity_id,
        message=question.encode("utf-8"),
        timestamp=timestamp,
        nonce=nonce,
        fee=1,
        signature=_empty_sig(),
        version=TX_VERSION_POLL,
        compression_flag=RAW_FLAG,
        poll_options=options,
    )


def _make_vote_tx(
    *,
    entity_id: bytes,
    poll_txid: bytes,
    option_index: int,
    nonce: int = 0,
    timestamp: float = 1_700_000_600.0,
) -> MessageTransaction:
    return MessageTransaction(
        entity_id=entity_id,
        message=b"",  # votes have empty message body
        timestamp=timestamp,
        nonce=nonce,
        fee=1,
        signature=_empty_sig(),
        version=TX_VERSION_POLL,
        compression_flag=RAW_FLAG,
        vote_target=(poll_txid, option_index),
    )


def _make_block_with_txs(txs: list[MessageTransaction], block_number: int = 0):
    return SimpleNamespace(
        block_hash=bytes([block_number & 0xff]) * 32,
        header=SimpleNamespace(
            merkle_root=b"\xff" * 32,
            block_number=block_number,
            timestamp=1_700_000_500 + block_number,
            state_root=b"\xcc" * 32,
        ),
        transactions=txs,
        transfer_transactions=[], slash_transactions=[],
        governance_txs=[], authority_txs=[], stake_transactions=[],
        unstake_transactions=[], finality_votes=[], custody_proofs=[],
        censorship_evidence_txs=[], bogus_rejection_evidence_txs=[],
        react_transactions=[], witness_acks=[], key_rotation_txs=[],
        non_response_evidence_txs=[], set_authority_key_txs=[],
        inclusion_list_violation_txs=[], emergency_revoke_txs=[],
        set_receipt_subtree_root_txs=[], attestations=[],
    )


# ── 1. get_recent_messages surfaces poll/vote shape ─────────────────


class TestGetRecentMessagesSurfacesPolls(unittest.TestCase):
    """The public-feed JSON shim must expose a ``kind`` discriminator
    plus ``poll_options`` / ``vote_target`` fields so the front-end
    can render poll cards and vote cards distinctly from plain
    messages.  Tier 72 polls are otherwise invisible end-to-end.
    """

    def _bc_with(self, blocks):
        from messagechain.core.blockchain import Blockchain

        bc = Blockchain.__new__(Blockchain)
        bc.chain = blocks
        # Blockchain.height is a @property reading len(self.chain) — no setter.
        bc.reaction_state = SimpleNamespace(choices={})
        return bc

    def test_plain_message_has_kind_message(self):
        from messagechain.core.blockchain import Blockchain

        tx = MessageTransaction(
            entity_id=b"\x42" * 32,
            message=b"hello permanence",
            timestamp=1_700_000_500.0,
            nonce=0, fee=1, signature=_empty_sig(),
            version=5, compression_flag=RAW_FLAG,
        )
        bc = self._bc_with([_make_block_with_txs([tx])])

        out = Blockchain.get_recent_messages(bc, 10)

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "message",
            "Plain v5 message tx must surface kind='message' on the "
            "public JSON shim so the front-end can dispatch render "
            "branches by kind.")
        self.assertNotIn("poll_options", out[0])
        self.assertNotIn("vote_target", out[0])

    def test_poll_tx_surfaces_options_and_kind(self):
        from messagechain.core.blockchain import Blockchain

        eid = b"\x42" * 32
        poll = _make_poll_tx(
            entity_id=eid,
            question="favourite colour?",
            options=("red", "green", "blue"),
        )
        bc = self._bc_with([_make_block_with_txs([poll])])

        out = Blockchain.get_recent_messages(bc, 10)

        self.assertEqual(len(out), 1)
        entry = out[0]
        self.assertEqual(entry["kind"], "poll",
            "A v6 tx with poll_options set must surface kind='poll'.")
        self.assertEqual(entry["poll_options"], ["red", "green", "blue"],
            "Poll options must be exposed as a JSON array of strings.")
        # The poll's question is the message body — already exposed.
        self.assertEqual(entry["message"], "favourite colour?")

    def test_vote_tx_surfaces_target_and_kind(self):
        from messagechain.core.blockchain import Blockchain

        poll_txid = b"\xab" * 32
        vote = _make_vote_tx(
            entity_id=b"\x77" * 32,
            poll_txid=poll_txid,
            option_index=1,
        )
        bc = self._bc_with([_make_block_with_txs([vote])])

        out = Blockchain.get_recent_messages(bc, 10)

        self.assertEqual(len(out), 1)
        entry = out[0]
        self.assertEqual(entry["kind"], "vote",
            "A v6 tx with vote_target set must surface kind='vote'.")
        self.assertEqual(
            entry["vote_target"],
            {"poll_txid": poll_txid.hex(), "option_index": 1},
            "Vote target must be exposed as "
            "{poll_txid: hex, option_index: int} so the front-end "
            "can resolve the option label client-side.",
        )

    def test_entity_messages_surfaces_same_shape(self):
        """The parallel surface (``/v1/entity_messages``) consumes the
        same helper, so the poll/vote fields appear identically on
        the entity profile page."""
        from messagechain.core.blockchain import Blockchain

        eid = b"\x42" * 32
        poll = _make_poll_tx(
            entity_id=eid,
            question="favourite colour?",
            options=("red", "blue"),
        )
        bc = self._bc_with([_make_block_with_txs([poll])])

        out = Blockchain.get_recent_messages_by_entity(bc, eid, 10)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "poll")
        self.assertEqual(out[0]["poll_options"], ["red", "blue"])


# ── 2. get_tx_status_public surfaces poll/vote + tally ──────────────


class TestGetTxStatusPublicSurfacesPollsAndTally(unittest.TestCase):
    """The receipt page (``/r/<tx_hash>``) is the second high-traffic
    surface that has to render polls visibly.  ``get_tx_status_public``
    must surface kind / poll_options / vote_target on every tx, AND
    for poll txs must include a per-option tally aggregated from the
    chain so the receipt page can render a live result bar."""

    def _bc_with(self, blocks):
        from messagechain.core.blockchain import Blockchain

        bc = Blockchain.__new__(Blockchain)
        bc.chain = blocks
        # height is a @property; get_block reads from self.chain natively.
        bc.db = None  # force the fallback chain-scan tx-lookup
        bc.finality = SimpleNamespace(
            attestations={}, attested_stake={},
        )
        bc.supply = SimpleNamespace(staked={b"\x01" * 32: 800})
        return bc

    def test_poll_status_returns_options_and_tally(self):
        from messagechain.core.blockchain import Blockchain

        author = b"\x42" * 32
        poll = _make_poll_tx(
            entity_id=author,
            question="favourite colour?",
            options=("red", "green", "blue"),
        )
        # Three voters: red, blue, blue.
        voter1, voter2, voter3 = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        v1 = _make_vote_tx(entity_id=voter1, poll_txid=poll.tx_hash, option_index=0)
        v2 = _make_vote_tx(entity_id=voter2, poll_txid=poll.tx_hash, option_index=2)
        v3 = _make_vote_tx(entity_id=voter3, poll_txid=poll.tx_hash, option_index=2)

        bc = self._bc_with([
            _make_block_with_txs([poll], block_number=0),
            _make_block_with_txs([v1, v2, v3], block_number=1),
        ])

        result = Blockchain.get_tx_status_public(bc, poll.tx_hash)

        self.assertEqual(result["status"], "included")
        self.assertEqual(result["kind"], "poll",
            "get_tx_status_public must surface kind='poll' so the "
            "receipt page can dispatch into the poll render branch.")
        self.assertEqual(result["poll_options"], ["red", "green", "blue"])
        self.assertEqual(
            result["poll_tally"], [1, 0, 2],
            "Poll tally must be a per-option vote count aggregated "
            "from the chain (red=1, green=0, blue=2).",
        )

    def test_vote_status_returns_target_and_resolved_option(self):
        from messagechain.core.blockchain import Blockchain

        author = b"\x42" * 32
        poll = _make_poll_tx(
            entity_id=author,
            question="favourite colour?",
            options=("red", "green", "blue"),
        )
        voter = b"\x01" * 32
        vote = _make_vote_tx(
            entity_id=voter, poll_txid=poll.tx_hash, option_index=1,
        )

        bc = self._bc_with([
            _make_block_with_txs([poll], block_number=0),
            _make_block_with_txs([vote], block_number=1),
        ])

        result = Blockchain.get_tx_status_public(bc, vote.tx_hash)

        self.assertEqual(result["kind"], "vote")
        self.assertEqual(
            result["vote_target"],
            {"poll_txid": poll.tx_hash.hex(), "option_index": 1},
        )
        # The chain can resolve the option label client-side using
        # the public-feed proxy + poll_txid; surface the resolved
        # label here too so the receipt page doesn't need a second
        # round-trip.
        self.assertEqual(
            result.get("vote_option_label"), "green",
            "When the vote's target poll resolves to a known on-chain "
            "poll tx, the receipt page response must surface the "
            "resolved option label so the page can render "
            "'voted: green' without a second RPC.",
        )

    def test_plain_message_status_does_not_carry_poll_fields(self):
        """Regression: a non-v6 message tx must not carry empty poll/
        vote placeholders in its receipt-status response."""
        from messagechain.core.blockchain import Blockchain

        tx = MessageTransaction(
            entity_id=b"\x42" * 32,
            message=b"plain old message",
            timestamp=1_700_000_500.0,
            nonce=0, fee=1, signature=_empty_sig(),
            version=5, compression_flag=RAW_FLAG,
        )
        bc = self._bc_with([_make_block_with_txs([tx])])

        result = Blockchain.get_tx_status_public(bc, tx.tx_hash)
        self.assertEqual(result["kind"], "message")
        self.assertNotIn("poll_options", result)
        self.assertNotIn("vote_target", result)
        self.assertNotIn("poll_tally", result)


# ── 3. Server._build_included_status mirrors poll/vote fields ───────


class TestServerJsonRpcMirrorsPollFields(unittest.TestCase):
    """The JSON-RPC twin used by the CLI must surface the same poll/
    vote / kind / tally fields as the HTTP shim — audit r43 #2
    pattern (one schema, two ports).  Adding a new structured-tx
    kind that ships dead on JSON-RPC re-introduces the r51 #2
    defect-shape by definition."""

    def test_server_build_included_status_carries_kind(self):
        from server import Server

        author = b"\x42" * 32
        poll = _make_poll_tx(
            entity_id=author,
            question="json-rpc poll?",
            options=("yes", "no"),
        )
        block = _make_block_with_txs([poll], block_number=0)

        s = Server.__new__(Server)
        s.blockchain = SimpleNamespace(
            height=1,
            db=None,
            chain=[block],
            finality=SimpleNamespace(attestations={}, attested_stake={}),
            supply=SimpleNamespace(staked={b"\x01" * 32: 800}),
            get_block=lambda idx: block if idx == 0 else None,
        )
        # The mempool attribute is unused on the included path.
        s.mempool = None

        response = s._build_included_status(poll.tx_hash, (0, 0))
        self.assertTrue(response.get("ok"))
        result = response["result"]
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["kind"], "poll")
        self.assertEqual(result["poll_options"], ["yes", "no"])


# ── 4. Static UI surfaces dispatch on kind ──────────────────────────


REPO_ROOT = Path(__file__).resolve().parent.parent
FEED_HTML = REPO_ROOT / "messagechain" / "static" / "feed.html"
RECEIPT_HTML = REPO_ROOT / "messagechain" / "static" / "receipt.html"


class TestFeedHtmlRendersPolls(unittest.TestCase):
    """The public feed page must render poll cards and vote cards
    distinctly from plain messages.  Structural source-string guard
    so a future refactor of the feed renderer doesn't silently drop
    the kind dispatch."""

    def test_feed_html_dispatches_on_kind(self):
        src = FEED_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "kind", src,
            "feed.html must reference the ``kind`` discriminator "
            "exposed by /v1/latest so polls and votes render with "
            "their own card pattern (audit r51 #2).",
        )

    def test_feed_html_renders_poll_options(self):
        src = FEED_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "poll_options", src,
            "feed.html must reference poll_options so the poll card "
            "can list the answer choices.",
        )

    def test_feed_html_renders_vote_target(self):
        src = FEED_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "vote_target", src,
            "feed.html must reference vote_target so a vote card "
            "links back to its parent poll.",
        )


class TestReceiptHtmlRendersPolls(unittest.TestCase):
    """The receipt page is the share-target for every CLI `send`
    success — a poll receipt that doesn't show the options is a
    dead surface."""

    def test_receipt_html_dispatches_on_kind(self):
        src = RECEIPT_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "kind", src,
            "receipt.html must reference the ``kind`` field exposed "
            "by /v1/tx_status so polls and votes render with their "
            "own body pattern (audit r51 #2).",
        )

    def test_receipt_html_renders_poll_options(self):
        src = RECEIPT_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "poll_options", src,
            "receipt.html must reference poll_options so a poll's "
            "answer choices are rendered.",
        )

    def test_receipt_html_renders_poll_tally(self):
        src = RECEIPT_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "poll_tally", src,
            "receipt.html must reference poll_tally so a poll's "
            "running result is visible to the page visitor.",
        )


# ── 5. Public docs mention polls ────────────────────────────────────


class TestPublicDocsSurfacePolls(unittest.TestCase):
    """Docs-as-tests guard: polls must be discoverable from README,
    COMPARISON.md, and the forum-primitives guide so newcomers
    actually find the feature."""

    def test_readme_mentions_poll_option_flag(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "--poll-option", readme,
            "README must include an example using the "
            "--poll-option CLI flag so newcomers discover polls "
            "(audit r51 #2 -- ship-dead surface).",
        )

    def test_comparison_mentions_structured_polls(self):
        comp = (REPO_ROOT / "COMPARISON.md").read_text(encoding="utf-8")
        # Case-insensitive contains: 'poll'.
        self.assertIn(
            "poll", comp.lower(),
            "COMPARISON.md must include a row referencing the "
            "structured-polls differentiator MessageChain just paid "
            "a hard fork to ship (audit r51 #2).",
        )

    def test_forum_primitives_guide_mentions_polls(self):
        guide_path = REPO_ROOT / "guides" / "forum-primitives.md"
        guide = guide_path.read_text(encoding="utf-8")
        self.assertIn(
            "poll", guide.lower(),
            "guides/forum-primitives.md must include a polls section "
            "documenting the v6 tx-version structured-poll primitive.",
        )


if __name__ == "__main__":
    unittest.main()
