"""Receipt page (``/r/<tx_hash>``) must render the message body.

The 1.71.0 shareable-receipt URL is the chain's headline demo moment:
every ``cmd_send`` success prints ``<PUBLIC_FEED_URL>/r/<tx_hash>``;
every user sharing "I just put something permanent on a chain" lands
a friend on this page.

Pre-fix the page renders only the inclusion verdict + finality stats +
merkle proof, never the message body itself.  The headline mission
("your message can never be deleted") is invisible at the exact
moment it should be visceral — a friend who follows the share link
sees a bureaucratic "Permanent" badge attached to an opaque 64-hex
``tx_hash``, with no way to learn WHAT was made permanent.

This file pins the funnel end-to-end:

  1. ``Blockchain.get_tx_status_public`` returns ``message``,
     ``entity_id``, ``community_id``, ``prev`` for an included
     ``MessageTransaction`` (community_id / prev only when set on
     the tx — omitted when None so v1-v4 / no-community txs don't
     carry empty placeholders).
  2. ``Server._build_included_status`` (the JSON-RPC twin used by the
     CLI) returns the same fields, so the receipt UI sees a consistent
     schema whether it hit the public-feed HTTP shim or the JSON-RPC
     port.
  3. The receipt-page HTML's renderIncluded function references
     ``result.message`` so the body is rendered when the chain
     returns it.

Surfaced by audit r43 value-prop axis (top-1) — every share-receipt
link issued from CLI or feed now lands on a page that surfaces what
was actually anchored, not just the verdict that something was.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from messagechain.network.public_feed_server import PublicFeedServer


# ── Real MessageTransaction (no signing — the receipt path only reads
#    the dataclass attributes, never re-verifies). ─────────────────────


def _make_message_tx(
    *, entity_id: bytes, plaintext: str, community_id=None, prev=None,
):
    """Construct a real MessageTransaction whose plaintext == ``plaintext``.

    No signature involved — the receipt path reads the dataclass
    attributes only.  Uses RAW_FLAG so ``tx.plaintext`` returns the
    bytes we encoded.  community_id / prev forwarded as-is.
    """
    from messagechain.core.transaction import (
        MessageTransaction, RAW_FLAG, TX_VERSION_COMMUNITY_ID,
    )
    from messagechain.crypto.keys import Signature

    sig = Signature(
        wots_signature=[], leaf_index=0, auth_path=[],
        wots_public_key=b"\x00" * 32, wots_public_seed=b"\x00" * 32,
    )
    return MessageTransaction(
        entity_id=entity_id,
        message=plaintext.encode("utf-8"),
        timestamp=1_700_000_500.0,
        nonce=0,
        fee=1,
        signature=sig,
        version=TX_VERSION_COMMUNITY_ID if community_id is not None else 5,
        compression_flag=RAW_FLAG,
        community_id=community_id,
        prev=prev,
    )


# ── 1. Blockchain.get_tx_status_public returns the message body ───────


class _FakeFinality:
    def __init__(self):
        self.attestations = {}
        self.attested_stake = {}


class _FakeBlockchain:
    """Just enough Blockchain shape for get_tx_status_public."""

    def __init__(self, *, block, staked):
        self.height = 2
        self.db = None  # force the fallback scan path
        self.finality = _FakeFinality()
        self.chain = [block, _make_attestation_block()]
        self.supply = SimpleNamespace(staked=dict(staked))

    def get_block(self, idx):
        if 0 <= idx < len(self.chain):
            return self.chain[idx]
        return None


def _make_attestation_block():
    """Block-1: just carries attestations on block-0.  No transactions."""
    return SimpleNamespace(
        block_hash=b"\xb0" * 32,
        header=SimpleNamespace(
            merkle_root=b"\xee" * 32, block_number=1,
            timestamp=1_700_000_600, state_root=b"\xcc" * 32,
        ),
        transactions=[], transfer_transactions=[], slash_transactions=[],
        governance_txs=[], authority_txs=[], stake_transactions=[],
        unstake_transactions=[], finality_votes=[], custody_proofs=[],
        censorship_evidence_txs=[], bogus_rejection_evidence_txs=[],
        react_transactions=[], witness_acks=[], key_rotation_txs=[],
        non_response_evidence_txs=[], set_authority_key_txs=[],
        inclusion_list_violation_txs=[], emergency_revoke_txs=[],
        set_receipt_subtree_root_txs=[], attestations=[],
    )


def _make_block_with_tx(tx):
    return SimpleNamespace(
        block_hash=b"\xa0" * 32,
        header=SimpleNamespace(
            merkle_root=b"\xff" * 32, block_number=0,
            timestamp=1_700_000_500, state_root=b"\xcc" * 32,
        ),
        transactions=[tx],
        transfer_transactions=[], slash_transactions=[],
        governance_txs=[], authority_txs=[], stake_transactions=[],
        unstake_transactions=[], finality_votes=[], custody_proofs=[],
        censorship_evidence_txs=[], bogus_rejection_evidence_txs=[],
        react_transactions=[], witness_acks=[], key_rotation_txs=[],
        non_response_evidence_txs=[], set_authority_key_txs=[],
        inclusion_list_violation_txs=[], emergency_revoke_txs=[],
        set_receipt_subtree_root_txs=[], attestations=[],
    )


class TestGetTxStatusPublicReturnsMessageBody(unittest.TestCase):
    """``get_tx_status_public`` must include the user-readable body
    for an included MessageTransaction so the receipt page can render
    what was anchored, not just the inclusion verdict."""

    def test_included_message_returns_plaintext(self):
        from messagechain.core.blockchain import Blockchain

        entity_id = b"\x42" * 32
        tx = _make_message_tx(
            entity_id=entity_id,
            plaintext="permanence is the whole point",
        )
        bc = _FakeBlockchain(
            block=_make_block_with_tx(tx),
            staked={b"\x01" * 32: 800, b"\x02" * 32: 200},
        )

        result = Blockchain.get_tx_status_public(bc, tx.tx_hash)

        self.assertEqual(result["status"], "included")
        # The message body must round-trip through the receipt schema.
        self.assertEqual(result["message"], "permanence is the whole point")
        # The author's entity_id must surface so the receipt UI can
        # link "by ..." to /e/<entity_id>.
        self.assertEqual(result["entity_id"], entity_id.hex())

    def test_included_message_includes_community_when_set(self):
        from messagechain.core.blockchain import Blockchain

        tx = _make_message_tx(
            entity_id=b"\x42" * 32,
            plaintext="post in a community",
            community_id="mc-dev",
        )
        bc = _FakeBlockchain(
            block=_make_block_with_tx(tx),
            staked={b"\x01" * 32: 800},
        )
        result = Blockchain.get_tx_status_public(bc, tx.tx_hash)
        self.assertEqual(result.get("community_id"), "mc-dev")

    def test_included_message_omits_community_when_unset(self):
        """A message without a community_id must not carry a stray
        empty / null value into the response — the receipt UI keys
        the affordance off of presence, not falsiness."""
        from messagechain.core.blockchain import Blockchain

        tx = _make_message_tx(
            entity_id=b"\x42" * 32,
            plaintext="no community here",
            community_id=None,
        )
        bc = _FakeBlockchain(
            block=_make_block_with_tx(tx),
            staked={b"\x01" * 32: 800},
        )
        result = Blockchain.get_tx_status_public(bc, tx.tx_hash)
        self.assertNotIn("community_id", result)

    def test_included_message_includes_prev_when_set(self):
        from messagechain.core.blockchain import Blockchain

        parent_hash = b"\xde" * 32
        tx = _make_message_tx(
            entity_id=b"\x42" * 32,
            plaintext="this is a reply",
            prev=parent_hash,
        )
        bc = _FakeBlockchain(
            block=_make_block_with_tx(tx),
            staked={b"\x01" * 32: 800},
        )
        result = Blockchain.get_tx_status_public(bc, tx.tx_hash)
        self.assertEqual(result.get("prev"), parent_hash.hex())


# ── 2. Server._build_included_status mirrors the same fields ──────────


class TestRpcBuildIncludedStatusMessageBody(unittest.TestCase):
    """The CLI's JSON-RPC twin must surface the same fields so the
    receipt UI sees a consistent schema regardless of port hit."""

    def test_rpc_included_returns_message_entity_community_prev(self):
        from server import Server

        s = Server.__new__(Server)
        tx = _make_message_tx(
            entity_id=b"\x42" * 32,
            plaintext="hello permanence",
            community_id="mc-dev",
            prev=b"\xde" * 32,
        )
        block = _make_block_with_tx(tx)

        s.blockchain = SimpleNamespace(
            height=2,
            db=None,
            chain=[block, _make_attestation_block()],
            finality=_FakeFinality(),
            supply=SimpleNamespace(staked={b"\x01" * 32: 800}),
            get_block=lambda idx: (
                [block, _make_attestation_block()][idx]
                if 0 <= idx < 2 else None
            ),
        )
        s.mempool = MagicMock(
            pending={}, react_pool={}, slash_pool={},
            censorship_evidence_pool={}, finality_pool={},
            orphan_pool={},
        )

        resp = Server._rpc_get_tx_status(s, {"tx_hash": tx.tx_hash.hex()})
        self.assertTrue(resp["ok"], resp)
        r = resp["result"]
        self.assertEqual(r["status"], "included")
        self.assertEqual(r["message"], "hello permanence")
        self.assertEqual(r["entity_id"], (b"\x42" * 32).hex())
        self.assertEqual(r["community_id"], "mc-dev")
        self.assertEqual(r["prev"], (b"\xde" * 32).hex())


# ── 3. Receipt HTML page references result.message ────────────────────


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChainForHTML:
    """Public-feed receipt-page tests use this stub.  Real-chain plumbing
    is exercised by the tests above; here we just need the page itself."""

    def __init__(self):
        self._genesis_hash = b"\xaa" * 32
        self._tip_hash = b"\xbb" * 32
        genesis = SimpleNamespace(
            header=SimpleNamespace(
                timestamp=1_700_000_000.0, state_root=self._genesis_hash,
            ),
            block_hash=self._genesis_hash,
        )
        tip = SimpleNamespace(
            header=SimpleNamespace(
                timestamp=1_700_000_999.0, state_root=b"\xcc" * 32,
            ),
            block_hash=self._tip_hash,
        )
        self.chain = [genesis, tip]
        self.height = 1

    def get_recent_messages(self, count):
        return []

    def get_tx_status_public(self, tx_hash: bytes) -> dict:
        return {"status": "not_found"}


class TestReceiptHtmlRendersMessageBody(unittest.TestCase):
    def setUp(self):
        self.chain = _StubChainForHTML()
        port = _find_free_port()
        self.server = PublicFeedServer(
            blockchain=self.chain, port=port, bind="127.0.0.1",
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.server.stop()
            raise RuntimeError("PublicFeedServer never came up")
        self.port = port

    def tearDown(self):
        self.server.stop()

    def _fetch_receipt_html(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/r/" + ("ab" * 32))
            resp = conn.getresponse()
            return resp.read().decode("utf-8")
        finally:
            conn.close()

    def test_receipt_html_references_result_message(self):
        """The renderIncluded path must consume ``result.message`` —
        without this reference the page has no way to display the
        body even when the chain returns it."""
        src = self._fetch_receipt_html()
        self.assertIn("result.message", src)

    def test_receipt_html_renders_entity_id_link(self):
        """A reader who lands on a receipt should be able to click
        through to the author profile.  We pin a /e/ entry-point so
        the link target survives template refactors."""
        src = self._fetch_receipt_html()
        # The link is built from result.entity_id.  Match flexibly:
        # any occurrence of result.entity_id alongside /e/ is fine.
        self.assertIn("result.entity_id", src)
        self.assertIn("/e/", src)


if __name__ == "__main__":
    unittest.main()
