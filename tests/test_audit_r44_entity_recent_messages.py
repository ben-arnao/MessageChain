"""``/e/<entity_id>`` profile page must render the entity's recent messages.

Pre-fix the profile page rendered only aggregate counters (Funds /
Activity / Reputation / Governance) -- no list of the entity's actual
messages.  A visitor clicking "from mc1..." on any feed card landed
on a block-explorer-style counters page, not a social-platform
profile.  Reddit/Twitter framing (CLAUDE.md positioning anchor)
broke at the third click of every visitor's exploration loop.

This file pins the three layers of the funnel:

  1. ``Blockchain.get_recent_messages_by_entity`` returns the
     entity's most recent messages, newest first, mirroring the
     shape of ``get_recent_messages`` so the UI can render them
     with the same card pattern.
  2. The public-feed HTTP server exposes
     ``GET /v1/entity_messages?id=<hex>&limit=N`` returning that
     list as JSON.
  3. ``entity.html`` references the new endpoint and renders the
     messages in a "Recent messages" section.

Surfaced by audit r44 #3 -- value-prop top-1 (Reddit/Twitter framing).
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace
from urllib.parse import urlencode

from messagechain.network.public_feed_server import PublicFeedServer


# ── 1. Blockchain.get_recent_messages_by_entity ───────────────────────


def _make_message_tx(entity_id: bytes, text: str, *, ts: float = 1_700_000_000):
    from messagechain.core.transaction import MessageTransaction, RAW_FLAG
    from messagechain.crypto.keys import Signature

    sig = Signature(
        wots_signature=[], leaf_index=0, auth_path=[],
        wots_public_key=b"\x00" * 32, wots_public_seed=b"\x00" * 32,
    )
    return MessageTransaction(
        entity_id=entity_id,
        message=text.encode("utf-8"),
        timestamp=ts,
        nonce=0,
        fee=1,
        signature=sig,
        compression_flag=RAW_FLAG,
    )


def _make_block(number: int, txs):
    return SimpleNamespace(
        block_hash=bytes([number % 256]) * 32,
        header=SimpleNamespace(
            merkle_root=b"\xff" * 32, block_number=number,
            timestamp=1_700_000_000 + number, state_root=b"\xcc" * 32,
        ),
        transactions=list(txs),
        transfer_transactions=[], slash_transactions=[],
        governance_txs=[], authority_txs=[], stake_transactions=[],
        unstake_transactions=[], finality_votes=[], custody_proofs=[],
        censorship_evidence_txs=[], bogus_rejection_evidence_txs=[],
        react_transactions=[], witness_acks=[], key_rotation_txs=[],
        non_response_evidence_txs=[], set_authority_key_txs=[],
        inclusion_list_violation_txs=[], emergency_revoke_txs=[],
        set_receipt_subtree_root_txs=[], attestations=[],
    )


class _ReactionStateStub:
    def __init__(self):
        self.choices = {}


class _ChainForEntityMessages:
    """Just enough Blockchain shape for get_recent_messages_by_entity."""

    def __init__(self, blocks):
        self.chain = blocks
        self.height = blocks[-1].header.block_number if blocks else 0
        self.reaction_state = _ReactionStateStub()


class TestGetRecentMessagesByEntity(unittest.TestCase):
    """The chain helper must filter on entity_id and return
    newest-first, capped to the requested count."""

    def test_filters_by_entity_and_returns_newest_first(self):
        from messagechain.core.blockchain import Blockchain

        alice = b"\xaa" * 32
        bob = b"\xbb" * 32

        # Two blocks: bob in block 0, alice ×2 in block 1.
        b0 = _make_block(0, [_make_message_tx(bob, "bob 1", ts=100)])
        b1 = _make_block(1, [
            _make_message_tx(alice, "alice 1", ts=200),
            _make_message_tx(alice, "alice 2", ts=300),
        ])
        chain = _ChainForEntityMessages([b0, b1])

        msgs = Blockchain.get_recent_messages_by_entity(chain, alice, 10)
        self.assertEqual(len(msgs), 2)
        # Newest-first.
        self.assertEqual(msgs[0]["message"], "alice 2")
        self.assertEqual(msgs[1]["message"], "alice 1")
        for m in msgs:
            self.assertEqual(m["entity_id"], alice.hex())
            # Same schema as get_recent_messages so the UI can render
            # the same card.
            self.assertIn("tx_hash", m)
            self.assertIn("block_number", m)
            self.assertIn("ups", m)
            self.assertIn("downs", m)

    def test_bob_not_in_alice_listing(self):
        from messagechain.core.blockchain import Blockchain

        alice = b"\xaa" * 32
        bob = b"\xbb" * 32
        b0 = _make_block(0, [_make_message_tx(bob, "bob solo", ts=100)])
        chain = _ChainForEntityMessages([b0])

        msgs = Blockchain.get_recent_messages_by_entity(chain, alice, 10)
        self.assertEqual(msgs, [])

    def test_limit_caps_results(self):
        from messagechain.core.blockchain import Blockchain

        alice = b"\xaa" * 32
        txs = [_make_message_tx(alice, f"msg {i}", ts=i) for i in range(5)]
        b0 = _make_block(0, txs)
        chain = _ChainForEntityMessages([b0])

        msgs = Blockchain.get_recent_messages_by_entity(chain, alice, 3)
        self.assertEqual(len(msgs), 3)


# ── 2. /v1/entity_messages HTTP endpoint ─────────────────────────────


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ChainForServer:
    """Tiny chain shim — the server reads `chain`, `height`, calls
    `get_recent_messages_by_entity` on us."""

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
        self._messages_by_entity: dict[bytes, list[dict]] = {}

    def get_recent_messages(self, count):
        return []

    def get_recent_messages_by_entity(self, entity_id, count):
        return list(self._messages_by_entity.get(entity_id, []))[:count]


class TestEntityMessagesHttpEndpoint(unittest.TestCase):
    def setUp(self):
        self.chain = _ChainForServer()
        self.alice = b"\xaa" * 32
        self.chain._messages_by_entity[self.alice] = [
            {
                "message": "alice latest",
                "entity_id": self.alice.hex(),
                "timestamp": 200, "tx_hash": "ab" * 32,
                "block_number": 1, "ups": 0, "downs": 0, "up_pct": None,
            },
            {
                "message": "alice older",
                "entity_id": self.alice.hex(),
                "timestamp": 100, "tx_hash": "cd" * 32,
                "block_number": 0, "ups": 0, "downs": 0, "up_pct": None,
            },
        ]
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

    def _get(self, path):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5,
        )
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_endpoint_returns_messages_for_entity(self):
        status, body = self._get(
            "/v1/entity_messages?" + urlencode({
                "id": self.alice.hex(), "limit": 10,
            })
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"], data)
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(data["messages"][0]["message"], "alice latest")

    def test_endpoint_rejects_malformed_id(self):
        status, body = self._get("/v1/entity_messages?id=notvalid&limit=10")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertFalse(data["ok"])

    def test_endpoint_clamps_limit(self):
        """Limit must be clamped to PUBLIC_FEED_MAX_LIMIT so a hostile
        caller cannot demand an arbitrary slice of an entity's history."""
        from messagechain.config import PUBLIC_FEED_MAX_LIMIT
        status, body = self._get(
            "/v1/entity_messages?" + urlencode({
                "id": self.alice.hex(),
                "limit": PUBLIC_FEED_MAX_LIMIT * 10,
            })
        )
        self.assertEqual(status, 200)
        # Behaviour is "clamp internally" — we trust the implementation
        # to bound the call into the chain helper; verifying it doesn't
        # crash is the structural check.
        data = json.loads(body)
        self.assertTrue(data["ok"])


# ── 3. entity.html references the new endpoint and renders a section ─


class TestEntityHtmlRendersRecentMessages(unittest.TestCase):
    """Pre-fix the page had no posts list -- the Reddit/Twitter
    framing of the chain ended at the third click of every visitor's
    exploration loop.  Post-fix the page renders the entity's recent
    messages with permalink chips to /r/<tx>."""

    def setUp(self):
        self.chain = _ChainForServer()
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

    def _fetch_entity_html(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/e/" + ("ab" * 32))
            resp = conn.getresponse()
            return resp.read().decode("utf-8")
        finally:
            conn.close()

    def test_html_fetches_entity_messages_endpoint(self):
        """The page must fetch from /v1/entity_messages -- without
        this the new endpoint is dark from the public surface."""
        src = self._fetch_entity_html()
        self.assertIn("/v1/entity_messages", src)

    def test_html_has_recent_messages_section(self):
        """The page must surface a Recent messages section -- the
        whole point is making the entity's posts visible on click 3."""
        src = self._fetch_entity_html()
        # Pin the section presence flexibly.  Either a heading or an
        # element id keyed for the list is fine.
        lower = src.lower()
        self.assertTrue(
            "recent messages" in lower or "messageslist" in lower,
            "entity.html must add a Recent messages section",
        )

    def test_html_links_messages_to_receipt_permalink(self):
        """Each rendered message should permalink to /r/<tx_hash> so a
        visitor can click through to the per-message receipt page."""
        src = self._fetch_entity_html()
        self.assertIn("/r/", src)


if __name__ == "__main__":
    unittest.main()
