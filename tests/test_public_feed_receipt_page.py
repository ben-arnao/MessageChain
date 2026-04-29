"""
Tests for the per-message permanence-receipt surface.

The headline value-prop is "your message can never be deleted."  The
public web feed at messagechain.org renders a list of messages but
without a per-message proof affordance a first-time visitor cannot
distinguish it from a generic social feed.  The fix:

  * Each card carries a "Permanent · verify" link to /r/<tx_hash>.
  * /r/<tx_hash> is a small HTML page that fetches /v1/tx_status?
    tx_hash=<hex> and renders inclusion proof + permanence framing.
  * /v1/tx_status is a thin HTTP proxy over a chain-side helper that
    returns the same shape `cmd_receipt` already consumes.

These tests pin the JSON contract + HTML page surface.  They use the
same StubChain pattern as test_public_feed_server but extend the
duck-type with a `get_tx_status_public(tx_hash)` method since the
feed server doesn't have access to a Mempool / FinalityTracker
itself — the public-feed view is inclusion-only.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace

from messagechain.network.public_feed_server import PublicFeedServer


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChain:
    """Minimal blockchain stub for receipt-page tests.

    The receipt-page surface only needs:
      * `chain[0].block_hash`        — genesis (chain-identity footer)
      * `chain[-1].block_hash`       — tip
      * `chain[-1].header.timestamp` — for /v1/info compat
      * `chain[-1].header.state_root`
      * `height`
      * `get_tx_status_public(tx_hash_bytes)` → dict in the schema below.
    """

    def __init__(self, statuses=None):
        # statuses: dict tx_hash_bytes -> status_dict
        self._statuses = dict(statuses or {})
        self._genesis_hash = b"\xaa" * 32
        self._tip_hash = b"\xbb" * 32
        self._state_root = b"\xcc" * 32
        genesis = SimpleNamespace(
            header=SimpleNamespace(timestamp=1_700_000_000.0,
                                   state_root=self._genesis_hash),
            block_hash=self._genesis_hash,
        )
        tip = SimpleNamespace(
            header=SimpleNamespace(timestamp=1_700_000_999.0,
                                   state_root=self._state_root),
            block_hash=self._tip_hash,
        )
        self.chain = [genesis, tip]
        self.height = 1

    def get_recent_messages(self, count):
        return []

    def get_tx_status_public(self, tx_hash: bytes) -> dict:
        return self._statuses.get(tx_hash, {"status": "not_found"})


class _ReceiptTestBase(unittest.TestCase):
    def _spin_up(self, chain):
        port = _find_free_port()
        server = PublicFeedServer(
            blockchain=chain, port=port, bind="127.0.0.1",
        )
        server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            server.stop()
            raise RuntimeError("PublicFeedServer never came up")
        return server, port

    def _http(self, path, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()


class TestTxStatusJsonProxy(_ReceiptTestBase):
    def setUp(self):
        self.tx_hash = b"\x11" * 32
        self.tx_hash_hex = self.tx_hash.hex()
        self.included_status = {
            "status": "included",
            "block_height": 42,
            "block_hash": ("ab" * 32),
            "tx_index": 0,
            "merkle_root": ("12" * 32),
            "block_timestamp": 1_700_000_500,
            "current_height": 50,
            "attesters": 3,
            "total_validators": 4,
            "attesting_stake": 1500,
            "total_stake": 2000,
            "finality_threshold_met": True,
            "finality_numerator": 2,
            "finality_denominator": 3,
        }
        self.chain = _StubChain(statuses={self.tx_hash: self.included_status})
        self.server, self.port = self._spin_up(self.chain)

    def tearDown(self):
        self.server.stop()

    def test_tx_status_returns_included(self):
        status, headers, body = self._http(
            "/v1/tx_status?tx_hash=" + self.tx_hash_hex,
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Content-Type"),
            "application/json; charset=utf-8",
        )
        data = json.loads(body)
        self.assertTrue(data["ok"])
        result = data["result"]
        self.assertEqual(result["status"], "included")
        self.assertEqual(result["block_height"], 42)
        self.assertEqual(result["attesters"], 3)
        self.assertTrue(result["finality_threshold_met"])

    def test_tx_status_not_found(self):
        status, _, body = self._http(
            "/v1/tx_status?tx_hash=" + ("ff" * 32),
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["status"], "not_found")

    def test_tx_status_invalid_hex_returns_400(self):
        status, _, body = self._http("/v1/tx_status?tx_hash=not-hex")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertFalse(data["ok"])

    def test_tx_status_missing_param_returns_400(self):
        status, _, body = self._http("/v1/tx_status")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertFalse(data["ok"])

    def test_tx_status_strips_0x_prefix(self):
        status, _, body = self._http(
            "/v1/tx_status?tx_hash=0x" + self.tx_hash_hex,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["result"]["status"], "included")


class TestReceiptStaticPage(_ReceiptTestBase):
    """`/r/<tx_hash>` returns a small HTML page that calls
    /v1/tx_status itself (mirrors the /e/<entity_id> pattern)."""

    def setUp(self):
        self.chain = _StubChain()
        self.server, self.port = self._spin_up(self.chain)

    def tearDown(self):
        self.server.stop()

    def test_receipt_path_serves_html(self):
        tx_hash = "ab" * 32
        status, headers, body = self._http("/r/" + tx_hash)
        self.assertEqual(status, 200)
        self.assertTrue(
            headers.get("Content-Type", "").startswith("text/html"),
        )

    def test_receipt_page_mentions_permanence(self):
        """First-time visitor scanning the page must see the
        permanence framing in plain text — that's the whole point
        of the per-message proof affordance."""
        tx_hash = "cd" * 32
        _, _, body = self._http("/r/" + tx_hash)
        src = body.decode("utf-8")
        self.assertIn("Permanent", src)

    def test_receipt_page_calls_tx_status_endpoint(self):
        """The page must hit /v1/tx_status — otherwise the proof
        data never arrives at the visitor's browser."""
        _, _, body = self._http("/r/" + ("11" * 32))
        src = body.decode("utf-8")
        self.assertIn("/v1/tx_status", src)

    def test_receipt_page_includes_chain_identity_footer(self):
        """Same chain-identity sanity-check footer the feed page
        carries — paranoid visitors should be able to compare the
        rendered genesis hash on a receipt page against their pinned
        copy without leaving the page."""
        _, _, body = self._http("/r/" + ("22" * 32))
        src = body.decode("utf-8")
        # Anchor by the /v1/info-driven element id used on every page.
        self.assertIn("chainFooter", src)


class TestFeedAndEntityChainFooter(_ReceiptTestBase):
    """The chain-identity footer renders on every page (feed,
    entity, receipt) so the trust-anchor cross-check is always one
    glance away."""

    def setUp(self):
        self.chain = _StubChain()
        self.server, self.port = self._spin_up(self.chain)

    def tearDown(self):
        self.server.stop()

    def test_feed_page_has_chain_footer(self):
        _, _, body = self._http("/")
        src = body.decode("utf-8")
        self.assertIn("chainFooter", src)

    def test_entity_page_has_chain_footer(self):
        _, _, body = self._http("/e/" + ("aa" * 32))
        src = body.decode("utf-8")
        self.assertIn("chainFooter", src)


if __name__ == "__main__":
    unittest.main()
