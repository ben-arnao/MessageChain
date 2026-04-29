"""
Tests for the chain-identity fields exposed by ``GET /v1/info``.

The headline value-prop is "your message can never be deleted."  A
paranoid visitor on a hostile network needs to be able to verify
they're talking to the chain they think they are — chain_id alone is
not enough (an MITM can echo it).  /v1/info therefore surfaces:

  * genesis_hash — block-0 hash, the immutable chain identity anchor.
  * tip_hash     — current latest block hash.
  * state_root   — current tip's state_root (consensus-canonical).

Together these let the web UI render a chain-identity footer that a
visitor can cross-check against the README's hard-coded genesis
hash before trusting the messages on the page.
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
    """Minimal blockchain stub.

    /v1/info now reads:
      * height
      * chain[-1].header.timestamp
      * chain[0].block_hash         (genesis)
      * chain[-1].block_hash        (tip)
      * chain[-1].header.state_root (state root)

    Stub provides each as plain bytes/floats so the JSON encoder
    matches what a live node would return.
    """

    def __init__(self):
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


class TestInfoChainIdentity(unittest.TestCase):
    def setUp(self):
        port = _find_free_port()
        self.chain = _StubChain()
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

    def _get_json(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, json.loads(body)
        finally:
            conn.close()

    def test_info_includes_genesis_hash(self):
        status, data = self._get_json("/v1/info")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["genesis_hash"], "aa" * 32)

    def test_info_includes_tip_hash(self):
        status, data = self._get_json("/v1/info")
        self.assertEqual(status, 200)
        self.assertEqual(data["tip_hash"], "bb" * 32)

    def test_info_includes_state_root(self):
        status, data = self._get_json("/v1/info")
        self.assertEqual(status, 200)
        self.assertEqual(data["state_root"], "cc" * 32)

    def test_info_handles_empty_chain_for_identity_fields(self):
        """A node still in IBD with no genesis loaded should return
        explicit null for each identity field, not omit them — the
        web UI shows "(loading)" rather than crashing on undefined."""
        self.server.stop()
        empty = _StubChain()
        empty.chain = []
        empty.height = 0
        port = _find_free_port()
        self.server = PublicFeedServer(
            blockchain=empty, port=port, bind="127.0.0.1",
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        self.port = port
        status, data = self._get_json("/v1/info")
        self.assertEqual(status, 200)
        self.assertIsNone(data["genesis_hash"])
        self.assertIsNone(data["tip_hash"])
        self.assertIsNone(data["state_root"])


if __name__ == "__main__":
    unittest.main()
