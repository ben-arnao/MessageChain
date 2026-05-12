"""Public-feed POST routes must reject non-JSON Content-Type.

Audit r49 #2.  ``/faucet`` and ``/quickpost`` accept a JSON body and
the response carries ``Access-Control-Allow-Origin: *``.  Pre-fix the
handlers read ``Content-Length`` worth of bytes and ran ``json.loads``
on whatever arrived, with no Content-Type check.

Browser CSRF surface: a "simple CORS" POST with
``Content-Type: text/plain`` is dispatched without a preflight (the
browser does NOT consult ``Access-Control-Allow-Methods`` for simple
requests), so any cross-origin web page a wallet user visits can drive
either endpoint.  The faucet's PoW challenge is bound to the recipient
address only — an attacker who pre-mines a challenge for ``attacker_addr``
can siphon the operator's per-/24 IP cooldown and per-window cap through
the visitor pool.

Abstraction-over-symptom fix: validate Content-Type at the shared POST
entry so every current and future POST route inherits the gate
unconditionally.

These tests exercise the gate at the HTTP boundary.  ``application/json``
bodies still process; ``text/plain``, ``application/x-www-form-urlencoded``,
``multipart/form-data``, and missing-Content-Type bodies are refused
with 415 BEFORE any rate-limit / PoW state is touched.  The same gate
covers ``/quickpost``.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from messagechain.network.faucet import FaucetState
from messagechain.network.public_feed_server import PublicFeedServer
from messagechain.network.quickpost import QuickpostState


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChain:
    def __init__(self):
        self.height = 0
        self.chain = [SimpleNamespace(header=SimpleNamespace(timestamp=1_700_000_000.0))]

    def get_recent_messages(self, count):
        return []


class _StubFaucet:
    """Records (try_drip, issue_challenge) calls so tests can assert
    the gate is enforced BEFORE any faucet state is consulted."""

    def __init__(self):
        self.try_drip_calls = 0
        self.issue_challenge_calls = 0

    def try_drip(self, *args, **kwargs):
        self.try_drip_calls += 1
        # Match FaucetDripResult duck-typed shape — these tests should
        # never reach this code path; if they do, the test will fail
        # on the request-count assertion below.
        return SimpleNamespace(ok=False, error="should not be reached",
                               remaining_window=0, tx_hash="", amount=0)

    def issue_challenge(self, address_hex):
        self.issue_challenge_calls += 1
        return True, "", {
            "seed": "ab" * 16,
            "address": address_hex,
            "difficulty": 8,
            "expires_at": time.time() + 60,
            "ttl_sec": 60,
        }


class _StubQuickpost:
    def __init__(self):
        self.try_quickpost_calls = 0
        self.issue_challenge_calls = 0

    def try_quickpost(self, *args, **kwargs):
        self.try_quickpost_calls += 1
        return SimpleNamespace(
            ok=False, error="should not be reached",
            entity_id_hex="", private_key_hex="", drip_tx_hash="",
            remaining_window=0,
        )

    def issue_challenge(self):
        self.issue_challenge_calls += 1
        return True, "", {
            "seed": "cd" * 16,
            "difficulty": 8,
            "expires_at": time.time() + 60,
            "ttl_sec": 60,
        }


class TestPostContentTypeGate(unittest.TestCase):

    def setUp(self):
        self.chain = _StubChain()
        self.faucet = _StubFaucet()
        self.quickpost = _StubQuickpost()
        self.port = _find_free_port()
        self.server = PublicFeedServer(
            blockchain=self.chain, port=self.port, bind="127.0.0.1",
            faucet=self.faucet, quickpost=self.quickpost,
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.1,
                ):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.server.stop()
            raise RuntimeError("PublicFeedServer never came up")

    def tearDown(self):
        self.server.stop()

    def _post(self, path: str, body: bytes, content_type: str | None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            headers = {"Content-Length": str(len(body))}
            if content_type is not None:
                headers["Content-Type"] = content_type
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_faucet_rejects_text_plain(self):
        body = json.dumps({"address": "ab" * 32, "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, raw = self._post("/faucet", body, "text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(self.faucet.try_drip_calls, 0,
                         "Content-Type gate must short-circuit before try_drip")

    def test_faucet_rejects_form_urlencoded(self):
        body = b"address=cafe"
        status, _ = self._post(
            "/faucet", body, "application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 415)
        self.assertEqual(self.faucet.try_drip_calls, 0)

    def test_faucet_rejects_multipart(self):
        body = b"--x--\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--x--\r\n"
        status, _ = self._post(
            "/faucet", body, "multipart/form-data; boundary=x",
        )
        self.assertEqual(status, 415)
        self.assertEqual(self.faucet.try_drip_calls, 0)

    def test_faucet_rejects_missing_content_type(self):
        body = json.dumps({"address": "ab" * 32, "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, _ = self._post("/faucet", body, None)
        self.assertEqual(status, 415)
        self.assertEqual(self.faucet.try_drip_calls, 0)

    def test_faucet_accepts_application_json(self):
        body = json.dumps({"address": "ab" * 32, "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, raw = self._post("/faucet", body, "application/json")
        # The stub's try_drip returns ok=False so we expect 4xx/2xx
        # from the handler — the precise code is not what we're
        # testing; we're testing that the request REACHED try_drip.
        self.assertNotEqual(status, 415)
        self.assertGreaterEqual(self.faucet.try_drip_calls, 1)

    def test_faucet_accepts_application_json_with_charset(self):
        body = json.dumps({"address": "ab" * 32, "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, _ = self._post(
            "/faucet", body, "application/json; charset=utf-8",
        )
        self.assertNotEqual(status, 415)
        self.assertGreaterEqual(self.faucet.try_drip_calls, 1)

    def test_quickpost_rejects_text_plain(self):
        body = json.dumps({"message": "hi", "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, _ = self._post("/quickpost", body, "text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(self.quickpost.try_quickpost_calls, 0)

    def test_quickpost_accepts_application_json(self):
        body = json.dumps({"message": "hi", "challenge_seed": "cd" * 16,
                           "nonce": 1}).encode()
        status, _ = self._post("/quickpost", body, "application/json")
        self.assertNotEqual(status, 415)
        self.assertGreaterEqual(self.quickpost.try_quickpost_calls, 1)


if __name__ == "__main__":
    unittest.main()
