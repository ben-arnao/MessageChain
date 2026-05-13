"""
Foot-gun defenses for the local wallet UI server.

Unlike PublicFeedServer (read-only, public bind, full CORS), the
LocalWalletServer holds a user's private key in process memory and
exposes signing routes under /wallet/*.  If anything other than the
user's own browser tab can reach those routes, the key is drained.

Every test here exists because removing the corresponding defense
turns the wallet server into a key-stealing endpoint.  Treat failures
as security regressions, not stylistic ones.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace

from messagechain.network.local_wallet_server import (
    LocalWalletServer,
    LoopbackBindError,
)


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChain:
    """Minimal duck-typed blockchain.  The empty-shell wallet server
    does not call into chain state yet; this is a placeholder so the
    constructor signature stays stable as real read routes are added."""

    def __init__(self):
        self.height = 0
        last = SimpleNamespace(header=SimpleNamespace(timestamp=1_700_000_000.0))
        self.chain = [last]

    def get_recent_messages(self, count):
        return []


class _WalletServerTestBase(unittest.TestCase):
    """Spin a server up on a fresh port; tear it down in tearDown."""

    def _spin_up(self, **kwargs):
        port = _find_free_port()
        defaults = dict(blockchain=_StubChain(), port=port, bind="127.0.0.1")
        defaults.update(kwargs)
        server = LocalWalletServer(**defaults)
        server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            server.stop()
            raise RuntimeError("LocalWalletServer never came up")
        self.addCleanup(server.stop)
        return server, port

    def _request(self, port, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()


# -----------------------------------------------------------------
# Defense 1 — bind enforcement.
# The server refuses any non-loopback bind at construction time.
# Removing this and binding to 0.0.0.0 would expose /wallet/* to the
# entire local network: a roommate / coworker / public-wifi attacker
# could pull the wallet's signing routes with no token (token alone
# is insufficient — see defense 3 for why).
# -----------------------------------------------------------------
class TestBindEnforcement(unittest.TestCase):
    def test_refuses_zero_bind(self):
        with self.assertRaises(LoopbackBindError):
            LocalWalletServer(_StubChain(), port=9999, bind="0.0.0.0")

    def test_refuses_external_ip_bind(self):
        with self.assertRaises(LoopbackBindError):
            LocalWalletServer(_StubChain(), port=9999, bind="192.168.1.1")

    def test_refuses_empty_bind(self):
        # Empty string can imply "all interfaces" depending on the
        # socket library — fail closed.
        with self.assertRaises(LoopbackBindError):
            LocalWalletServer(_StubChain(), port=9999, bind="")

    def test_refuses_hostname_bind(self):
        # Even "localhost" is rejected — the hosts file can be
        # tampered with, and we want defense in depth: the bind
        # value must be a literal loopback IP.
        with self.assertRaises(LoopbackBindError):
            LocalWalletServer(_StubChain(), port=9999, bind="localhost")

    def test_accepts_loopback_v4(self):
        srv = LocalWalletServer(_StubChain(), port=9999, bind="127.0.0.1")
        self.assertEqual(srv.bind, "127.0.0.1")

    def test_accepts_loopback_v6(self):
        srv = LocalWalletServer(_StubChain(), port=9999, bind="::1")
        self.assertEqual(srv.bind, "::1")


# -----------------------------------------------------------------
# Defense 2 — Host header allowlist.
# Defends against DNS rebinding: a malicious page resolves its own
# DNS name (e.g. evil.com) to 127.0.0.1, tricking the browser's
# same-origin policy into letting JS from evil.com talk to the
# wallet server.  The browser's outbound packet still carries
# `Host: evil.com`, which is the smoking-gun signal.  Reject it.
# -----------------------------------------------------------------
class TestHostHeaderAllowlist(_WalletServerTestBase):
    def test_rejects_attacker_host_header(self):
        srv, port = self._spin_up()
        headers = {
            "Host": "evil.com",
            "Authorization": f"Bearer {srv.token}",
        }
        status, _, _ = self._request(port, "GET", "/wallet/ping", headers=headers)
        self.assertEqual(status, 403)

    def test_rejects_attacker_host_header_even_on_health(self):
        # /health bypasses the token gate but NOT the Host gate.
        # An attacker page that can't reach /wallet shouldn't be able
        # to confirm the wallet server is running either.
        srv, port = self._spin_up()
        headers = {"Host": "evil.com"}
        status, _, _ = self._request(port, "GET", "/health", headers=headers)
        self.assertEqual(status, 403)

    def test_accepts_127_0_0_1_host_header(self):
        srv, port = self._spin_up()
        headers = {
            "Host": f"127.0.0.1:{port}",
            "Authorization": f"Bearer {srv.token}",
        }
        status, _, _ = self._request(port, "GET", "/wallet/ping", headers=headers)
        self.assertEqual(status, 200)

    def test_accepts_localhost_host_header(self):
        srv, port = self._spin_up()
        headers = {
            "Host": f"localhost:{port}",
            "Authorization": f"Bearer {srv.token}",
        }
        status, _, _ = self._request(port, "GET", "/wallet/ping", headers=headers)
        self.assertEqual(status, 200)

    def test_accepts_v6_loopback_host_header(self):
        # `[::1]:9335` form per RFC 7230.
        srv, port = self._spin_up()
        headers = {
            "Host": f"[::1]:{port}",
            "Authorization": f"Bearer {srv.token}",
        }
        status, _, _ = self._request(port, "GET", "/wallet/ping", headers=headers)
        self.assertEqual(status, 200)


# -----------------------------------------------------------------
# Defense 3 — per-session token gate on /wallet/*.
# Without this, any local process (a curl from a malware payload,
# any other browser tab the user happened to have open) could hit
# the wallet routes and drain the key.  Token is generated fresh at
# startup, never written to disk, and rotated on every restart.
# -----------------------------------------------------------------
class TestTokenGate(_WalletServerTestBase):
    def test_wallet_route_requires_token(self):
        srv, port = self._spin_up()
        status, _, _ = self._request(port, "GET", "/wallet/ping")
        self.assertEqual(status, 401)

    def test_wallet_route_rejects_wrong_bearer(self):
        srv, port = self._spin_up()
        headers = {"Authorization": "Bearer not-the-real-token"}
        status, _, _ = self._request(port, "GET", "/wallet/ping", headers=headers)
        self.assertEqual(status, 401)

    def test_wallet_route_accepts_correct_bearer(self):
        srv, port = self._spin_up()
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/wallet/ping", headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_wallet_route_accepts_query_token_for_initial_load(self):
        # The landing-page bootstrap loads with `?t=<token>` in the
        # URL bar; the page then stashes the token in sessionStorage
        # and never sends it as a query param again.  Server must
        # accept query-string tokens for this initial hop.
        srv, port = self._spin_up()
        status, _, body = self._request(
            port, "GET", f"/wallet/ping?t={srv.token}",
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_health_endpoint_does_not_require_token(self):
        # /health is for the operator's `messagechain ui`-side
        # readiness probe.  No token, but still loopback + Host-gated.
        srv, port = self._spin_up()
        status, _, body = self._request(port, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_token_auto_generated_random_when_omitted(self):
        srv_a = LocalWalletServer(_StubChain(), port=9001, bind="127.0.0.1")
        srv_b = LocalWalletServer(_StubChain(), port=9002, bind="127.0.0.1")
        self.assertNotEqual(srv_a.token, srv_b.token)
        # Reasonable randomness floor — any strong random source
        # produces tokens well above 32 chars.
        self.assertGreaterEqual(len(srv_a.token), 32)

    def test_explicit_token_used_verbatim(self):
        srv = LocalWalletServer(
            _StubChain(),
            port=9999,
            bind="127.0.0.1",
            token="known-fixed-token-for-tests",
        )
        self.assertEqual(srv.token, "known-fixed-token-for-tests")


# -----------------------------------------------------------------
# Defense 4 — no CORS on wallet routes.
# PublicFeedServer sets `Access-Control-Allow-Origin: *` because the
# data is public.  Wallet routes must NOT.  Combined with the token
# gate this is belt-and-suspenders: if someone somehow leaks the
# token, the absence of CORS still prevents a malicious origin from
# reading wallet response bodies in a browser.
# -----------------------------------------------------------------
class TestNoCORSOnWalletRoutes(_WalletServerTestBase):
    def test_wallet_route_does_not_set_cors_headers(self):
        srv, port = self._spin_up()
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, resp_headers, _ = self._request(
            port, "GET", "/wallet/ping", headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", resp_headers)
        self.assertNotIn("Access-Control-Allow-Methods", resp_headers)
        self.assertNotIn("Access-Control-Allow-Headers", resp_headers)


# -----------------------------------------------------------------
# Sanity — landing-page URL must include the session token so the
# operator can paste it into a browser and have the page bootstrap
# itself.  Browsers don't expose Authorization headers on initial
# navigation; the URL token is the one-shot handoff.
# -----------------------------------------------------------------
class TestUrlProperty(unittest.TestCase):
    def test_url_includes_token_and_loopback(self):
        srv = LocalWalletServer(
            _StubChain(),
            port=9999,
            bind="127.0.0.1",
            token="abc123",
        )
        self.assertEqual(srv.url, "http://127.0.0.1:9999/?t=abc123")


# -----------------------------------------------------------------
# Read endpoints — /v1/info, /v1/latest, /v1/entity, /v1/tx_status.
# These are RPC-proxies to the local validator.  The wallet UI reuses
# the same JSON shape as PublicFeedServer's /v1/* surface so the
# client JS works against either backend unchanged.
#
# All read endpoints are token-gated — the wallet UI is private to
# the user, and even read scrapes (e.g. "what feed is the operator
# looking at right now?") shouldn't be available to other local
# processes.
# -----------------------------------------------------------------
def _make_fake_rpc(handlers):
    """Build a (method, params) -> dict callable from a method->fn map.
    Unmapped methods raise so a forgotten stub blows up loudly in tests."""
    def _call(method, params):
        if method not in handlers:
            raise NotImplementedError(f"fake_rpc: no handler for {method!r}")
        return handlers[method](params)
    return _call


class TestV1Info(_WalletServerTestBase):
    def test_returns_chain_info_in_public_feed_shape(self):
        rpc = _make_fake_rpc({
            "get_chain_info": lambda p: {"ok": True, "result": {
                "height": 42,
                "last_block_timestamp": 1_700_000_999.0,
                "genesis_hash": "ab" * 32,
                "tip_hash": "cd" * 32,
                "state_root": "ef" * 32,
            }},
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/v1/info", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["height"], 42)
        self.assertEqual(data["last_block_timestamp"], 1_700_000_999.0)
        self.assertEqual(data["genesis_hash"], "ab" * 32)
        self.assertEqual(data["tip_hash"], "cd" * 32)
        self.assertEqual(data["state_root"], "ef" * 32)
        # Wallet server doesn't run a faucet/quickpost — surface
        # always-false so the client-side check returns clean.
        self.assertFalse(data["faucet_enabled"])
        self.assertFalse(data["quickpost_enabled"])
        # chain_id is the on-chain constant; should be a string.
        self.assertIsInstance(data["chain_id"], str)

    def test_token_required(self):
        srv, port = self._spin_up()
        status, _, _ = self._request(port, "GET", "/v1/info")
        self.assertEqual(status, 401)

    def test_503_when_rpc_unreachable(self):
        # Simulate the local validator being down — the RPC caller
        # raises ConnectionError.  Wallet server should report 503,
        # not crash, and not lie with a stale 200.
        def _raises(method, params):
            raise ConnectionError("validator not running")
        srv, port = self._spin_up(rpc_caller=_raises)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/v1/info", headers=headers,
        )
        self.assertEqual(status, 503)
        data = json.loads(body)
        self.assertFalse(data["ok"])


class TestV1Latest(_WalletServerTestBase):
    def test_returns_messages_with_height(self):
        sample = [
            {
                "message": "hello", "entity_id": "ab" * 32,
                "timestamp": 1_700_000_000.0, "tx_hash": "cd" * 32,
                "block_number": 5,
            },
        ]
        rpc = _make_fake_rpc({
            "get_messages": lambda p: {
                "ok": True, "result": {"messages": sample},
            },
            "get_chain_info": lambda p: {
                "ok": True, "result": {"height": 7},
            },
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/v1/latest?limit=10", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["height"], 7)
        self.assertEqual(data["messages"], sample)

    def test_clamps_limit_to_max(self):
        captured = {}
        def _gm(p):
            captured["count"] = p.get("count")
            return {"ok": True, "result": {"messages": []}}
        rpc = _make_fake_rpc({
            "get_messages": _gm,
            "get_chain_info": lambda p: {"ok": True, "result": {"height": 0}},
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, _ = self._request(
            port, "GET", "/v1/latest?limit=99999", headers=headers,
        )
        self.assertEqual(status, 200)
        # Same clamp as PublicFeedServer (PUBLIC_FEED_MAX_LIMIT).
        from messagechain.config import PUBLIC_FEED_MAX_LIMIT
        self.assertEqual(captured["count"], PUBLIC_FEED_MAX_LIMIT)

    def test_invalid_limit_returns_400(self):
        rpc = _make_fake_rpc({})  # never called
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/v1/latest?limit=garbage", headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])


class TestV1Entity(_WalletServerTestBase):
    def test_returns_entity_payload(self):
        rpc = _make_fake_rpc({
            "get_entity": lambda p: {
                "ok": True,
                "result": {
                    "entity_id": p["entity_id"],
                    "balance": 1234,
                    "stake": 200,
                    "pubkey_registered": True,
                    "sigs_remaining": 10000,
                },
            },
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        eid = "ab" * 32
        status, _, body = self._request(
            port, "GET", f"/v1/entity?id={eid}", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["entity_id"], eid)
        self.assertEqual(data["result"]["balance"], 1234)

    def test_invalid_id_returns_400(self):
        rpc = _make_fake_rpc({})  # never called
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/v1/entity?id=not-hex", headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])

    def test_unknown_entity_returns_404(self):
        rpc = _make_fake_rpc({
            "get_entity": lambda p: {"ok": False, "error": "Entity not found"},
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, _ = self._request(
            port, "GET", f"/v1/entity?id={'00' * 32}", headers=headers,
        )
        self.assertEqual(status, 404)


# -----------------------------------------------------------------
# /wallet/me — the "you" panel.  Composes loaded-Entity local data
# (entity_id, WOTS+ leaf accounting) with on-chain stats fetched via
# RPC (balance, stake, pubkey_registered).  Read-only mode (no key
# loaded) returns ok=true with mode="read-only" so the UI can render
# a "load a wallet" affordance.
# -----------------------------------------------------------------
class TestWalletMe(_WalletServerTestBase):
    def test_read_only_when_no_entity_loaded(self):
        # No entity passed to the server -- the cmd_ui --read-only
        # path takes this branch.  Should NOT 503; the UI needs a
        # 200 to render its "load a wallet" call-to-action.
        srv, port = self._spin_up()
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/wallet/me", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["mode"], "read-only")
        self.assertIsNone(data["entity_id"])
        self.assertIsNone(data["balance"])
        self.assertIsNone(data["sigs_remaining"])

    def test_with_loaded_entity_returns_id_and_chain_stats(self):
        eid_hex = "ab" * 32
        fake_entity = SimpleNamespace(
            entity_id_hex=eid_hex,
            entity_id=bytes.fromhex(eid_hex),
            keypair=SimpleNamespace(num_leaves=1024, _next_leaf=42),
        )
        rpc = _make_fake_rpc({
            "get_entity": lambda p: {
                "ok": True,
                "result": {
                    "entity_id": p["entity_id"],
                    "balance": 9001,
                    "stake": 100,
                    "pubkey_registered": True,
                },
            },
        })
        srv, port = self._spin_up(entity=fake_entity, rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/wallet/me", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["mode"], "wallet")
        self.assertEqual(data["entity_id"], eid_hex)
        self.assertEqual(data["balance"], 9001)
        self.assertEqual(data["stake"], 100)
        self.assertTrue(data["pubkey_registered"])
        # 1024 leaves total, 42 used -> 982 remaining.
        self.assertEqual(data["sigs_remaining"], 1024 - 42)

    def test_chain_unreachable_still_returns_local_fields(self):
        # An offline validator should NOT take the entire panel
        # offline.  The page can still render entity_id +
        # sigs_remaining (both purely local) with a "chain offline"
        # banner; that's far better UX than a 503 wipe.
        eid_hex = "cd" * 32
        fake_entity = SimpleNamespace(
            entity_id_hex=eid_hex,
            entity_id=bytes.fromhex(eid_hex),
            keypair=SimpleNamespace(num_leaves=2048, _next_leaf=0),
        )
        def _raises(method, params):
            raise ConnectionError("validator down")
        srv, port = self._spin_up(entity=fake_entity, rpc_caller=_raises)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, body = self._request(
            port, "GET", "/wallet/me", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["entity_id"], eid_hex)
        self.assertEqual(data["sigs_remaining"], 2048)
        self.assertIsNone(data["balance"])
        self.assertIsNone(data["stake"])

    def test_token_required(self):
        srv, port = self._spin_up()
        status, _, _ = self._request(port, "GET", "/wallet/me")
        self.assertEqual(status, 401)


class TestV1TxStatus(_WalletServerTestBase):
    def test_returns_tx_status(self):
        rpc = _make_fake_rpc({
            "get_tx_status": lambda p: {
                "ok": True,
                "result": {
                    "tx_hash": p["tx_hash"],
                    "in_mempool": False,
                    "block_height": 99,
                },
            },
        })
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        tx = "12" * 32
        status, _, body = self._request(
            port, "GET", f"/v1/tx_status?tx_hash={tx}", headers=headers,
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["block_height"], 99)

    def test_invalid_tx_hash_returns_400(self):
        rpc = _make_fake_rpc({})
        srv, port = self._spin_up(rpc_caller=rpc)
        headers = {"Authorization": f"Bearer {srv.token}"}
        status, _, _ = self._request(
            port, "GET", "/v1/tx_status?tx_hash=short", headers=headers,
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
