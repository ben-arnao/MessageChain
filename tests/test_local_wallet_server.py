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


if __name__ == "__main__":
    unittest.main()
