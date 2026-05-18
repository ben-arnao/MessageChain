"""Regression: ``/wallet/create-account`` MUST honor ``X-Forwarded-For``
from a configured trusted proxy when resolving the rate-limit bucket key.

Without this, every real user behind a TLS-terminating reverse proxy
(messagechain.org runs Caddy on 127.0.0.1) coalesces into the proxy's
loopback /24 (``127.0.0.0/24``).  The faucet's per-/24 cooldown then
makes one real user lock out every other real user for the full
cooldown window -- observed in production on 2026-05-18 when a single
smoke-test curl drained the slot and the next browser visitor got
``faucet drip refused: this network (127.0.0.0/24) already received a
drip recently; try again in 13.4 min``.

Mirrors the same XFF semantics already enforced by
``public_feed_server`` (and tested in
``tests/test_public_feed_trusted_proxies.py``): rightmost token,
trusted-proxy CIDR gate, malformed-token-to-unattributable-bucket.
This test guards the wiring on the wallet UI side; the underlying
``_resolve_client_ip`` helper is tested separately.
"""

import http.client
import json
import socket
import time
import unittest

from messagechain.network.local_wallet_server import LocalWalletServer
from messagechain.network.public_feed_server import _parse_trusted_proxies


class _StubChain:
    """Minimal blockchain stand-in: the create-account handler does not
    read any chain state directly (the faucet is a fake)."""
    height = 1
    def get_chain_info(self):
        return {"height": self.height}


class _RecordingFaucet:
    """Records every ``drip_for_quickpost(ip, recipient)`` call so the
    test can assert which IP the handler resolved."""
    def __init__(self):
        self.calls = []
    def drip_for_quickpost(self, ip, recipient_bytes):
        from messagechain.network.faucet import FaucetDripResult
        self.calls.append({"ip": ip, "recipient": bytes(recipient_bytes)})
        return FaucetDripResult(
            ok=True, tx_hash="ab" * 32, remaining_window=10,
        )


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_listen(port: int, deadline: float = 2.0) -> None:
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"LocalWalletServer never came up on {port}")


def _post_with_headers(port: int, path: str, extra_headers: dict, body: dict):
    """POST with arbitrary extra headers (including X-Forwarded-For)."""
    headers = {"Content-Type": "application/json"}
    headers.update(extra_headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("POST", path, body=json.dumps(body), headers=headers)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read() or b"{}")
    finally:
        conn.close()


class TestWalletCreateAccountTrustsXFFFromConfiguredProxy(unittest.TestCase):
    def setUp(self):
        # Shrink demo-account tree so the test's keygen is sub-second
        # even on the loaded xdist workers (matches the existing
        # create-account test's pattern in test_local_wallet_server.py).
        import messagechain.network.local_wallet_server as lws
        self._orig_height = lws.DEMO_ACCOUNT_TREE_HEIGHT
        lws.DEMO_ACCOUNT_TREE_HEIGHT = 4

    def tearDown(self):
        import messagechain.network.local_wallet_server as lws
        lws.DEMO_ACCOUNT_TREE_HEIGHT = self._orig_height

    def _spin_up(self, *, trusted_proxies):
        port = _find_free_port()
        srv = LocalWalletServer(
            blockchain=_StubChain(),
            port=port,
            bind="127.0.0.1",
            public_mode=True,
            trusted_proxies=trusted_proxies,
        )
        faucet = _RecordingFaucet()
        srv.faucet = faucet
        srv.start()
        _wait_for_listen(port)
        self.addCleanup(srv.stop)
        return srv, port, faucet

    def test_xff_from_trusted_proxy_overrides_socket_peer(self):
        """When trusted_proxies includes the socket peer, the rate-limit
        bucket key resolves to the rightmost X-Forwarded-For token --
        the REAL client's IP -- not the loopback proxy address.

        This is the exact misbehavior that locked out users on
        messagechain.org: socket peer was Caddy (127.0.0.1), no XFF
        honoring, every real user collapsed onto 127.0.0.0/24.
        """
        trusted = _parse_trusted_proxies("127.0.0.1/32")
        _, port, faucet = self._spin_up(trusted_proxies=trusted)

        status, body = _post_with_headers(
            port, "/wallet/create-account",
            {"X-Forwarded-For": "203.0.113.42"},
            {"duration_sec": 3600},
        )
        self.assertEqual(status, 200, msg=body)
        self.assertEqual(len(faucet.calls), 1)
        self.assertEqual(
            faucet.calls[0]["ip"], "203.0.113.42",
            "When the socket peer is on the trusted_proxies allowlist "
            "the handler MUST resolve the rate-limit bucket from the "
            "rightmost X-Forwarded-For token, not from the raw TCP "
            "source address.",
        )

    def test_xff_ignored_when_socket_peer_is_not_trusted(self):
        """When the trusted_proxies list does NOT include the socket
        peer's CIDR, an attacker-supplied X-Forwarded-For is ignored
        and the rate-limit bucket falls back to the raw TCP source.
        Otherwise any client could spoof their bucket key by sending
        a header.
        """
        trusted = _parse_trusted_proxies("10.99.99.99/32")  # NOT 127.0.0.1
        _, port, faucet = self._spin_up(trusted_proxies=trusted)

        status, body = _post_with_headers(
            port, "/wallet/create-account",
            {"X-Forwarded-For": "203.0.113.42"},
            {"duration_sec": 3600},
        )
        self.assertEqual(status, 200, msg=body)
        self.assertEqual(len(faucet.calls), 1)
        self.assertEqual(
            faucet.calls[0]["ip"], "127.0.0.1",
            "X-Forwarded-For from an untrusted peer MUST be ignored. "
            "Otherwise an attacker could rotate buckets by spoofing "
            "the header, defeating the per-/24 cooldown.",
        )

    def test_no_trusted_proxies_preserves_raw_socket_source(self):
        """Default (no --trusted-proxies configured) preserves the
        legacy behavior: rate-limit bucket = raw TCP socket source.
        This is the right default for personal / no-proxy installs.
        """
        _, port, faucet = self._spin_up(trusted_proxies=None)

        status, body = _post_with_headers(
            port, "/wallet/create-account",
            {"X-Forwarded-For": "203.0.113.42"},
            {"duration_sec": 3600},
        )
        self.assertEqual(status, 200, msg=body)
        self.assertEqual(len(faucet.calls), 1)
        self.assertEqual(faucet.calls[0]["ip"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
