"""
Tests for the public read-only feed endpoint.

The feed exposes `GET /v1/latest` + a bundled HTML viewer so non-
technical visitors have a thing to click.  It's read-only, plain HTTP
(operators front it with Caddy for TLS), and rate-limited.

Tests stub the blockchain to a tiny duck-typed object.  The feed
server only calls `blockchain.get_recent_messages(count)`,
`blockchain.height`, and `blockchain.chain[-1].header.timestamp`,
so there's no need to spin up a full chain.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import unittest
from types import SimpleNamespace

from messagechain.config import (
    CHAIN_ID,
    PUBLIC_FEED_BURST,
    PUBLIC_FEED_MAX_LIMIT,
)
from messagechain.network.public_feed_server import PublicFeedServer


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChain:
    """Minimal duck-typed blockchain for feed tests."""

    def __init__(self, messages=None, height=0, last_block_ts=1_700_000_000.0):
        self._messages = list(messages or [])
        self.height = height
        last_block = SimpleNamespace(
            header=SimpleNamespace(timestamp=last_block_ts),
        )
        # `chain` accessed like `chain.chain[-1]` in the feed server.
        self.chain = [last_block] if last_block_ts is not None else []

    def get_recent_messages(self, count: int) -> list[dict]:
        return self._messages[:count]


class PublicFeedTestBase(unittest.TestCase):
    def _spin_up(self, chain) -> tuple[PublicFeedServer, int]:
        port = _find_free_port()
        server = PublicFeedServer(
            blockchain=chain, port=port, bind="127.0.0.1",
        )
        server.start()
        # Wait for socket to accept connections.
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

    def setUp(self):
        self.messages = [
            {
                "message": "hello world",
                "entity_id": "ab" * 32,
                "timestamp": 1_700_000_000.0,
                "tx_hash": "cd" * 32,
                "block_number": 5,
            },
            {
                "message": "second message",
                "entity_id": "ef" * 32,
                "timestamp": 1_700_000_060.0,
                "tx_hash": "12" * 32,
                "block_number": 5,
            },
        ]
        self.chain = _StubChain(
            messages=self.messages, height=5, last_block_ts=1_700_000_060.0,
        )
        self.server, self.port = self._spin_up(self.chain)

    def tearDown(self):
        self.server.stop()

    def _get(self, path: str, method: str = "GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()


class TestLatestEndpoint(PublicFeedTestBase):
    def test_latest_returns_messages(self):
        status, headers, body = self._get("/v1/latest")
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Content-Type"),
            "application/json; charset=utf-8",
        )
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["height"], 5)
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(data["messages"][0]["message"], "hello world")
        self.assertEqual(data["messages"][1]["message"], "second message")

    def test_latest_respects_limit(self):
        status, _, body = self._get("/v1/latest?limit=1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["messages"]), 1)

    def test_latest_clamps_over_max_limit(self):
        status, _, body = self._get(
            f"/v1/latest?limit={PUBLIC_FEED_MAX_LIMIT + 500}",
        )
        self.assertEqual(status, 200)
        # We only stubbed two messages; the clamp is verified by the
        # call not returning an error and by the handler having
        # requested at most PUBLIC_FEED_MAX_LIMIT (stub would have
        # returned more if asked). Separate unit check below.
        data = json.loads(body)
        self.assertEqual(len(data["messages"]), 2)

    def test_latest_clamp_actually_passed_to_chain(self):
        """Verify the feed passes a clamped count to the chain."""
        observed = []

        class _Spy(_StubChain):
            def get_recent_messages(self, count: int):
                observed.append(count)
                return []

        self.server.stop()
        self.chain = _Spy(height=0, last_block_ts=None)
        self.server, self.port = self._spin_up(self.chain)
        self._get(f"/v1/latest?limit={PUBLIC_FEED_MAX_LIMIT + 1000}")
        self.assertEqual(observed, [PUBLIC_FEED_MAX_LIMIT])

    def test_latest_invalid_limit_returns_400(self):
        status, _, body = self._get("/v1/latest?limit=not-a-number")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertFalse(data["ok"])

    def test_latest_negative_limit_treated_as_one(self):
        status, _, body = self._get("/v1/latest?limit=-5")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["messages"]), 1)


class TestInfoEndpoint(PublicFeedTestBase):
    def test_info_returns_chain_metadata(self):
        status, _, body = self._get("/v1/info")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["chain_id"], CHAIN_ID.decode("ascii"))
        self.assertEqual(data["height"], 5)
        self.assertEqual(data["last_block_timestamp"], 1_700_000_060.0)

    def test_info_handles_empty_chain(self):
        self.server.stop()
        self.chain = _StubChain(messages=[], height=0, last_block_ts=None)
        self.server, self.port = self._spin_up(self.chain)
        status, _, body = self._get("/v1/info")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIsNone(data["last_block_timestamp"])


class TestHealthEndpoint(PublicFeedTestBase):
    def test_health_returns_ok(self):
        status, _, body = self._get("/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])

    def test_health_not_rate_limited(self):
        """Reverse-proxy health checks must not consume the rate budget."""
        # Burn through the burst on /v1/latest first, then prove /health
        # still returns 200.  (If the feed rate-limit applied to /health,
        # /health would start returning 429 after BURST+1 reqs.)
        for _ in range(PUBLIC_FEED_BURST):
            self._get("/v1/latest?limit=1")
        status, _, _ = self._get("/health")
        self.assertEqual(status, 200)


class TestStaticPage(PublicFeedTestBase):
    def test_root_serves_html(self):
        status, headers, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertTrue(
            headers.get("Content-Type", "").startswith("text/html"),
        )
        self.assertIn(b"MessageChain", body)
        self.assertIn(b"/v1/latest", body)  # HTML polls the JSON endpoint


class TestMethodAndPathGating(PublicFeedTestBase):
    def test_post_returns_405(self):
        status, _, _ = self._get("/v1/latest", method="POST")
        self.assertEqual(status, 405)

    def test_put_returns_405(self):
        status, _, _ = self._get("/v1/latest", method="PUT")
        self.assertEqual(status, 405)

    def test_unknown_path_returns_404(self):
        status, _, _ = self._get("/v1/not-a-thing")
        self.assertEqual(status, 404)

    def test_options_returns_204_with_cors(self):
        status, headers, _ = self._get("/v1/latest", method="OPTIONS")
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")
        self.assertIn("GET", headers.get("Access-Control-Allow-Methods", ""))


class TestCors(PublicFeedTestBase):
    def test_cors_header_present_on_latest(self):
        _, headers, _ = self._get("/v1/latest")
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")

    def test_cors_header_present_on_info(self):
        _, headers, _ = self._get("/v1/info")
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")


class TestRateLimit(PublicFeedTestBase):
    def test_excessive_requests_get_429(self):
        """After the burst budget is exhausted, /v1/latest 429s."""
        hit_429 = False
        for _ in range(PUBLIC_FEED_BURST + 20):
            status, _, _ = self._get("/v1/latest?limit=1")
            if status == 429:
                hit_429 = True
                break
        self.assertTrue(
            hit_429,
            f"expected 429 within {PUBLIC_FEED_BURST + 20} bursts",
        )


class TestXssSafety(PublicFeedTestBase):
    """Regression: the bundled HTML page must render message text via
    textContent (not innerHTML) so `<script>` in a message doesn't run.

    We can't exec JS here, but we can assert the page never writes raw
    message text into the DOM — the whole render path goes through
    `textContent = m.message`.
    """

    def test_feed_page_uses_text_content(self):
        _, _, body = self._get("/")
        src = body.decode("utf-8")
        self.assertIn("textContent = m.message", src)
        self.assertNotIn("innerHTML = m.message", src)
        self.assertNotIn(".innerHTML=m.message", src)


class TestGitHubRedirect(PublicFeedTestBase):
    """`/gh` is a 302 redirect to the public GitHub repo so operators
    can count outbound clicks via the access log instead of losing them
    to a bare anchor href."""

    GITHUB_URL = "https://github.com/ben-arnao/MessageChain"

    def test_gh_returns_302(self):
        status, _, _ = self._get("/gh")
        self.assertEqual(status, 302)

    def test_gh_location_points_to_repo(self):
        _, headers, _ = self._get("/gh")
        self.assertEqual(headers.get("Location"), self.GITHUB_URL)

    def test_gh_post_returns_405(self):
        status, _, _ = self._get("/gh", method="POST")
        self.assertEqual(status, 405)

    def test_feed_page_links_through_redirect(self):
        _, _, body = self._get("/")
        src = body.decode("utf-8")
        self.assertIn('href="/gh"', src)
        self.assertNotIn('href="https://github.com/ben-arnao', src)

    def test_gh_start_returns_302_to_getting_started(self):
        """`/gh/start` deep-links to the README's getting-started anchor
        instead of the repo top, so the "send a message" CTA on the
        landing page drops casual visitors at the install +
        first-message walkthrough rather than the install-from-source
        weeds."""
        status, headers, _ = self._get("/gh/start")
        self.assertEqual(status, 302)
        self.assertEqual(
            headers.get("Location"),
            self.GITHUB_URL + "#getting-started--your-first-message",
        )

    def test_gh_start_post_returns_405(self):
        status, _, _ = self._get("/gh/start", method="POST")
        self.assertEqual(status, 405)

    def test_gh_node_returns_302_to_run_a_validator(self):
        """`/gh/node` deep-links to the README's run-a-validator anchor
        for the "run a node to earn tokens" CTA on the landing page."""
        status, headers, _ = self._get("/gh/node")
        self.assertEqual(status, 302)
        self.assertEqual(
            headers.get("Location"),
            self.GITHUB_URL + "#run-a-validator",
        )

    def test_gh_node_post_returns_405(self):
        status, _, _ = self._get("/gh/node", method="POST")
        self.assertEqual(status, 405)


class TestScrollBeacon(PublicFeedTestBase):
    """`/beacon/scroll` is a tiny 204 endpoint the homepage's JS hits
    once when the visitor has scrolled past the initial fold.  The
    response carries no body — the only signal operators need is the
    request landing in the access log, paired with the visitor IP."""

    def test_beacon_scroll_returns_204(self):
        status, _, body = self._get("/beacon/scroll")
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

    def test_beacon_scroll_no_store(self):
        """The beacon must not be cached anywhere — Caddy/CDN/browser.
        A cached 204 would hide repeat visits and skew the engagement
        signal."""
        _, headers, _ = self._get("/beacon/scroll")
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_beacon_scroll_post_returns_405(self):
        status, _, _ = self._get("/beacon/scroll", method="POST")
        self.assertEqual(status, 405)

    def test_feed_page_includes_scroll_beacon_js(self):
        """The HTML page must wire the beacon — without the JS the
        endpoint exists but never fires."""
        _, _, body = self._get("/")
        src = body.decode("utf-8")
        self.assertIn("/beacon/scroll", src)


if __name__ == "__main__":
    unittest.main()
