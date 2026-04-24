"""
Public read-only HTTP feed for recent on-chain messages.

Purpose: give non-technical visitors a thing to click.  A validator
exposes `GET /v1/latest` returning the newest messages as JSON, plus
a single static HTML page that polls it.  Operators typically front
this with Caddy/Cloudflare for TLS; the server itself speaks plain
HTTP so cert management stays one level up.

Security posture:
  * Read-only.  No method other than GET/OPTIONS/HEAD is accepted,
    no state mutations possible.  Message content is fully public by
    design (MessageChain has no protocol-level encryption), so there
    is nothing to leak that the chain hasn't already committed.
  * Per-source-IP token bucket keeps casual scraping from DoSing the
    validator's event loop.  Reads are cheap but not free — every
    request touches chain state.
  * `limit` parameter is clamped to `PUBLIC_FEED_MAX_LIMIT` so a
    single request can't force a walk of the whole chain.
  * CORS: `Access-Control-Allow-Origin: *`.  The data is public and
    we want browsers on any origin to be able to render it.
  * Static HTML page is served from a bundled file; message text is
    inserted via textContent (XSS-safe).
  * Runs in a background daemon thread alongside the main P2P/RPC
    server, mirroring SubmissionServer's isolation so a bug here
    cannot corrupt the consensus sockets.

Stdlib-only: `http.server.ThreadingHTTPServer`.  No new pip deps.
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import socketserver
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from messagechain.config import (
    CHAIN_ID,
    PUBLIC_FEED_BURST,
    PUBLIC_FEED_MAX_LIMIT,
    PUBLIC_FEED_RATE_LIMIT_PER_SEC,
)
from messagechain.network.ratelimit import TokenBucket


logger = logging.getLogger("messagechain.public_feed")


__all__ = ["PublicFeedServer"]


# Path to the bundled static HTML page served at "/".
_STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static",
)
_FEED_HTML_PATH = os.path.join(_STATIC_DIR, "feed.html")


class _FeedHandlerContext:
    """Shared state for all handler instances on one server."""

    def __init__(self, blockchain):
        self.blockchain = blockchain
        self._buckets: dict[str, TokenBucket] = {}
        self._last_active: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max_tracked_ips = 4096

    def rate_limit_check(self, ip: str) -> bool:
        with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                if len(self._buckets) >= self._max_tracked_ips:
                    self._evict_locked()
                    if len(self._buckets) >= self._max_tracked_ips:
                        return False
                bucket = TokenBucket(
                    rate=PUBLIC_FEED_RATE_LIMIT_PER_SEC,
                    max_tokens=PUBLIC_FEED_BURST,
                )
                self._buckets[ip] = bucket
            self._last_active[ip] = time.time()
            return bucket.consume()

    def _evict_locked(self):
        # Drop fully-refilled (idle) buckets first, then LRU if still at cap.
        to_drop = []
        for ip, bucket in self._buckets.items():
            bucket._refill()
            if bucket.tokens >= bucket.max_tokens:
                to_drop.append(ip)
        for ip in to_drop:
            del self._buckets[ip]
            self._last_active.pop(ip, None)
        if len(self._buckets) >= self._max_tracked_ips and self._last_active:
            oldest_ip = min(self._last_active, key=self._last_active.get)
            self._buckets.pop(oldest_ip, None)
            self._last_active.pop(oldest_ip, None)


class _FeedHandler(http.server.BaseHTTPRequestHandler):
    """GET-only handler for the public feed.

    Routes:
        GET /                 → static HTML feed page
        GET /health           → {"ok": true}
        GET /v1/info          → chain id, height, last block timestamp
        GET /v1/latest?limit= → newest messages, JSON
        *                     → 404 / 405
    """

    server_version = "MessageChainFeed/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
        self.send_header("Access-Control-Max-Age", "3600")

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_text(self, status: int, msg: str):
        body = (msg + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_html(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        self._send_text(405, "Method Not Allowed")

    def do_PUT(self):
        self._send_text(405, "Method Not Allowed")

    def do_DELETE(self):
        self._send_text(405, "Method Not Allowed")

    def do_PATCH(self):
        self._send_text(405, "Method Not Allowed")

    def do_HEAD(self):
        # Let GET handle it; BaseHTTPRequestHandler writes the body to
        # wfile, but HEAD responses MUST have no body per RFC 7231.
        # Simplest correct behaviour: 405 — the feed has nothing
        # meaningful to expose via HEAD, and clients that care about
        # cacheability can use the JSON response directly.
        self._send_text(405, "Method Not Allowed")

    def do_GET(self):
        ctx = self.server._feed_context

        # Health check is cheap and must not be rate-limited — reverse
        # proxies (Caddy, Cloudflare, load balancers) poll it.
        split = urlsplit(self.path)
        path = split.path
        if path == "/health":
            self._send_json(200, {"ok": True})
            return

        if not ctx.rate_limit_check(self._client_ip()):
            self._send_text(429, "Too Many Requests")
            return

        if path == "/" or path == "/index.html":
            self._serve_static_feed()
            return
        if path == "/v1/info":
            self._serve_info(ctx)
            return
        if path == "/v1/latest":
            self._serve_latest(ctx, split.query)
            return

        self._send_text(404, "Not Found")

    def _serve_static_feed(self):
        try:
            with open(_FEED_HTML_PATH, "rb") as f:
                body = f.read()
        except OSError:
            self._send_text(500, "feed page unavailable")
            return
        self._send_html(body)

    def _serve_info(self, ctx: _FeedHandlerContext):
        chain = ctx.blockchain
        height = chain.height
        latest_ts = (
            chain.chain[-1].header.timestamp if chain.chain else None
        )
        self._send_json(200, {
            "ok": True,
            "chain_id": CHAIN_ID.decode("ascii", errors="replace"),
            "height": height,
            "last_block_timestamp": latest_ts,
        })

    def _serve_latest(self, ctx: _FeedHandlerContext, query: str):
        params = parse_qs(query)
        raw_limit = (params.get("limit") or ["20"])[0]
        try:
            limit = int(raw_limit)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid limit"})
            return
        if limit < 1:
            limit = 1
        if limit > PUBLIC_FEED_MAX_LIMIT:
            limit = PUBLIC_FEED_MAX_LIMIT

        try:
            messages = ctx.blockchain.get_recent_messages(limit)
        except Exception:
            logger.exception("get_recent_messages failed")
            self._send_json(500, {"ok": False, "error": "chain read failed"})
            return

        self._send_json(200, {
            "ok": True,
            "height": ctx.blockchain.height,
            "messages": messages,
        })


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PublicFeedServer:
    """Public read-only HTTP feed.

    Lifecycle:
        >>> f = PublicFeedServer(chain, port=8080, bind="0.0.0.0")
        >>> f.start()
        >>> ...
        >>> f.stop()

    Intended deployment: plain HTTP, bound to localhost or a private
    interface, with a reverse proxy (Caddy/Cloudflare) terminating TLS
    on the public edge.  Binding to 0.0.0.0 is allowed but operators
    should put a reverse proxy in front — this server does NOT
    terminate TLS itself.
    """

    def __init__(
        self,
        blockchain,
        port: int,
        bind: str = "127.0.0.1",
    ):
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self._httpd: Optional[_ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread is not None:
            raise RuntimeError("PublicFeedServer already started")
        self._httpd = _ThreadingHTTPServer(
            (self.bind, self.port), _FeedHandler,
        )
        self._httpd._feed_context = _FeedHandlerContext(self.blockchain)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"mc-public-feed-{self.port}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Public feed listening on http://%s:%d/",
            self.bind, self.port,
        )

    def stop(self, timeout: float = 5.0):
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
        except Exception:
            pass
        try:
            self._httpd.server_close()
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        return (self.bind, self.port)
