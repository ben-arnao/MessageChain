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

# Outbound link target for the `/gh` redirect (the public repo).
_GITHUB_REPO_URL = "https://github.com/ben-arnao/MessageChain"

# Deeper link for `/gh/start` — drops the visitor straight at the
# README's "Getting started — your first message" anchor, skipping the
# install-from-source weeds at the top.  Tracked the same way as `/gh`
# so we still see the click in the access log.
_GITHUB_GETTING_STARTED_URL = (
    "https://github.com/ben-arnao/MessageChain"
    "#getting-started--your-first-message"
)


class _FeedHandlerContext:
    """Shared state for all handler instances on one server."""

    def __init__(self, blockchain, faucet=None):
        self.blockchain = blockchain
        # Optional FaucetState (messagechain.network.faucet).  When
        # None the /faucet POST endpoint returns 405 and the public
        # feed remains read-only.
        self.faucet = faucet
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
        # The only POST route is the optional cold-start funding
        # faucet.  Every other path returns 405 so the public feed
        # surface stays read-only by default.
        ctx = self.server._feed_context
        split = urlsplit(self.path)
        if split.path == "/faucet" and ctx.faucet is not None:
            if not ctx.rate_limit_check(self._client_ip()):
                self._send_text(429, "Too Many Requests")
                return
            self._serve_faucet(ctx)
            return
        self._send_text(405, "Method Not Allowed")

    def _serve_faucet(self, ctx):
        """POST /faucet  body: {"address": "<entity_id_hex>"}.

        Returns JSON {"ok": ..., "tx_hash": ..., "amount": ...,
        "remaining_today": ..., "error": ...}.  The three
        rate-limit layers (per-/24 IP, per-address, daily cap) are
        enforced inside FaucetState.try_drip; this handler is just
        the HTTP boundary.
        """
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        # Reject pathologically large bodies upfront -- the JSON we
        # care about is well under 200 bytes.  Keeps a stray 1 GB
        # POST from blocking the handler thread.
        if length < 0 or length > 4096:
            self._send_json(400, {"ok": False, "error": "bad body length"})
            return
        try:
            body = self.rfile.read(length) if length else b""
            payload = json.loads(body or b"{}")
        except (json.JSONDecodeError, OSError):
            self._send_json(400, {"ok": False, "error": "invalid JSON body"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"ok": False, "error": "body must be a JSON object"})
            return
        address = payload.get("address", "")
        if not isinstance(address, str):
            self._send_json(400, {"ok": False, "error": "address must be a string"})
            return
        challenge_seed = payload.get("challenge_seed", "")
        if not isinstance(challenge_seed, str):
            self._send_json(400, {
                "ok": False,
                "error": "challenge_seed must be a hex string",
            })
            return
        nonce_raw = payload.get("nonce")
        if not isinstance(nonce_raw, int):
            self._send_json(400, {
                "ok": False,
                "error": (
                    "nonce must be an integer (PoW solution).  GET "
                    "/faucet/challenge?address=<hex> first to obtain "
                    "a challenge."
                ),
            })
            return

        result = ctx.faucet.try_drip(
            self._client_ip(), address,
            challenge_seed_hex=challenge_seed, nonce=nonce_raw,
        )
        if result.ok:
            self._send_json(200, {
                "ok": True,
                "tx_hash": result.tx_hash,
                "amount": result.amount,
                "remaining_today": result.remaining_today,
            })
        else:
            # 429 for rate-limit-style refusals so well-behaved
            # clients can detect/back-off; 400 for malformed input.
            status = 400 if "must be" in result.error else 429
            self._send_json(status, {
                "ok": False,
                "error": result.error,
                "remaining_today": result.remaining_today,
            })

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
        if path == "/gh" or path == "/gh/start":
            # 302 to the public repo so outbound clicks land in the
            # access log (a bare anchor href would let the browser
            # navigate away with no record on our side).  `/gh/start`
            # deep-links to the README's "Getting started" anchor for
            # visitors landing from the hero CTA.
            target = (
                _GITHUB_GETTING_STARTED_URL
                if path == "/gh/start"
                else _GITHUB_REPO_URL
            )
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if path == "/faucet/challenge" and ctx.faucet is not None:
            self._serve_faucet_challenge(ctx, split.query)
            return

        self._send_text(404, "Not Found")

    def _serve_faucet_challenge(self, ctx, query: str):
        """GET /faucet/challenge?address=<hex>: mint a fresh PoW
        challenge bound to the recipient address.

        Returns {"ok", "seed", "address", "difficulty", "expires_at",
        "ttl_sec"}.  The client uses (seed, address) to find a nonce
        such that sha256(seed || nonce_be_8 || address) has at least
        `difficulty` leading zero bits, then POSTs that to /faucet.
        Bound to the address so an attacker cannot pre-mine a nonce
        pool and burn it across many addresses.
        """
        params = parse_qs(query)
        address = (params.get("address") or [""])[0]
        ok, error, payload = ctx.faucet.issue_challenge(address)
        if not ok:
            self._send_json(400, {"ok": False, "error": error})
            return
        body = {"ok": True}
        body.update(payload)
        self._send_json(200, body)

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
        body = {
            "ok": True,
            "chain_id": CHAIN_ID.decode("ascii", errors="replace"),
            "height": height,
            "last_block_timestamp": latest_ts,
            "faucet_enabled": ctx.faucet is not None,
        }
        if ctx.faucet is not None:
            # Surface the visible knobs so the UI can render an
            # accurate "X drips remaining today" line without a second
            # round trip.  The drip amount and per-IP cooldown rarely
            # change but operators may tweak them across releases.
            body["faucet"] = {
                "drip_amount": ctx.faucet.drip_amount,
                "remaining_today": ctx.faucet.remaining_today(),
                "daily_cap": ctx.faucet.daily_cap,
            }
        self._send_json(200, body)

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
        faucet=None,
    ):
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self.faucet = faucet
        self._httpd: Optional[_ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread is not None:
            raise RuntimeError("PublicFeedServer already started")
        self._httpd = _ThreadingHTTPServer(
            (self.bind, self.port), _FeedHandler,
        )
        self._httpd._feed_context = _FeedHandlerContext(
            self.blockchain, faucet=self.faucet,
        )
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
