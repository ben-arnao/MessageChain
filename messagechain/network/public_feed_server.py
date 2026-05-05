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
import ipaddress
import json
import logging
import os
import socketserver
import threading
import time
from typing import Iterable, Mapping, Optional, Sequence, Union
from urllib.parse import parse_qs, urlsplit

from messagechain.config import (
    CHAIN_ID,
    PUBLIC_FEED_BURST,
    PUBLIC_FEED_MAX_LIMIT,
    PUBLIC_FEED_RATE_LIMIT_PER_SEC,
)
from messagechain.network.ratelimit import TokenBucket


logger = logging.getLogger("messagechain.public_feed")


__all__ = [
    "PublicFeedServer",
    "_parse_trusted_proxies",
    "_resolve_client_ip",
]


# Sentinel bucket key for syntactically invalid forwarded-for tokens
# from trusted proxies.  Routing all malformed traffic to one shared
# bucket prevents an attacker from rejoining the legitimate-traffic
# bucket by sending garbage in the header.  Value is intentionally
# not a valid IP literal so it can never collide with a real client.
_UNATTRIBUTABLE_BUCKET = "__unattributable__"


def _parse_trusted_proxies(
    spec: Optional[str],
) -> list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Parse a comma-separated list of trusted-proxy CIDRs.

    Empty / None yields an empty list, which means "trust no proxy" —
    headers are ignored unconditionally.  Bare IPs (no /prefix) are
    treated as host networks (/32 v4, /128 v6).  Garbage raises
    ValueError so a config typo fails loudly at startup rather than
    silently degrading to no header trust at all.
    """
    if not spec:
        return []
    out: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        # `strict=False` lets "10.0.0.5/24" parse without complaining
        # that host bits are set — the operator is naming the CIDR.
        out.append(ipaddress.ip_network(token, strict=False))
    return out


def _validate_ip_token(token: str) -> Optional[str]:
    """Return a normalized IP literal if `token` parses, else None.

    Strips an optional port suffix (Forwarded: for= can carry one,
    e.g. ``"203.0.113.7:1234"`` or ``"[2001:db8::1]:1234"``), then
    validates against ``ipaddress.ip_address``.  Returns the textual
    form so the caller can use it as a dict key directly.
    """
    s = token.strip()
    if not s:
        return None
    # Strip surrounding quotes (Forwarded: for="203.0.113.7").
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    # Bracketed IPv6 with optional port: "[2001:db8::1]:1234".
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            return None
        s = s[1:end]
    else:
        # Bare token may have a :port suffix only if it's IPv4.
        # IPv6 without brackets must NOT be split on ':' since the
        # address itself contains colons.
        if s.count(":") == 1 and "." in s:
            s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _extract_forwarded_for(
    headers: Mapping[str, str],
) -> Optional[str]:
    """Return the rightmost forwarded-for token, or None.

    Prefers ``X-Forwarded-For`` (the de facto standard).  Falls back
    to RFC 7239 ``Forwarded: for=<ip>``.  Returns the raw token so
    the caller can validate it; an empty/missing header yields None.
    """
    # Case-insensitive lookup -- http.server's headers object is
    # case-insensitive but generic Mapping (e.g. our test dicts)
    # is not.
    def _lookup(name: str) -> Optional[str]:
        if hasattr(headers, "get") and not isinstance(headers, dict):
            v = headers.get(name)
            if v is not None:
                return v
        # Fallback: linear scan, case-insensitive.
        for k, v in (headers.items() if hasattr(headers, "items") else []):
            if k.lower() == name.lower():
                return v
        return None

    xff = _lookup("X-Forwarded-For")
    if xff is not None:
        # Header explicitly present.  Even if empty, treat it as a
        # forwarding claim that needs validation downstream — an
        # empty/whitespace value from a trusted proxy is malformed
        # input, not "no header at all".
        # Rightmost is the only token the trusted proxy directly saw;
        # earlier entries are attacker-controlled appends.
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
        return ""  # header present but empty -> unattributable

    fwd = _lookup("Forwarded")
    if fwd is not None:
        # Multiple forwarded-elements separated by ',' — rightmost
        # again.  Each element is a ';'-separated set of pairs;
        # extract for=<value>.
        elements = [e.strip() for e in fwd.split(",") if e.strip()]
        if not elements:
            return ""
        last = elements[-1]
        for pair in last.split(";"):
            pair = pair.strip()
            if pair.lower().startswith("for="):
                return pair[4:].strip()
        return ""
    return None


def _resolve_client_ip(
    socket_peer: str,
    headers: Mapping[str, str],
    trusted_proxies: Sequence[
        Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    ],
) -> str:
    """Derive the bucket-key IP for per-IP rate limiting.

    Returns the socket peer unconditionally when ``trusted_proxies``
    is empty (default operator posture).  When non-empty, requests
    whose socket peer falls inside any allowlist CIDR have their
    rightmost forwarded-for token honored — provided it parses as
    a valid IP.  Malformed tokens from a trusted proxy go to the
    sentinel bucket so attackers can't collapse onto the legitimate
    bucket by sending garbage.
    """
    if not trusted_proxies:
        return socket_peer
    try:
        peer_addr = ipaddress.ip_address(socket_peer)
    except ValueError:
        # Socket peer itself is malformed -- shouldn't happen in
        # practice, but be defensive.  Treat as untrusted.
        return socket_peer
    is_trusted = any(peer_addr in net for net in trusted_proxies)
    if not is_trusted:
        return socket_peer
    raw = _extract_forwarded_for(headers)
    if raw is None:
        # No forwarded header at all -- honest direct hit on the
        # proxy (e.g. health probe).  Fall back to the socket peer.
        return socket_peer
    parsed = _validate_ip_token(raw)
    if parsed is None:
        return _UNATTRIBUTABLE_BUCKET
    return parsed


# Path to the bundled static HTML page served at "/".
_STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static",
)
_FEED_HTML_PATH = os.path.join(_STATIC_DIR, "feed.html")
_ENTITY_HTML_PATH = os.path.join(_STATIC_DIR, "entity.html")
_RECEIPT_HTML_PATH = os.path.join(_STATIC_DIR, "receipt.html")

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

# Deeper link for `/gh/node` — README's "Run a validator" anchor.
_GITHUB_RUN_VALIDATOR_URL = (
    "https://github.com/ben-arnao/MessageChain"
    "#run-a-validator"
)


class _FeedHandlerContext:
    """Shared state for all handler instances on one server."""

    def __init__(
        self,
        blockchain,
        faucet=None,
        quickpost=None,
        trusted_proxies: Optional[Iterable] = None,
    ):
        self.blockchain = blockchain
        # Optional FaucetState (messagechain.network.faucet).  When
        # None the /faucet POST endpoint returns 405 and the public
        # feed remains read-only.
        self.faucet = faucet
        # Optional QuickpostState (messagechain.network.quickpost).
        # When None the /quickpost POST endpoint returns 405; the
        # quickpost flow piggybacks on the faucet's wallet, so a
        # validator without --faucet-keyfile cannot enable it.
        self.quickpost = quickpost
        # Allowlist of reverse-proxy CIDRs whose X-Forwarded-For we
        # honor.  Empty => trust no proxy (default), header always
        # ignored.  See _resolve_client_ip + the operator-facing
        # --trusted-proxies CLI flag in server.py.
        self.trusted_proxies: list = list(trusted_proxies or [])
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

    # Per-connection socket read timeout.  See _SubmissionHandler for
    # the slow-loris rationale.  The feed handler also serves the
    # /faucet POST path on this same handler when faucet is enabled,
    # so the timeout protects both read-only feed traffic and the
    # faucet-drip body parse.
    timeout = 30

    server_version = "MessageChainFeed/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        # Per-IP rate-limit bucket key.  When the operator has
        # configured --trusted-proxies and this connection's socket
        # peer falls inside one of those CIDRs, we honor the
        # rightmost X-Forwarded-For (or RFC 7239 Forwarded: for=)
        # token as the real client IP.  Otherwise the header is
        # ignored entirely — never trust client-supplied identity
        # headers from arbitrary inbound.
        ctx = getattr(self.server, "_feed_context", None)
        trusted = getattr(ctx, "trusted_proxies", []) if ctx else []
        return _resolve_client_ip(
            self.client_address[0], self.headers, trusted,
        )

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
        # POST routes: the optional cold-start funding faucet and the
        # optional server-assisted /quickpost flow.  Every other path
        # returns 405 so the public feed surface stays read-only by
        # default.
        ctx = self.server._feed_context
        split = urlsplit(self.path)
        if split.path == "/faucet" and ctx.faucet is not None:
            if not ctx.rate_limit_check(self._client_ip()):
                self._send_text(429, "Too Many Requests")
                return
            self._serve_faucet(ctx)
            return
        if split.path == "/quickpost" and ctx.quickpost is not None:
            if not ctx.rate_limit_check(self._client_ip()):
                self._send_text(429, "Too Many Requests")
                return
            self._serve_quickpost(ctx)
            return
        self._send_text(405, "Method Not Allowed")

    def _serve_faucet(self, ctx):
        """POST /faucet  body: {"address": "<entity_id_hex>"}.

        Returns JSON {"ok": ..., "tx_hash": ..., "amount": ...,
        "remaining_window": ..., "error": ...}.  The three
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
                "remaining_window": result.remaining_window,
            })
        else:
            # 429 for rate-limit-style refusals so well-behaved
            # clients can detect/back-off; 400 for malformed input.
            status = 400 if "must be" in result.error else 429
            self._send_json(status, {
                "ok": False,
                "error": result.error,
                "remaining_window": result.remaining_window,
            })

    def _serve_quickpost(self, ctx):
        """POST /quickpost  body: {"message", "challenge_seed", "nonce"}.

        Server-assisted "try it" flow: generates a fresh wallet on
        behalf of the visitor, drips it from the faucet wallet, and
        queues the message tx for submission once the drip confirms.
        Returns the private key + entity id + drip tx hash; the visitor
        downloads the keyfile from the response and gets a real on-chain
        message a few minutes later (after the drip lands).

        Explicitly a "try it" path — the keypair was generated on the
        server.  The UI disclaimer + README direct serious users to
        offline keygen.
        """
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        # Cap body at 8 KB.  The message itself is <= 1024 bytes UTF-8
        # plus minor JSON framing; anything larger is malformed.
        if length < 0 or length > 8192:
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
        message = payload.get("message", "")
        if not isinstance(message, str):
            self._send_json(400, {"ok": False, "error": "message must be a string"})
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
                    "/quickpost/challenge first to obtain a challenge."
                ),
            })
            return

        result = ctx.quickpost.try_quickpost(
            self._client_ip(), message,
            challenge_seed_hex=challenge_seed, nonce=nonce_raw,
        )
        if result.ok:
            self._send_json(200, {
                "ok": True,
                "entity_id": result.entity_id_hex,
                "private_key": result.private_key_hex,
                "drip_tx_hash": result.drip_tx_hash,
                "remaining_window": result.remaining_window,
            })
        else:
            status = 400 if "must be" in result.error else 429
            self._send_json(status, {
                "ok": False,
                "error": result.error,
                "remaining_window": result.remaining_window,
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
        if path == "/v1/entity":
            self._serve_entity(ctx, split.query)
            return
        if path == "/v1/tx_status":
            # JSON proxy for the per-message permanence-receipt page.
            # Inclusion-only by design — the public feed has no
            # mempool view, and a web visitor doesn't need pending-tx
            # ETAs to evaluate a permanence claim.
            self._serve_tx_status(ctx, split.query)
            return
        if path.startswith("/e/"):
            # /e/<entity_id_hex>: static profile page.  The page reads
            # the id from its own URL and queries /v1/entity itself.
            # Serving the same HTML for any /e/* path keeps the server
            # branch trivial; client-side validates the hex.
            self._serve_static_entity()
            return
        if path.startswith("/r/"):
            # /r/<tx_hash_hex>: static permanence-receipt page.  The
            # page reads the tx_hash from its own URL and queries
            # /v1/tx_status itself.  The "Permanent · verify" link on
            # every message card on the feed lands here.
            self._serve_static_receipt()
            return
        if path == "/gh" or path == "/gh/start" or path == "/gh/node":
            # 302 to the public repo so outbound clicks land in the
            # access log (a bare anchor href would let the browser
            # navigate away with no record on our side).  `/gh/start`
            # deep-links to README's "Getting started" anchor; `/gh/node`
            # to the "Run a validator" anchor.
            if path == "/gh/start":
                target = _GITHUB_GETTING_STARTED_URL
            elif path == "/gh/node":
                target = _GITHUB_RUN_VALIDATOR_URL
            else:
                target = _GITHUB_REPO_URL
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if path == "/faucet/challenge" and ctx.faucet is not None:
            self._serve_faucet_challenge(ctx, split.query)
            return
        if path == "/quickpost/challenge" and ctx.quickpost is not None:
            self._serve_quickpost_challenge(ctx)
            return
        if path == "/beacon/scroll":
            # One-shot engagement beacon the homepage's JS fires when
            # the visitor scrolls past the initial fold. 204 + empty
            # body keeps the response tiny — the only signal we need
            # is the request itself landing in the access log paired
            # with the visitor IP.
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._send_text(404, "Not Found")

    def _serve_quickpost_challenge(self, ctx):
        """GET /quickpost/challenge: mint a fresh PoW challenge for the
        server-assisted "try it" flow.

        Returns {"ok", "seed", "difficulty", "expires_at", "ttl_sec"}.
        Unlike /faucet/challenge there is no address binding: the
        recipient does not exist at challenge time (the keypair is
        generated by the server AFTER PoW verification).  The PoW is
        bound at /quickpost time via sha256(seed || nonce_be_8 ||
        sha256(message_utf8)) so a precomputed nonce cannot be
        replayed for a different message.
        """
        ok, error, payload = ctx.quickpost.issue_challenge()
        if not ok:
            self._send_json(400, {"ok": False, "error": error})
            return
        body = {"ok": True}
        body.update(payload)
        self._send_json(200, body)

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

    def _serve_static_entity(self):
        try:
            with open(_ENTITY_HTML_PATH, "rb") as f:
                body = f.read()
        except OSError:
            self._send_text(500, "entity page unavailable")
            return
        self._send_html(body)

    def _serve_static_receipt(self):
        try:
            with open(_RECEIPT_HTML_PATH, "rb") as f:
                body = f.read()
        except OSError:
            self._send_text(500, "receipt page unavailable")
            return
        self._send_html(body)

    def _serve_tx_status(self, ctx: "_FeedHandlerContext", query: str):
        """JSON proxy for the per-message permanence-receipt page.

        Routes through ``Blockchain.get_tx_status_public`` so the
        result schema matches the JSON-RPC `_rpc_get_tx_status`
        "included" branch — the receipt UI can render the same proof
        whether it talks to the JSON-RPC port or the public-feed
        HTTP shim.
        """
        params = parse_qs(query)
        raw_hash = (params.get("tx_hash") or [""])[0].strip().lower()
        if not raw_hash:
            self._send_json(400, {
                "ok": False,
                "error": "tx_hash query parameter required",
            })
            return
        # Accept an optional 0x prefix to match the CLI's input rules.
        if raw_hash.startswith("0x"):
            raw_hash = raw_hash[2:]
        if len(raw_hash) != 64:
            self._send_json(400, {
                "ok": False,
                "error": "tx_hash must be 64 hex characters",
            })
            return
        try:
            tx_hash = bytes.fromhex(raw_hash)
        except ValueError:
            self._send_json(400, {
                "ok": False,
                "error": "tx_hash must be valid hex",
            })
            return
        try:
            result = ctx.blockchain.get_tx_status_public(tx_hash)
        except Exception:
            logger.exception("get_tx_status_public failed")
            self._send_json(500, {"ok": False, "error": "chain read failed"})
            return
        self._send_json(200, {"ok": True, "result": result})

    def _serve_entity(self, ctx: "_FeedHandlerContext", query: str):
        from messagechain.network.entity_profile import compute_entity_profile
        params = parse_qs(query)
        raw_id = (params.get("id") or [""])[0].strip().lower()
        if not raw_id or len(raw_id) != 64:
            self._send_json(400, {
                "ok": False,
                "error": "id must be a 64-char hex entity_id",
            })
            return
        try:
            entity_id = bytes.fromhex(raw_id)
        except ValueError:
            self._send_json(400, {
                "ok": False,
                "error": "id must be valid hex",
            })
            return
        try:
            profile = compute_entity_profile(ctx.blockchain, entity_id)
        except Exception:
            logger.exception("compute_entity_profile failed")
            self._send_json(500, {"ok": False, "error": "chain read failed"})
            return
        self._send_json(200, {
            "ok": True,
            "height": ctx.blockchain.height,
            "profile": profile,
        })

    def _serve_info(self, ctx: _FeedHandlerContext):
        chain = ctx.blockchain
        height = chain.height
        latest_ts = (
            chain.chain[-1].header.timestamp if chain.chain else None
        )
        # Chain-identity surface — the web UI renders these in a
        # footer on every page so a paranoid visitor on a hostile
        # network can sanity-check the rendered genesis_hash against
        # their pinned copy (README ships one).  All three are public
        # data already derivable from the chain.  Each lookup is
        # defensive: legacy / partial blockchain stubs (test fixtures,
        # pre-state-root migration) may lack one of the attributes;
        # we render `None` rather than crash the whole /v1/info call.
        def _hash_hex(b):
            if b is None:
                return None
            try:
                return b.hex()
            except AttributeError:
                return None

        genesis_hash = (
            _hash_hex(getattr(chain.chain[0], "block_hash", None))
            if chain.chain else None
        )
        tip_hash = (
            _hash_hex(getattr(chain.chain[-1], "block_hash", None))
            if chain.chain else None
        )
        state_root = None
        if chain.chain:
            tip_header = getattr(chain.chain[-1], "header", None)
            if tip_header is not None:
                state_root = _hash_hex(getattr(tip_header, "state_root", None))
        body = {
            "ok": True,
            "chain_id": CHAIN_ID.decode("ascii", errors="replace"),
            "genesis_hash": genesis_hash,
            "tip_hash": tip_hash,
            "state_root": state_root,
            "height": height,
            "last_block_timestamp": latest_ts,
            "faucet_enabled": ctx.faucet is not None,
            "quickpost_enabled": ctx.quickpost is not None,
        }
        if ctx.faucet is not None:
            # Surface the visible knobs so the UI can render an
            # accurate "X drips remaining" line without a second round
            # trip.  Tier 22 retired the daily cap in favor of a
            # rolling-window cap; the public field is renamed in step
            # so any UI client polling /v1/info gets a consistent name.
            body["faucet"] = {
                "drip_amount": ctx.faucet.drip_amount,
                "remaining_window": ctx.faucet.remaining_window(),
                "window_cap": ctx.faucet.window_cap,
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
        quickpost=None,
        trusted_proxies: Optional[Iterable] = None,
    ):
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self.faucet = faucet
        self.quickpost = quickpost
        # Sequence of ipaddress.ip_network objects.  Empty list (the
        # default) means "trust no proxy" — the X-Forwarded-For header
        # is ignored unconditionally and per-IP rate limits attribute
        # to the socket peer.  Operators fronting the feed with a
        # reverse proxy should pass --trusted-proxies <cidr> so real
        # client IPs flow through to the per-IP buckets.
        self.trusted_proxies: list = list(trusted_proxies or [])
        self._httpd: Optional[_ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread is not None:
            raise RuntimeError("PublicFeedServer already started")
        self._httpd = _ThreadingHTTPServer(
            (self.bind, self.port), _FeedHandler,
        )
        self._httpd._feed_context = _FeedHandlerContext(
            self.blockchain,
            faucet=self.faucet,
            quickpost=self.quickpost,
            trusted_proxies=self.trusted_proxies,
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
