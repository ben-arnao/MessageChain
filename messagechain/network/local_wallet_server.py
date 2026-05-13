"""
Local wallet UI HTTP server (loopback-only, key-holding, write-enabled).

Sister-process to PublicFeedServer.  Where the public feed exposes
read-only chain data on a public bind, this server exposes the user's
wallet — sign-and-submit routes for messages, transfers, stake, votes,
governance, key rotation — and is intended ONLY to be reached by the
user's own browser tab on the same machine.

THREAT MODEL & DEFENSES
-----------------------
The server holds the user's private key in process memory and exposes
signing routes under /wallet/*.  If anything other than the user's own
browser tab can reach those routes, the key is drained.  Four
independent defenses, each load-bearing:

  1. **Loopback-only bind.** Construction fails closed for any bind
     that is not a literal loopback IP (127.0.0.1 or ::1).  Removing
     this and binding to 0.0.0.0 would expose the wallet to the LAN.

  2. **Host-header allowlist.** Every request whose `Host:` header is
     not a loopback name (127.0.0.1, localhost, [::1], optionally with
     a port) is rejected with 403.  Defends against DNS rebinding,
     where a malicious page resolves its own DNS name to 127.0.0.1
     to trick the browser into letting JS from `evil.com` talk to the
     wallet over the same-origin policy.

  3. **Per-session bearer token.** A cryptographically random token
     is generated at startup, printed in the URL the operator opens,
     and required as `Authorization: Bearer <t>` (or `?t=<t>` for the
     initial page load) on every /wallet/* route.  Defends against
     other local processes (a curl from a malware payload, an unrelated
     browser tab) hitting the wallet routes.  Token is never written
     to disk and rotates on every server restart.

  4. **No CORS on wallet routes.** PublicFeedServer sets
     `Access-Control-Allow-Origin: *` because its data is public.
     The wallet server explicitly does NOT set CORS on /wallet/*.
     Combined with (3), this is belt-and-suspenders: even if a token
     leaks, the absence of CORS prevents a malicious origin from
     reading wallet response bodies via fetch().

Each is tested in tests/test_local_wallet_server.py.  Removing or
weakening any one of them is a security regression.

LIFECYCLE
---------
    >>> srv = LocalWalletServer(blockchain=chain, port=9335)
    >>> srv.start()
    >>> print(srv.url)  # http://127.0.0.1:9335/?t=<token>
    >>> ...
    >>> srv.stop()

Stdlib-only.  Pattern mirrors PublicFeedServer (ThreadingHTTPServer
in a daemon thread) so the operator can run this alongside a validator
and have either one crash without taking the other down.

This module is the empty shell — landing page + /health + /wallet/ping
only.  Real wallet routes (/wallet/send, /wallet/transfer, etc.) layer
on top of this scaffold in follow-up commits.
"""

from __future__ import annotations

import hmac
import http.server
import json
import logging
import os
import secrets
import socketserver
import threading
from typing import Optional
from urllib.parse import parse_qs, urlsplit


logger = logging.getLogger("messagechain.local_wallet")


__all__ = [
    "LocalWalletServer",
    "LoopbackBindError",
]


# --- Defense 1: loopback bind allowlist --------------------------------

class LoopbackBindError(ValueError):
    """Raised when LocalWalletServer is constructed with a non-loopback
    bind address.  The wallet server holds the user's private key; any
    bind beyond 127.0.0.1 / ::1 exposes signing routes to the network."""


_ALLOWED_LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1"})


def _validate_loopback_bind(bind: str) -> None:
    if bind not in _ALLOWED_LOOPBACK_BINDS:
        raise LoopbackBindError(
            f"LocalWalletServer refuses bind={bind!r}: only literal "
            f"loopback IPs are allowed (127.0.0.1 or ::1).  Binding to "
            f"anything else exposes /wallet/* signing routes -- and the "
            f"private key in this process -- to the network."
        )


# --- Defense 2: Host header allowlist ----------------------------------

_ALLOWED_HOST_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def _host_header_is_loopback(host_header: str) -> bool:
    """Strip optional :port from a `Host:` header and check the bare
    name against the loopback allowlist.  Handles both v4/hostname
    (`127.0.0.1:9335`, `localhost:9335`) and v6 (`[::1]:9335`)."""
    if not host_header:
        return False
    if host_header.startswith("["):
        # IPv6 literal in brackets per RFC 7230 §5.4.
        end = host_header.find("]")
        if end == -1:
            return False
        bare = host_header[1:end]
    elif ":" in host_header:
        bare = host_header.rsplit(":", 1)[0]
    else:
        bare = host_header
    return bare in _ALLOWED_HOST_NAMES


# --- Defense 3: per-session bearer token --------------------------------

def _generate_session_token() -> str:
    # 32 bytes => 43 base64url chars.  Comfortably above brute-force
    # attempts via /wallet/*: a 256-bit random token won't be guessed.
    return secrets.token_urlsafe(32)


def _extract_provided_token(headers, query_string: str) -> Optional[str]:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):]
    qs = parse_qs(query_string or "")
    vals = qs.get("t")
    if vals:
        return vals[0]
    return None


# --- Static landing page (placeholder for empty shell) -----------------

_STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static",
    "wallet",
)
_INDEX_HTML_PATH = os.path.join(_STATIC_DIR, "index.html")


# --- Handler & context --------------------------------------------------

class _WalletHandlerContext:
    """Per-server shared state.  Held on the server object so handler
    instances (one per request) can see it without globals."""

    def __init__(self, blockchain, token: str, entity=None):
        # Optional in the empty-shell phase.  Becomes required when
        # real read/write routes land.
        self.blockchain = blockchain
        self.token = token
        # Optional: an `Entity` (messagechain.identity.identity.Entity)
        # whose private key the server will use to sign /wallet/*
        # writes.  None for read-only / shell mode.
        self.entity = entity


class _WalletHandler(http.server.BaseHTTPRequestHandler):
    """Loopback HTTP handler.  Every request runs through:
        Host check  ->  (token check, unless route is bypass-listed)
                    ->  route dispatch

    Routes (empty shell):
        GET /             -> static landing page (loads token from ?t=)
        GET /health       -> {"ok": true}        (token-bypass)
        GET /wallet/ping  -> {"ok": true}        (token-required)
        *                 -> 404
    """

    timeout = 30
    server_version = "MessageChainWallet/1"
    sys_version = ""

    # Routes that DO NOT require the bearer token.  Every other route
    # is token-gated.  The Host check applies unconditionally.
    _TOKEN_BYPASS_PATHS = frozenset({"/", "/health", "/index.html"})

    def log_message(self, fmt, *args):
        # Quiet by default — wallet activity isn't useful operator
        # signal and the URL contains a token on the initial load.
        return

    # --- response helpers (no CORS — defense 4) -----------------------

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # --- defenses 2 & 3, applied as middleware ------------------------

    def _check_host_header_or_reject(self) -> bool:
        host = self.headers.get("Host", "")
        if not _host_header_is_loopback(host):
            self._send_text(
                403,
                "Forbidden: wallet server only accepts loopback Host headers",
            )
            return False
        return True

    def _check_token_or_reject(self, query: str) -> bool:
        ctx = self.server._wallet_context
        provided = _extract_provided_token(self.headers, query)
        if provided is None:
            self._send_text(401, "Unauthorized: missing wallet session token")
            return False
        # Constant-time comparison — token guessing via /wallet/* is
        # already infeasible at 256-bit entropy, but timing-side-channel
        # leakage of partial matches is cheap to defend.
        if not hmac.compare_digest(provided, ctx.token):
            self._send_text(401, "Unauthorized: invalid wallet session token")
            return False
        return True

    # --- routing ------------------------------------------------------

    def do_GET(self):
        if not self._check_host_header_or_reject():
            return

        split = urlsplit(self.path)
        path = split.path

        if path in self._TOKEN_BYPASS_PATHS:
            if path == "/health":
                self._send_json(200, {"ok": True})
                return
            # Landing page.  Empty-shell version is a tiny placeholder;
            # real wallet UI files land in static/wallet/ in follow-ups.
            self._serve_landing_page()
            return

        # All other routes require the session token.
        if not self._check_token_or_reject(split.query):
            return

        if path == "/wallet/ping":
            # Sentinel route used by the landing page to confirm the
            # token is good before unlocking any UI affordances, and
            # by tests as a token-gate canary.
            self._send_json(200, {"ok": True})
            return

        self._send_text(404, "Not Found")

    def _serve_landing_page(self):
        # Fall back to an inline placeholder if the static file is
        # missing — keeps the empty shell self-contained.  When we
        # ship the real wallet UI the bundled file takes over.
        if os.path.isfile(_INDEX_HTML_PATH):
            with open(_INDEX_HTML_PATH, "rb") as f:
                self._send_html(f.read())
            return
        placeholder = (
            "<!doctype html><meta charset=utf-8>"
            "<title>MessageChain Wallet</title>"
            "<h1>MessageChain Wallet (empty shell)</h1>"
            "<p>Server is up.  Real wallet UI lands in follow-up commits.</p>"
        ).encode("utf-8")
        self._send_html(placeholder)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    # ThreadingHTTPServer needs a per-address-family socket type for
    # the v6 loopback bind (::1).  Resolved per-instance below.
    address_family = None  # set in __init__


# --- Public entry point -------------------------------------------------

class LocalWalletServer:
    """Loopback-only HTTP server for the local wallet UI.

    Construction fails fast for non-loopback binds (defense 1).  The
    other three defenses live in the request handler and are exercised
    by the test suite — see module docstring."""

    def __init__(
        self,
        blockchain,
        port: int,
        bind: str = "127.0.0.1",
        token: Optional[str] = None,
        entity=None,
    ):
        _validate_loopback_bind(bind)
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self.token = token if token is not None else _generate_session_token()
        self.entity = entity
        self._httpd: Optional[_ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        # Loopback v6 needs bracket form in URLs per RFC 3986 §3.2.2.
        host = f"[{self.bind}]" if ":" in self.bind else self.bind
        return f"http://{host}:{self.port}/?t={self.token}"

    def start(self):
        if self._thread is not None:
            raise RuntimeError("LocalWalletServer already started")

        # Resolve address family for v4 vs v6 loopback bind.
        import socket as _socket
        family = _socket.AF_INET6 if ":" in self.bind else _socket.AF_INET

        class _BoundServer(_ThreadingHTTPServer):
            address_family = family

        self._httpd = _BoundServer((self.bind, self.port), _WalletHandler)
        self._httpd._wallet_context = _WalletHandlerContext(
            blockchain=self.blockchain,
            token=self.token,
            entity=self.entity,
        )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"mc-local-wallet-{self.port}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Local wallet UI listening on %s  (token-gated, loopback-only)",
            self.url,
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
