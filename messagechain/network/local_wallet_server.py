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
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import parse_qs, urlsplit

from messagechain.config import CHAIN_ID, PUBLIC_FEED_MAX_LIMIT


logger = logging.getLogger("messagechain.local_wallet")


__all__ = [
    "LocalWalletServer",
    "LoopbackBindError",
    "build_wallet_server_faucet",
]


# Tree height for newly-minted "create account" wallets in PUBLIC mode.
# Demo-quality: 4096 one-time WOTS+ leaves (~few seconds keygen on
# modest hardware).  Plenty of signature capacity for a casual user
# trying out the chain; SERIOUSLY UNDERPOWERED for a long-lived
# wallet.  The Create Account warning modal tells users this and
# points them at the README's offline-keygen workflow for real use.
DEMO_ACCOUNT_TREE_HEIGHT = 12


# --- Multi-session entity store ---------------------------------------
#
# In LOCAL mode (loopback bind, single operator) there is typically
# one session: the bootstrap token printed in the URL maps to the
# --keyfile-loaded entity (or to a no-entity placeholder under
# --read-only).  Sign-in via the browser overlays a new entity on
# the same session.
#
# In PUBLIC mode (--public, 0.0.0.0 bind, many users) each browser
# starts anonymous.  Sign-in mints a fresh random session_id and
# stores the entity against it; the browser sends that session_id
# on every /wallet/* request.  Sessions expire after the user-
# selected duration so a left-open tab does not keep a PK in server
# memory forever.
#
# The same in-memory dict serves both modes.  No PK ever touches
# disk: load-from-paste keeps it in process memory only, and
# logout/expiry deletes the entity reference (Python GC reclaims).

@dataclass
class _Session:
    entity: object = None         # messagechain.identity.identity.Entity, or None (anon)
    expires_at: Optional[float] = None  # absolute UNIX time; None = never expires

    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()


# Caps to keep session-flooding from exhausting server RAM (a single
# Entity at production tree height is ~32 MB of WOTS+ tree; even at
# the tiny test height it's a few KB).  At MAX_SESSIONS the oldest
# is evicted to make room.
_MAX_SESSIONS = 64
# Hard ceiling on session duration regardless of what the user picks
# in the UI (so a malicious / careless caller cannot pin a PK in
# server memory for years).
_MAX_SESSION_SECONDS = 60 * 60 * 24 * 30  # 30 days
_DEFAULT_SESSION_SECONDS = 60 * 60 * 24    # 1 day -- the iter-7 default


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
    instances (one per request) can see it without globals.

    Sessions: the auth model.  ``sessions[token]`` -> ``_Session``.
    The bootstrap token is set up at start (a single session whose
    entity is the --keyfile one, or None for --read-only / public
    mode).  Browser sign-in mints additional session_ids."""

    def __init__(
        self,
        blockchain,
        token: str,
        entity=None,
        rpc_caller: Optional[Callable] = None,
        public_mode: bool = False,
    ):
        self.blockchain = blockchain
        self.bootstrap_token = token
        self.public_mode = public_mode
        # session_id -> _Session.  In LOCAL mode the bootstrap token
        # is pre-installed with the --keyfile entity (or no entity
        # under --read-only); in PUBLIC mode no bootstrap session is
        # installed -- every signed-in user has their own random id.
        self.sessions: dict = {}
        if not public_mode:
            self.sessions[token] = _Session(entity=entity, expires_at=None)
        self._sessions_lock = threading.Lock()
        # Callable `(method: str, params: dict) -> dict` returning the
        # JSON-RPC response.  In production this is a thin wrapper
        # around `client.rpc_call(host, port, ...)` for the local
        # validator.  Tests inject a fake to avoid spinning a real
        # validator just to exercise the wallet-side routing.
        self.rpc_caller = rpc_caller

    def add_session(self, entity, duration_sec: int) -> str:
        """Mint a fresh session_id, register the entity against it, and
        return the new id.  Caps duration at the safety ceiling and
        evicts the oldest session if we're at cap."""
        duration = max(60, min(int(duration_sec), _MAX_SESSION_SECONDS))
        with self._sessions_lock:
            if len(self.sessions) >= _MAX_SESSIONS:
                # Evict the soonest-expiring session.  Bootstrap
                # session has expires_at=None so it sorts last and is
                # never evicted by this rule.
                victim = min(
                    self.sessions.keys(),
                    key=lambda k: self.sessions[k].expires_at or float("inf"),
                )
                self.sessions.pop(victim, None)
            sid = secrets.token_urlsafe(32)
            self.sessions[sid] = _Session(
                entity=entity,
                expires_at=time.time() + duration,
            )
            return sid

    def end_session(self, sid: str) -> bool:
        """Remove a session.  Returns True iff it existed."""
        with self._sessions_lock:
            return self.sessions.pop(sid, None) is not None

    def get_session(self, sid: Optional[str]) -> Optional[_Session]:
        """Return the session for sid (or None).  Sweeps expired."""
        if not sid:
            return None
        with self._sessions_lock:
            sess = self.sessions.get(sid)
            if sess is None:
                return None
            if sess.is_expired():
                self.sessions.pop(sid, None)
                return None
            return sess

    # --- Backwards-compatible single-entity surface ---
    # Older code paths reference ctx.entity directly.  Surface the
    # bootstrap session's entity here so they continue to work in
    # LOCAL mode without a refactor.  In PUBLIC mode this is None.
    @property
    def entity(self):
        sess = self.sessions.get(self.bootstrap_token) if not self.public_mode else None
        return sess.entity if sess else None

    @entity.setter
    def entity(self, e):
        # Legacy mutation path -- replaces the bootstrap session's
        # entity.  Used by /wallet/login in LOCAL single-user mode
        # (overlay a new wallet without restarting).  No-op in
        # public mode (which uses add_session instead).
        if self.public_mode:
            return
        with self._sessions_lock:
            sess = self.sessions.get(self.bootstrap_token)
            if sess is not None:
                sess.entity = e
            else:
                self.sessions[self.bootstrap_token] = _Session(
                    entity=e, expires_at=None,
                )


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
        ctx = self.server._wallet_context
        # In public mode the server is reachable via a real DNS name
        # (messagechain.org).  The loopback-Host gate would 403 every
        # legitimate request.  Loopback enforcement only applies to
        # local mode -- which still gets the DNS-rebinding defense.
        if ctx.public_mode:
            return True
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
        # Constant-time comparison against the bootstrap token covers
        # local-mode access (--keyfile or --read-only).  In public
        # mode there's no bootstrap token; sessions are the only auth.
        if not ctx.public_mode and hmac.compare_digest(provided, ctx.bootstrap_token):
            return True
        # Look up against the live session map.  Expired sessions
        # are GC'd by get_session itself.
        if ctx.get_session(provided) is not None:
            return True
        self._send_text(401, "Unauthorized: invalid or expired wallet session")
        return False

    def _current_session(self):
        """Return the _Session for this request (or None).  Used by
        /wallet/* routes that need to know WHICH user is signing."""
        ctx = self.server._wallet_context
        provided = _extract_provided_token(
            self.headers, urlsplit(self.path).query,
        )
        if provided is None:
            return None
        if (not ctx.public_mode
                and hmac.compare_digest(provided, ctx.bootstrap_token)):
            # Bootstrap path -- the legacy single-entity store.
            sess = ctx.sessions.get(ctx.bootstrap_token)
            return sess
        return ctx.get_session(provided)

    def _current_entity(self):
        sess = self._current_session()
        return sess.entity if sess else None

    # --- routing ------------------------------------------------------

    def do_GET(self):
        if not self._check_host_header_or_reject():
            return

        split = urlsplit(self.path)
        path = split.path
        ctx = self.server._wallet_context

        if path in self._TOKEN_BYPASS_PATHS:
            if path == "/health":
                self._send_json(200, {"ok": True})
                return
            self._serve_landing_page()
            return

        # In PUBLIC mode the /v1/* read routes are public-facing
        # (anyone can browse the chain on messagechain.org without
        # signing in).  /wallet/me is also open in public mode so the
        # SPA can render the anonymous "Sign in" affordance without
        # a token.  /wallet/* writes + everything else still require
        # a valid session.
        public_open = ctx.public_mode and (
            path.startswith("/v1/") or path == "/wallet/me"
        )
        if not public_open:
            if not self._check_token_or_reject(split.query):
                return

        if path == "/wallet/ping":
            # Sentinel route used by the landing page to confirm the
            # token is good before unlocking any UI affordances, and
            # by tests as a token-gate canary.
            self._send_json(200, {"ok": True})
            return

        if path == "/wallet/me":
            # The "you" panel pinned in the wallet UI's header.
            # Composed from two sources: the loaded Entity (entity_id,
            # WOTS+ leaf accounting -- in-process and free) and the
            # local validator (balance, stake, pubkey_registered --
            # one RPC).  In read-only mode (no key loaded) the
            # entity-side fields are null and `mode: read-only` so
            # the UI can render a "load a wallet" affordance instead
            # of error-state.
            self._serve_wallet_me()
            return

        # Read endpoints — same JSON shape as PublicFeedServer's
        # /v1/* surface so the same client JS works against either
        # server.  Implemented as RPC-proxies to the local validator
        # so the wallet UI is process-independent (does not require
        # an in-process chain handle and does not depend on the
        # public feed being enabled).
        if path == "/v1/info":
            self._serve_v1_info()
            return
        if path == "/v1/latest":
            self._serve_v1_latest(split.query)
            return
        if path == "/v1/entity":
            self._serve_v1_entity(split.query)
            return
        if path == "/v1/tx_status":
            self._serve_v1_tx_status(split.query)
            return
        if path == "/v1/proposals":
            # List open + recent governance proposals.  When an entity
            # is loaded, auto-fills voter_id so the response includes
            # a per-proposal ``voted`` flag that the UI uses to dim
            # already-voted entries.
            self._serve_v1_proposals(split.query)
            return
        if path == "/v1/profile":
            # Rich entity profile (balance, stake, first-seen block,
            # fees_paid, governance + reaction stats).  Backs the
            # profile modal's reputation score (sqrt(age_blocks *
            # fees_paid)).  Heavier than /v1/entity (O(N) chain walk)
            # so call it on-demand, not in a poll loop.
            self._serve_v1_profile(split.query)
            return
        if path == "/wallet/estimate-fee":
            self._serve_wallet_estimate_fee(split.query)
            return

        self._send_text(404, "Not Found")

    def do_POST(self):
        if not self._check_host_header_or_reject():
            return
        split = urlsplit(self.path)
        path = split.path

        # /wallet/login + /wallet/create-account are entry points
        # that MUST work without prior auth so an anonymous browser
        # (public mode) or a --read-only local startup can sign in
        # or mint a fresh demo account.  Every other write route
        # requires a valid session.
        if path == "/wallet/login":
            self._serve_wallet_login_post()
            return
        if path == "/wallet/create-account":
            self._serve_wallet_create_account_post()
            return

        if not self._check_token_or_reject(split.query):
            return

        if path == "/wallet/logout":
            self._serve_wallet_logout_post()
            return
        if path == "/wallet/send":
            self._serve_wallet_send_post()
            return
        if path == "/wallet/transfer":
            self._serve_wallet_transfer_post()
            return
        if path == "/wallet/stake":
            self._serve_wallet_stake_post()
            return
        if path == "/wallet/unstake":
            self._serve_wallet_unstake_post()
            return
        if path == "/wallet/react":
            self._serve_wallet_react_post()
            return
        if path == "/wallet/propose":
            self._serve_wallet_propose_post()
            return
        if path == "/wallet/vote-proposal":
            self._serve_wallet_vote_proposal_post()
            return

        self._send_text(404, "Not Found")

    # --- shared POST helpers ------------------------------------------

    def _read_json_body(self) -> tuple[bool, object]:
        """Read + parse a JSON request body.  Returns (ok, payload)."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        # Cap body size -- wallet write requests are small (text +
        # a few bytes of params).  10 KB is generous enough for the
        # max message + every other field, and small enough to not
        # let a misbehaving client wedge a handler thread.
        if length < 0 or length > 10_000:
            return False, {"error": "Content-Length missing or out of range"}
        if length == 0:
            return True, {}
        try:
            raw = self.rfile.read(length)
        except Exception as e:
            return False, {"error": f"body read failed: {type(e).__name__}"}
        try:
            return True, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return False, {"error": f"invalid JSON body: {type(e).__name__}"}

    # --- sign-in / sign-out -------------------------------------------

    def _serve_wallet_login_post(self):
        """POST /wallet/login

        Body:
          { "value": "<24-word mnemonic | 72-char checksummed hex |
                       64-char raw hex>",
            "duration_sec": <int seconds, default 86400, max 30 days> }

        Builds an ``Entity`` from the supplied private-key material
        and either:
          * (LOCAL mode) replaces the bootstrap session's entity --
            single-user model; subsequent /wallet/* requests using
            the bootstrap token sign as the new identity.
          * (PUBLIC mode) mints a fresh random session id and stores
            the entity against it; returns ``{session_id, expires_at}``
            so the browser can use it as the Bearer token from then
            on.

        IMPORTANT security note for PUBLIC mode: the server holds the
        loaded PK in process memory for the session's lifetime.  The
        UI surfaces a clear warning that this trust model is weaker
        than running the wallet locally.  PK never touches disk."""
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        value = body.get("value", "")
        if not isinstance(value, str) or not value.strip():
            self._send_json(400, {
                "ok": False,
                "error": "value required (paste hex / mnemonic / keyfile contents)",
            })
            return
        try:
            duration_sec = int(body.get("duration_sec", _DEFAULT_SESSION_SECONDS))
        except (TypeError, ValueError):
            duration_sec = _DEFAULT_SESSION_SECONDS

        # Parse the input.  decode_private_key accepts mnemonic +
        # 72-char checksummed hex; we add explicit support for the
        # 64-char raw hex form too (operator-paste convenience).
        from messagechain.identity.key_encoding import (
            decode_private_key,
            InvalidKeyChecksumError,
            InvalidKeyFormatError,
        )
        stripped = value.strip()
        try:
            private_key = decode_private_key(stripped)
        except InvalidKeyChecksumError as e:
            self._send_json(400, {
                "ok": False,
                "error": f"checksum mismatch -- looks like a typo: {e}",
            })
            return
        except InvalidKeyFormatError:
            # Fall back to raw 64-hex (no checksum protection -- the
            # daemon-format keyfile some operators have).
            low = stripped.lower()
            if len(low) == 64:
                try:
                    private_key = bytes.fromhex(low)
                    if len(private_key) != 32:
                        raise ValueError("not 32 bytes")
                except ValueError:
                    self._send_json(400, {
                        "ok": False,
                        "error": "invalid hex (expected 32 raw bytes / 64 hex chars)",
                    })
                    return
            else:
                self._send_json(400, {
                    "ok": False,
                    "error": (
                        "could not decode -- expected a 24-word mnemonic, "
                        "a 72-char checksummed hex, or a 64-char raw hex"
                    ),
                })
                return

        # Build the Entity.  Slow on first-ever load of a new key
        # (full WOTS+ keygen); fast on cache hit.  The HTTP request
        # blocks for the full duration -- callers should expect
        # minutes the very first time.  PK is consumed after this
        # call returns; only the derived Entity (which holds the
        # signing seed, NOT the original PK) is stored in memory.
        try:
            from messagechain.cli import _resolve_signing_entity
            entity = _resolve_signing_entity(private_key, args=None)
        except Exception as e:
            logger.warning(
                "wallet login keygen failed: %s", type(e).__name__,
            )
            self._send_json(500, {
                "ok": False,
                "error": f"keygen failed ({type(e).__name__})",
            })
            return
        # Drop the raw PK reference NOW, before storing the session
        # (the Entity holds a derived seed only).
        private_key = None

        ctx = self.server._wallet_context
        if ctx.public_mode:
            sid = ctx.add_session(entity, duration_sec)
            self._send_json(200, {
                "ok": True,
                "session_id": sid,
                "expires_at": ctx.sessions[sid].expires_at,
                "entity_id": entity.entity_id_hex,
            })
        else:
            # LOCAL single-user mode: overlay the bootstrap session.
            ctx.entity = entity  # property setter mutates bootstrap
            self._send_json(200, {
                "ok": True,
                "session_id": ctx.bootstrap_token,
                "expires_at": None,
                "entity_id": entity.entity_id_hex,
            })

    def _serve_wallet_create_account_post(self):
        """POST /wallet/create-account

        Demo-account flow for the public deployment.  Generates a
        fresh 32-byte private key, builds a small-tree (h=12) Entity
        from it, faucet-funds the resulting wallet, and signs the
        new user in (returning the freshly-minted PK + the session
        token).  The browser is expected to:
          1. immediately download the PK as a .key file (the only
             copy ever produced -- if the user closes the page
             without downloading, the wallet is irrecoverable);
          2. store the session token to keep the user signed in.

        Disabled when the operator did not configure a faucet
        keyfile -- no faucet means no funded demo wallets.

        Threat model: this is for browsers using messagechain.org as
        a demo.  The PK lives in browser memory + server memory for
        the session.  Real wallets should be generated offline per
        the README's `messagechain generate-key` workflow."""
        ctx = self.server._wallet_context
        if ctx.faucet is None:
            self._send_json(503, {
                "ok": False,
                "error": "Create Account is not enabled on this server "
                         "(operator did not configure --faucet-keyfile).",
            })
            return

        # Optional duration override; same default + cap as login.
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        try:
            duration_sec = int(body.get("duration_sec", _DEFAULT_SESSION_SECONDS))
        except (TypeError, ValueError):
            duration_sec = _DEFAULT_SESSION_SECONDS

        # 1. Generate a fresh PK (cryptographically random).  No
        #    persistence on the server side; the user gets a copy
        #    via the response and is responsible for saving it.
        from messagechain.identity.identity import Entity
        from messagechain.identity.address import encode_address
        from messagechain.identity.key_encoding import encode_to_mnemonic

        new_pk = secrets.token_bytes(32)

        # 2. Build the demo-tree Entity.  Sub-second at h=12.
        try:
            new_entity = Entity.create(
                new_pk, tree_height=DEMO_ACCOUNT_TREE_HEIGHT,
            )
        except Exception as e:
            logger.warning("create-account keygen failed: %s", type(e).__name__)
            self._send_json(500, {
                "ok": False,
                "error": f"keygen failed ({type(e).__name__})",
            })
            return

        # 3. Faucet-fund the new wallet.  drip_for_quickpost shares
        #    the rate-limit + window-cap machinery /faucet uses
        #    (per-/24 cooldown, window cap) so an attacker cannot
        #    spam create-account to drain the faucet.
        client_ip = self.client_address[0] if self.client_address else ""
        drip = ctx.faucet.drip_for_quickpost(
            client_ip, new_entity.entity_id,
        )
        if not drip.ok:
            self._send_json(429, {
                "ok": False,
                "error": "faucet drip refused: " + (drip.error or "unknown"),
                "remaining_window": drip.remaining_window,
            })
            return

        # 4. Mint a session for the new entity (PUBLIC mode only --
        #    the LOCAL bootstrap-overlay path doesn't apply since
        #    create-account is a public-deploy feature).
        if ctx.public_mode:
            sid = ctx.add_session(new_entity, duration_sec)
            expires_at = ctx.sessions[sid].expires_at
        else:
            ctx.entity = new_entity  # property setter
            sid = ctx.bootstrap_token
            expires_at = None

        # 5. Return the PK + session.  Browser downloads the PK and
        #    stores the session.
        try:
            mnemonic = encode_to_mnemonic(new_pk)
        except Exception:
            mnemonic = None
        self._send_json(200, {
            "ok": True,
            "session_id": sid,
            "expires_at": expires_at,
            "entity_id": new_entity.entity_id_hex,
            "address": encode_address(new_entity.entity_id),
            "private_key_hex": new_pk.hex(),
            "mnemonic": mnemonic,
            "drip_tx_hash": drip.tx_hash,
            "tree_height": DEMO_ACCOUNT_TREE_HEIGHT,
            "sigs_total": 1 << DEMO_ACCOUNT_TREE_HEIGHT,
        })

    def _serve_wallet_logout_post(self):
        """POST /wallet/logout -- end the current session.

        In LOCAL mode this clears the bootstrap session's entity
        (the user is back to read-only without losing their token).
        In PUBLIC mode it removes the session entirely; subsequent
        requests with the same Bearer token get 401."""
        ctx = self.server._wallet_context
        provided = _extract_provided_token(
            self.headers, urlsplit(self.path).query,
        )
        if (not ctx.public_mode and provided
                and hmac.compare_digest(provided, ctx.bootstrap_token)):
            ctx.entity = None  # property setter
            self._send_json(200, {"ok": True})
            return
        if provided:
            ctx.end_session(provided)
        self._send_json(200, {"ok": True})

    # --- wallet write routes ------------------------------------------

    def _send_op_result(self, result: dict):
        """Map a wallet_ops flat result dict to an HTTP response.

        200 -- chain accepted; 400 -- caller-fixable input;
        502 -- chain rejected; 503 -- RPC unreachable / read-only."""
        if result.get("ok"):
            self._send_json(200, result)
            return
        err = (result.get("error") or "").lower()
        if ("unreachable" in err or "read-only" in err
                or "no wallet loaded" in err):
            status = 503
        elif "must" in err and (
            "string" in err or "integer" in err or "bytes" in err
            or "positive" in err
        ):
            status = 400
        else:
            status = 502
        self._send_json(status, result)

    def _require_entity_or_503(self):
        """Return the current request's session entity if loaded,
        otherwise send 503 and return None.  Per-session in public
        mode (each browser has its own); single-entity in local
        mode (the bootstrap session)."""
        entity = self._current_entity()
        if entity is None:
            self._send_json(503, {
                "ok": False,
                "error": "no wallet loaded for this session -- sign in first",
            })
            return None
        return entity

    def _serve_wallet_send_post(self):
        """POST /wallet/send -- sign + submit a message tx.

        Body (JSON):
            {
              "message": "<text>",
              "fee": <int>,
              "prev": "<64-hex>" | null,             # optional reply pointer
              "community_id": "<handle>" | null,     # optional grouping
              "include_pubkey": <bool>,              # first-spend flag
              "poll_options": ["A","B"] | null,      # poll-creating tx
              "vote_target": ["<poll_txid_hex>", <int>] | null  # vote tx
            }

        Returns the tx_hash on success.  Rejects when no entity is
        loaded (read-only mode), the validator is unreachable, or the
        chain rejects the tx (e.g. fee too low, leaf consumed)."""
        entity = self._require_entity_or_503()
        if entity is None:
            return

        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return

        # Optional fields normalized + validated cheaply BEFORE the
        # signing call so we never burn a WOTS+ leaf on a doomed tx.
        prev_bytes = None
        prev_hex = body.get("prev")
        if prev_hex:
            if not isinstance(prev_hex, str) or len(prev_hex) != 64:
                self._send_json(400, {
                    "ok": False, "error": "prev must be 64 hex chars",
                })
                return
            try:
                prev_bytes = bytes.fromhex(prev_hex)
            except ValueError:
                self._send_json(400, {
                    "ok": False, "error": "prev must be valid hex",
                })
                return

        community_id = body.get("community_id")
        if community_id is not None and not isinstance(community_id, str):
            self._send_json(400, {
                "ok": False, "error": "community_id must be a string",
            })
            return

        poll_options = body.get("poll_options")
        if poll_options is not None:
            if not isinstance(poll_options, list) or not all(
                isinstance(x, str) for x in poll_options
            ):
                self._send_json(400, {
                    "ok": False,
                    "error": "poll_options must be a list of strings",
                })
                return
            poll_options = tuple(poll_options)

        vote_target = body.get("vote_target")
        if vote_target is not None:
            if (
                not isinstance(vote_target, list)
                or len(vote_target) != 2
                or not isinstance(vote_target[0], str)
                or not isinstance(vote_target[1], int)
            ):
                self._send_json(400, {
                    "ok": False,
                    "error": "vote_target must be [poll_txid_hex, option_index_int]",
                })
                return
            if len(vote_target[0]) != 64:
                self._send_json(400, {
                    "ok": False,
                    "error": "vote_target poll_txid must be 64 hex chars",
                })
                return
            try:
                vt_pid = bytes.fromhex(vote_target[0])
            except ValueError:
                self._send_json(400, {
                    "ok": False,
                    "error": "vote_target poll_txid must be valid hex",
                })
                return
            vote_target = (vt_pid, vote_target[1])

        from messagechain.network.wallet_ops import op_send_message
        ctx = self.server._wallet_context
        result = op_send_message(
            entity,
            ctx.rpc_caller,
            message=body.get("message", ""),
            fee=body.get("fee", 0),
            prev=prev_bytes,
            community_id=community_id,
            poll_options=poll_options,
            vote_target=vote_target,
            include_pubkey=bool(body.get("include_pubkey", False)),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_transfer_post(self):
        """POST /wallet/transfer

        Body:
          { "recipient_id": "<mc1...checksummed-address>" | "<64-hex>",
            "amount": int, "fee": int, "include_pubkey"?: bool }

        Recipient accepts EITHER the user-facing checksummed
        ``mc1<64hex><8hex>`` form (typo-resistant; what the UI shows
        to the user) OR a raw 64-char hex entity_id (back-compat
        for clients that already have one).  The decode helper
        rejects bad checksums with a clear error -- a single
        mistyped character in the address is caught BEFORE any leaf
        burns, mirroring the CLI's transfer protection."""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return

        rid_str = body.get("recipient_id")
        if not isinstance(rid_str, str) or not rid_str.strip():
            self._send_json(400, {
                "ok": False, "error": "recipient_id is required",
            })
            return
        from messagechain.identity.address import (
            decode_address,
            InvalidAddressError,
            InvalidAddressChecksumError,
        )
        try:
            recipient_bytes = decode_address(rid_str.strip())
        except InvalidAddressChecksumError:
            self._send_json(400, {
                "ok": False,
                "error": (
                    "address checksum mismatch -- looks like a transcription "
                    "error.  Re-check the address character by character."
                ),
            })
            return
        except InvalidAddressError as e:
            self._send_json(400, {
                "ok": False,
                "error": f"invalid recipient: {e}",
            })
            return

        from messagechain.network.wallet_ops import op_transfer
        ctx = self.server._wallet_context
        result = op_transfer(
            entity, ctx.rpc_caller,
            recipient=recipient_bytes,
            amount=body.get("amount", 0),
            fee=body.get("fee", 0),
            include_pubkey=bool(body.get("include_pubkey", False)),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_stake_post(self):
        """POST /wallet/stake  -- {amount, fee, include_pubkey?}"""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        from messagechain.network.wallet_ops import op_stake
        ctx = self.server._wallet_context
        result = op_stake(
            entity, ctx.rpc_caller,
            amount=body.get("amount", 0),
            fee=body.get("fee", 0),
            include_pubkey=bool(body.get("include_pubkey", False)),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_unstake_post(self):
        """POST /wallet/unstake  -- {amount, fee}

        Hot-key path only.  Cold-authority unstake belongs in the CLI
        with --cold-keyfile -- the wallet UI does not load cold keys."""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        from messagechain.network.wallet_ops import op_unstake
        ctx = self.server._wallet_context
        result = op_unstake(
            entity, ctx.rpc_caller,
            amount=body.get("amount", 0),
            fee=body.get("fee", 0),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_react_post(self):
        """POST /wallet/react  -- {target_hex, target_is_user, choice, fee}

        ``target_is_user``: True for entity-trust votes (target is a
        32B entity_id), False for message-quality votes (target is a
        32B tx_hash).  ``choice`` is the on-wire react int (CLEAR=0,
        UP=1, DOWN=2)."""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        target_hex = body.get("target")
        if not isinstance(target_hex, str) or len(target_hex) != 64:
            self._send_json(400, {
                "ok": False, "error": "target must be 64 hex chars",
            })
            return
        try:
            target_bytes = bytes.fromhex(target_hex)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "target must be valid hex",
            })
            return
        if not isinstance(body.get("target_is_user"), bool):
            self._send_json(400, {
                "ok": False, "error": "target_is_user must be a boolean",
            })
            return
        from messagechain.network.wallet_ops import op_react
        ctx = self.server._wallet_context
        result = op_react(
            entity, ctx.rpc_caller,
            target=target_bytes,
            target_is_user=body["target_is_user"],
            choice=body.get("choice", 0),
            fee=body.get("fee", 0),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_propose_post(self):
        """POST /wallet/propose  -- {title, description, reference_hash?, fee?}

        Governance proposals are deliberately expensive (CLAUDE.md
        anchor) -- omit ``fee`` to use the height-aware floor."""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        ref_hex = body.get("reference_hash") or ""
        if ref_hex and (not isinstance(ref_hex, str) or len(ref_hex) % 2):
            self._send_json(400, {
                "ok": False, "error": "reference_hash must be hex",
            })
            return
        try:
            ref_bytes = bytes.fromhex(ref_hex) if ref_hex else b""
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "reference_hash must be valid hex",
            })
            return
        from messagechain.network.wallet_ops import op_propose
        ctx = self.server._wallet_context
        result = op_propose(
            entity, ctx.rpc_caller,
            title=body.get("title", ""),
            description=body.get("description", ""),
            reference_hash=ref_bytes,
            fee=body.get("fee"),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_vote_proposal_post(self):
        """POST /wallet/vote-proposal  -- {proposal_id_hex, approve, fee?}

        Distinct from /wallet/send's poll-vote (which votes on a
        message-tx poll).  This is governance: voting on a proposal
        opened via /wallet/propose."""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return
        pid_hex = body.get("proposal_id")
        if not isinstance(pid_hex, str) or len(pid_hex) != 64:
            self._send_json(400, {
                "ok": False, "error": "proposal_id must be 64 hex chars",
            })
            return
        try:
            pid_bytes = bytes.fromhex(pid_hex)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "proposal_id must be valid hex",
            })
            return
        if not isinstance(body.get("approve"), bool):
            self._send_json(400, {
                "ok": False, "error": "approve must be a boolean",
            })
            return
        from messagechain.network.wallet_ops import op_vote_proposal
        ctx = self.server._wallet_context
        result = op_vote_proposal(
            entity, ctx.rpc_caller,
            proposal_id=pid_bytes,
            approve=body["approve"],
            fee=body.get("fee"),
            data_dir=getattr(ctx, "data_dir", None),
        )
        self._send_op_result(result)

    def _serve_wallet_estimate_fee(self, query: str):
        """GET /wallet/estimate-fee?tx_type=K&message_bytes=N&payload_bytes=P&recipient_id=H

        Audit r58 #2: routes through the unified ``estimate_fee`` RPC
        that audit r57 #1 already lifted on the CLI side -- so the
        wallet-UI's per-kind fee preview matches the CLI's per-kind
        quote at the same height, with the live ``supply.base_fee``
        and ``NEW_ACCOUNT_FEE`` branch folded in.

        Defaults: ``tx_type=message`` and ``message_bytes=0`` preserve
        the pre-r58 byte-count-only surface for any existing caller
        that doesn't pass ``tx_type``."""
        params = parse_qs(query or "")
        tx_type = (params.get("tx_type") or ["message"])[0]
        raw_bytes = (params.get("message_bytes") or ["0"])[0]
        try:
            mb = int(raw_bytes)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "message_bytes must be an integer",
            })
            return
        raw_payload = (params.get("payload_bytes") or ["0"])[0]
        try:
            pb = int(raw_payload)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "payload_bytes must be an integer",
            })
            return
        recipient_id = (params.get("recipient_id") or [""])[0]
        urgency = (params.get("urgency") or ["normal"])[0]
        ctx = self.server._wallet_context
        from messagechain.network.wallet_ops import op_estimate_fee
        result = op_estimate_fee(
            ctx.rpc_caller,
            tx_type=tx_type,
            message_bytes=mb,
            payload_bytes=pb,
            recipient_id=recipient_id,
            urgency=urgency,
        )
        if result.get("ok"):
            self._send_json(200, result)
        else:
            err = (result.get("error") or "").lower()
            self._send_json(503 if "unreachable" in err else 502, result)

    # --- wallet identity / "you" panel --------------------------------

    def _serve_wallet_me(self):
        sess = self._current_session()
        ctx = self.server._wallet_context
        entity = sess.entity if sess else None
        if entity is None:
            # No wallet loaded for this session.  In LOCAL mode this
            # is the --read-only path; in PUBLIC mode it's any
            # anonymous browser before sign-in.
            self._send_json(200, {
                "ok": True,
                "mode": "read-only",
                "entity_id": None,
                # Audit r55 #1: ``address`` (the mc1... checksummed
                # display form) is part of the contract in both modes
                # so the UI's address-rendering code can switch on
                # presence without a key-missing branch.
                "address": None,
                "balance": None,
                "stake": None,
                "pubkey_registered": None,
                "sigs_remaining": None,
                "session_expires_at": None,
            })
            return

        entity_id_hex = entity.entity_id_hex

        ok, ent_resp = self._rpc("get_entity", {"entity_id": entity_id_hex})
        on_chain: dict = {}
        if ok and isinstance(ent_resp, dict) and ent_resp.get("ok"):
            on_chain = ent_resp.get("result") or {}

        keypair = getattr(entity, "keypair", None)
        num_leaves = getattr(keypair, "num_leaves", None)
        next_leaf = getattr(keypair, "_next_leaf", None)
        if isinstance(num_leaves, int) and isinstance(next_leaf, int):
            sigs_remaining = max(0, num_leaves - next_leaf)
        else:
            sigs_remaining = None

        from messagechain.identity.address import encode_address
        addr = encode_address(entity.entity_id)

        self._send_json(200, {
            "ok": True,
            "mode": "wallet",
            "entity_id": entity_id_hex,
            "address": addr,
            "balance": on_chain.get("balance"),
            "stake": on_chain.get("stake"),
            "pubkey_registered": on_chain.get("pubkey_registered"),
            "sigs_remaining": sigs_remaining,
            "session_expires_at": sess.expires_at if sess else None,
        })

    # --- read-side RPC proxies ----------------------------------------

    def _rpc(self, method: str, params: dict):
        """Call the configured RPC caller; return (ok, payload).

        On connection failure / unconfigured caller, returns
        ``(False, {"error": ...})`` so callers can map to a 503.  The
        wallet server depends on the local validator being reachable;
        when it is not, the right answer to the browser is "the chain
        backend is unavailable", not a misleading 200 with empty data."""
        ctx = self.server._wallet_context
        if ctx.rpc_caller is None:
            return False, {"error": "no RPC backend configured"}
        try:
            return True, ctx.rpc_caller(method, params)
        except Exception as e:
            logger.warning(
                "wallet RPC %s failed: %s", method, type(e).__name__,
            )
            return False, {"error": f"RPC unreachable: {type(e).__name__}"}

    def _serve_v1_info(self):
        ok, info_resp = self._rpc("get_chain_info", {})
        if not ok:
            self._send_json(503, {"ok": False, **info_resp})
            return
        if not info_resp.get("ok"):
            self._send_json(502, info_resp)
            return
        info = info_resp.get("result") or {}
        ctx = self.server._wallet_context
        body = {
            "ok": True,
            "chain_id": CHAIN_ID.decode("ascii", errors="replace"),
            "genesis_hash": info.get("genesis_hash"),
            "tip_hash": info.get("tip_hash"),
            "state_root": info.get("state_root"),
            "height": info.get("height"),
            "last_block_timestamp": info.get("last_block_timestamp"),
            "faucet_enabled": False,
            "quickpost_enabled": False,
            # Mode hint for the SPA: "local" = single-user loopback
            # wallet (this is your machine), "public" = shared deploy
            # (sign-in expected, server holds your PK during the
            # session).  The UI renders different top-right
            # affordances per mode.
            "wallet_mode": "public" if ctx.public_mode else "local",
            # Whether /wallet/create-account will accept a request.
            # False when the operator did not configure
            # --faucet-keyfile (no faucet -> no funded demo wallet).
            # The UI hides the "Create Account" button accordingly.
            "create_account_enabled": ctx.faucet is not None,
            "demo_account_tree_height": DEMO_ACCOUNT_TREE_HEIGHT,
        }
        self._send_json(200, body)

    def _serve_v1_latest(self, query: str):
        params = parse_qs(query or "")
        raw_limit = (params.get("limit") or ["20"])[0]
        try:
            limit = int(raw_limit)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid limit"})
            return
        # Same clamp as PublicFeedServer so the UI cannot accidentally
        # request a chain-walk by passing an absurd value.
        limit = max(1, min(limit, PUBLIC_FEED_MAX_LIMIT))

        ok_msgs, msgs_resp = self._rpc("get_messages", {"count": limit})
        if not ok_msgs:
            self._send_json(503, {"ok": False, **msgs_resp})
            return
        if not msgs_resp.get("ok"):
            self._send_json(502, msgs_resp)
            return
        ok_info, info_resp = self._rpc("get_chain_info", {})
        height = None
        if ok_info and info_resp.get("ok"):
            height = (info_resp.get("result") or {}).get("height")
        messages = (msgs_resp.get("result") or {}).get("messages") or []
        self._send_json(200, {
            "ok": True,
            "height": height,
            "messages": messages,
        })

    def _serve_v1_entity(self, query: str):
        params = parse_qs(query or "")
        raw_id = (params.get("id") or [""])[0].strip().lower()
        if not raw_id or len(raw_id) != 64:
            self._send_json(400, {
                "ok": False,
                "error": "id must be a 64-char hex entity_id",
            })
            return
        try:
            bytes.fromhex(raw_id)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "id must be valid hex"})
            return
        ok, resp = self._rpc("get_entity", {"entity_id": raw_id})
        if not ok:
            self._send_json(503, {"ok": False, **resp})
            return
        # Pass the RPC payload through unchanged; the public-feed
        # /v1/entity contract is identical to the RPC's get_entity
        # result, so re-shaping would be lossy busy-work.
        self._send_json(200 if resp.get("ok") else 404, resp)

    def _serve_v1_tx_status(self, query: str):
        params = parse_qs(query or "")
        tx_hash = (params.get("tx_hash") or [""])[0].strip().lower()
        if not tx_hash or len(tx_hash) != 64:
            self._send_json(400, {
                "ok": False,
                "error": "tx_hash must be 64 hex chars",
            })
            return
        try:
            bytes.fromhex(tx_hash)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "tx_hash must be valid hex"})
            return
        ok, resp = self._rpc("get_tx_status", {"tx_hash": tx_hash})
        if not ok:
            self._send_json(503, {"ok": False, **resp})
            return
        self._send_json(200 if resp.get("ok") else 404, resp)

    def _serve_v1_profile(self, query: str):
        """GET /v1/profile?id=<64-hex>  --  proxy get_entity_profile.

        Returns the rich profile dict from compute_entity_profile so
        the wallet UI's profile modal can render reputation + activity
        history.  O(N) chain walk on the validator side -- meant for
        on-demand opens, not poll loops."""
        params = parse_qs(query or "")
        raw_id = (params.get("id") or [""])[0].strip().lower()
        if not raw_id or len(raw_id) != 64:
            self._send_json(400, {
                "ok": False,
                "error": "id must be a 64-char hex entity_id",
            })
            return
        try:
            bytes.fromhex(raw_id)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "id must be valid hex"})
            return
        ok, resp = self._rpc("get_entity_profile", {"entity_id": raw_id})
        if not ok:
            self._send_json(503, {"ok": False, **resp})
            return
        self._send_json(200 if resp.get("ok") else 502, resp)

    def _serve_v1_proposals(self, query: str):
        """GET /v1/proposals  --  proxy list_proposals.

        When an entity is loaded for THIS request's session,
        ``voter_id`` is auto-filled so each row carries a ``voted``
        flag the UI uses to dim already-voted proposals.  Per-session
        in PUBLIC mode (each browser sees its own voted-flags)."""
        params: dict = {}
        per_session_entity = self._current_entity()
        if per_session_entity is not None:
            params["voter_id"] = per_session_entity.entity_id_hex
        # Allow caller to override (e.g. inspecting another entity's
        # voting record from the UI later).
        qparams = parse_qs(query or "")
        override = (qparams.get("voter_id") or [""])[0].strip().lower()
        if override:
            if len(override) != 64:
                self._send_json(400, {
                    "ok": False, "error": "voter_id must be 64 hex chars",
                })
                return
            try:
                bytes.fromhex(override)
            except ValueError:
                self._send_json(400, {
                    "ok": False, "error": "voter_id must be valid hex",
                })
                return
            params["voter_id"] = override
        ok, resp = self._rpc("list_proposals", params)
        if not ok:
            self._send_json(503, {"ok": False, **resp})
            return
        self._send_json(200 if resp.get("ok") else 502, resp)

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
        rpc_endpoint: tuple = ("127.0.0.1", 9334),
        rpc_caller: Optional[Callable] = None,
        data_dir: Optional[str] = None,
        public_mode: bool = False,
        faucet=None,
    ):
        # Public mode RELAXES the loopback bind check -- the wallet UI
        # is intended to be deployable to messagechain.org as a single
        # SPA shared with local users.  When public_mode=True, callers
        # are explicitly opting into the broader threat model
        # (server holds users' PKs in memory for their session
        # duration).  Loopback enforcement still applies in local mode.
        if not public_mode:
            _validate_loopback_bind(bind)
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self.public_mode = public_mode
        self.token = token if token is not None else _generate_session_token()
        self.entity = entity
        self.rpc_endpoint = tuple(rpc_endpoint)
        # Optional FaucetState (built by build_wallet_server_faucet).
        # When set, /wallet/create-account is enabled and /v1/info
        # advertises create_account_enabled=True.  Public-mode-only
        # in practice: a local wallet has no need for an in-UI
        # account-creation flow.
        self.faucet = faucet
        # Optional: validator co-host data dir.  When set, the wallet
        # server's leaf-cursor binder routes through
        # <data_dir>/leaf_index.json (the same file the daemon owns)
        # so cross-process WOTS+ leaf coordination is exact.  Unset
        # falls back to the per-user
        # ~/.messagechain/leaves/<entity>.idx file -- safe for
        # off-validator wallets but does NOT coordinate with a daemon
        # signing on the same key.  cmd_ui defaults this from the
        # global --data-dir flag.
        self.data_dir = data_dir
        # Tests inject `rpc_caller` directly to bypass the actual RPC
        # round-trip.  In production we lazily wrap `client.rpc_call`
        # against `rpc_endpoint`.
        if rpc_caller is None:
            host_, port_ = self.rpc_endpoint
            from client import rpc_call as _rpc_call

            def _default_caller(method: str, params: dict) -> dict:
                return _rpc_call(host_, port_, method, params)

            self.rpc_caller = _default_caller
        else:
            self.rpc_caller = rpc_caller
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
        ctx = _WalletHandlerContext(
            blockchain=self.blockchain,
            token=self.token,
            entity=self.entity,
            rpc_caller=self.rpc_caller,
            public_mode=self.public_mode,
        )
        ctx.data_dir = self.data_dir
        ctx.faucet = self.faucet
        self._httpd._wallet_context = ctx
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


# ---------------------------------------------------------------------
# Faucet wiring for `messagechain ui --public --faucet-keyfile`.
#
# The wallet server in public mode optionally hosts a "Create Account"
# flow that mints a fresh demo wallet, faucets it some starter
# tokens, and signs the user in.  This helper builds the FaucetState
# the create-account route uses.
#
# Differs from server.py's _build_faucet in that the build/submit
# callbacks talk to the validator over RPC (the wallet server is its
# own process, separate from the validator).  Otherwise the threat
# model + rate-limit + tree-height logic mirror it.
# ---------------------------------------------------------------------

def build_wallet_server_faucet(
    faucet_keyfile_path: str,
    rpc_caller: Callable,
    data_dir: Optional[str] = None,
):
    """Load a faucet wallet keyfile and wrap it in a FaucetState ready
    for the wallet server's /wallet/create-account route to call via
    ``drip_for_quickpost``.

    Tree height: probes the chain via get_entity RPC for any recorded
    height for this faucet entity; falls back to 16 (~65k leaves --
    ample for years of bootstrap drips).  Cold keygen is a one-shot
    cost amortized into the keypair_cache; warm restarts are ms.

    The build/submit callbacks share the same audit r54 #2 leaf-
    cursor chokepoint other CLI signing surfaces use, so a co-
    resident validator daemon won't race the faucet on WOTS+ leaves."""
    from messagechain.identity.identity import Entity
    from messagechain.identity.keypair_cache import (
        load_or_create_personal_wallet_entity,
    )
    from messagechain.config import (
        MIN_FEE_POST_FLAT, NEW_ACCOUNT_FEE,
    )
    from messagechain.core.transfer import create_transfer_transaction
    from messagechain.network.faucet import FaucetState, FAUCET_DRIP

    # Load keyfile (raw 64-char hex, daemon-format; same shape
    # _build_faucet on server.py expects).
    with open(faucet_keyfile_path) as kf:
        hex_key = kf.read().strip()
    try:
        private_key = bytes.fromhex(hex_key)
    except ValueError as e:
        raise SystemExit(
            f"--faucet-keyfile {faucet_keyfile_path}: not valid hex ({e})"
        )
    if len(private_key) != 32:
        raise SystemExit(
            f"--faucet-keyfile {faucet_keyfile_path}: expected 64 hex "
            f"chars / 32 raw bytes, got {len(hex_key)} chars"
        )

    # Probe chain for recorded tree height; default to 16.
    probe_eid = Entity.create(private_key, tree_height=4).entity_id
    tree_height = 16
    try:
        resp = rpc_caller("get_entity", {"entity_id": probe_eid.hex()})
        if isinstance(resp, dict) and resp.get("ok"):
            h = (resp.get("result") or {}).get("tree_height")
            if isinstance(h, int) and h > 0:
                tree_height = h
    except Exception:
        pass

    logger.info(
        "Building wallet-server faucet (entity probe %s, tree_height=%d)...",
        probe_eid.hex()[:16], tree_height,
    )
    # load_or_create_personal_wallet_entity routes through the same
    # HMAC-authenticated keypair_cache the CLI uses, so a previously-
    # warmed faucet keypair loads in ms.
    entity = load_or_create_personal_wallet_entity(
        private_key, tree_height=tree_height,
    )
    logger.info(
        "Faucet wallet loaded for create-account: %s", entity.entity_id_hex[:16],
    )

    # Pubkey-installed flag mirrors server.py _build_faucet -- avoid
    # repeated include_pubkey on subsequent drips (chain rejects).
    pubkey_known_installed = [False]

    from messagechain.cli import _resolve_signing_leaf_via_caller

    def build_tx(recipient_bytes: bytes) -> dict:
        # Probe chain to know whether faucet pubkey already installed.
        # Refresh on every drip so a chain restart / first-spend
        # transition is picked up.
        if not pubkey_known_installed[0]:
            try:
                ent_resp = rpc_caller(
                    "get_entity", {"entity_id": entity.entity_id_hex},
                )
                if (isinstance(ent_resp, dict) and ent_resp.get("ok")
                        and (ent_resp.get("result") or {}).get("pubkey_registered")):
                    pubkey_known_installed[0] = True
            except Exception:
                pass

        # Get nonce + leaf watermark via RPC.
        nonce_resp = rpc_caller(
            "get_nonce", {"entity_id": entity.entity_id_hex},
        )
        if not (isinstance(nonce_resp, dict) and nonce_resp.get("ok")):
            raise RuntimeError(
                "faucet get_nonce failed: " +
                str((nonce_resp or {}).get("error", "unknown"))
            )
        nonce = nonce_resp["result"]["nonce"]
        watermark = nonce_resp["result"].get("leaf_watermark", nonce)

        # Atomic leaf reservation + persistent cursor bind.  Same
        # chokepoint cmd_send / cmd_transfer / op_send_message use.
        _resolve_signing_leaf_via_caller(
            rpc_caller, entity,
            data_dir=data_dir, watermark_fallback=watermark,
        )

        fee = MIN_FEE_POST_FLAT + NEW_ACCOUNT_FEE
        include_pubkey = not pubkey_known_installed[0]
        tx = create_transfer_transaction(
            entity, bytes(recipient_bytes),
            amount=FAUCET_DRIP,
            nonce=nonce,
            fee=fee,
            include_pubkey=include_pubkey,
        )
        # Optimistic flip -- back-to-back drips serialized by the
        # FaucetState lock means this is safe.
        if include_pubkey:
            pubkey_known_installed[0] = True
        return tx.serialize()

    def submit_tx(tx_dict) -> tuple:
        try:
            resp = rpc_caller(
                "submit_transfer", {"transaction": tx_dict},
            )
        except Exception as e:
            return False, f"RPC submit_transfer failed: {type(e).__name__}"
        if isinstance(resp, dict) and resp.get("ok"):
            return True, ""
        return False, str((resp or {}).get("error", "unknown"))

    return FaucetState(
        submit_callback=submit_tx,
        build_tx_callback=build_tx,
    )
