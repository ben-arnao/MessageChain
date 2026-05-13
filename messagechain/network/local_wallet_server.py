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
from typing import Callable, Optional
from urllib.parse import parse_qs, urlsplit

from messagechain.config import CHAIN_ID, PUBLIC_FEED_MAX_LIMIT


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

    def __init__(
        self,
        blockchain,
        token: str,
        entity=None,
        rpc_caller: Optional[Callable] = None,
    ):
        # Optional in the empty-shell phase.  Becomes required when
        # real read/write routes land.
        self.blockchain = blockchain
        self.token = token
        # Optional: an `Entity` (messagechain.identity.identity.Entity)
        # whose private key the server will use to sign /wallet/*
        # writes.  None for read-only / shell mode.
        self.entity = entity
        # Callable `(method: str, params: dict) -> dict` returning the
        # JSON-RPC response.  In production this is a thin wrapper
        # around `client.rpc_call(host, port, ...)` for the local
        # validator.  Tests inject a fake to avoid spinning a real
        # validator just to exercise the wallet-side routing.
        self.rpc_caller = rpc_caller


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
        if path == "/wallet/estimate-fee":
            self._serve_wallet_estimate_fee(split.query)
            return

        self._send_text(404, "Not Found")

    def do_POST(self):
        if not self._check_host_header_or_reject():
            return
        split = urlsplit(self.path)
        path = split.path
        # Every POST route is a write op -- token-required, no
        # bypass-listing.  Do the token check before any body parse.
        if not self._check_token_or_reject(split.query):
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

    # --- wallet write routes ------------------------------------------

    def _send_op_result(self, result: dict):
        """Map a wallet_ops flat result dict to an HTTP response.

        200 -- chain accepted; 400 -- caller-fixable input;
        502 -- chain rejected; 503 -- RPC unreachable / read-only."""
        if result.get("ok"):
            self._send_json(200, result)
            return
        err = (result.get("error") or "").lower()
        if "unreachable" in err or "read-only" in err:
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
        """Return ctx.entity if loaded, otherwise send 503 and return None."""
        ctx = self.server._wallet_context
        if ctx.entity is None:
            self._send_json(503, {
                "ok": False,
                "error": "wallet running in read-only mode (no key loaded)",
            })
            return None
        return ctx.entity

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
        """POST /wallet/transfer  -- {recipient_id_hex, amount, fee, include_pubkey?}"""
        entity = self._require_entity_or_503()
        if entity is None:
            return
        ok, body = self._read_json_body()
        if not ok or not isinstance(body, dict):
            err = body.get("error") if isinstance(body, dict) else "bad body"
            self._send_json(400, {"ok": False, "error": err})
            return

        rid_hex = body.get("recipient_id")
        if not isinstance(rid_hex, str) or len(rid_hex) != 64:
            self._send_json(400, {
                "ok": False, "error": "recipient_id must be 64 hex chars",
            })
            return
        try:
            recipient_bytes = bytes.fromhex(rid_hex)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "recipient_id must be valid hex",
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

    def _serve_wallet_estimate_fee(self, query: str):
        """GET /wallet/estimate-fee?message_bytes=N

        Pure RPC pass-through to the validator's get_fee_estimate.
        Surfaced as a wallet route so the composer can render a
        "this will cost ~X tokens" line BEFORE the user signs."""
        params = parse_qs(query or "")
        raw_bytes = (params.get("message_bytes") or ["0"])[0]
        try:
            mb = int(raw_bytes)
        except ValueError:
            self._send_json(400, {
                "ok": False, "error": "message_bytes must be an integer",
            })
            return
        ctx = self.server._wallet_context
        from messagechain.network.wallet_ops import op_estimate_fee
        result = op_estimate_fee(ctx.rpc_caller, message_bytes=mb)
        if result.get("ok"):
            self._send_json(200, result)
        else:
            err = (result.get("error") or "").lower()
            self._send_json(503 if "unreachable" in err else 502, result)

    # --- wallet identity / "you" panel --------------------------------

    def _serve_wallet_me(self):
        ctx = self.server._wallet_context
        if ctx.entity is None:
            # Read-only mode -- the page renders this as "no wallet
            # loaded; restart with --keyfile to enable signing".
            self._send_json(200, {
                "ok": True,
                "mode": "read-only",
                "entity_id": None,
                "balance": None,
                "stake": None,
                "pubkey_registered": None,
                "sigs_remaining": None,
            })
            return

        entity_id_hex = ctx.entity.entity_id_hex

        # Best-effort RPC pull for on-chain stats.  An unreachable
        # validator should NOT take the whole panel down -- the local
        # entity_id + leaf accounting are still useful, so return
        # what we have with the on-chain fields set to null.
        ok, ent_resp = self._rpc("get_entity", {"entity_id": entity_id_hex})
        on_chain: dict = {}
        if ok and isinstance(ent_resp, dict) and ent_resp.get("ok"):
            on_chain = ent_resp.get("result") or {}

        # WOTS+ remaining-signature count.  Each `_next_leaf` advance
        # consumes one one-time leaf; running out is a hard signing
        # stop.  Surfaced so the UI can warn the user before it bites
        # (the rotate-key flow is what they need next).  Pulled from
        # private attrs because the public surface doesn't expose them
        # -- an internal-only read, never written.
        keypair = getattr(ctx.entity, "keypair", None)
        num_leaves = getattr(keypair, "num_leaves", None)
        next_leaf = getattr(keypair, "_next_leaf", None)
        if isinstance(num_leaves, int) and isinstance(next_leaf, int):
            sigs_remaining = max(0, num_leaves - next_leaf)
        else:
            sigs_remaining = None

        self._send_json(200, {
            "ok": True,
            "mode": "wallet",
            "entity_id": entity_id_hex,
            "balance": on_chain.get("balance"),
            "stake": on_chain.get("stake"),
            "pubkey_registered": on_chain.get("pubkey_registered"),
            "sigs_remaining": sigs_remaining,
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
        # Reshape into the public-feed /v1/info contract so client JS
        # written against the public feed renders verbatim here.
        body = {
            "ok": True,
            "chain_id": CHAIN_ID.decode("ascii", errors="replace"),
            "genesis_hash": info.get("genesis_hash"),
            "tip_hash": info.get("tip_hash"),
            "state_root": info.get("state_root"),
            "height": info.get("height"),
            "last_block_timestamp": info.get("last_block_timestamp"),
            # Faucet / quickpost are operator-side public-feed knobs
            # and have no analogue here — the wallet UI signs its own
            # txs from the loaded entity.
            "faucet_enabled": False,
            "quickpost_enabled": False,
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
    ):
        _validate_loopback_bind(bind)
        self.blockchain = blockchain
        self.port = port
        self.bind = bind
        self.token = token if token is not None else _generate_session_token()
        self.entity = entity
        self.rpc_endpoint = tuple(rpc_endpoint)
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
        )
        ctx.data_dir = self.data_dir
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
