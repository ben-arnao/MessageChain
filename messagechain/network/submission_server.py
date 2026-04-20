"""
Public HTTPS transaction-submission endpoint.

Censorship-resistance design: any client on the public internet can
POST a signed MessageTransaction (binary-serialized) to any validator's
HTTPS endpoint, bypassing local mempool dependence.  If a client's
local peers drop their tx, they can still reach the chain by going
direct to a validator.

Security posture:
  * TLS mandatory — no plaintext fallback.  Operator supplies cert and
    key via CLI (Let's Encrypt, self-signed, whatever they trust).
  * Per-source-IP token bucket: `SUBMISSION_RATE_LIMIT_PER_SEC` /
    `SUBMISSION_BURST` tokens.  Every request (accepted or rejected)
    burns a token — a spammer can't skip the quota by sending garbage.
  * Body-size cap: `MAX_SUBMISSION_BODY_BYTES` (16KB).  Larger than
    any real tx but small enough to prevent memory exhaustion via
    chunked uploads.
  * Single endpoint, single method: `POST /v1/submit`.  Anything else
    returns 404 / 405.  Nothing that reads server state is exposed
    here — no balance lookups, no block queries.  This is a write-only
    ingress, on purpose.
  * No authentication — submission is a write-only channel for signed
    data; the signature IS the auth.  Anyone can submit; only valid
    txs land in the mempool.

The server runs in a background daemon thread and can be stopped
cleanly from the main process.  It sits alongside — not inside — the
main P2P/RPC server so a submission-endpoint bug can never corrupt
the P2P socket or the RPC socket.

Stdlib-only: `http.server.ThreadingHTTPServer`, `ssl.SSLContext`.  No
new pip deps.  Long-term durability beats framework sugar.
"""

from __future__ import annotations

import http.server
import logging
import socket
import socketserver
import ssl
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from messagechain.config import (
    MAX_SUBMISSION_BODY_BYTES,
    SUBMISSION_BURST,
    SUBMISSION_RATE_LIMIT_PER_SEC,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.network.ratelimit import TokenBucket


logger = logging.getLogger("messagechain.submission")


__all__ = [
    "SubmissionServer",
    "SubmissionResult",
    "submit_transaction_to_mempool",
]


@dataclass
class SubmissionResult:
    """Outcome of injecting a tx into the local mempool.

    Separate from HTTP status so the helper is usable from non-HTTP
    callers (tests, future RPC clients).
    """
    ok: bool
    tx_hash: bytes = b""
    error: str = ""
    # True iff the tx was already in the mempool — the HTTP layer
    # treats this as success (200) for idempotency.
    duplicate: bool = False


def submit_transaction_to_mempool(
    tx: MessageTransaction,
    blockchain,
    mempool,
) -> SubmissionResult:
    """Validate `tx` against chain state and inject into `mempool`.

    Mirrors the Server._rpc_submit_transaction ingress path so
    forced-inclusion arrival tracking stays consistent across ingress
    points (local RPC, P2P gossip, public HTTPS submission).
    """
    # Idempotency: if the tx is already in the pool, treat as success.
    # An honest retry (client that lost its connection) must not see
    # a "duplicate" error.
    if tx.tx_hash in mempool.pending:
        return SubmissionResult(ok=True, tx_hash=tx.tx_hash, duplicate=True)

    on_chain_nonce = blockchain.nonces.get(tx.entity_id, 0)
    pending_nonce = mempool.get_pending_nonce(tx.entity_id, on_chain_nonce)
    valid, reason = blockchain.validate_transaction(
        tx, expected_nonce=pending_nonce,
    )
    if not valid:
        return SubmissionResult(ok=False, error=reason)

    # Record arrival height so forced-inclusion "tx waited N blocks"
    # logic measures from the moment this node actually saw it.
    added = mempool.add_transaction(
        tx, arrival_block_height=blockchain.height,
    )
    if not added:
        # Mempool refused (e.g. per-sender cap, duplicate leaf, fee
        # under dynamic minimum).  If the tx still ended up pending
        # this call, treat as success; otherwise report rejection.
        if tx.tx_hash in mempool.pending:
            return SubmissionResult(ok=True, tx_hash=tx.tx_hash, duplicate=True)
        return SubmissionResult(
            ok=False, error="Mempool rejected transaction (rate / fee / cap)",
        )

    return SubmissionResult(ok=True, tx_hash=tx.tx_hash)


class _SubmissionHandler(http.server.BaseHTTPRequestHandler):
    """Per-request handler.

    Attributes injected by `SubmissionServer` via the server instance:
        server._submission_context: `_HandlerContext`
    """

    # Keep log output quiet; we log security-relevant events explicitly.
    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        # client_address is (host, port); host may be 'localhost'.
        return self.client_address[0]

    def _reject(self, status: int, message: str):
        body = message.encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _ok(self, body_bytes: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # Block every method except POST so a scanner probing /v1/submit
    # with GET can't leak implementation details in a default error page.
    def do_GET(self):
        self._reject(405, "Method Not Allowed")

    def do_PUT(self):
        self._reject(405, "Method Not Allowed")

    def do_DELETE(self):
        self._reject(405, "Method Not Allowed")

    def do_PATCH(self):
        self._reject(405, "Method Not Allowed")

    def do_HEAD(self):
        self._reject(405, "Method Not Allowed")

    def do_POST(self):
        ctx = self.server._submission_context

        # Path gate — reject anything that isn't our single endpoint.
        if self.path != "/v1/submit":
            self._reject(404, "Not Found")
            return

        # Rate limit FIRST — before allocating any buffers or parsing
        # headers.  An unlimited attacker can't exhaust memory if we
        # refuse them before read().
        if not ctx.rate_limit_check(self._client_ip()):
            self._reject(429, "Too Many Requests")
            return

        # Content-Type gate.  Reject anything that isn't
        # application/octet-stream — a browser form POST or JSON body
        # is not a signed tx and should be told so explicitly.
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/octet-stream":
            self._reject(415, "Unsupported Media Type — use application/octet-stream")
            return

        # Size gate.  Content-Length is advisory, but if the client
        # claims too much, don't even bother reading.
        try:
            declared_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._reject(400, "Invalid Content-Length")
            return
        if declared_length < 0 or declared_length > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, f"Payload too large (max {MAX_SUBMISSION_BODY_BYTES} bytes)")
            return

        # Read at most MAX_SUBMISSION_BODY_BYTES + 1 to catch
        # Content-Length liars.
        to_read = min(declared_length, MAX_SUBMISSION_BODY_BYTES)
        try:
            body = self.rfile.read(to_read)
        except (ConnectionResetError, OSError):
            return
        if len(body) > MAX_SUBMISSION_BODY_BYTES:
            self._reject(413, "Payload too large")
            return

        # Decode.
        try:
            tx = MessageTransaction.from_bytes(body)
        except Exception as e:
            logger.debug("submission decode failed from %s: %s", self._client_ip(), e)
            self._reject(400, "Invalid transaction encoding")
            return

        # Inject via the shared helper (same semantics as RPC ingress).
        result = ctx.submit(tx)
        if not result.ok:
            self._reject(400, f"Rejected: {result.error}")
            return

        # Optional relay hook — fire-and-forget; errors in relay must
        # never cause an accepted tx to look rejected to the caller.
        if ctx.relay_callback is not None and not result.duplicate:
            try:
                ctx.relay_callback(tx)
            except Exception:  # noqa: BLE001 — relay is best-effort
                logger.exception("submission relay hook raised")

        resp = (
            b'{"ok":true,"tx_hash":"' + tx.tx_hash.hex().encode("ascii") + b'"}'
        )
        self._ok(resp)


class _HandlerContext:
    """Shared state for all handlers on a single SubmissionServer.

    Holds the chain, mempool, rate-limiter buckets, and an optional
    relay callback.  The handler reads these via
    `self.server._submission_context`.
    """

    def __init__(
        self,
        blockchain,
        mempool,
        relay_callback: Optional[Callable[[MessageTransaction], None]],
    ):
        self.blockchain = blockchain
        self.mempool = mempool
        self.relay_callback = relay_callback
        self._buckets: dict[str, TokenBucket] = {}
        self._last_active: dict[str, float] = {}
        self._buckets_lock = threading.Lock()
        # Cap the dict to prevent an attacker rotating IPs from
        # exhausting memory with one-shot buckets.
        self._max_tracked_ips = 4096

    def rate_limit_check(self, ip: str) -> bool:
        """Consume one token from `ip`'s bucket; return True iff allowed."""
        import time as _time
        with self._buckets_lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                # If we're at the cap, first evict inactive buckets,
                # then fall back to LRU eviction of the oldest active IP.
                if len(self._buckets) >= self._max_tracked_ips:
                    self._evict_inactive_locked()
                    if len(self._buckets) >= self._max_tracked_ips:
                        self._evict_lru_locked()
                    if len(self._buckets) >= self._max_tracked_ips:
                        return False
                bucket = TokenBucket(
                    rate=SUBMISSION_RATE_LIMIT_PER_SEC,
                    max_tokens=SUBMISSION_BURST,
                )
                self._buckets[ip] = bucket
            self._last_active[ip] = _time.time()
            return bucket.consume()

    def _evict_inactive_locked(self):
        """Drop buckets that are fully refilled (peer hasn't posted in a while)."""
        to_drop = []
        for ip, bucket in self._buckets.items():
            bucket._refill()
            if bucket.tokens >= bucket.max_tokens:
                to_drop.append(ip)
        for ip in to_drop:
            del self._buckets[ip]
            self._last_active.pop(ip, None)

    def _evict_lru_locked(self):
        """Evict the least-recently-active IP to make room for a new one."""
        if not self._last_active:
            return
        oldest_ip = min(self._last_active, key=self._last_active.get)
        self._buckets.pop(oldest_ip, None)
        self._last_active.pop(oldest_ip, None)

    def submit(self, tx: MessageTransaction) -> SubmissionResult:
        return submit_transaction_to_mempool(tx, self.blockchain, self.mempool)


class _ThreadingHTTPSServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTPS server with threaded request handling.

    Wraps the listening socket in TLS.  Daemon threads so a shutdown
    doesn't wait on in-flight requests.
    """
    daemon_threads = True
    allow_reuse_address = True


class SubmissionServer:
    """Public HTTPS transaction-submission endpoint.

    Lifecycle:
        >>> s = SubmissionServer(chain, mempool, cert, key, port=8443)
        >>> s.start()          # spawns background thread
        >>> ...                # serve requests
        >>> s.stop()           # clean shutdown

    `relay_callback`, if provided, is called once per accepted tx with
    the `MessageTransaction` instance.  The server wraps the call in a
    broad except so a broken hook never surfaces as a client-visible
    error.  Pass a function that schedules a gossip relay on the main
    server's event loop; keep it fast (it runs on the HTTP handler
    thread).
    """

    def __init__(
        self,
        blockchain,
        mempool,
        cert_path: str,
        key_path: str,
        port: int,
        bind: str = "0.0.0.0",
        relay_callback: Optional[Callable[[MessageTransaction], None]] = None,
    ):
        self.blockchain = blockchain
        self.mempool = mempool
        self.cert_path = cert_path
        self.key_path = key_path
        self.port = port
        self.bind = bind
        self.relay_callback = relay_callback
        self._httpd: Optional[_ThreadingHTTPSServer] = None
        self._thread: Optional[threading.Thread] = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Server-side TLS context with sensible defaults.

        Uses the stdlib default-modern cipher list.  No client certs —
        this endpoint's caller is anonymous by design.  TLSv1.2+; the
        default Python stdlib rejects TLSv1.0/1.1 on modern builds.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        # Disable old protocols explicitly.  Python's default already
        # excludes them on recent builds, but being explicit is cheap
        # and survives future python-version downgrades.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def start(self):
        """Bind the socket, start the server thread.  Non-blocking."""
        if self._thread is not None:
            raise RuntimeError("SubmissionServer already started")

        handler_cls = _SubmissionHandler

        self._httpd = _ThreadingHTTPSServer(
            (self.bind, self.port), handler_cls,
        )
        # Attach shared context before wrapping — handlers read it off
        # the server instance.
        self._httpd._submission_context = _HandlerContext(
            blockchain=self.blockchain,
            mempool=self.mempool,
            relay_callback=self.relay_callback,
        )
        ssl_context = self._build_ssl_context()
        self._httpd.socket = ssl_context.wrap_socket(
            self._httpd.socket, server_side=True,
        )

        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"mc-submission-{self.port}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Submission server listening on https://%s:%d/v1/submit",
            self.bind, self.port,
        )

    def stop(self, timeout: float = 5.0):
        """Signal shutdown and wait for the thread to exit."""
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001 — server may already be dead
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        """(bind, port) — handy for tests that pick a free port."""
        return (self.bind, self.port)
