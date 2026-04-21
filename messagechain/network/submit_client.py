"""
Censorship-resistant multi-submit client.

Why this module exists
======================
The official CLI used to submit a signed MessageTransaction by JSON-RPC
to a SINGLE trusted node.  That collapses the entire chain's
censorship-resistance posture down to "do you trust your one node?" —
useless for users who don't run their own validator and need real
diversity.  This module fans out a signed tx over HTTPS to N>=3
validator endpoints in parallel, with at least one path optionally
routed through Tor's SOCKS5 proxy.  Result: single-validator censorship
and single-endpoint blocking become useless against a client that
always reaches multiple paths.

Receipts
========
When `request_receipts=True` (the default), every endpoint is asked to
return a `SubmissionReceipt` — a signed commitment from that validator
that they admitted the tx into their mempool.  The CLI persists each
receipt to disk so that, if the receipted tx never lands on-chain
within EVIDENCE_INCLUSION_WINDOW blocks, the user can file a
`CensorshipEvidenceTx` to slash the offending validator.  This closes
the censorship loop: a coerced validator either admits the tx (and is
slashed for not including it) or refuses it (and a competing endpoint
will admit it).

SOCKS5 / Tor path
=================
Stdlib has no SOCKS5 client (only the server side via `socketserver`).
We implement a small RFC 1928 client here in <100 LoC of stdlib so a
user behind a DPI'd national firewall can route to a `.onion` endpoint
without adding a third-party pip dependency to the project's
zero-deps mandate.  No-auth method (0x00), CONNECT command (0x01),
DOMAINNAME address type (0x03 — required so .onion names aren't
DNS-resolved locally) and IPv4 (0x01) are the only types supported.

Endpoint sourcing
=================
Endpoints come from (priority order):
    1. CLI `--endpoints host:port,host:port,...`
    2. `messagechain.config_local.SUBMIT_ENDPOINTS`
    3. `messagechain.config.DEFAULT_SUBMIT_ENDPOINTS` — intentionally
       EMPTY by default to match the codebase's no-hardcoded-seeds
       policy.  Operators populate via config_local.

A future PR will add P2P-gossip-based endpoint discovery; out of scope
for this module.

No new pip deps.  Stdlib-only by design — `http.client`, `ssl`,
`socket`, `concurrent.futures.ThreadPoolExecutor`.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from messagechain.core.transaction import MessageTransaction
from messagechain.network.submission_receipt import SubmissionReceipt


__all__ = [
    "ValidatorEndpoint",
    "MultiSubmitResult",
    "SubmitClient",
]


# Default port for the public submission endpoint — matches the
# convention in submission_server.py.
DEFAULT_SUBMIT_PORT = 8443


@dataclass
class ValidatorEndpoint:
    """A single submission target.

    `via_tor=True` routes the connection through the local SOCKS5
    proxy (default 127.0.0.1:9050).  `insecure=True` accepts a
    self-signed cert without CA-chain verification — strictly worse
    than full TLS, but still better than plaintext for
    censorship-resistance because middle-boxes still cannot inspect
    the body.
    """

    host: str
    port: int = DEFAULT_SUBMIT_PORT
    via_tor: bool = False
    # Optional .onion address for endpoints accessed via Tor.  When
    # set, this is what we send in the SOCKS5 CONNECT request — `host`
    # is then ignored for the connect itself but kept around for
    # display/logging.
    hidden_service: Optional[str] = None
    # Per-endpoint TLS posture.  False = full CA-chain verification.
    # True = TOFU (no CA chain, no hostname check) — for self-signed
    # operator certs.  This is set by the caller when they explicitly
    # opt in; the SubmitClient never silently downgrades.
    insecure: bool = False

    @classmethod
    def parse(cls, spec: str) -> "ValidatorEndpoint":
        """Parse a `host[:port]` or `onion:host[:port]` string.

        Examples:
            'validator.example.com'           -> port 8443, plain
            'validator.example.com:8443'      -> port 8443, plain
            'abc1234.onion:8443'              -> via_tor=True
            'onion:abc1234.onion:8443'        -> via_tor=True (explicit)
        """
        s = spec.strip()
        if not s:
            raise ValueError("empty endpoint spec")
        via_tor = False
        if s.lower().startswith("onion:"):
            via_tor = True
            s = s[6:]
        # Final ':' splits host[:port]; the explicit "onion:" prefix
        # was already stripped above so any remaining colon is the
        # host:port separator.
        if ":" in s:
            host, port_s = s.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                raise ValueError(f"invalid port in {spec!r}: {port_s!r}")
        else:
            host = s
            port = DEFAULT_SUBMIT_PORT
        if not via_tor and host.lower().endswith(".onion"):
            via_tor = True
        return cls(host=host, port=port, via_tor=via_tor)


@dataclass
class MultiSubmitResult:
    """Aggregate outcome of a fan-out submission."""

    tx_hash: bytes
    successes: int
    receipts: list[SubmissionReceipt] = field(default_factory=list)
    rejections: list[tuple[ValidatorEndpoint, str]] = field(default_factory=list)
    elapsed_ms: int = 0


# ─── SOCKS5 client (RFC 1928) ────────────────────────────────────────


# REP codes per RFC 1928 §6.  Stable wire constants — keep verbatim.
_SOCKS5_REPLIES = {
    0: "succeeded",
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes; raise on short read."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"SOCKS5: short read (wanted {n}, got {len(buf)})"
            )
        buf += chunk
    return buf


def _socks5_connect(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Open a TCP socket to `socks_host:socks_port`, perform the SOCKS5
    no-auth handshake, request a CONNECT to `target_host:target_port`,
    and return the connected socket positioned for application data.

    Implements:
      * VER=5
      * METHODS=[0x00] (no-auth) only
      * CMD=0x01 (CONNECT) only
      * ATYP=0x03 (DOMAINNAME) when target_host is not a literal IPv4
      * ATYP=0x01 (IPv4) when target_host is a dotted-quad

    Why .onion-friendly: a SOCKS5 client that locally DNS-resolves
    target_host before sending an IP would leak that lookup out of the
    Tor circuit AND can't resolve .onion at all.  Sending DOMAINNAME
    ATYP delegates resolution to the Tor daemon, which is the whole
    point — no DNS leakage, .onion works.
    """
    sock = socket.create_connection(
        (socks_host, socks_port), timeout=timeout,
    )
    try:
        sock.settimeout(timeout)
        # Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no-auth)
        sock.sendall(b"\x05\x01\x00")
        reply = _recv_exact(sock, 2)
        if reply[0] != 0x05:
            raise ConnectionError(
                f"SOCKS5: bad version in greeting reply: {reply[0]}"
            )
        if reply[1] == 0xFF:
            raise ConnectionError(
                "SOCKS5: server rejected no-auth (0xFF NO ACCEPTABLE METHODS)"
            )
        if reply[1] != 0x00:
            raise ConnectionError(
                f"SOCKS5: server selected unsupported method 0x{reply[1]:02x}"
            )
        # Request: VER=5, CMD=0x01 (CONNECT), RSV=0x00, ATYP, addr, port(BE16).
        # Decide ATYP by trying to parse target_host as a dotted-quad.
        is_ipv4 = False
        try:
            socket.inet_aton(target_host)
            # Make sure it's not a hostname that just happens to start
            # with digits (inet_aton parses "1234" as a 32-bit number).
            if target_host.count(".") == 3:
                is_ipv4 = True
        except OSError:
            pass

        if is_ipv4:
            atyp = b"\x01"
            addr_bytes = socket.inet_aton(target_host)
        else:
            host_b = target_host.encode("idna") if any(
                ord(c) > 127 for c in target_host
            ) else target_host.encode("ascii")
            if len(host_b) > 255:
                raise ValueError(
                    f"SOCKS5: hostname too long ({len(host_b)} > 255)"
                )
            atyp = b"\x03"
            addr_bytes = bytes([len(host_b)]) + host_b

        port_bytes = struct.pack(">H", int(target_port))
        sock.sendall(b"\x05\x01\x00" + atyp + addr_bytes + port_bytes)

        # Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        head = _recv_exact(sock, 4)
        if head[0] != 0x05:
            raise ConnectionError(
                f"SOCKS5: bad version in CONNECT reply: {head[0]}"
            )
        rep = head[1]
        if rep != 0x00:
            msg = _SOCKS5_REPLIES.get(rep, f"unknown 0x{rep:02x}")
            raise ConnectionError(f"SOCKS5: CONNECT failed — {msg}")
        # Drain BND.ADDR + BND.PORT according to ATYP so the socket
        # is positioned at the start of the application stream.
        bnd_atyp = head[3]
        if bnd_atyp == 0x01:  # IPv4
            _recv_exact(sock, 4)
        elif bnd_atyp == 0x04:  # IPv6
            _recv_exact(sock, 16)
        elif bnd_atyp == 0x03:  # DOMAINNAME
            length_b = _recv_exact(sock, 1)
            _recv_exact(sock, length_b[0])
        else:
            raise ConnectionError(
                f"SOCKS5: unsupported BND ATYP 0x{bnd_atyp:02x}"
            )
        _recv_exact(sock, 2)  # BND.PORT
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


# ─── HTTP request helpers ────────────────────────────────────────────


def _ssl_context_for_endpoint(endpoint: ValidatorEndpoint) -> ssl.SSLContext:
    """Return an SSLContext for `endpoint`.

    Two postures:
      * insecure=False (default): full CA-chain verification via
        `ssl.create_default_context()`.
      * insecure=True: a context that DOES NOT verify the cert chain
        and DOES NOT check hostname.  This is what the CLI uses when
        the operator runs a self-signed cert; the connection is still
        encrypted (so middle-boxes can't inspect the body — central
        win for censorship resistance) but identity isn't checked.
        Caller MUST opt in to this mode explicitly.
    """
    if endpoint.insecure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _post_via_direct(
    endpoint: ValidatorEndpoint,
    body: bytes,
    timeout_s: float,
    request_receipt: bool,
) -> tuple[int, bytes]:
    """POST `body` to https://{endpoint}/v1/submit.

    Stdlib http.client.HTTPSConnection.  No retries — the SubmitClient
    layer is responsible for diversifying across endpoints and the
    user is responsible for retrying the whole submit if every
    endpoint failed.
    """
    ctx = _ssl_context_for_endpoint(endpoint)
    conn = http.client.HTTPSConnection(
        endpoint.host, endpoint.port, context=ctx, timeout=timeout_s,
    )
    try:
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
            "Connection": "close",
        }
        if request_receipt:
            headers["X-MC-Request-Receipt"] = "1"
        conn.request("POST", "/v1/submit", body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _post_via_tor(
    endpoint: ValidatorEndpoint,
    body: bytes,
    timeout_s: float,
    request_receipt: bool,
    tor_socks_host: str,
    tor_socks_port: int,
) -> tuple[int, bytes]:
    """POST through a SOCKS5 proxy + TLS, hand-built HTTP/1.1 framing.

    `endpoint.hidden_service` (if set) overrides `endpoint.host` for
    the SOCKS5 CONNECT — so the user can keep a friendly display host
    while sending the .onion as the actual SOCKS target.
    """
    target_host = endpoint.hidden_service or endpoint.host
    raw = _socks5_connect(
        tor_socks_host, tor_socks_port, target_host, endpoint.port,
        timeout=timeout_s,
    )
    try:
        ctx = _ssl_context_for_endpoint(endpoint)
        # For .onion endpoints, a hostname check is meaningless (the
        # cert is unlikely to bear the .onion CN) — force insecure mode
        # there even if the caller forgot to set it.  For clearnet-via-
        # Tor, the caller's `insecure` posture is honored.
        if target_host.lower().endswith(".onion"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sni = target_host if not target_host.lower().endswith(".onion") else None
        # Wrap the SOCKS-tunneled raw socket in TLS.
        tls = ctx.wrap_socket(
            raw, server_hostname=sni,
        )
        try:
            tls.settimeout(timeout_s)
            # Build a minimal HTTP/1.1 request by hand.
            req_lines = [
                f"POST /v1/submit HTTP/1.1",
                f"Host: {target_host}:{endpoint.port}",
                f"Content-Type: application/octet-stream",
                f"Content-Length: {len(body)}",
                f"Connection: close",
            ]
            if request_receipt:
                req_lines.append("X-MC-Request-Receipt: 1")
            head = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")
            tls.sendall(head + body)

            # Read full response into a buffer.
            buf = b""
            deadline = time.monotonic() + timeout_s
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("Tor path: response read timed out")
                try:
                    chunk = tls.recv(8192)
                except socket.timeout:
                    raise TimeoutError("Tor path: recv timed out")
                if not chunk:
                    break
                buf += chunk
            return _parse_http_response(buf)
        finally:
            try:
                tls.close()
            except OSError:
                pass
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        raise


def _parse_http_response(blob: bytes) -> tuple[int, bytes]:
    """Tiny HTTP/1.1 response parser sufficient for our handler's
    fixed `Connection: close` semantics.  Returns (status, body).
    """
    sep = blob.find(b"\r\n\r\n")
    if sep < 0:
        raise ConnectionError("Tor path: malformed HTTP response (no header end)")
    head = blob[:sep].decode("iso-8859-1", errors="replace")
    body = blob[sep + 4:]
    first_line = head.split("\r\n", 1)[0]
    parts = first_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ConnectionError(f"Tor path: bad status line: {first_line!r}")
    try:
        status = int(parts[1])
    except ValueError:
        raise ConnectionError(f"Tor path: non-integer status: {parts[1]!r}")
    return status, body


# ─── Receipt extraction ─────────────────────────────────────────────


def _extract_receipt(body: bytes) -> Optional[SubmissionReceipt]:
    """Pull a `SubmissionReceipt` out of a /v1/submit JSON response.

    Returns None if the response carries no receipt or if parsing
    fails — never raises.  The caller already knows the submission
    was a success at this point; absence of a receipt just means we
    can't use this endpoint as censorship evidence later.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    receipt_hex = payload.get("receipt")
    if not isinstance(receipt_hex, str) or not receipt_hex:
        return None
    try:
        return SubmissionReceipt.from_bytes(bytes.fromhex(receipt_hex))
    except (ValueError, Exception):
        return None


# ─── SubmitClient ───────────────────────────────────────────────────


class SubmitClient:
    """Fan a tx out to N validator endpoints in parallel.

    Default behavior: every endpoint is hit, the call returns when all
    have either succeeded or failed/timed out.  `min_successes` is
    advisory — the client returns the actual number of successes (it
    does NOT artificially block waiting for more), and the caller
    decides whether the result is good enough.

    Each per-endpoint request runs in its own thread so a slow or
    hung peer does not block the others.  Wall-clock latency is
    bounded by `per_endpoint_timeout_s` plus a small overhead.
    """

    def __init__(
        self,
        endpoints: list[ValidatorEndpoint],
        min_successes: int = 1,
        tor_socks_host: str = "127.0.0.1",
        tor_socks_port: int = 9050,
        per_endpoint_timeout_s: float = 10.0,
        request_receipts: bool = True,
    ):
        if not endpoints:
            raise ValueError("SubmitClient requires at least one endpoint")
        if min_successes < 1:
            raise ValueError("min_successes must be >= 1")
        self.endpoints = list(endpoints)
        self.min_successes = min_successes
        self.tor_socks_host = tor_socks_host
        self.tor_socks_port = tor_socks_port
        self.per_endpoint_timeout_s = per_endpoint_timeout_s
        self.request_receipts = request_receipts

    def _submit_one(
        self,
        endpoint: ValidatorEndpoint,
        body: bytes,
    ) -> tuple[ValidatorEndpoint, Optional[SubmissionReceipt], Optional[str]]:
        """Submit to a single endpoint.  Returns (endpoint, receipt, err).

        On success: err is None, receipt is either the parsed receipt
        or None if the server didn't return one.
        On failure: err is a short string describing why; receipt None.

        Broad-except wrap because a per-endpoint exception MUST NOT
        cascade into the other endpoints' results.
        """
        try:
            if endpoint.via_tor:
                status, body_resp = _post_via_tor(
                    endpoint, body, self.per_endpoint_timeout_s,
                    self.request_receipts,
                    self.tor_socks_host, self.tor_socks_port,
                )
            else:
                status, body_resp = _post_via_direct(
                    endpoint, body, self.per_endpoint_timeout_s,
                    self.request_receipts,
                )
        except (socket.timeout, TimeoutError) as e:
            return endpoint, None, f"timeout: {e}"
        except (ConnectionError, ssl.SSLError, OSError) as e:
            return endpoint, None, f"connection error: {e}"
        except Exception as e:  # noqa: BLE001 — defensive only
            return endpoint, None, f"unexpected error: {type(e).__name__}: {e}"

        if status != 200:
            # Try to surface the server's error text if it looks short.
            err_snip = body_resp[:200].decode("utf-8", errors="replace")
            return endpoint, None, f"http {status}: {err_snip}"

        receipt = _extract_receipt(body_resp) if self.request_receipts else None
        return endpoint, receipt, None

    def submit(self, tx: MessageTransaction) -> MultiSubmitResult:
        body = tx.to_bytes()
        t0 = time.monotonic()
        successes = 0
        receipts: list[SubmissionReceipt] = []
        rejections: list[tuple[ValidatorEndpoint, str]] = []

        # ThreadPoolExecutor ≥ N workers so every endpoint runs
        # concurrently — no head-of-line blocking on a slow peer.
        with ThreadPoolExecutor(max_workers=len(self.endpoints)) as pool:
            futures = [
                pool.submit(self._submit_one, ep, body)
                for ep in self.endpoints
            ]
            for fut in as_completed(futures):
                ep, receipt, err = fut.result()
                if err is not None:
                    rejections.append((ep, err))
                else:
                    successes += 1
                    if receipt is not None:
                        receipts.append(receipt)

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return MultiSubmitResult(
            tx_hash=tx.tx_hash,
            successes=successes,
            receipts=receipts,
            rejections=rejections,
            elapsed_ms=elapsed_ms,
        )
