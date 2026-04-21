"""
Tests for the censorship-resistant multi-submit client.

The SubmitClient fans out a signed MessageTransaction to N>=3 validator
endpoints in parallel over HTTPS, with at least one path through Tor's
SOCKS5 proxy.  Single-validator censorship and single-endpoint blocking
become useless once the client routes through diverse paths.

These tests use stdlib http.server (TLS-wrapped) to spin up mock
validator endpoints and a tiny stdlib SOCKS5 mock to exercise the
Tor path.  No real Tor daemon is required.
"""

import http.client
import http.server
import json
import os
import select
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import MIN_FEE, FEE_PER_BYTE
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.crypto.keys import KeyPair
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.network.submission_receipt import (
    ReceiptIssuer, SubmissionReceipt, verify_receipt,
)
from messagechain.network.submission_server import SubmissionServer


_STATIC_FEE = DynamicFeePolicy(base_fee=100, max_fee=100)
_TEST_FEE = MIN_FEE + 40 * FEE_PER_BYTE


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _generate_self_signed_cert():
    """Self-signed cert via openssl subprocess.  Skip if unavailable."""
    tmp = tempfile.mkdtemp()
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key, "-out", cert, "-days", "1",
                "-nodes", "-subj", "/CN=localhost",
            ],
            check=True, capture_output=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise unittest.SkipTest(f"openssl not available: {e}")
    return cert, key, tmp


# ─── A canned mock validator endpoint ─────────────────────────────────
#
# We don't need full chain semantics for most submit-client tests; a
# tiny TLS HTTP handler that returns whatever we pre-program is enough.
# For the receipt-deserialization test we plug in a real ReceiptIssuer
# and have the handler emit a real-looking response.


class _CannedHandler(http.server.BaseHTTPRequestHandler):
    """Per-request handler that serves whatever the server has queued.

    The parent server holds:
        server._status_code: int
        server._response_body: bytes
        server._response_ct: str
        server._delay_s: float
        server._echo_tx_hash: bool   # if True and POST has a body, parse
                                     # the tx and substitute its hex hash
                                     # into the response template
        server._issuer: Optional[ReceiptIssuer]
    """

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        srv = self.server
        if srv._delay_s > 0:
            time.sleep(srv._delay_s)
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        resp_body = srv._response_body
        if srv._echo_tx_hash and body:
            try:
                tx = MessageTransaction.from_bytes(body)
                tx_hash_hex = tx.tx_hash.hex()
                if srv._issuer is not None:
                    receipt = srv._issuer.issue(tx.tx_hash)
                    receipt_hex = receipt.to_bytes().hex()
                    resp_body = (
                        b'{"ok":true,"tx_hash":"'
                        + tx_hash_hex.encode("ascii")
                        + b'","receipt":"'
                        + receipt_hex.encode("ascii")
                        + b'"}'
                    )
                else:
                    resp_body = (
                        b'{"ok":true,"tx_hash":"'
                        + tx_hash_hex.encode("ascii") + b'"}'
                    )
            except Exception:
                pass

        self.send_response(srv._status_code)
        self.send_header("Content-Type", srv._response_ct)
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(resp_body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class _ThreadedTLSServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _spawn_mock_validator(
    cert_path: str,
    key_path: str,
    port: int,
    *,
    status_code: int = 200,
    response_body: bytes = b'{"ok":true}',
    response_ct: str = "application/json",
    delay_s: float = 0.0,
    echo_tx_hash: bool = True,
    issuer=None,
):
    """Spin up a TLS HTTP server returning canned responses."""
    httpd = _ThreadedTLSServer(("127.0.0.1", port), _CannedHandler)
    httpd._status_code = status_code
    httpd._response_body = response_body
    httpd._response_ct = response_ct
    httpd._delay_s = delay_s
    httpd._echo_tx_hash = echo_tx_hash
    httpd._issuer = issuer

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    # Wait for socket to be listening.
    for _ in range(50):
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=0.1,
            ):
                break
        except OSError:
            time.sleep(0.02)
    return httpd


# ─── A tiny RFC1928 SOCKS5 mock ───────────────────────────────────────
#
# Implements just enough of SOCKS5 to test our SubmitClient's SOCKS5
# helper: no-auth method (0x00), CONNECT command (0x01), DOMAINNAME
# address type (0x03), IPv4 address type (0x01).  After the handshake
# the mock simply tunnels bytes to the real target.


class _Socks5Mock:
    def __init__(self):
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self.connections_handled = 0
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                client, _addr = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            t = threading.Thread(
                target=self._handle, args=(client,), daemon=True,
            )
            t.start()

    def _recv_n(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("short read")
            buf += chunk
        return buf

    def _handle(self, client):
        try:
            # Greeting: VER, NMETHODS, METHODS
            ver_nmethods = self._recv_n(client, 2)
            if ver_nmethods[0] != 0x05:
                client.close()
                return
            nmethods = ver_nmethods[1]
            self._recv_n(client, nmethods)
            # Reply: VER, METHOD (no-auth)
            client.sendall(b"\x05\x00")
            # Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
            hdr = self._recv_n(client, 4)
            if hdr[0] != 0x05 or hdr[1] != 0x01:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return
            atyp = hdr[3]
            if atyp == 0x01:  # IPv4
                addr_bytes = self._recv_n(client, 4)
                target_host = ".".join(str(b) for b in addr_bytes)
            elif atyp == 0x03:  # DOMAINNAME
                length_b = self._recv_n(client, 1)
                addr_bytes = self._recv_n(client, length_b[0])
                target_host = addr_bytes.decode("ascii")
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return
            port_b = self._recv_n(client, 2)
            target_port = struct.unpack(">H", port_b)[0]
            # Connect to target.
            try:
                # Re-route .onion-ish names to localhost for the mock.
                # Tests that pass a plain "localhost"/"127.0.0.1" hit it
                # directly; tests that pass "fakeonion.onion" map here.
                connect_host = target_host
                if connect_host.endswith(".onion") or connect_host == "fakeonion":
                    connect_host = "127.0.0.1"
                upstream = socket.create_connection(
                    (connect_host, target_port), timeout=5,
                )
            except OSError:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return
            # Success reply: VER, REP=0, RSV, ATYP=IPv4, BND.ADDR(0.0.0.0), BND.PORT(0)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self.connections_handled += 1
            self._tunnel(client, upstream)
        except Exception:
            try:
                client.close()
            except OSError:
                pass

    def _tunnel(self, a, b):
        """Bidirectional pipe until one side closes."""
        try:
            socks = [a, b]
            while True:
                r, _, _ = select.select(socks, [], [], 5.0)
                if not r:
                    break
                for s in r:
                    other = b if s is a else a
                    try:
                        data = s.recv(8192)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        other.sendall(data)
                    except OSError:
                        return
        finally:
            try:
                a.close()
            except OSError:
                pass
            try:
                b.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────


class SubmitClientTestBase(unittest.TestCase):
    """Provides a self-signed cert + a fresh chain per test."""

    @classmethod
    def setUpClass(cls):
        cls.cert_path, cls.key_path, cls.cert_dir = _generate_self_signed_cert()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        self.alice = Entity.create(b"alice-submit-client".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=_STATIC_FEE)
        self._spawned = []

    def tearDown(self):
        for httpd in self._spawned:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass

    def _make_tx(self, nonce: int = 0, fee: int = _TEST_FEE, msg: str = "hello"):
        return create_transaction(
            self.alice, f"{msg} {nonce}", fee=fee, nonce=nonce,
        )

    def _spawn(self, **kwargs):
        port = _find_free_port()
        httpd = _spawn_mock_validator(
            self.cert_path, self.key_path, port, **kwargs,
        )
        self._spawned.append(httpd)
        return port


# ───── Test 1: All endpoints accept ───────────────────────────────────


class TestAllEndpointsAccept(SubmitClientTestBase):
    def test_all_three_accept_returns_three_successes(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        ports = [self._spawn() for _ in range(3)]
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=p, insecure=True)
            for p in ports
        ]
        client = SubmitClient(endpoints, request_receipts=False)
        tx = self._make_tx()
        result = client.submit(tx)
        self.assertEqual(result.successes, 3)
        self.assertEqual(result.tx_hash, tx.tx_hash)
        self.assertEqual(len(result.rejections), 0)


# ───── Test 2: First accepts, rest reject ─────────────────────────────


class TestPartialReject(SubmitClientTestBase):
    def test_one_accept_two_reject_succeeds_with_min_one(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        good = self._spawn()
        bad1 = self._spawn(
            status_code=400, response_body=b"nope",
            response_ct="text/plain", echo_tx_hash=False,
        )
        bad2 = self._spawn(
            status_code=400, response_body=b"nope",
            response_ct="text/plain", echo_tx_hash=False,
        )
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=good, insecure=True),
            ValidatorEndpoint(host="127.0.0.1", port=bad1, insecure=True),
            ValidatorEndpoint(host="127.0.0.1", port=bad2, insecure=True),
        ]
        client = SubmitClient(endpoints, min_successes=1, request_receipts=False)
        tx = self._make_tx()
        result = client.submit(tx)
        self.assertEqual(result.successes, 1)
        self.assertEqual(len(result.rejections), 2)


# ───── Test 3: All endpoints reject ───────────────────────────────────


class TestAllReject(SubmitClientTestBase):
    def test_all_reject_returns_zero_successes_no_exception(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        ports = [
            self._spawn(
                status_code=400, response_body=b"err",
                response_ct="text/plain", echo_tx_hash=False,
            )
            for _ in range(3)
        ]
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=p, insecure=True)
            for p in ports
        ]
        client = SubmitClient(endpoints, min_successes=1, request_receipts=False)
        tx = self._make_tx()
        # Must NOT raise; caller decides what to do.
        result = client.submit(tx)
        self.assertEqual(result.successes, 0)
        self.assertEqual(len(result.rejections), 3)
        for ep, reason in result.rejections:
            self.assertTrue(reason)


# ───── Test 4: One endpoint times out ─────────────────────────────────


class TestTimeout(SubmitClientTestBase):
    def test_one_endpoint_times_out_other_succeeds(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        slow = self._spawn(delay_s=3.0)
        fast = self._spawn()
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=slow, insecure=True),
            ValidatorEndpoint(host="127.0.0.1", port=fast, insecure=True),
        ]
        client = SubmitClient(
            endpoints, min_successes=1,
            per_endpoint_timeout_s=0.5,
            request_receipts=False,
        )
        tx = self._make_tx()
        t0 = time.time()
        result = client.submit(tx)
        elapsed = time.time() - t0
        # Should not wait the full 3s — slow endpoint times out.
        self.assertLess(elapsed, 2.5)
        self.assertGreaterEqual(result.successes, 1)
        # The slow one is in rejections.
        self.assertGreaterEqual(len(result.rejections), 1)
        # Find the slow endpoint's rejection.
        slow_rejected = any(
            ep.port == slow and "timeout" in reason.lower()
            for ep, reason in result.rejections
        )
        self.assertTrue(
            slow_rejected,
            f"expected slow endpoint to be in rejections with timeout: "
            f"{result.rejections}",
        )


# ───── Test 5: min_successes=2, only 1 accepts ────────────────────────


class TestMinSuccesses(SubmitClientTestBase):
    def test_min_successes_two_only_one_accepts_returns_one(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        good = self._spawn()
        bad = self._spawn(
            status_code=400, response_body=b"err",
            response_ct="text/plain", echo_tx_hash=False,
        )
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=good, insecure=True),
            ValidatorEndpoint(host="127.0.0.1", port=bad, insecure=True),
        ]
        client = SubmitClient(
            endpoints, min_successes=2, request_receipts=False,
        )
        tx = self._make_tx()
        result = client.submit(tx)
        # Don't artificially block — return what we got.
        self.assertEqual(result.successes, 1)


# ───── Test 6: request_receipts=False ─────────────────────────────────


class TestNoReceipts(SubmitClientTestBase):
    def test_request_receipts_false_returns_no_receipts(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        # Build a real issuer + the canned-handler returns a real-ish
        # JSON, but the client must NOT parse the receipt back when
        # request_receipts=False.
        kp = KeyPair.generate(seed=b"recv-no-receipt", height=4)
        issuer = ReceiptIssuer(
            self.alice.entity_id, kp, height_fn=lambda: 0,
        )
        port = self._spawn(echo_tx_hash=True, issuer=issuer)
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=port, insecure=True),
        ]
        client = SubmitClient(endpoints, request_receipts=False)
        tx = self._make_tx()
        result = client.submit(tx)
        self.assertEqual(result.successes, 1)
        self.assertEqual(len(result.receipts), 0)


# ───── Test 7: TOFU/insecure mode accepts self-signed ─────────────────


class TestInsecureMode(SubmitClientTestBase):
    def test_insecure_mode_accepts_self_signed_cert(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        port = self._spawn()
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=port, insecure=True),
        ]
        client = SubmitClient(endpoints, request_receipts=False)
        tx = self._make_tx()
        result = client.submit(tx)
        # Self-signed accepted, success.
        self.assertEqual(result.successes, 1)


# ───── Test 8: parallel fan-out wall-clock ────────────────────────────


class TestParallelFanout(SubmitClientTestBase):
    def test_parallel_fanout_does_not_serialize_endpoints(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        slow = self._spawn(delay_s=2.0)
        fast = self._spawn(delay_s=0.1)
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=slow, insecure=True),
            ValidatorEndpoint(host="127.0.0.1", port=fast, insecure=True),
        ]
        client = SubmitClient(
            endpoints, min_successes=2,
            per_endpoint_timeout_s=5.0,
            request_receipts=False,
        )
        tx = self._make_tx()
        t0 = time.time()
        result = client.submit(tx)
        elapsed = time.time() - t0
        # Sequential would be > 2.1s; parallel ≈ 2.0s + small overhead.
        # Allow generous slack for slow CI.
        self.assertLess(elapsed, 3.0,
                        f"fan-out took {elapsed:.2f}s — should be <3s")
        self.assertEqual(result.successes, 2)


# ───── Test 9: SOCKS5 helper round-trip ───────────────────────────────


class TestSocks5Helper(SubmitClientTestBase):
    def test_socks5_connect_tunnels_to_target(self):
        from messagechain.network.submit_client import _socks5_connect
        # Spin up a plain TCP echo server.
        echo_sock = socket.socket()
        echo_sock.bind(("127.0.0.1", 0))
        echo_sock.listen(2)
        echo_port = echo_sock.getsockname()[1]
        stop = [False]

        def _serve():
            echo_sock.settimeout(0.5)
            while not stop[0]:
                try:
                    c, _ = echo_sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    data = c.recv(1024)
                    c.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                c.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

        socks = _Socks5Mock()
        try:
            sock = _socks5_connect(
                "127.0.0.1", socks.port, "127.0.0.1", echo_port,
                timeout=5.0,
            )
            sock.sendall(b"hello")
            buf = b""
            sock.settimeout(2.0)
            while len(buf) < len(b"ECHO:hello"):
                chunk = sock.recv(64)
                if not chunk:
                    break
                buf += chunk
            sock.close()
            self.assertEqual(buf, b"ECHO:hello")
            self.assertGreaterEqual(socks.connections_handled, 1)
        finally:
            stop[0] = True
            socks.stop()
            try:
                echo_sock.close()
            except OSError:
                pass

    def test_socks5_domainname_atyp(self):
        """A SOCKS5 request with a DOMAINNAME (.onion-style) address
        is sent with ATYP=0x03, length-prefixed.  The mock decodes
        that and routes to localhost — so an .onion-shaped name is
        correctly delivered without local DNS."""
        from messagechain.network.submit_client import _socks5_connect
        # Spin up a plain TCP echo server.
        echo_sock = socket.socket()
        echo_sock.bind(("127.0.0.1", 0))
        echo_sock.listen(2)
        echo_port = echo_sock.getsockname()[1]
        stop = [False]

        def _serve():
            echo_sock.settimeout(0.5)
            while not stop[0]:
                try:
                    c, _ = echo_sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    data = c.recv(1024)
                    c.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                c.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

        socks = _Socks5Mock()
        try:
            sock = _socks5_connect(
                "127.0.0.1", socks.port, "fakeonion", echo_port,
                timeout=5.0,
            )
            sock.sendall(b"x")
            buf = b""
            sock.settimeout(2.0)
            while len(buf) < len(b"ECHO:x"):
                chunk = sock.recv(64)
                if not chunk:
                    break
                buf += chunk
            sock.close()
            self.assertEqual(buf, b"ECHO:x")
        finally:
            stop[0] = True
            socks.stop()


# ───── Test 10: receipt deserialization & signature verifies ──────────


class TestReceiptRoundtrip(SubmitClientTestBase):
    def test_receipt_from_response_verifies(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        kp = KeyPair.generate(seed=b"recv-roundtrip", height=4)
        issuer = ReceiptIssuer(
            self.alice.entity_id, kp, height_fn=lambda: 7,
        )
        port = self._spawn(echo_tx_hash=True, issuer=issuer)
        endpoints = [
            ValidatorEndpoint(host="127.0.0.1", port=port, insecure=True),
        ]
        client = SubmitClient(endpoints, request_receipts=True)
        tx = self._make_tx()
        result = client.submit(tx)
        self.assertEqual(result.successes, 1)
        self.assertEqual(len(result.receipts), 1)
        receipt = result.receipts[0]
        self.assertEqual(receipt.tx_hash, tx.tx_hash)
        self.assertEqual(receipt.commit_height, 7)
        ok, reason = verify_receipt(receipt)
        self.assertTrue(ok, reason)


# ───── Test 11: Tor path via SOCKS5 ──────────────────────────────────


class TestTorPath(SubmitClientTestBase):
    def test_via_tor_routes_through_socks5(self):
        from messagechain.network.submit_client import (
            SubmitClient, ValidatorEndpoint,
        )
        port = self._spawn()
        socks = _Socks5Mock()
        try:
            endpoints = [
                ValidatorEndpoint(
                    host="127.0.0.1", port=port,
                    via_tor=True, insecure=True,
                ),
            ]
            client = SubmitClient(
                endpoints,
                tor_socks_host="127.0.0.1",
                tor_socks_port=socks.port,
                request_receipts=False,
                per_endpoint_timeout_s=10.0,
            )
            tx = self._make_tx()
            result = client.submit(tx)
            self.assertEqual(
                result.successes, 1,
                msg=f"rejections: {result.rejections}",
            )
            # Proof the Tor path was actually exercised: SOCKS5 mock
            # tracked a connection.
            self.assertGreaterEqual(socks.connections_handled, 1)
        finally:
            socks.stop()


# ───── Test 12: ValidatorEndpoint.parse helper ────────────────────────


class TestEndpointParse(unittest.TestCase):
    def test_parse_host_port(self):
        from messagechain.network.submit_client import ValidatorEndpoint
        ep = ValidatorEndpoint.parse("validator.example.com:8443")
        self.assertEqual(ep.host, "validator.example.com")
        self.assertEqual(ep.port, 8443)
        self.assertFalse(ep.via_tor)

    def test_parse_default_port(self):
        from messagechain.network.submit_client import ValidatorEndpoint
        ep = ValidatorEndpoint.parse("validator.example.com")
        self.assertEqual(ep.host, "validator.example.com")
        self.assertEqual(ep.port, 8443)

    def test_parse_onion_marks_via_tor(self):
        from messagechain.network.submit_client import ValidatorEndpoint
        ep = ValidatorEndpoint.parse(
            "abcdefghijklmnop234567ojvxyz.onion:8443",
        )
        self.assertTrue(ep.via_tor)
        self.assertEqual(ep.port, 8443)

    def test_parse_explicit_onion_prefix(self):
        from messagechain.network.submit_client import ValidatorEndpoint
        ep = ValidatorEndpoint.parse("onion:abc.onion:8443")
        self.assertTrue(ep.via_tor)
        self.assertEqual(ep.host, "abc.onion")
        self.assertEqual(ep.port, 8443)


# ───── Test 13: CLI integration --multi-submit ────────────────────────


class TestCliMultiSubmit(SubmitClientTestBase):
    def test_cli_multi_submit_against_real_validator_persists_receipts(self):
        """End-to-end: spin up three real SubmissionServers, drive the
        CLI's --multi-submit path with --endpoints, assert that receipts
        land on disk under the configured receipts dir.
        """
        # Spin up three real SubmissionServers with receipt issuers.
        servers = []
        ports = []
        for i in range(3):
            port = _find_free_port()
            kp = KeyPair.generate(
                seed=f"cli-mc-{i}".encode("ascii").ljust(32, b"\x00"),
                height=4,
            )
            issuer = ReceiptIssuer(
                self.alice.entity_id, kp,
                height_fn=lambda: self.chain.height,
            )
            srv = SubmissionServer(
                blockchain=self.chain,
                mempool=self.mempool,
                cert_path=self.cert_path,
                key_path=self.key_path,
                port=port,
                bind="127.0.0.1",
                receipt_issuer=issuer,
            )
            srv.start()
            # Wait for the socket.
            for _ in range(50):
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.1,
                    ):
                        break
                except OSError:
                    time.sleep(0.02)
            servers.append(srv)
            ports.append(port)

        try:
            # Drive the CLI command directly via cmd_send_multi.
            from messagechain.cli import cmd_send_multi_submit
            import argparse

            receipts_dir = tempfile.mkdtemp()
            try:
                # Pre-write the alice key to a temp file so the CLI
                # can read it without prompting.
                key_dir = tempfile.mkdtemp()
                key_path = os.path.join(key_dir, "key.txt")
                with open(key_path, "w", encoding="ascii") as f:
                    f.write(b"alice-submit-client".ljust(32, b"\x00").hex())
                try:
                    # Read the chain's current leaf watermark + nonce so
                    # the CLI signs with the right leaf — initialize_genesis
                    # may have consumed leaf 0 to register alice on-chain.
                    cli_nonce = self.chain.nonces.get(self.alice.entity_id, 0)
                    cli_leaf = self.chain.leaf_watermarks.get(
                        self.alice.entity_id, 0,
                    )
                    args = argparse.Namespace(
                        message="hello multi",
                        fee=_TEST_FEE,
                        endpoints=[
                            f"127.0.0.1:{ports[0]}",
                            f"127.0.0.1:{ports[1]}",
                            f"127.0.0.1:{ports[2]}",
                        ],
                        insecure=True,
                        keyfile=key_path,
                        receipts_dir=receipts_dir,
                        min_successes=1,
                        per_endpoint_timeout_s=10.0,
                        no_receipts=False,
                        nonce=cli_nonce,
                        leaf_index=cli_leaf,
                    )
                    rc = cmd_send_multi_submit(args)
                    self.assertEqual(rc, 0, msg="CLI returned non-zero")

                    # A receipt file should exist for the tx.
                    files = os.listdir(receipts_dir)
                    self.assertGreaterEqual(len(files), 1)
                    # The receipt files should round-trip via from_bytes.
                    for fname in files:
                        with open(
                            os.path.join(receipts_dir, fname), "rb"
                        ) as f:
                            blob = f.read()
                        rec = SubmissionReceipt.from_bytes(blob)
                        ok, _ = verify_receipt(rec)
                        self.assertTrue(ok)
                finally:
                    shutil.rmtree(key_dir, ignore_errors=True)
            finally:
                shutil.rmtree(receipts_dir, ignore_errors=True)
        finally:
            for s in servers:
                try:
                    s.stop()
                except Exception:
                    pass

    def test_cli_refuses_with_fewer_than_three_endpoints(self):
        from messagechain.cli import cmd_send_multi_submit
        import argparse

        receipts_dir = tempfile.mkdtemp()
        key_dir = tempfile.mkdtemp()
        key_path = os.path.join(key_dir, "key.txt")
        with open(key_path, "w", encoding="ascii") as f:
            f.write(b"alice-submit-client".ljust(32, b"\x00").hex())
        try:
            args = argparse.Namespace(
                message="hi",
                fee=_TEST_FEE,
                endpoints=["127.0.0.1:8443"],  # only 1
                insecure=True,
                keyfile=key_path,
                receipts_dir=receipts_dir,
                min_successes=1,
                per_endpoint_timeout_s=10.0,
                no_receipts=False,
            )
            rc = cmd_send_multi_submit(args)
            # Refuses to proceed with <3 endpoints.
            self.assertNotEqual(rc, 0)
        finally:
            shutil.rmtree(receipts_dir, ignore_errors=True)
            shutil.rmtree(key_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
