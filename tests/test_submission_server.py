"""
Tests for the public HTTPS submission endpoint.

The submission server is a censorship-resistance ingress: any client on
the internet can POST a signed MessageTransaction (binary-serialized)
to any validator's public HTTPS endpoint, bypassing local mempool
dependence.  TLS is mandatory; rate limiting + body-size caps defend
against DoS.

These tests exercise the full HTTP stack — real sockets, real TLS — to
catch any framing / header / status-code regression.  A self-signed
cert is generated on the fly per test; no fixtures checked in.
"""

import http.client
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock

from tests import register_entity_for_test
from messagechain.config import (
    MAX_SUBMISSION_BODY_BYTES,
    SUBMISSION_BURST,
    MIN_FEE, FEE_PER_BYTE,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.network.submission_server import (
    SubmissionServer,
    submit_transaction_to_mempool,
)


_STATIC_FEE = DynamicFeePolicy(base_fee=100, max_fee=100)
# Slightly generous fee to pass dynamic-fee + per-byte cost.
_TEST_FEE = MIN_FEE + 40 * FEE_PER_BYTE


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _generate_self_signed_cert() -> tuple[str, str, str]:
    """Generate a temporary self-signed cert + key with stdlib only.

    Uses `openssl` via subprocess because Python stdlib lacks a cert
    generator.  Every Linux / macOS / Windows dev machine with Python
    is expected to have openssl; skip the test if it's not present.
    Returns (cert_path, key_path, tempdir) — caller must clean up
    tempdir when done.
    """
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
        raise unittest.SkipTest(f"openssl not available for self-signed cert: {e}")
    return cert, key, tmp


class SubmissionServerTestBase(unittest.TestCase):
    """Spin up a real SubmissionServer with a self-signed cert and fresh chain."""

    @classmethod
    def setUpClass(cls):
        cls.cert_path, cls.key_path, cls.cert_dir = _generate_self_signed_cert()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        # Build a minimal chain with Alice as genesis so she can sign txs.
        self.alice = Entity.create(b"alice-submission-key".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=_STATIC_FEE)

        # Spin up a real HTTPS server on a free port.
        self.port = _find_free_port()
        self.server = SubmissionServer(
            blockchain=self.chain,
            mempool=self.mempool,
            cert_path=self.cert_path,
            key_path=self.key_path,
            port=self.port,
            bind="127.0.0.1",
            relay_callback=None,
        )
        self.server.start()
        # Give the socket a moment to come up (stdlib ThreadingHTTPServer is
        # usually ready immediately after serve_forever in thread).
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("SubmissionServer never came up")

    def tearDown(self):
        self.server.stop()

    def _tls_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _make_tx(self, nonce: int = 0, fee: int = _TEST_FEE) -> MessageTransaction:
        return create_transaction(self.alice, f"hello {nonce}", fee=fee, nonce=nonce)

    def _post(
        self,
        path: str,
        body: bytes,
        content_type: str = "application/octet-stream",
        method: str = "POST",
    ):
        """POST to the submission server.  Returns (status, body_bytes)."""
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self._tls_context(), timeout=5,
        )
        try:
            headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


class TestValidSubmission(SubmissionServerTestBase):
    def test_valid_tx_accepted_200(self):
        tx = self._make_tx()
        status, body = self._post("/v1/submit", tx.to_bytes())
        self.assertEqual(status, 200, msg=body)
        # Response body should contain the tx hash (hex)
        self.assertIn(tx.tx_hash.hex().encode(), body)

    def test_valid_tx_lands_in_mempool(self):
        tx = self._make_tx()
        self._post("/v1/submit", tx.to_bytes())
        self.assertIn(tx.tx_hash, self.mempool.pending)

    def test_arrival_height_recorded(self):
        """Forced-inclusion semantics require arrival_block_height tracking."""
        tx = self._make_tx()
        self._post("/v1/submit", tx.to_bytes())
        self.assertEqual(
            self.mempool.arrival_heights.get(tx.tx_hash),
            self.chain.height,
        )


class TestRejection(SubmissionServerTestBase):
    def test_invalid_signature_rejected_400(self):
        tx = self._make_tx()
        blob = bytearray(tx.to_bytes())
        # Corrupt a signature byte — flip something deep in the sig blob.
        # Layout ends with 32-byte tx_hash; signature blob is earlier.
        # Flip a byte 200 in from the end (well inside the sig).
        if len(blob) > 250:
            blob[-200] ^= 0xFF
        status, body = self._post("/v1/submit", bytes(blob))
        self.assertIn(status, (400,), msg=f"expected 400 got {status}: {body}")

    def test_oversized_body_rejected_413(self):
        """Bodies larger than MAX_SUBMISSION_BODY_BYTES are rejected."""
        oversized = b"\x00" * (MAX_SUBMISSION_BODY_BYTES + 1)
        status, _ = self._post("/v1/submit", oversized)
        self.assertEqual(status, 413)

    def test_wrong_content_type_rejected_415(self):
        tx = self._make_tx()
        status, _ = self._post(
            "/v1/submit", tx.to_bytes(), content_type="application/json",
        )
        self.assertEqual(status, 415)

    def test_wrong_method_rejected_405(self):
        status, _ = self._post("/v1/submit", b"", method="GET")
        self.assertEqual(status, 405)

    def test_wrong_path_rejected_404(self):
        status, _ = self._post("/v1/nope", b"")
        self.assertEqual(status, 404)

    def test_malformed_body_rejected_400(self):
        """Random garbage that isn't a transaction at all returns 400."""
        status, _ = self._post("/v1/submit", b"this is not a transaction")
        self.assertEqual(status, 400)


class TestIdempotent(SubmissionServerTestBase):
    def test_duplicate_submission_is_idempotent(self):
        """Re-POSTing the same tx returns success, mempool size unchanged."""
        tx = self._make_tx()
        status1, _ = self._post("/v1/submit", tx.to_bytes())
        self.assertEqual(status1, 200)
        size_after_first = len(self.mempool.pending)
        status2, _ = self._post("/v1/submit", tx.to_bytes())
        # Idempotent: not an error, still 200
        self.assertEqual(status2, 200)
        self.assertEqual(len(self.mempool.pending), size_after_first)


class TestRateLimit(SubmissionServerTestBase):
    def test_burst_exhausted_returns_429(self):
        """After the burst is drained, subsequent requests should 429.

        The token bucket refills at SUBMISSION_RATE_LIMIT_PER_SEC (2/sec),
        so a few TLS handshakes of elapsed time during the test will
        add fractional tokens back.  To prove rate limiting is working,
        we fire far more than the burst cap quickly and assert at least
        one 429 appeared — that's unambiguous evidence of throttling.
        """
        statuses = []
        # Fire 2x the burst; the small tokens refilled during the
        # test can't exceed burst, so at least some must 429.
        # Use small, cheaply-rejectable bodies to avoid racing the
        # refill clock.
        for i in range(SUBMISSION_BURST * 2 + 5):
            # Empty body → 400 on content-type, but rate limit fires first.
            # Use wrong content type to skip decode work.
            status, _ = self._post(
                "/v1/submit", b"", content_type="text/plain",
            )
            statuses.append(status)
        self.assertIn(
            429, statuses,
            msg=f"expected at least one 429 across {len(statuses)} rapid "
                f"requests; saw statuses: {statuses}",
        )


class TestMempoolInjectionUnit(unittest.TestCase):
    """Unit-level tests of the submit_transaction_to_mempool helper.

    These don't need a running HTTPS server and exercise every branch
    of the admission logic cheaply.
    """

    def setUp(self):
        self.alice = Entity.create(b"alice-helper".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=_STATIC_FEE)

    def test_helper_accepts_valid_tx(self):
        tx = create_transaction(self.alice, "hi", fee=_TEST_FEE, nonce=0)
        result = submit_transaction_to_mempool(tx, self.chain, self.mempool)
        self.assertTrue(result.ok)
        self.assertEqual(result.tx_hash, tx.tx_hash)
        self.assertIn(tx.tx_hash, self.mempool.pending)
        self.assertEqual(
            self.mempool.arrival_heights[tx.tx_hash], self.chain.height
        )

    def test_helper_duplicate_is_idempotent(self):
        tx = create_transaction(self.alice, "hi", fee=_TEST_FEE, nonce=0)
        r1 = submit_transaction_to_mempool(tx, self.chain, self.mempool)
        r2 = submit_transaction_to_mempool(tx, self.chain, self.mempool)
        self.assertTrue(r1.ok)
        self.assertTrue(r2.ok)
        self.assertTrue(r2.duplicate)

    def test_helper_rejects_invalid_signature(self):
        tx = create_transaction(self.alice, "hi", fee=_TEST_FEE, nonce=0)
        # Build a new MessageTransaction with the same signed signature but
        # a mutated fee — signature won't cover the new fee, so
        # verify_transaction fails.
        bad_tx = MessageTransaction(
            entity_id=tx.entity_id,
            message=tx.message,
            timestamp=tx.timestamp,
            nonce=tx.nonce,
            fee=tx.fee + 1,
            signature=tx.signature,
            compression_flag=tx.compression_flag,
        )
        result = submit_transaction_to_mempool(bad_tx, self.chain, self.mempool)
        self.assertFalse(result.ok)


class TestTLSRequired(SubmissionServerTestBase):
    def test_plaintext_http_fails(self):
        """Plaintext HTTP to a TLS-only endpoint must fail to establish."""
        # Open a raw socket and send a plaintext HTTP request; server
        # should drop or error — never serve a 200.
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect(("127.0.0.1", self.port))
            s.send(b"POST /v1/submit HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                data = s.recv(4096)
            except (ConnectionResetError, TimeoutError, OSError):
                data = b""
            # Either no response or a non-200 error response — but never
            # a real success.
            self.assertNotIn(b"200 OK", data)
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
