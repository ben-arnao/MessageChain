"""Audit r47 #3 -- when the submission server's relay_callback raises,
the SubmissionReceipt MUST NOT be returned to the submitter.

A SubmissionReceipt is the validator's signed on-chain commitment that
the tx will be widely seen and included.  If the validator's outbound
relay path silently breaks (misconfigured firewall, transient
partition, peers churning), the tx ages out of the validator's
mempool TTL having never reached another node -- no peer has it,
so no proposer ever includes it.  ``EVIDENCE_INCLUSION_WINDOW``
elapses; the submitter files a ``CensorshipEvidenceTx`` against the
validator who issued the receipt; the validator loses
``CENSORSHIP_SLASH_BPS`` (10%) of stake per matured slash.

CLAUDE.md anchors at risk:

  * Honest-operator insurance: "honest, well-configured nodes should
    rarely if ever be slashed under normal operation."  A single
    transient outbound-relay failure on an otherwise-honest validator
    is exactly the false-positive the anchor forbids.

  * Validator collusion defense (primary adversary): a coordinated
    attacker can target small/honest validators with broken relay
    paths and drain their stake one 10%-slice at a time for the cost
    of a tx submission per filing.

Pre-fix the HTTPS submit handler caught the relay exception, logged
it, and proceeded to write the JSON response including
``receipt_hex``.  The receipt was made public; the validator was
committed to a promise they could not honor.

Fix: on relay failure, suppress ``receipt_hex`` from the response.
The tx is still admitted (200 OK with ``tx_hash``), but no
SubmissionReceipt bytes leave the validator.  Without those bytes,
the submitter cannot weaponize this validator's signature into a
CensorshipEvidenceTx -- the slashing-magnet is closed.  The
receipt-subtree leaf is privately burnt (the WOTS+ key was used
internally), but the signed receipt was never published so no
public commitment was made.

The fix preserves the existing fail-open semantics from the receipt-
budget gate (audit 2026-04-28): a response with ``ok=true`` and no
receipt field is already a documented success shape, so honest
clients (including ``send-multi``) handle it correctly.  Senders who
want a receipt can fan out via ``send-multi`` to peer validators
whose relay surface works.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import ReceiptIssuer
from messagechain.network.submission_server import SubmissionServer
from messagechain.config import MIN_FEE


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _generate_self_signed_cert():
    tmp = tempfile.mkdtemp(prefix="mc-r47-relay-")
    cert = os.path.join(tmp, "cert.pem")
    key = os.path.join(tmp, "key.pem")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key, "-out", cert,
                "-days", "1", "-nodes",
                "-subj", "/CN=127.0.0.1",
            ],
            check=True, capture_output=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as e:
        raise unittest.SkipTest(
            f"openssl not available for self-signed cert: {e}"
        )
    return cert, key, tmp


class _BrokenRelayTestBase(unittest.TestCase):
    """Stand up a real SubmissionServer with a relay_callback that
    deterministically raises, plus a receipt_issuer so receipts would
    normally be returned."""

    @classmethod
    def setUpClass(cls):
        cls.cert_path, cls.key_path, cls.cert_dir = _generate_self_signed_cert()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        self.alice = Entity.create(b"alice-r47-relay".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool()

        # Real receipt issuer so a successful path would normally
        # populate result.receipt_hex.
        self.receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-r47-relay", height=4,
        )
        self.issuer = ReceiptIssuer(self.alice.entity_id, self.receipt_kp)

        # Track whether the relay was attempted (it should be, even
        # when it raises) so we can pin "relay was called" separately
        # from "receipt suppressed".
        self.relay_attempts: list = []

        def broken_relay(tx):
            self.relay_attempts.append(tx)
            raise RuntimeError(
                "simulated outbound-relay failure (test) -- "
                "no peers reachable, packet loss, firewall, etc."
            )

        self.port = _find_free_port()
        self.server = SubmissionServer(
            blockchain=self.chain,
            mempool=self.mempool,
            cert_path=self.cert_path,
            key_path=self.key_path,
            port=self.port,
            bind="127.0.0.1",
            relay_callback=broken_relay,
            receipt_issuer=self.issuer,
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.1,
                ):
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

    def _post(self, body: bytes):
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self._tls_context(), timeout=5,
        )
        try:
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
            }
            conn.request("POST", "/v1/submit", body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


class TestRelayFailureSuppressesReceipt(_BrokenRelayTestBase):

    def test_relay_was_attempted(self):
        """Sanity baseline: the broken relay was actually called.  If
        this fails the rest of the test class proves nothing."""
        tx = create_transaction(
            self.alice, "r47 relay sanity", fee=MIN_FEE + 200, nonce=0,
        )
        status, _ = self._post(tx.to_bytes())
        self.assertEqual(status, 200)
        self.assertEqual(
            len(self.relay_attempts), 1,
            "Broken relay_callback must have been invoked exactly "
            "once on a fresh admission.",
        )

    def test_admission_still_succeeds_with_200(self):
        """Suppressing the receipt must NOT regress the admission
        status: the tx is in the mempool, the submitter gets 200 OK,
        only the public commitment (receipt_hex) is withheld."""
        tx = create_transaction(
            self.alice, "r47 admission survives", fee=MIN_FEE + 200,
            nonce=0,
        )
        status, body = self._post(tx.to_bytes())
        self.assertEqual(status, 200, msg=body)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        self.assertEqual(
            payload.get("tx_hash"), tx.tx_hash.hex(),
            "tx_hash must still be returned -- submitter needs it "
            "regardless of receipt status",
        )
        # And the tx really is in the mempool.
        self.assertIn(tx.tx_hash, self.mempool.pending)

    def test_receipt_field_is_absent_or_empty(self):
        """The critical security property: the JSON response must not
        contain a non-empty ``receipt`` field when relay failed.
        Without this, an honest validator with a broken outbound relay
        becomes a CensorshipEvidenceTx slashing magnet."""
        tx = create_transaction(
            self.alice, "r47 receipt suppressed", fee=MIN_FEE + 200,
            nonce=0,
        )
        status, body = self._post(tx.to_bytes())
        self.assertEqual(status, 200, msg=body)
        payload = json.loads(body.decode("utf-8"))
        receipt = payload.get("receipt", "")
        self.assertEqual(
            receipt, "",
            f"Response JSON must NOT include a SubmissionReceipt when "
            f"relay_callback raised -- the validator cannot honestly "
            f"commit to propagation when their outbound relay failed.  "
            f"Got receipt={receipt!r}.",
        )


class TestRelaySuccessStillIssuesReceipt(unittest.TestCase):
    """Regression: when the relay_callback succeeds, the receipt MUST
    still be returned.  The suppression behavior in audit r47 #3 must
    only fire on relay FAILURE, not on every submission."""

    @classmethod
    def setUpClass(cls):
        cls.cert_path, cls.key_path, cls.cert_dir = _generate_self_signed_cert()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        self.alice = Entity.create(
            b"alice-r47-relay-ok".ljust(32, b"\x00"),
        )
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool()

        receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-r47-ok", height=4,
        )
        self.issuer = ReceiptIssuer(self.alice.entity_id, receipt_kp)

        self.relay_calls = 0

        def working_relay(tx):
            self.relay_calls += 1

        self.port = _find_free_port()
        self.server = SubmissionServer(
            blockchain=self.chain,
            mempool=self.mempool,
            cert_path=self.cert_path,
            key_path=self.key_path,
            port=self.port,
            bind="127.0.0.1",
            relay_callback=working_relay,
            receipt_issuer=self.issuer,
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.port), timeout=0.1,
                ):
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

    def test_working_relay_gets_a_receipt(self):
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self._tls_context(), timeout=5,
        )
        try:
            tx = create_transaction(
                self.alice, "r47 relay ok", fee=MIN_FEE + 200, nonce=0,
            )
            body = tx.to_bytes()
            conn.request(
                "POST", "/v1/submit", body=body,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(body)),
                },
            )
            resp = conn.getresponse()
            status = resp.status
            payload_bytes = resp.read()
        finally:
            conn.close()
        self.assertEqual(status, 200, msg=payload_bytes)
        payload = json.loads(payload_bytes.decode("utf-8"))
        self.assertTrue(payload.get("ok"))
        self.assertEqual(self.relay_calls, 1)
        receipt = payload.get("receipt", "")
        self.assertNotEqual(
            receipt, "",
            "Working relay path must still return the SubmissionReceipt "
            "-- the audit r47 #3 suppression must fire only on relay "
            "FAILURE, not on every submission.",
        )


if __name__ == "__main__":
    unittest.main()
