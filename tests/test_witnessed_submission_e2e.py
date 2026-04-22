"""End-to-end witnessed-submission tests.

Cases (per task brief #11 + #12):
  11. Submission server with `X-MC-Witnessed-Submission` header
      returns `ack` blob in the JSON body.
  12. End-to-end:
        * validator that responds → no evidence;
        * validator that silently drops → witnesses observe →
          evidence assembled → slash applied.

These exercise the full HTTPS submission stack with the witnessed
submission opt-in plus the gossip / observation store / evidence
assembly path that closes the silent-TCP-drop censorship gap.
"""

import hashlib
import http.client
import json
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
    HASH_ALGO, MIN_FEE, FEE_PER_BYTE,
    WITNESS_SURCHARGE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.network.submission_receipt import ReceiptIssuer
from messagechain.network.submission_server import SubmissionServer
from messagechain.consensus.witness_submission import (
    SubmissionAck,
    SubmissionRequest,
    WitnessObservationStore,
    sign_submission_request,
    sign_witness_observation,
    verify_submission_ack,
    ACK_ADMITTED,
    ACK_REJECTED,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
    sign_non_response_evidence,
    compute_non_response_slash_amount,
)


_STATIC_FEE = DynamicFeePolicy(base_fee=100, max_fee=100)
_TEST_FEE = MIN_FEE + 40 * FEE_PER_BYTE


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _generate_self_signed_cert():
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
        raise unittest.SkipTest(
            f"openssl not available for self-signed cert: {e}"
        )
    return cert, key, tmp


def _make_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(seed=b"e2e-subtree-" + seed_tag, height=height)


# ────────────────────────────────────────────────────────────────────
# Test 11 — server returns ack on opt-in.
# ────────────────────────────────────────────────────────────────────

class TestSubmissionServerAck(unittest.TestCase):
    """Submission server with X-MC-Witnessed-Submission header
    returns an `ack` blob in the JSON body — both on success and on
    validation failure paths."""

    @classmethod
    def setUpClass(cls):
        cls.cert_path, cls.key_path, cls.cert_dir = _generate_self_signed_cert()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        self.alice = Entity.create(b"alice-ack-e2e".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=_STATIC_FEE)

        self.subtree_kp = _make_subtree_keypair(b"e2e-alice")
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.subtree_kp.public_key
        )
        self.issuer = ReceiptIssuer(
            self.alice.entity_id, self.subtree_kp,
            height_fn=lambda: self.chain.height,
        )

        self.ack_relay_calls: list[bytes] = []
        self.port = _find_free_port()
        self.server = SubmissionServer(
            blockchain=self.chain,
            mempool=self.mempool,
            cert_path=self.cert_path,
            key_path=self.key_path,
            port=self.port,
            bind="127.0.0.1",
            relay_callback=None,
            receipt_issuer=self.issuer,
            ack_relay_callback=self.ack_relay_calls.append,
        )
        self.server.start()
        # Wait for server to come up.
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

    def _post(
        self,
        body: bytes,
        witnessed_request_hash: bytes | None = None,
    ):
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port,
            context=self._tls_context(), timeout=5,
        )
        try:
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
            }
            if witnessed_request_hash is not None:
                headers["X-MC-Witnessed-Submission"] = (
                    witnessed_request_hash.hex()
                )
            conn.request("POST", "/v1/submit", body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def test_witnessed_success_returns_ack_admitted(self):
        tx = create_transaction(self.alice, "hi-ack", _TEST_FEE, nonce=0)
        # Build a SubmissionRequest just so we have a stable request_hash;
        # the server doesn't need to validate the request contents at
        # the HTTPS layer (validation lives in the gossip path).
        req = sign_submission_request(
            submitter=self.alice,
            target_validator_id=self.alice.entity_id,
            tx_hash=tx.tx_hash,
            timestamp=int(time.time()),
            client_nonce=b"\x55" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        status, body = self._post(tx.to_bytes(), req.request_hash)
        self.assertEqual(status, 200, msg=body)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertIn("ack", payload, msg=payload)
        ack = SubmissionAck.from_bytes(bytes.fromhex(payload["ack"]))
        self.assertEqual(ack.action_code, ACK_ADMITTED)
        self.assertEqual(ack.request_hash, req.request_hash)
        self.assertEqual(ack.issuer_id, self.alice.entity_id)
        ok, reason = verify_submission_ack(ack)
        self.assertTrue(ok, reason)
        # Defense in depth: ack also fanned out via gossip callback.
        self.assertEqual(len(self.ack_relay_calls), 1)

    def test_witnessed_failure_returns_ack_rejected(self):
        # Submit a malformed-fee tx (fee mutation breaks the sig).
        tx = create_transaction(self.alice, "hi-rej", _TEST_FEE, nonce=0)
        from messagechain.core.transaction import MessageTransaction
        bad = MessageTransaction(
            entity_id=tx.entity_id,
            message=tx.message,
            timestamp=tx.timestamp,
            nonce=tx.nonce,
            fee=tx.fee + 1,
            signature=tx.signature,
            compression_flag=tx.compression_flag,
        )
        req = sign_submission_request(
            submitter=self.alice,
            target_validator_id=self.alice.entity_id,
            tx_hash=bad.tx_hash,
            timestamp=int(time.time()),
            client_nonce=b"\x77" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        status, body = self._post(bad.to_bytes(), req.request_hash)
        self.assertEqual(status, 400, msg=body)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertIn("ack", payload)
        ack = SubmissionAck.from_bytes(bytes.fromhex(payload["ack"]))
        self.assertEqual(ack.action_code, ACK_REJECTED)
        self.assertEqual(ack.request_hash, req.request_hash)

    def test_no_header_no_ack(self):
        """Default submission path is unchanged — no ack issued without
        the opt-in header.  Default leaf-budget posture preserved."""
        tx = create_transaction(self.alice, "hi-default", _TEST_FEE, nonce=0)
        status, body = self._post(tx.to_bytes())
        self.assertEqual(status, 200, msg=body)
        payload = json.loads(body.decode("utf-8"))
        self.assertNotIn("ack", payload)
        # Receipt is still issued (default opt-in via configured issuer
        # — that path is independent of witnessed submission).
        self.assertIn("receipt", payload)

    def test_malformed_header_silently_ignored(self):
        """Garbage in the X-MC-Witnessed-Submission header doesn't
        break the submission; client just gets no ack."""
        tx = create_transaction(self.alice, "hi-bad-hdr", _TEST_FEE, nonce=0)
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self._tls_context(), timeout=5,
        )
        try:
            blob = tx.to_bytes()
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(blob)),
                "X-MC-Witnessed-Submission": "not-hex-at-all",
            }
            conn.request("POST", "/v1/submit", body=blob, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
        finally:
            conn.close()
        self.assertEqual(status, 200, msg=body)
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertNotIn("ack", payload)


# ────────────────────────────────────────────────────────────────────
# Test 12 — full silent-drop scenario.
# ────────────────────────────────────────────────────────────────────

class TestEndToEndSilentDrop(unittest.TestCase):
    """End-to-end: a client gossips a witnessed submission; the
    target validator silently drops the request (never issues an
    ack); honest peers observe via the witness gossip topic and
    assemble a NonResponseEvidenceTx; the chain admits + slashes."""

    def setUp(self):
        self.target = Entity.create(b"validator-silent".ljust(32, b"\x00"))
        self.client = Entity.create(b"client-silent".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"submitter-silent".ljust(32, b"\x00"))
        self.target.keypair._next_leaf = 0
        self.client.keypair._next_leaf = 0
        self.submitter.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        self.chain.supply.balances[self.target.entity_id] = 1_000_000
        self.chain.supply.balances[self.client.entity_id] = 1_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 1_000_000
        self.chain.supply.staked[self.target.entity_id] = 100_000

        # Build a quorum of witnesses, all in the active validator set.
        self.witnesses = [
            Entity.create(
                (b"wn-silent-" + str(i).encode()).ljust(32, b"\x00")
            )
            for i in range(WITNESS_QUORUM)
        ]
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 100_000

    def _signed_request(self, nonce_seed: bytes = b"\x01") -> SubmissionRequest:
        return sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"silent-payload-" + nonce_seed),
            timestamp=int(time.time()),
            client_nonce=(nonce_seed * 16)[:16],
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )

    def test_responsive_validator_no_evidence_assembled(self):
        """If the validator publishes an ack, the WitnessObservationStore
        marks the obligation discharged and no evidence is signed."""
        req = self._signed_request(nonce_seed=b"\x10")
        store = WitnessObservationStore()
        observed_height = 0
        store.record_request(req.request_hash, observed_height)
        # Validator publishes an ack at height 3 — within deadline.
        store.record_ack(req.request_hash, 3)

        current_height = WITNESS_RESPONSE_DEADLINE_BLOCKS + 5
        overdue = store.is_overdue(
            req.request_hash, current_height,
            WITNESS_RESPONSE_DEADLINE_BLOCKS,
        )
        self.assertFalse(overdue, "ack should discharge the obligation")

    def test_silent_drop_witnesses_assemble_evidence_and_slash_applies(self):
        """The full pipeline:
          * client signs and gossips a SubmissionRequest;
          * target validator silently drops (never issues an ack);
          * honest witnesses see the gossip via WitnessObservationStore;
          * after the deadline, witnesses are 'overdue' and sign
            WitnessObservations;
          * an entity packages them into a NonResponseEvidenceTx;
          * NonResponseEvidenceProcessor admits + slashes the target.
        """
        req = self._signed_request(nonce_seed=b"\x20")

        # All witnesses see the gossip at observed_height = 0.
        observed_height = 0
        stores = [WitnessObservationStore() for _ in self.witnesses]
        for s in stores:
            s.record_request(req.request_hash, observed_height)

        # Target validator silently drops — NO record_ack call.
        # Time passes; current_height crosses the deadline.
        current_height = WITNESS_RESPONSE_DEADLINE_BLOCKS + 5

        # Each witness checks is_overdue → True → signs an observation.
        observations = []
        for w, s in zip(self.witnesses, stores):
            self.assertTrue(s.is_overdue(
                req.request_hash, current_height,
                WITNESS_RESPONSE_DEADLINE_BLOCKS,
            ))
            observations.append(
                sign_witness_observation(
                    w, req.request_hash, observed_height,
                )
            )

        # Submitter packages the evidence.
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )

        # Processor admits and slashes.
        proc = NonResponseEvidenceProcessor()
        stake_before = self.chain.supply.staked[self.target.entity_id]
        burned_before = self.chain.supply.total_burned
        result = proc.process(etx, self.chain, current_height)
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(result.offender_id, self.target.entity_id)
        expected_slash = compute_non_response_slash_amount(stake_before)
        self.assertEqual(result.slash_amount, expected_slash)
        self.assertEqual(
            self.chain.supply.staked[self.target.entity_id],
            stake_before - expected_slash,
        )
        self.assertEqual(
            self.chain.supply.total_burned, burned_before + expected_slash,
        )

    def test_responsive_validator_evidence_rejected(self):
        """If the chain's witness_ack_registry shows an ack within the
        deadline, evidence built from the same request_hash is
        rejected (no slash, no admission)."""
        req = self._signed_request(nonce_seed=b"\x30")
        # Pre-record an in-deadline ack on the chain.
        self.chain.witness_ack_registry[req.request_hash] = 2

        observed_height = 0
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in self.witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        proc = NonResponseEvidenceProcessor()
        stake_before = self.chain.supply.staked[self.target.entity_id]
        result = proc.process(
            etx, self.chain,
            current_height=WITNESS_RESPONSE_DEADLINE_BLOCKS + 5,
        )
        self.assertFalse(result.slashed)
        self.assertFalse(result.accepted)
        self.assertEqual(
            self.chain.supply.staked[self.target.entity_id], stake_before,
        )


if __name__ == "__main__":
    unittest.main()
