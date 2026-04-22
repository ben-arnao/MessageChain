"""Tests for the witness-submission wire types.

Closes the silent-TCP-drop censorship gap: a coerced validator that
hangs up the TCP connection without answering becomes slashable when
the client opted in via witnessed submission and Q honest peers saw
the gossip but never saw an ack.

Wire types under test:
  * SubmissionRequest — client-signed: "I am submitting tx_hash to
    target_validator at time T, paying WITNESS_SURCHARGE on top of fee".
    Gossiped to the witness topic AND POSTed to /v1/submit with header
    X-MC-Witnessed-Submission: <hex(request_hash)>.
  * SubmissionAck — validator-signed: "I received and processed
    request_hash at height H".  Issued from the same WOTS+ subtree as
    SubmissionReceipt (one extra leaf per ack).
  * WitnessObservation — witness-signed attestation that they saw the
    gossip but not an ack within the deadline.  The on-chain
    NonResponseEvidenceTx aggregates Q of these.
"""

import hashlib
import time
import unittest

from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    WITNESS_SURCHARGE,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.network.submission_receipt import ReceiptIssuer
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    SubmissionAck,
    WitnessObservation,
    ACK_ADMITTED,
    ACK_REJECTED,
    _VALID_ACK_CODES,
    sign_submission_request,
    sign_witness_observation,
    verify_submission_request,
    verify_submission_ack,
    verify_witness_observation,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(seed=b"witness-sub-" + seed_tag, height=height)


def _make_request(
    submitter: Entity,
    target_id: bytes,
    tx_hash: bytes | None = None,
    fee: int = MIN_FEE + WITNESS_SURCHARGE,
    timestamp: int | None = None,
    nonce: bytes | None = None,
) -> SubmissionRequest:
    return sign_submission_request(
        submitter=submitter,
        target_validator_id=target_id,
        tx_hash=tx_hash if tx_hash is not None else _h(b"tx-payload"),
        timestamp=int(time.time()) if timestamp is None else int(timestamp),
        client_nonce=nonce if nonce is not None else b"\x11" * 16,
        fee=fee,
    )


# ────────────────────────────────────────────────────────────────────
# SubmissionRequest
# ────────────────────────────────────────────────────────────────────

class TestSubmissionRequest(unittest.TestCase):

    def test_dict_roundtrip(self):
        alice = Entity.create(b"alice-srdr".ljust(32, b"\x00"))
        target = b"V" * 32
        req = _make_request(alice, target)
        round_tripped = SubmissionRequest.deserialize(req.serialize())
        self.assertEqual(round_tripped.request_hash, req.request_hash)
        self.assertEqual(round_tripped.tx_hash, req.tx_hash)
        self.assertEqual(round_tripped.target_validator_id, target)
        self.assertEqual(round_tripped.fee, req.fee)
        self.assertEqual(round_tripped.client_nonce, req.client_nonce)

    def test_binary_roundtrip(self):
        alice = Entity.create(b"alice-srbin".ljust(32, b"\x00"))
        target = b"T" * 32
        req = _make_request(alice, target)
        blob = req.to_bytes()
        decoded = SubmissionRequest.from_bytes(blob)
        self.assertEqual(decoded.request_hash, req.request_hash)
        self.assertEqual(decoded.timestamp, req.timestamp)
        self.assertEqual(decoded.target_validator_id, target)

    def test_signature_verifies_under_submitter_pk(self):
        alice = Entity.create(b"alice-srvk".ljust(32, b"\x00"))
        req = _make_request(alice, b"X" * 32)
        ok, reason = verify_submission_request(req, alice.public_key)
        self.assertTrue(ok, reason)

    def test_signature_rejects_wrong_pk(self):
        alice = Entity.create(b"alice-srbad".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-srbad".ljust(32, b"\x00"))
        req = _make_request(alice, b"Y" * 32)
        ok, reason = verify_submission_request(req, bob.public_key)
        self.assertFalse(ok)

    def test_underfee_rejected(self):
        alice = Entity.create(b"alice-srfee".ljust(32, b"\x00"))
        # Witness surcharge required on top of MIN_FEE.  We construct
        # an under-fee request directly (bypassing sign_submission_request's
        # fee guard) to prove verify_submission_request rejects it.
        placeholder = Signature([], 0, [], b"", b"")
        # Build a request with the correct sig over the under-fee body.
        underfee = MIN_FEE  # missing the surcharge
        from messagechain.consensus.witness_submission import (
            SubmissionRequest as _SR,
        )
        req = _SR(
            tx_hash=_h(b"tx-payload"),
            target_validator_id=b"Z" * 32,
            timestamp=int(time.time()),
            client_nonce=b"\x11" * 16,
            submitter_id=alice.entity_id,
            fee=underfee,
            signature=placeholder,
        )
        msg_hash = _h(req._signable_data())
        sig = alice.keypair.sign(msg_hash)
        req = _SR(
            tx_hash=req.tx_hash,
            target_validator_id=req.target_validator_id,
            timestamp=req.timestamp,
            client_nonce=req.client_nonce,
            submitter_id=req.submitter_id,
            fee=underfee,
            signature=sig,
        )
        ok, reason = verify_submission_request(req, alice.public_key)
        self.assertFalse(ok)
        self.assertIn("surcharge", reason.lower())

    def test_target_validator_id_bound_into_signature(self):
        """Tampering with target_validator_id must invalidate the sig."""
        alice = Entity.create(b"alice-srt".ljust(32, b"\x00"))
        req = _make_request(alice, b"A" * 32)
        # Mutate target — recompute hash but keep old signature.
        req.target_validator_id = b"B" * 32
        req.request_hash = req._compute_hash()
        ok, _ = verify_submission_request(req, alice.public_key)
        self.assertFalse(ok)


# ────────────────────────────────────────────────────────────────────
# SubmissionAck
# ────────────────────────────────────────────────────────────────────

class TestSubmissionAck(unittest.TestCase):

    def test_issuer_emits_verifiable_ack(self):
        validator = Entity.create(b"val-ack".ljust(32, b"\x00"))
        kp = _make_subtree_keypair(b"ack-val")
        issuer = ReceiptIssuer(validator.entity_id, kp, height_fn=lambda: 7)

        request_hash = _h(b"req-blob")
        ack = issuer.issue_ack(request_hash, ACK_ADMITTED)
        self.assertEqual(ack.request_hash, request_hash)
        self.assertEqual(ack.action_code, ACK_ADMITTED)
        self.assertEqual(ack.commit_height, 7)
        self.assertEqual(ack.issuer_id, validator.entity_id)
        self.assertEqual(ack.issuer_root_public_key, kp.public_key)
        ok, reason = verify_submission_ack(ack)
        self.assertTrue(ok, reason)

    def test_dict_roundtrip(self):
        validator = Entity.create(b"val-ackdr".ljust(32, b"\x00"))
        kp = _make_subtree_keypair(b"ackdr")
        issuer = ReceiptIssuer(validator.entity_id, kp, height_fn=lambda: 1)
        ack = issuer.issue_ack(_h(b"r1"), ACK_REJECTED)
        round_tripped = SubmissionAck.deserialize(ack.serialize())
        self.assertEqual(round_tripped.ack_hash, ack.ack_hash)
        self.assertEqual(round_tripped.action_code, ACK_REJECTED)

    def test_binary_roundtrip(self):
        validator = Entity.create(b"val-ackbin".ljust(32, b"\x00"))
        kp = _make_subtree_keypair(b"ackbin")
        issuer = ReceiptIssuer(validator.entity_id, kp, height_fn=lambda: 99)
        ack = issuer.issue_ack(_h(b"r2"), ACK_ADMITTED)
        decoded = SubmissionAck.from_bytes(ack.to_bytes())
        self.assertEqual(decoded.ack_hash, ack.ack_hash)
        self.assertEqual(decoded.commit_height, 99)

    def test_invalid_action_code_rejected(self):
        validator = Entity.create(b"val-bad".ljust(32, b"\x00"))
        kp = _make_subtree_keypair(b"bad")
        issuer = ReceiptIssuer(validator.entity_id, kp)
        with self.assertRaises(ValueError):
            issuer.issue_ack(_h(b"x"), 99)

    def test_action_codes_are_distinct(self):
        self.assertIn(ACK_ADMITTED, _VALID_ACK_CODES)
        self.assertIn(ACK_REJECTED, _VALID_ACK_CODES)
        self.assertNotEqual(ACK_ADMITTED, ACK_REJECTED)

    def test_tampered_ack_fails_verify(self):
        validator = Entity.create(b"val-tamper".ljust(32, b"\x00"))
        kp = _make_subtree_keypair(b"tamper")
        issuer = ReceiptIssuer(validator.entity_id, kp, height_fn=lambda: 5)
        ack = issuer.issue_ack(_h(b"req"), ACK_ADMITTED)
        # Mutate the action code without re-signing.
        ack.action_code = ACK_REJECTED
        ack.ack_hash = ack._compute_hash()
        ok, _ = verify_submission_ack(ack)
        self.assertFalse(ok)


# ────────────────────────────────────────────────────────────────────
# WitnessObservation
# ────────────────────────────────────────────────────────────────────

class TestWitnessObservation(unittest.TestCase):

    def test_signed_observation_verifies(self):
        witness = Entity.create(b"witness-1".ljust(32, b"\x00"))
        request_hash = _h(b"req-being-watched")
        obs = sign_witness_observation(
            witness=witness,
            request_hash=request_hash,
            observed_height=42,
        )
        self.assertEqual(obs.witness_id, witness.entity_id)
        self.assertEqual(obs.request_hash, request_hash)
        self.assertEqual(obs.observed_height, 42)
        ok, reason = verify_witness_observation(obs, witness.public_key)
        self.assertTrue(ok, reason)

    def test_dict_roundtrip(self):
        witness = Entity.create(b"witness-dr".ljust(32, b"\x00"))
        obs = sign_witness_observation(
            witness=witness,
            request_hash=_h(b"r"),
            observed_height=10,
        )
        round_tripped = WitnessObservation.deserialize(obs.serialize())
        self.assertEqual(round_tripped.observation_hash, obs.observation_hash)

    def test_binary_roundtrip(self):
        witness = Entity.create(b"witness-bin".ljust(32, b"\x00"))
        obs = sign_witness_observation(
            witness=witness,
            request_hash=_h(b"q"),
            observed_height=21,
        )
        decoded = WitnessObservation.from_bytes(obs.to_bytes())
        self.assertEqual(decoded.observation_hash, obs.observation_hash)

    def test_wrong_pk_fails(self):
        w1 = Entity.create(b"w1-bad".ljust(32, b"\x00"))
        w2 = Entity.create(b"w2-bad".ljust(32, b"\x00"))
        obs = sign_witness_observation(
            witness=w1,
            request_hash=_h(b"r"),
            observed_height=1,
        )
        ok, _ = verify_witness_observation(obs, w2.public_key)
        self.assertFalse(ok)


class TestDomainTagsAreDistinct(unittest.TestCase):
    """Belt-and-braces: every domain tag must be unique to prevent
    cross-replay between request, ack, observation, and evidence."""

    def test_tags_distinct(self):
        from messagechain.consensus.witness_submission import (
            _REQUEST_DOMAIN_TAG,
            _ACK_DOMAIN_TAG,
            _OBSERVATION_DOMAIN_TAG,
        )
        from messagechain.consensus.non_response_evidence import (
            _DOMAIN_TAG as _EVIDENCE_DOMAIN_TAG,
        )
        tags = {
            _REQUEST_DOMAIN_TAG,
            _ACK_DOMAIN_TAG,
            _OBSERVATION_DOMAIN_TAG,
            _EVIDENCE_DOMAIN_TAG,
        }
        self.assertEqual(len(tags), 4, f"Domain tags collide: {tags}")


if __name__ == "__main__":
    unittest.main()
