"""Tests for NonResponseEvidenceTx + NonResponseEvidenceProcessor.

Closes the silent-TCP-drop censorship gap:
  * Validator hangs up the TCP connection on a witnessed submission.
  * Q honest peers saw the witness gossip but never saw a SubmissionAck.
  * They sign WitnessObservations and ANY entity packages them into a
    NonResponseEvidenceTx.
  * Processor admits if Q valid sigs from distinct active-set members,
    deadline truly passed, and the chain has no record of an ack →
    slash WITNESS_NON_RESPONSE_SLASH_BPS.

Required test cases (per task brief):
  4. NonResponseEvidenceTx round-trip.
  5. NonResponseEvidence admitted with Q valid witness sigs → slash applied.
  6. NonResponseEvidence rejected with < Q witness sigs.
  7. NonResponseEvidence rejected if any witness sig is invalid or duplicate-witness.
  8. NonResponseEvidence rejected if request_hash was ack'd within deadline.
  9. Double-submit prevention: same request_hash can only slash once.
  10. Snapshot round-trip preserves processed set + ack registry.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    WITNESS_SURCHARGE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_NON_RESPONSE_SLASH_BPS,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    WitnessObservation,
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceTx,
    NonResponseEvidenceProcessor,
    verify_non_response_evidence_tx,
    sign_non_response_evidence,
    compute_non_response_slash_amount,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_request(client: Entity, target_id: bytes, nonce_seed: bytes = b"\x01") -> SubmissionRequest:
    return sign_submission_request(
        submitter=client,
        target_validator_id=target_id,
        tx_hash=_h(b"tx-payload-" + nonce_seed),
        timestamp=int(time.time()),
        client_nonce=(nonce_seed * 16)[:16],
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )


def _make_witnesses(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create((b"wn-" + tag + b"-" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


# ────────────────────────────────────────────────────────────────────
# Wire round-trips
# ────────────────────────────────────────────────────────────────────

class TestNonResponseEvidenceTxRoundtrip(unittest.TestCase):

    def test_dict_roundtrip(self):
        client = Entity.create(b"client-rd".ljust(32, b"\x00"))
        target_id = b"V" * 32
        req = _make_request(client, target_id)
        witnesses = _make_witnesses(WITNESS_QUORUM, b"rd")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in witnesses
        ]
        submitter = Entity.create(b"submitter-rd".ljust(32, b"\x00"))
        etx = sign_non_response_evidence(
            submitter=submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        round_tripped = NonResponseEvidenceTx.deserialize(etx.serialize())
        self.assertEqual(round_tripped.tx_hash, etx.tx_hash)
        self.assertEqual(round_tripped.evidence_hash, etx.evidence_hash)
        self.assertEqual(
            len(round_tripped.witness_observations), WITNESS_QUORUM,
        )

    def test_binary_roundtrip(self):
        client = Entity.create(b"client-bin".ljust(32, b"\x00"))
        target_id = b"T" * 32
        req = _make_request(client, target_id, nonce_seed=b"\x02")
        witnesses = _make_witnesses(WITNESS_QUORUM, b"bin")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=11)
            for w in witnesses
        ]
        submitter = Entity.create(b"submitter-bin".ljust(32, b"\x00"))
        etx = sign_non_response_evidence(
            submitter=submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        decoded = NonResponseEvidenceTx.from_bytes(etx.to_bytes())
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertEqual(decoded.evidence_hash, etx.evidence_hash)


# ────────────────────────────────────────────────────────────────────
# Stateless verification
# ────────────────────────────────────────────────────────────────────

class TestNonResponseEvidenceTxVerify(unittest.TestCase):

    def setUp(self):
        self.client = Entity.create(b"client-v".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"submitter-v".ljust(32, b"\x00"))
        self.target_id = b"V" * 32

    def _make_etx(self, witnesses, fee=MIN_FEE) -> NonResponseEvidenceTx:
        req = _make_request(self.client, self.target_id, nonce_seed=b"\xAA")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=20)
            for w in witnesses
        ]
        return sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=fee,
        )

    def test_verify_accepts_quorum(self):
        ws = _make_witnesses(WITNESS_QUORUM, b"vok")
        etx = self._make_etx(ws)
        ok, reason = verify_non_response_evidence_tx(
            etx,
            self.submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in ws},
            client_public_key=self.client.public_key,
        )
        self.assertTrue(ok, reason)

    def test_verify_rejects_underfee(self):
        ws = _make_witnesses(WITNESS_QUORUM, b"vfee")
        etx = self._make_etx(ws, fee=1)
        ok, reason = verify_non_response_evidence_tx(
            etx, self.submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in ws},
            client_public_key=self.client.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("fee", reason.lower())

    def test_verify_rejects_below_quorum(self):
        ws = _make_witnesses(WITNESS_QUORUM - 1, b"vq")
        etx = self._make_etx(ws)
        ok, reason = verify_non_response_evidence_tx(
            etx, self.submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in ws},
            client_public_key=self.client.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("quorum", reason.lower())

    def test_verify_rejects_duplicate_witness(self):
        """The same witness signing twice for the same request_hash
        does NOT count as two distinct attestations."""
        ws = _make_witnesses(2, b"vdup")
        # Repeat the first witness so we appear to have WITNESS_QUORUM
        # entries — but only 2 distinct entities.
        ws_dupe = [ws[0], ws[0], ws[1]]
        etx = self._make_etx(ws_dupe)
        ok, reason = verify_non_response_evidence_tx(
            etx, self.submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in ws},
            client_public_key=self.client.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("duplicate", reason.lower())

    def test_verify_rejects_invalid_witness_sig(self):
        ws = _make_witnesses(WITNESS_QUORUM, b"vinv")
        etx = self._make_etx(ws)
        # Tamper one observation's signature by substituting a different
        # signer's public key in the verify map.
        wrong_pk_map = {w.entity_id: w.public_key for w in ws}
        # Swap one witness's pubkey to an unrelated key.
        intruder = Entity.create(b"intruder".ljust(32, b"\x00"))
        wrong_pk_map[ws[0].entity_id] = intruder.public_key
        ok, reason = verify_non_response_evidence_tx(
            etx, self.submitter.public_key,
            witness_public_keys=wrong_pk_map,
            client_public_key=self.client.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("witness", reason.lower())


# ────────────────────────────────────────────────────────────────────
# Processor: state machine
# ────────────────────────────────────────────────────────────────────

class TestNonResponseEvidenceProcessor(unittest.TestCase):

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.target = Entity.create(b"validator-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"client-proc".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"submitter-proc".ljust(32, b"\x00"))
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

        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"proc")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            # Witnesses must be in the active validator set.
            self.chain.supply.staked[w.entity_id] = 100_000

    def _make_request(self, nonce_seed: bytes = b"\x01") -> SubmissionRequest:
        return _make_request(self.client, self.target.entity_id, nonce_seed)

    def _make_evidence(
        self,
        observed_height: int,
        request_seed: bytes = b"\x01",
    ) -> NonResponseEvidenceTx:
        req = self._make_request(nonce_seed=request_seed)
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height)
            for w in self.witnesses
        ]
        return sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )

    def test_admits_quorum_and_slashes(self):
        etx = self._make_evidence(observed_height=0)
        # Bring chain height past observed + deadline.
        current_height = WITNESS_RESPONSE_DEADLINE_BLOCKS + 5
        proc = NonResponseEvidenceProcessor()
        stake_before = self.chain.supply.staked[self.target.entity_id]
        result = proc.process(etx, self.chain, current_height)
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(result.offender_id, self.target.entity_id)
        self.assertEqual(
            result.slash_amount, compute_non_response_slash_amount(stake_before),
        )
        # Stake actually moved.
        self.assertEqual(
            self.chain.supply.staked[self.target.entity_id],
            stake_before - result.slash_amount,
        )
        # Marked processed.
        self.assertIn(etx.evidence_hash, proc.processed)

    def test_rejects_if_deadline_not_passed(self):
        etx = self._make_evidence(observed_height=10)
        proc = NonResponseEvidenceProcessor()
        # Current_height too low — observed=10 + deadline still in future.
        result = proc.process(
            etx, self.chain,
            current_height=10 + WITNESS_RESPONSE_DEADLINE_BLOCKS - 1,
        )
        self.assertFalse(result.slashed)
        self.assertFalse(result.accepted)
        self.assertIn("deadline", result.reason.lower())

    def test_rejects_if_acked_within_deadline(self):
        etx = self._make_evidence(observed_height=0)
        proc = NonResponseEvidenceProcessor()
        # Pre-record an ack in the chain's ack registry.  Ack arrived
        # at height 3, which is BEFORE observed (0) + deadline (8),
        # so the obligation was met → evidence rejected.
        self.chain.witness_ack_registry[etx.request.request_hash] = 3
        result = proc.process(
            etx, self.chain,
            current_height=WITNESS_RESPONSE_DEADLINE_BLOCKS + 5,
        )
        self.assertFalse(result.slashed)
        self.assertFalse(result.accepted)
        self.assertIn("ack", result.reason.lower())

    def test_double_slash_prevented(self):
        etx = self._make_evidence(observed_height=0)
        proc = NonResponseEvidenceProcessor()
        first = proc.process(
            etx, self.chain,
            current_height=WITNESS_RESPONSE_DEADLINE_BLOCKS + 5,
        )
        self.assertTrue(first.slashed)
        # Same evidence again — rejected as already-processed.
        second = proc.process(
            etx, self.chain,
            current_height=WITNESS_RESPONSE_DEADLINE_BLOCKS + 6,
        )
        self.assertFalse(second.slashed)
        self.assertFalse(second.accepted)
        self.assertIn("processed", second.reason.lower())

    def test_witness_outside_active_set_rejected(self):
        # Build an evidence whose witnesses include one entity NOT in
        # the active validator set.
        outsider = Entity.create(b"outsider".ljust(32, b"\x00"))
        outsider.keypair._next_leaf = 0
        register_entity_for_test(self.chain, outsider)
        # outsider has no stake — NOT active.

        req = self._make_request(nonce_seed=b"\x33")
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=0)
            for w in self.witnesses[:WITNESS_QUORUM - 1]
        ]
        observations.append(
            sign_witness_observation(outsider, req.request_hash, observed_height=0)
        )
        etx = sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=WITNESS_RESPONSE_DEADLINE_BLOCKS + 5,
        )
        self.assertFalse(result.accepted)
        # Active-set drops the outsider, leaving < quorum → rejected.
        self.assertTrue(
            "active" in result.reason.lower()
            or "quorum" in result.reason.lower(),
            result.reason,
        )

    def test_snapshot_roundtrip_preserves_processed(self):
        proc = NonResponseEvidenceProcessor()
        proc.processed.add(_h(b"a"))
        proc.processed.add(_h(b"b"))
        snap = proc.snapshot_dict()

        proc2 = NonResponseEvidenceProcessor()
        proc2.load_snapshot_dict(snap)
        self.assertEqual(proc.processed, proc2.processed)


class TestAckRegistry(unittest.TestCase):
    """The chain tracks request_hash → ack_height so a NonResponse
    evidence can be checked against the ack registry."""

    def test_blockchain_has_ack_registry(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        # Registry must exist as a dict on a fresh chain.
        self.assertTrue(hasattr(chain, "witness_ack_registry"))
        self.assertIsInstance(chain.witness_ack_registry, dict)


if __name__ == "__main__":
    unittest.main()
