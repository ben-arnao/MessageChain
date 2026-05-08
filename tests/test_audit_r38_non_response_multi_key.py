"""Audit r38 #1 -- NonResponseEvidenceTx multi-key candidate set.

Closes the rotation-evasion silent-drop gap on the witnessed-submission
pipeline.  Pre-fix `Blockchain.validate_non_response_evidence_tx`
resolved the CURRENT public_keys[client_id] and public_keys[witness_id]
at admission, not the keys active when the SubmissionRequest /
WitnessObservation were signed.  Any rotation in the interval between
sign-time and evidence-admission defeated the evidence -- the verifier
saw a sig under K_old but resolved K_new and rejected as "invalid
request signature" / "invalid witness observation".

This is the same bug class fixed for AttestationSlashing /
double-proposal SlashingEvidence (audit r6), FinalityDoubleVote (audit
r11), and the slash-tx submitter path (audit r33) -- never propagated
to non-response.  CLAUDE.md anchor at risk: "censorship resistance is
a *collective decision*" -- the witnessed-submission pipeline IS the
slashable-evidence layer that backs the collective guarantee against
silent-TCP-drop censorship; rotation evasion reopens the silent-drop
gap.

Fix: extend the multi-key shape to non-response evidence.  Update
`verify_non_response_evidence_tx` to accept iterables of candidate
pubkeys for both `client_public_key` and each entry in
`witness_public_keys` (back-compat: a single bytes key is normalised
to a one-element list).  Update `validate_non_response_evidence_tx`
to enumerate the same `key_history + current` candidate set the slash
path already uses.

Tests:
  1. Forward-compat: legacy single-bytes caller still works for both
     client and witness.
  2. Verifier accepts a list of candidate client pubkeys; admits when
     the request was signed under K_old and the candidate set
     includes K_old (post-rotation chain holds K_new as current).
  3. Verifier accepts an iterable of candidate witness pubkeys per
     witness_id; admits when the observation was signed under W_old
     and the per-witness candidate set includes W_old.
  4. Pre-fix sanity: passing only the post-rotation key (K_new /
     W_new) MUST still reject -- this documents the exact bypass the
     multi-key path closes.
  5. End-to-end via `validate_non_response_evidence_tx`: a rotate-
     then-evidence client case is now admitted, where pre-fix it was
     dismissed as "invalid request: invalid request signature".
  6. End-to-end witness rotation: same shape on the witness axis.
"""

from __future__ import annotations

import hashlib
import time
import unittest

from messagechain.config import (
    HASH_ALGO,
    MIN_FEE,
    WITNESS_QUORUM,
    WITNESS_SURCHARGE,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceTx,
    sign_non_response_evidence,
    verify_non_response_evidence_tx,
)
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    WitnessObservation,
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


def _make_request(client: Entity, target_id: bytes) -> SubmissionRequest:
    return sign_submission_request(
        submitter=client,
        target_validator_id=target_id,
        tx_hash=_h(b"r38-tx"),
        timestamp=int(time.time()),
        client_nonce=b"\xA5" * 16,
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )


def _build_request_signed_with(
    *, claimed_submitter_id: bytes, signing_kp,
    target_validator_id: bytes, tx_hash: bytes,
    timestamp: int, client_nonce: bytes, fee: int,
) -> SubmissionRequest:
    """Construct a SubmissionRequest whose payload claims
    `submitter_id=claimed_submitter_id` but whose signature is produced
    by `signing_kp` -- i.e., a rotated client whose chain entity_id is
    K_old's entity_id but who currently signs with K_new.
    """
    placeholder = Signature([], 0, [], b"", b"")
    r = SubmissionRequest(
        tx_hash=tx_hash,
        target_validator_id=target_validator_id,
        timestamp=int(timestamp),
        client_nonce=client_nonce,
        submitter_id=claimed_submitter_id,
        fee=int(fee),
        signature=placeholder,
    )
    msg_hash = _h(r._signable_data())
    sig = signing_kp.sign(msg_hash)
    return SubmissionRequest(
        tx_hash=tx_hash,
        target_validator_id=target_validator_id,
        timestamp=int(timestamp),
        client_nonce=client_nonce,
        submitter_id=claimed_submitter_id,
        fee=int(fee),
        signature=sig,
    )


def _build_observation_signed_with(
    *, claimed_witness_id: bytes, signing_kp,
    request_hash: bytes, observed_height: int,
) -> WitnessObservation:
    """Construct a WitnessObservation whose payload claims
    `witness_id=claimed_witness_id` but whose signature is produced by
    `signing_kp` -- i.e., a rotated witness whose chain entity_id is
    W_old's entity_id but who currently signs with W_new.
    """
    placeholder = Signature([], 0, [], b"", b"")
    o = WitnessObservation(
        request_hash=request_hash,
        witness_id=claimed_witness_id,
        observed_height=int(observed_height),
        signature=placeholder,
    )
    msg_hash = _h(o._signable_data())
    sig = signing_kp.sign(msg_hash)
    return WitnessObservation(
        request_hash=request_hash,
        witness_id=claimed_witness_id,
        observed_height=int(observed_height),
        signature=sig,
    )


# ─────────────────────────────────────────────────────────────────────
# Verifier surface: legacy single-pubkey + multi-key iterable
# ─────────────────────────────────────────────────────────────────────


class TestVerifierAcceptsMultiKeyCandidates(unittest.TestCase):
    """`verify_non_response_evidence_tx` must accept iterables for
    both `client_public_key` and per-witness entries in
    `witness_public_keys`, mirroring the multi-key shape already
    shipped on attestation/finality/slash paths."""

    def test_legacy_single_bytes_callers_still_work(self):
        """Forward-compat: existing callers passing a single 32-byte
        pubkey for client + single bytes per witness MUST keep working
        unchanged."""
        client = _entity(b"r38-legacy-client")
        submitter = _entity(b"r38-legacy-sub")
        target_id = b"V" * 32
        witnesses = [
            _entity(b"r38-legacy-w" + bytes([i]))
            for i in range(WITNESS_QUORUM)
        ]
        req = _make_request(client, target_id)
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in witnesses
        ]
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        ok, reason = verify_non_response_evidence_tx(
            etx, submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in witnesses},
            client_public_key=client.public_key,
        )
        self.assertTrue(ok, f"Legacy single-bytes path broken: {reason}")

    def test_multi_key_admits_post_rotation_client(self):
        """Client signed the SubmissionRequest under K_old, then
        rotated; chain currently holds K_new.  Verifier with candidate
        list [K_old, K_new] must admit the evidence (matches K_old)."""
        client_old = _entity(b"r38-mk-client-old")
        client_new = _entity(b"r38-mk-client-new")
        # Build a request that CLAIMS submitter_id = client_old.entity_id
        # (the chain identity) but is SIGNED with client_old's keypair.
        target_id = b"V" * 32
        req = _build_request_signed_with(
            claimed_submitter_id=client_old.entity_id,
            signing_kp=client_old.keypair,
            target_validator_id=target_id,
            tx_hash=_h(b"r38-mk-client"),
            timestamp=int(time.time()),
            client_nonce=b"\xC1" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        # NOTE: request_hash is computed in the SubmissionRequest
        # ctor over the signed fields; `request.request_hash` is the
        # canonical handle used downstream.
        witnesses = [
            _entity(b"r38-mk-cw" + bytes([i]))
            for i in range(WITNESS_QUORUM)
        ]
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in witnesses
        ]
        submitter = _entity(b"r38-mk-client-sub")
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        # Chain currently holds K_new for this client (post-rotation),
        # but key_history retains K_old.  Caller passes the union as
        # the candidate set -- verifier must walk it.
        ok, reason = verify_non_response_evidence_tx(
            etx, submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in witnesses},
            client_public_key=[client_new.public_key, client_old.public_key],
        )
        self.assertTrue(
            ok,
            f"Multi-key client candidate list MUST admit a rotated-"
            f"client request whose K_old is in the set. Got: {reason}",
        )

    def test_multi_key_admits_post_rotation_witness(self):
        """One witness signed the observation under W_old, then
        rotated; chain currently holds W_new.  Verifier with the
        per-witness candidate list [W_new, W_old] must admit."""
        client = _entity(b"r38-mk-w-client")
        submitter = _entity(b"r38-mk-w-sub")
        target_id = b"V" * 32
        req = _make_request(client, target_id)
        # First witness rotated; the rest are legacy single-key.
        w0_old = _entity(b"r38-mk-w0-old")
        w0_new = _entity(b"r38-mk-w0-new")
        rest = [
            _entity(b"r38-mk-wr" + bytes([i]))
            for i in range(WITNESS_QUORUM - 1)
        ]
        observations = [
            _build_observation_signed_with(
                claimed_witness_id=w0_old.entity_id,
                signing_kp=w0_old.keypair,
                request_hash=req.request_hash,
                observed_height=10,
            ),
        ] + [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in rest
        ]
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        witness_pks: dict[bytes, object] = {
            w0_old.entity_id: [w0_new.public_key, w0_old.public_key],
        }
        for w in rest:
            witness_pks[w.entity_id] = w.public_key
        ok, reason = verify_non_response_evidence_tx(
            etx, submitter.public_key,
            witness_public_keys=witness_pks,
            client_public_key=client.public_key,
        )
        self.assertTrue(
            ok,
            f"Multi-key per-witness candidate list MUST admit a "
            f"rotated-witness observation whose W_old is in the set. "
            f"Got: {reason}",
        )

    def test_pre_fix_path_rejects_rotated_client_with_only_new_key(self):
        """Sanity-check the bypass shape: passing ONLY the post-
        rotation key for a request signed under K_old MUST still
        reject.  This is the exact pre-fix admission failure -- the
        chain only had K_new and the verifier dismissed it."""
        client_old = _entity(b"r38-pre-client-old")
        client_new = _entity(b"r38-pre-client-new")
        target_id = b"V" * 32
        req = _build_request_signed_with(
            claimed_submitter_id=client_old.entity_id,
            signing_kp=client_old.keypair,
            target_validator_id=target_id,
            tx_hash=_h(b"r38-pre-client"),
            timestamp=int(time.time()),
            client_nonce=b"\xC2" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        witnesses = [
            _entity(b"r38-pre-cw" + bytes([i]))
            for i in range(WITNESS_QUORUM)
        ]
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in witnesses
        ]
        submitter = _entity(b"r38-pre-client-sub")
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        ok, reason = verify_non_response_evidence_tx(
            etx, submitter.public_key,
            witness_public_keys={w.entity_id: w.public_key for w in witnesses},
            # Only K_new in the candidate set -- pre-fix admission
            # behaviour: the chain resolves the current pubkey only.
            client_public_key=client_new.public_key,
        )
        self.assertFalse(
            ok,
            "Sanity: with only K_new in the candidate set, a request "
            "signed under K_old MUST still reject -- this is the "
            "exact bypass the multi-key path closes.",
        )
        self.assertIn("request", reason.lower())


# ─────────────────────────────────────────────────────────────────────
# End-to-end via Blockchain.validate_non_response_evidence_tx
# ─────────────────────────────────────────────────────────────────────


class TestValidateNonResponseEvidenceWalksKeyHistory(unittest.TestCase):
    """`validate_non_response_evidence_tx` MUST enumerate the
    `key_history + current` candidate set for both the client and
    each witness, mirroring the slash-path enumeration in
    `validate_slash_transaction`."""

    def _bootstrap_chain(self) -> tuple[Blockchain, Entity]:
        chain = Blockchain()
        # Genesis target validator.
        target = _entity(b"r38-e2e-target")
        chain.initialize_genesis(target)
        chain.supply.balances[target.entity_id] = 1_000_000
        chain.supply.staked[target.entity_id] = 100_000
        return chain, target

    def _build_evidence_with_rotated_client(
        self, chain: Blockchain, target: Entity,
    ) -> tuple:
        """Set up a rotated client (K_old → K_new) with chain state
        reflecting the rotation, then build an evidence tx whose
        embedded SubmissionRequest was signed under K_old.

        Returns (etx, target_entity).
        """
        target_id = target.entity_id
        client_old = _entity(b"r38-e2e-rot-client-old")
        client_new = _entity(b"r38-e2e-rot-client-new")
        # Register K_old, then rotate to K_new in chain state.
        register_entity_for_test(chain, client_old)
        chain.public_keys[client_old.entity_id] = client_new.public_key
        chain.key_history[client_old.entity_id] = [
            (0, client_old.public_key),
            (150, client_new.public_key),
        ]
        chain.supply.balances[client_old.entity_id] = 1_000_000
        # Build a request claiming submitter_id=client_old.entity_id
        # (the chain identity) but signed by K_old.
        req = _build_request_signed_with(
            claimed_submitter_id=client_old.entity_id,
            signing_kp=client_old.keypair,
            target_validator_id=target_id,
            tx_hash=_h(b"r38-e2e-rot"),
            timestamp=int(time.time()),
            client_nonce=b"\xD1" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        witnesses = [
            _entity(b"r38-e2e-rot-w" + bytes([i]))
            for i in range(WITNESS_QUORUM)
        ]
        for w in witnesses:
            register_entity_for_test(chain, w)
            chain.supply.balances[w.entity_id] = 1_000_000
            chain.supply.staked[w.entity_id] = 100_000
        observations = [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in witnesses
        ]
        submitter = _entity(b"r38-e2e-rot-sub")
        register_entity_for_test(chain, submitter)
        chain.supply.balances[submitter.entity_id] = 1_000_000
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        # Stitch in the offender_id the validator API expects.
        # Tier-43 NonResponseEvidenceTx exposes this as a property
        # derived from request.target_validator_id, so the chain's
        # admission gate looks it up correctly.
        return etx, submitter

    def test_rotated_client_evidence_is_admitted_e2e(self):
        chain, target = self._bootstrap_chain()
        etx, _ = self._build_evidence_with_rotated_client(chain, target)
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertTrue(
            ok,
            f"Rotate-then-evidence client case MUST be admitted "
            f"post-fix.  Pre-fix this was dismissed as 'invalid "
            f"request: invalid request signature' because the "
            f"admission gate resolved K_new from public_keys but the "
            f"request was signed under K_old.  Got: {reason}",
        )

    def test_rotated_witness_evidence_is_admitted_e2e(self):
        chain, target = self._bootstrap_chain()
        target_id = target.entity_id
        client = _entity(b"r38-e2e-rotw-client")
        register_entity_for_test(chain, client)
        chain.supply.balances[client.entity_id] = 1_000_000
        req = _make_request(client, target_id)
        # First witness rotated W_old → W_new on chain.
        w0_old = _entity(b"r38-e2e-rotw-w0-old")
        w0_new = _entity(b"r38-e2e-rotw-w0-new")
        register_entity_for_test(chain, w0_old)
        chain.public_keys[w0_old.entity_id] = w0_new.public_key
        chain.key_history[w0_old.entity_id] = [
            (0, w0_old.public_key),
            (150, w0_new.public_key),
        ]
        chain.supply.balances[w0_old.entity_id] = 1_000_000
        chain.supply.staked[w0_old.entity_id] = 100_000
        rest_witnesses = [
            _entity(b"r38-e2e-rotw-rest" + bytes([i]))
            for i in range(WITNESS_QUORUM - 1)
        ]
        for w in rest_witnesses:
            register_entity_for_test(chain, w)
            chain.supply.balances[w.entity_id] = 1_000_000
            chain.supply.staked[w.entity_id] = 100_000
        observations = [
            _build_observation_signed_with(
                claimed_witness_id=w0_old.entity_id,
                signing_kp=w0_old.keypair,
                request_hash=req.request_hash,
                observed_height=10,
            ),
        ] + [
            sign_witness_observation(w, req.request_hash, observed_height=10)
            for w in rest_witnesses
        ]
        submitter = _entity(b"r38-e2e-rotw-sub")
        register_entity_for_test(chain, submitter)
        chain.supply.balances[submitter.entity_id] = 1_000_000
        etx = sign_non_response_evidence(
            submitter=submitter, request=req,
            observations=observations,
            timestamp=int(time.time()), fee=MIN_FEE,
        )
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertTrue(
            ok,
            f"Rotate-then-evidence witness case MUST be admitted "
            f"post-fix.  Pre-fix this was dismissed as 'invalid "
            f"witness observation: invalid observation signature' "
            f"because the admission gate resolved W_new but the "
            f"observation was signed under W_old.  Got: {reason}",
        )


if __name__ == "__main__":
    unittest.main()
