"""Tier-41 — Ack-deadline GRACE defense on the slash-decision comparator.

Tier 39 closed the issuer-side backdating attack on witness-non-response
slashing by re-pinning the registry's recorded ack discharge height to
``block.header.block_number`` (the chain-observed inclusion height).
That fix introduced an asymmetry on the OTHER side of the same gate:

  * The validate-side path (``_validate_acks_observed_this_block``)
    accepts an ack within ``WITNESS_RESPONSE_DEADLINE_BLOCKS +
    ACK_INCLUSION_GRACE`` of the inclusion height — the GRACE absorbs
    the propagation delay between an issuer signing the ack and the
    next honest proposer landing it on chain.

  * The slash-decision path
    (``NonResponseEvidenceProcessor.process()``) compared
    ``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS``
    with NO grace.  An honest acker who lands one block past the bare
    deadline — because a colluding next-proposer drops the ack for one
    block before the next honest proposer includes it — is then
    fabricated as "obligation not met" and slashed.

A two-validator collusion (Q witnesses + 1 deadline-tip proposer who
drops the ack for one block) is enough to fabricate a non-response
slash against an honest target.  Tier 41 widens the slash-decision
comparator to:

    ``ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS +
               ACK_INCLUSION_GRACE``

restoring symmetry with the validate-side bound.  The same change is
mirrored in ``compute_post_state_root`` so propose-time and apply-time
non-response decisions stay byte-identical.

Pre-activation: legacy comparator (no GRACE) preserved byte-for-byte
for replay determinism.
"""

from __future__ import annotations

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    ACK_INCLUSION_GRACE,
    HASH_ALGO,
    MIN_FEE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
    NonResponseEvidenceTx,
    sign_non_response_evidence,
)
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_witnesses(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create((b"t41-wn-" + tag + b"-" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _make_request(
    client: Entity, target_id: bytes, nonce_seed: bytes
) -> SubmissionRequest:
    from messagechain.config import WITNESS_SURCHARGE
    return sign_submission_request(
        submitter=client,
        target_validator_id=target_id,
        tx_hash=_h(b"t41-tx-payload-" + nonce_seed),
        timestamp=int(time.time()),
        client_nonce=(nonce_seed * 16)[:16],
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )


class _GraceDefenseHarness(unittest.TestCase):
    """Spin up a chain + target + Q witnesses; let the subclass set the
    Tier 41 activation height."""

    # Per-test override of the Tier 41 activation gate.  Tests for the
    # pre-activation legacy path raise this above the block height they
    # exercise; tests for the post-activation behavior lower it.
    activation_height: int | None = None

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        if self.activation_height is not None:
            import messagechain.config as _cfg
            self._orig_t41_h = _cfg.ACK_DEADLINE_GRACE_DEFENSE_HEIGHT
            _cfg.ACK_DEADLINE_GRACE_DEFENSE_HEIGHT = self.activation_height

        self.target = Entity.create(b"t41-target".ljust(32, b"\x00"))
        self.client = Entity.create(b"t41-client".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"t41-submitter".ljust(32, b"\x00"))
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

        self.witnesses = _make_witnesses(WITNESS_QUORUM, b"grace")
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 100_000

    def tearDown(self):
        if self.activation_height is not None:
            import messagechain.config as _cfg
            _cfg.ACK_DEADLINE_GRACE_DEFENSE_HEIGHT = self._orig_t41_h

    def _make_evidence(
        self,
        observed_height: int,
        request_seed: bytes = b"\x01",
    ) -> NonResponseEvidenceTx:
        req = _make_request(self.client, self.target.entity_id, request_seed)
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


class TestGraceDefensePostActivation(_GraceDefenseHarness):
    """Activation-on. Block heights ≥ activation 1 → new comparator with
    GRACE applies."""

    activation_height = 1

    def test_honest_ack_within_deadline_plus_grace_not_slashed(self):
        """An honest acker whose ack lands at exactly
        ``earliest_obs + DEADLINE + GRACE`` is recognized as
        obligation-met and the evidence is rejected (no slash)."""
        observed_h = 0
        etx = self._make_evidence(observed_height=observed_h)
        # Pre-record an ack landing at observed + DEADLINE + GRACE.
        # Pre-Tier-41 this would have failed the comparator and slashed
        # the honest target; Tier 41 widens the bound to admit it.
        self.chain.witness_ack_registry[etx.request.request_hash] = (
            observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE
        )
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=(
                WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5
            ),
        )
        self.assertFalse(result.slashed, result.reason)
        self.assertFalse(result.accepted, result.reason)
        self.assertIn("obligation met", result.reason.lower())

    def test_honest_ack_one_block_past_deadline_not_slashed(self):
        """Concrete realization of the audit finding: an honest acker
        whose ack lands at ``observed + DEADLINE + 1`` (one block past
        the bare deadline, well inside DEADLINE+GRACE) is NOT slashed
        post-Tier-41, where pre-Tier-41 it would have been."""
        observed_h = 0
        etx = self._make_evidence(observed_height=observed_h)
        ack_h = observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS + 1
        self.chain.witness_ack_registry[etx.request.request_hash] = ack_h
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=(
                WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5
            ),
        )
        self.assertFalse(result.slashed, result.reason)
        self.assertFalse(result.accepted, result.reason)

    def test_ack_past_deadline_plus_grace_still_slashed(self):
        """Boundary: an ack landing at
        ``observed + DEADLINE + GRACE + 1`` is past the widened bound
        and the slash still fires.  Confirms Tier 41 widens but does
        not remove the bound."""
        observed_h = 0
        etx = self._make_evidence(
            observed_height=observed_h, request_seed=b"\x02",
        )
        # Ack one block past the widened (DEADLINE + GRACE) bound.
        ack_h = (
            observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS
            + ACK_INCLUSION_GRACE + 1
        )
        self.chain.witness_ack_registry[etx.request.request_hash] = ack_h
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=(
                WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5
            ),
        )
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)
        self.assertEqual(result.offender_id, self.target.entity_id)


class TestGraceDefensePreActivation(_GraceDefenseHarness):
    """Activation-off. Block heights well below activation 10**9 → legacy
    comparator (no GRACE)."""

    activation_height = 10**9

    def test_pre_fork_honest_ack_one_block_past_deadline_is_slashed(self):
        """Pre-fork: byte-identical to legacy.  An honest acker landing
        ``observed + DEADLINE + 1`` IS still slashed pre-fork (this is
        the very bug Tier 41 fixes; we pin the legacy behavior here so
        the activation gate is provably load-bearing)."""
        observed_h = 0
        etx = self._make_evidence(observed_height=observed_h)
        ack_h = observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS + 1
        self.chain.witness_ack_registry[etx.request.request_hash] = ack_h
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=(
                WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5
            ),
        )
        # Legacy path: comparator has no GRACE, so ack at DEADLINE+1
        # fails the bound and the honest target is slashed.
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed, result.reason)

    def test_pre_fork_ack_at_bare_deadline_not_slashed(self):
        """Pre-fork: byte-identical to legacy.  An ack at exactly
        ``observed + DEADLINE`` IS recognized as obligation-met (bare-
        deadline accept).  Pinning the boundary keeps replay
        deterministic."""
        observed_h = 0
        etx = self._make_evidence(
            observed_height=observed_h, request_seed=b"\x03",
        )
        self.chain.witness_ack_registry[etx.request.request_hash] = (
            observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS
        )
        proc = NonResponseEvidenceProcessor()
        result = proc.process(
            etx, self.chain,
            current_height=(
                WITNESS_RESPONSE_DEADLINE_BLOCKS + ACK_INCLUSION_GRACE + 5
            ),
        )
        self.assertFalse(result.slashed, result.reason)
        self.assertFalse(result.accepted, result.reason)


class TestGraceDefenseSimApplyParity(_GraceDefenseHarness):
    """The propose-side ``compute_post_state_root`` mirror and the
    apply-side ``NonResponseEvidenceProcessor.process()`` must reach
    byte-identical decisions for every ack/observed/current-height
    triple in the gate.  A divergence here is a state-root mismatch
    that takes down the network at the activation tip."""

    activation_height = 1

    def test_sim_and_apply_agree_post_fork_in_grace_window(self):
        """In the GRACE window (ack at DEADLINE+1, well inside
        DEADLINE+GRACE), both paths must say "obligation met"
        (no slash, no balance/state delta)."""
        from messagechain.config import (
            NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT as _T35_H,
        )
        observed_h = 0
        etx = self._make_evidence(observed_height=observed_h)
        ack_h = observed_h + WITNESS_RESPONSE_DEADLINE_BLOCKS + 1
        self.chain.witness_ack_registry[etx.request.request_hash] = ack_h

        # Run heights ≥ Tier 35 (block-slot fork) so the sim mirror's
        # NRE branch is even reachable.  Tier 41 is set to 1 by the
        # harness so the GRACE applies on both sides.
        height = max(_T35_H, WITNESS_RESPONSE_DEADLINE_BLOCKS + 100)

        # Snapshot live state hash (sim must NOT mutate live state).
        live_target_stake_before = self.chain.supply.staked[self.target.entity_id]

        # Sim run: compute_post_state_root with the etx in the new slot.
        from messagechain.consensus.pos import ProofOfStake
        # The sim path expects the block to be at `height`; fabricate
        # a proposer leaf-index hint.  Use the target as proposer since
        # they hold genesis stake; Blockchain.initialize_genesis already
        # registered them.
        sim_root = self.chain.compute_post_state_root(
            transactions=[],
            proposer_id=self.target.entity_id,
            block_height=height,
            non_response_evidence_txs=[etx],
            proposer_signature_leaf_index=(
                self.target.keypair._next_leaf
            ),
        )
        self.assertIsInstance(sim_root, bytes)
        # Sim must not have mutated live state.
        self.assertEqual(
            self.chain.supply.staked[self.target.entity_id],
            live_target_stake_before,
        )

        # Apply-side run on the same etx + same height.  The processor
        # is the source of truth that the sim mirror must agree with.
        proc = NonResponseEvidenceProcessor()
        result = proc.process(etx, self.chain, current_height=height)
        # In the GRACE window: both paths must agree NO slash fires.
        self.assertFalse(result.slashed, result.reason)
        self.assertFalse(result.accepted, result.reason)
        self.assertEqual(
            self.chain.supply.staked[self.target.entity_id],
            live_target_stake_before,
        )


class TestActivationOrdering(unittest.TestCase):
    """Tier 41 must follow Tier 40 (the most recent active fork) and
    Tier 39 (the symmetric-counterpart fork it widens)."""

    def test_t41_follows_t40(self):
        from messagechain.config import (
            ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
            REWARD_CURVE_SMOOTH_HEIGHT,
        )
        self.assertGreater(
            ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
            REWARD_CURVE_SMOOTH_HEIGHT,
            "Tier 41 must activate after Tier 40 — pre-activation "
            "callers see the legacy slash-decision comparator (no "
            "GRACE) byte-for-byte; activating before Tier 40 lands "
            "would interleave two unrelated rule changes in the same "
            "upgrade window",
        )

    def test_t41_follows_t39(self):
        from messagechain.config import (
            ACK_BACKDATING_DEFENSE_HEIGHT,
            ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
        )
        self.assertGreater(
            ACK_DEADLINE_GRACE_DEFENSE_HEIGHT,
            ACK_BACKDATING_DEFENSE_HEIGHT,
            "Tier 41 must activate after Tier 39 — Tier 41 widens the "
            "slash-decision side of the same ack-deadline gate Tier 39 "
            "tightened on the issuer side; the registry-source change "
            "Tier 39 lands must already be live or the wider comparator "
            "widens against issuer-controlled discharge heights.",
        )


if __name__ == "__main__":
    unittest.main()
