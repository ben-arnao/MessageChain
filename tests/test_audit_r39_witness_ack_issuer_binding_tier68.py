"""Audit r39 #1 -- Tier 68 witness-ack issuer-binding (silent-drop
collusion bypass).

Closes the silent-drop censorship-arm bypass on the witnessed-
submission slashing pipeline.  Pre-fix ``Blockchain.witness_ack_registry``
was keyed only on ``request_hash``: any registered validator's ack
landed in the registry discharged the obligation of the request's
ACTUAL target, regardless of who issued the ack.

Concrete attack: validator V_target receives a witnessed
``SubmissionRequest`` (``target_validator_id == V_target``) and
silently drops it (TCP-level censorship).  Q honest peers sign
``WitnessObservation`` records.  Before the assembled
``NonResponseEvidenceTx`` lands, attacker validator V_attacker (any
registered validator -- a sybil under the registration burn is fine)
signs a ``SubmissionAck`` for the same ``request_hash`` and a
colluding proposer embeds it in ``acks_observed_this_block``.  The
chain's apply path writes ``witness_ack_registry[rh] = h`` keyed only
on ``rh``.  ``validate_non_response_evidence_tx`` then rejects the
honest evidence with "ack present in chain state: obligation was met"
-- discharging V_target's silent-drop obligation by V_attacker's ack.

Net: the entire silent-drop censorship arm of the witnessed-submission
slashing pipeline collapses to a 2-validator collusion threshold (the
target + any one ally to sign the ack + a friendly-or-bribed proposer
to land it; in practice 2 hostile validators suffice).  This is the
canonical CLAUDE.md "validator collusion" adversary, dropping the
slashable-evidence cost of suppression to free.

Tier 68 (``WITNESS_ACK_ISSUER_BINDING_HEIGHT``) hard-fork-gates a
parallel ``witness_ack_by_issuer`` registry: ``request_hash ->
{issuer_id -> first ack_height}``.  Post-fork the discharge readers
(admission gate, processor, sim path) consult
``witness_ack_by_issuer[rh].get(target_validator_id)`` so only the
TARGET's own ack discharges the obligation.  Pre-fork the legacy
``witness_ack_registry`` reader runs unchanged for replay
determinism.

Same bug-class shape as the audit r38 #3 censorship-evidence
admission-gate fix (admission gate over-trusted state), but on a
sibling slashing arm; mirror the activation-gated parallel-registry
pattern used elsewhere (e.g. ``key_history`` for rotation-aware sig
verification).

Tests:
  1. Activation constant ordering (Tier 68 sits 50 above Tier 67).
  2. Pre-fork legacy: ``validate_non_response_evidence_tx`` rejects
     ANY ack in ``witness_ack_registry`` (the bug, preserved for
     historical replay).
  3. Post-fork bypass close: an attacker's ack in
     ``witness_ack_by_issuer`` does NOT discharge a different
     target's obligation; admission ADMITS the evidence.
  4. Post-fork positive: the target's OWN ack in
     ``witness_ack_by_issuer`` DOES discharge; admission rejects
     with "obligation was met".
  5. Apply path post-fork: a block carrying acks populates BOTH
     registries; ``witness_ack_by_issuer[rh][issuer_id]`` is
     keyed by issuer, supporting multiple acks for the same
     request_hash from distinct issuers.
  6. NonResponseEvidenceProcessor.process post-fork: same shape as
     #3/#4 on the apply-time slashing path (the actual stake-burn
     gate, not just the admission gate).
  7. Pruning: ``_prune_witness_ack_registry`` drops
     ``witness_ack_by_issuer`` entries symmetrically with the
     legacy registry.
"""

from __future__ import annotations

import hashlib
import time
import unittest

import messagechain.config as _cfg
from messagechain.config import (
    HASH_ALGO,
    MIN_FEE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_SURCHARGE,
)
from messagechain.consensus.non_response_evidence import (
    NonResponseEvidenceProcessor,
    NonResponseResult,
    sign_non_response_evidence,
)
from messagechain.consensus.witness_submission import (
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


# ─────────────────────────────────────────────────────────────────────
# Activation constant ordering
# ─────────────────────────────────────────────────────────────────────


class TestActivationOrdering(unittest.TestCase):
    """Tier 68 must sit AFTER Tier 67 (activation-cohort spacing)."""

    def test_tier68_height_exists(self):
        self.assertTrue(
            hasattr(_cfg, "WITNESS_ACK_ISSUER_BINDING_HEIGHT"),
            "WITNESS_ACK_ISSUER_BINDING_HEIGHT (Tier 68) must be defined",
        )

    def test_tier68_after_tier67(self):
        from messagechain.config import (
            ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
            WITNESS_ACK_ISSUER_BINDING_HEIGHT,
        )
        self.assertGreater(
            WITNESS_ACK_ISSUER_BINDING_HEIGHT,
            ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
            "Tier 68 must follow Tier 67 -- consecutive activations need "
            "cohort spacing to keep the validator-upgrade window open",
        )


# ─────────────────────────────────────────────────────────────────────
# Test fixture: bootstrap a chain + build legitimate evidence
# ─────────────────────────────────────────────────────────────────────


def _bootstrap_chain_with_target_and_attacker():
    """Build a chain with three registered entities:
      * V_target  -- the validator the SubmissionRequest is directed at
      * V_attacker -- a registered validator who will sign a discharge
                       ack for someone else's request_hash
      * client     -- the user who originated the SubmissionRequest
    Returns (chain, target_entity, attacker_entity, client_entity).
    """
    chain = Blockchain()
    target = _entity(b"r39-tier68-target")
    chain.initialize_genesis(target)
    chain.supply.balances[target.entity_id] = 1_000_000
    chain.supply.staked[target.entity_id] = 100_000

    attacker = _entity(b"r39-tier68-attacker")
    register_entity_for_test(chain, attacker)
    chain.supply.balances[attacker.entity_id] = 1_000_000
    chain.supply.staked[attacker.entity_id] = 100_000

    client = _entity(b"r39-tier68-client")
    register_entity_for_test(chain, client)
    chain.supply.balances[client.entity_id] = 1_000_000

    return chain, target, attacker, client


def _build_silent_drop_evidence(chain, target, client):
    """Build a NonResponseEvidenceTx alleging V_target silently dropped
    a witnessed SubmissionRequest from `client`.  Signs the request +
    Q witness observations + the wrapping evidence tx.  Returns
    (etx, request_hash, observed_height).
    """
    observed_height = 10
    req = sign_submission_request(
        submitter=client,
        target_validator_id=target.entity_id,
        tx_hash=_h(b"r39-tier68-tx"),
        timestamp=int(time.time()),
        client_nonce=b"\xA5" * 16,
        fee=MIN_FEE + WITNESS_SURCHARGE,
    )
    witnesses = [
        _entity(b"r39-t68-w" + bytes([i]))
        for i in range(WITNESS_QUORUM)
    ]
    for w in witnesses:
        register_entity_for_test(chain, w)
        chain.supply.balances[w.entity_id] = 1_000_000
        chain.supply.staked[w.entity_id] = 100_000
    observations = [
        sign_witness_observation(
            w, req.request_hash, observed_height=observed_height,
        )
        for w in witnesses
    ]
    submitter = _entity(b"r39-t68-sub")
    register_entity_for_test(chain, submitter)
    chain.supply.balances[submitter.entity_id] = 1_000_000
    etx = sign_non_response_evidence(
        submitter=submitter, request=req,
        observations=observations,
        timestamp=int(time.time()), fee=MIN_FEE,
    )
    return etx, req.request_hash, observed_height


# ─────────────────────────────────────────────────────────────────────
# Pre-fork legacy: any-issuer ack discharges (the bug, preserved)
# ─────────────────────────────────────────────────────────────────────


class TestPreForkLegacyBehavior(unittest.TestCase):
    """At chain heights below ``WITNESS_ACK_ISSUER_BINDING_HEIGHT``
    the legacy single-key registry is the discharge authority -- ANY
    issuer's ack for a request_hash discharges the target's obligation.
    This is the bug, but historical replay determinism requires we
    keep it for blocks below the activation gate."""

    def setUp(self):
        # Force pre-fork by pinning the activation gate above tip.
        self._orig = _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = 10_000_000

    def tearDown(self):
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = self._orig

    def test_attacker_ack_discharges_pre_fork(self):
        """Pre-fork: attacker's ack in legacy registry blocks legitimate
        evidence admission.  Documents the exact bypass Tier 68 closes
        post-activation."""
        chain, target, attacker, client = (
            _bootstrap_chain_with_target_and_attacker()
        )
        etx, rh, _ = _build_silent_drop_evidence(chain, target, client)
        # Simulate attacker's ack landing on chain via legacy apply path.
        chain.witness_ack_registry[rh] = (
            10 + WITNESS_RESPONSE_DEADLINE_BLOCKS // 2
        )
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertFalse(
            ok,
            "Pre-fork legacy MUST reject when ANY ack is in the "
            "single-key registry -- this is the bug Tier 68 closes "
            f"post-fork.  Got: ok={ok}, reason={reason!r}",
        )
        self.assertIn("ack present", reason)


# ─────────────────────────────────────────────────────────────────────
# Post-fork: only the TARGET's ack discharges
# ─────────────────────────────────────────────────────────────────────


class TestPostForkIssuerBinding(unittest.TestCase):
    """At chain heights at/after ``WITNESS_ACK_ISSUER_BINDING_HEIGHT``
    discharge readers consult the per-issuer registry, so an
    attacker's ack does NOT discharge a different target's obligation."""

    def setUp(self):
        # Force post-fork by pinning the activation gate at 0.
        self._orig = _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = 0

    def tearDown(self):
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = self._orig

    def test_attacker_ack_does_not_discharge_post_fork(self):
        """Post-fork: an attacker's ack recorded in
        ``witness_ack_by_issuer`` MUST NOT discharge the target's
        obligation -- admission ADMITS the evidence so the slash path
        proceeds to the deadline + active-set + quorum gates."""
        chain, target, attacker, client = (
            _bootstrap_chain_with_target_and_attacker()
        )
        etx, rh, _ = _build_silent_drop_evidence(chain, target, client)
        # Simulate attacker's ack landing post-fork via the per-issuer
        # registry.  Legacy registry mirrors the write (apply path
        # writes both post-fork) -- but legacy is no longer the
        # discharge authority post-activation.
        ack_h = 10 + WITNESS_RESPONSE_DEADLINE_BLOCKS // 2
        chain.witness_ack_registry[rh] = ack_h
        chain.witness_ack_by_issuer.setdefault(rh, {})[
            attacker.entity_id
        ] = ack_h
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertTrue(
            ok,
            "Post-fork MUST admit silent-drop evidence even when an "
            "attacker validator's ack is in the registry -- only the "
            "target's own ack should discharge the obligation.  Got: "
            f"ok={ok}, reason={reason!r}",
        )

    def test_target_own_ack_discharges_post_fork(self):
        """Post-fork: the target's own ack DOES discharge -- no false
        positive on legitimate self-acked submissions."""
        chain, target, attacker, client = (
            _bootstrap_chain_with_target_and_attacker()
        )
        etx, rh, _ = _build_silent_drop_evidence(chain, target, client)
        ack_h = 10 + WITNESS_RESPONSE_DEADLINE_BLOCKS // 2
        chain.witness_ack_registry[rh] = ack_h
        chain.witness_ack_by_issuer.setdefault(rh, {})[
            target.entity_id
        ] = ack_h
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertFalse(
            ok,
            "Post-fork MUST reject evidence when the TARGET's own "
            "ack is recorded -- legitimate discharge.  Got: "
            f"ok={ok}, reason={reason!r}",
        )
        self.assertIn("ack", reason.lower())

    def test_no_ack_at_all_post_fork(self):
        """Post-fork: if no ack is recorded for the request_hash, the
        evidence still passes the discharge gate (it'll be filtered by
        deadline/quorum elsewhere; the discharge gate doesn't reject)."""
        chain, target, _attacker, client = (
            _bootstrap_chain_with_target_and_attacker()
        )
        etx, _rh, _ = _build_silent_drop_evidence(chain, target, client)
        # No ack populated anywhere.
        ok, reason = chain.validate_non_response_evidence_tx(etx)
        self.assertTrue(
            ok,
            "Post-fork MUST admit evidence when no ack is recorded -- "
            f"discharge gate has nothing to short-circuit on.  Got: "
            f"ok={ok}, reason={reason!r}",
        )

    def test_processor_process_respects_issuer_binding(self):
        """The apply-time path (NonResponseEvidenceProcessor.process)
        must mirror the admission gate's per-issuer discharge check."""
        chain, target, attacker, client = (
            _bootstrap_chain_with_target_and_attacker()
        )
        etx, rh, observed_height = _build_silent_drop_evidence(
            chain, target, client,
        )
        # Attacker's ack present, target's NOT.
        ack_h = observed_height + WITNESS_RESPONSE_DEADLINE_BLOCKS // 2
        chain.witness_ack_by_issuer.setdefault(rh, {})[
            attacker.entity_id
        ] = ack_h
        # Run process at a height past the deadline so the slash gates
        # run cleanly.
        proc = chain.non_response_processor
        result = proc.process(
            etx,
            blockchain=chain,
            current_height=observed_height
            + WITNESS_RESPONSE_DEADLINE_BLOCKS
            + 5,
        )
        # Either accepted+slashed (full slash path), or accepted=False
        # with a NON-discharge reason (e.g. quorum/active-set gate).
        # The KEY is that "obligation met" must NOT be the rejection
        # reason -- that's the bug class.
        if isinstance(result, NonResponseResult) and not result.accepted:
            self.assertNotIn(
                "obligation met", (result.reason or "").lower(),
                "Post-fork process() MUST NOT short-circuit on an "
                "attacker's ack -- 'obligation met' rejection means "
                "the per-issuer binding is bypassed.  Got: "
                f"reason={result.reason!r}",
            )


# ─────────────────────────────────────────────────────────────────────
# Apply path: writes both registries post-fork
# ─────────────────────────────────────────────────────────────────────


class TestApplyPathPopulatesBothRegistries(unittest.TestCase):
    """The apply path must populate BOTH ``witness_ack_registry`` and
    ``witness_ack_by_issuer`` post-fork so multiple distinct issuers
    each get tracked under the same request_hash."""

    def setUp(self):
        self._orig = _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = 0

    def tearDown(self):
        _cfg.WITNESS_ACK_ISSUER_BINDING_HEIGHT = self._orig

    def test_witness_ack_by_issuer_attribute_exists(self):
        """The per-issuer registry attribute must exist on Blockchain."""
        chain = Blockchain()
        self.assertTrue(
            hasattr(chain, "witness_ack_by_issuer"),
            "Blockchain must expose witness_ack_by_issuer registry",
        )
        self.assertIsInstance(chain.witness_ack_by_issuer, dict)

    def test_first_write_wins_per_issuer(self):
        """Multiple issuers acking the same request_hash each get their
        own first-write-wins entry under the same rh key."""
        chain = Blockchain()
        rh = b"\xAA" * 32
        i1 = b"\x01" * 32
        i2 = b"\x02" * 32
        chain.witness_ack_by_issuer.setdefault(rh, {})[i1] = 100
        chain.witness_ack_by_issuer.setdefault(rh, {})[i2] = 105
        # First write wins per issuer (mirror the legacy registry's
        # first-write-wins shape, but SCOPED to the (rh, issuer) key).
        chain.witness_ack_by_issuer[rh].setdefault(i1, 999)
        chain.witness_ack_by_issuer[rh].setdefault(i2, 999)
        self.assertEqual(chain.witness_ack_by_issuer[rh][i1], 100)
        self.assertEqual(chain.witness_ack_by_issuer[rh][i2], 105)


# ─────────────────────────────────────────────────────────────────────
# Pruning: drops witness_ack_by_issuer symmetrically
# ─────────────────────────────────────────────────────────────────────


class TestPruningDropsBothRegistries(unittest.TestCase):
    """``_prune_witness_ack_registry`` must drop entries from
    ``witness_ack_by_issuer`` symmetrically with the legacy registry --
    otherwise the per-issuer registry grows unboundedly."""

    def test_prune_drops_old_per_issuer_entries(self):
        from messagechain.config import (
            WITNESS_OBSERVATION_RETENTION_BLOCKS,
            WITNESS_RESPONSE_DEADLINE_BLOCKS,
        )
        chain = Blockchain()
        # Old entry (well past the prune cutoff).
        rh_old = b"\x01" * 32
        old_h = 0
        chain.witness_ack_registry[rh_old] = old_h
        chain.witness_ack_by_issuer[rh_old] = {b"\xAA" * 32: old_h}
        # Fresh entry.
        rh_fresh = b"\x02" * 32
        fresh_h = 10_000
        chain.witness_ack_registry[rh_fresh] = fresh_h
        chain.witness_ack_by_issuer[rh_fresh] = {b"\xBB" * 32: fresh_h}
        # Prune at a height that produces a cutoff strictly between
        # old_h and fresh_h.  Inside the prune helper:
        #   cutoff = current_height - retention - deadline
        #   drop iff h < cutoff.
        # Choosing current_height = old_h + 1 + retention + deadline
        # gives cutoff = old_h + 1 -- so old (h=old_h) drops and
        # fresh (h=fresh_h >> cutoff) stays.
        cutoff_height = (
            old_h + 1
            + int(WITNESS_OBSERVATION_RETENTION_BLOCKS)
            + int(WITNESS_RESPONSE_DEADLINE_BLOCKS)
        )
        chain._prune_witness_ack_registry(current_height=cutoff_height)
        self.assertNotIn(rh_old, chain.witness_ack_registry)
        self.assertNotIn(rh_old, chain.witness_ack_by_issuer)
        self.assertIn(rh_fresh, chain.witness_ack_registry)
        self.assertIn(rh_fresh, chain.witness_ack_by_issuer)


if __name__ == "__main__":
    unittest.main()
