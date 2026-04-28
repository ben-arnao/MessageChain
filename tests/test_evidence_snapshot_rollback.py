"""Snapshot/restore symmetry for evidence-tracking collections.

Audit finding: ``Blockchain._snapshot_memory_state`` and
``_restore_memory_snapshot`` capture ``_processed_evidence`` but NOT
four other mutable evidence-tracking structures that
``_apply_block_state`` mutates:

  * ``non_response_processor.processed`` (set[bytes])
  * ``bogus_rejection_processor.processed`` (set[bytes])
  * ``censorship_processor.pending`` (dict[bytes, _PendingEvidence])
  * ``witness_ack_registry`` (dict[bytes, int])

When a block fails the post-apply state-root check (line ~12071) the
chain calls ``_restore_memory_snapshot``.  Pre-fix, those four
mutations are NOT rolled back.

Attack: a coerced validator crafts a block carrying a valid evidence
tx and a deliberately-wrong ``state_root``.  Honest peers run the
apply path: ``non_response_processor.processed`` gets the evidence's
hash bumped in.  The post-apply state-root check then fails and the
block is rejected — but the dedup gate has already been poisoned, so
a later honest re-submission of the SAME evidence is silently dropped
at validation time (``non_response_processor.has_processed`` returns
True).  Result: the offender escapes slashing forever.

This test pins the snapshot/restore contract: every evidence-tracking
collection that ``_apply_block_state`` mutates MUST be captured by
the snapshot and restored verbatim by the restore path.

No-fork: the snapshot/restore boundary is purely in-memory; the
chaindb mirror runs only after the state-root check passes, so
historical replay is unchanged.
"""

from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    MIN_FEE,
    NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT,
    WITNESS_QUORUM,
    WITNESS_SURCHARGE,
)
from messagechain.consensus.censorship_evidence import _PendingEvidence
from messagechain.consensus.non_response_evidence import (
    sign_non_response_evidence,
)
from messagechain.consensus.witness_submission import (
    sign_submission_request,
    sign_witness_observation,
)
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _force_chain_height(chain: Blockchain, h: int):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


def _make_block(
    proposer: Entity,
    block_number: int,
    prev_hash: bytes,
    **slots,
) -> Block:
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=prev_hash,
        merkle_root=_h(b"empty"),
        timestamp=int(time.time()) + 1,
        proposer_id=proposer.entity_id,
    )
    header.proposer_signature = proposer.keypair.sign(
        _h(header.signable_data()),
    )
    blk = Block(header=header, transactions=[], **slots)
    blk.block_hash = blk._compute_hash()
    return blk


# ────────────────────────────────────────────────────────────────────
# Direct symmetry tests — populate the four collections, snapshot,
# mutate, restore, assert pre-mutation state is back.
# ────────────────────────────────────────────────────────────────────

class TestEvidenceCollectionsSnapshotSymmetry(unittest.TestCase):
    """Pin ``_snapshot_memory_state`` / ``_restore_memory_snapshot``
    captures and restores every evidence-tracking collection that the
    apply path mutates.  Each test seeds a single collection, takes
    a snapshot, mutates it (simulating a bad-state-root apply), then
    restores from the snapshot and checks the mutation was rolled back.
    """

    def setUp(self):
        self.proposer = Entity.create(b"snap-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_non_response_processor_processed_is_rolled_back(self):
        """A bad-state-root apply that bumps
        ``non_response_processor.processed`` must NOT leak the bump
        past the snapshot/restore boundary.  Pre-fix the bumped hash
        survives the rollback and silently blocks honest resubmission
        of the same evidence."""
        prior_hash = _h(b"nre-evidence-pre-existing")
        self.chain.non_response_processor.processed.add(prior_hash)
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply mutating the set (this is what
        # _apply_block_state does at the point an NRE is admitted).
        attacker_hash = _h(b"nre-evidence-poisoned")
        self.chain.non_response_processor.processed.add(attacker_hash)

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_hash,
            self.chain.non_response_processor.processed,
            "non_response_processor.processed must be rolled back to "
            "the pre-apply snapshot — pre-fix the attacker's evidence "
            "hash survives a failed-state-root rollback and silently "
            "blocks honest resubmission of the same evidence.",
        )
        self.assertIn(
            prior_hash,
            self.chain.non_response_processor.processed,
            "Pre-existing entries must be preserved by the restore.",
        )

    def test_bogus_rejection_processor_processed_is_rolled_back(self):
        """Same defect class for the bogus-rejection processor's dedup
        set.  The attacker can poison BR-evidence dedup in addition
        to NRE."""
        prior_hash = _h(b"br-evidence-pre-existing")
        self.chain.bogus_rejection_processor.processed.add(prior_hash)
        snapshot = self.chain._snapshot_memory_state()

        attacker_hash = _h(b"br-evidence-poisoned")
        self.chain.bogus_rejection_processor.processed.add(attacker_hash)

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_hash,
            self.chain.bogus_rejection_processor.processed,
            "bogus_rejection_processor.processed must be rolled back "
            "to the pre-apply snapshot.",
        )
        self.assertIn(
            prior_hash,
            self.chain.bogus_rejection_processor.processed,
            "Pre-existing entries must be preserved by the restore.",
        )

    def test_censorship_processor_pending_is_rolled_back(self):
        """The censorship processor's ``pending`` map carries
        ``_PendingEvidence`` records keyed by evidence_hash.  A bad-
        state-root apply that admits a CensorshipEvidenceTx bumps
        ``pending[ev_hash]``; the rollback must reset both the mapping
        AND its inner record state (deep enough that mutations after
        snapshot don't bleed back through the snapshot's view)."""
        prior_ev = _h(b"cs-pending-pre-existing")
        prior_entry = _PendingEvidence(
            evidence_hash=prior_ev,
            offender_id=b"O" * 32,
            tx_hash=_h(b"cs-target-tx"),
            admitted_height=1,
            evidence_tx_hash=_h(b"cs-evidence-tx"),
            staked_at_admission=10_000,
        )
        self.chain.censorship_processor.pending[prior_ev] = prior_entry
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply admitting a NEW evidence (poisons pending),
        # plus an in-place mutation of the pre-existing record's
        # `staked_at_admission` (would happen if the apply path ever
        # recomputed the basis on observe_block).  Both must roll back.
        attacker_ev = _h(b"cs-pending-poisoned")
        self.chain.censorship_processor.pending[attacker_ev] = (
            _PendingEvidence(
                evidence_hash=attacker_ev,
                offender_id=b"X" * 32,
                tx_hash=_h(b"cs-target-tx-2"),
                admitted_height=2,
                evidence_tx_hash=_h(b"cs-evidence-tx-2"),
                staked_at_admission=99_999,
            )
        )
        self.chain.censorship_processor.pending[prior_ev].staked_at_admission = (
            777_777
        )

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_ev,
            self.chain.censorship_processor.pending,
            "censorship_processor.pending must be rolled back to the "
            "pre-apply snapshot — attacker-admitted evidence cannot "
            "survive a failed-state-root rollback.",
        )
        self.assertIn(
            prior_ev,
            self.chain.censorship_processor.pending,
            "Pre-existing pending entries must be preserved.",
        )
        self.assertEqual(
            self.chain.censorship_processor.pending[prior_ev]
            .staked_at_admission,
            10_000,
            "In-place mutations of the pre-existing pending record "
            "must also roll back — the snapshot must be deep enough "
            "to isolate the inner record's state.",
        )

    def test_witness_ack_registry_is_rolled_back(self):
        """The witness-ack registry maps ``request_hash -> ack_height``.
        ``_apply_block_state`` writes here on every block.  A bad-state-
        root apply that bumps the registry must roll those entries
        back, otherwise an attacker can plant a phantom ack at the
        deadline and silently disable an honest NRE resubmission."""
        prior_rh = _h(b"witness-ack-pre-existing")
        self.chain.witness_ack_registry[prior_rh] = 100
        snapshot = self.chain._snapshot_memory_state()

        attacker_rh = _h(b"witness-ack-poisoned")
        self.chain.witness_ack_registry[attacker_rh] = 999
        # In-place mutation — the apply path's "first write wins" guard
        # means this normally wouldn't happen on the LIVE map, but the
        # snapshot MUST be deep enough that mutating the live dict
        # post-snapshot cannot leak back through the captured copy.
        self.chain.witness_ack_registry[prior_rh] = 555

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_rh,
            self.chain.witness_ack_registry,
            "witness_ack_registry must be rolled back to the pre-apply "
            "snapshot — pre-fix a phantom ack survives the rollback "
            "and silently disables NRE resubmission for the request.",
        )
        self.assertEqual(
            self.chain.witness_ack_registry[prior_rh],
            100,
            "Pre-existing registry entries must be preserved verbatim.",
        )


# ────────────────────────────────────────────────────────────────────
# End-to-end: real apply path bumps non_response_processor.processed,
# then a manual restore proves the bug at the realistic attack site.
# ────────────────────────────────────────────────────────────────────

class TestNonResponseEvidenceApplyRollback(unittest.TestCase):
    """Realistic attack scenario: build an NRE, run ``_apply_block_state``
    against a synthetic block carrying it (which mutates
    ``non_response_processor.processed`` at line ~10405 in
    blockchain.py), then call ``_restore_memory_snapshot`` and assert
    the evidence_hash is gone from the dedup set.

    Pre-fix the dedup entry survives the rollback — the snapshot
    omitted the field — so a later honest resubmission of the same
    evidence is silently dropped at the dedup gate
    (``non_response_evidence.py:463``).
    """

    def setUp(self):
        self.post_fork = NON_RESPONSE_EVIDENCE_BLOCK_SLOT_HEIGHT
        self.proposer = Entity.create(b"nrr-prop".ljust(32, b"\x00"))
        self.target = Entity.create(b"nrr-tgt".ljust(32, b"\x00"))
        self.client = Entity.create(b"nrr-cli".ljust(32, b"\x00"))
        self.submitter = Entity.create(b"nrr-sub".ljust(32, b"\x00"))
        for e in (
            self.proposer, self.target, self.client, self.submitter,
        ):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.target)
        register_entity_for_test(self.chain, self.client)
        register_entity_for_test(self.chain, self.submitter)
        # Offender stake — both buckets so the slash is observable.
        self.chain.supply.balances[self.target.entity_id] = 10_000_000
        self.chain.supply.balances[self.submitter.entity_id] = 10_000_000
        self.chain.supply.staked[self.target.entity_id] = 300_000
        self.chain.supply.pending_unstakes[self.target.entity_id] = [
            (700_000, 99_999),
        ]
        self.chain.slash_offense_counts[self.target.entity_id] = 2
        self.witnesses = [
            Entity.create(
                (b"nrr-w-" + str(i).encode()).ljust(32, b"\x00"),
            )
            for i in range(WITNESS_QUORUM)
        ]
        for w in self.witnesses:
            w.keypair._next_leaf = 0
            register_entity_for_test(self.chain, w)
            self.chain.supply.staked[w.entity_id] = 1_000_000

    def _signed_evidence(self, observed_height: int):
        req = sign_submission_request(
            submitter=self.client,
            target_validator_id=self.target.entity_id,
            tx_hash=_h(b"nrr-target-tx"),
            timestamp=int(time.time()),
            client_nonce=b"\x42" * 16,
            fee=MIN_FEE + WITNESS_SURCHARGE,
        )
        observations = [
            sign_witness_observation(
                w, req.request_hash, observed_height=observed_height,
            )
            for w in self.witnesses
        ]
        return sign_non_response_evidence(
            submitter=self.submitter,
            request=req,
            observations=observations,
            timestamp=int(time.time()),
            fee=MIN_FEE,
        )

    def test_apply_bump_does_not_leak_past_restore(self):
        """Snapshot, apply (bumps processor.processed), restore, then
        check the evidence_hash is gone from the dedup set.  This is
        the exact rollback path the bad-state-root branch takes at
        ``blockchain.py:12072``."""
        etx = self._signed_evidence(
            observed_height=self.post_fork - 50,
        )
        blk = _make_block(
            self.proposer, self.post_fork,
            self.chain.get_latest_block().block_hash,
            non_response_evidence_txs=[etx],
        )
        with _force_chain_height(self.chain, self.post_fork):
            snapshot = self.chain._snapshot_memory_state()
            self.chain._apply_block_state(blk)
            # Confirm the apply path actually bumped the dedup set —
            # otherwise the test would be trivially green for the
            # wrong reason.
            self.assertIn(
                etx.evidence_hash,
                self.chain.non_response_processor.processed,
                "Pre-condition: apply path must mutate "
                "non_response_processor.processed when an NRE is "
                "admitted; otherwise the test cannot exercise the "
                "rollback bug.",
            )
            self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            etx.evidence_hash,
            self.chain.non_response_processor.processed,
            "After _restore_memory_snapshot, the NRE evidence_hash "
            "MUST be gone from the processor's dedup set.  Pre-fix "
            "the hash survives the rollback because the snapshot "
            "omitted the collection — a coerced validator can poison "
            "this gate by crafting a bad-state-root block carrying "
            "the evidence, and the offender then escapes slashing "
            "when an honest peer later resubmits.",
        )


if __name__ == "__main__":
    unittest.main()
