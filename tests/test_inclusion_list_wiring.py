"""Inclusion-list processor wiring — block-apply integration.

The audit (round 13) found that `InclusionListProcessor.register /
observe_block / expire / process_inclusion_list_violation` had ZERO
non-test call sites in the apply path.  A perfectly valid
`InclusionListViolationEvidenceTx` could land in a block body and the
chain would never act on it — the colluding cohort's expected on-chain
cost of suppression was zero.

This test locks in the wiring:

  1. A block carrying an `InclusionList` causes the processor to
     `register(...)` it.
  2. Each applied block triggers `processor.observe_block(block)` so
     inclusions/proposers are recorded.
  3. At the end of each block apply, `processor.expire(height)` runs.
  4. An `InclusionListViolationEvidenceTx` in a block, after a
     state-dependent gate (list active at accused_height, accused
     proposer matches recorded proposer-by-height, omitted_tx_hash not
     in `inclusions_seen`), invokes `process_inclusion_list_violation`
     and slashes the colluding proposer.

The slashing severity itself is owned by `compute_violation_slash_amount`
(= INCLUSION_VIOLATION_SLASH_BPS of stake — flat).  This test does not
exercise the honest-operator-insurance escalating curve; per CLAUDE.md
that's the slashing-curve PR's concern.  TODO: when the graduated curve
lands, extend this test to assert escalation.
"""

from __future__ import annotations

import hashlib
import time
import unittest
from types import SimpleNamespace

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    INCLUSION_LIST_WAIT_BLOCKS, INCLUSION_LIST_WINDOW,
    INCLUSION_VIOLATION_SLASH_BPS,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    InclusionListProcessor,
    InclusionListViolationEvidenceTx,
    build_attester_mempool_report,
    aggregate_inclusion_list,
    compute_violation_slash_amount,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_attesters(n: int, tag: bytes) -> list[Entity]:
    return [
        Entity.create((tag + b"-att" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _sign_violation_evidence(
    submitter: Entity,
    inclusion_list: InclusionList,
    omitted_tx_hash: bytes,
    accused_proposer_id: bytes,
    accused_height: int,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> InclusionListViolationEvidenceTx:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = InclusionListViolationEvidenceTx(
        inclusion_list=inclusion_list,
        omitted_tx_hash=omitted_tx_hash,
        accused_proposer_id=accused_proposer_id,
        accused_height=accused_height,
        submitter_id=submitter.entity_id,
        timestamp=ts,
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def _make_stub_block(
    *,
    block_number: int,
    proposer_id: bytes,
    inclusion_list=None,
    inclusion_list_violation_evidence_txs=None,
    transactions=None,
    transfer_transactions=None,
):
    """Minimal stand-in block that exercises only the inclusion-list
    wiring slots inside `_apply_block_state`.

    All fields touched by the apply path get sensible defaults so the
    apply loop runs cleanly past the wiring under test.  Fields the
    wiring DOESN'T read (validator_signatures, attestations, etc.) are
    left as empty containers / None.
    """
    return SimpleNamespace(
        header=SimpleNamespace(
            block_number=block_number,
            proposer_id=proposer_id,
            proposer_signature=None,
            prev_hash=b"\x00" * 32,
            state_root=b"\x00" * 32,
        ),
        # Stable-but-unique stub block_hash — some apply-path branches
        # (archive-challenge snapshot in particular) read it.  In an
        # xdist worker that has previously loaded a test which patched
        # ARCHIVE_CHALLENGE_INTERVAL down to a small value, our blocks
        # 2..N could land ON a challenge boundary and the apply path
        # would fault on a missing block_hash without this field.
        block_hash=hashlib.new(
            HASH_ALGO,
            b"wiring-test-stub-block-" + str(block_number).encode(),
        ).digest(),
        transactions=list(transactions or []),
        transfer_transactions=list(transfer_transactions or []),
        slash_transactions=[],
        attestations=[],
        validator_signatures=[],
        governance_txs=[],
        authority_txs=[],
        stake_transactions=[],
        unstake_transactions=[],
        finality_votes=[],
        custody_proofs=[],
        censorship_evidence_txs=[],
        bogus_rejection_evidence_txs=[],
        inclusion_list_violation_evidence_txs=list(
            inclusion_list_violation_evidence_txs or []
        ),
        react_transactions=[],
        archive_proof_bundle=None,
        inclusion_list=inclusion_list,
        acks_observed_this_block=[],
    )


class TestInclusionListProcessorWiringInBlockApply(unittest.TestCase):
    """End-to-end: drive `_apply_block_state` with stub blocks and
    assert the InclusionListProcessor's lifecycle hooks fire.
    """

    def setUp(self):
        from messagechain.core.blockchain import Blockchain

        # Three attester entities whose signed mempool reports back the
        # InclusionList's quorum.
        self.attesters = _make_attesters(3, b"wir")
        # Submitter of the violation evidence tx.
        self.submitter = Entity.create(b"wir-sub".ljust(32, b"\x00"))
        # Accused proposer — the colluding actor that omits the
        # mandated tx during the forward window.
        self.accused = Entity.create(b"wir-acc".ljust(32, b"\x00"))

        # Reset key counters so the test is hermetic against module-level
        # entity reuse on a shared xdist worker.
        self.submitter.keypair._next_leaf = 0
        self.accused.keypair._next_leaf = 0
        for a in self.attesters:
            a.keypair._next_leaf = 0

        self.chain = Blockchain()
        # Genesis is the submitter — gives them a balance & pubkey.
        self.chain.initialize_genesis(self.submitter)
        for a in self.attesters:
            register_entity_for_test(self.chain, a)
        register_entity_for_test(self.chain, self.accused)

        # Fund accounts and stake the attesters (so their mempool
        # reports have non-zero weight in the quorum-check) plus the
        # accused proposer (so there's stake to slash).
        self.chain.supply.balances[self.submitter.entity_id] = 10_000_000
        self.chain.supply.balances[self.accused.entity_id] = 10_000_000
        self.chain.supply.staked[self.accused.entity_id] = 1_000_000
        for a in self.attesters:
            self.chain.supply.balances[a.entity_id] = 10_000_000
            self.chain.supply.staked[a.entity_id] = 1_000_000

        # The omitted-tx hash the accused proposer suppresses.
        self.target_tx = _h(b"wir-target-tx")

        # Build a quorum-backed InclusionList published at block N.
        self.publish_height = self.chain.height + 1
        reports = [
            build_attester_mempool_report(
                a,
                report_height=self.publish_height - 1,
                tx_hashes=[self.target_tx],
            )
            for a in self.attesters
        ]
        stakes = {a.entity_id: 1_000_000 for a in self.attesters}
        self.inclusion_list = aggregate_inclusion_list(
            reports=reports,
            stakes=stakes,
            publish_height=self.publish_height,
        )
        # Sanity: the aggregate must include our target tx.
        self.assertTrue(
            any(
                e.tx_hash == self.target_tx
                for e in self.inclusion_list.entries
            ),
            "test setup: aggregated inclusion list must contain target tx",
        )

    # ── Helpers ─────────────────────────────────────────────────────

    def _apply_stub_block(self, block):
        """Drive the apply path far enough to exercise the inclusion-
        list wiring without requiring full block validation.  Direct
        call into `_apply_block_state` is the same entry point reorg
        replay uses.
        """
        self.chain._apply_block_state(block)

    # ── Tests ───────────────────────────────────────────────────────

    def test_register_fires_on_block_carrying_inclusion_list(self):
        """A block carrying an InclusionList must call
        `processor.register(...)`.  Pre-wiring this assertion fails —
        `active_lists` stays empty no matter how many lists land."""
        proc = self.chain.inclusion_list_processor
        self.assertEqual(proc.active_lists, {})

        block = _make_stub_block(
            block_number=self.publish_height,
            proposer_id=self.submitter.entity_id,
            inclusion_list=self.inclusion_list,
        )
        self._apply_stub_block(block)

        self.assertIn(
            self.publish_height, proc.active_lists,
            "Block carrying an InclusionList must register it on the "
            "processor — wiring missing.",
        )
        self.assertEqual(
            proc.active_lists[self.publish_height].list_hash,
            self.inclusion_list.list_hash,
        )

    def test_observe_block_records_proposer_for_active_list(self):
        """Each applied block within an active list's window must
        record (proposer_id, included tx_hashes) via `observe_block`.
        The colluding proposer's omission shows up as the absence of
        an `inclusions_seen` entry for the target tx."""
        proc = self.chain.inclusion_list_processor

        # Block N: publish the list (proposer = submitter, honest).
        publish_block = _make_stub_block(
            block_number=self.publish_height,
            proposer_id=self.submitter.entity_id,
            inclusion_list=self.inclusion_list,
        )
        self._apply_stub_block(publish_block)

        # Block N+1: accused proposer's slot.  They omit the listed tx.
        accused_height = self.publish_height + 1
        accused_block = _make_stub_block(
            block_number=accused_height,
            proposer_id=self.accused.entity_id,
            transactions=[],  # OMITS target_tx
            transfer_transactions=[],
        )
        self._apply_stub_block(accused_block)

        # observe_block must have recorded the accused proposer for
        # the active list at accused_height.
        self.assertIn(
            self.inclusion_list.list_hash,
            proc.proposers_by_height,
            "observe_block must populate proposers_by_height[list_hash]",
        )
        self.assertEqual(
            proc.proposers_by_height[self.inclusion_list.list_hash].get(
                accused_height,
            ),
            self.accused.entity_id,
            "Recorded proposer for accused_height must be the accused",
        )
        # The target tx was NOT included; inclusions_seen must be empty
        # for (list_hash, target_tx).
        self.assertEqual(
            proc.inclusions_seen.get(
                (self.inclusion_list.list_hash, self.target_tx), [],
            ),
            [],
            "An omission must leave inclusions_seen empty for the tx",
        )

    def test_violation_evidence_in_block_slashes_colluding_proposer(self):
        """The headline test: a colluding proposer omits a list-mandated
        tx; an `InclusionListViolationEvidenceTx` lands in a later
        block; the apply path runs the state-dependent gate and slashes
        the proposer.

        Pre-wiring this fails — the evidence tx is dropped silently and
        the accused proposer's stake is unchanged.
        """
        proc = self.chain.inclusion_list_processor

        # Block N: publish the list.
        publish_block = _make_stub_block(
            block_number=self.publish_height,
            proposer_id=self.submitter.entity_id,
            inclusion_list=self.inclusion_list,
        )
        self._apply_stub_block(publish_block)

        # Block N+1..N+window: accused proposer signs every block in
        # the window.  None of them include the target tx — total
        # collusion across the whole window.
        accused_height = self.publish_height + 1
        for h in range(
            self.publish_height + 1,
            self.publish_height + 1 + INCLUSION_LIST_WINDOW,
        ):
            blk = _make_stub_block(
                block_number=h,
                proposer_id=self.accused.entity_id,
            )
            self._apply_stub_block(blk)

        # Stake snapshot just before the evidence-bearing block.
        stake_before = self.chain.supply.staked[self.accused.entity_id]
        burned_before = self.chain.supply.total_burned
        self.assertGreater(stake_before, 0, "test setup: accused must have stake")
        self.assertNotIn(
            (
                self.inclusion_list.list_hash,
                self.target_tx,
                self.accused.entity_id,
            ),
            proc.processed_violations,
            "Pre-evidence: violation must not yet be processed",
        )

        # Build the evidence tx and put it in the next block.  It
        # accuses the proposer at accused_height (the first in-window
        # block, where proposers_by_height did record them).
        etx = _sign_violation_evidence(
            self.submitter,
            self.inclusion_list,
            self.target_tx,
            accused_proposer_id=self.accused.entity_id,
            accused_height=accused_height,
        )
        # Submitter needs to sit at a sane leaf-watermark — feed leaf
        # 0 since this is their first signature in the test.
        self.chain.leaf_watermarks[self.submitter.entity_id] = 0

        evidence_block = _make_stub_block(
            block_number=self.publish_height + 1 + INCLUSION_LIST_WINDOW,
            proposer_id=self.submitter.entity_id,
            inclusion_list_violation_evidence_txs=[etx],
        )
        self._apply_stub_block(evidence_block)

        stake_after = self.chain.supply.staked[self.accused.entity_id]
        burned_after = self.chain.supply.total_burned
        expected_slash = compute_violation_slash_amount(stake_before)

        self.assertEqual(
            stake_before - stake_after, expected_slash,
            f"Accused proposer must be slashed "
            f"INCLUSION_VIOLATION_SLASH_BPS ({INCLUSION_VIOLATION_SLASH_BPS}bps) "
            f"of stake — wiring missing.",
        )
        self.assertGreaterEqual(
            burned_after - burned_before, expected_slash,
            "Slashed stake must be burned (no finder reward).",
        )
        self.assertIn(
            (
                self.inclusion_list.list_hash,
                self.target_tx,
                self.accused.entity_id,
            ),
            proc.processed_violations,
            "processed_violations must record the (list, tx, proposer) "
            "triple once the slash applies (double-slash defence).",
        )

    def test_evidence_for_unrecorded_proposer_is_not_slashed(self):
        """State-dependent gate: an evidence tx accusing someone the
        chain never recorded as proposing at `accused_height` MUST NOT
        slash.  This catches forged evidence that names an innocent
        bystander.
        """
        proc = self.chain.inclusion_list_processor

        # Publish the list and run an in-window block by SOMEONE ELSE
        # (the submitter, not the accused).  proposers_by_height for
        # the accused stays empty.
        publish_block = _make_stub_block(
            block_number=self.publish_height,
            proposer_id=self.submitter.entity_id,
            inclusion_list=self.inclusion_list,
        )
        self._apply_stub_block(publish_block)
        for h in range(
            self.publish_height + 1,
            self.publish_height + 1 + INCLUSION_LIST_WINDOW,
        ):
            blk = _make_stub_block(
                block_number=h,
                proposer_id=self.submitter.entity_id,
            )
            self._apply_stub_block(blk)

        stake_before = self.chain.supply.staked[self.accused.entity_id]
        # Forged evidence: names accused at a height where the accused
        # never proposed.
        accused_height = self.publish_height + 1
        forged_etx = _sign_violation_evidence(
            self.submitter,
            self.inclusion_list,
            self.target_tx,
            accused_proposer_id=self.accused.entity_id,
            accused_height=accused_height,
        )
        self.chain.leaf_watermarks[self.submitter.entity_id] = 0
        evidence_block = _make_stub_block(
            block_number=self.publish_height + 1 + INCLUSION_LIST_WINDOW,
            proposer_id=self.submitter.entity_id,
            inclusion_list_violation_evidence_txs=[forged_etx],
        )
        self._apply_stub_block(evidence_block)

        stake_after = self.chain.supply.staked[self.accused.entity_id]
        self.assertEqual(
            stake_before, stake_after,
            "Forged evidence (accused never proposed at that height) "
            "must NOT slash — state-dependent gate must reject it.",
        )
        self.assertNotIn(
            (
                self.inclusion_list.list_hash,
                self.target_tx,
                self.accused.entity_id,
            ),
            proc.processed_violations,
            "Refused evidence must not pollute processed_violations.",
        )

    def test_evidence_for_included_tx_is_not_slashed(self):
        """State-dependent gate: if the listed tx actually landed
        on-chain in the window, the proposer did NOT censor — even an
        otherwise-well-formed evidence tx must be rejected.

        We seed `inclusions_seen` directly (rather than threading a
        synthetic message-tx through the apply path that would also
        invoke fee accounting on a stub).  observe_block writes the
        same shape on real-tx inclusion.
        """
        proc = self.chain.inclusion_list_processor

        publish_block = _make_stub_block(
            block_number=self.publish_height,
            proposer_id=self.submitter.entity_id,
            inclusion_list=self.inclusion_list,
        )
        self._apply_stub_block(publish_block)

        # Accused proposes a block in-window — record their proposer
        # slot for the gate check.
        accused_height = self.publish_height + 1
        accused_block = _make_stub_block(
            block_number=accused_height,
            proposer_id=self.accused.entity_id,
        )
        self._apply_stub_block(accused_block)
        # Simulate the tx landing later in the window: write the same
        # entry observe_block would have written.  This is the
        # state-dependent fact the gate must consult.
        proc.inclusions_seen.setdefault(
            (self.inclusion_list.list_hash, self.target_tx), [],
        ).append(accused_height + 1)
        # Run remaining in-window blocks (any proposer is fine).
        for h in range(
            accused_height + 1,
            self.publish_height + 1 + INCLUSION_LIST_WINDOW,
        ):
            blk = _make_stub_block(
                block_number=h, proposer_id=self.submitter.entity_id,
            )
            self._apply_stub_block(blk)

        stake_before = self.chain.supply.staked[self.accused.entity_id]
        etx = _sign_violation_evidence(
            self.submitter,
            self.inclusion_list,
            self.target_tx,
            accused_proposer_id=self.accused.entity_id,
            accused_height=accused_height,
        )
        self.chain.leaf_watermarks[self.submitter.entity_id] = 0
        evidence_block = _make_stub_block(
            block_number=self.publish_height + 1 + INCLUSION_LIST_WINDOW,
            proposer_id=self.submitter.entity_id,
            inclusion_list_violation_evidence_txs=[etx],
        )
        self._apply_stub_block(evidence_block)

        self.assertEqual(
            self.chain.supply.staked[self.accused.entity_id], stake_before,
            "Tx WAS included → no censorship → no slash, regardless of "
            "evidence-tx surface form.",
        )
        self.assertNotIn(
            (
                self.inclusion_list.list_hash,
                self.target_tx,
                self.accused.entity_id,
            ),
            proc.processed_violations,
        )


if __name__ == "__main__":
    unittest.main()
