"""``compute_post_state_root`` must mirror IL state mutations.

Anchors the audit-finding-1 invariant: any block carrying a non-empty
``inclusion_list`` or any ``inclusion_list_violation_evidence_txs`` must
not self-reject at the post-apply state_root commitment check.  The sim
in ``compute_post_state_root`` mirrors the apply path mutation-for-
mutation, including:

* ``process_inclusion_list_violation`` → drains accused proposer's
  ``staked`` by the slash amount, burns total_supply / total_burned.
* ``_apply_inclusion_list_coverage_leak`` → the per-attester quadratic
  stake drain when their AttesterMempoolReport in
  ``inclusion_list.quorum_attestation`` failed to cover any listed
  tx_hash.

If the sim does NOT mirror these, the proposer's committed
``state_root`` (via ``compute_post_state_root``) diverges from the
validator-side post-apply ``compute_current_state_root()`` → block
self-rejects with "Invalid state_root — state commitment mismatch."

Strategy: drive the canonical ``propose_block`` + ``add_block`` flow
with the new IL kwargs threaded through.  The same flow is used by
``test_compute_post_state_root_incremental`` for non-IL kinds; here we
extend the kwarg list with the audit-finding fields.
"""

from __future__ import annotations

import hashlib
import time
import unittest

from tests import register_entity_for_test, pick_selected_proposer
from messagechain.config import (
    HASH_ALGO,
    INCLUSION_LIST_WINDOW,
    MIN_FEE,
    COVERAGE_LEAK_ACTIVATION_MISSES,
    VALIDATOR_MIN_STAKE,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.inclusion_list import (
    InclusionListViolationEvidenceTx,
    aggregate_inclusion_list,
    build_attester_mempool_report,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _sign_violation_evidence(
    submitter,
    inclusion_list,
    omitted_tx_hash,
    accused_proposer_id,
    accused_height,
    fee=MIN_FEE,
    timestamp=None,
):
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


def _fresh_chain(num_validators=3):
    """Funded, staked chain with `num_validators` validators."""
    entities = [
        Entity.create(f"sr_val_{i}".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    from messagechain.core.blockchain import Blockchain
    chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)
    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 10_000_000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    chain._rebuild_state_tree()
    return chain, consensus, entities


class TestComputePostStateRootMirrorsInclusionList(unittest.TestCase):
    """compute_post_state_root must mirror apply for IL state mutations."""

    def test_compute_post_state_root_accepts_il_kwargs(self):
        """compute_post_state_root must accept the new IL kwargs
        without TypeError — the API shape requirement of the fix."""
        chain, _, entities = _fresh_chain(num_validators=2)
        proposer = entities[0]
        # Pre-fix this raises TypeError on the IL kwargs.
        chain.compute_post_state_root(
            transactions=[],
            proposer_id=proposer.entity_id,
            block_height=chain.height + 1,
            inclusion_list_violation_evidence_txs=[],
            inclusion_list=None,
            proposer_signature_leaf_index=proposer.keypair._next_leaf,
        )

    def test_block_with_inclusion_list_accepts(self):
        """A block carrying a non-empty inclusion_list must NOT
        self-reject at the state-root commitment check.

        Pre-fix: ``compute_post_state_root`` ignores the inclusion_list
        argument entirely → its ``sim_staked`` doesn't account for the
        coverage-leak drain on the missing attester → committed
        state_root != post-apply state_root → ``_append_block`` returns
        "Invalid state_root — state commitment mismatch."
        """
        # 5 validators so 4/5 = 80% > 2/3 quorum with 1 missing.
        chain, consensus, entities = _fresh_chain(num_validators=5)
        attesters = entities

        # Pre-load the missing attester's miss counter past the
        # activation threshold so the leak fires immediately.
        missing = attesters[4]
        chain.attester_coverage_misses[missing.entity_id] = (
            COVERAGE_LEAK_ACTIVATION_MISSES + 1
        )

        # Build a partial-quorum list: 4/5 attesters report, the 5th
        # is "missing" and accumulates a coverage miss.
        target_tx = _h(b"sr-cov-target")
        publish_height = chain.get_latest_block().header.block_number + 1
        partial_reports = [
            build_attester_mempool_report(
                a, report_height=publish_height - 1,
                tx_hashes=[target_tx],
            )
            for a in attesters[:4]
        ]
        stakes = {a.entity_id: VALIDATOR_MIN_STAKE for a in attesters[:4]}
        inclusion_list = aggregate_inclusion_list(
            reports=partial_reports, stakes=stakes,
            publish_height=publish_height,
        )

        proposer = pick_selected_proposer(chain, entities)
        block = chain.propose_block(
            consensus, proposer, [],
            inclusion_list=inclusion_list,
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(
            ok,
            f"add_block must accept a block with non-empty "
            f"inclusion_list — pre-fix the proposer's committed "
            f"state_root diverges from the validator-side computed "
            f"root because the sim doesn't mirror "
            f"_apply_inclusion_list_coverage_leak.  reason={reason}",
        )

    def test_block_with_il_violation_evidence_accepts(self):
        """A block carrying an InclusionListViolationEvidenceTx must
        NOT self-reject at the state-root commitment check.

        Pre-fix: the apply path slashes the accused proposer's stake,
        but the sim sees a fully-intact stake.  state_root divergence
        → block rejected.
        """
        chain, consensus, entities = _fresh_chain(num_validators=3)
        submitter = entities[0]
        accused = entities[1]
        attesters = entities

        # Build a quorum-backed inclusion list whose entries include a
        # target tx that the accused proposer will omit.
        target_tx = _h(b"sr-iv-target-tx")
        publish_height = chain.get_latest_block().header.block_number + 1
        reports = [
            build_attester_mempool_report(
                a, report_height=publish_height - 1,
                tx_hashes=[target_tx],
            )
            for a in attesters
        ]
        stakes = {a.entity_id: VALIDATOR_MIN_STAKE for a in attesters}
        inclusion_list = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=publish_height,
        )

        # Step 1: publish the list as a normal block.
        proposer = pick_selected_proposer(chain, entities)
        publish_block = chain.propose_block(
            consensus, proposer, [], inclusion_list=inclusion_list,
        )
        ok, reason = chain.add_block(publish_block)
        self.assertTrue(ok, f"publish-list block rejected: {reason}")

        # Step 2: drive a few in-window blocks so accused gets recorded
        # in proposers_by_height (a state-dependent gate the IL
        # violation evidence consults).
        warmup_blocks = min(INCLUSION_LIST_WINDOW, 3)
        for _ in range(warmup_blocks):
            p = pick_selected_proposer(chain, entities)
            blk = chain.propose_block(consensus, p, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"warm-up block rejected: {reason}")

        # If the accused was actually selected as proposer in any of
        # those blocks, the violation evidence has a recorded
        # accused_height to point at.  Pick the most recent block where
        # accused was the proposer; otherwise skip the slash assertion
        # path and just check the wiring accepts an evidence-bearing
        # block (the slash applies if the gate accepts).
        accused_height = None
        for blk in chain.chain[1:]:
            if blk.header.proposer_id == accused.entity_id:
                accused_height = blk.header.block_number
                break
        if accused_height is None:
            self.skipTest(
                "Accused was never selected as proposer in the "
                "warm-up window — re-roll selection seed."
            )

        # Step 3: build the violation evidence and propose a block
        # carrying it as inclusion_list_violation_evidence_txs.
        etx = _sign_violation_evidence(
            submitter,
            inclusion_list,
            target_tx,
            accused_proposer_id=accused.entity_id,
            accused_height=accused_height,
        )
        evidence_proposer = pick_selected_proposer(chain, entities)
        evidence_block = chain.propose_block(
            consensus, evidence_proposer, [],
            inclusion_list_violation_evidence_txs=[etx],
        )
        ok, reason = chain.add_block(evidence_block)
        self.assertTrue(
            ok,
            f"add_block must accept a block with "
            f"inclusion_list_violation_evidence_txs — pre-fix the "
            f"proposer's committed state_root diverges from the "
            f"validator-side computed root because the sim doesn't "
            f"mirror process_inclusion_list_violation's stake drain.  "
            f"reason={reason}",
        )


if __name__ == "__main__":
    unittest.main()
