"""Critical-severity audit fixes — 2026-04-25.

Two CRITICAL issues identified by the consensus + storage audit:

1. `block.inclusion_list.quorum_attestation` was never verified by the
   block-validation path.  A malicious proposer could attach a forged
   list (claiming a tx_hash supermajority that no honest attester ever
   reported) and the coverage-leak path would burn honest validators'
   stake based on the lie.  Fix: validate the list against the live
   stake/pubkey snapshot before accepting the block.

2. `Blockchain._append_block` issued four chain-write helpers
   (`store_block`, `remove_chain_tip`, `add_chain_tip`, `_persist_state`)
   without an enclosing `begin_transaction` scope.  Because each helper
   commits independently, a SIGKILL between any two of them left the
   chain head pointing at block N while the persisted state was as-of
   N-1.  Genesis fixes this exact issue and even comments on it; the
   hot path lost the wrapper.  Fix: wrap the four calls in
   begin/commit/rollback.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest
from dataclasses import dataclass

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    INCLUSION_LIST_WINDOW,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.inclusion_list import (
    InclusionList,
    InclusionListEntry,
    aggregate_inclusion_list,
    build_attester_mempool_report,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_chain(num_validators: int = 3, with_db: bool = False):
    """Build a Blockchain with `num_validators` staked validators.

    Mirrors `_make_chain_with_validators` from test_block_production.py
    but optionally backs the chain with a real on-disk ChainDB so we
    can exercise the persistence path.
    """
    entities = [
        Entity.create(f"il-audit-v{i}".encode().ljust(32, b"\x00"))
        for i in range(num_validators)
    ]
    if with_db:
        tmpdir = tempfile.mkdtemp(prefix="mc-audit-")
        db = ChainDB(db_path=os.path.join(tmpdir, "chain.db"))
        chain = Blockchain(db=db)
    else:
        tmpdir = None
        chain = Blockchain()
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)

    consensus = ProofOfStake()
    for e in entities:
        chain.supply.balances[e.entity_id] = (
            chain.supply.balances.get(e.entity_id, 0) + 5000
        )
        chain.supply.stake(e.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[e.entity_id] = VALIDATOR_MIN_STAKE
    return chain, consensus, entities, tmpdir


@dataclass
class _StubBlock:
    """Minimal stand-in for Block — exercises only the inclusion-list
    quorum-verification gate, which reads `block.inclusion_list` and
    `block.header.block_number`."""
    inclusion_list: object
    block_number: int

    @property
    def header(self):
        return self

    # Header attribute access used by the validator
    @property
    def block_number_attr(self):
        return self.block_number


class _StubHeader:
    def __init__(self, block_number: int):
        self.block_number = block_number


class _StubBlockNS:
    def __init__(self, inclusion_list, block_number: int):
        self.inclusion_list = inclusion_list
        self.header = _StubHeader(block_number)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1: forged inclusion-list rejection
# ─────────────────────────────────────────────────────────────────────

class TestInclusionListQuorumGate(unittest.TestCase):
    """`_validate_inclusion_list_quorum` must reject blocks carrying a
    forged inclusion_list whose quorum_attestation does NOT actually
    back the listed entries.  Without the gate, a colluding proposer
    can grief-burn honest attesters' stake via the coverage-divergence
    leak.
    """

    def test_no_inclusion_list_passes(self):
        chain, _, _, _ = _make_chain(num_validators=1)
        block = _StubBlockNS(inclusion_list=None, block_number=10)
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertTrue(ok, reason)

    def test_empty_entries_passes(self):
        """A list with no entries carries no consensus signal — the
        leak path skips it, so the validator should too."""
        chain, _, _, _ = _make_chain(num_validators=1)
        empty = InclusionList(
            publish_height=10,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[],
            quorum_attestation=[],
        )
        block = _StubBlockNS(inclusion_list=empty, block_number=10)
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertTrue(ok, reason)

    def test_forged_quorum_is_rejected(self):
        """A list claiming an entry that NO report supports must fail."""
        chain, _, entities, _ = _make_chain(num_validators=3)
        publish_height = chain.height + 1

        forged = InclusionList(
            publish_height=publish_height,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=_h(b"never-reported"),
                first_seen_height=publish_height - 1,
            )],
            quorum_attestation=[],
        )
        block = _StubBlockNS(
            inclusion_list=forged, block_number=publish_height,
        )
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertFalse(
            ok,
            "Forged inclusion list must be rejected — without this "
            "gate, a colluding proposer can burn honest validators' "
            "stake via the coverage-divergence leak.",
        )
        self.assertIn("inclusion", reason.lower())

    def test_valid_quorum_is_accepted(self):
        chain, _, entities, _ = _make_chain(num_validators=3)
        publish_height = chain.height + 1
        target_tx = _h(b"genuine-tx")
        report_height = publish_height - 1
        reports = [
            build_attester_mempool_report(
                v, report_height=report_height, tx_hashes=[target_tx],
            )
            for v in entities
        ]
        stakes = {v.entity_id: VALIDATOR_MIN_STAKE for v in entities}
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes,
            publish_height=publish_height,
        )
        self.assertTrue(lst.entries, "test setup: list must be non-empty")
        block = _StubBlockNS(
            inclusion_list=lst, block_number=publish_height,
        )
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertTrue(ok, reason)

    def test_publish_height_must_match_block_number(self):
        """A list whose publish_height disagrees with the carrying
        block's height is structurally suspect — the leak's
        bookkeeping is keyed by block_number, so accepting a
        misaligned list lets the proposer mis-attribute coverage
        misses across slots."""
        chain, _, entities, _ = _make_chain(num_validators=3)
        target_tx = _h(b"misaligned-tx")
        wrong_publish = chain.height + 5
        reports = [
            build_attester_mempool_report(
                v, report_height=wrong_publish - 1, tx_hashes=[target_tx],
            )
            for v in entities
        ]
        stakes = {v.entity_id: VALIDATOR_MIN_STAKE for v in entities}
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes,
            publish_height=wrong_publish,
        )
        block = _StubBlockNS(
            inclusion_list=lst, block_number=chain.height + 1,
        )
        ok, reason = chain._validate_inclusion_list_quorum(block)
        self.assertFalse(ok)
        self.assertIn("publish_height", reason.lower())

    def test_forged_list_in_full_add_block_path_is_rejected(self):
        """End-to-end: a freshly-proposed block that an attacker
        decorates with a forged inclusion_list must be rejected by
        add_block.  Defense-in-depth — the merkle-root check (which
        notices the body changed) and the state-root check (which
        notices the leak's stake mutation) also fire on a naively-
        forged block, so we accept a rejection from any of those
        gates as long as the block does NOT land."""
        chain, consensus, entities, _ = _make_chain(num_validators=1)
        proposer = entities[0]
        block = chain.propose_block(consensus, proposer, [])
        height_before = chain.height

        forged = InclusionList(
            publish_height=block.header.block_number,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=_h(b"never-reported-e2e"),
                first_seen_height=block.header.block_number - 1,
            )],
            quorum_attestation=[],
        )
        block.inclusion_list = forged

        ok, _reason = chain.add_block(block)
        self.assertFalse(ok)
        self.assertEqual(
            chain.height, height_before,
            "Forged-list block must not land — chain tip must not advance.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2: atomic block-apply persistence
# ─────────────────────────────────────────────────────────────────────

class TestAppendBlockAtomicPersistence(unittest.TestCase):
    """`_append_block` must wrap its DB writes in a single transaction
    so a crash between `store_block` and `_persist_state` cannot leave
    the chain head pointing at block N while persisted state is N-1.
    """

    def test_db_writes_are_wrapped_in_a_single_transaction(self):
        """Spy on begin/commit + the four apply-path writes; assert all
        four sit inside a begin/commit pair."""
        chain, consensus, entities, tmpdir = _make_chain(
            num_validators=1, with_db=True,
        )
        try:
            db = chain.db
            calls: list[str] = []
            orig_begin = db.begin_transaction
            orig_commit = db.commit_transaction
            orig_rollback = db.rollback_transaction
            orig_store_block = db.store_block
            orig_remove_tip = db.remove_chain_tip
            orig_add_tip = db.add_chain_tip
            orig_persist = chain._persist_state

            def trace_begin():
                calls.append("BEGIN")
                return orig_begin()

            def trace_commit():
                calls.append("COMMIT")
                return orig_commit()

            def trace_rollback():
                calls.append("ROLLBACK")
                return orig_rollback()

            def trace_store(*a, **kw):
                calls.append("store_block")
                return orig_store_block(*a, **kw)

            def trace_remove(*a, **kw):
                calls.append("remove_chain_tip")
                return orig_remove_tip(*a, **kw)

            def trace_add(*a, **kw):
                calls.append("add_chain_tip")
                return orig_add_tip(*a, **kw)

            def trace_persist(*a, **kw):
                calls.append("_persist_state")
                return orig_persist(*a, **kw)

            db.begin_transaction = trace_begin
            db.commit_transaction = trace_commit
            db.rollback_transaction = trace_rollback
            db.store_block = trace_store
            db.remove_chain_tip = trace_remove
            db.add_chain_tip = trace_add
            chain._persist_state = trace_persist

            block = chain.propose_block(consensus, entities[0], [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)

            apply_writes = {
                "store_block", "remove_chain_tip",
                "add_chain_tip", "_persist_state",
            }
            apply_indices = [
                i for i, c in enumerate(calls) if c in apply_writes
            ]
            self.assertTrue(
                apply_indices,
                "test failed to capture any apply-path write",
            )
            first, last = apply_indices[0], apply_indices[-1]
            preceding_begins = [
                i for i in range(first) if calls[i] == "BEGIN"
            ]
            self.assertTrue(
                preceding_begins,
                f"No BEGIN observed before apply-path writes; "
                f"call sequence: {calls}",
            )
            following_commits = [
                i for i in range(last, len(calls)) if calls[i] == "COMMIT"
            ]
            self.assertTrue(
                following_commits,
                f"No COMMIT observed after apply-path writes; "
                f"call sequence: {calls}",
            )
            self.assertNotIn(
                "ROLLBACK", calls,
                "Successful add_block must not roll back",
            )
        finally:
            try:
                chain.db.close()
            except Exception:
                pass
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def test_persist_state_failure_rolls_back_chain_tip(self):
        """If `_persist_state` raises mid-apply, the chain tip in the
        DB must NOT advance to the failed block.  Without the wrapping
        transaction, the tip would already have committed by the time
        _persist_state ran, leaving on-disk state inconsistent with
        the chain head."""
        chain, consensus, entities, tmpdir = _make_chain(
            num_validators=1, with_db=True,
        )
        try:
            db = chain.db
            block = chain.propose_block(consensus, entities[0], [])
            parent_tip = block.header.prev_hash

            def boom(*a, **kw):
                raise RuntimeError("simulated mid-apply crash")
            chain._persist_state = boom

            with self.assertRaises(RuntimeError):
                chain.add_block(block)

            db_path = db.db_path
            chain.db.close()
            db2 = ChainDB(db_path=db_path)
            try:
                tips = db2.get_all_tips()
                tip_hashes = {t[0] for t in tips}
                self.assertIn(
                    parent_tip, tip_hashes,
                    f"Parent tip {parent_tip.hex()[:16]} must remain after "
                    f"a rolled-back apply; got tips {[t.hex()[:16] for t in tip_hashes]}",
                )
                self.assertNotIn(
                    block.block_hash, tip_hashes,
                    "Failed block must not leave its hash as a chain tip.",
                )
            finally:
                db2.close()
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
