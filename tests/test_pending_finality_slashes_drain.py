"""Regression: ``_pending_finality_slashes`` is a write-only accumulator.

``Blockchain._apply_block_state`` calls
``self.finalized_checkpoints.get_pending_slashing_evidence()`` and
appends the result into ``self._pending_finality_slashes`` -- but no
caller in the entire codebase ever READ from that list (verified by
grep: 3 hits, all the write site at blockchain.py:8291-8293).
``FinalityDoubleVoteEvidence`` auto-detected at the FinalityVote layer
therefore accumulated forever and never produced a SlashTransaction,
so equivocators at the FinalityVote layer escaped slashing despite the
detection being fully wired.

This test pins:

  * ``Blockchain.drain_pending_finality_slashes()`` exists, returns
    pending evidence, and clears the queue.
  * Already-on-chain evidence (whose hash is in
    ``_processed_evidence``) is filtered out so a reorg replay does
    not re-emit a slash tx for an offence already applied.
  * The drain helper survives an empty queue (returns []).

Plus an integration assertion that the node-side post-block hook
wraps each drained evidence in a SlashTransaction signed by the
local entity and pushes it into the mempool, mirroring
``EquivocationWatcher._emit_slash``.
"""

import os
import tempfile
import unittest

from messagechain.config import TREASURY_ENTITY_ID
from messagechain.consensus.finality import (
    FinalityCheckpoints,
    FinalityDoubleVoteEvidence,
    FinalityVote,
)
from messagechain.consensus.slashing import SlashTransaction
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _placeholder_sig() -> Signature:
    return Signature([], 0, [], b"", b"")


def _make_vote(signer_id: bytes, target_hash: bytes, target_num: int) -> FinalityVote:
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=target_num,
        signature=_placeholder_sig(),
    )


def _make_double_vote_evidence() -> FinalityDoubleVoteEvidence:
    """Drive two conflicting votes through the real
    FinalityCheckpoints.add_vote path -- exercises the same
    auto-detection code the apply path runs.
    """
    cp = FinalityCheckpoints()
    signer = b"v1".ljust(32, b"\x00")
    cp.add_vote(
        _make_vote(signer, b"\x01" * 32, 7),
        signer_stake=100, total_stake_at_target=300,
    )
    cp.add_vote(
        _make_vote(signer, b"\x02" * 32, 7),
        signer_stake=100, total_stake_at_target=300,
    )
    pending = cp.get_pending_slashing_evidence()
    assert len(pending) == 1, (
        "FinalityCheckpoints.add_vote must auto-build evidence on "
        "conflicting same-signer same-height votes"
    )
    return pending[0]


class TestDrainPendingFinalitySlashes(unittest.TestCase):
    """Pure-logic tests on the Blockchain drain helper."""

    def setUp(self):
        self.bc = Blockchain()

    def test_drain_returns_empty_when_no_pending(self):
        self.assertEqual(self.bc.drain_pending_finality_slashes(), [])

    def test_drain_returns_and_clears(self):
        ev = _make_double_vote_evidence()
        # Mirror the apply path's append site (blockchain.py:8291-8293).
        self.bc._pending_finality_slashes = [ev]

        out = self.bc.drain_pending_finality_slashes()
        self.assertEqual(out, [ev])

        out2 = self.bc.drain_pending_finality_slashes()
        self.assertEqual(out2, [], "drain must clear the queue")

    def test_drain_filters_already_processed_evidence(self):
        ev = _make_double_vote_evidence()
        self.bc._pending_finality_slashes = [ev]
        # Already on-chain (e.g., a peer's slash tx was applied
        # before this node got around to draining).
        self.bc._processed_evidence.add(ev.evidence_hash)

        out = self.bc.drain_pending_finality_slashes()
        self.assertEqual(out, [], (
            "evidence already in _processed_evidence must be filtered "
            "out so reorg replay / peer-already-applied does not "
            "re-emit a slash tx for an offence already on chain"
        ))


class TestNodeEmitsPendingFinalitySlashes(unittest.TestCase):
    """End-to-end: drained evidence becomes a SlashTransaction in mempool."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-finality-drain-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)

        self.alice = Entity.create(b"alice-fdrain".ljust(32, b"\x00"))
        self.finder = Entity.create(b"finder-fdrain".ljust(32, b"\x00"))

        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.finder)
        self.chain.supply.balances[self.finder.entity_id] = 10_000

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_emit_helper_produces_slash_tx_in_mempool(self):
        ev = _make_double_vote_evidence()
        self.chain._pending_finality_slashes = [ev]

        captured = []

        class _MempoolStub:
            def add_slash_transaction(self, slash_tx):
                captured.append(slash_tx)
                return True

        mempool = _MempoolStub()

        # Drain hook is exposed as a module-level helper so it can be
        # tested without spinning a full Node.
        from messagechain.network.node import _emit_pending_finality_slashes
        _emit_pending_finality_slashes(
            blockchain=self.chain, entity=self.finder, mempool=mempool,
        )

        self.assertEqual(len(captured), 1, (
            "drained FinalityDoubleVoteEvidence must produce exactly "
            "one SlashTransaction in the mempool"
        ))
        self.assertIsInstance(captured[0], SlashTransaction)
        self.assertIsInstance(captured[0].evidence, FinalityDoubleVoteEvidence)
        self.assertEqual(
            captured[0].evidence.evidence_hash, ev.evidence_hash,
        )
        # Queue is now drained.
        self.assertEqual(self.chain.drain_pending_finality_slashes(), [])

    def test_emit_helper_no_op_without_entity(self):
        """Detect-only nodes (no submitter entity) must drain the
        queue but not crash.  Mirrors EquivocationWatcher.submitter_entity=None.
        """
        ev = _make_double_vote_evidence()
        self.chain._pending_finality_slashes = [ev]

        class _MempoolStub:
            def add_slash_transaction(self, slash_tx):
                raise AssertionError("must not be called without entity")

        from messagechain.network.node import _emit_pending_finality_slashes
        _emit_pending_finality_slashes(
            blockchain=self.chain, entity=None, mempool=_MempoolStub(),
        )

        # Without a submitter we cannot sign — leave the queue intact
        # so a future call with a submitter can drain it.
        remaining = self.chain.drain_pending_finality_slashes()
        self.assertEqual([e.evidence_hash for e in remaining], [ev.evidence_hash])


if __name__ == "__main__":
    unittest.main()
