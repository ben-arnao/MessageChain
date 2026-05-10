"""Equivocation watchers must never emit a slash tx targeting their
own submitter entity.

Audit r41 #3 root cause (mainnet stall, 2026-05-10).  Surfaced after
1.70.4 still didn't unstick the chain: the actual slot-2199 wedge was
NOT downstream of Tier 59 (the inactivity-leak honesty-curve relief
multiplier divergence shipped in 1.70.3 / 1.70.4) but a separate
defect-class bug -- the watcher slashing the operator's OWN entity.

Concrete cascade observed at block 2199 on mainnet:

  1. v1's chaindb ``seen_signatures`` table holds v1's signature on
     a previous-attempt block #2199 (persisted by ``add_seen_
     signature`` from a prior failed propose-block attempt -- the
     sig was emitted, the block then failed to add for an unrelated
     reason, but the sig was already stored).
  2. v1 boots.  The proposer slot fires, builds a NEW block #2199.
     Slightly different content (timestamp drift, fresh block
     header) -> byte-different sig at the same (validator, height,
     round).
  3. Watcher.observe_block_header runs the new sig through
     ``_check_equivocation``, sees the stored prior-attempt sig,
     classifies the conflict as "equivocation".
  4. Watcher.``_emit_slash`` builds a SlashTransaction with
     ``offender_id = v1.entity_id`` and ``submitter_id =
     v1.entity_id`` (self-slash).
  5. Block #2199 candidate is built with the self-slash tx in the
     transactions list.
  6. add_block runs.  Sim and apply diverge on the self-slash apply
     (because the operator's stake is mutated by both the slash AND
     the proposer-side fee path; integer-rounding edge cases at
     "submitter == offender == proposer" produce a state delta sim
     does not predict).  ``Invalid state_root`` rejection.  Chain
     wedges.

CLAUDE.md anchor at risk: "honest operators are insured against
accidents" + "honest, well-configured nodes should rarely if ever
be slashed under normal operation."  An operator's own restart
cycle is the textbook "operational mishap" the anchor exists to
insulate.  Censorship-resistance is preserved: if a different
honest watcher genuinely sees us double-sign on the wire (vs.
observing our chaindb-replayed prior attempt), that watcher emits
the slash from THEIR submitter context and lands it on chain via
standard gossip.

Permanent fix: every watcher path that builds a slash tx (the
block-/attestation-equivocation path in
``EquivocationWatcher._emit_slash`` AND the finality-double-vote
drain ``_emit_pending_finality_slashes`` in
``messagechain.network.node``) must drop the slash if
``offender_id == self.submitter_entity.entity_id`` (or
``entity.entity_id`` in the drain case).

These tests pin the invariant.  Pre-fix both paths emit a slash tx
when the offender is the local node; post-fix they skip emission
and log a warning.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.equivocation_watcher import EquivocationWatcher
from messagechain.consensus.finality import (
    FinalityDoubleVoteEvidence,
    create_finality_vote,
)
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _make_signed_header(
    proposer_entity, prev_block, merkle_seed, t_offset=0.0,
):
    block_num = prev_block.header.block_number + 1
    header = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(merkle_seed),
        timestamp=time.time() + t_offset,
        proposer_id=proposer_entity.entity_id,
    )
    header.proposer_signature = proposer_entity.keypair.sign(
        _hash(header.signable_data())
    )
    return header


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-r41-no-self-slash-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)

        # The operator entity that runs the watcher.  This is the
        # ``submitter_entity`` for the watcher AND ALSO the proposer
        # whose chaindb stored signature triggers the self-equivocation.
        self.operator = Entity.create(
            b"operator-r41-self".ljust(32, b"\x00"),
        )

        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.operator,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.operator.entity_id: 10_000_000,
            },
        )
        # The operator must have stake so a slash tx targeting them
        # would not short-circuit on "offender has no stake to slash"
        # -- we want the test to force the watcher all the way through
        # to its slash-emit decision point.
        self.chain.supply.stake(
            self.operator.entity_id, VALIDATOR_MIN_STAKE,
        )

        self.mempool = Mempool()
        self.watcher = EquivocationWatcher(
            chaindb=self.db,
            blockchain=self.chain,
            mempool=self.mempool,
            submitter_entity=self.operator,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestNoSelfSlashOnBlockEquivocation(_Fixture):
    """Watcher MUST NOT emit a slash tx when the offender is the
    watcher's own submitter entity (self-equivocation triggered by
    the operator's own restart-cycle re-signing).
    """

    def test_self_block_equivocation_skipped(self):
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.operator, prev, b"A")
        header_b = _make_signed_header(
            self.operator, prev, b"B", t_offset=1.0,
        )
        self.assertEqual(header_a.block_number, header_b.block_number)
        self.assertNotEqual(
            header_a.signable_data(),
            header_b.signable_data(),
            "test setup: the two headers must differ for the watcher "
            "to fire its equivocation branch",
        )

        # First sighting: just records, no slash regardless of fix.
        self.watcher.observe_block_header(header_a)
        self.assertEqual(len(self.mempool.slash_pool), 0)

        # Second sighting at same height by the SAME operator.  Pre-
        # fix this fires _emit_slash with offender == submitter ==
        # operator and pools the slash.  Post-fix the self-slash
        # guard catches it and skips emission entirely.
        self.watcher.observe_block_header(header_b)
        self.assertEqual(
            len(self.mempool.slash_pool), 0,
            "Watcher must NOT pool a slash tx for self-equivocation "
            "(audit r41 #3 / CLAUDE.md honest-operator-insurance "
            "anchor).  An operator's own restart-cycle re-sign is an "
            "operational accident, not a slashable byzantine action.",
        )

    def test_other_validator_equivocation_still_slashed(self):
        """Symmetric guard: the no-self-slash invariant must NOT
        regress the canonical "OTHER validator equivocates" case.
        Censorship-resistance depends on watchers slashing genuine
        on-the-wire double-signers from non-self submitter contexts.
        """
        offender = Entity.create(
            b"offender-not-self".ljust(32, b"\x00"),
        )
        register_entity_for_test(self.chain, offender)
        self.chain.supply.balances[offender.entity_id] = 10_000
        self.chain.supply.stake(
            offender.entity_id, VALIDATOR_MIN_STAKE,
        )

        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(offender, prev, b"A")
        header_b = _make_signed_header(
            offender, prev, b"B", t_offset=1.0,
        )
        self.watcher.observe_block_header(header_a)
        self.watcher.observe_block_header(header_b)
        self.assertEqual(
            len(self.mempool.slash_pool), 1,
            "Watcher MUST emit a slash tx when a DIFFERENT validator "
            "equivocates -- the self-slash guard must not regress "
            "the canonical malicious-double-signer slash path that "
            "backs collective censorship resistance.",
        )


class TestNoSelfSlashOnFinalityDoubleVote(unittest.TestCase):
    """Companion guard for the finality-double-vote drain path
    (``_emit_pending_finality_slashes`` in ``messagechain/network/
    node.py``).  Same defect class -- a finality vote drained from
    the local pending queue whose offender is the local entity is
    the operator's own restart-cycle re-sign, not a malicious
    double-vote.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-r41-no-self-fv-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)
        self.operator = Entity.create(
            b"operator-r41-fv-self".ljust(32, b"\x00"),
        )
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.operator,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.operator.entity_id: 10_000_000,
            },
        )
        self.chain.supply.stake(
            self.operator.entity_id, VALIDATOR_MIN_STAKE,
        )
        self.mempool = Mempool()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_self_finality_double_vote_skipped(self):
        """A FinalityDoubleVoteEvidence whose offender equals the
        local entity must NOT result in a slash tx in the mempool.
        """
        from messagechain.network.node import (
            _emit_pending_finality_slashes,
        )
        signing_height = self.chain.height
        target_height = signing_height + 1
        vote_a = create_finality_vote(
            self.operator, b"A" * 32, target_height, signing_height,
        )
        vote_b = create_finality_vote(
            self.operator, b"B" * 32, target_height, signing_height,
        )
        evidence = FinalityDoubleVoteEvidence(
            offender_id=self.operator.entity_id,
            vote_a=vote_a,
            vote_b=vote_b,
        )
        self.chain._pending_finality_slashes = [evidence]

        _emit_pending_finality_slashes(
            blockchain=self.chain,
            entity=self.operator,
            mempool=self.mempool,
        )

        self.assertEqual(
            len(self.mempool.slash_pool), 0,
            "FinalityDoubleVote drain MUST NOT pool a slash tx for "
            "self-equivocation (audit r41 #3 / CLAUDE.md honest-"
            "operator-insurance anchor).  Other honest watchers will "
            "slash if the double-vote is genuinely byzantine.",
        )


if __name__ == "__main__":
    unittest.main()
