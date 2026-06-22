"""The FinalityTracker prune must NOT change the state_root.

This is the invariant the coordinated-hard-fork prune relies on.  The
state_root is computed in ``_append_block`` AFTER ``_apply_block_state``
but BEFORE ``_process_attestations`` (the only consumer of the prunable
attestation maps).  ``_apply_block_state`` reads the block's in-block
attestations, ``supply.staked`` and ``blocks_since_last_finalization`` --
never the FinalityTracker's accumulated ``attestations`` /
``_attestation_objects`` maps.  The tracker only influences state via
``_process_attestations`` -> a finalization decision that resets
``blocks_since_last_finalization``; and a finalization decision only
flips when attested stake crosses 2/3 of a still-accumulating target,
which the prune (bounded at the stake-pin horizon) never touches.

A read-only probe on the real mainnet chain.db (h=5357) confirmed this
empirically: pruning 2333 -> 104 attestation entries left the computed
state_root byte-identical.  These tests pin it in CI so two nodes that
prune at the same activation height stay in consensus.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

import messagechain.config as _cfg
from messagechain.config import (
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from messagechain.consensus.attestation import create_attestation
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _close(db):
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class _Pin:
    @classmethod
    def _install(cls, eid):
        cls._saved = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    @classmethod
    def _restore(cls):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = cls._saved


class TestPruneDoesNotChangeStateRoot(_Pin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"prune-stateroot-invariant-founder",
            tree_height=5,
        )
        cls.attester = Entity.create(
            private_key=b"prune-stateroot-invariant-attester",
            tree_height=5,
        )

    def _build(self):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        tmp = tempfile.mkdtemp(prefix="mc_prune_sr_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db = ChainDB(os.path.join(tmp, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id, stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        for _ in range(8):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, reason)
        return chain, db, consensus

    def _populate_tracker(self, chain):
        # Seed the FinalityTracker with attestations across many heights
        # so that a prune actually removes a large chunk of data (mirrors
        # the mainnet condition where the tracker held thousands of
        # attestation objects).
        pks = {self.attester.entity_id: self.attester.keypair.public_key}
        for h in range(1, chain.height + 1):
            bh = h.to_bytes(32, "big")
            chain.finality.add_attestation(
                create_attestation(self.attester, bh, h),
                validator_stake=1, total_stake=1_000_000,
                public_keys=pks, min_validator_count=99,  # never finalizes
            )

    def test_compute_state_root_unchanged_by_prune(self):
        self._install(self.founder.entity_id)
        try:
            chain, db, _ = self._build()
            self._populate_tracker(chain)
            objs_before = len(chain.finality._attestation_objects)
            root_before = chain.compute_current_state_root()

            chain.finality.prune(chain.height - 2)  # drop most of it

            objs_after = len(chain.finality._attestation_objects)
            root_after = chain.compute_current_state_root()

            self.assertLess(
                objs_after, objs_before,
                "test precondition: prune must actually remove entries",
            )
            self.assertEqual(
                root_before, root_after,
                "pruning the FinalityTracker MUST NOT change the "
                "state_root -- this invariant is what makes the "
                "coordinated prune consensus-safe",
            )
            _close(db)
        finally:
            self._restore()

    def test_block_apply_state_root_independent_of_prune(self):
        """A pruned node and an unpruned node applying the SAME block
        compute the SAME post-apply state_root (no `Invalid state_root`)."""
        from tests import pick_selected_proposer

        self._install(self.founder.entity_id)
        try:
            chain, db, consensus = self._build()
            self._populate_tracker(chain)

            # Produce the next block from the UNPRUNED chain.
            proposer = pick_selected_proposer(chain, [self.founder])
            nxt = chain.propose_block(consensus, proposer, [])
            unpruned_root = nxt.header.state_root

            # Now prune this same chain's tracker hard, and re-derive the
            # post-apply state_root for the very same block.  If the apply
            # path read the (now-pruned) tracker, the roots would differ
            # and add_block would reject with a state-commitment mismatch.
            chain.finality.prune(chain.height - 2)
            ok, reason = chain.add_block(nxt)
            self.assertTrue(
                ok,
                f"pruned chain rejected an unpruned-built block: {reason} "
                "-- the apply path must not depend on pruned tracker data",
            )
            self.assertEqual(
                chain.chain[-1].header.state_root, unpruned_root,
                "post-apply state_root must match regardless of prune",
            )
            _close(db)
        finally:
            self._restore()


if __name__ == "__main__":
    unittest.main()
