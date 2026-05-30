"""Mainnet wedge at h=3000 (2026-05-30) -- the root cause is a
code bug in 1.96.0's post-activation propose-side state_root path,
NOT state divergence between validators.

Symptom on live mainnet at h=3000 (ACCUMULATOR_COMMITMENT_HEIGHT):
Both validators throw the IDENTICAL traceback every block-production
attempt, every 10 minutes for ~28 hours:

    File ".../blockchain.py", line 6298,
        in _compute_post_state_root_via_real_apply
        self._apply_block_state(block)
    File ".../blockchain.py", line 14809, in _apply_block_state
        self._apply_archive_duty(block)
    File ".../blockchain.py", line 15261, in _apply_archive_duty
        block.block_hash, height, k=ARCHIVE_CHALLENGE_K,
    AttributeError: 'types.SimpleNamespace' object has no attribute
        'block_hash'

Diagnosis:
  * Post-``ACCUMULATOR_COMMITMENT_HEIGHT``, ``compute_post_state_root_
    for_block`` routes through ``_compute_post_state_root_via_real_apply``
    (the snapshot-apply-rollback dry-run).
  * The propose-side ``block`` is a ``BlockDraft`` (a
    ``types.SimpleNamespace``) WITHOUT a ``block_hash`` attribute --
    block_hash commits to header.state_root which the dry-run is
    computing, so it can't be set yet.
  * ``_apply_block_state`` -> ``_apply_archive_duty`` reads
    ``block.block_hash`` to seed ``compute_challenges()`` -- the
    archive-challenge-block snapshot.
  * Crash -> propose_block raises -> block production loop logs ERROR
    -> no new blocks proposed -> chain wedged.

The wedge only fires when h is BOTH post-activation AND a challenge
block (``h % ARCHIVE_CHALLENGE_INTERVAL == 0 and h > 0``).  At
h=3000 mainnet, both conditions hold simultaneously.

The existing ``test_end_to_end_activation_chain_advances`` lowered
``ACCUMULATOR_COMMITMENT_HEIGHT = 1`` and proposed h=1,2,3 -- none
of which are challenge blocks (1,2,3 % 100 != 0) -- so the bug
slipped through pre-deployment testing.  This test closes that gap.

Fix: provide ``block.block_hash`` as a deterministic placeholder
when missing.  The seed lands in ``archive_active_snapshot``, which
is NOT in ``_COMMITTED_FIELDS`` -- so the placeholder doesn't
affect state_root.  Live apply uses the real block_hash; the
in-memory snapshot it creates is canonical (the dry-run's
placeholder snapshot is rolled back).

CLAUDE.md anchors at risk:
  * Permanence -- mainnet is wedged, no new messages can land.
  * Security principle #1 -- a code bug that halts the entire
    chain is a worst-class regression.
  * Operator-recovery -- without a hotfix, validators run forever
    in the failed-propose loop.
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
    TREASURY_ALLOCATION,
    TREASURY_ENTITY_ID,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class ProposeOnPostActivationChallengeBlock(unittest.TestCase):
    """The exact mainnet failure: a block whose height is BOTH post-
    activation AND ``h % ARCHIVE_CHALLENGE_INTERVAL == 0``.  Before
    the fix, ``propose_block`` raises ``AttributeError``.
    """

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"audit-r60-mainnet-wedge-fix-test",
            tree_height=4,
        )

    def setUp(self):
        # Save every constant we touch so failures don't leak into
        # other tests (the suite runs xdist-parallel; a leaked
        # ACCUMULATOR_COMMITMENT_HEIGHT=1 would silently alter
        # downstream state-root behaviour in other test modules).
        self._saved = {
            "ACCUMULATOR_COMMITMENT_HEIGHT": _cfg.ACCUMULATOR_COMMITMENT_HEIGHT,
            "ARCHIVE_CHALLENGE_INTERVAL": _cfg.ARCHIVE_CHALLENGE_INTERVAL,
            "_MAINNET_FOUNDER_ENTITY_ID": _cfg._MAINNET_FOUNDER_ENTITY_ID,
            "PINNED_GENESIS_HASH": getattr(_cfg, "PINNED_GENESIS_HASH", None),
            "_MAINNET_GENESIS_HASH": getattr(_cfg, "_MAINNET_GENESIS_HASH", None),
        }

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(_cfg, k, v)

    def test_propose_post_activation_challenge_block_does_not_raise(self):
        """The smoking-gun mainnet repro, minimised.  With
        ACCUMULATOR_COMMITMENT_HEIGHT=1 and ARCHIVE_CHALLENGE_INTERVAL=2,
        block height 2 is BOTH post-activation AND a challenge block --
        exactly the conjunction that wedged mainnet at h=3000.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 1
        _cfg.ARCHIVE_CHALLENGE_INTERVAL = 2
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_wedge_")
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
        _cfg.PINNED_GENESIS_HASH = chain.chain[0].block_hash
        _cfg._MAINNET_GENESIS_HASH = chain.chain[0].block_hash
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        try:
            # Block 1: post-activation but NOT a challenge block
            # (1 % 2 == 1).  This block should propose+apply cleanly
            # regardless of the fix -- it exercises the dry-run path
            # WITHOUT hitting the missing-attr crash.
            proposer = pick_selected_proposer(chain, [self.founder])
            blk1 = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk1)
            self.assertTrue(
                ok,
                f"h=1 (post-activation, non-challenge) failed: "
                f"{reason}",
            )

            # Block 2: post-activation AND a challenge block
            # (2 % 2 == 0).  Pre-fix: AttributeError on
            # block.block_hash during dry-run.  Post-fix: clean
            # propose, clean apply, identical state_root agreement
            # propose-side vs apply-side.
            proposer = pick_selected_proposer(chain, [self.founder])
            blk2 = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk2)
            self.assertTrue(
                ok,
                f"h=2 (post-activation challenge block) failed to "
                f"add: {reason}.  If propose_block raised "
                f"AttributeError on block.block_hash, the mainnet "
                f"wedge regression has reappeared -- the "
                f"_compute_post_state_root_via_real_apply path "
                f"must provide a placeholder for missing top-level "
                f"block attributes the dry-run apply reads.",
            )
        finally:
            _close(db)

    def test_propose_advances_through_multiple_challenge_blocks(self):
        """Belt-and-suspenders: walk a few challenge blocks in a row
        to confirm the snapshot lifecycle (capture -> hold -> close
        -> next capture) survives the dry-run + rollback discipline.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 1
        _cfg.ARCHIVE_CHALLENGE_INTERVAL = 2
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_wedge_multi_")
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
        _cfg.PINNED_GENESIS_HASH = chain.chain[0].block_hash
        _cfg._MAINNET_GENESIS_HASH = chain.chain[0].block_hash
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        try:
            # Walk h=1..6 -- with INTERVAL=2 that covers 3 challenge
            # blocks (h=2,4,6) and exercises the dry-run path at
            # every one.
            for n in range(1, 7):
                proposer = pick_selected_proposer(chain, [self.founder])
                blk = chain.propose_block(consensus, proposer, [])
                ok, reason = chain.add_block(blk)
                self.assertTrue(
                    ok,
                    f"h={n} failed: {reason}.  Multi-challenge "
                    f"propose+apply path is broken at h={n}.",
                )
                # chain.height = len(self.chain): genesis (h=0)
                # contributes 1, so after appending block #n we
                # have height == n + 1.
                self.assertEqual(chain.height, n + 1)
        finally:
            _close(db)


if __name__ == "__main__":
    unittest.main()
