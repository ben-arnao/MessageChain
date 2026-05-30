"""Mainnet wedge follow-up (2026-05-30): cold-load integrity
check fires a phantom state_root mismatch when chain tip lies on
the activation-height boundary minus one.

Root cause: ``compute_current_state_root`` gates the
accumulator-commitment (Phase 3) and reaction-state (Tier 17)
contributions on ``self.height`` -- but ``self.height ==
len(self.chain)`` has TWO different meanings:

  * At apply-time of block #N (block not yet appended):
    ``self.height == N`` -> gate fires at ``N >= ACTIVATION``,
    correct for block #N's commit decision.
  * At cold-load with chain.db containing blocks 0..N (block
    already appended): ``self.height == N + 1`` -> gate fires
    ONE BLOCK EARLIER than it should when verifying block #N's
    stored header.state_root.

Mainnet at h=2999 (tip): chain.db has blocks 0..2999, self.height
becomes 3000 after cold-load, the gate fires (3000 >= 3000) and
INCLUDES the accumulator commitment in the computed root.  Block
#2999's header committed WITHOUT the commitment (block_number=2999
< 3000), so the integrity check sees a state_root mismatch.  No
underlying state drift -- a pure off-by-one in the gate height.

Fix: ``compute_current_state_root(as_of_block=...)`` lets the
cold-load integrity check pin the gate to
``latest_block.header.block_number`` -- the same value the
apply-time gate used when this header was minted.  Apply-time
and propose-time callsites keep the default (``self.height``)
because at those points ``self.height ==
block_number_being_committed``.

CLAUDE.md anchors at risk:
  * Permanence -- if cold-load can't recover the chain, the
    chain is effectively pruned to the running process's
    memory.
  * Honest-operator insurance -- a phantom integrity failure
    blocks legitimate restarts (validator reboots, hardware
    migration, upgrade smoke tests).
  * Hard-fork minimization -- the 1.96.0 activation should have
    been one event; instead the chain wedged into a state that
    no clean restart can recover from without this fix.
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


class ColdLoadGateOnActivationBoundary(unittest.TestCase):
    """Cold-load of a chain whose tip lies on the
    ``activation_height - 1`` boundary must NOT raise
    ``ChainIntegrityError`` -- the gate-height off-by-one is a
    false positive, not real drift.
    """

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"audit-r60-cold-load-gate-off-by-one",
            tree_height=4,
        )

    def setUp(self):
        self._saved = {
            "ACCUMULATOR_COMMITMENT_HEIGHT": _cfg.ACCUMULATOR_COMMITMENT_HEIGHT,
            "_MAINNET_FOUNDER_ENTITY_ID": _cfg._MAINNET_FOUNDER_ENTITY_ID,
            "PINNED_GENESIS_HASH": getattr(_cfg, "PINNED_GENESIS_HASH", None),
            "_MAINNET_GENESIS_HASH": getattr(_cfg, "_MAINNET_GENESIS_HASH", None),
        }

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(_cfg, k, v)

    def test_cold_load_at_activation_height_minus_one_does_not_wedge(self):
        """Build a chain whose latest block_number == ACTIVATION - 1.
        Close + re-open chain.db.  Cold-load must succeed.

        Pre-fix mainnet repro: ACCUMULATOR_COMMITMENT_HEIGHT=3000,
        chain.db tip=#2999, cold-load failed with state_root mismatch
        because compute_current_state_root used self.height=3000 to
        gate the commitment-mix while block #2999's stored header
        was minted at gate-height 2999.

        We exercise the same shape with ACCUMULATOR_COMMITMENT_HEIGHT
        set to a small value so the test cost stays bounded.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        # ACCUMULATOR_COMMITMENT_HEIGHT = 3 puts the activation at
        # block #3.  We'll mint blocks 1 and 2 (so the tip is #2,
        # one block before activation), then cold-load.  This is
        # the exact "tip lies on activation_height - 1" shape that
        # wedged mainnet.
        _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 3
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_coldgate_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, "chain.db")

        # Mint phase: build a chain whose latest block_number is
        # ACTIVATION - 1.  Persist to chain.db, then close.
        db = ChainDB(db_path)
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
        # Mint blocks 1 + 2.  Activation is at 3, so both blocks
        # are pre-activation -- their state_roots commit WITHOUT
        # the accumulator commitment.
        for _ in range(2):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"mint failed: {reason}")
        self.assertEqual(
            chain.chain[-1].header.block_number, 2,
            "Setup invariant: tip block_number must be "
            "ACTIVATION - 1 (= 2).",
        )
        _close(db)

        # Cold-load phase: re-open the chain.db with a fresh
        # Blockchain instance.  The integrity check inside
        # _load_from_db calls compute_current_state_root() and
        # compares to latest_block.header.state_root.
        #
        # Pre-fix: self.height == len(chain) == 3 == ACTIVATION
        # -> gate fires -> commitment INCLUDED -> mismatch ->
        # ChainIntegrityError -> chain wedged.
        # Post-fix: gate uses as_of_block = latest.block_number
        # = 2 < 3 -> commitment EXCLUDED -> matches header ->
        # cold-load succeeds.
        db2 = ChainDB(db_path)
        try:
            chain2 = Blockchain(db=db2)
            # Re-opening at all is the assertion: if the integrity
            # check raises, __init__ never returns.  Belt-and-
            # suspenders: confirm height + latest block_number.
            self.assertEqual(chain2.height, 3)
            self.assertEqual(
                chain2.chain[-1].header.block_number, 2,
            )
        finally:
            _close(db2)

    def test_cold_load_well_past_activation_still_works(self):
        """Belt-and-suspenders: chain whose tip lies well PAST
        the activation boundary still cold-loads cleanly.  The
        off-by-one fix doesn't accidentally break the
        post-activation common path.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        # Tip at block #5; activation at block #3 -- 2 blocks
        # past activation.
        _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 3
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_coldgate_past_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, "chain.db")

        db = ChainDB(db_path)
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
        for _ in range(5):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"mint failed: {reason}")
        self.assertEqual(chain.chain[-1].header.block_number, 5)
        _close(db)

        db2 = ChainDB(db_path)
        try:
            chain2 = Blockchain(db=db2)
            self.assertEqual(chain2.height, 6)
            self.assertEqual(
                chain2.chain[-1].header.block_number, 5,
            )
        finally:
            _close(db2)


if __name__ == "__main__":
    unittest.main()
