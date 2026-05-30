"""Audit r60 latent issue D fix (2026-05-30) -- cold-load on a
post-activation chain must succeed.

Root cause: pre-1.97.1 ``_persist_state_snapshot`` was called at
the END of ``_append_block``, AFTER ``_process_attestations`` had
already mutated ``reputation`` (in ``_COMMITTED_FIELDS``).  Cold-
load restoring the snapshot ended up with POST-intermediate
accumulator values while ``header.state_root`` committed PRE-
intermediate values -- the integrity check ALWAYS failed for
post-activation chains where _process_attestations had bumped
any reputation values for tip's attestations.

This was the exact failure mode that prevented 1.97.0 deployment
to mainnet (validator-1 chain.db at h=3007 produced ``computed
167e1fd5 != header 6d09e991`` on both 1.96.3 and 1.97.0 binaries
because the bad snapshot was written by the same old code).

Two fixes in 1.97.1:
  1. Apply path captures the snapshot blob at commit-point (right
     after compute_current_state_root verified header.state_root)
     and DEFERS the write to the existing snapshot-point (atomic
     with the rest of the block-apply transaction).  NEW snapshots
     match header by construction.
  2. Cold-load adds a smart integrity check that subtracts tip's
     attestation reputation bumps before comparing -- handles
     EXISTING chain.db files with old-format snapshots so
     mainnet daemons can be upgraded without manual splice.

CLAUDE.md anchors at risk:
  * Permanence -- a chain that can't be cold-loaded is one
    process-restart away from total loss.
  * Honest-operator insurance -- the deepest "operator did
    nothing wrong but their node won't restart" failure mode.
  * Hard-fork minimization -- fix is structural (no consensus
    change) AND ships compatibility for existing chain.db.
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


class SnapshotCapturedAtCommitPoint(unittest.TestCase):
    """End-to-end: build a post-activation chain, close it, re-open
    it from cold -- cold-load integrity check MUST pass.
    """

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"audit-r60-snapshot-commit-point-test",
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

    def _build_and_close_post_activation_chain(
        self, db_path: str, n_blocks: int = 5,
    ) -> bytes:
        """Build n_blocks past the activation height, close chain.db.
        Returns the latest block's header.state_root for verification.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        _cfg.ACCUMULATOR_COMMITMENT_HEIGHT = 1
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

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
        for _ in range(n_blocks):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"mint failed: {reason}")
        latest_state_root = chain.chain[-1].header.state_root
        _close(db)
        return latest_state_root

    def test_cold_load_post_activation_chain_succeeds(self):
        """Build a 5-block post-activation chain with the
        1.97.1 apply path (captures snapshot at commit-point),
        then cold-load.  Integrity check MUST pass on the direct
        comparison (no smart rewind needed -- new snapshots are
        already in commit-point format).
        """
        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_snap_cp_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, "chain.db")

        expected_root = self._build_and_close_post_activation_chain(
            db_path, n_blocks=5,
        )

        # Cold-load with fresh Blockchain instance.  Pre-1.97.1
        # this raised ChainIntegrityError on any post-activation
        # chain because the snapshot was captured post-intermediate
        # while header.state_root committed pre-intermediate.
        db2 = ChainDB(db_path)
        try:
            chain2 = Blockchain(db=db2)
            # Confirm load succeeded + state matches header.
            self.assertEqual(chain2.chain[-1].header.state_root, expected_root)
            # The new commit-point snapshot makes the DIRECT
            # integrity check pass; smart-rewind isn't triggered.
            # Verify by recomputing state_root and comparing.
            actual = chain2.compute_current_state_root(
                as_of_block=chain2.chain[-1].header.block_number,
            )
            self.assertEqual(
                actual, expected_root,
                "Cold-load state_root MUST match header.state_root "
                "directly (no smart-rewind needed) when chain.db "
                "was written by 1.97.1+ apply path.",
            )
        finally:
            _close(db2)

    def test_smart_rewind_recovers_old_format_snapshot(self):
        """Simulate the EXISTING mainnet situation: chain.db
        contains a snapshot captured post-intermediate (legacy
        format).  Cold-load must use smart-rewind to bridge to
        the pre-intermediate state header.state_root expects.

        We construct the bad-format snapshot by:
          1. Building a chain normally (commit-point snapshots).
          2. AFTER load, manually bumping reputation for tip's
             attestations (simulating what old code's late
             _process_attestations did to the snapshot before
             writing).
          3. Re-writing the snapshot.
          4. Re-opening from cold.

        Smart-rewind must subtract the simulated bumps and match
        header.  Without the fix, cold-load fails.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_smart_rewind_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, "chain.db")

        expected_root = self._build_and_close_post_activation_chain(
            db_path, n_blocks=5,
        )

        # Reopen, simulate post-intermediate snapshot by bumping
        # reputation as old code would have AND re-writing snapshot.
        db_mid = ChainDB(db_path)
        chain_mid = Blockchain(db=db_mid)
        latest = chain_mid.chain[-1]
        # Apply what late _process_attestations would have done:
        # +1 reputation per attestation in tip block.
        attestations = getattr(latest, "attestations", []) or []
        for att in attestations:
            cur = chain_mid.reputation.get(att.validator_id, 0)
            chain_mid.reputation[att.validator_id] = cur + 1
        # Re-write snapshot in the bad (post-intermediate) format.
        chain_mid._persist_state_snapshot(latest.header.block_number)
        _close(db_mid)

        # Cold-load on the rewritten chain.db.  Must succeed via
        # smart-rewind -- the direct integrity check fails because
        # the snapshot is post-intermediate but header is pre-
        # intermediate; smart-rewind subtracts the simulated bumps
        # and produces header-matching state_root.
        db_cold = ChainDB(db_path)
        try:
            chain_cold = Blockchain(db=db_cold)
            self.assertEqual(
                chain_cold.chain[-1].header.state_root, expected_root,
            )
            # Daemon's warm state should be post-intermediate
            # (smart-rewind restores after the check).
            for att in attestations:
                self.assertGreaterEqual(
                    chain_cold.reputation.get(att.validator_id, 0),
                    1,
                    "Smart-rewind must leave warm state post-"
                    "intermediate so subsequent block apply uses "
                    "the same reputation values peers have.",
                )
        finally:
            _close(db_cold)


if __name__ == "__main__":
    unittest.main()
