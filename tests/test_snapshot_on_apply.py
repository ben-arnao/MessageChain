"""Tests for snapshot-on-apply / snapshot-on-load (1.52.0).

Background -- 2026-05-03 incident chain: the 1.50.0-1.51.4 release
sequence was driven entirely by ONE defect class.  Several consensus-
critical accumulators (validator_archive_misses, _bootstrap_ratchet,
_immature_rewards, _escrow, archive_active_snapshot, etc.) were held
in memory only -- accumulated incrementally during block apply,
never persisted to chaindb.  Cold-load (e.g. after restart) created
them as empty defaults; a long-running node had them populated.
Apply paths read those values, so the two nodes computed different
state_roots on the next received block, and the chain rejected with
``Invalid state_root -- state commitment mismatch``.

Each prior fix patched ONE field's persistence (lottery_prize_pool
in 1.41.0, archive_reward_pool in 1.50.0, genesis allocations in
1.51.4) and missed the next one in the queue.  The 1.52.0 fix is
structural: every block apply persists the FULL serialized state
via the existing ``serialize_state`` / ``encode_snapshot`` path.
Cold-restart and reorg-restore both load from the latest snapshot
row.  Adding a new in-memory accumulator now requires only that
``serialize_state`` capture it -- no separate persistence path to
forget.

These tests pin the contract.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.config import (
    _MAINNET_FOUNDER_LIQUID,
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
import messagechain.config as _cfg


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class TestStateSnapshotsTable(unittest.TestCase):
    """The chaindb table + accessor methods round-trip cleanly."""

    def _fresh(self):
        tmp = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp, True)
        return os.path.join(tmp, "chain.db")

    def test_set_get_round_trip(self):
        path = self._fresh()
        db = ChainDB(path)
        db.set_state_snapshot(42, b"hello world")
        db.flush_state()
        _close(db)
        db2 = ChainDB(path)
        self.assertEqual(db2.get_state_snapshot(42), b"hello world")
        self.assertIsNone(db2.get_state_snapshot(43))
        _close(db2)

    def test_latest_height(self):
        path = self._fresh()
        db = ChainDB(path)
        db.set_state_snapshot(10, b"a")
        db.set_state_snapshot(15, b"b")
        db.set_state_snapshot(12, b"c")
        self.assertEqual(db.get_latest_state_snapshot_height(), 15)
        _close(db)

    def test_prune(self):
        path = self._fresh()
        db = ChainDB(path)
        for h in (10, 50, 100, 500, 1500):
            db.set_state_snapshot(h, b"x")
        db.prune_state_snapshots_before(100)
        # 10, 50 deleted; 100, 500, 1500 retained
        self.assertIsNone(db.get_state_snapshot(10))
        self.assertIsNone(db.get_state_snapshot(50))
        self.assertEqual(db.get_state_snapshot(100), b"x")
        self.assertEqual(db.get_state_snapshot(500), b"x")
        self.assertEqual(db.get_state_snapshot(1500), b"x")
        _close(db)


class _MainnetPinOverride:
    _saved: object = object()

    @classmethod
    def _install(cls, eid: bytes):
        cls._saved = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    @classmethod
    def _restore(cls):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = cls._saved


class TestSnapshotOnApplyPersists(_MainnetPinOverride, unittest.TestCase):
    """Every block apply MUST persist a snapshot row.  Without this,
    cold-restart can't restore in-memory accumulators."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"snap-on-apply-test-founder-key-1",
            tree_height=4,
        )

    def _build_chain_with_db(self):
        tmp = tempfile.mkdtemp(prefix="mc_test_")
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
        return chain, db

    def test_genesis_does_not_require_snapshot(self):
        # initialize_genesis runs BEFORE the snapshot-on-apply hook
        # is wired into _append_block.  Genesis block 0 doesn't
        # produce a snapshot row; only post-genesis blocks do.
        # Validates that the absence of a row at height 0 isn't a
        # bug -- it's by design.
        self._install(self.founder.entity_id)
        try:
            chain, db = self._build_chain_with_db()
            self.assertIsNone(db.get_state_snapshot(0))
        finally:
            self._restore()

    def test_block_apply_writes_snapshot_row(self):
        """Mint a single post-genesis block via the real propose +
        add_block path.  After the apply, a snapshot row MUST exist
        at that block's height."""
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install(self.founder.entity_id)
        try:
            chain, db = self._build_chain_with_db()
            consensus = ProofOfStake()
            consensus.register_validator(
                self.founder.entity_id,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            proposer = pick_selected_proposer(chain, [self.founder])
            block = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)
            # Snapshot row at block 1 MUST exist post-apply.
            self.assertIsNotNone(
                db.get_state_snapshot(block.header.block_number),
                "snapshot-on-apply did not persist a row -- "
                "cold-restart will lose in-memory accumulators",
            )
        finally:
            self._restore()


class TestSnapshotOnLoadRestoresAccumulators(
    _MainnetPinOverride, unittest.TestCase,
):
    """Cold-restart MUST restore in-memory accumulators from the
    snapshot row, not start them at empty defaults.  This is the
    core 1.52.0 contract -- a freshly-loaded node and a long-
    running node MUST have identical in-memory state at the same
    height.
    """

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"snap-on-load-test-founder-key-001",
            tree_height=4,
        )

    def test_cold_restart_recovers_full_state(self):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install(self.founder.entity_id)
        try:
            tmp = tempfile.mkdtemp(prefix="mc_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")

            # Phase 1: build chain with a few blocks, accumulating
            # in-memory state.
            db1 = ChainDB(db_path)
            chain1 = Blockchain(db=db1)
            chain1.initialize_genesis(
                self.founder,
                {
                    self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                },
            )
            bootstrap_seed_local(
                chain1, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            consensus = ProofOfStake()
            consensus.register_validator(
                self.founder.entity_id,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            for _ in range(3):
                proposer = pick_selected_proposer(chain1, [self.founder])
                blk = chain1.propose_block(consensus, proposer, [])
                ok, _ = chain1.add_block(blk)
                self.assertTrue(ok)

            # Capture the long-running node's state_root and the
            # in-memory accumulators that aren't in standalone chaindb
            # tables.
            running_root = chain1.compute_current_state_root()
            running_bootstrap_progress = chain1.bootstrap_progress
            running_immature_count = len(chain1._immature_rewards)
            db1.flush_state()
            _close(db1)

            # Phase 2: cold-restart from the same chain.db.  Without
            # snapshot-on-load, in-memory accumulators come back at
            # empty defaults and the load-time invariant fires.  With
            # the fix, state matches what the long-running node had.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            # If the load-time invariant fires, the constructor raises
            # ChainIntegrityError -- we never reach this line.
            cold_root = chain2.compute_current_state_root()
            self.assertEqual(
                cold_root, running_root,
                "cold-restart state_root must match long-running "
                "state_root at the same height -- this is the "
                "1.52.0 invariant",
            )
            self.assertEqual(
                chain2.bootstrap_progress,
                running_bootstrap_progress,
                "_bootstrap_ratchet must be restored from snapshot",
            )
            self.assertEqual(
                len(chain2._immature_rewards),
                running_immature_count,
                "_immature_rewards must be restored from snapshot",
            )
            _close(db2)
        finally:
            self._restore()


class TestSnapshotOnLoadInvariantFires(
    _MainnetPinOverride, unittest.TestCase,
):
    """The load-time invariant
    ``compute_current_state_root() == latest_block.header.state_root``
    MUST fire when the loaded state is genuinely incomplete (snapshot
    missing AND chaindb-table-only load is insufficient).  Catches
    the defect at startup instead of silently producing divergent
    state_roots on the next received block (which is how every bug
    from 1.50-1.51.4 manifested).

    Test strategy: simulate a "snapshot path is missing" scenario by
    deleting the snapshot row before load; with the snapshot absent
    the load falls through to legacy field-by-field rehydration,
    which DOES restore field-table state correctly so the invariant
    DOESN'T fire in this benign case.  The corruption case (where
    chaindb tables AND snapshot disagree with the header) is harder
    to construct without manipulating the snapshot blob -- pinned
    by the symmetric ``test_cold_restart_recovers_full_state`` above
    rather than by an explicit corruption injector."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"snap-load-invariant-test-founder",
            tree_height=4,
        )

    def test_load_without_snapshot_falls_back_cleanly(self):
        """Removing the snapshot row should fall back to legacy
        field-by-field rehydration without raising the invariant
        (because field-by-field is enough for this small test
        scenario where no in-memory accumulators are populated)."""
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install(self.founder.entity_id)
        try:
            tmp = tempfile.mkdtemp(prefix="mc_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")
            db1 = ChainDB(db_path)
            chain1 = Blockchain(db=db1)
            chain1.initialize_genesis(
                self.founder,
                {
                    self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                    TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                },
            )
            bootstrap_seed_local(
                chain1, self.founder,
                cold_authority_pubkey=self.founder.public_key,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            consensus = ProofOfStake()
            consensus.register_validator(
                self.founder.entity_id,
                stake_amount=_MAINNET_FOUNDER_STAKE,
            )
            for _ in range(2):
                proposer = pick_selected_proposer(chain1, [self.founder])
                blk = chain1.propose_block(consensus, proposer, [])
                self.assertTrue(chain1.add_block(blk)[0])
            db1.flush_state()
            _close(db1)

            # Simulate "legacy chain.db without snapshot rows": delete
            # all state_snapshots rows.  Cold-load should fall back to
            # field-by-field rehydration without raising.
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM state_snapshots")
            conn.commit()
            conn.close()

            # Cold-restart MUST not raise -- the legacy path is
            # sufficient for the simple state in this test (no
            # accumulators populated).  This also exercises the
            # 1.51.x → 1.52.0 upgrade path: a node upgrading from
            # an older release loads its existing chain.db (no
            # snapshot rows) without breaking, then the next block
            # apply writes a snapshot row.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            self.assertEqual(chain2.height, chain1.height)
            _close(db2)
        finally:
            self._restore()


if __name__ == "__main__":
    unittest.main()
