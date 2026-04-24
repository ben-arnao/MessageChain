"""
Tests for `Blockchain._stake_snapshots` persistence across cold restart.

Before the fix, `self._stake_snapshots` was purely in-memory: per-
block pins populated by `_record_stake_snapshot` at every apply
but never mirrored into chaindb.  `_load_from_db` pinned a single
tip snapshot and relied on the "fall back to live stakes" branch
in `_process_attestations` and `_process_finality_votes` for any
target whose snapshot wasn't present.

`_stake_snapshots` is the authoritative 2/3-threshold denominator
for every attestation AND every FinalityVote processed by
`_apply_block_state`.  FinalityVotes can target a block up to
`FINALITY_VOTE_MAX_AGE_BLOCKS = 1000` slots back -- so every
cold restart loses the pins for those historical blocks and the
fallback computes the 2/3 check against a post-restart live stake
map that differs from the uprestarted peer's pinned denominator.
The `crossed` predicate diverges, `finalized_checkpoints` (the
long-range-attack ratchet) diverges, and the restarted peer
forks off the honest chain with no recovery path.

These tests prove the map round-trips through SQLite so a cold
restart produces byte-identical behaviour to an uprestarted peer.
"""

import os
import shutil
import tempfile
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB


def _close_chaindb(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class TestStakeSnapshotsTablePersists(unittest.TestCase):
    """Direct ChainDB round-trip - the nested (height → {eid: stake})
    map survives a reopen."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_single_snapshot_round_trip(self):
        path = self._fresh_chaindb()
        eid_a = b"a" * 32
        eid_b = b"b" * 32
        db1 = ChainDB(path)
        db1.add_stake_snapshot(42, {eid_a: 100, eid_b: 200})
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_stake_snapshots(),
            {42: {eid_a: 100, eid_b: 200}},
        )
        _close_chaindb(db2)

    def test_multi_block_round_trip(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32
        db1 = ChainDB(path)
        db1.add_stake_snapshot(10, {eid: 100})
        db1.add_stake_snapshot(20, {eid: 300})
        db1.add_stake_snapshot(15, {eid: 150})
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_stake_snapshots(),
            {10: {eid: 100}, 15: {eid: 150}, 20: {eid: 300}},
        )
        _close_chaindb(db2)

    def test_upsert_replaces(self):
        """A second `add_stake_snapshot` at the same block overwrites
        (matches the in-memory `= dict(self.supply.staked)` replace
        semantics)."""
        path = self._fresh_chaindb()
        eid = b"v" * 32
        db1 = ChainDB(path)
        db1.add_stake_snapshot(42, {eid: 100})
        db1.add_stake_snapshot(42, {eid: 999})
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_stake_snapshots(),
            {42: {eid: 999}},
        )
        _close_chaindb(db2)

    def test_prune_removes_old_rows(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32
        db1 = ChainDB(path)
        db1.add_stake_snapshot(10, {eid: 100})
        db1.add_stake_snapshot(100, {eid: 1000})
        db1.add_stake_snapshot(500, {eid: 5000})
        db1.prune_stake_snapshots_before(200)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_stake_snapshots(),
            {500: {eid: 5000}},
        )
        _close_chaindb(db2)


class TestBlockchainMirrorsSnapshotsToDB(unittest.TestCase):
    """`_record_stake_snapshot` must mirror every pin into the chaindb
    table so a cold reopen sees the same map."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_record_mirrors_to_db(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        eid = b"v" * 32

        chain.supply.staked[eid] = 5_000
        chain._record_stake_snapshot(100)
        chain.supply.staked[eid] = 5_500
        chain._record_stake_snapshot(101)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        persisted = db2.get_all_stake_snapshots()
        self.assertEqual(persisted.get(100), {eid: 5_000})
        self.assertEqual(persisted.get(101), {eid: 5_500})
        _close_chaindb(db2)


class TestColdRestartPreservesFinalityDenominator(unittest.TestCase):
    """End-to-end: after a cold restart the restarted peer's
    `_stake_snapshots` must match the uprestarted peer's for every
    pin within the FinalityVote age window, so the 2/3-threshold
    computation converges on the same `crossed` decision."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_restart_preserves_all_pins_within_window(self):
        path = self._fresh_chaindb()
        eid_a = b"a" * 32
        eid_b = b"b" * 32

        db_a = ChainDB(path)
        chain_a = Blockchain(db=db_a)
        # Populate snapshots across 50 blocks, with varying stake
        # distributions (simulating validator churn).  50 is well
        # under the FINALITY_VOTE_MAX_AGE_BLOCKS window so nothing
        # gets pruned.
        for block_number in range(1, 51):
            chain_a.supply.staked[eid_a] = 1000 + block_number
            chain_a.supply.staked[eid_b] = 2000 - block_number
            chain_a._record_stake_snapshot(block_number)
        db_a.flush_state()
        _close_chaindb(db_a)

        # Cold restart.  `_load_from_db` early-returns on empty
        # block count, so manually rehydrate the pins the way the
        # full load path would once a block has been persisted.
        db_b = ChainDB(path)
        chain_b = Blockchain(db=db_b)
        chain_b._stake_snapshots = db_b.get_all_stake_snapshots()

        # Every pin within the window must match byte-for-byte.
        self.assertEqual(chain_b._stake_snapshots, chain_a._stake_snapshots)

        # Spot-check: a FinalityVote targeting block 10 (40 blocks
        # before the tip) must resolve to identical stake maps on
        # both peers -- without the persistence, chain_b would
        # have only the tip pin and fall back to live stakes for
        # target=10, diverging the 2/3 denominator.
        target_block = 10
        pinned_a = chain_a._stake_snapshots.get(target_block)
        pinned_b = chain_b._stake_snapshots.get(target_block)
        self.assertIsNotNone(
            pinned_a,
            "Baseline: uprestarted peer must have pin for target "
            "block (population invariant)",
        )
        self.assertEqual(
            pinned_b, pinned_a,
            "Cold-restart peer is missing the historical pin for "
            "target block -- `_process_finality_votes` would fall "
            "back to live stakes and compute a different 2/3 "
            "denominator than the uprestarted peer, diverging the "
            "`crossed` decision and forking `finalized_checkpoints`.",
        )
        _close_chaindb(db_b)


if __name__ == "__main__":
    unittest.main()
