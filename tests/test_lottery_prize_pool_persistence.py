"""
Tests for `SupplyTracker.lottery_prize_pool` persistence across
cold restart.

Before the fix, `self.supply.lottery_prize_pool` was purely
in-memory: accumulated inline at every REDIST-era divestment
block, drained inline at every LOTTERY_INTERVAL firing, carried
through the checkpoint-sync blob but NEVER mirrored into chaindb.
`_load_from_db` left it at 0 on every cold start.

The pool drives `pool_payout = pool / remaining_firings` at the
LOTTERY_INTERVAL winner selection -- `supply.balances[winner] +=
total_bounty` and `supply.lottery_prize_pool -= pool_payout`.  On
a cold-restarted peer during the divestment window:

  * uprestarted peers: pool = N, pool_payout = N/R, winner gets
    bounty + N/R, pool -= N/R.
  * restarted peer: pool = 0, pool_payout = 0, winner gets bounty
    only, pool stays 0.

`supply.balances[winner]` and `supply.lottery_prize_pool` diverge
→ state_root at the next block mismatches → restarted peer forks
off the honest chain.  Sixth in the cold-restart persistence class
after pending_unstakes / key_history / reputation /
blocks_since_last_finalization / stake_snapshots.

Activates at `SEED_DIVESTMENT_REDIST_HEIGHT = 74,000` -- still in
runway, fix lands before the fork window opens.
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


class TestLotteryPrizePoolTable(unittest.TestCase):
    """Direct ChainDB round-trip -- the scalar survives reopen."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_default_zero_when_unset(self):
        path = self._fresh_chaindb()
        db = ChainDB(path)
        self.assertEqual(db.get_lottery_prize_pool(), 0)
        _close_chaindb(db)

    def test_set_and_read_back(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        db1.set_lottery_prize_pool(123_456)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_lottery_prize_pool(), 123_456)
        _close_chaindb(db2)

    def test_set_is_upsert(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        db1.set_lottery_prize_pool(100)
        db1.set_lottery_prize_pool(500)
        db1.set_lottery_prize_pool(0)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_lottery_prize_pool(), 0)
        _close_chaindb(db2)


class TestBlockchainHelperMirrorsToDB(unittest.TestCase):
    """`_set_lottery_prize_pool` must mirror every mutation into the
    chaindb row so a cold reopen sees the current value."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_helper_mirrors_to_db(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)

        chain._set_lottery_prize_pool(42_000)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_lottery_prize_pool(), 42_000)
        _close_chaindb(db2)

    def test_helper_keeps_memory_and_db_in_lockstep(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)

        chain._set_lottery_prize_pool(1_000)
        self.assertEqual(chain.supply.lottery_prize_pool, 1_000)

        # Simulate an accumulate step (REDIST-era divestment).
        chain._set_lottery_prize_pool(
            chain.supply.lottery_prize_pool + 500,
        )
        self.assertEqual(chain.supply.lottery_prize_pool, 1_500)

        # Simulate a drain step (LOTTERY_INTERVAL firing).
        chain._set_lottery_prize_pool(
            chain.supply.lottery_prize_pool - 300,
        )
        self.assertEqual(chain.supply.lottery_prize_pool, 1_200)

        db1.flush_state()

        db2 = ChainDB(path)
        self.assertEqual(db2.get_lottery_prize_pool(), 1_200)
        _close_chaindb(db1)
        _close_chaindb(db2)


class TestColdRestartPreservesLotteryPool(unittest.TestCase):
    """End-to-end: after a cold restart during the divestment
    window, both peers must compute the same `pool_payout` for the
    same `remaining_firings` input -- without persistence the
    restarted peer pays 0, uprestarted peers pay pool/R,
    `supply.balances[winner]` diverges."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_restart_preserves_pool_and_payout(self):
        path = self._fresh_chaindb()

        # Node A: accumulates pool across a few divestment blocks.
        db_a = ChainDB(path)
        chain_a = Blockchain(db=db_a)
        chain_a._set_lottery_prize_pool(
            chain_a.supply.lottery_prize_pool + 10_000,
        )
        chain_a._set_lottery_prize_pool(
            chain_a.supply.lottery_prize_pool + 7_500,
        )
        chain_a._set_lottery_prize_pool(
            chain_a.supply.lottery_prize_pool + 2_500,
        )
        pool_value = chain_a.supply.lottery_prize_pool
        self.assertEqual(pool_value, 20_000)
        db_a.flush_state()
        _close_chaindb(db_a)

        # Node B: cold-restart from the same DB.  Manually drive the
        # rehydrate step the way `_load_from_db` would once a block
        # has been persisted.
        db_b = ChainDB(path)
        chain_b = Blockchain(db=db_b)
        chain_b.supply.lottery_prize_pool = db_b.get_lottery_prize_pool()

        self.assertEqual(
            chain_b.supply.lottery_prize_pool, pool_value,
            "Cold-restart peer's lottery pool does not match the "
            "uprestarted peer's -- next LOTTERY_INTERVAL firing "
            "would pay a different bounty and diverge "
            "supply.balances[winner].",
        )

        # Compute the same pool_payout the drain site would, on both
        # peers, and confirm they match byte-for-byte.
        remaining_firings = 10
        payout_a = chain_a.supply.lottery_prize_pool // remaining_firings
        payout_b = chain_b.supply.lottery_prize_pool // remaining_firings
        self.assertEqual(payout_b, payout_a)
        self.assertGreater(payout_b, 0)
        _close_chaindb(db_b)


if __name__ == "__main__":
    unittest.main()
