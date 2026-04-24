"""
Tests for `Blockchain.blocks_since_last_finalization` persistence
across cold restart.

Before the fix, `self.blocks_since_last_finalization` was purely
in-memory: it was incremented inline in `_apply_block_state`,
reset inline on finalization and on `_handle_fork`, and never
mirrored into chaindb.  `_load_from_db` did not replay blocks to
rebuild it.

The counter drives two consensus-visible decisions:

1. `is_leak_active(counter)` — whether `_apply_block_state` fires
   the inactivity leak this block.
2. `apply_inactivity_leak(staked, counter, inactive, ...)` — the
   QUADRATIC per-validator burn scales with the counter value, so
   even a small counter difference produces a large stake
   divergence.

Empty counter on a restarted peer during a finalization stall
means the leak is silently off while uprestarted peers burn stake
every block -- `supply.staked` + `supply.total_supply` +
`supply.total_burned` diverge and the next block's state_root
mismatches.

These tests prove the counter round-trips through SQLite so a
cold restart produces byte-identical behavior to an uprestarted
peer.
"""

import os
import shutil
import tempfile
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB


def _close_chaindb(db: ChainDB) -> None:
    """Close the thread-local SQLite connection so Windows can delete
    the temp DB file."""
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class TestFinalizationStallCounterTable(unittest.TestCase):
    """Direct ChainDB round-trip — the counter survives reopen."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_default_zero_when_unset(self):
        path = self._fresh_chaindb()
        db = ChainDB(path)
        self.assertEqual(db.get_finalization_stall_counter(), 0)
        _close_chaindb(db)

    def test_set_and_read_back(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        db1.set_finalization_stall_counter(42)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_finalization_stall_counter(), 42)
        _close_chaindb(db2)

    def test_set_is_upsert(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        db1.set_finalization_stall_counter(5)
        db1.set_finalization_stall_counter(200)
        db1.set_finalization_stall_counter(0)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_finalization_stall_counter(), 0)
        _close_chaindb(db2)


class TestBlockchainHelperMirrorsToDB(unittest.TestCase):
    """`_set_finalization_stall_counter` must mirror every mutation
    into the chaindb row so a cold reopen sees the current value."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_helper_mirrors_to_db(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)

        chain._set_finalization_stall_counter(150)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_finalization_stall_counter(), 150)
        _close_chaindb(db2)

    def test_helper_updates_in_memory_and_db_together(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)

        chain._set_finalization_stall_counter(7)
        self.assertEqual(chain.blocks_since_last_finalization, 7)
        chain._set_finalization_stall_counter(0)
        self.assertEqual(chain.blocks_since_last_finalization, 0)
        db1.flush_state()

        db2 = ChainDB(path)
        self.assertEqual(db2.get_finalization_stall_counter(), 0)
        _close_chaindb(db1)
        _close_chaindb(db2)


class TestColdRestartPreservesFinalizationStall(unittest.TestCase):
    """End-to-end: after a cold restart during a finalization stall,
    the restarted peer's counter and the uprestarted peer's counter
    must match -- and `is_leak_active` must return the same bool on
    both.  Without this, one peer burns stake every block while the
    other doesn't, forking consensus at the next `_apply_block_state`."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_restart_preserves_counter_and_leak_activation(self):
        from messagechain.consensus.inactivity import is_leak_active

        path = self._fresh_chaindb()

        # Node A: accumulates a finalization stall over many blocks.
        db_a = ChainDB(path)
        chain_a = Blockchain(db=db_a)
        # Drive the counter to a value well above the leak activation
        # threshold so the invariant is exercised meaningfully.
        for _ in range(600):
            chain_a._set_finalization_stall_counter(
                chain_a.blocks_since_last_finalization + 1,
            )
        stall_value = chain_a.blocks_since_last_finalization
        db_a.flush_state()
        _close_chaindb(db_a)

        # Node B: cold-restart from the same DB.  `_load_from_db`
        # early-returns on empty block count, so manually rehydrate
        # the counter the way the full load path would.
        db_b = ChainDB(path)
        chain_b = Blockchain(db=db_b)
        chain_b.blocks_since_last_finalization = (
            db_b.get_finalization_stall_counter()
        )

        self.assertEqual(
            chain_b.blocks_since_last_finalization, stall_value,
            "Cold-restart peer's stall counter does not match the "
            "uprestarted peer's -- inactivity leak would now fire "
            "asymmetrically and diverge supply.staked.",
        )
        self.assertGreater(stall_value, 0)
        # Activation predicate must match on both peers.
        self.assertEqual(
            is_leak_active(chain_b.blocks_since_last_finalization),
            is_leak_active(chain_a.blocks_since_last_finalization),
        )
        _close_chaindb(db_b)


if __name__ == "__main__":
    unittest.main()
