"""
Tests for pending-unstakes persistence across cold restart.

Before the fix, `SupplyTracker.pending_unstakes` lived purely in
Python memory and was never mirrored into chaindb.  A routine
`systemctl restart` or binary upgrade on one validator while others
stayed up would produce this divergence:

  * `staked` was persisted and reflected the unstake debit.
  * `pending_unstakes` was gone.
  * At the next `process_pending_unstakes(height)`, the restarted
    node released nothing; uprestarted peers released the real
    tokens.
  * Next block's `state_root` computed over `balances` disagreed on
    the unbonded amount.  The restarted node forked off the honest
    chain.

These tests prove the queue round-trips through SQLite so a cold
restart of one node produces the same release behavior as a peer
that never restarted.
"""

import os
import shutil
import tempfile
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB


def _close_chaindb(db: ChainDB) -> None:
    """Close the thread-local SQLite connection so Windows lets us
    delete the file.  ChainDB uses threading.local() for its conn,
    so close() is per-thread — fine because tests run single-threaded."""
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class TestPendingUnstakesPersistence(unittest.TestCase):
    def _fresh_chaindb(self):
        # Per-test tempdir avoids the Windows "file in use" error
        # NamedTemporaryFile triggers when SQLite still holds the fd.
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_add_pending_unstake_persists(self):
        """A single unstake ticket survives a ChainDB reopen."""
        path = self._fresh_chaindb()
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.add_pending_unstake(eid, amount=500, release_block=2176)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_pending_unstakes(),
            {eid: [(500, 2176)]},
        )
        _close_chaindb(db2)

    def test_multiple_tickets_per_entity_ordered_by_release_block(self):
        """Stacked unstakes for one entity round-trip in release-order."""
        path = self._fresh_chaindb()
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.add_pending_unstake(eid, amount=300, release_block=4000)
        db1.add_pending_unstake(eid, amount=100, release_block=2176)
        db1.add_pending_unstake(eid, amount=200, release_block=3000)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_pending_unstakes(),
            {eid: [(100, 2176), (200, 3000), (300, 4000)]},
        )
        _close_chaindb(db2)

    def test_clear_pending_unstake_persists(self):
        """Clearing one ticket doesn't regenerate it on reopen."""
        path = self._fresh_chaindb()
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.add_pending_unstake(eid, amount=100, release_block=2176)
        db1.add_pending_unstake(eid, amount=200, release_block=3000)
        db1.clear_pending_unstake(eid, release_block=2176)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_pending_unstakes(),
            {eid: [(200, 3000)]},
        )
        _close_chaindb(db2)

    def test_clear_all_pending_unstakes_persists(self):
        """Slash-all zeroes the queue and a reopen confirms."""
        path = self._fresh_chaindb()
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.add_pending_unstake(eid, amount=100, release_block=2176)
        db1.add_pending_unstake(eid, amount=200, release_block=3000)
        db1.clear_all_pending_unstakes(eid)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_all_pending_unstakes(), {})
        _close_chaindb(db2)


class TestSupplyTrackerMirrorsDB(unittest.TestCase):
    """When SupplyTracker has `db` attached, every mutation path mirrors
    into the SQL table so a cold reopen sees the same queue."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_unstake_mirrors_to_db(self):
        """SupplyTracker.unstake() writes to the pending_unstakes table."""
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        eid = b"v" * 32
        chain.supply.staked[eid] = 10_000

        ok = chain.supply.unstake(eid, amount=3_000, current_block=100)
        self.assertTrue(ok)
        chain.supply.db.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        persisted = db2.get_all_pending_unstakes()
        self.assertIn(eid, persisted)
        self.assertEqual(len(persisted[eid]), 1)
        amount, release_block = persisted[eid][0]
        self.assertEqual(amount, 3_000)
        self.assertGreater(release_block, 100)
        _close_chaindb(db2)

    def test_process_pending_unstakes_clears_db_rows(self):
        """Maturity-release removes the ticket from both memory and DB."""
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        eid = b"v" * 32
        chain.supply.staked[eid] = 10_000
        chain.supply.unstake(eid, amount=3_000, current_block=100)

        # Advance past the release block and mature the ticket.
        ticket = chain.supply.pending_unstakes[eid][0]
        release_block = ticket[1]
        chain.supply.process_pending_unstakes(release_block)
        chain.supply.db.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_all_pending_unstakes(), {})
        # And the release went to balances.
        self.assertEqual(chain.supply.get_balance(eid), 3_000)
        _close_chaindb(db2)

    def test_slash_validator_clears_db_rows(self):
        """slash_validator removes every outstanding ticket from DB."""
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        eid = b"v" * 32
        finder = b"f" * 32
        chain.supply.staked[eid] = 10_000
        chain.supply.unstake(eid, amount=3_000, current_block=100)
        chain.supply.unstake(eid, amount=2_000, current_block=101)

        chain.supply.slash_validator(eid, finder)
        chain.supply.db.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_all_pending_unstakes(), {})
        _close_chaindb(db2)


class TestColdRestartNoDivergence(unittest.TestCase):
    """End-to-end: two SupplyTracker instances sharing the same DB path
    must agree on pending_unstakes after a simulated cold restart.
    Before the fix, the restarted tracker started with an empty queue
    while the other still had the ticket — at the next maturity-release
    they would diverge on `balances`."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_restart_preserves_pending_unstake_queue(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32

        # Node A: queue an unstake.
        db_a = ChainDB(path)
        chain_a = Blockchain(db=db_a)
        chain_a.supply.staked[eid] = 10_000
        chain_a.supply.unstake(eid, amount=3_000, current_block=100)
        ticket = chain_a.supply.pending_unstakes[eid][0]
        release_block = ticket[1]
        chain_a.supply.db.flush_state()
        _close_chaindb(db_a)

        # Node B: cold-boot from the same DB (simulate restart).
        # _load_from_db early-returns on empty block DB (no genesis),
        # so explicitly re-hydrate pending_unstakes from the table —
        # matches what a real node does once its first block has been
        # persisted (triggers the full _load_from_db path).
        db_b = ChainDB(path)
        chain_b = Blockchain(db=db_b)
        chain_b.supply.pending_unstakes = db_b.get_all_pending_unstakes()

        # Both nodes must agree on the queue.
        self.assertEqual(
            chain_b.supply.pending_unstakes.get(eid),
            chain_a.supply.pending_unstakes.get(eid),
        )

        # Release on the restarted node must pay the same balance as on
        # the uprestarted node — the divergence this fix closes.
        chain_b.supply.process_pending_unstakes(release_block)
        chain_a.supply.process_pending_unstakes(release_block)
        self.assertEqual(
            chain_b.supply.get_balance(eid),
            chain_a.supply.get_balance(eid),
            "Restarted node released a different amount than the "
            "uprestarted node — pending_unstakes persistence broken",
        )
        _close_chaindb(db_b)


if __name__ == "__main__":
    unittest.main()
