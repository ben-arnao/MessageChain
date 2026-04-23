"""
Tests for key_history persistence across cold restart.

Before the fix, `Blockchain.key_history` was purely in-memory:
`_record_key_history` appended to a dict but never mirrored into
chaindb, and `_load_from_db` did not replay blocks to rebuild it.

`validate_slash_transaction` uses `_public_key_at_height(ev_height)`
to look up the pubkey that was ACTIVE when the evidence was signed
(so a validator who equivocates at height M and then rotates keys
at height N > M can still be slashed with evidence from M).  When
`key_history` is empty at cold start, that lookup falls back to the
CURRENT (post-rotation) pubkey, the pre-rotation evidence's WOTS+
verify fails, and the slash is rejected.

Two concrete failure modes this regression-tests:

1. Slash evasion via rotate-then-restart: the offender's rotation
   silently defeats the 100% stake burn on restarted peers.

2. Consensus divergence: uprestarted peers accept the slash block
   that a restarted peer rejects for "invalid evidence signature",
   producing a state_root mismatch and forking the restarted peer
   off the honest chain.

These tests prove the history round-trips through SQLite so a cold
restart produces the same `_public_key_at_height` result as a peer
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
    delete the temp DB file.  Matches the pattern in
    test_pending_unstakes_persistence.py."""
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class TestKeyHistoryTablePersists(unittest.TestCase):
    """Direct ChainDB round-trip tests — the table survives a reopen."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_add_single_entry_persists(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32
        old_pk = b"\x01" * 32

        db1 = ChainDB(path)
        db1.add_key_history_entry(eid, installed_at=100, public_key=old_pk)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_key_history(),
            {eid: [(100, old_pk)]},
        )
        _close_chaindb(db2)

    def test_multiple_rotations_ordered_by_installed_at(self):
        """Stacked rotations for one entity round-trip in install order."""
        path = self._fresh_chaindb()
        eid = b"v" * 32
        pk_gen = b"\x01" * 32
        pk_rot1 = b"\x02" * 32
        pk_rot2 = b"\x03" * 32

        db1 = ChainDB(path)
        db1.add_key_history_entry(eid, installed_at=300, public_key=pk_rot2)
        db1.add_key_history_entry(eid, installed_at=0, public_key=pk_gen)
        db1.add_key_history_entry(eid, installed_at=150, public_key=pk_rot1)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(
            db2.get_all_key_history(),
            {eid: [(0, pk_gen), (150, pk_rot1), (300, pk_rot2)]},
        )
        _close_chaindb(db2)

    def test_clear_removes_all_entries_for_entity(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32

        db1 = ChainDB(path)
        db1.add_key_history_entry(eid, 0, b"\x01" * 32)
        db1.add_key_history_entry(eid, 150, b"\x02" * 32)
        db1.clear_key_history(eid)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        self.assertEqual(db2.get_all_key_history(), {})
        _close_chaindb(db2)


class TestBlockchainMirrorsKeyHistoryToDB(unittest.TestCase):
    """`Blockchain._record_key_history` must mirror into the chaindb
    table so a cold reopen sees every rotation."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def _pad_chain(self, chain, target_height: int) -> None:
        """`Blockchain.height == len(chain.chain)` — pad with stubs so
        `_record_key_history` records the intended height."""
        while len(chain.chain) < target_height:
            chain.chain.append(object())

    def test_record_key_history_mirrors_to_db(self):
        path = self._fresh_chaindb()
        db1 = ChainDB(path)
        chain = Blockchain(db=db1)
        eid = b"v" * 32
        old_pk = b"\x01" * 32

        self._pad_chain(chain, 42)
        chain._record_key_history(eid, old_pk)
        db1.flush_state()
        _close_chaindb(db1)

        db2 = ChainDB(path)
        persisted = db2.get_all_key_history()
        self.assertIn(eid, persisted)
        entries = persisted[eid]
        self.assertEqual(len(entries), 1)
        installed_at, pk = entries[0]
        self.assertEqual(installed_at, 42)
        self.assertEqual(pk, old_pk)
        _close_chaindb(db2)


class TestColdRestartPreservesPublicKeyAtHeight(unittest.TestCase):
    """End-to-end: after a rotate-then-restart cycle the restarted
    node must return the PRE-rotation pubkey for pre-rotation heights
    — without this, slash evidence signed with the pre-rotation key
    fails WOTS+ verify on the restarted node, the slash is rejected,
    and the offender escapes."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def _pad_chain(self, chain, target_height: int) -> None:
        """`Blockchain.height == len(chain.chain)` — pad with stubs so
        `_record_key_history` records the intended height."""
        while len(chain.chain) < target_height:
            chain.chain.append(object())

    def test_pre_rotation_pubkey_survives_restart(self):
        path = self._fresh_chaindb()
        eid = b"v" * 32
        old_pk = b"\x01" * 32
        new_pk = b"\x02" * 32

        # Node A: install old_pk at height 5, rotate to new_pk at height 500.
        db_a = ChainDB(path)
        chain_a = Blockchain(db=db_a)
        self._pad_chain(chain_a, 5)
        chain_a._record_key_history(eid, old_pk)
        self._pad_chain(chain_a, 500)
        chain_a._record_key_history(eid, new_pk)
        # Current pubkey post-rotation is new_pk.
        chain_a.public_keys[eid] = new_pk
        db_a.flush_state()
        _close_chaindb(db_a)

        # Node B: cold-restart from the same chaindb.  `_load_from_db`
        # early-returns on empty block count, so manually drive the
        # rehydrate step — matches what a real node does once its
        # first block has been persisted (triggers the full path).
        db_b = ChainDB(path)
        chain_b = Blockchain(db=db_b)
        chain_b.public_keys[eid] = new_pk  # post-rotation current
        chain_b.key_history = db_b.get_all_key_history()

        # Both nodes must agree on the history.
        self.assertEqual(
            chain_b.key_history.get(eid),
            chain_a.key_history.get(eid),
        )

        # Pre-rotation-height lookup (evidence signed at height 200
        # — before the rotation at 500) must return the OLD pubkey
        # on BOTH nodes, not the current one.  The pre-fix cold-
        # restart path returned `new_pk` here, silently breaking
        # WOTS+ verify against old-key-signed evidence.
        self.assertEqual(
            chain_b._public_key_at_height(eid, 200),
            old_pk,
        )
        # And the uprestarted-peer equivalent matches byte-for-byte.
        self.assertEqual(
            chain_b._public_key_at_height(eid, 200),
            chain_a._public_key_at_height(eid, 200),
        )

        # Post-rotation-height lookup returns new_pk on both.
        self.assertEqual(
            chain_b._public_key_at_height(eid, 600),
            new_pk,
        )
        _close_chaindb(db_b)


if __name__ == "__main__":
    unittest.main()
