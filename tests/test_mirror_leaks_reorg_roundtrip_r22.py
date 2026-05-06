"""Round-22: four more chaindb mirror tables leak orphan rows on the
successful-reorg path -- ``proposer_sig_counts``, ``slash_offense_counts``,
``reputation``, ``key_rotation_last_height``.  Same defect class as the
eight prior mirror-leak fixes (round-2 ``entity_id_to_index``, round-4
``key_rotation_last_height`` save/restore, round-7
``receipt_subtree_roots``, round-12 ``reaction_choices``, round-13
successful-reorg twin, round-14 ``entity_last_active`` for Tier-47,
round-15 ``pending_censorship_evidence``, round-21
``key_rotation_counts``).

All four feed consensus-deterministic state:

  * ``proposer_sig_counts`` -- attester-weight input + ``slashing_severity``
    ``_track_record`` (volume of good behavior).
  * ``slash_offense_counts`` -- ``slashing_severity`` repeat-offense
    escalation (post-Tier-23/24).
  * ``reputation`` -- bootstrap-era reputation-weighted lottery winner
    selection (lottery payouts mutate ``supply.balances``) +
    ``slashing_severity`` good-history input.
  * ``key_rotation_last_height`` -- KeyRotation cooldown gate
    (``KEY_ROTATION_COOLDOWN_BLOCKS``).  An orphan row that survives
    a successful reorg silently rejects a valid KeyRotation tx that
    warm peers admit -- consensus split on every block carrying that
    rotation tx.

Pre-fix scenario (in production today) -- same shape for every table:

  1. Entity X registers + mutates the mirrored counter only on a
     fork-tip that loses the reorg.  Each mutation routes through the
     eager-write chokepoint (``_bump_reputation`` /
     ``_bump_slash_offense_count`` for the eager mirrors, or the
     ``_persist_state`` upsert for ``proposer_sig_counts`` /
     ``key_rotation_last_height``) that mirrors the value to disk.
  2. ``_reset_state`` clears the in-memory map and canonical replay
     rebuilds it -- X is absent.  ``restore_state_snapshot`` already
     wipes + re-inserts each of these tables (round-4 / earlier
     fixes), but the SUCCESSFUL-reorg path ends in
     ``_persist_state(full_flush=True)`` -- no chaindb-level restore.
     The dirty-only INSERT-OR-REPLACE loop (or, for
     ``reputation`` / ``slash_offense_counts``, no upsert loop at
     all in pre-fix ``_persist_state``) skips rows for entity_ids
     not in the canonical in-memory dict, so the orphan rows survive.
  3. Cold restart of any node that processed the losing fork
     rehydrates the orphan via ``get_all_*`` -- the rehydrated value
     feeds consensus-deterministic state and the restarted node
     silently forks vs. the warm cluster on the next slash /
     rotation / lottery tick.

Anchored in CLAUDE.md:
  - "Security -- The most important principle of this project."
  - Honest operators are insured against accidents (a node that
    crashes during a reorg must auto-resync without state surgery,
    not silently fork at the next consensus-deterministic decision).
  - Pure stake-threshold validator entry; identity continuity via
    key rotation (``key_rotation_last_height`` cooldown gate must be
    consensus-uniform across the network).

These tests MUST fail on current main and pass after the fix.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.storage.chaindb import ChainDB


# ---------------------------------------------------------------------
# Layer 1 -- chaindb clear_all_* helpers exist + DELETE the table
# ---------------------------------------------------------------------


class TestChaindbClearAllHelpersExist(unittest.TestCase):
    """Each of the four mirror tables MUST expose a
    ``clear_all_*`` helper that DELETEs the table.  Without the
    helper, ``_persist_state`` cannot wipe orphan rows on a full
    flush -- the gate uses ``hasattr(self.db, "clear_all_*")`` so a
    missing helper silently re-opens the leak."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_clear_all_proposer_sig_counts_exists_and_deletes(self):
        db = ChainDB(self.db_path)
        try:
            self.assertTrue(
                hasattr(db, "clear_all_proposer_sig_counts"),
                "ChainDB MUST expose clear_all_proposer_sig_counts -- "
                "without it the _persist_state full-flush gate "
                "silently no-ops and the mirror leak survives.",
            )
            db.set_proposer_sig_count(b"A" * 32, 7)
            db.set_proposer_sig_count(b"B" * 32, 3)
            db.flush_state()
            self.assertEqual(len(db.get_all_proposer_sig_counts()), 2)
            db.clear_all_proposer_sig_counts()
            self.assertEqual(
                db.get_all_proposer_sig_counts(), {},
                "clear_all_proposer_sig_counts MUST DELETE every row.",
            )
        finally:
            db.close()

    def test_clear_all_slash_offense_counts_exists_and_deletes(self):
        db = ChainDB(self.db_path)
        try:
            self.assertTrue(
                hasattr(db, "clear_all_slash_offense_counts"),
                "ChainDB MUST expose clear_all_slash_offense_counts.",
            )
            db.set_slash_offense_count(b"A" * 32, 2)
            db.set_slash_offense_count(b"B" * 32, 1)
            db.flush_state()
            self.assertEqual(len(db.get_all_slash_offense_counts()), 2)
            db.clear_all_slash_offense_counts()
            self.assertEqual(
                db.get_all_slash_offense_counts(), {},
                "clear_all_slash_offense_counts MUST DELETE every row.",
            )
        finally:
            db.close()

    def test_clear_all_reputation_exists_and_deletes(self):
        db = ChainDB(self.db_path)
        try:
            self.assertTrue(
                hasattr(db, "clear_all_reputation"),
                "ChainDB MUST expose clear_all_reputation.",
            )
            db.set_reputation(b"A" * 32, 5)
            db.set_reputation(b"B" * 32, 11)
            db.flush_state()
            self.assertEqual(len(db.get_all_reputation()), 2)
            db.clear_all_reputation()
            self.assertEqual(
                db.get_all_reputation(), {},
                "clear_all_reputation MUST DELETE every row.",
            )
        finally:
            db.close()

    def test_clear_all_key_rotation_last_height_exists_and_deletes(self):
        db = ChainDB(self.db_path)
        try:
            self.assertTrue(
                hasattr(db, "clear_all_key_rotation_last_height"),
                "ChainDB MUST expose clear_all_key_rotation_last_height.",
            )
            db.set_key_rotation_last_height(b"A" * 32, 100)
            db.set_key_rotation_last_height(b"B" * 32, 200)
            db.flush_state()
            self.assertEqual(
                len(db.get_all_key_rotation_last_height()), 2,
            )
            db.clear_all_key_rotation_last_height()
            self.assertEqual(
                db.get_all_key_rotation_last_height(), {},
                "clear_all_key_rotation_last_height MUST DELETE "
                "every row.",
            )
        finally:
            db.close()


# ---------------------------------------------------------------------
# Layer 2 -- _persist_state full-flush deletes orphan disk rows
# ---------------------------------------------------------------------


class TestPersistStateCleansOrphanRows(unittest.TestCase):
    """Even WITHOUT a reorg-restore, a divergence between in-memory
    state and the on-disk mirror MUST be reconciled by
    ``_persist_state`` on full flush.  This is the second half of the
    fix: ``restore_state_snapshot`` covers the failed-reorg rollback
    path, but the SUCCESSFUL reorg path ends in ``_persist_state``
    (no chaindb-level restore), so the persist must also delete
    orphan rows whose entity_id is no longer in the canonical
    in-memory dict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _close_db(self, db):
        try:
            conn = getattr(db._local, "conn", None)
            if conn is not None:
                conn.close()
                db._local.conn = None
        except Exception:
            pass

    def test_persist_state_deletes_proposer_sig_counts_orphan(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            orphan_eid = b"O" * 32
            db.set_proposer_sig_count(orphan_eid, 9)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_proposer_sig_counts(),
                "Sanity: orphan planted.",
            )
            live_eid = b"L" * 32
            chain.proposer_sig_counts = {live_eid: 2}
            chain._dirty_entities = None
            chain._persist_state()
            self.assertEqual(
                db.get_all_proposer_sig_counts(), {live_eid: 2},
                "_persist_state full-flush MUST delete orphan "
                "proposer_sig_counts rows whose entity_id is no longer "
                "in the in-memory dict.",
            )
        finally:
            self._close_db(db)

    def test_persist_state_deletes_slash_offense_counts_orphan(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            orphan_eid = b"O" * 32
            db.set_slash_offense_count(orphan_eid, 4)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_slash_offense_counts(),
                "Sanity: orphan planted.",
            )
            live_eid = b"L" * 32
            chain.slash_offense_counts = {live_eid: 1}
            chain._dirty_entities = None
            chain._persist_state()
            self.assertEqual(
                db.get_all_slash_offense_counts(), {live_eid: 1},
                "_persist_state full-flush MUST delete orphan "
                "slash_offense_counts rows whose entity_id is no "
                "longer in the in-memory dict.",
            )
        finally:
            self._close_db(db)

    def test_persist_state_deletes_reputation_orphan(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            orphan_eid = b"O" * 32
            db.set_reputation(orphan_eid, 6)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_reputation(),
                "Sanity: orphan planted.",
            )
            live_eid = b"L" * 32
            chain.reputation = {live_eid: 3}
            chain._dirty_entities = None
            chain._persist_state()
            self.assertEqual(
                db.get_all_reputation(), {live_eid: 3},
                "_persist_state full-flush MUST delete orphan "
                "reputation rows whose entity_id is no longer in "
                "the in-memory dict.",
            )
        finally:
            self._close_db(db)

    def test_persist_state_deletes_key_rotation_last_height_orphan(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            orphan_eid = b"O" * 32
            db.set_key_rotation_last_height(orphan_eid, 500)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_key_rotation_last_height(),
                "Sanity: orphan planted.",
            )
            live_eid = b"L" * 32
            chain.key_rotation_last_height = {live_eid: 100}
            chain._dirty_entities = None
            chain._persist_state()
            self.assertEqual(
                db.get_all_key_rotation_last_height(), {live_eid: 100},
                "_persist_state full-flush MUST delete orphan "
                "key_rotation_last_height rows whose entity_id is no "
                "longer in the in-memory dict.",
            )
        finally:
            self._close_db(db)


if __name__ == "__main__":
    unittest.main()
