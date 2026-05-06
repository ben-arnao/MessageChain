"""key_rotation_counts mirror leak — chaindb table must be wiped+restored
on reorg and orphan rows cleaned up by _persist_state.

Defect class -- same as the seven mirror-leak fixes already shipped
(round-2 entity_id_to_index, round-4 key_rotation_last_height, round-7
receipt_subtree_roots, round-12 reaction_choices, round-13 successful-
reorg twin, round-14 entity_last_active for Tier-47, round-15
pending_censorship_evidence): a chaindb table that mirrors a
consensus-critical in-memory map gets WRITTEN by the apply path
(via ``set_key_rotation_count`` from the rotation-apply path) but
the reorg restore + the periodic ``_persist_state`` flush both miss
the orphan-cleanup symmetry.

Pre-fix scenario (in production today):
  1. Entity X registers + rotates only on a fork-tip that loses the
     reorg -> ``key_rotation_counts[X]`` mirrored to disk via
     ``set_key_rotation_count``.
  2. ``_reset_state`` clears ``self.key_rotation_counts`` in-memory and
     canonical replay rebuilds it -- X is absent.  But
     ``restore_state_snapshot`` does NOT wipe ``key_rotation_counts``
     and ``_persist_state`` only upserts -- it never deletes orphan
     rows.
  3. Cold restart of any node that processed the losing fork
     rehydrates the orphan via ``get_all_key_rotation_counts`` ->
     state-tree commits the phantom rotation_count into the per-leaf
     state-root (state_tree.py via ``rotation_count=...``) ->
     state_root mismatch on the next checkpoint -> silent consensus
     fork from the warm cluster.

Anchored in CLAUDE.md:
  - "Security -- The most important principle of this project."
  - Pure stake-threshold validator entry; honest operators are insured
    against accidents (a node that crashes during a reorg must
    auto-resync without state surgery, not silently fork).
  - Crypto-agility: key rotations are a first-class tx type and the
    rotation count is committed into the state-root.

These tests MUST fail on current main and pass after the fix.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.storage.chaindb import ChainDB


# ---------------------------------------------------------------------
# Layer 1 -- chaindb save/restore symmetry for key_rotation_counts
# ---------------------------------------------------------------------


class TestChaindbKeyRotationCountsSaveRestoreSymmetry(unittest.TestCase):
    """``save_state_snapshot`` MUST capture key_rotation_counts and
    ``restore_state_snapshot`` MUST wipe + re-insert the
    key_rotation_counts table inside the same SQL transaction.

    Pre-fix a successful reorg across a key-rotation block left the
    losing-fork rotation count permanently on disk -- cold restart
    rehydrated the orphan row and silently forked at the next
    state-root commitment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_state_snapshot_captures_key_rotation_counts(self):
        db = ChainDB(self.db_path)
        try:
            eid = b"A" * 32
            db.set_key_rotation_count(eid, 3)
            db.flush_state()
            snap = db.save_state_snapshot()
            self.assertIn(
                "key_rotation_counts", snap,
                "save_state_snapshot MUST capture key_rotation_counts "
                "or restore wipes the table without re-population -- "
                "cold restart in the post-restore window forks on the "
                "next state-root commitment (rotation_count is "
                "committed per-leaf in state_tree).",
            )
            self.assertEqual(snap["key_rotation_counts"][eid], 3)
        finally:
            db.close()

    def test_restore_state_snapshot_wipes_orphan_rows(self):
        """Snapshot at canonical state, plant losing-fork orphan,
        restore -- the orphan MUST be gone, the snapshot's entries
        MUST be present."""
        db = ChainDB(self.db_path)
        try:
            canonical_eid = b"C" * 32
            orphan_eid = b"O" * 32
            db.set_key_rotation_count(canonical_eid, 1)
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a losing-fork rotation that wrote to disk via
            # set_key_rotation_count (this is what happens when the
            # rotation-apply path bumps the count on the fork tip).
            db.set_key_rotation_count(orphan_eid, 1)
            # And mutate the canonical entry as if it was rotated again
            # on the losing fork.
            db.set_key_rotation_count(canonical_eid, 5)
            db.flush_state()
            # Commit any auto-opened DML tx so restore's BEGIN can fire.
            db._conn.commit()
            db.restore_state_snapshot(snap)
            rehydrated = db.get_all_key_rotation_counts()
            self.assertEqual(
                rehydrated.get(canonical_eid), 1,
                "restore MUST roll back the losing-fork mutation and "
                "re-insert the snapshot value.",
            )
            self.assertNotIn(
                orphan_eid, rehydrated,
                "Losing-fork-only rotation count MUST NOT survive "
                "restore -- this is the mirror leak that silently forks "
                "the cold-restarted node from the canonical cluster.",
            )
        finally:
            db.close()

    def test_restore_state_snapshot_handles_legacy_snapshot(self):
        """A snapshot dict without the ``key_rotation_counts`` key
        (chaindb snapshot taken before save was extended) MUST still
        restore cleanly -- the table becomes empty, matching the
        pristine state."""
        db = ChainDB(self.db_path)
        try:
            db.set_key_rotation_count(b"X" * 32, 2)
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a legacy / pre-field snapshot.
            snap.pop("key_rotation_counts", None)
            db._conn.commit()
            db.restore_state_snapshot(snap)
            self.assertEqual(
                db.get_all_key_rotation_counts(), {},
                "Legacy snapshot restore MUST leave key_rotation_counts "
                "empty -- matches the pristine state.",
            )
        finally:
            db.close()


# ---------------------------------------------------------------------
# Layer 2 -- _persist_state cleans up orphan disk rows
# ---------------------------------------------------------------------


class TestPersistStateCleansOrphanKeyRotationCountRows(unittest.TestCase):
    """Even WITHOUT a reorg-restore, a divergence between in-memory
    ``key_rotation_counts`` and the on-disk mirror MUST be reconciled
    by ``_persist_state``.  This is the second half of the fix:
    ``restore_state_snapshot`` covers the failed-reorg rollback path,
    but the SUCCESSFUL reorg path ends in ``_persist_state`` (no
    chaindb-level restore), so the persist must also delete orphan
    rows whose entity_id is no longer in the in-memory dict."""

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

    def test_persist_state_deletes_in_memory_absent_rows(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            # Plant an orphan row on disk that the in-memory dict
            # does NOT contain -- simulates the post-successful-reorg
            # state where ``_reset_state`` cleared the in-memory dict
            # and canonical replay rebuilt it without this entity, but
            # the chaindb mirror still carries the orphan from the
            # losing fork.
            orphan_eid = b"O" * 32
            db.set_key_rotation_count(orphan_eid, 4)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_key_rotation_counts(),
                "Sanity: orphan row planted.",
            )
            # In-memory dict has a different live entity, no orphan.
            live_eid = b"L" * 32
            chain.key_rotation_counts = {live_eid: 1}
            # Full flush -- mirrors the post-reorg invocation.
            chain._dirty_entities = None
            chain._persist_state()
            on_disk = db.get_all_key_rotation_counts()
            self.assertEqual(
                on_disk, {live_eid: 1},
                "_persist_state on a full flush MUST delete orphan "
                "key_rotation_counts rows whose entity_id is no longer "
                "in the in-memory dict.  Pre-fix the orphan survives "
                "indefinitely and rehydrates on the next cold restart.",
            )
        finally:
            self._close_db(db)


if __name__ == "__main__":
    unittest.main()
