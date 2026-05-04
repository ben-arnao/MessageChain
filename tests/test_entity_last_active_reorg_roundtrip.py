"""Tier-47 mirror leak — entity_last_active is wiped+restored on reorg
and orphan rows are cleaned up by _persist_state.

Defect class — same as the four mirror-leak fixes already shipped
(entity_id_to_index round-2, key_rotation_last_height round-4,
receipt_subtree_roots round-7, reaction_choices round-12, plus the
1.50–1.52.0 hotfix sequence): a chaindb table that mirrors a
consensus-critical in-memory map gets WRITTEN by the apply path
(via ``set_last_active_height`` from ``SupplyTracker.bump_active``)
but the reorg restore + the periodic ``_persist_state`` flush both
miss the orphan-cleanup symmetry.

Pre-fix scenario (post DORMANCY_CONTROLLER_HEIGHT activation):
  1. Entity bumped on a fork-tip that loses the reorg → row
     mirrored to disk via ``set_last_active_height``.
  2. Reorg restores in-memory ``last_active_heights`` from the
     state-snapshot at the ancestor height (no entry for that eid)
     but ``restore_state_snapshot`` does NOT wipe
     ``entity_last_active`` and ``_persist_state`` only upserts —
     it never deletes orphan rows.
  3. Cold restart in the days/weeks before that key bumps again on
     the canonical chain rehydrates the orphan row →
     ``compute_active_supply`` differs from peers →
     ``compute_dormancy_issuance`` mints a different amount →
     state_root mismatch on the next block → restarted node
     permanently forks from the network.

Anchored in CLAUDE.md:
  - "Security — The most important principle of this project."
  - "Issuance targets a stable active supply, not a fixed schedule …
    `active_supply` is dormancy-filtered."  (Tier-47 — this is the
    on-disk mirror of the dormancy-filter input.)
  - "Honest operators are insured against accidents."  (A node that
    crashes during a post-activation reorg must auto-resync without
    state surgery, not silently fork.)

These tests MUST fail on current main and pass after the fix.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.storage.chaindb import ChainDB


# ─────────────────────────────────────────────────────────────────────
# Layer 1 — chaindb save/restore symmetry for entity_last_active
# ─────────────────────────────────────────────────────────────────────


class TestChaindbEntityLastActiveSaveRestoreSymmetry(unittest.TestCase):
    """``save_state_snapshot`` MUST capture last_active_heights and
    ``restore_state_snapshot`` MUST wipe + re-insert the
    entity_last_active table inside the same SQL transaction.

    Pre-fix a successful reorg across a Tier-47-bumping block left the
    losing-fork bump permanently on disk -- cold restart rehydrated
    the orphan row and silently forked at the next mint."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_state_snapshot_captures_last_active_heights(self):
        db = ChainDB(self.db_path)
        try:
            eid = b"A" * 32
            db.set_last_active_height(eid, 6000)
            db.flush_state()
            snap = db.save_state_snapshot()
            self.assertIn(
                "last_active_heights", snap,
                "save_state_snapshot MUST capture last_active_heights "
                "or restore wipes the table without re-population — "
                "cold restart in the post-restore window forks on "
                "the next compute_active_supply / "
                "compute_dormancy_issuance call.",
            )
            self.assertEqual(
                snap["last_active_heights"][eid], 6000,
            )
        finally:
            db.close()

    def test_restore_state_snapshot_wipes_orphan_rows(self):
        """Snapshot at canonical state, plant losing-fork orphan,
        restore — the orphan MUST be gone, the snapshot's entries
        MUST be present."""
        db = ChainDB(self.db_path)
        try:
            canonical_eid = b"C" * 32
            orphan_eid = b"O" * 32
            db.set_last_active_height(canonical_eid, 6000)
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a losing-fork bump that wrote to disk via
            # ``set_last_active_height`` (this is what happens when
            # SupplyTracker.bump_active fires on the fork tip).
            db.set_last_active_height(orphan_eid, 6500)
            # And mutate the canonical entry as if it was bumped
            # higher on the losing fork.
            db.set_last_active_height(canonical_eid, 6500)
            db.flush_state()
            # Commit any auto-opened DML tx so restore's BEGIN can fire.
            db._conn.commit()
            db.restore_state_snapshot(snap)
            rehydrated = db.get_all_last_active_heights()
            self.assertEqual(
                rehydrated.get(canonical_eid), 6000,
                "restore MUST roll back the losing-fork mutation and "
                "re-insert the snapshot value.",
            )
            self.assertNotIn(
                orphan_eid, rehydrated,
                "Losing-fork-only bump MUST NOT survive restore — "
                "this is the mirror leak that silently forks the "
                "cold-restarted node from the canonical cluster.",
            )
        finally:
            db.close()

    def test_restore_state_snapshot_handles_legacy_snapshot(self):
        """A snapshot dict without the ``last_active_heights`` key
        (pre-Tier-47 round-trip, or a chaindb snapshot taken before
        save was extended) MUST still restore cleanly — the table
        becomes empty, matching the pre-fork pristine state."""
        db = ChainDB(self.db_path)
        try:
            db.set_last_active_height(b"X" * 32, 6000)
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a legacy / pre-field snapshot.
            snap.pop("last_active_heights", None)
            db._conn.commit()
            db.restore_state_snapshot(snap)
            self.assertEqual(
                db.get_all_last_active_heights(), {},
                "Legacy snapshot restore MUST leave entity_last_active "
                "empty — matches the pristine pre-fork state.",
            )
        finally:
            db.close()


# ─────────────────────────────────────────────────────────────────────
# Layer 2 — Cold-load round-trip after a simulated reorg
# ─────────────────────────────────────────────────────────────────────


class TestColdLoadAfterReorgDoesNotResurrectOrphan(unittest.TestCase):
    """End-to-end shape: stamp a few entities on the canonical chain,
    plant a losing-fork bump that mirrored to disk via
    ``set_last_active_height``, simulate the post-reorg in-memory
    state via the canonical snapshot (no orphan), run
    ``_persist_state``, and verify the on-disk
    ``entity_last_active`` table no longer carries the orphan.

    Uses the chain-DB primitives directly to keep the test fast (~5s);
    a full block-apply reorg roundtrip would require the full
    Entity.create + Block.sign machinery.  The exact failure mode
    being pinned is the chaindb mirror cleanup, not the higher-level
    reorg bookkeeping (which has its own coverage).

    Asserts on the disk shape (via a fresh ChainDB instance) rather
    than on a re-opened ``Blockchain.supply.last_active_heights`` —
    ``Blockchain._load_from_db`` short-circuits when the chain has
    zero blocks (``block_count == 0`` early-return), so a fresh DB
    with state planted directly through the chaindb primitives only
    surfaces the leak via the chaindb-level read.  The disk shape
    IS the source of truth on cold-restart for any chain with at
    least one block, so this assertion still proves the leak."""

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

    def test_orphan_disk_row_does_not_survive_post_reorg_persist(self):
        """Plant canonical state, simulate a losing-fork bump that
        mirrored to disk, set in-memory to the canonical map (as
        ``_restore_memory_snapshot`` would on a successful reorg),
        run ``_persist_state``, and re-open the chaindb against the
        same path.  The entity_last_active table MUST contain the
        canonical entries only — no orphan."""
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        try:
            canonical_a = b"A" * 32
            canonical_b = b"B" * 32
            orphan_eid = b"O" * 32

            # 1. Establish canonical state on disk.
            chain.supply.last_active_heights = {
                canonical_a: 6000,
                canonical_b: 6010,
            }
            db.set_last_active_height(canonical_a, 6000)
            db.set_last_active_height(canonical_b, 6010)
            db.flush_state()

            # 2. Simulate a losing-fork bump: an entity that signed on
            # the fork tip wrote a row to disk via the chaindb mirror
            # (this is what ``SupplyTracker.bump_active`` does in
            # production).
            db.set_last_active_height(orphan_eid, 6500)
            db.flush_state()

            # 3. Reorg-equivalent: in-memory state is restored to the
            # canonical snapshot (no orphan_eid).  On the SUCCESSFUL
            # reorg path, ``_restore_memory_snapshot`` overwrites the
            # in-memory dict; the chaindb mirror is left to
            # ``_persist_state`` to clean up.
            chain.supply.last_active_heights = {
                canonical_a: 6000,
                canonical_b: 6010,
            }
            # Force a full flush so the persist path covers every row
            # the reorg may have touched (mirrors the post-reorg
            # ``_persist_state`` invocation at the end of the
            # successful-reorg branch in ``replace_chain``).
            chain._dirty_entities = None
            chain._persist_state()

            # 4. Close, re-open, read disk state via a fresh ChainDB
            # connection (mirrors what cold-restart sees when
            # ``_load_from_db`` reads ``get_all_last_active_heights``).
            self._close_db(db)
            db2 = ChainDB(self.db_path)
            try:
                on_disk = db2.get_all_last_active_heights()
                self.assertEqual(
                    on_disk,
                    {canonical_a: 6000, canonical_b: 6010},
                    "After a successful-reorg-equivalent persist, the "
                    "on-disk entity_last_active table MUST match the "
                    "in-memory ``last_active_heights`` exactly.  The "
                    "orphan row from the losing fork survives "
                    "indefinitely on current main — cold restart "
                    "reads it back, mixes it into "
                    "``compute_active_supply``, and the next mint "
                    "diverges from peers (silent fork).",
                )
                self.assertNotIn(
                    orphan_eid, on_disk,
                    "Orphan-fork bump MUST NOT survive a "
                    "reorg + persist cycle.",
                )
            finally:
                self._close_db(db2)
        finally:
            self._close_db(db)


# ─────────────────────────────────────────────────────────────────────
# Layer 3 — _persist_state cleans up orphan disk rows
# ─────────────────────────────────────────────────────────────────────


class TestPersistStateCleansOrphanLastActiveRows(unittest.TestCase):
    """Even WITHOUT a reorg-restore, a divergence between in-memory
    ``last_active_heights`` and the on-disk mirror MUST be reconciled
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

    def test_persist_state_deletes_in_memory_absent_rows(self):
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            # Plant an orphan row on disk that the in-memory dict
            # does NOT contain — simulates the post-successful-reorg
            # state where ``_restore_memory_snapshot`` overwrote the
            # in-memory dict but the chaindb mirror still carries the
            # orphan from the losing fork.
            orphan_eid = b"O" * 32
            db.set_last_active_height(orphan_eid, 6500)
            db.flush_state()
            self.assertIn(
                orphan_eid, db.get_all_last_active_heights(),
                "Sanity: orphan row planted.",
            )
            # In-memory dict has a different live entity, no orphan.
            live_eid = b"L" * 32
            chain.supply.last_active_heights = {live_eid: 6000}
            # Full flush — mirrors the post-reorg invocation.
            chain._dirty_entities = None
            chain._persist_state()
            on_disk = db.get_all_last_active_heights()
            self.assertEqual(
                on_disk, {live_eid: 6000},
                "_persist_state on a full flush MUST delete orphan "
                "entity_last_active rows whose entity_id is no longer "
                "in the in-memory dict.  Pre-fix the orphan survives "
                "indefinitely and rehydrates on the next cold restart.",
            )
        finally:
            try:
                conn = getattr(db._local, "conn", None)
                if conn is not None:
                    conn.close()
                    db._local.conn = None
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
