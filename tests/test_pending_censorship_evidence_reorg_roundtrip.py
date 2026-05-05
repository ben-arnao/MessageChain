"""``pending_censorship_evidence`` mirror leak — wiped+restored on reorg
and orphan rows are cleaned up by ``_persist_state``.

Defect class — same as the six prior mirror-leak fixes already shipped
(entity_id_to_index round-2, key_rotation_last_height round-4,
receipt_subtree_roots round-7, reaction_choices round-12, the round-13
successful-reorg twin, and round-14 entity_last_active for Tier-47):
a chaindb table that mirrors a consensus-critical in-memory map gets
WRITTEN by the apply path (via ``set_pending_censorship_evidence``
inside ``_persist_state``) but the reorg restore + the periodic
``_persist_state`` flush both miss the orphan-cleanup symmetry.

Pre-fix scenario:
  1. ``CensorshipEvidenceTx`` admitted on a fork-tip writes a row to
     disk via ``set_pending_censorship_evidence``.
  2. Reorg restores in-memory ``censorship_processor.pending`` from
     the canonical-chain snapshot, but
     ``restore_state_snapshot`` does NOT wipe
     ``pending_censorship_evidence``, and ``_persist_state`` only
     INSERT-OR-REPLACEs — never DELETEs orphan rows.
  3. Cold restart calls ``get_all_pending_censorship_evidence``,
     rehydrates the orphan row into
     ``censorship_processor.pending``, and the next maturity tick
     at ``EVIDENCE_MATURITY_BLOCKS`` slashes a validator the warm
     cluster never accuses → consensus split + an unjustified
     ``CENSORSHIP_SLASH_BPS`` burn against an honest operator.

Anchored in CLAUDE.md:
  - "Security — The most important principle of this project."
  - "Honest operators are insured against accidents." (A reorg-orphan
    censorship-evidence row that survives to the next maturity tick
    would slash an honest operator the canonical chain never accuses
    — the inverse of this anchor's intent.)
  - "A node ending up on a minority/unintentional fork must auto-resync
    to the canonical chain with no manual state surgery on the operator
    side, and must not accumulate slashable evidence solely from being
    briefly on the wrong tip."

These tests MUST fail on current main and pass after the fix.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.storage.chaindb import ChainDB


# ─────────────────────────────────────────────────────────────────────
# Layer 1 — chaindb save/restore symmetry for pending_censorship_evidence
# ─────────────────────────────────────────────────────────────────────


class TestChaindbPendingCensorshipEvidenceSaveRestoreSymmetry(unittest.TestCase):
    """``save_state_snapshot`` MUST capture pending_censorship_evidence
    and ``restore_state_snapshot`` MUST wipe + re-insert the table
    inside the same SQL transaction.

    Pre-fix a successful reorg across an evidence-admitting block left
    the losing-fork evidence permanently on disk -- cold restart
    rehydrated the orphan row and silently slashed an honest operator
    at the next maturity tick."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _ev(self, b: bytes) -> bytes:
        return b * 32

    def test_save_state_snapshot_captures_pending_censorship_evidence(self):
        db = ChainDB(self.db_path)
        try:
            ev_hash = self._ev(b"\x01")
            offender_id = self._ev(b"\x02")
            tx_hash = self._ev(b"\x03")
            evidence_tx_hash = self._ev(b"\x04")
            db.set_pending_censorship_evidence(
                ev_hash, offender_id, tx_hash,
                admitted_height=100,
                evidence_tx_hash=evidence_tx_hash,
                staked_at_admission=5_000_000,
            )
            db.flush_state()
            snap = db.save_state_snapshot()
            self.assertIn(
                "pending_censorship_evidence", snap,
                "save_state_snapshot MUST capture "
                "pending_censorship_evidence or restore wipes the "
                "table without re-population — cold restart in the "
                "post-restore window then misses the canonical "
                "evidence's maturity tick (silent failure to slash a "
                "real censoring validator).",
            )
            self.assertIn(ev_hash, snap["pending_censorship_evidence"])
            payload = snap["pending_censorship_evidence"][ev_hash]
            self.assertEqual(payload[0], offender_id)
            self.assertEqual(payload[1], tx_hash)
            self.assertEqual(payload[2], 100)
            self.assertEqual(payload[3], evidence_tx_hash)
            self.assertEqual(payload[4], 5_000_000)
        finally:
            db.close()

    def test_restore_state_snapshot_wipes_orphan_rows(self):
        """Snapshot at canonical state, plant losing-fork orphan,
        restore — the orphan MUST be gone, the snapshot's entries
        MUST be present."""
        db = ChainDB(self.db_path)
        try:
            canonical_ev = self._ev(b"\xc1")
            canonical_off = self._ev(b"\xc2")
            canonical_tx = self._ev(b"\xc3")
            canonical_evtx = self._ev(b"\xc4")
            orphan_ev = self._ev(b"\xa1")
            orphan_off = self._ev(b"\xa2")
            orphan_tx = self._ev(b"\xa3")
            orphan_evtx = self._ev(b"\xa4")

            db.set_pending_censorship_evidence(
                canonical_ev, canonical_off, canonical_tx,
                admitted_height=100,
                evidence_tx_hash=canonical_evtx,
                staked_at_admission=1_000_000,
            )
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a losing-fork admission that wrote to disk
            # via the chaindb mirror — this is what
            # ``_persist_state`` does when a CensorshipEvidenceTx is
            # admitted on a fork tip.
            db.set_pending_censorship_evidence(
                orphan_ev, orphan_off, orphan_tx,
                admitted_height=200,
                evidence_tx_hash=orphan_evtx,
                staked_at_admission=2_000_000,
            )
            db.flush_state()
            db._conn.commit()
            db.restore_state_snapshot(snap)
            rehydrated = db.get_all_pending_censorship_evidence()
            self.assertIn(
                canonical_ev, rehydrated,
                "restore MUST re-insert the snapshot's canonical "
                "evidence — without the re-insert the post-restore "
                "DB has empty pending_censorship_evidence and the "
                "next cold restart silently drops the canonical "
                "evidence's maturity slash.",
            )
            payload = rehydrated[canonical_ev]
            self.assertEqual(payload[0], canonical_off)
            self.assertEqual(payload[1], canonical_tx)
            self.assertEqual(payload[2], 100)
            self.assertEqual(payload[3], canonical_evtx)
            self.assertEqual(payload[4], 1_000_000)
            self.assertNotIn(
                orphan_ev, rehydrated,
                "Losing-fork-only evidence MUST NOT survive restore — "
                "this is the mirror leak that silently slashes an "
                "honest validator the canonical chain never accuses.",
            )
        finally:
            db.close()

    def test_restore_state_snapshot_handles_legacy_snapshot(self):
        """A snapshot dict without the
        ``pending_censorship_evidence`` key (pre-fix round-trip, or a
        chaindb snapshot taken before save was extended) MUST still
        restore cleanly — the table becomes empty, matching the
        pre-fork pristine state."""
        db = ChainDB(self.db_path)
        try:
            db.set_pending_censorship_evidence(
                self._ev(b"\x10"),
                self._ev(b"\x11"),
                self._ev(b"\x12"),
                admitted_height=50,
                evidence_tx_hash=self._ev(b"\x13"),
                staked_at_admission=100,
            )
            db.flush_state()
            snap = db.save_state_snapshot()
            # Simulate a legacy / pre-field snapshot.
            snap.pop("pending_censorship_evidence", None)
            db._conn.commit()
            db.restore_state_snapshot(snap)
            self.assertEqual(
                db.get_all_pending_censorship_evidence(), {},
                "Legacy snapshot restore MUST leave "
                "pending_censorship_evidence empty — matches the "
                "pristine pre-fork state.",
            )
        finally:
            db.close()


# ─────────────────────────────────────────────────────────────────────
# Layer 2 — Cold-load round-trip after a simulated reorg
# ─────────────────────────────────────────────────────────────────────


class TestColdLoadAfterReorgDoesNotResurrectOrphan(unittest.TestCase):
    """End-to-end shape: stamp a few canonical evidences on disk,
    plant a losing-fork evidence row, simulate the post-reorg
    in-memory state via the canonical replay (no orphan), run
    ``_persist_state``, and verify the on-disk
    ``pending_censorship_evidence`` table no longer carries the
    orphan.

    Uses the chain-DB primitives directly to keep the test fast
    (~5s); a full block-apply reorg roundtrip would require the full
    Entity.create + CensorshipEvidenceTx machinery.  The exact
    failure mode being pinned is the chaindb mirror cleanup, not
    higher-level reorg bookkeeping (which has its own coverage).
    """

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

    def _ev(self, b: bytes) -> bytes:
        return b * 32

    def _make_pending(self, evidence_hash, offender_id, tx_hash,
                     admitted_height, evidence_tx_hash,
                     staked_at_admission):
        from messagechain.consensus.censorship_evidence import (
            _PendingEvidence,
        )
        return _PendingEvidence(
            evidence_hash=evidence_hash,
            offender_id=offender_id,
            tx_hash=tx_hash,
            admitted_height=admitted_height,
            evidence_tx_hash=evidence_tx_hash,
            staked_at_admission=staked_at_admission,
        )

    def test_orphan_disk_row_does_not_survive_post_reorg_persist(self):
        """Plant canonical state, simulate a losing-fork admission
        that mirrored to disk, set the in-memory pending dict to the
        canonical map (as canonical replay would on a successful
        reorg), run ``_persist_state``, and re-open the chaindb
        against the same path.  The pending_censorship_evidence
        table MUST contain the canonical entries only — no orphan.
        """
        from messagechain.core.blockchain import Blockchain
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        try:
            canon_a_ev = self._ev(b"\xa1")
            canon_a_off = self._ev(b"\xa2")
            canon_a_tx = self._ev(b"\xa3")
            canon_a_evtx = self._ev(b"\xa4")
            canon_b_ev = self._ev(b"\xb1")
            canon_b_off = self._ev(b"\xb2")
            canon_b_tx = self._ev(b"\xb3")
            canon_b_evtx = self._ev(b"\xb4")
            orphan_ev = self._ev(b"\x01")
            orphan_off = self._ev(b"\x02")
            orphan_tx = self._ev(b"\x03")
            orphan_evtx = self._ev(b"\x04")

            # 1. Canonical evidences on disk.
            chain.censorship_processor.pending = {
                canon_a_ev: self._make_pending(
                    canon_a_ev, canon_a_off, canon_a_tx,
                    100, canon_a_evtx, 1_000_000,
                ),
                canon_b_ev: self._make_pending(
                    canon_b_ev, canon_b_off, canon_b_tx,
                    110, canon_b_evtx, 2_000_000,
                ),
            }
            db.set_pending_censorship_evidence(
                canon_a_ev, canon_a_off, canon_a_tx,
                admitted_height=100,
                evidence_tx_hash=canon_a_evtx,
                staked_at_admission=1_000_000,
            )
            db.set_pending_censorship_evidence(
                canon_b_ev, canon_b_off, canon_b_tx,
                admitted_height=110,
                evidence_tx_hash=canon_b_evtx,
                staked_at_admission=2_000_000,
            )
            db.flush_state()

            # 2. Simulate a losing-fork admission: an evidence
            # admitted on the fork tip wrote a row to disk via the
            # chaindb mirror (this is what ``_persist_state`` does
            # in production).
            db.set_pending_censorship_evidence(
                orphan_ev, orphan_off, orphan_tx,
                admitted_height=200,
                evidence_tx_hash=orphan_evtx,
                staked_at_admission=3_000_000,
            )
            db.flush_state()

            # 3. Reorg-equivalent: in-memory state is restored to
            # the canonical pending map (no orphan).  On the
            # SUCCESSFUL reorg path, the in-memory dict is rebuilt
            # from canonical replay; the chaindb mirror is left to
            # ``_persist_state`` to clean up.
            chain.censorship_processor.pending = {
                canon_a_ev: self._make_pending(
                    canon_a_ev, canon_a_off, canon_a_tx,
                    100, canon_a_evtx, 1_000_000,
                ),
                canon_b_ev: self._make_pending(
                    canon_b_ev, canon_b_off, canon_b_tx,
                    110, canon_b_evtx, 2_000_000,
                ),
            }
            chain._dirty_entities = None
            chain._persist_state()

            # 4. Close, re-open, read disk state via a fresh
            # ChainDB connection (mirrors what cold-restart sees
            # when ``_load_from_db`` reads
            # ``get_all_pending_censorship_evidence``).
            self._close_db(db)
            db2 = ChainDB(self.db_path)
            try:
                on_disk = db2.get_all_pending_censorship_evidence()
                self.assertIn(canon_a_ev, on_disk)
                self.assertIn(canon_b_ev, on_disk)
                self.assertNotIn(
                    orphan_ev, on_disk,
                    "Orphan-fork evidence MUST NOT survive a "
                    "reorg + persist cycle.  Pre-fix the row "
                    "survives indefinitely on disk; cold restart "
                    "rehydrates it into "
                    "censorship_processor.pending and the next "
                    "maturity tick slashes a validator the "
                    "canonical chain never accuses.",
                )
                self.assertEqual(
                    set(on_disk.keys()),
                    {canon_a_ev, canon_b_ev},
                    "After a successful-reorg-equivalent persist, "
                    "the on-disk pending_censorship_evidence table "
                    "MUST match the in-memory "
                    "censorship_processor.pending exactly.",
                )
            finally:
                self._close_db(db2)
        finally:
            self._close_db(db)


# ─────────────────────────────────────────────────────────────────────
# Layer 3 — _persist_state cleans up orphan disk rows
# ─────────────────────────────────────────────────────────────────────


class TestPersistStateCleansOrphanPendingCensorshipRows(unittest.TestCase):
    """Even WITHOUT a reorg-restore, a divergence between in-memory
    ``censorship_processor.pending`` and the on-disk mirror MUST be
    reconciled by ``_persist_state``.  This is the second half of
    the fix: ``restore_state_snapshot`` covers the failed-reorg
    rollback path, but the SUCCESSFUL reorg path ends in
    ``_persist_state`` (no chaindb-level restore), so the persist
    must also delete orphan rows whose evidence_hash is no longer
    in the in-memory dict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _ev(self, b: bytes) -> bytes:
        return b * 32

    def test_persist_state_deletes_in_memory_absent_rows(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.censorship_evidence import (
            _PendingEvidence,
        )
        db = ChainDB(self.db_path)
        try:
            chain = Blockchain(db=db)
            # Plant an orphan row on disk that the in-memory dict
            # does NOT contain — simulates the post-successful-reorg
            # state where canonical replay rebuilt the in-memory
            # dict but the chaindb mirror still carries the orphan
            # from the losing fork.
            orphan_ev = self._ev(b"\x01")
            db.set_pending_censorship_evidence(
                orphan_ev,
                self._ev(b"\x02"),
                self._ev(b"\x03"),
                admitted_height=200,
                evidence_tx_hash=self._ev(b"\x04"),
                staked_at_admission=3_000_000,
            )
            db.flush_state()
            self.assertIn(
                orphan_ev,
                db.get_all_pending_censorship_evidence(),
                "Sanity: orphan row planted.",
            )
            # In-memory dict has a different live evidence, no
            # orphan.
            live_ev = self._ev(b"\xa1")
            chain.censorship_processor.pending = {
                live_ev: _PendingEvidence(
                    evidence_hash=live_ev,
                    offender_id=self._ev(b"\xa2"),
                    tx_hash=self._ev(b"\xa3"),
                    admitted_height=100,
                    evidence_tx_hash=self._ev(b"\xa4"),
                    staked_at_admission=1_000_000,
                ),
            }
            # Full flush — mirrors the post-reorg invocation.
            chain._dirty_entities = None
            chain._persist_state()
            on_disk = db.get_all_pending_censorship_evidence()
            self.assertEqual(
                set(on_disk.keys()),
                {live_ev},
                "_persist_state on a full flush MUST delete orphan "
                "pending_censorship_evidence rows whose "
                "evidence_hash is no longer in the in-memory dict.  "
                "Pre-fix the orphan survives indefinitely and "
                "rehydrates on the next cold restart, slashing an "
                "honest validator the canonical chain never "
                "accuses.",
            )
            self.assertNotIn(orphan_ev, on_disk)
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
