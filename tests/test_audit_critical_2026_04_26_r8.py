"""Critical-severity audit fixes -- round 8 (2026-04-26).

Two CRITICAL silent-fork findings on top of v1.16.0:

#1 -- `state_snapshot.py` does not include `key_history`.  The
slash-evidence pipeline reads `_public_key_at_height(entity, h)` for
both single-key (FinalityDoubleVote, signed_at_height) and multi-key
(Attestation/double-proposal candidate set) verification.  A state-
synced node bootstrapping from a checkpoint whose source had any
rotated entities starts with `key_history = {}`, so
`_public_key_at_height` falls back to the CURRENT pubkey.  Slash
evidence whose signing height predates a rotation then verifies
against the wrong key -> rejected on the synced node, admitted on
warm nodes -> silent fork at the slash block.

Fix: bump STATE_SNAPSHOT_VERSION 19 -> 20, add `_TAG_KEY_HISTORY`
section + serializer + leaf builder + install path, mirror through
chaindb.

#2 -- `ChainDB.save_state_snapshot` does not capture
`receipt_subtree_roots`, `past_receipt_subtree_roots`, or
`key_rotation_last_height`, but `restore_state_snapshot` DELETEs all
three tables.  The reorg-failure path at blockchain.py calls
`restore_state_snapshot` then returns without `_persist_state`; in
the post-restore window a process exit (operator restart, OOM,
SIGKILL) cold-restarts the node into empty mirrors.  After the
round-7 forged-receipt fix the empty `receipt_subtree_roots` makes
LEGITIMATE evidence rejected on the cold-restarted node while warm
nodes admit -> silent fork.

Fix: add the three missing keys to `save_state_snapshot`, add three
INSERT loops to `restore_state_snapshot` mirroring the existing
balances/staked/nonces shape.  Belt-and-suspenders: also call
`_persist_state` after `_reset_state` + replay on the failed-reorg
path.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB
from messagechain.storage.state_snapshot import (
    STATE_SNAPSHOT_VERSION,
    _TAG_KEY_HISTORY,
    serialize_state, encode_snapshot, decode_snapshot, deserialize_state,
    compute_state_root,
)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 -- state_snapshot must encode + install key_history
# ─────────────────────────────────────────────────────────────────────


class TestStateSnapshotIncludesKeyHistory(unittest.TestCase):
    """Verify the v20 snapshot pipeline carries key_history end-to-end:
    serialize_state extracts it, encode/decode round-trips it,
    compute_state_root commits to it, and `_install_state_snapshot`
    populates the in-memory dict + chaindb mirror.
    """

    def test_version_bumped_to_20(self):
        self.assertEqual(
            STATE_SNAPSHOT_VERSION, 20,
            "Round-8 fix bumps STATE_SNAPSHOT_VERSION 19 -> 20 to "
            "carry key_history in the wire format and snapshot root.",
        )

    def test_serialize_state_extracts_key_history(self):
        alice = Entity.create(b"r8-c1-extract".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid = b"\x55" * 32
        chain.key_history[eid] = [(0, b"\xa1" * 32), (10, b"\xa2" * 32)]
        snap = serialize_state(chain)
        self.assertIn(
            "key_history", snap,
            "serialize_state MUST extract key_history for the v20 "
            "snapshot root commitment.",
        )
        self.assertEqual(snap["key_history"][eid][0], (0, b"\xa1" * 32))
        self.assertEqual(snap["key_history"][eid][1], (10, b"\xa2" * 32))

    def test_encode_decode_round_trip_preserves_key_history(self):
        alice = Entity.create(b"r8-c1-rt".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        eid_a = b"\x33" * 32
        eid_b = b"\x44" * 32
        chain.key_history[eid_a] = [
            (0, b"\x01" * 32),
            (5, b"\x02" * 32),
            (12, b"\x03" * 32),
        ]
        chain.key_history[eid_b] = [(7, b"\x04" * 32)]
        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))
        self.assertEqual(
            decoded["key_history"][eid_a],
            [(0, b"\x01" * 32), (5, b"\x02" * 32), (12, b"\x03" * 32)],
        )
        self.assertEqual(
            decoded["key_history"][eid_b],
            [(7, b"\x04" * 32)],
        )

    def test_state_root_diverges_when_key_history_differs(self):
        """Two snapshots identical except for key_history MUST produce
        DIFFERENT state roots -- otherwise state-synced nodes that
        observed different rotation histories agree on root but
        disagree on `_public_key_at_height` and silently fork on the
        next slash for a rotated entity."""
        alice = Entity.create(b"r8-c1-div".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        snap_a = serialize_state(chain)
        snap_b = serialize_state(chain)
        snap_a["key_history"] = {}
        snap_b["key_history"] = {b"\x99" * 32: [(0, b"\xee" * 32)]}
        root_a = compute_state_root(snap_a)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(
            root_a, root_b,
            "State-snapshot root MUST commit to key_history under "
            "_TAG_KEY_HISTORY -- silent fork otherwise on the next "
            "slash for a rotated validator.",
        )

    def test_install_state_snapshot_round_trips_key_history(self):
        # Source chain: install a non-trivial key_history via the
        # snapshot dict (bypass live block apply for unit-test speed).
        src_alice = Entity.create(b"r8-c1-src".ljust(32, b"\x00"))
        src = Blockchain()
        src.initialize_genesis(src_alice)
        eid = b"\x77" * 32
        src.key_history[eid] = [(0, b"\xb1" * 32), (3, b"\xb2" * 32)]
        snap = serialize_state(src)
        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))

        dst_alice = Entity.create(b"r8-c1-dst".ljust(32, b"\x00"))
        dst = Blockchain()
        dst.initialize_genesis(dst_alice)
        # Sanity: pre-install dst has no key_history for this entity.
        self.assertNotIn(eid, dst.key_history)

        dst._install_state_snapshot(decoded)

        self.assertIn(
            eid, dst.key_history,
            "_install_state_snapshot MUST install key_history from the "
            "v20 snapshot or `_public_key_at_height` falls back to the "
            "current pubkey for rotated entities -- silent fork at the "
            "next slash for that entity.",
        )
        self.assertEqual(
            dst.key_history[eid],
            [(0, b"\xb1" * 32), (3, b"\xb2" * 32)],
        )

    def test_install_resolves_pre_rotation_key_correctly(self):
        """End-to-end consequence: after install, the synced node's
        `_public_key_at_height` returns the SAME key as the source for
        a pre-rotation height.  Pre-fix the synced node returned the
        post-rotation key, breaking slash-evidence verification."""
        src_alice = Entity.create(b"r8-c1-resolve-src".ljust(32, b"\x00"))
        src = Blockchain()
        src.initialize_genesis(src_alice)
        eid = b"\x66" * 32
        # Two-key history: K1 active at heights [0, 9], K2 from 10 on.
        src.key_history[eid] = [(0, b"\x10" * 32), (10, b"\x20" * 32)]
        # Current pubkey is the post-rotation key.
        src.public_keys[eid] = b"\x20" * 32
        snap = serialize_state(src)
        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))
        dst_alice = Entity.create(b"r8-c1-resolve-dst".ljust(32, b"\x00"))
        dst = Blockchain()
        dst.initialize_genesis(dst_alice)
        dst.public_keys[eid] = b"\x20" * 32  # mirror current key
        dst._install_state_snapshot(decoded)
        # Pre-rotation height: must resolve to K1 on BOTH nodes.
        self.assertEqual(
            src._public_key_at_height(eid, 5), b"\x10" * 32,
            "source resolves pre-rotation key correctly",
        )
        self.assertEqual(
            dst._public_key_at_height(eid, 5), b"\x10" * 32,
            "synced node MUST resolve the same pre-rotation key the "
            "source resolves -- otherwise slash-evidence verification "
            "diverges and the chain forks at the slash block.",
        )

    def test_tag_key_history_present(self):
        """Sanity: the _TAG_KEY_HISTORY constant exists and is the
        documented 5-byte prefix (`khist`).  Locking the bytes means
        a future rename can't silently shift the snapshot-root
        section ordering."""
        self.assertEqual(_TAG_KEY_HISTORY, b"khist")


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2 -- chaindb save/restore symmetry for receipt-roots +
#                key_rotation_last_height
# ─────────────────────────────────────────────────────────────────────


class TestChaindbSaveRestoreSymmetry(unittest.TestCase):
    """`save_state_snapshot` MUST capture the three mirror tables that
    `restore_state_snapshot` deletes.  Verify the round-trip by:
      1. Populating the tables.
      2. Snapshotting.
      3. Wiping the live tables (simulating mid-restore).
      4. Restoring from the snapshot.
      5. Asserting the tables are repopulated.

    Without this round-trip, the post-restore window between
    `restore_state_snapshot` and the next `_persist_state` flush is
    crash-fatal -- a cold restart silently forks on the next contested
    CensorshipEvidence (round-7 forged-receipt fix means an empty
    `receipt_subtree_roots` rejects all evidence) or admits a rotation
    the warm cluster rejects under the cooldown gate.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_state_snapshot_includes_receipt_subtree_roots(self):
        db = ChainDB(self.db_path)
        try:
            eid_a = b"\xaa" * 32
            db.set_receipt_subtree_root(eid_a, b"\x01" * 32)
            db.add_past_receipt_subtree_root(eid_a, b"\x02" * 32)
            db.set_key_rotation_last_height(eid_a, 100)
            snap = db.save_state_snapshot()
            self.assertIn(
                "receipt_subtree_roots", snap,
                "save_state_snapshot MUST include receipt_subtree_roots "
                "or restore wipes the table without re-population -- "
                "cold restart in the post-restore window forks on the "
                "next contested CensorshipEvidence.",
            )
            self.assertEqual(
                snap["receipt_subtree_roots"][eid_a], b"\x01" * 32,
            )
            self.assertIn(
                "past_receipt_subtree_roots", snap,
                "save_state_snapshot MUST include past_receipt_subtree_roots",
            )
            self.assertIn(
                b"\x02" * 32, snap["past_receipt_subtree_roots"][eid_a],
            )
            self.assertIn(
                "key_rotation_last_height", snap,
                "save_state_snapshot MUST include key_rotation_last_height "
                "or restore wipes the cooldown table -- cold restart "
                "bypasses the rotation cooldown gate.",
            )
            self.assertEqual(
                snap["key_rotation_last_height"][eid_a], 100,
            )
        finally:
            db.close()

    def test_restore_state_snapshot_repopulates_receipt_subtree_roots(self):
        db = ChainDB(self.db_path)
        try:
            eid = b"\xbb" * 32
            db.set_receipt_subtree_root(eid, b"\x11" * 32)
            db.add_past_receipt_subtree_root(eid, b"\x12" * 32)
            db.set_key_rotation_last_height(eid, 200)
            snap = db.save_state_snapshot()
            db.flush_state()
            # Mutate the live tables (simulate a losing-fork rotation
            # that the snapshot must roll us back from).
            db.set_receipt_subtree_root(eid, b"\xee" * 32)  # wrong root
            db.add_past_receipt_subtree_root(eid, b"\xef" * 32)
            db.set_key_rotation_last_height(eid, 999)
            # Commit any auto-opened DML tx so restore's BEGIN can fire.
            db._conn.commit()
            # Restore -- the round-8 fix wipes AND re-inserts these
            # tables atomically inside the restore transaction.
            db.restore_state_snapshot(snap)
            roots = db.get_all_receipt_subtree_roots()
            self.assertEqual(
                roots[eid], b"\x11" * 32,
                "restore_state_snapshot MUST re-populate "
                "receipt_subtree_roots from the snapshot dict; "
                "pre-fix the table was wiped without re-insertion, "
                "leaving the cold-restart window with an empty map.",
            )
            past = db.get_all_past_receipt_subtree_roots()
            self.assertIn(b"\x12" * 32, past[eid])
            self.assertNotIn(
                b"\xef" * 32, past.get(eid, set()),
                "Losing-fork past root should NOT survive the restore",
            )
            cooldown = db.get_all_key_rotation_last_height()
            self.assertEqual(
                cooldown[eid], 200,
                "restore_state_snapshot MUST re-populate "
                "key_rotation_last_height from the snapshot dict.",
            )
        finally:
            db.close()

    def test_cold_restart_after_restore_sees_full_state(self):
        """End-to-end: snapshot, mutate, restore, CLOSE the DB,
        re-open, and verify the rehydrated maps match the snapshot.
        This is the exact crash-recovery path that motivated the fix."""
        db = ChainDB(self.db_path)
        try:
            eid = b"\xcc" * 32
            db.set_receipt_subtree_root(eid, b"\x21" * 32)
            db.add_past_receipt_subtree_root(eid, b"\x22" * 32)
            db.set_key_rotation_last_height(eid, 300)
            snap = db.save_state_snapshot()
            db.set_receipt_subtree_root(eid, b"\xff" * 32)
            db.set_key_rotation_last_height(eid, 9999)
            db.flush_state()
            db.restore_state_snapshot(snap)
        finally:
            db.close()
        # Cold reopen.
        db2 = ChainDB(self.db_path)
        try:
            roots = db2.get_all_receipt_subtree_roots()
            self.assertEqual(
                roots[eid], b"\x21" * 32,
                "After cold restart following a restore, the mirror "
                "table MUST hold the snapshot value -- this is the "
                "crash-window the round-8 fix closes.",
            )
            past = db2.get_all_past_receipt_subtree_roots()
            self.assertIn(b"\x22" * 32, past.get(eid, set()))
            cooldown = db2.get_all_key_rotation_last_height()
            self.assertEqual(cooldown[eid], 300)
        finally:
            db2.close()


if __name__ == "__main__":
    unittest.main()
