"""Audit r33 #3 -- `messagechain doctor` MUST check leaf-index file
presence and freshness.

Pre-fix `run_doctor` checks: python, data-dir, keyfile, disk, two
ports, seeds, optional systemd timers -- NO leaf-index check.  The
README warns in prose that a keyfile-without-leaf-index restore is
a 100% slash event ("Operating a live validator -> Back up the
keyfile AND the leaf-index files"), but the diagnostic command
operators are told to trust silently approves the fatal config.

Concrete bite: operator restores on a fresh disk from "keyfile
only" backup.  Runs `messagechain doctor` -- GREEN.  Starts the
validator -- the chaindb gets rebuilt from peer sync, but the
leaf-index cursor starts at 0.  The first sign re-uses leaf 0,
publishing a second signature at a leaf the chain's leaf_watermark
already records as burned.  Equivocation evidence lands; 100%
stake slash.

CLAUDE.md anchor at risk: "honest operators are insured against
accidents... when an honest node IS slashed, the burn is a small
*fraction* of stake, not a wipe."  100% slash on what is
structurally a backup mistake is a wipe; the chain could surface
the misconfig before the slash fires.

Fix: a new `_check_leaf_index(data_dir, entity_id_hex,
chaindb_open_fn=None)` helper added to the doctor checklist:

  * data_dir or entity_id_hex unset -> WARN (skip, fresh install).
  * No chain.db AND no leaf_index.json -> GREEN (fresh node).
  * No chain.db, leaf_index.json present  -> GREEN (offline wallet,
    no signing history yet on this host).
  * chain.db present with leaf_watermark[entity]==0 AND no
    leaf_index.json -> GREEN (the entity has never signed; even a
    restored chaindb has no slashable history for this validator).
  * chain.db present with leaf_watermark[entity]>0 AND no
    leaf_index.json -> RED (RESTORE WITHOUT CURSOR -- next sign
    will re-use a burned leaf).
  * chain.db present with leaf_watermark[entity]>0 AND
    leaf_index.json present but cursor < watermark -> RED (STALE
    CURSOR -- next sign will re-use a burned leaf).
  * chain.db present with leaf_watermark[entity]>0 AND
    leaf_index.json present with cursor >= watermark -> GREEN.

Soft fix: doctor-only, no consensus rule change, no fork.  The
catastrophic config is detected before the daemon is started, so
the slash never fires.
"""

from __future__ import annotations

import inspect
import json
import os
import sqlite3
import tempfile
import unittest


def _build_chaindb_with_watermark(
    data_dir: str, entity_id_hex: str, watermark: int,
):
    """Materialize a minimal chain.db with one row in the
    leaf_watermarks table for the given entity at the given
    watermark.  We don't need a fully-populated database -- the
    doctor check only reads leaf_watermarks for one entity."""
    db_path = os.path.join(data_dir, "chain.db")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE leaf_watermarks ("
            " entity_id BLOB PRIMARY KEY,"
            " next_leaf INTEGER NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT INTO leaf_watermarks (entity_id, next_leaf) "
            "VALUES (?, ?)",
            (bytes.fromhex(entity_id_hex), int(watermark)),
        )
        conn.commit()
    finally:
        conn.close()


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="mc-doctor-leaf-")
        self.entity_hex = "ab" * 32  # 64-char hex

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_leaf_index(self, cursor: int):
        from messagechain.config import LEAF_INDEX_FILENAME
        path = os.path.join(self._tmp, LEAF_INDEX_FILENAME)
        with open(path, "w") as f:
            json.dump({"_next_leaf": cursor}, f)


class TestCheckExists(_Base):
    """Source pin: `_check_leaf_index` MUST exist as a module-level
    helper in onboarding.py and MUST be invoked by `run_doctor`.
    Without these source pins the regression is silent -- a future
    refactor that drops the call would re-open the catastrophic
    silent-GREEN window."""

    def test_helper_exists(self):
        from messagechain.runtime import onboarding
        self.assertTrue(
            hasattr(onboarding, "_check_leaf_index"),
            "onboarding._check_leaf_index MUST exist -- doctor "
            "leaf-index check is the defense against keyfile-"
            "without-cursor restore wipes.",
        )

    def test_run_doctor_source_invokes_helper(self):
        from messagechain.runtime.onboarding import run_doctor
        src = inspect.getsource(run_doctor)
        self.assertIn(
            "_check_leaf_index", src,
            "run_doctor MUST invoke _check_leaf_index in its "
            "checklist -- otherwise the disaster path stays "
            "GREEN-lit.",
        )


class TestFreshNodeGreen(_Base):
    """Behavioral pin: no chain.db, no leaf_index.json -> GREEN.
    A fresh install hasn't signed and has no chaindb history; the
    leaf-index cursor will be created on first sign."""

    def test_no_chaindb_no_cursor_is_green(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        res = _check_leaf_index(self._tmp, self.entity_hex)
        self.assertEqual(
            res.level, 0,
            f"Fresh install (no chain.db, no leaf cursor) MUST "
            f"return GREEN; got level={res.level} ({res.detail}).",
        )


class TestRestoreWithoutCursorRed(_Base):
    """Behavioral pin: chain.db has leaf_watermark[entity]>0 AND no
    leaf_index.json -> RED.  This is the README-warned disaster
    path: operator restored from keyfile-only backup, chaindb is
    fresh-synced, the entity has signed history on chain, the
    next sign re-uses a burned leaf."""

    def test_chaindb_with_history_no_cursor_is_red(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        _build_chaindb_with_watermark(self._tmp, self.entity_hex, 42)
        # No leaf_index.json written.
        res = _check_leaf_index(self._tmp, self.entity_hex)
        self.assertEqual(
            res.level, 2,
            f"Chaindb with leaf_watermark[entity]>0 + no leaf "
            f"cursor MUST be RED (level=2); got level={res.level} "
            f"({res.detail}).  This is the catastrophic restore-"
            f"without-cursor signature -- starting the daemon "
            f"would re-use a burned leaf and 100%-slash the "
            f"validator.",
        )


class TestStaleCursorRed(_Base):
    """Behavioral pin: chain.db says watermark=N, on-disk cursor
    says <N -> RED.  Stale-cursor is functionally identical to
    no-cursor -- the next sign re-uses a leaf the chain has
    already recorded as burned."""

    def test_cursor_behind_chain_watermark_is_red(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        _build_chaindb_with_watermark(self._tmp, self.entity_hex, 42)
        self._write_leaf_index(cursor=10)  # behind chain
        res = _check_leaf_index(self._tmp, self.entity_hex)
        self.assertEqual(
            res.level, 2,
            f"Stale cursor (file cursor=10, chain watermark=42) "
            f"MUST be RED (level=2); got level={res.level} "
            f"({res.detail}).",
        )


class TestCurrentCursorGreen(_Base):
    """Behavioral pin: chain.db says watermark=N, on-disk cursor
    >= N -> GREEN.  Healthy operational state."""

    def test_cursor_ahead_of_chain_is_green(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        _build_chaindb_with_watermark(self._tmp, self.entity_hex, 42)
        self._write_leaf_index(cursor=42)
        res = _check_leaf_index(self._tmp, self.entity_hex)
        self.assertEqual(
            res.level, 0,
            f"Cursor at chain watermark MUST be GREEN; "
            f"got level={res.level} ({res.detail}).",
        )

    def test_cursor_strictly_ahead_is_green(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        _build_chaindb_with_watermark(self._tmp, self.entity_hex, 42)
        self._write_leaf_index(cursor=50)  # ahead = recent local
        res = _check_leaf_index(self._tmp, self.entity_hex)
        self.assertEqual(
            res.level, 0,
            f"Cursor strictly ahead of chain (recent local sign) "
            f"MUST be GREEN; got level={res.level} ({res.detail}).",
        )


class TestNoEntityIdHexWarn(_Base):
    """Behavioral pin: entity_id_hex unset (config not yet written)
    -> WARN (level=1).  Doctor on a brand-new install before the
    operator runs `init` should not fail-RED."""

    def test_no_entity_warns_not_red(self):
        from messagechain.runtime.onboarding import _check_leaf_index
        res = _check_leaf_index(self._tmp, "")
        self.assertLess(
            res.level, 2,
            f"Empty entity_id_hex MUST NOT be RED; "
            f"got level={res.level} ({res.detail}).",
        )


class TestRunDoctorIncludesLeafIndex(_Base):
    """End-to-end pin: `run_doctor` returned check list MUST
    include a leaf-index entry.  Source-pin tests above ensure
    the call is wired; this confirms the result lands in the
    visible checklist."""

    def test_doctor_checklist_includes_leaf_index(self):
        from collections import namedtuple
        from messagechain.runtime.onboarding import run_doctor
        # Minimal cfg: data_dir + entity_id_hex configured but no
        # chaindb/cursor on disk -- exercises the fresh-install
        # branch.  Stub bind/connect/disk to avoid socket / fs
        # heuristics.
        cfg = {
            "data_dir": self._tmp,
            "keyfile": os.path.join(self._tmp, "no-such-keyfile"),
            "entity_id_hex": self.entity_hex,
            "auto_upgrade": False,
            "auto_rotate": False,
        }
        DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
        worst, results = run_doctor(
            onboard_cfg=cfg,
            data_dir=self._tmp,
            seeds=[],
            bind_fn=lambda port: (True, ""),  # ports bindable
            connect_fn=lambda host, port: True,
            disk_usage_fn=lambda path: DiskUsage(
                total=100 * 1024**3, used=90 * 1024**3, free=10 * 1024**3,
            ),
        )
        labels = [r.label for r in results]
        self.assertTrue(
            any("leaf" in lbl.lower() for lbl in labels),
            f"run_doctor result list MUST contain a leaf-index "
            f"entry; got labels={labels}.",
        )


if __name__ == "__main__":
    unittest.main()
