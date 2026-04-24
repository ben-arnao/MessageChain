"""
Tests for the chain.db schema v1 -> v2 migration.

v2 added six consensus-visible state surfaces that v1 chain.db
files don't carry: `reputation`, `key_history`, `pending_unstakes`,
`stake_snapshots`, and the two `supply_meta` scalars
`blocks_since_last_finalization` and `lottery_prize_pool`.

Without an explicit schema bump + migration, an operator who
upgrades the binary on an existing chain.db would have the
new tables created empty by `CREATE TABLE IF NOT EXISTS` and the
new supply_meta keys return 0 via the missing-key fallback --
which is precisely the cold-restart divergence the six
persistence fixes in this session were designed to close.

The tests here:

1. Prove `_SCHEMA_VERSION` is now 2 (regression gate against the
   version staying stuck as new tables are added).
2. Prove the tripwire fires with an actionable migrate-chain-db
   message on a v1 DB.
3. Prove `skip_schema_check=True` lets the migration CLI open a
   v1 DB without tripping the guard.
4. Prove `migrate_schema_v1_to_v2` is idempotent -- running it
   after the stamp would be a no-op.
5. Prove the migration stamps schema_version to 2.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest

from messagechain.storage.chaindb import ChainDB, _SCHEMA_VERSION


def _close_chaindb(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


def _write_v1_schema_marker(db_path: str) -> None:
    """Stamp the meta.schema_version row to 1 so a fresh DB looks
    like a v1 DB to the tripwire.  We do this by opening with
    skip_schema_check and overwriting the row that the v2 __init__
    just wrote.  Mirrors what an old binary would have left behind
    on disk."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("schema_version", "1"),
        )
        conn.commit()
    finally:
        conn.close()


class TestSchemaVersionConstant(unittest.TestCase):
    def test_schema_version_is_current(self):
        """Regression gate: if a new consensus-visible state surface
        lands in chaindb.py without bumping this constant, the
        previous cold-restart-persistence fixes are inert for
        upgrading operators.  Bump this AND write a migration
        whenever a new table / supply_meta key is added.

        Current code is at v3 (Tier 10 prev-pointer tx_locations index
        on top of the v2 cold-restart surfaces).
        """
        self.assertEqual(_SCHEMA_VERSION, 3)


class TestV1DBTripwireFiresActionably(unittest.TestCase):
    """Opening a v1-stamped DB under the current binary must refuse to
    start and point the operator at `migrate-chain-db`."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_v1_db_refuses_to_open_normally(self):
        path = self._fresh_chaindb()
        # Seed the file with the current schema, then stamp schema_version=1.
        db = ChainDB(path)
        _close_chaindb(db)
        _write_v1_schema_marker(path)

        with self.assertRaises(RuntimeError) as ctx:
            ChainDB(path)
        msg = str(ctx.exception)
        self.assertIn("schema version mismatch", msg)
        self.assertIn("disk=1", msg)
        # v3 code opens a v1 DB and the generic tripwire message
        # fires — specific v1→v2 hint is only shown when _SCHEMA_VERSION
        # itself is 2.  Either way, the CLI's migrate-chain-db path
        # handles the v1→v2→v3 cascade.
        self.assertIn("migration is required", msg)

    def test_skip_schema_check_allows_v1_open(self):
        path = self._fresh_chaindb()
        db = ChainDB(path)
        _close_chaindb(db)
        _write_v1_schema_marker(path)

        # Does not raise: migration path uses this flag.
        db2 = ChainDB(path, skip_schema_check=True)
        # And it can read schema_version directly.
        cur = db2._conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",),
        )
        self.assertEqual(cur.fetchone()[0], "1")
        _close_chaindb(db2)


class TestV1ToV2MigrationStamps(unittest.TestCase):
    """`migrate_schema_v1_to_v2` must stamp schema_version to 2 and
    leave a DB that opens under the normal tripwire path."""

    def _fresh_chaindb(self):
        tmp_dir = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp_dir, True)
        return os.path.join(tmp_dir, "chain.db")

    def test_migration_stamps_v2(self):
        """`migrate_schema_v1_to_v2` stamps schema_version=2 on disk.

        Under the current v3 binary this leaves the DB at v2 — an
        intermediate state — so a second ChainDB open without bypass
        still trips the tripwire (2 → 3).  The `messagechain migrate-
        chain-db` CLI path cascades v1 → v2 → v3 in one invocation;
        this test exercises only the first leg.
        """
        path = self._fresh_chaindb()
        db = ChainDB(path)
        _close_chaindb(db)
        _write_v1_schema_marker(path)

        # Migrate v1 → v2 with the bypass flag.
        db2 = ChainDB(path, skip_schema_check=True)
        summary = db2.migrate_schema_v1_to_v2()
        db2.flush_state()
        _close_chaindb(db2)

        # Summary shape.
        self.assertEqual(summary["schema_from"], 1)
        self.assertEqual(summary["schema_to"], 2)

        # Direct read of the stamped row (bypassing the tripwire).
        db3 = ChainDB(path, skip_schema_check=True)
        cur = db3._conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",),
        )
        self.assertEqual(cur.fetchone()[0], "2")
        _close_chaindb(db3)

    def test_full_v1_to_v3_cascade(self):
        """Running both migrations in sequence lands on the current
        version and passes the tripwire on normal reopen."""
        path = self._fresh_chaindb()
        db = ChainDB(path)
        _close_chaindb(db)
        _write_v1_schema_marker(path)

        db2 = ChainDB(path, skip_schema_check=True)
        db2.migrate_schema_v1_to_v2()
        v3_summary = db2.migrate_schema_v2_to_v3()
        db2.flush_state()
        _close_chaindb(db2)

        self.assertEqual(v3_summary["schema_from"], 2)
        self.assertEqual(v3_summary["schema_to"], 3)

        # Normal open must succeed now.
        db3 = ChainDB(path)
        cur = db3._conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",),
        )
        self.assertEqual(cur.fetchone()[0], "3")
        _close_chaindb(db3)


if __name__ == "__main__":
    unittest.main()
