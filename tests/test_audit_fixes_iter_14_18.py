"""Regression tests for the iter 14-18 audit pass fixes.

Two verified fixes this batch:
1. base_fee upper bound (MAX_BASE_FEE_MULTIPLIER) — prevents unbounded
   spam-fill fee escalation (iter 18)
2. SQLite schema version pin — prevents silent cross-version opens that
   would hide missing columns behind NULL (iter 18)
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.config import MIN_FEE, MAX_BASE_FEE_MULTIPLIER
from messagechain.economics.inflation import SupplyTracker


def _best_effort_rmtree(path: str) -> None:
    """Windows holds sqlite files open briefly after the handle drops;
    ignore the resulting unlink error rather than polluting CI."""
    try:
        shutil.rmtree(path)
    except OSError:
        pass


class TestBaseFeeUpperBound(unittest.TestCase):
    def test_cap_constant_is_sane(self):
        self.assertGreaterEqual(MAX_BASE_FEE_MULTIPLIER, 100)
        self.assertLessEqual(MAX_BASE_FEE_MULTIPLIER, 1_000_000)

    def test_base_fee_stops_growing_at_cap(self):
        from messagechain.config import TARGET_BLOCK_SIZE
        st = SupplyTracker()
        cap = MIN_FEE * MAX_BASE_FEE_MULTIPLIER
        # Force base_fee near cap, then blast full blocks and assert the
        # cap holds.
        st.base_fee = cap - 10
        # Need a meaningful `excess` so delta is non-zero — full blocks
        # past target size.
        full = TARGET_BLOCK_SIZE * 100
        for _ in range(50):
            st.update_base_fee(full)
        self.assertEqual(
            st.base_fee, cap,
            f"base_fee exceeded cap: got {st.base_fee} vs cap {cap}",
        )


class TestChainDBSchemaVersion(unittest.TestCase):
    def test_fresh_db_stamps_schema_version(self):
        from messagechain.storage.chaindb import ChainDB, _SCHEMA_VERSION
        tmp = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            cur = db._conn.execute(
                "SELECT value FROM meta WHERE key = ?", ("schema_version",),
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(int(row[0]), _SCHEMA_VERSION)
            db._local.conn.close()
        finally:
            _best_effort_rmtree(tmp)

    def test_mismatched_schema_version_raises_on_open(self):
        from messagechain.storage.chaindb import ChainDB, _SCHEMA_VERSION
        tmp = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            db._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(_SCHEMA_VERSION + 42)),
            )
            db._conn.commit()
            db._local.conn.close()
            with self.assertRaises(RuntimeError) as ctx:
                ChainDB(db_path)
            self.assertIn("schema version mismatch", str(ctx.exception))
        finally:
            _best_effort_rmtree(tmp)

    def test_non_integer_schema_version_raises(self):
        from messagechain.storage.chaindb import ChainDB
        tmp = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            db._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", "not_a_number"),
            )
            db._conn.commit()
            db._local.conn.close()
            with self.assertRaises(RuntimeError):
                ChainDB(db_path)
        finally:
            _best_effort_rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
