"""Regression tests for the `messagechain prune-fork-branches` CLI
added after the 2026-05-22 chain.db pollution incident on validator-1.

The 1.89.0 cold-load ChainIntegrityError correctly refused to load
validator-1's chain.db after the prior incident left 37 non-canonical
fork-branch rows in it.  The operator's only recovery options at the
time were (a) splice a healthy chain.db from validator-2, or (b)
hand-craft DELETE statements.  This CLI is the third option: walk
the canonical chain from best_tip via prev_hash, then DELETE every
blocks-row whose block_hash is NOT on it.

Tests build a synthetic chain.db with a canonical chain plus some
fork-branch rows, then assert:

  1. Dry-run prints the planned deletions but doesn't mutate the file.
  2. Apply mode deletes all non-canonical rows and leaves the
     canonical chain intact.
  3. A daemon-locked data_dir is refused (the CLI refuses to operate
     on a live db).
  4. A clean chain.db (zero fork branches) is a no-op.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest


def _make_synthetic_chaindb(path: str, canonical_heights: int, fork_heights: list[int]) -> tuple[bytes, int]:
    """Build a minimal chain.db with the schema columns the CLI
    actually reads (blocks: block_hash, prev_hash, block_number, data;
    chain_tips: tip_hash, block_number, cumulative_weight).  Returns
    the canonical tip hash + height for the test's assertions."""
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE blocks ("
        "block_hash BLOB PRIMARY KEY, "
        "prev_hash BLOB, "
        "block_number INTEGER, "
        "data BLOB)"
    )
    con.execute(
        "CREATE TABLE chain_tips ("
        "tip_hash BLOB PRIMARY KEY, "
        "block_number INTEGER, "
        "cumulative_weight INTEGER)"
    )

    def _h(n: int, suffix: str = "c") -> bytes:
        # Deterministic 32-byte hash from (block_number, suffix).
        return f"{n:06d}-{suffix}-".encode("utf-8").ljust(32, b"\x00")

    prev = b"\x00" * 32
    canonical_tip = None
    for n in range(canonical_heights):
        h = _h(n, "c")
        con.execute(
            "INSERT INTO blocks(block_hash, prev_hash, block_number, data) "
            "VALUES (?, ?, ?, ?)",
            (h, prev, n, b"canonical-" + str(n).encode()),
        )
        prev = h
        canonical_tip = (h, n)

    for n in fork_heights:
        if n >= canonical_heights:
            continue
        # Fork-branch row at height n with a non-canonical hash.
        # prev_hash points at the canonical (n-1) hash so the row is
        # a sibling, not an orphan.
        fork_prev = _h(n - 1, "c") if n > 0 else b"\x00" * 32
        con.execute(
            "INSERT INTO blocks(block_hash, prev_hash, block_number, data) "
            "VALUES (?, ?, ?, ?)",
            (_h(n, "f"), fork_prev, n, b"fork-" + str(n).encode()),
        )
        # Also register the fork-tip in chain_tips with LOWER weight
        # so the canonical-tip-by-cumulative-weight selection picks
        # the canonical one.
        con.execute(
            "INSERT INTO chain_tips(tip_hash, block_number, cumulative_weight) "
            "VALUES (?, ?, ?)",
            (_h(n, "f"), n, 1),
        )

    # Canonical tip row.
    assert canonical_tip is not None
    con.execute(
        "INSERT INTO chain_tips(tip_hash, block_number, cumulative_weight) "
        "VALUES (?, ?, ?)",
        (canonical_tip[0], canonical_tip[1], 1_000_000),
    )
    con.commit()
    con.close()
    return canonical_tip


def _run_cli(*args, data_dir: str) -> tuple[int, str]:
    """Invoke `python -m messagechain --data-dir <dd> prune-fork-branches [args]`.
    Returns (exit_code, combined_stdout_stderr)."""
    cmd = [
        sys.executable, "-m", "messagechain",
        "--data-dir", data_dir, "prune-fork-branches",
    ] + list(args)
    res = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30,
    )
    return res.returncode, (res.stdout or "") + (res.stderr or "")


class TestPruneForkBranchesCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-prune-test-")
        self.chain_db = os.path.join(self.tmp, "chain.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _count_rows(self):
        con = sqlite3.connect(self.chain_db)
        n_blocks = con.execute("SELECT count(*) FROM blocks").fetchone()[0]
        n_tips = con.execute("SELECT count(*) FROM chain_tips").fetchone()[0]
        con.close()
        return n_blocks, n_tips

    def test_dry_run_does_not_mutate(self):
        # 5 canonical blocks + 3 fork branches at heights 1, 2, 3.
        _make_synthetic_chaindb(
            self.chain_db, canonical_heights=5, fork_heights=[1, 2, 3],
        )
        before_blocks, before_tips = self._count_rows()
        self.assertEqual(before_blocks, 8)
        self.assertEqual(before_tips, 4)  # 1 canonical + 3 fork tips

        code, out = _run_cli("--dry-run", data_dir=self.tmp)
        self.assertEqual(code, 0, msg=out)
        self.assertIn("non-canonical rows to delete: 3", out)
        self.assertIn("Dry-run", out)

        after_blocks, after_tips = self._count_rows()
        self.assertEqual(after_blocks, before_blocks,
            "dry-run must not delete any blocks rows")
        self.assertEqual(after_tips, before_tips,
            "dry-run must not delete any chain_tips rows")

    def test_apply_deletes_fork_branches_and_preserves_canonical(self):
        canonical_tip, canonical_tip_h = _make_synthetic_chaindb(
            self.chain_db, canonical_heights=10, fork_heights=[3, 5, 7, 9],
        )
        code, out = _run_cli(data_dir=self.tmp)
        self.assertEqual(code, 0, msg=out)
        self.assertIn("Deleted 4 non-canonical block rows", out)

        # The 10 canonical rows stay; the 4 fork rows are gone.
        n_blocks, n_tips = self._count_rows()
        self.assertEqual(n_blocks, 10)
        # Only the canonical tip remains in chain_tips.
        self.assertEqual(n_tips, 1)
        con = sqlite3.connect(self.chain_db)
        rows = con.execute(
            "SELECT tip_hash FROM chain_tips"
        ).fetchall()
        con.close()
        self.assertEqual(bytes(rows[0][0]), canonical_tip)

    def test_clean_chaindb_is_noop(self):
        _make_synthetic_chaindb(
            self.chain_db, canonical_heights=5, fork_heights=[],
        )
        before_blocks, before_tips = self._count_rows()
        code, out = _run_cli(data_dir=self.tmp)
        self.assertEqual(code, 0, msg=out)
        self.assertIn("chain.db is clean -- nothing to prune", out)
        after_blocks, after_tips = self._count_rows()
        self.assertEqual(before_blocks, after_blocks)
        self.assertEqual(before_tips, after_tips)

    @unittest.skipIf(os.name == "nt", "fcntl-based daemon-running gate is POSIX-only")
    def test_refuses_when_daemon_lock_held(self):
        # The CLI's daemon-running gate uses fcntl.flock on .node.lock.
        # If the lock can be acquired non-blockingly, the daemon is
        # NOT running -- safe to prune.  If acquisition fails (held
        # by another process), refuse.  Simulate the held-lock state
        # by acquiring the lock in this test process.
        _make_synthetic_chaindb(
            self.chain_db, canonical_heights=3, fork_heights=[1],
        )
        lock_path = os.path.join(self.tmp, ".node.lock")
        open(lock_path, "w").close()
        import fcntl
        held = open(lock_path, "r+")
        try:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX)
            code, out = _run_cli(data_dir=self.tmp)
            self.assertNotEqual(code, 0,
                "prune must refuse to operate on a live db")
            self.assertIn("daemon appears to be running", out)
        finally:
            try: fcntl.flock(held.fileno(), fcntl.LOCK_UN)
            except OSError: pass
            held.close()


if __name__ == "__main__":
    unittest.main()
