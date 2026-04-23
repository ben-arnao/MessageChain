"""Exclusive data_dir lock — prevents two node processes from sharing a
data_dir and double-signing WOTS+ leaves.

See messagechain.storage.data_dir_lock for the threat model.  These
tests cover the public contract:

* only one holder at a time (within a process and across processes);
* release-then-reacquire works;
* the lockfile is at the expected path with safe mode (POSIX);
* PID is discoverable from the lockfile for forensic/error output;
* the MESSAGECHAIN_SKIP_DATA_DIR_LOCK=1 test escape hatch works.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

from messagechain.storage.data_dir_lock import (
    DataDirLock,
    DataDirLockedError,
    HOLDER_FILE_NAME,
    LOCKFILE_NAME,
)


_IS_POSIX = os.name == "posix"


class TestDataDirLock(unittest.TestCase):

    def setUp(self):
        # Always start with the skip env var cleared so one test can't
        # accidentally mask a real locking bug exposed by another.
        self._orig_skip = os.environ.pop("MESSAGECHAIN_SKIP_DATA_DIR_LOCK", None)

    def tearDown(self):
        os.environ.pop("MESSAGECHAIN_SKIP_DATA_DIR_LOCK", None)
        if self._orig_skip is not None:
            os.environ["MESSAGECHAIN_SKIP_DATA_DIR_LOCK"] = self._orig_skip

    # ------------------------------------------------------------------
    # Test A: second concurrent acquisition fails
    # ------------------------------------------------------------------
    def test_second_acquisition_raises(self):
        with tempfile.TemporaryDirectory() as d:
            first = DataDirLock(d)
            first.__enter__()
            try:
                second = DataDirLock(d)
                with self.assertRaises(DataDirLockedError) as cm:
                    second.__enter__()
                # Error message is operator-facing and should include
                # both the path and the holder PID so diagnosis is
                # one line of output.
                self.assertIn(d, str(cm.exception))
                self.assertIn("PID", str(cm.exception))
            finally:
                first.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Test B: release → reacquire works
    # ------------------------------------------------------------------
    def test_release_then_reacquire(self):
        with tempfile.TemporaryDirectory() as d:
            first = DataDirLock(d)
            first.__enter__()
            first.__exit__(None, None, None)

            # Now a fresh lock should acquire cleanly.
            second = DataDirLock(d)
            second.__enter__()
            try:
                # Sanity: a third would fail while the second holds it.
                third = DataDirLock(d)
                with self.assertRaises(DataDirLockedError):
                    third.__enter__()
            finally:
                second.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Test C: lockfile path + mode (POSIX mode check)
    # ------------------------------------------------------------------
    def test_lockfile_path_and_mode(self):
        with tempfile.TemporaryDirectory() as d:
            lock = DataDirLock(d)
            lock.__enter__()
            try:
                expected = os.path.join(d, LOCKFILE_NAME)
                self.assertTrue(os.path.exists(expected))
                # File name must be '.node.lock'.
                self.assertEqual(LOCKFILE_NAME, ".node.lock")
                if _IS_POSIX:
                    st = os.stat(expected)
                    # Low 9 bits = perm bits.  0o600 = owner r/w only.
                    self.assertEqual(st.st_mode & 0o777, 0o600)
            finally:
                lock.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Test D: lockfile contains our PID, parseable
    # ------------------------------------------------------------------
    def test_lockfile_contains_pid(self):
        with tempfile.TemporaryDirectory() as d:
            lock = DataDirLock(d)
            lock.__enter__()
            try:
                # On POSIX the PID is written inside the lockfile
                # (advisory flock doesn't block other opens).
                # On Windows the lockfile is held exclusively, so the
                # PID metadata is kept in a sibling holder file.
                if _IS_POSIX:
                    read_path = os.path.join(d, LOCKFILE_NAME)
                else:
                    read_path = os.path.join(d, HOLDER_FILE_NAME)
                with open(read_path, "r") as f:
                    contents = f.read()
                # Format: "pid=<int> host=<str>\n"
                self.assertIn("pid=", contents)
                # Extract and parse the pid.
                pid_token = next(
                    t for t in contents.split() if t.startswith("pid=")
                )
                pid_val = int(pid_token.split("=", 1)[1])
                self.assertEqual(pid_val, os.getpid())
            finally:
                lock.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Test E: env override bypasses the lock
    # ------------------------------------------------------------------
    def test_env_override_bypasses_lock(self):
        with tempfile.TemporaryDirectory() as d:
            first = DataDirLock(d)
            first.__enter__()
            try:
                os.environ["MESSAGECHAIN_SKIP_DATA_DIR_LOCK"] = "1"
                second = DataDirLock(d)
                # Should NOT raise despite first holding the lock.
                second.__enter__()
                second.__exit__(None, None, None)
            finally:
                first.__exit__(None, None, None)
                os.environ.pop("MESSAGECHAIN_SKIP_DATA_DIR_LOCK", None)

    def test_env_override_non_one_value_does_not_bypass(self):
        # Defensive: only the literal "1" should bypass — "true", "0",
        # empty-string, etc. must NOT.  A typo shouldn't silently
        # disable the protection.
        with tempfile.TemporaryDirectory() as d:
            first = DataDirLock(d)
            first.__enter__()
            try:
                for bogus in ("", "0", "true", "yes", "on"):
                    os.environ["MESSAGECHAIN_SKIP_DATA_DIR_LOCK"] = bogus
                    second = DataDirLock(d)
                    with self.assertRaises(DataDirLockedError):
                        second.__enter__()
            finally:
                os.environ.pop("MESSAGECHAIN_SKIP_DATA_DIR_LOCK", None)
                first.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Test F: cross-process lock contention (integration)
    # ------------------------------------------------------------------
    def test_subprocess_cannot_acquire_held_lock(self):
        """A second Python process attempting the same lock must fail."""
        with tempfile.TemporaryDirectory() as d:
            lock = DataDirLock(d)
            lock.__enter__()
            try:
                child = textwrap.dedent(f"""\
                    import sys
                    sys.path.insert(0, {repr(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))})
                    from messagechain.storage.data_dir_lock import (
                        DataDirLock, DataDirLockedError,
                    )
                    try:
                        DataDirLock({repr(d)}).__enter__()
                    except DataDirLockedError:
                        sys.exit(42)
                    sys.exit(0)
                """)
                # Run with SKIP env cleared so the child doesn't bypass.
                env = dict(os.environ)
                env.pop("MESSAGECHAIN_SKIP_DATA_DIR_LOCK", None)
                result = subprocess.run(
                    [sys.executable, "-c", child],
                    env=env,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(
                    result.returncode, 42,
                    msg=f"child stdout={result.stdout!r} "
                        f"stderr={result.stderr!r}",
                )
            finally:
                lock.__exit__(None, None, None)

    # ------------------------------------------------------------------
    # Release survives repeated __exit__ calls (defensive)
    # ------------------------------------------------------------------
    def test_double_exit_is_safe(self):
        with tempfile.TemporaryDirectory() as d:
            lock = DataDirLock(d)
            lock.__enter__()
            lock.__exit__(None, None, None)
            # Second exit must not raise.
            lock.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
