"""Symlink-guard for the WOTS+ leaf-cursor advisory lock.

Audit finding: ``_acquire_leaf_cursor_lock`` (``messagechain/crypto/keys.py``)
opened the sibling ``<leaf_index_path>.lock`` file with a plain ``open(...,
"a+")`` — no ``O_NOFOLLOW``, no ``realpath()`` validation, no ``S_ISREG``
post-open assertion.  A local attacker who can pre-create the sibling lock
path as a *symlink* causes two MessageChain processes to follow different
symlinks, take their advisory locks on different files, and BOTH proceed to
sign at the same on-disk leaf cursor.  WOTS+ leaf reuse is a private-key
recovery primitive; this is the highest-severity item in the round-6 audit.

These tests pin the fix:

  1. Symlink at the lock path is refused.
  2. Symlink in the parent directory is refused (realpath guard).
  3. A directory at the lock path is refused (S_ISREG post-open check).
  4. The happy path still works (regression).
  5. Cross-process serialization still works (regression on the lock that
     was just shipped).
  6. Windows refuses symlink lock paths via ``os.path.islink`` pre-check.

The persist-side already mirrors a realpath guard at
``messagechain/crypto/keys.py`` lines ~929-932; this fix lifts the same
defense onto the lock-acquire path.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

import pytest

from messagechain.crypto import keys as keys_module
from messagechain.crypto.keys import KeyPair


# Helper subprocess script copied (and trimmed) from
# tests/test_leaf_cursor_cross_process_lock.py — keeps the regression
# self-contained.
_SUBPROC_SIGN_SCRIPT = textwrap.dedent(
    """\
    import json
    import os
    import sys
    import time

    seed_hex = sys.argv[1]
    leaf_path = sys.argv[2]
    height = int(sys.argv[3])
    msg_byte = int(sys.argv[4])
    barrier_path = sys.argv[5] if len(sys.argv) > 5 else ""

    from messagechain.crypto.keys import KeyPair

    seed = bytes.fromhex(seed_hex)
    kp = KeyPair(seed, height=height)
    kp.leaf_index_path = leaf_path
    kp.load_leaf_index(leaf_path)

    if barrier_path:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not os.path.exists(barrier_path):
            time.sleep(0.005)

    msg = bytes([msg_byte]) * 32
    try:
        sig = kp.sign(msg)
        out = {"ok": True, "leaf_index": sig.leaf_index}
    except Exception as e:
        out = {"ok": False, "error": repr(e)}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    """
)


def _spawn_signer(seed_hex, leaf_path, height, msg_byte, barrier_path=""):
    env = os.environ.copy()
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        repo_root + (os.pathsep + existing if existing else "")
    )
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SUBPROC_SIGN_SCRIPT,
            seed_hex,
            leaf_path,
            str(height),
            str(msg_byte),
            barrier_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


# ----------------------------------------------------------------------
# Test 1.  POSIX: a symlink AT the lock path must be refused.
# ----------------------------------------------------------------------
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX O_NOFOLLOW path; Windows symlink behavior tested separately",
)
class TestLockAcquireRefusesSymlinkLockPath(unittest.TestCase):
    def test_lock_acquire_refuses_symlink_lock_path(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "attacker_target.txt")
            with open(target, "w") as f:
                f.write("UNTOUCHED")
            target_mtime_before = os.path.getmtime(target)

            lock_path = os.path.join(td, "leaf.json.lock")
            os.symlink(target, lock_path)

            with self.assertRaises(
                keys_module.LeafCursorLockSymlinkRefusedError
            ):
                keys_module._acquire_leaf_cursor_lock(lock_path, timeout_s=1.0)

            # The attacker's target file must not have been opened/written.
            with open(target, "r") as f:
                self.assertEqual(f.read(), "UNTOUCHED")
            # And its mtime must not have moved (we don't truncate or
            # touch it via the lock path).
            self.assertEqual(target_mtime_before, os.path.getmtime(target))


# ----------------------------------------------------------------------
# Test 2.  Symlink in the PARENT directory of the lock path is refused.
# Triggers the realpath != abspath guard.
# ----------------------------------------------------------------------
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX symlink semantics; Windows symlinks need elevation",
)
class TestLockAcquireRefusesSymlinkInParentPath(unittest.TestCase):
    def test_lock_acquire_refuses_symlink_in_parent_path(self):
        with tempfile.TemporaryDirectory() as td:
            real_dir = os.path.join(td, "real_wallet")
            os.makedirs(real_dir, exist_ok=True)

            link_dir = os.path.join(td, "link_wallet")
            os.symlink(real_dir, link_dir)

            # Lock path goes through the symlinked parent directory.
            lock_path = os.path.join(link_dir, "leaf.json.lock")

            with self.assertRaises(
                keys_module.LeafCursorLockSymlinkRefusedError
            ):
                keys_module._acquire_leaf_cursor_lock(lock_path, timeout_s=1.0)


# ----------------------------------------------------------------------
# Test 3.  A directory at the lock path is refused via the S_ISREG
# post-open assertion (defense-in-depth even when O_NOFOLLOW lets the
# open succeed).
# ----------------------------------------------------------------------
class TestLockAcquireRefusesDirectoryAtLockPath(unittest.TestCase):
    def test_lock_acquire_refuses_directory_at_lock_path(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = os.path.join(td, "leaf.json.lock")
            os.makedirs(lock_path, exist_ok=True)

            with self.assertRaises(
                keys_module.LeafCursorLockSymlinkRefusedError
            ):
                keys_module._acquire_leaf_cursor_lock(lock_path, timeout_s=1.0)


# ----------------------------------------------------------------------
# Test 4.  Happy path — regular file, no symlinks — still works.
# ----------------------------------------------------------------------
class TestLockAcquireSucceedsOnNormalPath(unittest.TestCase):
    def test_lock_acquire_succeeds_on_normal_path(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = os.path.join(td, "leaf.json.lock")
            handle = keys_module._acquire_leaf_cursor_lock(
                lock_path, timeout_s=1.0,
            )
            self.assertIsNotNone(handle)
            keys_module._release_leaf_cursor_lock(handle)
            # Lock file should exist and be a regular file.
            self.assertTrue(os.path.isfile(lock_path))
            st = os.stat(lock_path)
            self.assertTrue(stat.S_ISREG(st.st_mode))


# ----------------------------------------------------------------------
# Test 5.  Cross-process serialization REGRESSION — the new guard must
# not break the cross-process lock that was just shipped.  Two real
# subprocesses race; both must succeed and consume distinct leaves.
# ----------------------------------------------------------------------
class TestLockAcquireConcurrentProcessesStillSerialize(unittest.TestCase):
    def test_lock_acquire_concurrent_processes_still_serialize(self):
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")
            barrier = os.path.join(td, "go")
            seed_hex = ("\x99" * 32).encode("latin-1").hex()

            p1 = _spawn_signer(seed_hex, leaf_path, 4, 0xAA, barrier)
            p2 = _spawn_signer(seed_hex, leaf_path, 4, 0xBB, barrier)

            time.sleep(0.5)
            with open(barrier, "w") as f:
                f.write("go")

            out1, err1 = p1.communicate(timeout=60)
            out2, err2 = p2.communicate(timeout=60)

            self.assertEqual(
                p1.returncode, 0,
                f"signer 1 failed: {err1.decode(errors='replace')}",
            )
            self.assertEqual(
                p2.returncode, 0,
                f"signer 2 failed: {err2.decode(errors='replace')}",
            )

            r1 = json.loads(out1.decode())
            r2 = json.loads(out2.decode())
            self.assertTrue(r1.get("ok"), f"signer 1: {r1}")
            self.assertTrue(r2.get("ok"), f"signer 2: {r2}")
            self.assertNotEqual(
                r1["leaf_index"], r2["leaf_index"],
                "Symlink guard broke cross-process leaf-cursor lock — "
                "two signers reused the same WOTS+ leaf.",
            )


# ----------------------------------------------------------------------
# Test 6.  Windows-only — symlink at the lock path is refused via the
# os.path.islink pre-check.  Skips if symlink creation fails (the
# default Windows account isn't allowed to create symlinks without
# Developer Mode or admin rights, but the code path is the part we
# actually want to exercise).
# ----------------------------------------------------------------------
@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-specific pre-check; POSIX is covered above",
)
class TestLockAcquireRefusesSymlinkLockPathWindows(unittest.TestCase):
    def test_lock_acquire_refuses_symlink_lock_path_windows(self):
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "attacker_target.txt")
            with open(target, "w") as f:
                f.write("UNTOUCHED")

            lock_path = os.path.join(td, "leaf.json.lock")
            try:
                os.symlink(target, lock_path)
            except (OSError, NotImplementedError) as e:
                self.skipTest(
                    f"Cannot create symlink on this Windows host "
                    f"(needs Developer Mode or admin): {e!r}"
                )

            with self.assertRaises(
                keys_module.LeafCursorLockSymlinkRefusedError
            ):
                keys_module._acquire_leaf_cursor_lock(lock_path, timeout_s=1.0)

            with open(target, "r") as f:
                self.assertEqual(f.read(), "UNTOUCHED")


if __name__ == "__main__":
    unittest.main()
