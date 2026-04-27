"""Cross-process WOTS+ leaf-cursor advisory file lock.

Audit finding: the leaf-index file (`<home>/.messagechain/leaves/<entity>.idx`
for CLI users, `<data_dir>/leaf_index.json` for daemons) had no cross-process
file lock.  Two concurrent CLI invocations on the same wallet (shell loop,
retry-while-pending, two terminal panes, GUI shim dispatching twice) could
both read leaf=N, both pass the in-process `_sign_lock` (which is a
``threading.Lock``, per-process), both persist N+1, both sign at leaf N.
WOTS+ leaf reuse mathematically reveals the leaf's private key — an attacker
who scrapes both signatures from the chain or mempool can forge new txs at
that leaf (spend balance, rotate key, impersonate identity).

The fix: a sibling-file advisory lock (``<leaf_index_path>.lock``) acquired
inside ``KeyPair.sign`` BEFORE ``load_leaf_index`` reads the cursor and held
THROUGH ``persist_leaf_index`` until after the file is flushed and renamed.
The lock uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows.
A 30-second timeout prevents indefinite blocking; on timeout we raise
``LeafCursorLockTimeoutError`` with a message naming the entity so operators
can clear stuck processes.

These tests lock in the cross-process safety property: even when two
honest invocations race on the same on-disk cursor, they MUST consume
distinct leaves.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

from messagechain.crypto import keys as keys_module
from messagechain.crypto.keys import KeyPair


def _make_keypair(leaf_path=None, height=4, seed=b"\x33" * 32):
    """Build a small KeyPair, optionally wired to a leaf-index file."""
    kp = KeyPair(seed, height=height)
    if leaf_path is not None:
        kp.leaf_index_path = leaf_path
    return kp


def _read_persisted_leaf(path):
    with open(path, "r") as f:
        return json.load(f)["next_leaf"]


# Helper script body for subprocess-based race tests.  Imports are inside
# so the script is self-contained and works under any cwd.  The script
# signs once and writes (leaf_index, exit_code) to its stdout as JSON.
_SUBPROC_SIGN_SCRIPT = textwrap.dedent(
    """\
    import json
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

    # Optional rendezvous: wait until barrier_path exists, so two procs
    # cross the lock acquisition point at very nearly the same time.
    if barrier_path:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not __import__("os").path.exists(barrier_path):
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
    """Spawn a subprocess that signs once and returns (proc, ...).

    The subprocess inherits PYTHONPATH from the test runner so the
    in-tree messagechain package is importable.
    """
    env = os.environ.copy()
    # Make sure the worktree's messagechain package is importable.
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
# Test 1.  Two concurrent signs on the same on-disk cursor MUST consume
# different leaves.  We use real subprocesses because thread-level races
# are masked by the in-process ``_sign_lock``; a ``threading.Lock`` does
# nothing when the second signer lives in another OS process.
# ----------------------------------------------------------------------
class TestConcurrentSignsDoNotReuseLeaf(unittest.TestCase):
    def test_two_concurrent_signs_same_keypair_same_path_do_not_reuse_leaf(self):
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")
            barrier = os.path.join(td, "go")
            seed_hex = ("\x77" * 32).encode("latin-1").hex()

            p1 = _spawn_signer(seed_hex, leaf_path, 4, 0xAA, barrier)
            p2 = _spawn_signer(seed_hex, leaf_path, 4, 0xBB, barrier)

            # Start the gun.  Both children should already be parked at
            # the barrier check; touching the barrier file releases them
            # within the same ~5ms window.
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
                "Two concurrent signers reused the same WOTS+ leaf — "
                "this is the catastrophic key-disclosure race.",
            )
            # Persisted cursor must reflect both consumptions: at minimum
            # both leaves used must be < persisted next_leaf.
            persisted = _read_persisted_leaf(leaf_path)
            self.assertGreater(persisted, max(r1["leaf_index"], r2["leaf_index"]))


# ----------------------------------------------------------------------
# Test 2.  The lock serializes signers: the second signer's acquisition
# must happen AFTER the first signer's release.  We instrument the lock
# helpers in keys_module so we can record the timestamps.
# ----------------------------------------------------------------------
class TestConcurrentSignsSerializeThroughFileLock(unittest.TestCase):
    def test_concurrent_signs_serialize_through_file_lock(self):
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")

            # Two keypairs, same seed + same path: simulates two
            # processes (or two CLI invocations) holding independent
            # in-memory state but sharing the on-disk cursor.
            seed = b"\x44" * 32
            kp1 = KeyPair(seed, height=4)
            kp1.leaf_index_path = leaf_path
            kp2 = KeyPair(seed, height=4)
            kp2.leaf_index_path = leaf_path

            # Each KeyPair gets its own in-memory _sign_lock by
            # construction, so the only thing that can serialize them
            # is the cross-process file lock under test.
            self.assertIsNot(kp1._sign_lock, kp2._sign_lock)

            events = []  # list of ("a"|"r", thread_ident, t)
            events_lock = threading.Lock()

            real_acquire = keys_module._acquire_leaf_cursor_lock
            real_release = keys_module._release_leaf_cursor_lock

            # Tag the slow path by thread ident — that's the only
            # value that's stable per-thread without races on a
            # shared dict.  kp1's thread ident is captured before
            # kp2 starts.
            kp1_thread_ident = {"id": None}

            def slow_acquire(lock_path, timeout_s=None):
                handle = real_acquire(lock_path, timeout_s=timeout_s)
                tid = threading.get_ident()
                with events_lock:
                    events.append(("a", tid, time.monotonic()))
                # Make signer 1 hold the lock long enough that signer 2
                # is forced to actually wait on the file lock.
                if tid == kp1_thread_ident["id"]:
                    time.sleep(0.25)
                return handle

            def tracking_release(handle):
                tid = threading.get_ident()
                with events_lock:
                    events.append(("r", tid, time.monotonic()))
                real_release(handle)

            with mock.patch.object(
                keys_module, "_acquire_leaf_cursor_lock", slow_acquire
            ), mock.patch.object(
                keys_module, "_release_leaf_cursor_lock", tracking_release
            ):
                results = {}

                def run(role, kp, msg_byte):
                    if role == "kp1":
                        kp1_thread_ident["id"] = threading.get_ident()
                    results[role] = (
                        threading.get_ident(),
                        kp.sign(bytes([msg_byte]) * 32).leaf_index,
                    )

                t1 = threading.Thread(target=run, args=("kp1", kp1, 0xCC))
                t1.start()
                # Stagger so kp1 enters the lock first; kp2 then has to
                # wait on the file lock for ~250ms before it can proceed.
                time.sleep(0.05)
                t2 = threading.Thread(target=run, args=("kp2", kp2, 0xDD))
                t2.start()
                t1.join(timeout=10)
                t2.join(timeout=10)

            kp1_tid, kp1_leaf = results["kp1"]
            kp2_tid, kp2_leaf = results["kp2"]
            self.assertNotEqual(kp1_leaf, kp2_leaf)

            # The recorded acquire/release stream should show kp1's
            # release happening BEFORE kp2's acquire — i.e. the lock
            # serialized them.
            kp1_releases = [
                t for kind, tid, t in events if kind == "r" and tid == kp1_tid
            ]
            kp2_acquires = [
                t for kind, tid, t in events if kind == "a" and tid == kp2_tid
            ]
            self.assertTrue(
                kp1_releases,
                "kp1 never recorded a release — instrumentation broken",
            )
            self.assertTrue(
                kp2_acquires,
                "kp2 never recorded an acquire — instrumentation broken",
            )
            self.assertGreaterEqual(
                kp2_acquires[0], kp1_releases[0],
                "kp2 acquired the file lock before kp1 released it — "
                "the cross-process lock did NOT serialize signers.",
            )


# ----------------------------------------------------------------------
# Test 3.  When the lock is already held by another process (simulated
# here by another thread holding a real flock/msvcrt lock on the sibling
# file), sign() must time out with a clear error.
# ----------------------------------------------------------------------
class TestLockTimeoutRaisesClearError(unittest.TestCase):
    def test_lock_timeout_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")
            kp = _make_keypair(leaf_path=leaf_path, seed=b"\x55" * 32)

            # Hold the file lock from a helper thread for longer than
            # the sign() timeout.
            lock_held = threading.Event()
            release_holder = threading.Event()

            def holder():
                handle = keys_module._acquire_leaf_cursor_lock(
                    leaf_path + ".lock", timeout_s=5.0,
                )
                lock_held.set()
                release_holder.wait(timeout=5.0)
                keys_module._release_leaf_cursor_lock(handle)

            ht = threading.Thread(target=holder)
            ht.start()
            try:
                self.assertTrue(lock_held.wait(timeout=5.0))

                # Force sign() to use a tiny timeout so the test runs
                # fast.  We patch the constant rather than passing a
                # parameter — sign() reads the module-level default.
                with mock.patch.object(
                    keys_module, "_LEAF_CURSOR_LOCK_TIMEOUT_S", 0.5
                ):
                    with self.assertRaises(
                        keys_module.LeafCursorLockTimeoutError
                    ) as ctx:
                        kp.sign(b"\xee" * 32)

                # The error message must be operator-actionable.
                msg = str(ctx.exception)
                self.assertIn("leaf-index lock", msg)
                self.assertIn(leaf_path + ".lock", msg)
            finally:
                release_holder.set()
                ht.join(timeout=5.0)


# ----------------------------------------------------------------------
# Test 4.  When ``leaf_index_path`` is None, no .lock sibling should
# ever appear on disk.  In-memory ``_sign_lock`` is sufficient for the
# no-persistence case (no cross-process surface to defend).
# ----------------------------------------------------------------------
class TestNoLockWhenLeafIndexPathIsNone(unittest.TestCase):
    def test_no_lock_when_leaf_index_path_is_none(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_keypair(leaf_path=None, seed=b"\x66" * 32)
            self.assertIsNone(kp.leaf_index_path)

            kp.sign(b"\x01" * 32)

            # No `.lock` file anywhere under the temp dir.
            for root, _dirs, files in os.walk(td):
                for fn in files:
                    self.assertFalse(
                        fn.endswith(".lock"),
                        f"Unexpected lock file created at "
                        f"{os.path.join(root, fn)}",
                    )


# ----------------------------------------------------------------------
# Test 5.  If the inner WOTS+ sign raises, the lock must be released
# cleanly — a follow-up sign() must succeed without timing out.
# ----------------------------------------------------------------------
class TestLockReleasedOnSignException(unittest.TestCase):
    def test_lock_released_on_sign_exception(self):
        with tempfile.TemporaryDirectory() as td:
            leaf_path = os.path.join(td, "leaf.json")
            kp = _make_keypair(leaf_path=leaf_path, seed=b"\x77" * 32)

            with mock.patch.object(
                keys_module, "wots_sign",
                side_effect=RuntimeError("inner sign blew up"),
            ):
                with self.assertRaises(RuntimeError):
                    kp.sign(b"\x02" * 32)

            # If the lock leaked, this would block until the timeout
            # and then raise LeafCursorLockTimeoutError.  Use a short
            # timeout so a leak fails fast.
            with mock.patch.object(
                keys_module, "_LEAF_CURSOR_LOCK_TIMEOUT_S", 1.0
            ):
                sig = kp.sign(b"\x03" * 32)
            self.assertIsNotNone(sig)
            # The first attempt advanced the persisted cursor (persist-
            # before-sign) so the second sign uses the next leaf.
            self.assertEqual(sig.leaf_index, 1)


# ----------------------------------------------------------------------
# Test 6.  The daemon path (``<data_dir>/leaf_index.json``) is also
# protected — same code path, different on-disk location.
# ----------------------------------------------------------------------
class TestOperatorDataDirPathAlsoProtected(unittest.TestCase):
    def test_operator_data_dir_path_also_protected(self):
        with tempfile.TemporaryDirectory() as td:
            data_dir = os.path.join(td, "mc-data")
            os.makedirs(data_dir, exist_ok=True)
            leaf_path = os.path.join(data_dir, "leaf_index.json")
            seed_hex = ("\x88" * 32).encode("latin-1").hex()
            barrier = os.path.join(td, "go")

            p1 = _spawn_signer(seed_hex, leaf_path, 4, 0x10, barrier)
            p2 = _spawn_signer(seed_hex, leaf_path, 4, 0x20, barrier)
            time.sleep(0.5)
            with open(barrier, "w") as f:
                f.write("go")

            out1, err1 = p1.communicate(timeout=60)
            out2, err2 = p2.communicate(timeout=60)

            self.assertEqual(p1.returncode, 0, err1.decode(errors="replace"))
            self.assertEqual(p2.returncode, 0, err2.decode(errors="replace"))

            r1 = json.loads(out1.decode())
            r2 = json.loads(out2.decode())
            self.assertTrue(r1.get("ok"), f"signer 1: {r1}")
            self.assertTrue(r2.get("ok"), f"signer 2: {r2}")
            self.assertNotEqual(
                r1["leaf_index"], r2["leaf_index"],
                "daemon-path leaf-index file races just like CLI path",
            )
            # The lock sibling must live next to the cursor file.
            self.assertTrue(
                os.path.exists(leaf_path + ".lock"),
                "expected sibling .lock file at the daemon-path location",
            )


if __name__ == "__main__":
    unittest.main()
