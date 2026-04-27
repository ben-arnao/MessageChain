"""R12-#2: Directory fsync failure must block sign(), not be swallowed.

Original bug: persist_leaf_index() wrapped the parent-directory fsync in
a bare `except OSError: pass`, with the reasoning that some tmpfs-style
filesystems return EINVAL for dir fsync.  That is true for tmpfs, but
the same blanket swallow also hides genuine durability failures — EIO
(hardware/media error), ENOSPC (disk full, which can block the rename
entry from being written), EACCES/EPERM (perm loss during ops), etc.

On POSIX, the rename atomicity guarantee covers only the inode content;
the directory entry update for a rename can be lost on power loss
unless the directory itself is fsynced.  If the dir fsync silently
failed and the machine then crashed, the next boot would see:
    - no leaf-index file (rename entry lost), OR
    - a stale one pointing at an earlier leaf,
both of which cause load_leaf_index to leave _next_leaf = 0 (or the
stale value).  The next sign() reuses a leaf that was already
broadcast.  WOTS+ leaf reuse mathematically reveals the one-time
private key for that leaf — a catastrophic key leak.

Fix: narrow the swallowed exception to errno.EINVAL only (the known
tmpfs/overlayfs case), log an ERROR for anything else, and raise a
new LeafIndexPersistError so sign() bails out without producing a
signature.  Burning a leaf on a spurious abort is cheap; reusing one
is unrecoverable.

These tests lock in that behavior:

 A. EIO on dir fsync -> LeafIndexPersistError.  _next_leaf rollback
    in sign() is verified in test C.
 B. EINVAL on dir fsync (tmpfs) -> persist succeeds silently, file IS
    advanced.  Preserves the legitimate tmpfs carve-out.
 C. sign() with EIO on fsync -> sign() raises, no Signature returned,
    _next_leaf rolled back.  End-to-end safety property.
 D. Happy path regression: fsync succeeds, sign() returns a valid sig.

The tests mock the internal _fsync_parent_dir helper so the errno
classification can be exercised on any platform — on Windows the
production code path is a no-op (no O_DIRECTORY), but the safety
logic lives in a platform-independent helper and MUST be tested.
"""

import errno
import json
import logging
import os
import tempfile
import unittest
from unittest import mock

from messagechain.crypto import keys as keys_module
from messagechain.crypto.keys import KeyPair, LeafIndexPersistError


def _make_persistent_keypair(tmpdir, height=4):
    """Small KeyPair wired to a leaf-index file under tmpdir (16 leaves)."""
    seed = b"\x11" * 32
    kp = KeyPair(seed, height=height)
    kp.leaf_index_path = os.path.join(tmpdir, "leaf.json")
    return kp


def _read_persisted_leaf(path):
    with open(path, "r") as f:
        return json.load(f)["next_leaf"]


def _fsync_raising(err_errno):
    """Return a drop-in replacement for _fsync_parent_dir that simulates
    the exact errno path the production helper would take."""
    def _fake(dir_path):
        e = OSError(err_errno, os.strerror(err_errno))
        if err_errno == errno.EINVAL:
            # Mirror the production helper's tmpfs carve-out.
            logging.getLogger("messagechain.crypto.keys").debug(
                "directory fsync not supported on %r: %s "
                "(treating as tmpfs/overlay; not a durability bug)",
                dir_path, e,
            )
            return
        logging.getLogger("messagechain.crypto.keys").error(
            "directory fsync FAILED on %r: %s; "
            "leaf-index durability is NOT guaranteed — "
            "refusing to sign rather than risk WOTS+ leaf reuse",
            dir_path, e,
        )
        raise LeafIndexPersistError(
            f"leaf-index directory fsync failed on {dir_path!r}: {e}"
        ) from e
    return _fake


# Use the real helper with monkey-patched os.fsync so we exercise the
# actual classification logic end-to-end when possible.  Only available
# on platforms that provide O_DIRECTORY.
_HAS_O_DIR = hasattr(os, "O_DIRECTORY")


def _make_selective_os_fsync(err_errno):
    """Return a fake os.fsync that raises OSError on directory fds only.
    File (non-dir) fds get the real os.fsync so the tmp-file flush step
    before the dir fsync still succeeds."""
    real_fsync = os.fsync

    def fake_fsync(fd):
        try:
            st = os.fstat(fd)
        except OSError:
            return real_fsync(fd)
        import stat as _stat
        if _stat.S_ISDIR(st.st_mode):
            raise OSError(err_errno, os.strerror(err_errno))
        return real_fsync(fd)
    return fake_fsync


class TestDirFsyncFailurePropagates(unittest.TestCase):
    """Test A: EIO / ENOSPC on dir fsync must raise LeafIndexPersistError."""

    def test_eio_raises_leaf_index_persist_error(self):
        """EIO in _fsync_parent_dir propagates out of persist_leaf_index."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 3

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EIO),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.persist_leaf_index(leaf_path)

    def test_enospc_raises_leaf_index_persist_error(self):
        """ENOSPC is another 'real failure' — must also raise."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 2

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.ENOSPC),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.persist_leaf_index(leaf_path)

    def test_eacces_raises_leaf_index_persist_error(self):
        """EACCES (perm loss mid-op) is also a real failure."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 1

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EACCES),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.persist_leaf_index(leaf_path)

    @unittest.skipUnless(_HAS_O_DIR,
                         "directory fsync branch only active on POSIX")
    def test_eio_via_real_os_fsync_patch(self):
        """End-to-end: patch os.fsync directly (POSIX only) and verify
        the real _fsync_parent_dir classifies EIO correctly."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 4

            with mock.patch.object(
                os, "fsync", _make_selective_os_fsync(errno.EIO),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.persist_leaf_index(leaf_path)


class TestEinvalIsBenign(unittest.TestCase):
    """Test B: EINVAL (tmpfs) must be swallowed — preserves the legit
    carve-out for volatile filesystems."""

    def test_einval_is_benign(self):
        """EINVAL does NOT raise; file advance still visible on disk."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 5

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EINVAL),
            ):
                kp.persist_leaf_index(leaf_path)  # must NOT raise

            # The rename landed before the dir fsync, so the file is
            # advanced on disk.
            self.assertEqual(_read_persisted_leaf(leaf_path), 5)

    def test_einval_logs_at_debug_not_error(self):
        """The tmpfs case logs only at DEBUG — no operator log noise."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            leaf_path = kp.leaf_index_path
            kp._next_leaf = 1

            logger = logging.getLogger("messagechain.crypto.keys")
            prev_level = logger.level
            prev_disabled = logging.root.manager.disable
            try:
                logger.setLevel(logging.DEBUG)
                logging.disable(logging.NOTSET)
                with self.assertLogs(
                    "messagechain.crypto.keys", level="DEBUG",
                ) as captured:
                    with mock.patch.object(
                        keys_module, "_fsync_parent_dir",
                        side_effect=_fsync_raising(errno.EINVAL),
                    ):
                        kp.persist_leaf_index(leaf_path)
            finally:
                logger.setLevel(prev_level)
                logging.disable(prev_disabled)

            debug_hits = [
                r for r in captured.records
                if r.levelno == logging.DEBUG and "fsync" in r.getMessage()
            ]
            self.assertTrue(
                debug_hits,
                f"expected a DEBUG log mentioning fsync; "
                f"got {captured.output}",
            )
            error_hits = [
                r for r in captured.records if r.levelno >= logging.ERROR
            ]
            self.assertFalse(
                error_hits,
                f"EINVAL must not produce ERROR logs; got {captured.output}",
            )

    def test_real_helper_einval_swallowed(self):
        """Call the real _fsync_parent_dir with a fake errno to confirm
        its own classification logic — not the mocked side_effect."""
        # Simulate EINVAL by patching os.open to return a fake fd and
        # os.fsync to raise EINVAL.  This works cross-platform because
        # the helper just no-ops when O_DIRECTORY is absent — we have
        # to install the attribute temporarily to exercise the branch.
        fake_fd = 12345

        with mock.patch.object(os, "open", return_value=fake_fd), \
             mock.patch.object(os, "close", return_value=None), \
             mock.patch.object(
                 os, "fsync",
                 side_effect=OSError(errno.EINVAL, "not supported"),
             ):
            # Ensure O_DIRECTORY looks present so the helper enters the
            # branch even on Windows test runners.
            patched_attrs = {}
            if not hasattr(os, "O_DIRECTORY"):
                os.O_DIRECTORY = 0x10000  # placeholder; not used
                patched_attrs["O_DIRECTORY"] = True
            try:
                # Must NOT raise.
                keys_module._fsync_parent_dir("/some/dir")
            finally:
                if "O_DIRECTORY" in patched_attrs:
                    delattr(os, "O_DIRECTORY")

    def test_real_helper_eio_raises(self):
        """Same shape as above but with EIO — the real helper must
        raise LeafIndexPersistError."""
        fake_fd = 12345

        with mock.patch.object(os, "open", return_value=fake_fd), \
             mock.patch.object(os, "close", return_value=None), \
             mock.patch.object(
                 os, "fsync",
                 side_effect=OSError(errno.EIO, "I/O error"),
             ):
            patched_attrs = {}
            if not hasattr(os, "O_DIRECTORY"):
                os.O_DIRECTORY = 0x10000
                patched_attrs["O_DIRECTORY"] = True
            try:
                with self.assertRaises(LeafIndexPersistError):
                    keys_module._fsync_parent_dir("/some/dir")
            finally:
                if "O_DIRECTORY" in patched_attrs:
                    delattr(os, "O_DIRECTORY")


class TestSignRefusesOnFsyncFailure(unittest.TestCase):
    """Test C: sign() must propagate the persist failure — no sig emitted,
    _next_leaf rolled back.  End-to-end safety property: validator
    refuses to sign rather than burn a leaf whose durability isn't
    guaranteed."""

    def test_sign_refuses_when_dir_fsync_raises_eio(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            self.assertEqual(kp._next_leaf, 0)

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EIO),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.sign(b"\xaa" * 32)

            # _next_leaf MUST be rolled back.
            self.assertEqual(
                kp._next_leaf, 0,
                "sign() must roll back _next_leaf on persist failure"
            )

    def test_sign_recovers_after_transient_eio(self):
        """If fsync recovers on the next try, the next sign succeeds.

        Note on which leaf is used: ``_fsync_parent_dir`` runs AFTER
        ``os.replace`` has already swapped the cursor file to the
        advanced value — only the directory's durability fsync raised.
        From an outside observer's perspective the leaf IS already
        burned on disk; the in-memory rollback was best-effort.  With
        the cross-process advisory lock in place, ``sign`` re-loads
        the cursor from disk inside the lock and observes the
        advanced value, so the next sign uses the NEXT leaf.  This is
        the safer semantic: burning a leaf is cheap, reusing one is
        unrecoverable.
        """
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            msg = b"\xbb" * 32

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EIO),
            ):
                with self.assertRaises(LeafIndexPersistError):
                    kp.sign(msg)
            self.assertEqual(kp._next_leaf, 0)
            # The on-disk cursor advanced before fsync raised — rename
            # already happened.  Honoring this on the retry is the
            # whole point of the cross-process lock's load-inside-lock
            # step.
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 1)

            # Recovery — fsync succeeds.  The retry observes the
            # already-advanced disk cursor and signs the next leaf.
            sig = kp.sign(msg)
            self.assertEqual(sig.leaf_index, 1)
            self.assertEqual(kp._next_leaf, 2)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 2)

    def test_sign_with_einval_succeeds(self):
        """EINVAL (tmpfs) on dir fsync: sign() must still succeed."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            msg = b"\xcc" * 32

            with mock.patch.object(
                keys_module, "_fsync_parent_dir",
                side_effect=_fsync_raising(errno.EINVAL),
            ):
                sig = kp.sign(msg)

            self.assertEqual(sig.leaf_index, 0)
            self.assertEqual(kp._next_leaf, 1)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 1)


class TestHappyPathRegression(unittest.TestCase):
    """Test D: normal fsync success path must still work — don't break
    the common case while hardening the failure case."""

    def test_normal_sign_and_persist(self):
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            msg = b"\xcc" * 32

            sig = kp.sign(msg)

            self.assertEqual(sig.leaf_index, 0)
            self.assertEqual(kp._next_leaf, 1)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 1)

    def test_normal_persist_without_sign(self):
        """Direct persist_leaf_index call with real fsync must succeed."""
        with tempfile.TemporaryDirectory() as td:
            kp = _make_persistent_keypair(td)
            kp._next_leaf = 7
            kp.persist_leaf_index(kp.leaf_index_path)
            self.assertEqual(_read_persisted_leaf(kp.leaf_index_path), 7)

    def test_exception_class_is_runtime_error_subclass(self):
        """LeafIndexPersistError must be a RuntimeError so existing
        `except RuntimeError:` handlers keep catching it — no silent
        behavior shift for callers already alert to sign() failures."""
        self.assertTrue(issubclass(LeafIndexPersistError, RuntimeError))


if __name__ == "__main__":
    unittest.main()
