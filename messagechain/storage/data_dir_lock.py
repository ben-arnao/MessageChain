"""
Exclusive process lock for a node's data directory.

## Why this exists (threat model)

MessageChain signs blocks and receipts with WOTS+ — a one-time signature
scheme.  Each leaf index in the WOTS+ Merkle tree MUST NOT be used
twice; reusing a leaf leaks the private key outright (two signatures at
the same index let an attacker recover the key and forge arbitrary
messages from that entity).

Two node processes pointed at the same ``data_dir`` will both load the
same WOTS+ keypair cache and the same persisted ``leaf_index.json``.
If they're online simultaneously they WILL race, both pick the same
next leaf, and sign different payloads at that leaf — full key
recovery and (for a validator) a consensus fork.

Nothing in the filesystem layout alone prevents this: an operator can
trivially launch a second node with ``--data-dir=/path/to/live`` and
nothing complains until the damage is already done.  This module is
the enforcement: an OS-level advisory lock on
``<data_dir>/.node.lock`` held for the process lifetime.  The second
starter fails loudly with the holder's PID before it touches any
keyfile.

## Design

* POSIX: ``fcntl.flock(fd, LOCK_EX | LOCK_NB)`` — non-blocking
  exclusive on the lockfile fd.  The kernel releases the lock
  automatically if the process dies (SIGKILL, crash, OOM).  No
  stale-lock cleanup ever needed.  Because POSIX ``flock`` is
  advisory and does NOT block other opens, we can write the holder
  PID + hostname into the same file and a conflicting starter can
  still read it.
* Windows: ``msvcrt.locking(fd, LK_NBLCK, 1)`` on byte 0.  Windows'
  mandatory locking + default share mode prevents a conflicting
  starter from even opening the locked file to read the holder info.
  To preserve the ability to name the holder in the error message,
  the holder PID + hostname are written to a SIBLING file
  ``<data_dir>/.node.lock.holder`` which is NOT locked and can be
  read by the conflicting starter.  The sibling is truncated +
  rewritten on lock acquisition, so it always reflects the current
  (or most recent) holder; it's diagnostic metadata, not the lock
  itself.
* The lockfile (and on Windows the sibling holder file) are left on
  disk across clean shutdowns (no unlink).  Their presence is NOT a
  signal of live ownership — only the kernel-held lock is.  Leaving
  the holder record preserves forensic context after a crash.

## Test-harness escape hatch

Some integration tests spin up multiple ``Blockchain`` / ``Server``
instances in the same tempdir (they don't actually share keyfiles).
Setting ``MESSAGECHAIN_SKIP_DATA_DIR_LOCK=1`` in the environment
bypasses the lock.  Only for test harness — production MUST hold
the lock.
"""

from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)

LOCKFILE_NAME = ".node.lock"
HOLDER_FILE_NAME = ".node.lock.holder"
_SKIP_ENV_VAR = "MESSAGECHAIN_SKIP_DATA_DIR_LOCK"

# Platform dispatch: prefer POSIX fcntl, fall back to Windows msvcrt.
# Exactly one of these is non-None after import on a supported OS.
try:
    import fcntl as _fcntl  # type: ignore[import-not-found]
    _msvcrt = None
except ImportError:
    _fcntl = None
    try:
        import msvcrt as _msvcrt  # type: ignore[import-not-found]
    except ImportError:
        _msvcrt = None


class DataDirLockedError(RuntimeError):
    """Raised when another node process is already using this data_dir."""


class DataDirLock:
    """Context manager holding an exclusive OS-level lock on a data_dir.

    Usage::

        lock = DataDirLock("/var/lib/messagechain")
        lock.__enter__()          # or: with DataDirLock(...) as lock:
        try:
            ...                   # run node
        finally:
            lock.__exit__(None, None, None)

    If another process already holds the lock, ``__enter__`` raises
    ``DataDirLockedError`` with the holder's PID/hostname (best-effort
    read from the lockfile contents).
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, LOCKFILE_NAME)
        self.holder_path = os.path.join(data_dir, HOLDER_FILE_NAME)
        self._fd: int | None = None
        self._bypassed = False

    def __enter__(self) -> "DataDirLock":
        # Test-harness escape hatch.  WHY a string compare and not
        # `bool(os.environ.get(...))`: we want the operator to have to
        # TYPE "1" — a stray empty env var shouldn't silently disable
        # the protection.  Only for test harness — production MUST
        # hold the lock.
        if os.environ.get(_SKIP_ENV_VAR) == "1":
            self._bypassed = True
            logger.warning(
                "DataDirLock bypassed via %s=1; this is for tests only — "
                "a real node MUST hold the lock to prevent WOTS+ leaf reuse.",
                _SKIP_ENV_VAR,
            )
            return self

        if _fcntl is None and _msvcrt is None:
            raise RuntimeError(
                "DataDirLock requires either fcntl (POSIX) or msvcrt "
                "(Windows); neither is available on this platform."
            )

        os.makedirs(self.data_dir, exist_ok=True)

        # Open with O_WRONLY | O_CREAT and mode 0o600.  The mode is
        # meaningful only on creation; on POSIX we also chmod after
        # open in case an umask trimmed the perms.  0o600 = owner r/w
        # only — the file holds the PID of whoever last locked it
        # and there's no reason any other user needs to read it.
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            # Best-effort tighten of perms on POSIX.  On Windows this
            # is a no-op; guarded by platform dispatch.
            if _fcntl is not None:
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

            # Windows msvcrt.locking needs the byte at offset 0 to
            # exist.  Make the file at least 1 byte long before the
            # lock attempt.  POSIX flock doesn't care about file size
            # but extending with a single zero byte is harmless.
            if _msvcrt is not None:
                os.ftruncate(fd, 1)

            # Attempt non-blocking exclusive lock.
            try:
                if _fcntl is not None:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)  # type: ignore[union-attr]
            except (BlockingIOError, OSError) as e:
                # Someone else holds it.  Read the holder info from
                # whichever location holds it on this platform.
                holder_info = self._read_holder_info()
                os.close(fd)
                msg = (
                    f"data_dir '{self.data_dir}' is locked by "
                    f"{holder_info}. Another MessageChain node is using "
                    f"this directory. Refusing to start to prevent WOTS+ "
                    f"leaf reuse / key leakage."
                )
                raise DataDirLockedError(msg) from e

            # Got the lock.  Write our PID/hostname so the NEXT
            # conflicting starter can name us.
            #
            # POSIX: write it into the lockfile itself (advisory
            # flock does not block other opens, so a conflicting
            # starter can still open+read this file).
            # Windows: write it into a SIBLING file that's not
            # locked, because Windows' mandatory locking + default
            # share mode prevents any other handle from opening the
            # locked file for read.
            payload = self._build_payload().encode("utf-8")
            if _fcntl is not None:
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, payload)
            else:
                # Windows sidecar holder file.  Plain write — no lock.
                # Atomic-ish: we truncate + write in one open/close.
                # Worst case the conflicting starter reads a
                # partial/empty file and falls back to the generic
                # "another process" placeholder — this is a
                # diagnostic hint, not consensus state.
                try:
                    with open(self.holder_path, "w") as hf:
                        hf.write(self._build_payload())
                    try:
                        os.chmod(self.holder_path, 0o600)
                    except OSError:
                        pass
                except OSError:
                    # Non-fatal: the lock is held regardless of
                    # whether we managed to stamp the holder file.
                    pass

            self._fd = fd
        except Exception:
            # Any failure between open and lock-acquired: close the fd.
            # If we already locked it, the `except` above closed fd
            # before re-raising, so we only reach this for programming
            # errors (e.g. ftruncate failure).  Defensive.
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._bypassed:
            self._bypassed = False
            return
        if self._fd is None:
            return
        try:
            if _fcntl is not None:
                try:
                    _fcntl.flock(self._fd, _fcntl.LOCK_UN)
                except OSError:
                    pass
            else:
                try:
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    _msvcrt.locking(self._fd, _msvcrt.LK_UNLCK, 1)  # type: ignore[union-attr]
                except OSError:
                    pass
        finally:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        # We deliberately do NOT unlink self.path or the holder file.
        # Leaving them preserves a forensic record of the last holder's
        # PID, and their presence doesn't imply a live lock — only the
        # kernel-held lock on the open fd does.

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload() -> str:
        try:
            host = socket.gethostname()
        except OSError:
            host = "unknown"
        return f"pid={os.getpid()} host={host}\n"

    def _read_holder_info(self) -> str:
        """Best-effort read of the holder metadata.

        Returns a human-readable string like
        ``'PID 12345 (hostname)'``.  On any error, returns a generic
        placeholder.  Never raises — this runs inside the error path
        for a contended lock and must not mask the real failure.

        Reads from the lockfile directly on POSIX, or from the
        sibling holder file on Windows (see the design comment at
        module top).
        """
        read_path = self.path if _fcntl is not None else self.holder_path
        try:
            with open(read_path, "r") as f:
                raw = f.read(256)
        except OSError:
            return "another process (holder info unavailable)"
        pid_s = "unknown"
        host_s = "unknown"
        for tok in raw.split():
            if tok.startswith("pid="):
                pid_s = tok[4:] or "unknown"
            elif tok.startswith("host="):
                host_s = tok[5:] or "unknown"
        if pid_s == "unknown" and host_s == "unknown":
            return "another process (holder info unavailable)"
        return f"PID {pid_s} ({host_s})"
