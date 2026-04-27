"""Persistent same-height sign guard.

Prevents an honest crash-restart from producing two byte-different
signatures at the same chain height — the realistic false-positive
path the audit on this branch surfaced:

  * ``BlockHeader.signable_data`` includes ``timestamp`` (rounded to
    integer seconds) and ``merkle_root`` (which moves with mempool
    churn).  A proposer that signs block N, partially propagates,
    crashes, and resigns block N on restart will produce a
    byte-different second header — fully valid signatures from the
    same key, same height — and ``EquivocationWatcher`` will file a
    100% slash.

  * Same shape for attestations and finality votes: any second sign
    at a height the operator already signed for produces conflicting
    evidence.

The fix is the same persist-before-sign ratchet that
``messagechain.crypto.keys`` uses for WOTS+ leaf indexes: durably
record "I have signed at height N" to disk BEFORE the signature
escapes the process.  On restart, the on-disk state is the floor; a
re-sign attempt at the same height refuses *before* a second
signature is produced.

Three independent height counters: block proposal, attestation,
finality vote.  A validator may legitimately propose block N AND
attest to block N's parent in the same chain slot — those are
different signing roles even though they share the same height
number.

File format: a small JSON blob, atomic write via tmp + rename +
parent-dir fsync (same primitive ``persist_leaf_index`` uses).  On
Windows, parent-dir fsync is a no-op — same caveat applies as the
WOTS+ leaf-index persist; Windows is not a production validator
target.

The guard is deliberately simple: dict of counters, persist on every
update, refuse on any attempt to re-record a height ≤ the recorded
one.  No batch / no lazy flush — durability beats throughput here.
A validator signs at most ~1 block proposal, ~1 attestation, ~0.01
finality votes per slot, so the IO overhead is bounded.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class HeightAlreadySignedError(RuntimeError):
    """Raised when a sign attempt would re-sign at a recorded height.

    Catching this and degrading to "skip the sign, log loudly, move
    on" is the correct response — the operator's chain has just
    avoided a false-positive slash.  Re-raising it crashes the
    proposer process; that's an acceptable (and audit-loud) failure
    mode for a paranoid deployment that wants a human to look at why
    a same-height re-sign was attempted.
    """


class HeightGuardPersistError(RuntimeError):
    """Raised when durable persistence of the guard file fails.

    Same shape as ``LeafIndexPersistError`` in ``crypto.keys``.  When
    raised, no signature has been produced — the caller should
    abort the sign and surface the error to the operator (likely a
    full disk or filesystem error).
    """


def _fsync_parent_dir(dir_path: str) -> None:
    """Fsync a directory so its rename entry is durable.

    Mirrors ``crypto.keys._fsync_parent_dir``.  On platforms without
    ``O_DIRECTORY`` (notably Windows) this is a no-op — production
    validator hosts run Linux, where the fsync is load-bearing.
    """
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        dir_fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as e:
        if e.errno == errno.EINVAL:
            logger.debug(
                "directory fsync not supported on %r: %s "
                "(treating as tmpfs/overlay)",
                dir_path, e,
            )
            return
        logger.error(
            "directory fsync FAILED on %r: %s; refusing to mark "
            "sign as durable rather than risk same-height re-sign",
            dir_path, e,
        )
        raise HeightGuardPersistError(
            f"directory fsync failed on {dir_path!r}: {e}"
        ) from e


_FILE_VERSION = 1
_KEY_BLOCK = "last_block_signed"
_KEY_ATTEST = "last_attestation_signed"
_KEY_FINALITY = "last_finality_signed"


class HeightSignGuard:
    """Per-role last-signed-height counter, persisted to disk.

    Three roles tracked independently:
      * block proposal (record_block_sign)
      * attestation (record_attestation_sign)
      * finality vote (record_finality_sign)

    Each ``record_X_sign(height)`` is a "reserve and persist before
    use" operation: it MUST be called before the signing primitive
    for that role.  If it returns successfully, the on-disk state
    has been durably advanced past ``height`` and a subsequent
    process restart will refuse a re-sign at the same height.  If it
    raises ``HeightAlreadySignedError``, the caller MUST NOT sign.
    """

    def __init__(self, path: str):
        self.path = path
        self.last_block_signed: int = -1
        self.last_attestation_signed: int = -1
        self.last_finality_signed: int = -1

    @classmethod
    def load_or_create(cls, path: str) -> "HeightSignGuard":
        """Construct a guard from disk, or with -1 floors if absent.

        A missing file is treated as "fresh state" — the guard starts
        with all-counters-at-(-1) so any height ≥ 0 is accepted.  A
        corrupt/unreadable file is logged and treated as fresh state
        ONLY if the file is unreadable (FileNotFoundError); a
        partially-written file (JSONDecodeError) is a real
        durability failure and is escalated, because silently
        zeroing it would undo the very protection the file exists
        to provide.

        On Windows the JSON file may be opened by an antivirus
        scanner during write — treat OSError other than ENOENT the
        same as JSONDecodeError (escalate, don't silently zero).
        """
        guard = cls(path)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return guard  # fresh state
        except (json.JSONDecodeError, OSError) as e:
            logger.error(
                "Refusing to load corrupt height-guard file %r: %s; "
                "operator must inspect manually rather than silently "
                "reset to fresh state (which would re-enable the "
                "same-height re-sign window the file is supposed to "
                "close)",
                path, e,
            )
            raise HeightGuardPersistError(
                f"corrupt height-guard file at {path!r}: {e}"
            ) from e
        if not isinstance(data, dict):
            raise HeightGuardPersistError(
                f"height-guard file at {path!r} is not a JSON object"
            )
        guard.last_block_signed = int(data.get(_KEY_BLOCK, -1))
        guard.last_attestation_signed = int(data.get(_KEY_ATTEST, -1))
        guard.last_finality_signed = int(data.get(_KEY_FINALITY, -1))
        return guard

    # ── persistence ─────────────────────────────────────────────────

    def _persist(self) -> None:
        """Atomic write of the current counters to disk.

        Tmp + rename + parent-dir fsync — same primitive
        ``KeyPair.persist_leaf_index`` uses for WOTS+ leaf indexes.
        Raises HeightGuardPersistError on any I/O failure that would
        leave the on-disk state behind the in-memory state.
        """
        # Symlink-traversal guard.
        real_path = os.path.realpath(self.path)
        if real_path != os.path.abspath(self.path):
            raise ValueError(f"Refusing to write through symlink: {self.path}")

        data = {
            "version": _FILE_VERSION,
            _KEY_BLOCK: self.last_block_signed,
            _KEY_ATTEST: self.last_attestation_signed,
            _KEY_FINALITY: self.last_finality_signed,
        }
        tmp_path = self.path + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
            _fsync_parent_dir(
                os.path.dirname(os.path.abspath(self.path)) or ".",
            )
        except OSError as e:
            raise HeightGuardPersistError(
                f"failed to persist height guard to {self.path!r}: {e}"
            ) from e

    # ── reservation API ─────────────────────────────────────────────

    def _reserve(self, role_attr: str, height: int) -> None:
        """Common reserve-and-persist for all three role counters.

        Refuses any height ≤ the current floor.  Successful return
        means the new floor is durably on disk.  On rollback (persist
        failure), the in-memory counter is restored — exactly the
        same shape as ``KeyPair.sign``'s persist-before-sign rollback
        path.
        """
        prior = getattr(self, role_attr)
        if height <= prior:
            raise HeightAlreadySignedError(
                f"already signed at height {height} for role {role_attr} "
                f"(recorded floor: {prior}); refusing to re-sign — "
                "this is the persistent same-height guard preventing a "
                "false-positive double-sign on crash-restart"
            )
        setattr(self, role_attr, height)
        try:
            self._persist()
        except Exception:
            setattr(self, role_attr, prior)
            raise

    def record_block_sign(self, height: int) -> None:
        """Reserve the proposer-signing slot at ``height``.

        Call this BEFORE invoking ``proposer_entity.keypair.sign``
        on the block header hash.  If it returns successfully, the
        on-disk state has been durably advanced past ``height``.
        If it raises ``HeightAlreadySignedError``, the caller MUST
        NOT sign — the on-disk state shows another signature was
        already produced at this height in a previous run of this
        process.
        """
        self._reserve("last_block_signed", int(height))

    def record_attestation_sign(self, height: int) -> None:
        """Reserve the attestation-signing slot at ``height``.

        Same shape as ``record_block_sign``; tracked separately so
        a validator can both propose and attest at the same height.
        """
        self._reserve("last_attestation_signed", int(height))

    def record_finality_sign(self, height: int) -> None:
        """Reserve the finality-vote-signing slot at ``height``.

        Same shape; tracked separately because finality votes go on
        their own cadence (every FINALITY_INTERVAL blocks) and the
        guard floor for them is independent of block / attestation
        floors.
        """
        self._reserve("last_finality_signed", int(height))

    # ── introspection (used by tests + operator CLI) ────────────────

    def can_sign_block(self, height: int) -> bool:
        return height > self.last_block_signed

    def can_attest(self, height: int) -> bool:
        return height > self.last_attestation_signed

    def can_finality_vote(self, height: int) -> bool:
        return height > self.last_finality_signed
