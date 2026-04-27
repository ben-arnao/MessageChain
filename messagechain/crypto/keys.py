"""
Merkle tree of WOTS+ keypairs for multi-use quantum-resistant signatures.

A single WOTS+ key can only sign once safely. This module builds a Merkle tree
over many WOTS+ public keys, giving a single long-lived root public key that
supports up to 2^height signatures.

Key generation is lazy: leaf keypairs are derived on demand from a seed,
so even large trees (height=40 → ~1 trillion signatures) have near-instant
creation time and constant memory overhead.
"""

import errno
import hashlib
import hmac
import json
import logging
import os
import stat
import struct
from dataclasses import dataclass, field
from messagechain.config import (
    HASH_ALGO, MERKLE_TREE_HEIGHT, WOTS_KEY_CHAINS,
    SIG_VERSION_CURRENT, validate_sig_version,
)
from messagechain.crypto.hash_sig import wots_keygen, wots_sign, wots_verify, _hash

logger = logging.getLogger(__name__)


class LeafIndexPersistError(RuntimeError):
    """Raised when durable persistence of the WOTS+ leaf counter fails.

    Specifically raised when the parent-directory fsync that guarantees
    the tmp+rename atomic write survives a power loss returns an errno
    other than EINVAL.  EINVAL is the known-benign tmpfs/overlayfs case
    (the filesystem genuinely doesn't support dir fsync); any other
    errno (EIO, ENOSPC, EACCES, ...) is a real durability failure.

    sign() catches `Exception` from persist_leaf_index(), rolls back
    _next_leaf, and re-raises.  This class is a RuntimeError subclass
    so existing broad handlers keep catching it — the only behavioral
    change is that a signature is NO LONGER produced when durability
    is uncertain.  Burning a leaf under a spurious abort is cheap;
    reusing one is unrecoverable (WOTS+ leaf reuse leaks the private
    key for that leaf).
    """


class LeafCursorLockTimeoutError(RuntimeError):
    """Raised when the cross-process leaf-cursor advisory lock cannot
    be acquired within the timeout window.

    The lock guards the read-modify-persist sequence on the on-disk
    leaf-index cursor: two concurrent CLI invocations on the same
    wallet (shell loop, retry-while-pending, two terminal panes, GUI
    shim dispatching twice) could otherwise both observe leaf=N, both
    pass the in-process ``_sign_lock`` (which is a per-process
    ``threading.Lock``), both persist N+1, and both sign at leaf N.
    WOTS+ leaf reuse mathematically reveals the leaf's private key.

    A timeout here means another ``messagechain`` process holds the
    lock — either still actively signing, or stuck.  The error message
    names the lock path so operators can identify the cursor file and
    investigate (typically: another shell, a hung CLI, or a stale lock
    on a crashed process whose fd was closed by the OS — in which
    case retrying is enough).
    """


class LeafCursorLockSymlinkRefusedError(RuntimeError):
    """Raised when the leaf-cursor advisory lock path is unsafe to open.

    The lock file (``<leaf_index_path>.lock``) sits next to the WOTS+
    leaf-index cursor.  If a hostile uid on a shared host (or a
    misconfigured shared-tenancy mount) pre-creates the lock path as a
    symlink, two MessageChain processes that follow *different* symlinks
    take their advisory locks on different files.  Each appears to hold
    an exclusive lock, and BOTH proceed past ``load_leaf_index`` to
    sign at the same on-disk leaf cursor.  WOTS+ leaf reuse mathematically
    reveals the leaf's private key — an attacker who scrapes both
    signatures from the chain or mempool can forge new transactions
    (spend balance, rotate key, impersonate identity) at that leaf.

    This refusal is raised when:

      * the lock path itself is a symlink (POSIX ``O_NOFOLLOW`` /
        Windows ``os.path.islink`` pre-check);
      * the parent directory contains a symlink, so the realpath of the
        lock path differs from its abspath (mirrors the existing
        persist-side guard — see ``persist_leaf_index`` realpath check);
      * the path resolves to a non-regular file (directory, FIFO,
        device) — defense-in-depth via post-open ``S_ISREG`` assertion.

    The right operator response is to inspect the wallet directory and
    remove the offending symlink/non-regular entry; signing must NOT
    proceed silently through whatever the symlink pointed at.
    """


# ---------------------------------------------------------------------------
# Cross-process advisory file lock for the WOTS+ leaf cursor.
#
# The lock is held on a sibling file (``<leaf_index_path>.lock``) rather
# than on the cursor file itself: locking the cursor would fight with
# its atomic tmp+rename persist path (a flock on the *old* inode
# silently goes away when ``os.replace`` swaps the inode).  The sibling
# pattern keeps the lock fd stable across the persist.
#
# POSIX uses ``fcntl.flock`` (advisory, fd-bound, automatically
# released when the fd closes — including on process crash, which is
# exactly what we want for stuck-process recovery).  Windows uses
# ``msvcrt.locking`` with ``LK_LOCK`` for the blocking acquire and
# ``LK_NBLCK`` for the polled timeout-bounded acquire.
#
# A 30-second default timeout is the operator-friendly upper bound:
# long enough that healthy contention (two near-simultaneous CLI
# invocations) resolves without an error, short enough that a stuck
# lock surfaces a clear message instead of hanging indefinitely.
# ---------------------------------------------------------------------------
_LEAF_CURSOR_LOCK_TIMEOUT_S = 30.0


def _acquire_leaf_cursor_lock(lock_path: str, timeout_s: float | None = None):
    """Acquire an exclusive advisory lock on ``lock_path`` (a sibling
    file next to the leaf-index cursor).

    Returns the open file handle the caller MUST keep alive — the
    advisory lock is bound to the fd's lifetime, so letting the fd be
    garbage-collected releases the lock.  The handle is opaque to
    callers; pass it to ``_release_leaf_cursor_lock`` when done.

    Raises ``LeafCursorLockTimeoutError`` if the lock cannot be
    acquired within ``timeout_s`` seconds.
    """
    # Read the timeout at call time so test-only patches of
    # ``_LEAF_CURSOR_LOCK_TIMEOUT_S`` (and any future runtime
    # reconfiguration) take effect.  An explicit positional argument
    # overrides the module-level default.
    if timeout_s is None:
        # Late binding — pick up the current module-level value.
        import messagechain.crypto.keys as _self
        timeout_s = _self._LEAF_CURSOR_LOCK_TIMEOUT_S

    # Make sure the parent directory exists; the cursor file may not
    # have been created yet on first sign of a fresh wallet.
    parent = os.path.dirname(os.path.abspath(lock_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    # ------------------------------------------------------------------
    # Symlink-traversal guard (CRITICAL for WOTS+ safety).
    #
    # If a hostile uid on a shared host pre-creates the lock path as a
    # symlink, two MessageChain processes that follow different
    # symlinks both take "exclusive" advisory locks on different files
    # and both proceed to sign at the same on-disk leaf cursor.
    # WOTS+ leaf reuse leaks the leaf's private key.
    #
    # Defenses, layered:
    #   (a) realpath(lock_path) must equal abspath(lock_path) — same
    #       guard the persist path uses (see persist_leaf_index).
    #       Catches symlinks anywhere in the path, including parent
    #       directories.
    #   (b) POSIX: open with O_NOFOLLOW so the open itself fails with
    #       ELOOP if the final component is a symlink.  Windows lacks
    #       O_NOFOLLOW; we pre-check with os.path.islink (Windows
    #       symlinks require Developer Mode or admin to create, so the
    #       attack surface is much narrower; documented TOCTOU below).
    #   (c) Post-open S_ISREG assertion — even with O_NOFOLLOW, defend
    #       against directories, FIFOs, devices, etc. landing at the
    #       lock path.
    # ------------------------------------------------------------------
    abspath_lock = os.path.abspath(lock_path)
    if os.path.realpath(lock_path) != abspath_lock:
        raise LeafCursorLockSymlinkRefusedError(
            f"refusing to acquire leaf-cursor lock through a symlink: "
            f"{lock_path} (realpath {os.path.realpath(lock_path)!r} "
            f"differs from abspath {abspath_lock!r}); inspect the "
            f"wallet directory for hostile or misconfigured symlinks."
        )

    if os.name == "nt":
        # Windows: no O_NOFOLLOW.  Pre-check with islink + lstat.
        # TOCTOU window between the pre-check and the open call: an
        # attacker would need to create a symlink in that ~microsecond
        # window AND have permission to do so (Developer Mode or
        # admin), which is a much narrower threat than the POSIX case.
        if os.path.islink(lock_path):
            raise LeafCursorLockSymlinkRefusedError(
                f"refusing to acquire leaf-cursor lock at a symlink: "
                f"{lock_path}; inspect the wallet directory."
            )
        # Pre-flight: if a non-regular entry already lives at the lock
        # path (directory, reparse point, junction, etc.) Windows'
        # plain ``open()`` raises ``PermissionError`` rather than
        # surfacing the underlying mismatch — convert to the explicit
        # refusal so operators see the actual problem.  os.lstat does
        # not follow symlinks (matching the islink check above).
        try:
            pre_st = os.lstat(lock_path)
        except FileNotFoundError:
            pre_st = None
        if pre_st is not None and not stat.S_ISREG(pre_st.st_mode):
            raise LeafCursorLockSymlinkRefusedError(
                f"refusing to acquire leaf-cursor lock at non-regular "
                f"file: {lock_path} (st_mode={pre_st.st_mode:#o}); "
                f"inspect the wallet directory."
            )
        # Open with append mode so the file is created on first acquire
        # and not truncated on subsequent ones.
        handle = open(lock_path, "a+")
    else:
        # POSIX: O_NOFOLLOW makes the open itself fail with ELOOP if
        # the final path component is a symlink.  We then wrap the fd
        # with os.fdopen to keep the existing handle semantics ("a+"
        # text-mode file object that supports .seek/.fileno/.close).
        try:
            fd = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.EMLINK):
                raise LeafCursorLockSymlinkRefusedError(
                    f"refusing to acquire leaf-cursor lock at a "
                    f"symlink: {lock_path}; inspect the wallet "
                    f"directory."
                ) from e
            raise
        try:
            handle = os.fdopen(fd, "a+")
        except Exception:
            os.close(fd)
            raise

    # Defense-in-depth: even with O_NOFOLLOW, ensure we landed on a
    # regular file.  A directory, FIFO, character/block device, or
    # socket at the lock path is unsafe — refuse and clean up the fd.
    try:
        st = os.fstat(handle.fileno())
    except OSError:
        try:
            handle.close()
        except OSError:
            pass
        raise
    if not stat.S_ISREG(st.st_mode):
        try:
            handle.close()
        except OSError:
            pass
        raise LeafCursorLockSymlinkRefusedError(
            f"refusing to acquire leaf-cursor lock at non-regular "
            f"file: {lock_path} (st_mode={st.st_mode:#o}); inspect "
            f"the wallet directory."
        )

    deadline = _time_monotonic() + max(0.0, float(timeout_s))

    if os.name == "nt":
        # Windows: msvcrt.locking is byte-range; we lock byte 0.
        # LK_NBLCK fails immediately if held; we poll until the
        # deadline.  msvcrt requires a non-zero length.
        import msvcrt as _msvcrt
        while True:
            try:
                # Position to byte 0 then attempt to lock 1 byte.
                handle.seek(0)
                _msvcrt.locking(handle.fileno(), _msvcrt.LK_NBLCK, 1)
                return handle
            except OSError:
                if _time_monotonic() >= deadline:
                    handle.close()
                    raise LeafCursorLockTimeoutError(
                        f"another messagechain process holds the "
                        f"leaf-index lock at {lock_path}; wait for "
                        f"it to finish or check for a stuck process."
                    )
                _time_sleep(0.05)
    else:
        # POSIX: fcntl.flock with non-blocking + sleep loop gives us a
        # bounded wait.  A blocking flock has no portable timeout, and
        # signal-based watchdogs interact badly with pytest-timeout's
        # thread-method.  Polling at 50ms is cheap and bounded.
        try:
            import fcntl as _fcntl
        except ImportError:
            # Platform without fcntl AND without msvcrt: fall through
            # without a real lock.  The in-process _sign_lock still
            # serializes within the process; cross-process safety is
            # genuinely not enforceable on such a platform.  This is
            # a no-op only on niche/unsupported targets.
            return handle

        while True:
            try:
                _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                return handle
            except (OSError, IOError):
                if _time_monotonic() >= deadline:
                    handle.close()
                    raise LeafCursorLockTimeoutError(
                        f"another messagechain process holds the "
                        f"leaf-index lock at {lock_path}; wait for "
                        f"it to finish or check for a stuck process."
                    )
                _time_sleep(0.05)


def _release_leaf_cursor_lock(handle) -> None:
    """Release the advisory lock and close the handle.

    Safe to call with a None handle (no-op).  Best-effort: any error
    on release is logged but not raised — the lock is already released
    when the fd closes regardless of explicit unlock.
    """
    if handle is None:
        return
    try:
        if os.name == "nt":
            import msvcrt as _msvcrt
            try:
                handle.seek(0)
                _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        else:
            try:
                import fcntl as _fcntl
                _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
            except (OSError, IOError, ImportError):
                pass
    finally:
        try:
            handle.close()
        except OSError:
            pass


# Module-level imports for the lock helpers.  Done here so the lock
# path is hot-path friendly (no per-call import overhead).
import time as _time_module
_time_monotonic = _time_module.monotonic
_time_sleep = _time_module.sleep


def _fsync_parent_dir(dir_path: str) -> None:
    """Fsync a directory so its recent rename entries are durable.

    On POSIX, `os.replace()` is inode-atomic but the directory entry
    update can still be lost on a power cut unless the directory
    itself is fsynced.  We open the directory O_RDONLY and fsync the
    fd.

    Errno classification (CRITICAL for WOTS+ safety):
      - EINVAL: tmpfs / some overlay filesystems genuinely don't
        support directory fsync.  Volatile by design; not a durability
        bug.  Logged at DEBUG and ignored.
      - anything else (EIO, ENOSPC, EACCES, EPERM, ...): a real
        durability failure.  If swallowed, a subsequent power loss
        could revert the on-disk leaf counter; the next sign() would
        then reuse a leaf that was already broadcast, and the WOTS+
        private key for that leaf would be recoverable from the two
        signatures.  Surface loudly as LeafIndexPersistError so
        sign() refuses to produce bytes.

    Platforms without O_DIRECTORY (notably Windows) fall through as a
    no-op — Windows is not a production validator target and its FS
    semantics for rename durability differ.  The no-op is acceptable
    for dev but operators running on Windows have been warned.
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
                "(treating as tmpfs/overlay; not a durability bug)",
                dir_path, e,
            )
            return
        logger.error(
            "directory fsync FAILED on %r: %s; "
            "leaf-index durability is NOT guaranteed — "
            "refusing to sign rather than risk WOTS+ leaf reuse",
            dir_path, e,
        )
        raise LeafIndexPersistError(
            f"leaf-index directory fsync failed on {dir_path!r}: {e}"
        ) from e

# WOTS+ leaf-usage thresholds (percent of capacity) at which sign() emits
# an operator-visible WARNING.  The footgun these guard against: a
# wallet or validator that never submits a KeyRotationTransaction will
# silently brick its funds the instant leaf #(num_leaves) is requested.
# 80% is the "plan a rotation" line; 95% is "do it TODAY".
_SIG_WARN_PERCENTS = (80, 95)

# Tracks which (keypair_root, threshold_pct) pairs have already emitted
# a warning in this process run.  Module-level so the dedup survives
# across sign() calls, but deliberately keyed on the Merkle root so two
# different keypairs warn independently — a rotated key does NOT inherit
# the pre-rotation silence, and two validators on the same host do not
# cross-suppress each other.  Cleared only on process restart.
_warned_thresholds: set[tuple[bytes, int]] = set()

# Hash output size for SHA3-256, used for strict size validation on signatures.
_HASH_SIZE = 32

# Upper bound on the Merkle auth_path length a deserialized Signature
# may carry.  Every extra element costs a hash op in verify_signature, so
# an unbounded path is a trivial DoS.  64 covers 2^64 leaves per key —
# well beyond any sane MERKLE_TREE_HEIGHT (current prod = 20) and still
# small enough that the verify loop stays cheap on adversarial input.
MAX_AUTH_PATH_LEN = 64


@dataclass
class Signature:
    """A complete signature: WOTS+ sig + Merkle authentication path.

    `sig_version` is a crypto-agility register: carried on every signature,
    committed into the signable_data of every transaction, and rejected by
    validators when it doesn't match SIG_VERSION_CURRENT. See config.py
    (`SIG_VERSION_*`, `validate_sig_version`) for the migration design.
    """
    wots_signature: list[bytes]
    leaf_index: int
    auth_path: list[bytes]  # sibling hashes from leaf to root
    wots_public_key: bytes  # the leaf's WOTS+ public key
    wots_public_seed: bytes
    sig_version: int = SIG_VERSION_CURRENT

    def canonical_bytes(self) -> bytes:
        """Canonical byte representation of the signature.

        Deterministic serialization used for witness_hash computation
        and relay-level deduplication. Prevents malleability from
        non-canonical encodings of the same signature.

        M23: Includes length prefixes for variable-length lists to prevent
        ambiguous concatenation between different element counts.
        """
        parts = []
        # M23: Length prefix for WOTS+ signature list
        parts.append(struct.pack(">I", len(self.wots_signature)))
        for s in self.wots_signature:
            parts.append(s)
        # Leaf index as big-endian 4 bytes
        parts.append(struct.pack(">I", self.leaf_index))
        # M23: Length prefix for auth path list
        parts.append(struct.pack(">I", len(self.auth_path)))
        for h in self.auth_path:
            parts.append(h)
        # Public key and seed
        parts.append(self.wots_public_key)
        parts.append(self.wots_public_seed)
        # Crypto-agility: sig_version trails the existing fields so the
        # canonical form is a superset of the pre-migration bytes.  The
        # witness_hash therefore commits to the signer's chosen scheme.
        parts.append(struct.pack(">B", self.sig_version))
        return b"".join(parts)

    def serialize(self) -> dict:
        return {
            "wots_signature": [s.hex() for s in self.wots_signature],
            "leaf_index": self.leaf_index,
            "auth_path": [h.hex() for h in self.auth_path],
            "wots_public_key": self.wots_public_key.hex(),
            "wots_public_seed": self.wots_public_seed.hex(),
            "sig_version": self.sig_version,
        }

    def to_bytes(self) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (all unsigned big-endian):
            u16  wots_chain_count
            N x  32-byte chain hashes  (where N = wots_chain_count)
            u32  leaf_index
            u8   auth_path_len
            M x  32-byte path hashes   (where M = auth_path_len)
            32   wots_public_key
            32   wots_public_seed
            u8   sig_version             <- crypto-agility register

        Every variable-length section is length-prefixed to prevent
        ambiguous concatenation (same defense as canonical_bytes uses).
        Hash elements are fixed-size (SHA3-256 = 32 bytes) so we encode
        only the count, not each element's length.

        sig_version is appended after the pre-migration fields so the
        blob is a strict extension: a pre-migration parser would fail
        fast on the trailing byte rather than mis-decode into a valid-
        looking sig.  (That is what we want — silently accepting a
        pre-migration blob as a post-migration signature would let an
        attacker forge a sig_version of their choosing via truncation.)
        """
        # Placeholder / witness-stripped sentinel: empty signature encodes
        # as zero bytes.  from_bytes(b"") decodes back to the placeholder.
        # This enables stripped transactions to round-trip through binary
        # serialization without carrying witness data.
        if not self.wots_signature and not self.wots_public_key:
            return b""
        parts = [struct.pack(">H", len(self.wots_signature))]
        parts.extend(self.wots_signature)
        parts.append(struct.pack(">I", self.leaf_index))
        parts.append(struct.pack(">B", len(self.auth_path)))
        parts.extend(self.auth_path)
        parts.append(self.wots_public_key)
        parts.append(self.wots_public_seed)
        parts.append(struct.pack(">B", self.sig_version))
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Signature":
        """Decode a Signature from its compact binary form.

        Matches the structural validation in deserialize(dict): all size
        checks happen here before any hash work runs, so malformed blobs
        cannot burn CPU on wots_verify.
        """
        # Placeholder-signature carve-out: empty blob decodes to the
        # placeholder used during transaction construction (see
        # `Signature([], 0, [], b"", b"")`).  Only relevant for in-memory
        # round-trips that embed unsigned placeholders; stored blocks
        # always carry a real signature.
        if len(data) == 0:
            return cls([], 0, [], b"", b"")

        offset = 0
        if len(data) < 2:
            raise ValueError("Signature blob too short for chain count")
        chain_count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if chain_count != WOTS_KEY_CHAINS:
            raise ValueError(
                f"WOTS signature must have exactly {WOTS_KEY_CHAINS} chains, "
                f"got {chain_count}"
            )
        wots_sig = []
        for _ in range(chain_count):
            if offset + _HASH_SIZE > len(data):
                raise ValueError("Signature blob truncated in wots chains")
            wots_sig.append(bytes(data[offset:offset + _HASH_SIZE]))
            offset += _HASH_SIZE

        if offset + 4 > len(data):
            raise ValueError("Signature blob truncated at leaf_index")
        leaf_index = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        if offset + 1 > len(data):
            raise ValueError("Signature blob truncated at auth_path length")
        auth_len = struct.unpack_from(">B", data, offset)[0]
        offset += 1
        if auth_len > MAX_AUTH_PATH_LEN:
            raise ValueError(
                f"Auth path too long: {auth_len} > {MAX_AUTH_PATH_LEN}"
            )
        auth_path = []
        for _ in range(auth_len):
            if offset + _HASH_SIZE > len(data):
                raise ValueError("Signature blob truncated in auth_path")
            auth_path.append(bytes(data[offset:offset + _HASH_SIZE]))
            offset += _HASH_SIZE

        if offset + _HASH_SIZE > len(data):
            raise ValueError("Signature blob truncated at wots_public_key")
        pub_key = bytes(data[offset:offset + _HASH_SIZE])
        offset += _HASH_SIZE

        if offset + _HASH_SIZE > len(data):
            raise ValueError("Signature blob truncated at wots_public_seed")
        pub_seed = bytes(data[offset:offset + _HASH_SIZE])
        offset += _HASH_SIZE

        # Crypto-agility register: reject unknown versions at decode time so
        # malformed or future-version blobs never reach wots_verify.  A
        # missing byte here is a truncation; a non-current value is either
        # a byte flip in transit or a too-new peer — either way, not ours.
        if offset + 1 > len(data):
            raise ValueError("Signature blob truncated at sig_version")
        sig_version = struct.unpack_from(">B", data, offset)[0]
        offset += 1
        ok, reason = validate_sig_version(sig_version)
        if not ok:
            raise ValueError(f"Invalid signature: {reason}")

        # leaf_index must be a valid index into a tree of height = auth_len.
        max_leaf_index = (1 << auth_len) - 1 if auth_len > 0 else 0
        if leaf_index > max_leaf_index:
            raise ValueError(
                f"leaf_index {leaf_index} outside tree coverage "
                f"(auth_path len {auth_len} → max index {max_leaf_index})"
            )

        return cls(
            wots_signature=wots_sig,
            leaf_index=leaf_index,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
            sig_version=sig_version,
        )

    @classmethod
    def deserialize(cls, data: dict) -> "Signature":
        wots_sig = [bytes.fromhex(s) for s in data["wots_signature"]]
        leaf_index = data["leaf_index"]
        auth_path = [bytes.fromhex(h) for h in data["auth_path"]]
        pub_key = bytes.fromhex(data["wots_public_key"])
        pub_seed = bytes.fromhex(data["wots_public_seed"])
        # Crypto-agility: default to SIG_VERSION_CURRENT when the field is
        # absent so pre-migration dicts (mempool dumps, test fixtures) load
        # cleanly.  A PRESENT-but-unknown value is a clear error and rejected.
        sig_version = data.get("sig_version", SIG_VERSION_CURRENT)
        ok, reason = validate_sig_version(sig_version)
        if not ok:
            raise ValueError(f"Invalid signature: {reason}")

        # M4: Structural validation on deserialization.  Every check here
        # runs BEFORE verify_signature sees the input, so malformed blobs
        # never reach the hash-heavy verify path — a cheap DoS guard.
        if not isinstance(leaf_index, int) or leaf_index < 0:
            raise ValueError(f"Invalid leaf_index: {leaf_index}")
        # WOTS+ signatures always carry exactly WOTS_KEY_CHAINS chains.
        # Anything else cannot be a valid signature under this scheme —
        # rejecting here prevents wasted hashing in wots_verify.
        if len(wots_sig) != WOTS_KEY_CHAINS:
            raise ValueError(
                f"WOTS signature must have exactly {WOTS_KEY_CHAINS} chains, "
                f"got {len(wots_sig)}"
            )
        for i, s in enumerate(wots_sig):
            if len(s) != _HASH_SIZE:
                raise ValueError(f"WOTS signature element {i} has wrong size: {len(s)}")
        # auth_path length is unbounded by the wire format — cap it before
        # verify runs a rehash-per-level loop on adversarial input.
        if len(auth_path) > MAX_AUTH_PATH_LEN:
            raise ValueError(
                f"Auth path too long: {len(auth_path)} > {MAX_AUTH_PATH_LEN}"
            )
        for i, h in enumerate(auth_path):
            if len(h) != _HASH_SIZE:
                raise ValueError(f"Auth path element {i} has wrong size: {len(h)}")
        # A path of length N addresses exactly 2^N leaves; any leaf_index
        # outside that range cannot point at a real position in the tree.
        max_leaf_index = (1 << len(auth_path)) - 1
        if leaf_index > max_leaf_index:
            raise ValueError(
                f"leaf_index {leaf_index} outside tree coverage "
                f"(auth_path len {len(auth_path)} → max index {max_leaf_index})"
            )
        if len(pub_key) != _HASH_SIZE:
            raise ValueError(f"Public key has wrong size: {len(pub_key)}")
        if len(pub_seed) != _HASH_SIZE:
            raise ValueError(f"Public seed has wrong size: {len(pub_seed)}")

        return cls(
            wots_signature=wots_sig,
            leaf_index=leaf_index,
            auth_path=auth_path,
            wots_public_key=pub_key,
            wots_public_seed=pub_seed,
            sig_version=sig_version,
        )


def _derive_leaf(seed: bytes, leaf_index: int) -> tuple[list[bytes], bytes, bytes]:
    """Derive a full WOTS+ keypair (private + public) for a single leaf."""
    leaf_seed = _hash(seed + struct.pack(">Q", leaf_index))
    return wots_keygen(leaf_seed)


def _derive_leaf_pubkey(seed: bytes, leaf_index: int) -> bytes:
    """Derive just the WOTS+ public key for a leaf (discards private keys)."""
    _, pub, _ = _derive_leaf(seed, leaf_index)
    return pub


def _subtree_root(seed: bytes, start: int, count: int, progress=None) -> bytes:
    """Compute the Merkle root hash over a contiguous range of leaves.

    If `progress` is provided, it is called after each leaf derivation
    with the leaf index that just completed. The callback is expected to
    do its own throttling.
    """
    if count == 1:
        pk = _derive_leaf_pubkey(seed, start)
        if progress is not None:
            progress(start)
        return pk
    half = count >> 1
    left = _subtree_root(seed, start, half, progress)
    right = _subtree_root(seed, start + half, half, progress)
    return _hash(left + right)


def _compute_auth_path(seed: bytes, height: int, leaf_index: int) -> list[bytes]:
    """Compute the Merkle authentication path for a leaf on demand.

    For each tree level, computes the sibling subtree root. This is
    O(2^height) work total but requires no stored tree — all hashes
    are recomputed from the seed.
    """
    path = []
    for level in range(height):
        # At this level, blocks are 2^(level+1) leaves wide
        block_size = 1 << (level + 1)
        half = block_size >> 1
        block_start = (leaf_index >> (level + 1)) << (level + 1)

        if (leaf_index >> level) & 1 == 0:
            # We're on the left; sibling is the right half
            sibling_start = block_start + half
        else:
            # We're on the right; sibling is the left half
            sibling_start = block_start

        path.append(_subtree_root(seed, sibling_start, half))
    return path


class KeyPair:
    """
    Merkle tree of WOTS+ keypairs with lazy leaf derivation.

    The root hash is the long-lived public key. Each leaf is a one-time WOTS+
    key derived on demand from the seed. No private keys or tree nodes are
    stored persistently, so large trees (height=40) use constant memory.
    """

    def __init__(
        self,
        seed: bytes,
        height: int | None = None,
        start_leaf: int = 0,
        progress=None,
    ):
        if height is None:
            import messagechain.config
            height = messagechain.config.MERKLE_TREE_HEIGHT
        self.height = height
        self.num_leaves = 1 << height
        self._seed = seed
        self._next_leaf = start_leaf

        # Serializes the read-modify-write of `_next_leaf` inside
        # sign().  Two threads racing into sign() without this lock
        # could each observe the same `leaf_idx = self._next_leaf`
        # before either advances the counter, then both produce
        # WOTS+ signatures over different message hashes under the
        # same one-time leaf -- mathematically reveals the leaf's
        # WOTS+ private key (per the catastrophic-reuse comment
        # below).  The race is reachable in production via the
        # ReceiptIssuer's subtree keypair: SubmissionServer runs
        # under socketserver.ThreadingMixIn, so two concurrent
        # /v1/submit POSTs that both qualify for receipt / ack /
        # rejection issuance enter sign() on different threads.
        # Cheap to acquire (uncontended in single-thread CLI / IBD
        # paths); the cost of NOT holding it is one-shot key
        # disclosure per collision.
        import threading as _threading
        self._sign_lock = _threading.Lock()

        # Optional path for persistent leaf-index tracking.  When set,
        # sign() writes the updated _next_leaf to this file BEFORE
        # returning the signature (write-ahead), preventing WOTS+ leaf
        # reuse after a process restart.
        self.leaf_index_path: str | None = None

        # Optional MerkleNodeCache (messagechain.crypto.merkle_cache).
        # Attached by the server loader once a cache is built or loaded;
        # when present, sign() uses it to produce auth paths in O(height)
        # instead of O(2^height).  None → fall back to recomputation.
        self._node_cache = None

        # Compute the Merkle root (the public key) by building the tree
        # bottom-up over derived leaf public keys. This is the only expensive
        # operation — O(2^height) leaf derivations, done once at creation.
        # No private keys or intermediate tree nodes are retained.
        #
        # `progress`, if provided, is called with the leaf index each time a
        # leaf is derived. Long-running keygen (height >= 20) can show a
        # status indicator without the caller needing to know tree internals.
        self.public_key = _subtree_root(seed, 0, self.num_leaves, progress)

    @classmethod
    def generate(
        cls,
        seed: bytes,
        height: int | None = None,
        start_leaf: int = 0,
        progress=None,
    ) -> "KeyPair":
        return cls(seed, height, start_leaf=start_leaf, progress=progress)

    @classmethod
    def _from_trusted_root(
        cls,
        seed: bytes,
        height: int,
        public_key: bytes,
        start_leaf: int = 0,
    ) -> "KeyPair":
        """Construct a KeyPair with a pre-computed Merkle root.

        Skips the O(2^height) leaf derivation that __init__ performs —
        the caller supplies a previously-computed public_key from
        trusted storage (e.g. an HMAC-authenticated cache file).

        The root is NOT re-derived, so the caller is responsible for
        making sure the supplied public_key actually corresponds to
        `seed` and `height`.  Passing a forged root produces a signer
        whose signatures will never verify against the claimed root —
        a local DoS, not a forgery vector — but callers must still
        authenticate the source before taking this path.
        """
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError("public_key must be 32 bytes (SHA3-256 output)")
        if height <= 0:
            raise ValueError(f"height must be positive, got {height}")
        kp = cls.__new__(cls)
        kp.height = height
        kp.num_leaves = 1 << height
        kp._seed = seed
        kp._next_leaf = start_leaf
        kp.leaf_index_path = None
        kp.public_key = bytes(public_key)
        kp._node_cache = None
        # Same threading-safety contract as __init__ — see the
        # comment there.  `_from_trusted_root` bypasses __init__
        # entirely, so the lock must be set up here too or
        # subsequent sign() calls AttributeError on `_sign_lock`.
        import threading as _threading
        kp._sign_lock = _threading.Lock()
        return kp

    def advance_to_leaf(self, leaf_index: int):
        """Advance the next-leaf pointer to skip already-used leaves.

        Used when reconstructing a keypair (e.g., from private key) to avoid
        reusing one-time WOTS+ keys. The caller should set this based on
        the on-chain nonce or signature count.

        Valid leaf indices are [0, num_leaves). A value equal to or greater
        than num_leaves is invalid — WOTS+ keys are one-time, and allowing
        leaf_index == num_leaves would permit a subsequent out-of-bounds
        access in sign() or wrap-around key reuse.
        """
        if leaf_index < 0:
            raise RuntimeError(f"Leaf index {leaf_index} must be non-negative")
        if leaf_index >= self.num_leaves:
            raise RuntimeError(f"Leaf index {leaf_index} exceeds tree capacity {self.num_leaves}")
        self._next_leaf = max(self._next_leaf, leaf_index)

    def sign(self, message_hash: bytes) -> Signature:
        """Sign using the next available WOTS+ leaf key (derived on demand).

        Thread-safe AND process-safe: the leaf-index reservation (read-
        modify-write of `_next_leaf`, plus the optional persist-before-
        sign disk write) runs under both `_sign_lock` (in-process,
        serializes threads in this interpreter) AND a cross-process
        advisory file lock on a sibling of `leaf_index_path` (when
        `leaf_index_path` is set).  The cross-process lock protects
        against two CLI invocations on the same wallet observing the
        same on-disk cursor and signing under the same one-time
        WOTS+ leaf — a race that mathematically reveals the leaf's
        private key.  Leaf-derivation + WOTS+ signing runs OUTSIDE
        the lock -- those operations only read the seed (immutable)
        and the reserved `leaf_idx` (local), so parallel signing on
        different leaves is allowed.

        The cursor file is machine-local; restoring the same key on a
        second host requires `rotate-key` first.  The advisory lock
        only prevents same-host races; a second machine has no fd-
        bound lock to coordinate against.
        """
        # Cross-process advisory lock on a sibling .lock file.  Held
        # across the load-from-disk → advance → persist-to-disk
        # critical section so a concurrent process cannot observe a
        # stale cursor.  In-memory _sign_lock is still held inside
        # the file lock to keep thread-level race coverage intact.
        file_lock_handle = None
        if self.leaf_index_path is not None:
            lock_path = self.leaf_index_path + ".lock"
            file_lock_handle = _acquire_leaf_cursor_lock(lock_path)

        try:
            with self._sign_lock:
                # Re-load the on-disk cursor INSIDE the file lock so a
                # concurrent process's persist (which finished before
                # we acquired the lock) is observed.  load_leaf_index
                # is monotonic — it never moves _next_leaf backwards —
                # so the in-memory state may already be ahead of disk
                # (e.g. an in-process advance_to_leaf from chain
                # watermark, or a prior sign in this same process); in
                # that case the load is a no-op.
                if self.leaf_index_path is not None:
                    try:
                        self.load_leaf_index(self.leaf_index_path)
                    except ValueError:
                        # Corrupt cursor (next_leaf >= num_leaves).
                        # Re-raise: signing further would risk reuse.
                        raise
                    except Exception:
                        # Missing / unreadable file: load_leaf_index
                        # already swallows FileNotFoundError +
                        # JSONDecodeError + OSError, so anything that
                        # bubbles up here is unexpected.  Don't crash
                        # the sign on a transient read error -- the
                        # in-memory _next_leaf is the safety floor.
                        pass

                if self._next_leaf >= self.num_leaves:
                    raise RuntimeError(
                        "Key exhausted: all one-time keys have been used"
                    )
                leaf_idx = self._next_leaf

                # Persist-BEFORE-sign: durably record "leaf_idx has been
                # consumed" before wots_sign() can produce bytes that
                # might escape this process.  If we instead signed first
                # and persisted after, a crash between the two would
                # leave the broadcast signature on the wire while the on-
                # disk counter still pointed at leaf_idx — on restart we
                # would reuse leaf_idx and sign a second message with the
                # same one-time key, which mathematically reveals the
                # WOTS+ private key for that leaf.  Burning a leaf
                # without a corresponding sign is cheap; reusing one is
                # catastrophic.  If persist_leaf_index raises (disk full,
                # I/O error), we abort the sign entirely — no signature
                # is returned and _next_leaf stays put, so the next
                # attempt retries the same leaf.
                if self.leaf_index_path is not None:
                    # persist_leaf_index reads self._next_leaf, so
                    # temporarily advance it for the write then roll
                    # back on failure.
                    self._next_leaf = leaf_idx + 1
                    try:
                        self.persist_leaf_index(self.leaf_index_path)
                    except Exception:
                        self._next_leaf = leaf_idx
                        raise
                else:
                    self._next_leaf = leaf_idx + 1

            # Derive the leaf keypair on demand — no private keys stored.
            # Outside the in-memory _sign_lock (leaf_idx is reserved &
            # disk-recorded; parallel signers on different leaves are
            # safe), but still inside the cross-process file lock.  We
            # could in principle release the file lock here too, but
            # holding it across wots_sign costs only a few ms and keeps
            # the contention model simple: one signer per process at a
            # time, full stop.
            priv_keys, pub_key, pub_seed = _derive_leaf(self._seed, leaf_idx)
            try:
                wots_sig = wots_sign(message_hash, priv_keys, pub_seed)
                if self._node_cache is not None:
                    # Cached path: O(height) slice reads rather than O(2^height)
                    # seed-based recomputation.  The cache is HMAC-authenticated
                    # on disk and its root is cross-checked against
                    # self.public_key at load time, so trusting it here does not
                    # introduce a new attack surface.
                    auth_path = self._node_cache.auth_path(leaf_idx)
                else:
                    auth_path = _compute_auth_path(self._seed, self.height, leaf_idx)
            finally:
                # Best-effort private key zeroing.  priv_keys are bytearray
                # (mutable), so we can overwrite the buffer contents in-place.
                # This limits the window in which key material sits in memory.
                for pk in priv_keys:
                    if isinstance(pk, bytearray):
                        for j in range(len(pk)):
                            pk[j] = 0

            # Exhaustion-visibility warnings.  Emit at 80% and 95% usage so
            # operators notice in their normal log pipeline long before the
            # hard wall at 100% (after which funds are locked unless the
            # user previously submitted a KeyRotationTransaction).  Deduped
            # per (root, threshold) to avoid flooding logs on every slot.
            self._maybe_warn_exhaustion()

            return Signature(
                wots_signature=wots_sig,
                leaf_index=leaf_idx,
                auth_path=auth_path,
                wots_public_key=pub_key,
                wots_public_seed=pub_seed,
            )
        finally:
            # Release the cross-process advisory lock no matter how the
            # body exits — successful sign, persist failure, exhaustion,
            # corrupt-cursor ValueError, KeyboardInterrupt, anything.
            # Without this, a sign that throws after acquire would leak
            # the lock until process exit, blocking all subsequent CLI
            # invocations on the same wallet for `_LEAF_CURSOR_LOCK_TIMEOUT_S`
            # seconds.
            _release_leaf_cursor_lock(file_lock_handle)

    def _maybe_warn_exhaustion(self) -> None:
        """Emit a WARNING log when leaf usage first crosses 80% and 95%.

        Called from sign() after _next_leaf has been incremented so the
        percentage reflects the signature just produced.  Uses integer
        math to avoid float drift at very large num_leaves (production
        is 2^20 = 1,048,576 and we must not miss the threshold due to
        rounding).
        """
        # Scale by 100 for integer comparison: used_pct_x100 is
        # (used * 100) // num_leaves, which is exact for all finite
        # tree heights we support.
        used = self._next_leaf
        total = self.num_leaves
        if total <= 0:
            return
        used_pct = (used * 100) // total
        for threshold in _SIG_WARN_PERCENTS:
            if used_pct < threshold:
                continue
            key = (bytes(self.public_key), threshold)
            if key in _warned_thresholds:
                continue
            _warned_thresholds.add(key)
            remaining = total - used
            logger.warning(
                "WOTS+ one-time signatures at %d%% capacity "
                "(%d used / %d total, %d remaining) for key %s. "
                "Run `messagechain rotate-key` before exhaustion — "
                "past 100%% the key is bricked and funds lock until "
                "a previously-signed KeyRotationTransaction is submitted.",
                threshold,
                used,
                total,
                remaining,
                self.public_key.hex()[:16],
            )

    @property
    def remaining_signatures(self) -> int:
        return self.num_leaves - self._next_leaf

    def persist_leaf_index(self, path: str) -> None:
        """Write the current _next_leaf to disk (atomic via tmp + rename).

        The file is a small JSON object so it is human-inspectable and
        trivially portable across platforms.

        Raises LeafIndexPersistError if the parent-directory fsync (the
        step that makes the rename survive a power loss) fails with a
        real I/O error.  The known-benign tmpfs case (EINVAL) is logged
        at DEBUG and treated as success.  See _fsync_parent_dir below
        for the errno classification rationale.
        """
        # Symlink traversal guard: refuse to write through symlinks.
        real_path = os.path.realpath(path)
        if real_path != os.path.abspath(path):
            raise ValueError(f"Refusing to write through symlink: {path}")

        data = {"next_leaf": self._next_leaf}
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        # Atomic rename — on POSIX this is guaranteed atomic; on Windows
        # os.replace is as close as we get.
        os.replace(tmp_path, path)
        # Durability: fsync the parent directory so the rename itself
        # survives a power loss.  Without this, POSIX can lose the
        # rename entry even when the file contents are flushed — next
        # boot sees no leaf-index file, load_leaf_index silently
        # defaults to _next_leaf=0, and the next sign() reuses leaves
        # that were already published.  WOTS+ leaf reuse = private
        # key recovery on that leaf.
        _fsync_parent_dir(os.path.dirname(os.path.abspath(path)) or ".")

    def load_leaf_index(self, path: str) -> None:
        """Restore _next_leaf from a previously-persisted file.

        If the file does not exist, _next_leaf is left unchanged (safe
        default: a fresh KeyPair starts at 0).

        The loaded value is never allowed to move _next_leaf backwards —
        this prevents a stale backup from causing WOTS+ leaf reuse.
        """
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return  # no file or corrupt — use current _next_leaf
        stored = data.get("next_leaf", 0)
        if not isinstance(stored, int) or stored < 0:
            return  # ignore corrupt data
        if stored >= self.num_leaves:
            raise ValueError(
                f"Corrupted leaf index file: next_leaf={stored} >= num_leaves={self.num_leaves}"
            )
        if stored > self._next_leaf:
            self._next_leaf = stored


def compute_root_from_signature(signature: "Signature") -> bytes | None:
    """Reconstruct the Merkle tree root (= the long-term public key) from a
    one-time WOTS+ signature's auth path.

    The signature carries the leaf public key, the leaf index, and the
    sibling hashes along the Merkle path.  Hashing upward from
    (wots_public_key, leaf_index) using auth_path yields the tree root.

    Used by joining validators during IBD to register the genesis
    entity's pubkey from block 0 alone — without knowing the entity's
    long-term public key out of band.  Separate from verify_signature
    so the caller can use the derived root to populate state (e.g.,
    self.public_keys[genesis_id] = derived_root) before any signature
    verification runs.

    Returns None if the signature is structurally malformed.
    """
    if not isinstance(signature, Signature):
        return None
    if not isinstance(signature.wots_public_key, (bytes, bytearray)) or len(signature.wots_public_key) != _HASH_SIZE:
        return None
    if not isinstance(signature.auth_path, list):
        return None
    for sib in signature.auth_path:
        if not isinstance(sib, (bytes, bytearray)) or len(sib) != _HASH_SIZE:
            return None
    if not isinstance(signature.leaf_index, int) or signature.leaf_index < 0:
        return None
    # leaf_index must be within the tree described by auth_path length.
    # Without this check, a crafted leaf_index past 2**tree_height walks
    # past the tree and produces a meaningless root.  verify_signature
    # enforces this, but compute_root_from_signature may be used without
    # a subsequent verify (e.g., state reconstruction) so we harden here.
    if signature.leaf_index >= (1 << len(signature.auth_path)):
        return None
    current = bytes(signature.wots_public_key)
    idx = signature.leaf_index
    for sibling in signature.auth_path:
        if idx & 1 == 0:
            current = _hash(current + bytes(sibling))
        else:
            current = _hash(bytes(sibling) + current)
        idx >>= 1
    return current


def verify_signature(message_hash: bytes, signature: Signature, root_public_key: bytes) -> bool:
    """
    Verify a signature against a Merkle-tree root public key.

    1. Structural validation of the signature (sizes, counts, ranges)
    2. Verify the WOTS+ signature against the leaf public key
    3. Verify the leaf public key is in the Merkle tree (via auth path)

    Returns False on any structural defect or verification failure. Never
    raises on malformed input — all rejection is via False return.
    """
    # Step 0: Structural validation. A malformed signature must be rejected
    # cleanly rather than producing an IndexError or allowing truncated
    # authentication paths to compute a spurious root.
    if not isinstance(root_public_key, (bytes, bytearray)) or len(root_public_key) != _HASH_SIZE:
        return False
    if not isinstance(message_hash, (bytes, bytearray)) or len(message_hash) != _HASH_SIZE:
        return False
    if not isinstance(signature, Signature):
        return False
    if len(signature.wots_signature) != WOTS_KEY_CHAINS:
        return False
    for part in signature.wots_signature:
        if not isinstance(part, (bytes, bytearray)) or len(part) != _HASH_SIZE:
            return False
    if not isinstance(signature.wots_public_key, (bytes, bytearray)) or len(signature.wots_public_key) != _HASH_SIZE:
        return False
    if not isinstance(signature.wots_public_seed, (bytes, bytearray)) or len(signature.wots_public_seed) != _HASH_SIZE:
        return False
    tree_height = len(signature.auth_path)
    if tree_height <= 0 or tree_height > 64:
        return False
    for sibling in signature.auth_path:
        if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != _HASH_SIZE:
            return False
    if not isinstance(signature.leaf_index, int):
        return False
    num_leaves = 1 << tree_height
    if signature.leaf_index < 0 or signature.leaf_index >= num_leaves:
        return False

    # Step 1: Verify WOTS+ signature.  Pass through the signature's
    # own sig_version so legacy V1 sigs are verified under the old
    # checksum encoding (which the live chain committed with before
    # the V2 fix) while V2 sigs go through the corrected encoder.
    if not wots_verify(message_hash, signature.wots_signature,
                       signature.wots_public_key, signature.wots_public_seed,
                       sig_version=signature.sig_version):
        return False

    # Step 2: Verify Merkle path from leaf to root
    current = signature.wots_public_key
    idx = signature.leaf_index
    for sibling in signature.auth_path:
        if idx & 1 == 0:
            current = _hash(current + sibling)
        else:
            current = _hash(sibling + current)
        idx >>= 1

    # Constant-time comparison to avoid timing side-channels.
    return hmac.compare_digest(current, root_public_key)
