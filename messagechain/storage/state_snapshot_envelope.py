"""HMAC-tagged envelope for state-snapshot blobs.

The state-snapshot blob persisted at the end of every block apply
contains the full consensus-critical in-memory state (balances,
accumulators, escrow, ratchet state, etc.) serialized via ``pickle``.
``pickle.loads`` is a remote-code-execution primitive: anyone who can
write a single row in ``chain.db.state_snapshots`` -- a tampered
backup tape, a restored snapshot from an untrusted host, a misconfig-
ured-permissions data dir -- gets arbitrary code execution at
validator-process privilege the next time the node cold-boots,
reorgs, or runs a fork-emergency rewind, BEFORE any signature or
state-root check fires.

This envelope wraps the raw pickle blob in an HMAC-SHA256 tag keyed
by a per-node secret stored in the chaindb ``meta`` table.  On read,
the tag is verified in constant time before ``pickle.loads`` is ever
called; an envelope that fails verification raises and the caller
falls back to the legacy field-by-field load.

Threat model: an attacker who can write the snapshot blob alone (via
backup-restore, filesystem permissions error, or hostile supply chain
on disk images) cannot forge a valid envelope because they don't
have the per-node secret.  An attacker who already has full chaindb
write access (including the secret in ``meta``) is outside the scope
this envelope defends -- such an attacker can tamper with balances
directly and the snapshot is no longer the weakest link.

Wire format (no version byte beyond the magic; bump magic for v2):

    bytes 0..7:    MAGIC = b"MCSNAPv1"
    bytes 8..39:   HMAC-SHA256(secret, payload)   (32 bytes)
    bytes 40..:    payload  (the raw pickle blob produced by
                   ``pickle.dumps(snap, protocol=HIGHEST_PROTOCOL)``)
"""

from __future__ import annotations

import hmac
import hashlib
import secrets


MAGIC = b"MCSNAPv1"
_TAG_LEN = 32  # HMAC-SHA256 output length
_HEADER_LEN = len(MAGIC) + _TAG_LEN

# How many bytes of secret to generate for a fresh node.  HMAC-SHA256
# accepts arbitrary key length; 32 bytes (== output length) is the
# canonical choice -- longer doesn't add security, shorter compresses
# the keyspace for an offline-search attacker.
_SECRET_BYTES = 32


class SnapshotEnvelopeError(Exception):
    """Raised when an HMAC-tagged snapshot envelope fails to verify.

    Callers should treat this as "blob is untrusted" and fall back to
    a load path that does NOT call ``pickle.loads`` on the blob.
    """


def generate_secret() -> bytes:
    """Generate a fresh per-node HMAC secret.  Persist this once via
    ChainDB.set_meta and reuse forever; rotating it forces a re-snapshot
    on the next block apply but does not break the chain."""
    return secrets.token_bytes(_SECRET_BYTES)


def pack(payload: bytes, secret: bytes) -> bytes:
    """Wrap ``payload`` (typically a pickle blob) in the v1 envelope.

    The returned blob is what callers should write to chaindb.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("secret must be non-empty bytes")
    tag = hmac.new(secret, bytes(payload), hashlib.sha256).digest()
    return MAGIC + tag + bytes(payload)


def unpack(blob: bytes, secret: bytes) -> bytes:
    """Verify the envelope and return the inner payload.

    Raises ``SnapshotEnvelopeError`` if the magic is wrong, the blob
    is truncated, or the HMAC tag does not match the payload under
    ``secret``.  Constant-time comparison so an attacker cannot
    distinguish "wrong magic" from "wrong tag" timing.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise SnapshotEnvelopeError("blob must be bytes")
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise SnapshotEnvelopeError("secret must be non-empty bytes")
    blob = bytes(blob)
    if len(blob) < _HEADER_LEN:
        raise SnapshotEnvelopeError(
            f"snapshot blob too short ({len(blob)} bytes; need >="
            f" {_HEADER_LEN})",
        )
    if blob[:len(MAGIC)] != MAGIC:
        raise SnapshotEnvelopeError(
            "snapshot magic mismatch (legacy unprefixed blob, or "
            "different envelope version)",
        )
    tag = blob[len(MAGIC):_HEADER_LEN]
    payload = blob[_HEADER_LEN:]
    expected = hmac.new(
        bytes(secret), payload, hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(tag, expected):
        raise SnapshotEnvelopeError(
            "snapshot HMAC tag mismatch (tampered or written under "
            "a different node secret)",
        )
    return payload


def is_envelope(blob: bytes) -> bool:
    """Return True if the blob carries the v1 magic prefix.

    Used by callers that want to log "legacy unprefixed blob" vs
    "tampered/foreign envelope" distinctly without calling unpack.
    """
    return (
        isinstance(blob, (bytes, bytearray))
        and len(blob) >= len(MAGIC)
        and bytes(blob[:len(MAGIC)]) == MAGIC
    )
