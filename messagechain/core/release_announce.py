"""
ReleaseAnnounceTransaction — threshold multi-sig'd release manifest.

Signals "new node/validator release available" on-chain without giving
any single party remote-code-execution rights over validators.  The
manifest carries:

- `version`            — the release string (e.g., "1.2.3").
- `binary_hashes`      — platform → SHA3-256 of the distributed binary.
- `min_activation_height` — optional earliest height at which the
                             release is "active" (advisory only — no
                             auto-apply, no consensus gating).
- `release_notes_uri`  — pointer to human-readable notes (off-chain).
- `severity`           — 0 normal, 1 security, 2 emergency.
- `nonce`              — 16 random bytes for replay protection; the
                          canonical signable data commits to it, so
                          two announcements with identical fields but
                          different nonces produce distinct tx_hashes
                          (useful for recalling a superseded manifest).
- `signer_indices`     — which entries in `config.RELEASE_KEY_ROOTS`
                          the signatures correspond to.
- `signatures`         — WOTS+ signatures parallel to signer_indices.

## Verify semantics

`verify()` enforces:

1. Every signature is a valid WOTS+ sig over the canonical signable
   data, against the release-key pubkey at `signer_indices[i]`.
2. The number of **unique** signer indices is >= RELEASE_THRESHOLD.
   A duplicate index does not count twice — otherwise a single
   compromised key could unilaterally satisfy the threshold by
   self-replicating its own signature.
3. Every index is in range of `RELEASE_KEY_ROOTS`.
4. `sig_version` on every signature matches SIG_VERSION_CURRENT
   (crypto-agility boundary; mismatch → reject).

## Apply semantics

This iteration is storage-only: `_apply_authority_tx` in Blockchain
sets `blockchain.latest_release_manifest = tx` if `verify()` passes
and the new `version` is lexicographically greater than the current
one (or the current is None).  No balance change, no fee, no slashing,
no auto-apply of the announced binary.  Operator notification is a
follow-up iteration.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from messagechain.config import (
    CHAIN_ID,
    HASH_ALGO,
    RELEASE_ANNOUNCE_MAX_PLATFORMS,
    RELEASE_ANNOUNCE_MAX_URI_LEN,
    RELEASE_ANNOUNCE_VERSION_MAX_LEN,
    SIG_VERSION_CURRENT,
    TX_SERIALIZATION_VERSION,
    validate_sig_version,
    validate_tx_serialization_version,
)
from messagechain.core.release_version import parse_release_version
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.crypto.hashing import default_hash

# Domain-separation tag — bound into `_signable_data` so a signature
# over a ReleaseAnnounce manifest cannot be replayed against any other
# transaction type (or vice versa).  Changing this breaks all existing
# signatures by design.
_DOMAIN_TAG = b"release_announce"

# Hash output size (SHA3-256) — same constant used throughout the crypto
# layer.  Binary hashes in the manifest must be exactly this many bytes.
_HASH_SIZE = 32

# Nonce length — 16 random bytes, per spec.  Longer would be wasteful;
# shorter would risk collisions for recalled-and-re-issued manifests.
_NONCE_SIZE = 16


def _hash(data: bytes) -> bytes:
    return default_hash(data)


def _canonical_binary_hashes_blob(binary_hashes: Dict[str, bytes]) -> bytes:
    """Deterministic byte encoding of the platform → hash map.

    Sorted by platform name so the signable data is stable regardless
    of dict insertion order.  Length-prefixed entries prevent ambiguous
    concatenation (same defense Signature.canonical_bytes uses).
    """
    parts = [struct.pack(">H", len(binary_hashes))]
    for platform in sorted(binary_hashes):
        h = binary_hashes[platform]
        pname = platform.encode("utf-8")
        parts.append(struct.pack(">H", len(pname)))
        parts.append(pname)
        parts.append(struct.pack(">H", len(h)))
        parts.append(h)
    return b"".join(parts)


@dataclass
class ReleaseAnnounceTransaction:
    """Threshold multi-sig'd release manifest.

    No `entity_id`, no `fee`, no `nonce` counter — this tx is issued
    by a hardcoded committee (`config.RELEASE_KEY_ROOTS`), not by any
    per-entity account.  Replay is defeated by the random 16-byte
    `nonce` field, which the signable data commits to (so two
    announcements of the same version with different nonces produce
    distinct tx_hashes, and a recorded manifest cannot be silently
    re-broadcast under a fresh identity).
    """

    version: str
    binary_hashes: Dict[str, bytes]
    min_activation_height: Optional[int]
    release_notes_uri: str
    severity: int
    nonce: bytes
    signer_indices: List[int] = field(default_factory=list)
    signatures: List[Signature] = field(default_factory=list)
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def affected_entities(self) -> set[bytes]:
        """ReleaseAnnounce is committee-signed, not per-entity.  No fee,
        no nonce, no entity to debit.  Apply path only updates the
        ``latest_release_manifest`` scalar (NOT inside the per-entity
        SMT leaf commitment).  Empty set — no state_tree rows touched.
        See CLAUDE.md canonical registry contract.
        """
        return set()

    # ──────────────────────────────────────────────────────────────
    # Signable data
    # ──────────────────────────────────────────────────────────────
    def _signable_body(self) -> bytes:
        """Everything in the signable data EXCEPT chain_id/tag/sig_version.

        Factored out so `_signable_data` can wrap it with the outer
        preamble (chain id + domain tag + sig_version) without having
        to duplicate field layout in two places.  Also exposed to
        tests that need to prove domain-separation works.
        """
        version_bytes = self.version.encode("utf-8")
        uri_bytes = self.release_notes_uri.encode("utf-8")
        parts = [
            struct.pack(">B", len(version_bytes)),
            version_bytes,
            _canonical_binary_hashes_blob(self.binary_hashes),
            # min_activation_height: u8 present-flag + u64 value (0 when absent)
            struct.pack(
                ">BQ",
                1 if self.min_activation_height is not None else 0,
                int(self.min_activation_height or 0),
            ),
            struct.pack(">H", len(uri_bytes)),
            uri_bytes,
            struct.pack(">B", int(self.severity)),
            self.nonce,
        ]
        return b"".join(parts)

    def _signable_data(self) -> bytes:
        """Canonical bytes that every release-signer signs.

        Layout: CHAIN_ID || b"release_announce" || u8 sig_version || body.
        The domain tag is bound so a valid signature over a release
        manifest cannot be replayed against any other tx type; the
        sig_version is bound so a crypto-agility upgrade retires the
        old signatures cleanly (old sig won't verify against the new
        preamble).
        """
        sig_version = SIG_VERSION_CURRENT
        # If any signature is already attached, reuse its sig_version —
        # all signatures on a single manifest share a sig_version.
        if self.signatures:
            sig_version = getattr(
                self.signatures[0], "sig_version", SIG_VERSION_CURRENT,
            )
        return (
            CHAIN_ID
            + _DOMAIN_TAG
            + struct.pack(">B", sig_version)
            + self._signable_body()
        )

    def _compute_hash(self) -> bytes:
        # tx_hash covers the signable data AND the signer set: without
        # binding signer_indices + signatures into the hash, two
        # semantically identical announces with different signer
        # subsets would collide (and the block decoder's tx_hash check
        # would accept either).
        parts = [self._signable_data()]
        parts.append(struct.pack(">H", len(self.signer_indices)))
        for idx in self.signer_indices:
            parts.append(struct.pack(">H", int(idx)))
        parts.append(struct.pack(">H", len(self.signatures)))
        for sig in self.signatures:
            sb = sig.to_bytes()
            parts.append(struct.pack(">I", len(sb)))
            parts.append(sb)
        return _hash(b"".join(parts))

    # ──────────────────────────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────────────────────────
    def verify(self) -> bool:
        """Threshold multi-sig verify against config.RELEASE_KEY_ROOTS.

        - sig_version must match SIG_VERSION_CURRENT (crypto-agility gate).
        - len(signer_indices) == len(signatures).
        - Each index must be in range of RELEASE_KEY_ROOTS.
        - Each signature must verify WOTS+ under the corresponding root.
        - Unique-index count must reach RELEASE_THRESHOLD.
        """
        # Read config lazily so test fixtures that monkeypatch
        # `config.RELEASE_KEY_ROOTS` / `RELEASE_THRESHOLD` are picked up.
        from messagechain import config as _cfg
        roots = _cfg.RELEASE_KEY_ROOTS
        threshold = _cfg.RELEASE_THRESHOLD

        if len(self.signer_indices) != len(self.signatures):
            return False
        if not self.signatures:
            return False

        # Bounds checks first — cheap rejection before any hash work.
        for idx in self.signer_indices:
            if not isinstance(idx, int) or idx < 0 or idx >= len(roots):
                return False

        # Crypto-agility gate: reject unknown sig_version without ever
        # trying to verify the sig.
        for sig in self.signatures:
            ok, _ = validate_sig_version(getattr(sig, "sig_version", 0))
            if not ok:
                return False

        # Structural bounds — keep verify O(1) on obvious garbage.
        if len(self.nonce) != _NONCE_SIZE:
            return False
        # Outer size gate (primary): the wire format itself caps the
        # version string at RELEASE_ANNOUNCE_VERSION_MAX_LEN.  Re-check
        # here for objects that bypassed the decoder (tampering tests,
        # in-memory construction).  An additional inner 64-char cap
        # inside parse_release_version() is belt-and-suspenders.
        if len(self.version.encode("utf-8")) > RELEASE_ANNOUNCE_VERSION_MAX_LEN:
            return False
        # Strict-semver gate: the `version` field must parse as
        # MAJOR.MINOR.PATCH[-PRERELEASE].  Without this, any bytes
        # that deserialize successfully would pollute the state slot
        # (e.g. "zzz" or "9.9.9\x00evil"), and the semver monotonic
        # guard in blockchain.py would silently skip them — which
        # would be the old lex-compare bug wearing a disguise.
        try:
            parse_release_version(self.version)
        except ValueError:
            return False
        if len(self.release_notes_uri.encode("utf-8")) > RELEASE_ANNOUNCE_MAX_URI_LEN:
            return False
        if len(self.binary_hashes) > RELEASE_ANNOUNCE_MAX_PLATFORMS:
            return False
        for h in self.binary_hashes.values():
            if not isinstance(h, (bytes, bytearray)) or len(h) != _HASH_SIZE:
                return False
        if self.severity not in (0, 1, 2):
            return False

        msg_hash = _hash(self._signable_data())
        for idx, sig in zip(self.signer_indices, self.signatures):
            if not verify_signature(msg_hash, sig, roots[idx]):
                return False

        # Unique signer count — a duplicate index does NOT count.  This
        # blocks a single compromised key from unilaterally "reaching"
        # threshold by self-replicating a signature.
        unique = len(set(self.signer_indices))
        if unique < threshold:
            return False
        return True

    # ──────────────────────────────────────────────────────────────
    # Serialization
    # ──────────────────────────────────────────────────────────────
    def serialize(self) -> dict:
        return {
            "type": "release_announce",
            "version": self.version,
            "binary_hashes": {
                k: v.hex() for k, v in self.binary_hashes.items()
            },
            "min_activation_height": self.min_activation_height,
            "release_notes_uri": self.release_notes_uri,
            "severity": self.severity,
            "nonce": self.nonce.hex(),
            "signer_indices": list(self.signer_indices),
            "signatures": [s.serialize() for s in self.signatures],
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ReleaseAnnounceTransaction":
        sigs = [Signature.deserialize(s) for s in data["signatures"]]
        tx = cls(
            version=data["version"],
            binary_hashes={
                k: bytes.fromhex(v) for k, v in data["binary_hashes"].items()
            },
            min_activation_height=data.get("min_activation_height"),
            release_notes_uri=data["release_notes_uri"],
            severity=int(data["severity"]),
            nonce=bytes.fromhex(data["nonce"]),
            signer_indices=list(data["signer_indices"]),
            signatures=sigs,
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"ReleaseAnnounce hash mismatch: declared "
                f"{data['tx_hash'][:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding.

        Layout (all big-endian unsigned):
            u8   TX_SERIALIZATION_VERSION
            u8   version_len + version_bytes
            u16  platform_count
            per platform: u16 name_len + name + u16 hash_len + hash
            u8   has_min_height + u64 min_height (zero when absent)
            u16  uri_len + uri_bytes
            u8   severity
            16   nonce
            u16  signer_count
            per signer: u16 index
            u16  signature_count
            per signature: u32 sig_len + sig_bytes
            32   tx_hash
        """
        # `state` is accepted for compatibility with the polymorphic
        # authority-tx encoder — ReleaseAnnounce carries no entity_id,
        # so the registry-aware varint-index form does not apply.
        parts = [struct.pack(">B", TX_SERIALIZATION_VERSION)]
        parts.append(self._signable_body())
        parts.append(struct.pack(">H", len(self.signer_indices)))
        for idx in self.signer_indices:
            parts.append(struct.pack(">H", int(idx)))
        parts.append(struct.pack(">H", len(self.signatures)))
        for sig in self.signatures:
            sb = sig.to_bytes()
            parts.append(struct.pack(">I", len(sb)))
            parts.append(sb)
        parts.append(self.tx_hash)
        return b"".join(parts)

    @classmethod
    def from_bytes(
        cls, data: bytes, state=None,
    ) -> "ReleaseAnnounceTransaction":
        off = 0

        def need(n: int):
            nonlocal off
            if off + n > len(data):
                raise ValueError("ReleaseAnnounce blob truncated")

        need(1)
        ser_version = struct.unpack_from(">B", data, off)[0]; off += 1
        ok, reason = validate_tx_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"ReleaseAnnounce: {reason}")

        need(1)
        vlen = struct.unpack_from(">B", data, off)[0]; off += 1
        if vlen > RELEASE_ANNOUNCE_VERSION_MAX_LEN:
            raise ValueError(
                f"ReleaseAnnounce version too long: {vlen} > "
                f"{RELEASE_ANNOUNCE_VERSION_MAX_LEN}"
            )
        need(vlen)
        version = bytes(data[off:off + vlen]).decode("utf-8"); off += vlen

        need(2)
        platform_count = struct.unpack_from(">H", data, off)[0]; off += 2
        if platform_count > RELEASE_ANNOUNCE_MAX_PLATFORMS:
            raise ValueError(
                f"ReleaseAnnounce too many platforms: {platform_count} > "
                f"{RELEASE_ANNOUNCE_MAX_PLATFORMS}"
            )
        binary_hashes: Dict[str, bytes] = {}
        for _ in range(platform_count):
            need(2)
            nlen = struct.unpack_from(">H", data, off)[0]; off += 2
            need(nlen)
            pname = bytes(data[off:off + nlen]).decode("utf-8"); off += nlen
            need(2)
            hlen = struct.unpack_from(">H", data, off)[0]; off += 2
            if hlen != _HASH_SIZE:
                raise ValueError(
                    f"ReleaseAnnounce binary hash has wrong size: "
                    f"{hlen} (expected {_HASH_SIZE})"
                )
            need(hlen)
            binary_hashes[pname] = bytes(data[off:off + hlen]); off += hlen

        need(9)
        has_mh = struct.unpack_from(">B", data, off)[0]; off += 1
        mh_val = struct.unpack_from(">Q", data, off)[0]; off += 8
        min_activation_height = mh_val if has_mh else None

        need(2)
        uri_len = struct.unpack_from(">H", data, off)[0]; off += 2
        if uri_len > RELEASE_ANNOUNCE_MAX_URI_LEN:
            raise ValueError(
                f"ReleaseAnnounce URI too long: {uri_len} > "
                f"{RELEASE_ANNOUNCE_MAX_URI_LEN}"
            )
        need(uri_len)
        release_notes_uri = bytes(data[off:off + uri_len]).decode("utf-8")
        off += uri_len

        need(1 + _NONCE_SIZE)
        severity = struct.unpack_from(">B", data, off)[0]; off += 1
        nonce = bytes(data[off:off + _NONCE_SIZE]); off += _NONCE_SIZE

        need(2)
        sig_idx_count = struct.unpack_from(">H", data, off)[0]; off += 2
        signer_indices: List[int] = []
        for _ in range(sig_idx_count):
            need(2)
            signer_indices.append(
                struct.unpack_from(">H", data, off)[0],
            )
            off += 2

        need(2)
        sig_count = struct.unpack_from(">H", data, off)[0]; off += 2
        signatures: List[Signature] = []
        for _ in range(sig_count):
            need(4)
            slen = struct.unpack_from(">I", data, off)[0]; off += 4
            need(slen)
            signatures.append(
                Signature.from_bytes(bytes(data[off:off + slen])),
            )
            off += slen

        need(32)
        declared_hash = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("ReleaseAnnounce has trailing bytes")

        tx = cls(
            version=version,
            binary_hashes=binary_hashes,
            min_activation_height=min_activation_height,
            release_notes_uri=release_notes_uri,
            severity=severity,
            nonce=nonce,
            signer_indices=signer_indices,
            signatures=signatures,
        )
        expected = tx._compute_hash()
        if expected != declared_hash:
            raise ValueError(
                f"ReleaseAnnounce hash mismatch: declared "
                f"{declared_hash.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx


def create_release_announce_transaction(
    *,
    version: str,
    binary_hashes: Dict[str, bytes],
    min_activation_height: Optional[int],
    release_notes_uri: str,
    severity: int,
    nonce: bytes,
    signers,
) -> ReleaseAnnounceTransaction:
    """Build and sign a release-announce tx.

    `signers` is a list of (index, Entity) tuples where `index` is the
    signer's position in `config.RELEASE_KEY_ROOTS` and the Entity is
    the corresponding keypair (signing test fixtures or a real offline
    signer in production).  The index order is preserved on the wire
    so the verifier pairs signatures with pubkeys correctly.
    """
    # Build the unsigned tx so we can compute the canonical signable
    # data once, then sign it with each signer's keypair.
    tx = ReleaseAnnounceTransaction(
        version=version,
        binary_hashes=dict(binary_hashes),
        min_activation_height=min_activation_height,
        release_notes_uri=release_notes_uri,
        severity=severity,
        nonce=nonce,
        signer_indices=[idx for idx, _ in signers],
        signatures=[],
    )
    msg_hash = _hash(tx._signable_data())
    tx.signatures = [entity.keypair.sign(msg_hash) for _, entity in signers]
    tx.tx_hash = tx._compute_hash()
    return tx
