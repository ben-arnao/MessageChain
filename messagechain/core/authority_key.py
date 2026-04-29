"""
Authority-key (cold-key) management for MessageChain.

Standard single-key identity: one key signs everything. Fine for a
message-sending user, but a validator who leaves the signing key loaded
on a running node 24/7 has no defense-in-depth: a compromised server
means lost stake, stolen rewards, and hostile governance votes.

The authority key is a separately-generated public key, kept offline,
that gates the critical withdrawal paths:

- Unstaking (moving stake back to liquid balance).
- Emergency revoke (instantly disabling a compromised validator — see
  the emergency_revoke module).

Block production, attestation, message sending, and staking-more continue
to require only the hot signing key. That is the set of operations a
running validator actually needs to perform to do its job; anything
destructive is gated on the cold key.

The cold key is FIRST installed by a SetAuthorityKey transaction signed
with the current signing key. Before any SetAuthorityKey has been
applied, the entity's authority key implicitly equals its signing key —
the single-key model remains the default for backward compatibility.

## Tier 46 — Cold-key counter-signature on rebind

Until Tier 46 the SetAuthorityKey transaction *itself* was signed only
by the hot key, including when it was used to RE-BIND an
already-installed cold key to a new value. That made hot-key compromise
operationally equivalent to cold-key compromise: an attacker with the
hot key could broadcast SetAuthorityKey(new_authority_key=ATTACKER) and
inherit Unstake/Revoke. The defense-in-depth was not actually present.

At/above ``AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT`` a SetAuthorityKey
that re-binds an already-installed authority key MUST carry a second
signature verified under the EXISTING cold key. The first-time install
path is unchanged — the user has no cold key yet to counter-sign with.

Pre-activation blobs (no trailer) round-trip byte-identically to the
pre-fork encoding so historical blocks replay deterministically.
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from messagechain.config import (
    CHAIN_ID,
    HASH_ALGO,
    MAX_TIMESTAMP_DRIFT,
    MIN_FEE,
    SIG_VERSION_CURRENT,
)
from messagechain.crypto.hashing import default_hash
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return default_hash(data)


# Wire-format marker that distinguishes a post-Tier-46 cold-signed
# SetAuthorityKey blob from a legacy hot-only one.  The legacy
# encoding ends in a 32-byte tx_hash immediately after the hot
# signature; the cold-signed encoding inserts ``\x01`` + the
# length-prefixed cold sig before the tx_hash.  Mirrors the marker-
# pattern used by RevokeTransaction's Tier 26 window field.
_COLD_SIG_MARKER = 0x01


@dataclass
class SetAuthorityKeyTransaction:
    """Promote (or rebind) the entity's authority public key.

    First-time install: signed by the current signing key only — the
    user is authenticating as themselves, not yet as the cold identity.

    Tier 46 rebind: when the entity already has an installed authority
    key, this tx must additionally carry ``cold_signature`` — a
    signature over the same signable bytes, verified under the
    currently-installed authority key.  The hot key alone is no longer
    sufficient to escalate cold-key powers to a different cold key.
    """
    entity_id: bytes
    new_authority_key: bytes
    nonce: int
    timestamp: float
    fee: int
    signature: Signature
    # Tier 46: optional second signature from the currently-installed
    # cold key. None encodes the legacy / first-install form. Present
    # when the tx is re-binding an already-installed cold key at/above
    # AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT.
    cold_signature: Optional[Signature] = None
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def has_cold_signature(self) -> bool:
        """True if this tx carries a Tier 46 cold-key counter-signature.

        ``cold_signature is None`` is the legacy / first-install form.
        A placeholder ``Signature([], 0, [], b"", b"")`` is also
        treated as "no cold sig" so unsigned-construction paths
        (``Signature.to_bytes()`` returns b"" for the placeholder) do
        not accidentally promote themselves to the cold-signed wire
        form.
        """
        cs = self.cold_signature
        if cs is None:
            return False
        # Treat the unsigned placeholder as "absent" — same convention
        # the rest of the tx classes use for unfinished construction.
        if not cs.wots_signature and not cs.wots_public_key:
            return False
        return True

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"set_authority_key"
            + struct.pack(">B", sig_version)
            + self.entity_id
            + self.new_authority_key
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def affected_entities(self) -> set[bytes]:
        """Apply path installs the new authority key on entity_id and
        bumps the entity's nonce + leaf_watermark + balance (fee).
        new_authority_key is a raw public key, not a registered entity,
        so only entity_id needs its state_tree row refreshed.
        See CLAUDE.md canonical registry contract.
        """
        return {self.entity_id}

    def _compute_hash(self) -> bytes:
        # The tx_hash commits to the cold signature (when present) so
        # an attacker cannot drop the cold counter-sig from a captured
        # cold-signed blob and replay it as a legacy hot-only one with
        # an unchanged hash.  The commitment uses canonical_bytes(),
        # which already includes sig_version + WOTS+ chains + auth path,
        # so the cold sig is bound at the same granularity as the hot.
        base = self._signable_data()
        if self.has_cold_signature():
            base = (
                base
                + b"cold"
                + self.cold_signature.canonical_bytes()
            )
        return _hash(base)

    def serialize(self) -> dict:
        out = {
            "type": "set_authority_key",
            "entity_id": self.entity_id.hex(),
            "new_authority_key": self.new_authority_key.hex(),
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }
        if self.has_cold_signature():
            out["cold_signature"] = self.cold_signature.serialize()
        return out

    def to_bytes(self, state=None) -> bytes:
        """Binary wire format.

        Pre-Tier-46 (legacy / first-install):
          ENT entity_ref | 32 new_authority_key | u64 nonce |
          f64 timestamp | u64 fee | u32 sig_len | sig | 32 tx_hash

        Tier 46 cold-signed (rebind):
          ENT entity_ref | 32 new_authority_key | u64 nonce |
          f64 timestamp | u64 fee | u32 sig_len | sig
          | u8 0x01 (cold-sig-present marker)
          | u32 cold_sig_len | cold_sig
          | 32 tx_hash

        new_authority_key is a raw public key (not an entity_id) —
        it is deliberately NOT encoded as an entity reference because
        the cold key often does not belong to a registered on-chain
        entity (keeping it wholly off-chain prevents a leaf-reveal
        attack on it).

        The legacy encoding is unchanged at the byte level when
        ``cold_signature`` is absent — replay determinism on
        historical blocks is preserved.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        parts = [
            encode_entity_ref(self.entity_id, state=state),
            self.new_authority_key,
            struct.pack(">Q", self.nonce),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ]
        if self.has_cold_signature():
            cold_blob = self.cold_signature.to_bytes()
            parts.append(struct.pack(">B", _COLD_SIG_MARKER))
            parts.append(struct.pack(">I", len(cold_blob)))
            parts.append(cold_blob)
        # tx_hash always last so legacy parsers find their 32-byte
        # trailer immediately after the hot signature.
        parts.append(self.tx_hash)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "SetAuthorityKeyTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 32 + 8 + 8 + 8 + 4 + 32:
            raise ValueError("SetAuthorityKey blob too short")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        new_auth = bytes(data[off:off + 32]); off += 32
        nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SetAuthorityKey truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len

        # Tier 46: disambiguate legacy vs cold-signed by trailing length.
        # Legacy has exactly 32 bytes left (the tx_hash); cold-signed has
        # 1 (marker) + 4 (cold_sig_len) + cold_sig + 32 (tx_hash).
        cold_sig: Optional[Signature] = None
        remaining = len(data) - off
        if remaining == 32:
            pass  # legacy — no cold sig trailer
        else:
            # Must be the marker form.  Anything else is malformed.
            if remaining < 1 + 4 + 32:
                raise ValueError(
                    "SetAuthorityKey has unexpected trailer length "
                    f"{remaining} (expected 32 legacy or marker+u32+sig+32 cold-signed)"
                )
            marker = data[off]; off += 1
            if marker != _COLD_SIG_MARKER:
                raise ValueError(
                    f"SetAuthorityKey unknown trailer marker {marker:#x}"
                )
            cold_sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
            if off + cold_sig_len + 32 > len(data):
                raise ValueError(
                    "SetAuthorityKey truncated at cold_signature/tx_hash"
                )
            cold_sig = Signature.from_bytes(
                bytes(data[off:off + cold_sig_len])
            ); off += cold_sig_len

        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SetAuthorityKey has trailing bytes")
        tx = cls(
            entity_id=entity_id, new_authority_key=new_auth,
            nonce=nonce, timestamp=timestamp, fee=fee, signature=sig,
            cold_signature=cold_sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SetAuthorityKey hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "SetAuthorityKeyTransaction":
        sig = Signature.deserialize(data["signature"])
        cold_sig: Optional[Signature] = None
        if "cold_signature" in data and data["cold_signature"] is not None:
            cold_sig = Signature.deserialize(data["cold_signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            new_authority_key=bytes.fromhex(data["new_authority_key"]),
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            cold_signature=cold_sig,
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"SetAuthorityKey hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx


def create_set_authority_key_transaction(
    entity,
    new_authority_key: bytes,
    nonce: int,
    fee: int = MIN_FEE,
) -> SetAuthorityKeyTransaction:
    """Build and sign a SetAuthorityKey transaction (FIRST-INSTALL form).

    Signed with the entity's current signing key (hot) only. The new
    authority key is just a public key — it does NOT need to belong
    to an on-chain entity, and typically should not (keeping the cold
    key completely off-chain prevents a leaf-reveal attack on it).

    Use this when no authority key has been installed yet for the
    entity, OR pre-activation where the legacy hot-only path is still
    accepted on rebind. For the post-activation rebind path, use
    ``create_set_authority_key_rebind_transaction`` which attaches the
    cold-key counter-signature.
    """
    tx = SetAuthorityKeyTransaction(
        entity_id=entity.entity_id,
        new_authority_key=new_authority_key,
        nonce=nonce,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def create_set_authority_key_rebind_transaction(
    entity,
    new_authority_key: bytes,
    nonce: int,
    fee: int = MIN_FEE,
    *,
    existing_cold_keypair,
) -> SetAuthorityKeyTransaction:
    """Build a Tier-46 cold-signed rebind SetAuthorityKey transaction.

    Both the hot key (``entity.keypair``) and the currently-installed
    cold key (``existing_cold_keypair``) sign the same canonical
    payload. At/above ``AUTHORITY_REBIND_REQUIRES_COLD_HEIGHT`` this
    is the only acceptable rebind form.

    Order matters: the cold sig is computed AFTER the hot sig is
    placed, because tx_hash commits to both signatures. The cold sig
    itself signs only the pre-cold-sig signable bytes — i.e., what
    the hot key signed — so a verifier can check both signatures
    against the same byte sequence.
    """
    tx = SetAuthorityKeyTransaction(
        entity_id=entity.entity_id,
        new_authority_key=new_authority_key,
        nonce=nonce,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    # Cold counter-sig signs the SAME canonical payload the hot key
    # signed (entity_id, new_authority_key, nonce, timestamp, fee, +
    # sig_version), endorsing the same operation.
    tx.cold_signature = existing_cold_keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_set_authority_key_transaction(
    tx: SetAuthorityKeyTransaction,
    signing_public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify structural fields and the hot-key signature.

    `current_height` selects the fee rule: post
    FEE_INCLUDES_SIGNATURE_HEIGHT the floor becomes max(MIN_FEE,
    sig-aware min) so large WOTS+ witnesses can't be admitted at
    MIN_FEE (R5-A).

    NOTE: this verifier does NOT check the cold counter-signature —
    that's a chain-state-dependent check (it requires reading
    ``authority_keys[entity_id]``) and lives in
    ``Blockchain.validate_set_authority_key``.  The standalone verifier
    here is used by mempool / RPC / unit-test paths that only need the
    structural and hot-sig checks.
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    if len(tx.new_authority_key) != 32:
        return False
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=MIN_FEE,
    ):
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, signing_public_key)


def verify_set_authority_key_cold_countersig(
    tx: SetAuthorityKeyTransaction,
    existing_cold_public_key: bytes,
) -> bool:
    """Verify the Tier 46 cold-key counter-signature.

    Returns False if no cold signature is present, OR if the present
    cold signature does not verify under ``existing_cold_public_key``.
    The "no cold sig present" rejection is intentional: callers should
    only invoke this when they've already determined a cold counter-
    sig is REQUIRED (post-activation rebind).
    """
    if not tx.has_cold_signature():
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(
        msg_hash, tx.cold_signature, existing_cold_public_key,
    )
