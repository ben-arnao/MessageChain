"""
Emergency revocation for compromised validators.

When a validator's hot signing key is suspected compromised (server
intrusion, leaked backup, rogue operator), the cold authority-key
holder broadcasts a RevokeTransaction. Immediately upon inclusion:

- The entity is flagged as revoked. Subsequent blocks proposed by this
  entity and attestations from it are rejected by validation — the
  compromised key can no longer affect consensus or earn rewards.
- All active stake is pushed into the normal 7-day unbonding queue.
  The cold-key holder recovers the funds after the standard delay.
  Slashing windows remain open for in-flight evidence during that
  period, so this does not let an attacker escape punishment for past
  misbehavior.

The revoke tx is signed by the authority (cold) key. The whole point
is that the attacker does NOT have this key — it lives offline, and
is only used for this emergency path and for unstaking.

## Why no nonce

Revoke is intentionally *nonce-free* and idempotent.  apply_revoke
rejects re-submission of an already-revoked entity, so the only
meaningful side effect is the one-way flip of a flag.  Dropping the
nonce lets operators pre-sign a revoke offline (on paper, in a cold
environment) without needing to know the live nonce — the whole point
of an emergency kill-switch is that it's ready to broadcast the
moment a compromise is suspected, not to wait while the operator
queries a trusted node for a counter value.

## Chain-height window (Tier 26 / REVOKE_TX_WINDOW_HEIGHT)

Past timestamps were originally accepted unboundedly (see git
history) so a revoke pre-signed months ago could still apply.
Combined with nonce-free idempotency, that made any captured signed
hex a permanent bearer broadcast token: anyone who later recovered a
leaked backup, photo, or USB stick could broadcast the un-aged
revoke and force the target validator into the 7-day unbonding queue.

Tier 26 closes the bearer-replay window without losing the offline
pre-sign workflow.  At/above REVOKE_TX_WINDOW_HEIGHT every revoke
commits to a chain-height window [valid_from_height, valid_to_height]
inside the signable bytes; validation rejects a tx whose
current_height falls outside that window.  Operators re-sign every
quarter (default ~13140 blocks ≈ 90 days at 600 s/block); a leaked
hex expires within 90 days of its valid_to and becomes inert.  The
window IS the signed payload, so an attacker who captures the bytes
cannot extend it without the cold key.

Pre-fork (height < REVOKE_TX_WINDOW_HEIGHT) the legacy un-windowed
encoding is still accepted, preserving historical replay
determinism.
"""

import hashlib
import struct
import time
from dataclasses import dataclass

from messagechain.config import (
    CHAIN_ID,
    HASH_ALGO,
    MAX_TIMESTAMP_DRIFT,
    MIN_FEE,
    REVOKE_TX_WINDOW_HEIGHT,
    SIG_VERSION_CURRENT,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


@dataclass
class RevokeTransaction:
    """Signed by the cold authority key; flips the entity to revoked state.

    No nonce field: revoke is idempotent (apply_revoke rejects already-
    revoked entities), so replay protection is unnecessary and the lack
    of a nonce is what makes pre-signing offline practical.

    `valid_from_height` / `valid_to_height` are the Tier 26 chain-height
    window.  Both None encodes the legacy pre-fork format (accepted only
    below REVOKE_TX_WINDOW_HEIGHT); at/above the fork, both must be
    non-None and current_height must satisfy
    valid_from_height <= current_height <= valid_to_height for
    validation to succeed.  See module docstring for rationale.
    """
    entity_id: bytes
    timestamp: float
    fee: int
    signature: Signature
    valid_from_height: int | None = None
    valid_to_height: int | None = None
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def has_window(self) -> bool:
        """True if this tx carries the post-fork [valid_from, valid_to]
        window.  False for legacy pre-fork blobs.
        """
        return (
            self.valid_from_height is not None
            and self.valid_to_height is not None
        )

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        base = (
            CHAIN_ID
            + b"revoke"
            + struct.pack(">B", sig_version)
            + self.entity_id
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )
        if not self.has_window():
            # Pre-fork (legacy) encoding.  Below REVOKE_TX_WINDOW_HEIGHT
            # this is the only valid form.  At/above, validate_revoke
            # rejects this branch with a clear error.
            return base
        # Post-fork: include both heights.  Domain-tag the suffix
        # (b"window") so a pre-fork verifier presented with a post-fork
        # blob never accidentally hashes equal to a different pre-fork
        # tx -- the suffix is structurally distinct, not a numeric
        # extension that could collide.
        return base + b"window" + struct.pack(
            ">QQ",
            int(self.valid_from_height),
            int(self.valid_to_height),
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        out = {
            "type": "revoke",
            "entity_id": self.entity_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }
        if self.has_window():
            out["valid_from_height"] = self.valid_from_height
            out["valid_to_height"] = self.valid_to_height
        return out

    def to_bytes(self, state=None) -> bytes:
        """Binary wire format.

        Pre-fork (legacy):
          ENT entity_ref | f64 timestamp | u64 fee
          | u32 sig_len | sig | 32 tx_hash

        Post-fork (Tier 26 windowed):
          ENT entity_ref | f64 timestamp | u64 fee
          | u32 sig_len | sig
          | u8 0x01 (window-present marker)
          | u64 valid_from_height | u64 valid_to_height
          | 32 tx_hash

        The window-present marker disambiguates the trailing bytes
        between the two encodings on the wire (legacy ends with 32-byte
        tx_hash immediately after the signature; windowed inserts a
        marker + 16 bytes before the hash).
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        parts = [
            encode_entity_ref(self.entity_id, state=state),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ]
        if self.has_window():
            parts.append(b"\x01")  # window-present marker
            parts.append(
                struct.pack(
                    ">QQ",
                    int(self.valid_from_height),
                    int(self.valid_to_height),
                )
            )
        # tx_hash always last so legacy parsers find their 32-byte
        # trailer immediately after the signature.
        parts.append(self.tx_hash)
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "RevokeTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 8 + 8 + 4 + 32:
            raise ValueError("RevokeTransaction blob too short")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("RevokeTransaction truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len

        # Disambiguate legacy vs windowed by trailing length.  Legacy
        # has exactly 32 bytes left (the tx_hash); windowed has
        # 1 (marker) + 16 (two u64 heights) + 32 (tx_hash) = 49 bytes
        # left.  Anything else is a parse error.
        remaining = len(data) - off
        valid_from = None
        valid_to = None
        if remaining == 32:
            pass  # legacy
        elif remaining == 1 + 16 + 32:
            marker = data[off]; off += 1
            if marker != 0x01:
                raise ValueError(
                    f"RevokeTransaction unknown window marker {marker:#x}"
                )
            valid_from = struct.unpack_from(">Q", data, off)[0]; off += 8
            valid_to = struct.unpack_from(">Q", data, off)[0]; off += 8
        else:
            raise ValueError(
                "RevokeTransaction has unexpected trailer length "
                f"{remaining} (expected 32 legacy or 49 windowed)"
            )
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("RevokeTransaction has trailing bytes")
        tx = cls(
            entity_id=entity_id,
            timestamp=timestamp,
            fee=fee,
            signature=sig,
            valid_from_height=valid_from,
            valid_to_height=valid_to,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"RevokeTransaction hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "RevokeTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            valid_from_height=data.get("valid_from_height"),
            valid_to_height=data.get("valid_to_height"),
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"RevokeTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx


def create_revoke_transaction(
    signer,
    fee: int = MIN_FEE,
    entity_id: bytes | None = None,
    valid_from_height: int | None = None,
    valid_to_height: int | None = None,
) -> RevokeTransaction:
    """Build and sign a revoke tx.

    No nonce — see module docstring. Pre-signing on paper / offline is
    the intended workflow: fix the fee, sign once, store until needed.

    By default `entity_id` is the signer's own entity_id (single-key
    setups where the signer IS the validator). For the canonical cold/
    hot split, pass `entity_id=hot.entity_id` so the cold signer can
    revoke the hot identity.

    `valid_from_height` / `valid_to_height` carry the Tier 26 chain-
    height window.  Pass both to produce a post-fork (windowed) tx;
    leave both as None to produce a legacy un-windowed tx (only valid
    pre-fork).  See module docstring for rationale.
    """
    target = entity_id if entity_id is not None else signer.entity_id
    tx = RevokeTransaction(
        entity_id=target,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
        valid_from_height=valid_from_height,
        valid_to_height=valid_to_height,
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = signer.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_revoke_transaction(
    tx: RevokeTransaction,
    authority_public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify structural fields and the authority-key signature.

    Past timestamps are accepted without bound — a pre-signed revoke
    kept on paper for months should still apply when needed (the
    chain-height window in the signed payload is what bounds replay
    post Tier 26).  Only future timestamps beyond MAX_TIMESTAMP_DRIFT
    are rejected, to prevent a malicious proposer from pre-dating an
    attack.

    `current_height` selects:
      * the fee rule: post FEE_INCLUDES_SIGNATURE_HEIGHT the floor
        becomes max(MIN_FEE, sig-aware min) to price witness bytes
        (R5-A);
      * the window rule: at/above REVOKE_TX_WINDOW_HEIGHT the tx must
        carry [valid_from_height, valid_to_height] AND current_height
        must satisfy valid_from <= current <= valid_to.  Pre-fork the
        window check is skipped (legacy un-windowed format remains
        valid).  Note: signature is checked LAST -- only after window
        gating accepts the tx -- so a post-fork legacy blob is
        rejected with a clear "missing window" reason rather than a
        cryptic "bad signature".
    """
    from messagechain.config import REVOKE_TX_WINDOW_HEIGHT as _RWH
    from messagechain.core.transaction import enforce_signature_aware_min_fee
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
    if current_height is not None and current_height >= _RWH:
        # Post-fork window enforcement happens here AND in
        # validate_revoke; this layer is the authoritative cryptographic
        # check (signature commits to the window), the chain-side check
        # is what produces a human-readable rejection reason.
        if not tx.has_window():
            return False
        if current_height < tx.valid_from_height:
            return False
        if current_height > tx.valid_to_height:
            return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, authority_public_key)
