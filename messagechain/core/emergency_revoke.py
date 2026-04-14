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
is only used for this emergency path and for unstaking. Operators
should keep a pre-computed revoke tx on paper or in a dedicated cold
environment so recovery takes minutes, not hours.
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
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class RevokeTransaction:
    """Signed by the cold authority key; flips the entity to revoked state."""
    entity_id: bytes
    nonce: int
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            CHAIN_ID
            + b"revoke"
            + self.entity_id
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "revoke",
            "entity_id": self.entity_id.hex(),
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "RevokeTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
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
    nonce: int,
    fee: int = MIN_FEE,
    entity_id: bytes | None = None,
) -> RevokeTransaction:
    """Build and sign a revoke tx.

    By default `entity_id` is the signer's own entity_id (useful for tests
    and for single-key setups where the signer IS the validator). For the
    canonical cold/hot split, pass `entity_id=hot.entity_id` so the cold
    signer can revoke the hot identity.
    """
    target = entity_id if entity_id is not None else signer.entity_id
    tx = RevokeTransaction(
        entity_id=target,
        nonce=nonce,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = signer.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_revoke_transaction(
    tx: RevokeTransaction,
    authority_public_key: bytes,
) -> bool:
    """Verify structural fields and the authority-key signature."""
    if tx.fee < MIN_FEE:
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, authority_public_key)
