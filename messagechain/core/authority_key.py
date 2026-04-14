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

The cold key is promoted by a SetAuthorityKey transaction signed with
the current signing key. Before any SetAuthorityKey has been applied,
the entity's authority key implicitly equals its signing key — the
single-key model remains the default for backward compatibility.
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
class SetAuthorityKeyTransaction:
    """Promote a separately-generated public key to the authority role.

    Signed by the current signing key — the user is authenticating as
    themselves, not yet as the cold identity. After this tx applies,
    authority-gated operations (unstake, revoke) require signatures
    from `new_authority_key`; the signing key can no longer authorize
    them on its own.
    """
    entity_id: bytes
    new_authority_key: bytes
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
            + b"set_authority_key"
            + self.entity_id
            + self.new_authority_key
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "set_authority_key",
            "entity_id": self.entity_id.hex(),
            "new_authority_key": self.new_authority_key.hex(),
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "SetAuthorityKeyTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            new_authority_key=bytes.fromhex(data["new_authority_key"]),
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
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
    """Build and sign a SetAuthorityKey transaction.

    Signed with the entity's current signing key (hot). The new
    authority key is just a public key — it does NOT need to belong
    to an on-chain entity, and typically should not (keeping the cold
    key completely off-chain prevents a leaf-reveal attack on it).
    """
    tx = SetAuthorityKeyTransaction(
        entity_id=entity.entity_id,
        new_authority_key=new_authority_key,
        nonce=nonce,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_set_authority_key_transaction(
    tx: SetAuthorityKeyTransaction,
    signing_public_key: bytes,
) -> bool:
    """Verify structural fields and the signature (against the signing key)."""
    if len(tx.new_authority_key) != 32:
        return False
    if tx.fee < MIN_FEE:
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, signing_public_key)
