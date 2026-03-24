"""
MessageTransaction - the fundamental unit of data on MessageChain.

Each transaction represents one message posted by one entity. It contains:
- The message content (up to MAX_MESSAGE_LENGTH chars)
- The entity who posted it
- Which biometric type was used to authenticate
- A quantum-resistant signature
- The token burn amount

The base layer stores raw message bytes with no content interpretation.
L2 / third-party protocols can define message structure and semantics.
"""

import hashlib
import struct
import time
import json
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, MAX_MESSAGE_LENGTH
from messagechain.identity.biometrics import BiometricType, Entity
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.economics.deflation import SupplyTracker


@dataclass
class MessageTransaction:
    entity_id: bytes
    message: bytes
    biometric_type: BiometricType
    timestamp: float
    nonce: int  # per-entity tx counter (replay protection)
    burn_amount: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        """Canonical byte representation for signing (excludes signature and tx_hash)."""
        return (
            self.entity_id
            + self.message
            + self.biometric_type.value.encode()
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.burn_amount)
        )

    def _compute_hash(self) -> bytes:
        return hashlib.new(HASH_ALGO, self._signable_data()).digest()

    def serialize(self) -> dict:
        return {
            "entity_id": self.entity_id.hex(),
            "message": self.message.decode("utf-8", errors="replace"),
            "biometric_type": self.biometric_type.value,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "burn_amount": self.burn_amount,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "MessageTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            message=data["message"].encode("utf-8"),
            biometric_type=BiometricType(data["biometric_type"]),
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            burn_amount=data["burn_amount"],
            signature=sig,
        )
        tx.tx_hash = bytes.fromhex(data["tx_hash"])
        return tx


def create_transaction(
    entity: Entity,
    message: str,
    bio_type: BiometricType,
    supply_tracker: SupplyTracker,
    nonce: int,
) -> MessageTransaction:
    """Create and sign a new message transaction."""
    msg_bytes = message.encode("utf-8")
    if len(msg_bytes) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message exceeds {MAX_MESSAGE_LENGTH} bytes")

    burn_amount = supply_tracker.calculate_burn_cost()
    if not supply_tracker.can_afford(entity.entity_id):
        raise ValueError(f"Insufficient balance. Need {burn_amount} tokens")

    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=msg_bytes,
        biometric_type=bio_type,
        timestamp=time.time(),
        nonce=nonce,
        burn_amount=burn_amount,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    # Sign the transaction data
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx


def verify_transaction(tx: MessageTransaction, public_key: bytes) -> bool:
    """Verify a transaction's signature and basic validity."""
    if len(tx.message) > MAX_MESSAGE_LENGTH:
        return False

    if tx.burn_amount < 1:
        return False

    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    return verify_signature(msg_hash, tx.signature, public_key)
