"""
Transfer transactions for MessageChain.

Enables peer-to-peer token transfers between registered entities.
Follows the same pattern as StakeTransaction:
- Nonce-based replay protection
- Signature verification
- Fee payment
- Hash verification on deserialize
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, MIN_FEE, MAX_TIMESTAMP_DRIFT, CHAIN_ID
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class TransferTransaction:
    """An on-chain transaction to transfer tokens between entities."""
    entity_id: bytes       # sender
    recipient_id: bytes    # recipient
    amount: int
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
            + b"transfer"
            + self.entity_id
            + self.recipient_id
            + struct.pack(">Q", self.amount)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "transfer",
            "entity_id": self.entity_id.hex(),
            "recipient_id": self.recipient_id.hex(),
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "TransferTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            recipient_id=bytes.fromhex(data["recipient_id"]),
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"TransferTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


def create_transfer_transaction(
    entity,
    recipient_id: bytes,
    amount: int,
    nonce: int,
    fee: int = MIN_FEE,
) -> TransferTransaction:
    """Create and sign a transfer transaction."""
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if entity.entity_id == recipient_id:
        raise ValueError("Cannot transfer to yourself")

    tx = TransferTransaction(
        entity_id=entity.entity_id,
        recipient_id=recipient_id,
        amount=amount,
        nonce=nonce,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_transfer_transaction(tx: TransferTransaction, public_key: bytes) -> bool:
    """Verify a transfer transaction's signature and structural fields."""
    if tx.amount <= 0:
        return False
    if tx.fee < MIN_FEE:
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
