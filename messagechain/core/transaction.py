"""
MessageTransaction - the fundamental unit of data on MessageChain.

Each transaction represents one message posted by one entity. It contains:
- The message content (up to MAX_MESSAGE_CHARS characters)
- The entity who posted it
- A quantum-resistant signature
- A user-set fee (BTC-style bidding: higher fee = higher block priority)
- A timestamp

The base layer stores raw message bytes with no content interpretation.
L2 / third-party protocols can define message structure, chain messages
together, link messages to threads, etc.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, MAX_MESSAGE_CHARS, MAX_MESSAGE_BYTES, MIN_FEE, MAX_TIMESTAMP_DRIFT
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature, verify_signature


@dataclass
class MessageTransaction:
    entity_id: bytes
    message: bytes
    timestamp: float
    nonce: int  # per-entity tx counter (replay protection)
    fee: int  # user-set fee (higher = more likely to be included in next block)
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
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return hashlib.new(HASH_ALGO, self._signable_data()).digest()

    @property
    def char_count(self) -> int:
        """Count characters in the message."""
        text = self.message.decode("utf-8", errors="replace")
        return len(text)

    def serialize(self) -> dict:
        return {
            "entity_id": self.entity_id.hex(),
            "message": self.message.decode("utf-8", errors="replace"),
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "MessageTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            message=data["message"].encode("utf-8"),
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            fee=data["fee"],
            signature=sig,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"Transaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


def _validate_message(message: str) -> tuple[bool, str]:
    """Check message is within character and byte limits."""
    msg_bytes = message.encode("utf-8")
    if len(msg_bytes) > MAX_MESSAGE_BYTES:
        return False, f"Message exceeds {MAX_MESSAGE_BYTES} bytes ({len(msg_bytes)} bytes)"
    if len(message) > MAX_MESSAGE_CHARS:
        return False, f"Message exceeds {MAX_MESSAGE_CHARS} characters"
    return True, "OK"


def create_transaction(
    entity: Entity,
    message: str,
    fee: int,
    nonce: int,
) -> MessageTransaction:
    """
    Create and sign a new message transaction.

    The fee is set by the user — higher fee means higher priority for
    block inclusion (BTC-style fee bidding).
    """
    valid, reason = _validate_message(message)
    if not valid:
        raise ValueError(reason)

    if fee < MIN_FEE:
        raise ValueError(f"Fee must be at least {MIN_FEE}")

    msg_bytes = message.encode("utf-8")

    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=msg_bytes,
        timestamp=time.time(),
        nonce=nonce,
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    # Sign the transaction data with quantum-resistant signature
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx


def verify_transaction(tx: MessageTransaction, public_key: bytes) -> bool:
    """Verify a transaction's quantum-resistant signature."""
    if tx.char_count > MAX_MESSAGE_CHARS:
        return False
    if len(tx.message) > MAX_MESSAGE_BYTES:
        return False
    if tx.fee < MIN_FEE:
        return False
    # Reject timestamps too far in the future (clock drift protection)
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    return verify_signature(msg_hash, tx.signature, public_key)
