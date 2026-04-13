"""
MessageTransaction - the fundamental unit of data on MessageChain.

Each transaction represents one message posted by one entity. It contains:
- The message content (printable ASCII only, up to MAX_MESSAGE_CHARS characters)
- The entity who posted it
- A quantum-resistant signature
- A user-set fee (BTC-style bidding: higher fee = higher block priority)
- A timestamp
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import (
    HASH_ALGO, MAX_MESSAGE_CHARS, MAX_MESSAGE_BYTES, MIN_FEE, FEE_PER_BYTE,
    FEE_QUADRATIC_COEFF, MAX_TIMESTAMP_DRIFT, CHAIN_ID,
    MESSAGE_DEFAULT_TTL, MESSAGE_MIN_TTL, MESSAGE_MAX_TTL,
)
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
    version: int = 1  # transaction format version (enables future upgrades without hard forks)
    ttl: int = 0  # message retention in blocks (0 = protocol default MESSAGE_DEFAULT_TTL)
    tx_hash: bytes = b""
    witness_hash: bytes = b""  # hash covering signature (for relay-level dedup)

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()
        if not self.witness_hash and self.signature and self.signature.wots_public_key:
            self.witness_hash = self._compute_witness_hash()

    def _signable_data(self) -> bytes:
        """Canonical byte representation for signing (excludes signature and tx_hash)."""
        return (
            CHAIN_ID
            + struct.pack(">I", self.version)
            + self.entity_id
            + self.message
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.fee)
            + struct.pack(">I", self.effective_ttl)
        )

    @property
    def effective_ttl(self) -> int:
        """Resolve TTL: 0 means protocol default."""
        return self.ttl if self.ttl > 0 else MESSAGE_DEFAULT_TTL

    def _compute_hash(self) -> bytes:
        return hashlib.new(HASH_ALGO, self._signable_data()).digest()

    def _compute_witness_hash(self) -> bytes:
        """Hash covering both transaction data AND signature.

        Unlike tx_hash (which excludes the signature for malleability
        resistance), witness_hash includes the canonical signature bytes.
        Used for relay-level deduplication to detect modified signatures.
        """
        return hashlib.new(
            HASH_ALGO,
            self._signable_data() + self.signature.canonical_bytes()
        ).digest()

    @property
    def char_count(self) -> int:
        """Count characters in the message (ASCII: 1 byte = 1 char)."""
        return len(self.message)

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "entity_id": self.entity_id.hex(),
            "message": self.message.decode("ascii", errors="replace"),
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "fee": self.fee,
            "ttl": self.ttl,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "MessageTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            message=data["message"].encode("ascii"),
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            fee=data["fee"],
            signature=sig,
            version=data.get("version", 1),
            ttl=data.get("ttl", 0),
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


def calculate_min_fee(message_bytes: bytes) -> int:
    """Calculate minimum fee for a message with non-linear size pricing.

    Fee = MIN_FEE + (bytes * FEE_PER_BYTE) + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000

    The quadratic term makes larger messages disproportionately more expensive,
    incentivizing conciseness and penalizing bloat-heavy messages.
    """
    size = len(message_bytes)
    linear = size * FEE_PER_BYTE
    quadratic = (size * size * FEE_QUADRATIC_COEFF) // 1000
    return MIN_FEE + linear + quadratic


def _validate_message(message: str) -> tuple[bool, str]:
    """Check message contains only printable ASCII (32-126) and is within limits."""
    for ch in message:
        code = ord(ch)
        if code < 32 or code > 126:
            return False, f"Non-printable-ASCII character U+{code:04X} not allowed"
    if len(message) > MAX_MESSAGE_CHARS:
        return False, f"Message exceeds {MAX_MESSAGE_CHARS} characters"
    return True, "OK"


def _validate_ttl(ttl: int) -> tuple[bool, str]:
    """Check TTL is within protocol bounds (0 means default)."""
    if ttl == 0:
        return True, "OK"  # 0 = use protocol default
    if ttl < MESSAGE_MIN_TTL:
        return False, f"TTL {ttl} below minimum {MESSAGE_MIN_TTL}"
    if ttl > MESSAGE_MAX_TTL:
        return False, f"TTL {ttl} exceeds maximum {MESSAGE_MAX_TTL}"
    return True, "OK"


def create_transaction(
    entity: Entity,
    message: str,
    fee: int,
    nonce: int,
    ttl: int = 0,
) -> MessageTransaction:
    """
    Create and sign a new message transaction.

    The fee is set by the user — higher fee means higher priority for
    block inclusion (BTC-style fee bidding).

    TTL sets message retention in blocks (0 = protocol default).
    """
    valid, reason = _validate_message(message)
    if not valid:
        raise ValueError(reason)

    valid, reason = _validate_ttl(ttl)
    if not valid:
        raise ValueError(reason)

    msg_bytes = message.encode("ascii")
    min_required = calculate_min_fee(msg_bytes)
    if fee < min_required:
        raise ValueError(f"Fee must be at least {min_required} for this message ({len(msg_bytes)} bytes)")

    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=msg_bytes,
        timestamp=time.time(),
        nonce=nonce,
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        ttl=ttl,
    )

    # Sign the transaction data with quantum-resistant signature
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    tx.witness_hash = tx._compute_witness_hash()

    return tx


def verify_transaction(tx: MessageTransaction, public_key: bytes) -> bool:
    """Verify a transaction's quantum-resistant signature."""
    if tx.char_count > MAX_MESSAGE_CHARS:
        return False
    if len(tx.message) > MAX_MESSAGE_BYTES:
        return False
    # Reject non-ASCII bytes in message payload
    for byte in tx.message:
        if byte < 32 or byte > 126:
            return False
    if tx.fee < calculate_min_fee(tx.message):
        return False
    # Validate TTL bounds
    valid, _ = _validate_ttl(tx.ttl)
    if not valid:
        return False
    # Reject timestamps too far in the future (clock drift protection)
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    return verify_signature(msg_hash, tx.signature, public_key)
