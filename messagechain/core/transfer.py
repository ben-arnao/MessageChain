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
from messagechain.config import (
    HASH_ALGO, MIN_FEE, MAX_TIMESTAMP_DRIFT, CHAIN_ID, SIG_VERSION_CURRENT,
)
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
        # sig_version from the attached signature is committed into tx_hash
        # so the chosen signature scheme is tamper-evident (see MessageTransaction
        # for the full rationale — this mirrors the same crypto-agility pattern).
        # getattr fallback keeps test fixtures that pass signature=None working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"transfer"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (big-endian):
            ENT  sender entity reference
            ENT  recipient entity reference
            u64  amount
            u64  nonce
            f64  timestamp
            u64  fee
            u32  signature_blob_len
            M    signature_blob
            32   tx_hash

        With `state` provided, both sender and recipient are encoded
        as varint indices — a transfer tx saves ~58 B vs the legacy
        two-32-byte-id form.  _signable_data still commits to the
        full 32-byte ids so tx_hash is independent of the encoding.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.entity_id, state=state),
            encode_entity_ref(self.recipient_id, state=state),
            struct.pack(">Q", self.amount),
            struct.pack(">Q", self.nonce),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "TransferTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 1 + 8 + 8 + 8 + 8 + 4 + 32:
            raise ValueError("TransferTransaction blob too short")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        recipient_id, n = decode_entity_ref(data, off, state=state); off += n
        amount = struct.unpack_from(">Q", data, off)[0]; off += 8
        nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("TransferTransaction truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared_hash = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("TransferTransaction has trailing bytes")
        tx = cls(
            entity_id=entity_id, recipient_id=recipient_id,
            amount=amount, nonce=nonce, timestamp=timestamp,
            fee=fee, signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared_hash:
            raise ValueError(
                f"TransferTransaction hash mismatch: declared "
                f"{declared_hash.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

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
