"""
Staking transactions for MessageChain.

Stake and unstake operations are on-chain transactions with:
- Nonce-based replay protection (prevents signature replay)
- Signature verification (proves ownership)
- Fee payment (anti-spam)
- Hash verification on deserialize (tamper detection)

Previously, stake/unstake were RPC-only operations that bypassed block
inclusion. This broke consensus because different nodes could have
different stake states, leading to disagreement on validator sets and
proposer selection.
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
    VALIDATOR_MIN_STAKE,
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class StakeTransaction:
    """An on-chain transaction to lock tokens for validator staking."""
    entity_id: bytes
    amount: int
    nonce: int  # per-entity replay protection
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
            + b"stake"
            + self.entity_id
            + struct.pack(">Q", self.amount)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "stake",
            "entity_id": self.entity_id.hex(),
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "StakeTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"StakeTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


@dataclass
class UnstakeTransaction:
    """An on-chain transaction to unlock staked tokens."""
    entity_id: bytes
    amount: int
    nonce: int  # per-entity replay protection
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
            + b"unstake"
            + self.entity_id
            + struct.pack(">Q", self.amount)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "unstake",
            "entity_id": self.entity_id.hex(),
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "UnstakeTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"UnstakeTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


def create_stake_transaction(
    entity,
    amount: int,
    nonce: int,
    fee: int = MIN_FEE,
) -> StakeTransaction:
    """Create and sign a stake transaction."""
    tx = StakeTransaction(
        entity_id=entity.entity_id,
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


def create_unstake_transaction(
    entity,
    amount: int,
    nonce: int,
    fee: int = MIN_FEE,
) -> UnstakeTransaction:
    """Create and sign an unstake transaction."""
    tx = UnstakeTransaction(
        entity_id=entity.entity_id,
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


def verify_stake_transaction(tx: StakeTransaction, public_key: bytes, block_height: int = 0) -> bool:
    """Verify a stake transaction's signature and structural fields.

    Mirrors the uniform timestamp/amount validation applied to message and
    transfer transactions so that no transaction type has a weaker check
    than another.
    """
    from messagechain.consensus.pos import graduated_min_stake
    if tx.amount <= 0:
        return False
    if tx.amount < graduated_min_stake(block_height):
        return False
    if tx.fee < MIN_FEE:
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_unstake_transaction(tx: UnstakeTransaction, public_key: bytes) -> bool:
    """Verify an unstake transaction's signature and structural fields."""
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
