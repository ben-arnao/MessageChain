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
    SIG_VERSION_CURRENT,
    VALIDATOR_MIN_STAKE,
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _decode_stake_like(cls, data: bytes, label: str, state=None):
    """Shared binary decoder for StakeTransaction / UnstakeTransaction.

    Both types have identical envelopes (entity_ref | amount | nonce |
    timestamp | fee | sig | tx_hash); only the _signable_data domain
    tag differs.  Sharing the decoder means an envelope change has
    exactly one implementation to touch.

    `state` enables resolving varint-indexed entity references.
    Without state, only legacy 32-byte-id blobs decode.
    """
    from messagechain.core.entity_ref import decode_entity_ref
    off = 0
    if len(data) < 1 + 8 + 8 + 8 + 8 + 4 + 32:
        raise ValueError(f"{label} blob too short")
    entity_id, n = decode_entity_ref(data, off, state=state); off += n
    amount = struct.unpack_from(">Q", data, off)[0]; off += 8
    nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
    timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
    fee = struct.unpack_from(">Q", data, off)[0]; off += 8
    sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
    if off + sig_len + 32 > len(data):
        raise ValueError(f"{label} truncated at signature/hash")
    sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
    declared_hash = bytes(data[off:off + 32]); off += 32
    if off != len(data):
        raise ValueError(f"{label} has trailing bytes")
    tx = cls(
        entity_id=entity_id, amount=amount, nonce=nonce,
        timestamp=timestamp, fee=fee, signature=sig,
    )
    expected = tx._compute_hash()
    if expected != declared_hash:
        raise ValueError(
            f"{label} hash mismatch: declared {declared_hash.hex()[:16]}, "
            f"computed {expected.hex()[:16]}"
        )
    return tx


def _encode_stake_like(tx, state=None) -> bytes:
    """Shared binary encoder for StakeTransaction / UnstakeTransaction.

    Factored so envelope changes (e.g., swapping 32-byte entity_id
    for a varint entity_index) have a single implementation site.
    """
    import struct as _s
    from messagechain.core.entity_ref import encode_entity_ref
    sig_blob = tx.signature.to_bytes()
    return b"".join([
        encode_entity_ref(tx.entity_id, state=state),
        _s.pack(">Q", tx.amount),
        _s.pack(">Q", tx.nonce),
        _s.pack(">d", float(tx.timestamp)),
        _s.pack(">Q", tx.fee),
        _s.pack(">I", len(sig_blob)),
        sig_blob,
        tx.tx_hash,
    ])


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
        # Crypto-agility: commit the signer's chosen scheme into tx_hash.
        # getattr fallback keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"stake"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Compact binary: ENT entity_ref | u64 amount | u64 nonce |
        f64 timestamp | u64 fee | u32 sig_len | sig | 32 tx_hash.

        With `state`, the entity reference is a 1-byte tag + varint
        index (~3 B total), saving ~29 B vs the legacy 32-byte id.
        """
        return _encode_stake_like(self, state=state)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "StakeTransaction":
        return _decode_stake_like(
            cls, data, label="StakeTransaction", state=state,
        )

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
        # Crypto-agility: commit the signer's chosen scheme into tx_hash.
        # getattr fallback keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"unstake"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Same layout as StakeTransaction — the distinguishing "stake" vs
        "unstake" discriminator lives in _signable_data (domain-separated
        hashing), not in the binary envelope.  Callers know which class
        to deserialize into from context (which block-level list it came
        out of).
        """
        return _encode_stake_like(self, state=state)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "UnstakeTransaction":
        return _decode_stake_like(
            cls, data, label="UnstakeTransaction", state=state,
        )

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


def verify_stake_transaction(
    tx: StakeTransaction,
    public_key: bytes,
    block_height: int = 0,
    *,
    min_stake_override: int | None = None,
) -> bool:
    """Verify a stake transaction's signature and structural fields.

    Mirrors the uniform timestamp/amount validation applied to message and
    transfer transactions so that no transaction type has a weaker check
    than another.

    `min_stake_override`: if provided, the caller (typically Blockchain,
    which has access to `bootstrap_progress`) dictates the minimum stake
    amount.  When None, falls back to the legacy height-tier table
    (graduated_min_stake) for backward compatibility with tests that do
    not drive a full blockchain context.
    """
    if tx.amount <= 0:
        return False
    if min_stake_override is not None:
        if tx.amount < min_stake_override:
            return False
    else:
        from messagechain.consensus.pos import graduated_min_stake
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
