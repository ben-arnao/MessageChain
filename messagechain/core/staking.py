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

Receive-to-exist stake-as-first-spend:
  StakeTransaction mirrors TransferTransaction's first-spend reveal.
  A new validator whose first on-chain action is Stake (not Transfer)
  may carry `sender_pubkey` so the chain can verify the signature and
  install the pubkey into state.  On every subsequent stake from the
  same entity `sender_pubkey` MUST be empty (rejected as malleability
  otherwise).  The field is length-prefixed inside `_signable_data` so
  tx_hash commits to it — a relayer cannot strip the pubkey after
  signing.

  UnstakeTransaction deliberately does NOT carry a self-reveal: unstake
  is authority-gated (cold-key-signed) and by construction can only
  happen from an entity that already has an active stake, which means
  its pubkey has already been installed on-chain by whichever earlier
  tx created that stake.
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
    TX_SERIALIZATION_VERSION,
    VALIDATOR_MIN_STAKE,
    validate_tx_serialization_version,
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _decode_unstake_like(cls, data: bytes, label: str, state=None):
    """Shared binary decoder for UnstakeTransaction (and historically Stake).

    Envelope: u8 ser_version | entity_ref | amount | nonce | timestamp |
              fee | sig | tx_hash.

    The leading u8 is a wire-format carry-only register (see
    config.TX_SERIALIZATION_VERSION); unknown values are rejected at
    parse time with a clear error rather than surfacing later as a
    cryptic hash mismatch.

    `state` enables resolving varint-indexed entity references.
    Without state, only legacy 32-byte-id blobs decode.
    """
    from messagechain.core.entity_ref import decode_entity_ref
    off = 0
    if len(data) < 1 + 1 + 8 + 8 + 8 + 8 + 4 + 32:
        raise ValueError(f"{label} blob too short")
    ser_version = struct.unpack_from(">B", data, off)[0]; off += 1
    ok, reason = validate_tx_serialization_version(ser_version)
    if not ok:
        raise ValueError(f"{label}: {reason}")
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


def _encode_unstake_like(tx, state=None) -> bytes:
    """Shared binary encoder for UnstakeTransaction (and historically Stake).

    Factored so envelope changes (e.g., swapping 32-byte entity_id
    for a varint entity_index) have a single implementation site.
    Emits a leading u8 TX_SERIALIZATION_VERSION so the wire-format
    gate can reject unknown versions at parse time.
    """
    import struct as _s
    from messagechain.core.entity_ref import encode_entity_ref
    sig_blob = tx.signature.to_bytes()
    return b"".join([
        _s.pack(">B", TX_SERIALIZATION_VERSION),
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
    # First-spend pubkey reveal: populated only on the sender's FIRST
    # on-chain spend (when entity_id has no mapping in Blockchain.
    # public_keys yet) — this is the receive-to-exist path for a new
    # validator whose natural first action is Stake rather than Transfer.
    # Empty on every subsequent stake.  Committed inside _signable_data
    # with a length prefix so stripping or swapping the field invalidates
    # the tx hash (the same pattern as TransferTransaction).
    sender_pubkey: bytes = b""
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit the signer's chosen scheme into tx_hash.
        # getattr fallback keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        # Length-prefix sender_pubkey so empty (b"") and non-empty (32 B)
        # produce different signable data — otherwise a relayer could
        # strip the pubkey bytes without invalidating the signature.
        # Mirrors TransferTransaction._signable_data.
        pk = self.sender_pubkey or b""
        return (
            CHAIN_ID
            + b"stake"
            + struct.pack(">B", sig_version)
            + self.entity_id
            + struct.pack(">Q", self.amount)
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
            + struct.pack(">H", len(pk)) + pk
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        d = {
            "type": "stake",
            "entity_id": self.entity_id.hex(),
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }
        if self.sender_pubkey:
            d["sender_pubkey"] = self.sender_pubkey.hex()
        return d

    def to_bytes(self, state=None) -> bytes:
        """Compact binary: u8 ser_version | ENT entity_ref | u64 amount |
        u64 nonce | f64 timestamp | u64 fee | u32 sig_len | sig |
        u16 pk_len | pk | 32 tx_hash.

        Leading u8 is TX_SERIALIZATION_VERSION — a carry-only register
        that lets a future governance proposal bump the wire format
        without silently invalidating existing chain data.

        With `state`, the entity reference is a 1-byte tag + varint
        index (~3 B total), saving ~29 B vs the legacy 32-byte id.
        `sender_pubkey` is usually absent (0 bytes with a 2-byte len
        prefix) — only first-spend stake reveals it.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        pk = self.sender_pubkey or b""
        return b"".join([
            struct.pack(">B", TX_SERIALIZATION_VERSION),
            encode_entity_ref(self.entity_id, state=state),
            struct.pack(">Q", self.amount),
            struct.pack(">Q", self.nonce),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            struct.pack(">H", len(pk)),
            pk,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "StakeTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        # Minimum size: u8 ser_ver + ENT(1)+8+8+8+8+4 sig_len+0 sig+2 pk_len+0 pk+32 hash
        if len(data) < 1 + 1 + 8 + 8 + 8 + 8 + 4 + 2 + 32:
            raise ValueError("StakeTransaction blob too short")
        ser_version = struct.unpack_from(">B", data, off)[0]; off += 1
        ok, reason = validate_tx_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"StakeTransaction: {reason}")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        amount = struct.unpack_from(">Q", data, off)[0]; off += 8
        nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 2 + 32 > len(data):
            raise ValueError("StakeTransaction truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        pk_len = struct.unpack_from(">H", data, off)[0]; off += 2
        if off + pk_len + 32 > len(data):
            raise ValueError("StakeTransaction truncated at sender_pubkey")
        sender_pubkey = bytes(data[off:off + pk_len]); off += pk_len
        declared_hash = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("StakeTransaction has trailing bytes")
        tx = cls(
            entity_id=entity_id, amount=amount, nonce=nonce,
            timestamp=timestamp, fee=fee, signature=sig,
            sender_pubkey=sender_pubkey,
        )
        expected = tx._compute_hash()
        if expected != declared_hash:
            raise ValueError(
                f"StakeTransaction hash mismatch: declared "
                f"{declared_hash.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "StakeTransaction":
        sig = Signature.deserialize(data["signature"])
        sender_pubkey = (
            bytes.fromhex(data["sender_pubkey"])
            if data.get("sender_pubkey")
            else b""
        )
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            sender_pubkey=sender_pubkey,
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
        """Binary envelope:
            ENT entity_ref | u64 amount | u64 nonce | f64 timestamp |
            u64 fee | u32 sig_len | sig | 32 tx_hash.

        Unlike StakeTransaction, UnstakeTransaction carries no
        `sender_pubkey` first-spend field — unstake is authority-gated
        and by construction only runs against an entity that already
        has an active stake (so its pubkey is already on chain).  The
        distinguishing "stake" vs "unstake" domain tag lives in
        _signable_data, not in the binary envelope.  Callers know
        which class to deserialize into from context (which block-
        level list it came out of).
        """
        return _encode_unstake_like(self, state=state)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "UnstakeTransaction":
        return _decode_unstake_like(
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
    *,
    include_pubkey: bool = False,
) -> StakeTransaction:
    """Create and sign a stake transaction.

    Set `include_pubkey=True` on the entity's FIRST on-chain spend when
    that first spend is a Stake (e.g., a new validator funded by a
    previous Transfer now bonding for the first time).  The chain
    verifies derive_entity_id(sender_pubkey) == entity_id and installs
    the pubkey on apply.  Leave it False thereafter — non-empty on a
    subsequent stake is rejected as malleability.
    """
    tx = StakeTransaction(
        entity_id=entity.entity_id,
        amount=amount,
        nonce=nonce,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        sender_pubkey=entity.public_key if include_pubkey else b"",
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
    amount.  When None, falls back to the flat VALIDATOR_MIN_STAKE.
    """
    if tx.amount <= 0:
        return False
    if min_stake_override is not None:
        if tx.amount < min_stake_override:
            return False
    else:
        from messagechain.config import VALIDATOR_MIN_STAKE
        if tx.amount < VALIDATOR_MIN_STAKE:
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
