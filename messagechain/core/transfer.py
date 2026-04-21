"""
Transfer transactions for MessageChain.

Enables peer-to-peer token transfers between entities.  Follows the same
pattern as StakeTransaction (nonce-based replay protection, signature
verification, fee payment, hash-verified deserialization) with ONE
receive-to-exist extension:

  * On an entity's FIRST outgoing Transfer, the tx may carry
    `sender_pubkey` so the chain can verify the signature and install
    the pubkey into state (Bitcoin P2PKH-style first-spend reveal).
  * On every subsequent Transfer the field MUST be empty — non-empty is
    rejected as malleability (the pubkey is already on chain).
  * The field is always covered by `_signable_data` with an explicit
    length prefix so flipping it empty<->non-empty is tamper-evident in
    the tx hash.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import (
    HASH_ALGO, MIN_FEE, MAX_TIMESTAMP_DRIFT, CHAIN_ID, SIG_VERSION_CURRENT,
    TX_SERIALIZATION_VERSION, validate_tx_serialization_version,
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
    # First-spend pubkey reveal: populated only on the sender's FIRST
    # outgoing transfer (when entity_id has no mapping in Blockchain.
    # public_keys yet).  Empty on every subsequent transfer.  Committed
    # inside _signable_data with a length prefix so stripping or
    # swapping the field invalidates the tx hash.
    sender_pubkey: bytes = b""
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
        # Length-prefix sender_pubkey so empty (b"") and non-empty (32 B)
        # produce different signable data — otherwise a relayer could
        # strip the pubkey bytes without invalidating the signature.
        pk = self.sender_pubkey or b""
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
            + struct.pack(">H", len(pk)) + pk
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        d = {
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
        if self.sender_pubkey:
            d["sender_pubkey"] = self.sender_pubkey.hex()
        return d

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (big-endian):
            u8   serialization_version  (wire-format gate)
            ENT  sender entity reference
            ENT  recipient entity reference
            u64  amount
            u64  nonce
            f64  timestamp
            u64  fee
            u32  signature_blob_len
            M    signature_blob
            u16  sender_pubkey_len
            P    sender_pubkey     (P may be 0 on steady-state transfers)
            32   tx_hash

        Leading u8 is a wire-format carry-only register — see
        config.TX_SERIALIZATION_VERSION.  A future format bump widens
        the gate; unknown values are rejected at parse time with a
        clear error instead of surfacing as a hash mismatch.

        With `state` provided, both sender and recipient are encoded
        as varint indices — a transfer tx saves ~58 B vs the legacy
        two-32-byte-id form.  _signable_data still commits to the
        full 32-byte ids so tx_hash is independent of the encoding.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        pk = self.sender_pubkey or b""
        return b"".join([
            struct.pack(">B", TX_SERIALIZATION_VERSION),
            encode_entity_ref(self.entity_id, state=state),
            encode_entity_ref(self.recipient_id, state=state),
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
    def from_bytes(cls, data: bytes, state=None) -> "TransferTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        # Minimum size: u8 ser_ver + ENT(1)+ENT(1)+8+8+8+8+4 sig_len+0 sig+2 pk_len+0 pk+32 hash
        if len(data) < 1 + 1 + 1 + 8 + 8 + 8 + 8 + 4 + 2 + 32:
            raise ValueError("TransferTransaction blob too short")
        ser_version = struct.unpack_from(">B", data, off)[0]; off += 1
        ok, reason = validate_tx_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"TransferTransaction: {reason}")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        recipient_id, n = decode_entity_ref(data, off, state=state); off += n
        amount = struct.unpack_from(">Q", data, off)[0]; off += 8
        nonce = struct.unpack_from(">Q", data, off)[0]; off += 8
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 2 + 32 > len(data):
            raise ValueError("TransferTransaction truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        pk_len = struct.unpack_from(">H", data, off)[0]; off += 2
        if off + pk_len + 32 > len(data):
            raise ValueError("TransferTransaction truncated at sender_pubkey")
        sender_pubkey = bytes(data[off:off + pk_len]); off += pk_len
        declared_hash = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("TransferTransaction has trailing bytes")
        tx = cls(
            entity_id=entity_id, recipient_id=recipient_id,
            amount=amount, nonce=nonce, timestamp=timestamp,
            fee=fee, signature=sig, sender_pubkey=sender_pubkey,
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
        sender_pubkey = (
            bytes.fromhex(data["sender_pubkey"])
            if data.get("sender_pubkey")
            else b""
        )
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            recipient_id=bytes.fromhex(data["recipient_id"]),
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            sender_pubkey=sender_pubkey,
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
    *,
    include_pubkey: bool = False,
) -> TransferTransaction:
    """Create and sign a transfer transaction.

    Set `include_pubkey=True` on the sender's FIRST outgoing transfer so
    the chain can install their public key on apply.  Leave it False
    thereafter — non-empty on a subsequent transfer is rejected.
    """
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if entity.entity_id == recipient_id:
        raise ValueError("Cannot transfer to yourself")

    tx = TransferTransaction(
        entity_id=entity.entity_id,
        recipient_id=recipient_id,
        amount=amount,
        nonce=nonce,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        sender_pubkey=entity.public_key if include_pubkey else b"",
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_transfer_transaction(
    tx: TransferTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a transfer transaction's signature and structural fields.

    `current_height` selects the fee rule: at/after
    FEE_INCLUDES_SIGNATURE_HEIGHT the admission floor is
    max(MIN_FEE, sig-aware min) so witness bloat is priced alongside
    payload bloat (R5-A).  Legacy callers (current_height=None) get
    the message-only flat floor, preserving historical-block validity.
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    if tx.amount <= 0:
        return False
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=MIN_FEE,
    ):
        return False
    if tx.timestamp <= 0:
        return False
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
