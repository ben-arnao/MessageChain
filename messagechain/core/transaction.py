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
    SIG_VERSION_CURRENT, FEE_INCLUDES_SIGNATURE_HEIGHT,
    TX_SERIALIZATION_VERSION, validate_tx_serialization_version,
)
from messagechain.core.compression import (
    encode_payload, decode_payload, RAW_FLAG, COMPRESSED_FLAG,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature, verify_signature


@dataclass
class MessageTransaction:
    entity_id: bytes
    # `message` stores the CANONICAL form (raw or compressed, per
    # compression_flag). Use `plaintext` for the decoded user bytes.
    message: bytes
    timestamp: float
    nonce: int  # per-entity tx counter (replay protection)
    fee: int  # user-set fee (higher = more likely to be included in next block)
    signature: Signature
    version: int = 1  # transaction format version (enables future upgrades without hard forks)
    # compression_flag: 0 = raw, 1 = raw-deflate (zlib level 9, header/adler32 stripped).
    # Part of _signable_data — tx_hash commits to the canonical encoding.
    compression_flag: int = RAW_FLAG
    tx_hash: bytes = b""
    witness_hash: bytes = b""  # hash covering signature (for relay-level dedup)

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()
        if not self.witness_hash and self.signature and self.signature.wots_public_key:
            self.witness_hash = self._compute_witness_hash()

    def _signable_data(self) -> bytes:
        """Canonical byte representation for signing (excludes signature and tx_hash).

        compression_flag is included so tx_hash commits to the canonical
        encoding — an attacker who re-encodes the same plaintext under a
        different flag cannot produce a matching hash.

        sig_version (from the attached signature) is included so tx_hash
        commits to the chosen signature scheme: an attacker cannot swap
        the sig_version after signing without changing the tx hash, which
        breaks any downstream references (mempool dedupe, merkle root).

        When `signature is None` (test fixtures constructing malformed
        tx objects), we fall back to SIG_VERSION_CURRENT so the hash is
        still deterministic — those tests drive negative-path code in
        validate_transaction, which rejects them before the signature is
        ever checked.
        """
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"message"  # domain-separation tag: prevents cross-type sig replay
            + struct.pack(">I", self.version)
            + struct.pack(">B", sig_version)
            + self.entity_id
            + struct.pack(">B", self.compression_flag)
            + self.message
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.fee)
        )

    @property
    def plaintext(self) -> bytes:
        """The user's original ASCII bytes, decoded from the canonical form."""
        return decode_payload(self.message, self.compression_flag)

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
        """Count characters in the plaintext message (ASCII: 1 byte = 1 char).

        Char limit is a user-content constraint (human readability),
        decoupled from on-chain storage size.
        """
        return len(self.plaintext)

    def serialize(self) -> dict:
        """Human-readable dict form for CLI/RPC output.

        Exposes the decoded plaintext as `message` and the canonical
        encoding choice as `compression_flag`. deserialize() re-encodes
        the plaintext via the canonical rule and rebuilds the same
        stored bytes — the pair is a lossless round-trip because the
        encoder is deterministic.
        """
        return {
            "version": self.version,
            "entity_id": self.entity_id.hex(),
            "message": self.plaintext.decode("ascii", errors="replace"),
            "compression_flag": self.compression_flag,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    def to_bytes(self, state=None) -> bytes:
        """Compact binary encoding for storage/wire.

        Layout (big-endian throughout):
            u8   serialization_version (wire-format gate, see TX_SERIALIZATION_VERSION)
            u32  version              (the tx-logic version, NOT the wire format)
            ENT  entity reference (1-byte tag + 32 full id OR varint index)
            u8   compression_flag (0=raw, 1=raw-deflate)
            u16  message_len
            N    message (canonical stored bytes)
            f64  timestamp (seconds, float)
            u64  nonce
            u64  fee
            u32  signature_blob_len
            M    signature_blob (Signature.to_bytes)
            32   tx_hash

        The leading serialization_version byte is a carry-only register
        that lets a future governance proposal bump the wire format
        without silently invalidating existing chain data — the decoder
        rejects unknown versions at the parse boundary with a clear
        error rather than letting a layout change surface as a cryptic
        "hash mismatch" further down the pipeline.  See
        config.BLOCK_SERIALIZATION_VERSION's module comment for the
        full motivation.

        timestamp is stored as float64 so the dict round-trip is
        bit-equivalent. Consensus hashing uses int(self.timestamp)
        in _signable_data, so the fractional part never affects
        tx_hash — storing the fractional seconds is a convenience
        for clients that want sub-second ordering.

        `state`: if provided, the entity reference is emitted as a
        1-byte tag + varint entity_index (saving ~29 B vs the full id).
        Without state, the legacy 32-byte-id form is emitted so
        round-trips keep working in callers that don't thread state
        through (tests, bare-tx contexts).  `_signable_data` always
        uses the 32-byte entity_id — tx_hash is independent of the
        chosen wire form, so any valid encoding yields the same hash.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        parts = [
            struct.pack(">B", TX_SERIALIZATION_VERSION),
            struct.pack(">I", self.version),
            encode_entity_ref(self.entity_id, state=state),
            struct.pack(">B", self.compression_flag),
            struct.pack(">H", len(self.message)),
            self.message,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.nonce),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ]
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "MessageTransaction":
        """Decode a MessageTransaction from its compact binary form.

        Verifies the declared tx_hash against a freshly-computed hash, so
        a tampered-with blob never produces a seemingly-valid object —
        matches the integrity guarantee of deserialize(dict).

        `state` must be provided if the blob uses the varint-index
        entity reference form (tag=0x01); blobs written without state
        use the legacy 32-byte form and decode with state=None.
        """
        from messagechain.core.entity_ref import decode_entity_ref
        offset = 0
        if len(data) < 1 + 4 + 1 + 1 + 2:
            raise ValueError("MessageTransaction blob too short")
        # Wire-format gate: reject unknown versions at the parse boundary.
        # See config.TX_SERIALIZATION_VERSION for the upgrade pattern.
        ser_version = struct.unpack_from(">B", data, offset)[0]; offset += 1
        ok, reason = validate_tx_serialization_version(ser_version)
        if not ok:
            raise ValueError(f"MessageTransaction: {reason}")
        version = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        entity_id, consumed = decode_entity_ref(data, offset, state=state)
        offset += consumed
        compression_flag = struct.unpack_from(">B", data, offset)[0]; offset += 1
        msg_len = struct.unpack_from(">H", data, offset)[0]; offset += 2
        if offset + msg_len > len(data):
            raise ValueError("MessageTransaction message truncated")
        message = bytes(data[offset:offset + msg_len]); offset += msg_len
        if offset + 8 + 8 + 8 + 4 > len(data):
            raise ValueError("MessageTransaction blob truncated at fixed fields")
        timestamp = struct.unpack_from(">d", data, offset)[0]; offset += 8
        nonce = struct.unpack_from(">Q", data, offset)[0]; offset += 8
        fee = struct.unpack_from(">Q", data, offset)[0]; offset += 8
        sig_len = struct.unpack_from(">I", data, offset)[0]; offset += 4
        if offset + sig_len > len(data):
            raise ValueError("MessageTransaction signature truncated")
        sig = Signature.from_bytes(bytes(data[offset:offset + sig_len]))
        offset += sig_len
        if offset + 32 > len(data):
            raise ValueError("MessageTransaction tx_hash truncated")
        declared_hash = bytes(data[offset:offset + 32]); offset += 32
        if offset != len(data):
            raise ValueError("MessageTransaction blob has trailing bytes")
        tx = cls(
            entity_id=entity_id,
            message=message,
            timestamp=timestamp,
            nonce=nonce,
            fee=fee,
            signature=sig,
            version=version,
            compression_flag=compression_flag,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        if expected_hash != declared_hash:
            raise ValueError(
                f"Transaction hash mismatch: declared {declared_hash.hex()[:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "MessageTransaction":
        """Rebuild a MessageTransaction from its dict form.

        The dict exposes `message` as decoded plaintext (human-readable).
        We re-run the canonical encoder to rebuild the stored bytes and
        compression_flag — the encoder is deterministic, so two nodes
        reading the same dict produce identical (message, flag) pairs,
        and hash integrity verifies against the declared tx_hash.

        Accepts dicts without `compression_flag` for backward
        compatibility with the pre-compression format: in that case the
        `message` field is assumed to be already-raw ASCII and the flag
        defaults to RAW_FLAG. Any non-ASCII bytes in that legacy path
        still get caught by verify_transaction's ASCII check.
        """
        sig = Signature.deserialize(data["signature"])
        plaintext = data["message"].encode("ascii")
        if "compression_flag" in data:
            # New format: canonicalize plaintext → (stored, flag).  The
            # declared flag must match the canonical choice, else the
            # tx hash check below will fail and reject the dict.
            stored, flag = encode_payload(plaintext)
        else:
            # Legacy format (pre-compression): no flag field → assume raw.
            stored, flag = plaintext, RAW_FLAG
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            message=stored,
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            fee=data["fee"],
            signature=sig,
            version=data.get("version", 1),
            compression_flag=flag,
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


def calculate_min_fee(message_bytes: bytes, signature_bytes: int = 0) -> int:
    """Calculate minimum fee for a message with non-linear size pricing.

    Fee = MIN_FEE + (bytes * FEE_PER_BYTE) + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000

    The quadratic term makes larger messages disproportionately more expensive,
    incentivizing conciseness and penalizing bloat-heavy messages.

    `signature_bytes` is the canonical length of the witness (WOTS+ sig +
    Merkle auth path).  Default 0 preserves the legacy message-only pricing
    that shipped on mainnet.  Post-FEE_INCLUDES_SIGNATURE_HEIGHT consensus
    callers pass the real signature length so the same formula is applied
    to (message_bytes + signature_bytes) — otherwise attackers can flood
    chain storage with ~2.7 KB of witness per tx while paying only for the
    message payload.
    """
    size = len(message_bytes) + signature_bytes
    linear = size * FEE_PER_BYTE
    quadratic = (size * size * FEE_QUADRATIC_COEFF) // 1000
    return MIN_FEE + linear + quadratic


def enforce_signature_aware_min_fee(
    tx_fee: int,
    signature_bytes: int,
    current_height: int | None,
    flat_floor: int,
) -> bool:
    """Return True if `tx_fee` satisfies the post-activation fee rule.

    Shared fee-admission gate for EVERY non-MessageTransaction tx type.
    MessageTransaction has its own copy inline in `verify_transaction`
    because it also prices the payload bytes; everything else has no
    payload and only needs to cover the signature witness above the
    existing flat floor.

    Pre-activation (`current_height is None` or < activation height):
      * Accept iff `tx_fee >= flat_floor` (unchanged legacy rule).

    Post-activation (`current_height >= FEE_INCLUDES_SIGNATURE_HEIGHT`):
      * Accept iff `tx_fee >= max(flat_floor, calculate_min_fee(b"",
        signature_bytes=signature_bytes))`.

    Pricing witnesses uniformly plugs the R5-A hole where a small-flat-
    fee tx type (transfer, stake, unstake, vote, revoke, authority,
    receipt-root, slash) could carry a ~2.7 KB WOTS+ signature at
    MIN_FEE and bloat permanent chain state at nearly zero cost.
    """
    if tx_fee < flat_floor:
        return False
    if (
        current_height is not None
        and current_height >= FEE_INCLUDES_SIGNATURE_HEIGHT
    ):
        sig_min = calculate_min_fee(b"", signature_bytes=signature_bytes)
        if tx_fee < sig_min:
            return False
    return True


def _validate_message(message: str) -> tuple[bool, str]:
    """Check message contains only printable ASCII (32-126) and is within limits."""
    for ch in message:
        code = ord(ch)
        if code < 32 or code > 126:
            return False, f"Non-printable-ASCII character U+{code:04X} not allowed"
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

    plaintext = message.encode("ascii")
    # Canonicalize: store whichever is smaller of raw or compressed.
    # Fee is charged on the STORED size, which incentivizes compressible
    # content and rewards senders for efficient encoding.
    stored, flag = encode_payload(plaintext)
    if len(stored) > MAX_MESSAGE_BYTES:
        raise ValueError(
            f"Stored message size {len(stored)} exceeds MAX_MESSAGE_BYTES "
            f"{MAX_MESSAGE_BYTES}"
        )
    min_required = calculate_min_fee(stored)
    if fee < min_required:
        raise ValueError(
            f"Fee must be at least {min_required} for this message "
            f"({len(stored)} stored bytes, flag={flag})"
        )

    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=stored,
        timestamp=int(time.time()),
        nonce=nonce,
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        compression_flag=flag,
    )

    # Sign the transaction data with quantum-resistant signature
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    tx.witness_hash = tx._compute_witness_hash()

    return tx


def verify_transaction(
    tx: MessageTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a transaction's quantum-resistant signature and well-formedness.

    Size/fee checks apply to the STORED (canonical) form; ASCII and
    char-count checks apply to the decoded plaintext. Canonical-form
    enforcement prevents a sender from wasting chain bytes by submitting
    a compressed payload that's larger than the raw alternative.

    `current_height` selects the fee rule: callers without chain context
    get the legacy (message-only) rule so historical blocks and isolated
    unit tests keep validating.  Consensus verification MUST pass the
    applying block's height so the FEE_INCLUDES_SIGNATURE_HEIGHT gate
    kicks in — at/after activation, fee covers message + signature bytes.
    """
    # Size cap applies to stored (on-chain) bytes
    if len(tx.message) > MAX_MESSAGE_BYTES:
        return False
    # Decode plaintext for ASCII/char-count validation
    try:
        plaintext = tx.plaintext
    except Exception:
        return False
    if len(plaintext) > MAX_MESSAGE_CHARS:
        return False
    for byte in plaintext:
        if byte < 32 or byte > 126:
            return False
    # Canonical-form check: the stored bytes MUST equal the canonical
    # encoding of the plaintext. This rejects non-canonical encodings
    # (e.g. compressed form larger than raw, or double-compressed data)
    # that would let a sender waste chain bytes.
    canonical_stored, canonical_flag = encode_payload(plaintext)
    if canonical_stored != tx.message or canonical_flag != tx.compression_flag:
        return False
    # Fee applies to stored size; at/after activation it also covers the
    # WOTS+ signature + Merkle auth-path bytes so witness bloat is priced
    # alongside payload bloat (see FEE_INCLUDES_SIGNATURE_HEIGHT).
    if (
        current_height is not None
        and current_height >= FEE_INCLUDES_SIGNATURE_HEIGHT
    ):
        sig_len = len(tx.signature.to_bytes())
        if tx.fee < calculate_min_fee(tx.message, signature_bytes=sig_len):
            return False
    else:
        if tx.fee < calculate_min_fee(tx.message):
            return False
    # Reject timestamps too far in the future (clock drift protection)
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    msg_hash = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    return verify_signature(msg_hash, tx.signature, public_key)
