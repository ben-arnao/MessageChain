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
    HASH_ALGO, MAX_MESSAGE_CHARS, MAX_MESSAGE_BYTES, MIN_FEE,
    MIN_FEE_POST_FLAT, FLAT_FEE_HEIGHT, FEE_PER_BYTE,
    FEE_QUADRATIC_COEFF, MAX_TIMESTAMP_DRIFT, CHAIN_ID,
    SIG_VERSION_CURRENT, FEE_INCLUDES_SIGNATURE_HEIGHT,
    TX_SERIALIZATION_VERSION, validate_tx_serialization_version,
    BASE_TX_FEE, FEE_PER_STORED_BYTE, LINEAR_FEE_HEIGHT,
    BLOCK_BYTES_RAISE_HEIGHT, FEE_PER_STORED_BYTE_POST_RAISE,
    PREV_POINTER_HEIGHT,
    FIRST_SEND_PUBKEY_HEIGHT,
    MESSAGE_TX_LENGTH_PREFIX_HEIGHT,
)

# Tx-logic version that enables the optional `prev` pointer (Tier 10).
# Version 1 txs hash/sign exactly the pre-fork bytes (backward-compatible).
# Version 2 txs include the `prev` field (1-byte presence flag, +32 bytes
# when set) in both _signable_data and the wire form.
TX_VERSION_PREV_POINTER = 2
# Raw byte cost of the `prev` field when set (1B presence flag + 32B hash).
# Added to the per-stored-byte fee basis so pointer-bearing txs pay
# uniformly for their on-chain footprint.
PREV_POINTER_STORED_BYTES = 33
# Tx-logic version that enables the optional sender_pubkey reveal (Tier 11).
# v3 txs carry an additional 1-byte presence flag + 32-byte pubkey AFTER
# the prev-pointer block.  When set, validate_transaction admits the tx
# even if the sender's entity_id is not yet on chain (provided
# derive_entity_id matches), and apply installs the pubkey in
# self.public_keys.  Mirrors TransferTransaction.sender_pubkey so a fresh
# wallet that just received funds via the cold-start faucet can post its
# first message in one round-trip instead of needing a transfer-first
# bootstrap.
TX_VERSION_FIRST_SEND_PUBKEY = 3
# Raw byte cost of the sender_pubkey field when set (1B presence flag +
# 32B pubkey).  Charged at the per-stored-byte fee basis alongside `prev`.
SENDER_PUBKEY_STORED_BYTES = 33
# Tx-logic version that closes the _signable_data length-prefix
# collision (Tier 12 — MESSAGE_TX_LENGTH_PREFIX_HEIGHT).  v4
# `_signable_data` prepends `struct.pack(">H", len(self.message))`
# immediately before the message bytes; everything else (entity_id,
# compression_flag, ts/nonce/fee, prev/pubkey trailers) matches the
# v3 layout byte-for-byte.  The 2-byte prefix binds the message
# length into the signed commitment so two parses of the same byte
# string with different message lengths can no longer produce the
# same tx_hash.  Pre-activation v4 admission is rejected; historical
# v1/v2/v3 replay continues unchanged.
TX_VERSION_LENGTH_PREFIX = 4
from messagechain.core.compression import (
    encode_payload, decode_payload, RAW_FLAG, COMPRESSED_FLAG,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.hashing import default_hash
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
    # `prev` (optional): 32-byte tx_hash this message references as its
    # immediate predecessor, forming a single-linked list of prior
    # messages.  Only meaningful at version >= TX_VERSION_PREV_POINTER;
    # version=1 txs MUST leave this as None.  At version 2, may be None
    # (no pointer) or exactly 32 bytes.  Strict validation: when set,
    # the referenced tx_hash must resolve to a tx included in a strictly
    # earlier block (same-height same-block earlier tx_index is also
    # accepted at block-validate time).
    prev: bytes | None = None
    # `sender_pubkey` (optional, v3+): 32-byte public key of the sender.
    # Only meaningful at version >= TX_VERSION_FIRST_SEND_PUBKEY.  When
    # set on a tx whose entity_id is not yet in chain.public_keys, the
    # apply path installs it; this is the messaging counterpart to
    # TransferTransaction.sender_pubkey.  Empty (b"") for v1/v2 txs and
    # for v3 txs from senders already on chain (the chain rejects a v3
    # tx that re-supplies the pubkey for an already-installed entity, so
    # the field is structurally exclusive with "already registered").
    sender_pubkey: bytes = b""
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
        # v4 (TX_VERSION_LENGTH_PREFIX) closes the legacy length-prefix
        # collision: prepend `struct.pack(">H", len(self.message))`
        # immediately before the message bytes so the parsed message
        # length is committed into the signed payload.  Without this,
        # two byte-strings that parse to different (message, ts/nonce/
        # fee/prev/pk) tuples can collide on tx_hash and a single
        # WOTS+ signature verifies under both parses (mempool dedup
        # then displaces the victim's intended tx).  v1/v2/v3 keep
        # the legacy raw-message concatenation byte-for-byte for
        # historical replay -- the new constant gates the new shape
        # so pre-Tier-12 blocks hash exactly as they always did.
        if self.version >= TX_VERSION_LENGTH_PREFIX:
            message_block = struct.pack(">H", len(self.message)) + self.message
        else:
            message_block = self.message
        base = (
            CHAIN_ID
            + b"message"  # domain-separation tag: prevents cross-type sig replay
            + struct.pack(">I", self.version)
            + struct.pack(">B", sig_version)
            + self.entity_id
            + struct.pack(">B", self.compression_flag)
            + message_block
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.fee)
        )
        # Version 1 txs hash the exact pre-fork bytes (backward-compat).
        # Version 2 txs append a 1-byte presence flag + 32-byte hash if
        # set.  The flag is part of the signed payload so an attacker
        # can't flip "no prev" ↔ "prev set" without invalidating the sig.
        if self.version >= TX_VERSION_PREV_POINTER:
            if self.prev is None:
                base += b"\x00"
            else:
                if len(self.prev) != 32:
                    raise ValueError(
                        f"prev must be exactly 32 bytes, got {len(self.prev)}"
                    )
                base += b"\x01" + self.prev
        # Version 3 appends the optional sender_pubkey block in the same
        # presence-flag-then-bytes shape.  Same security rationale as
        # `prev`: making the flag part of the signed payload prevents an
        # attacker from grafting a sender_pubkey onto someone else's
        # legitimately-signed v3 tx.
        if self.version >= TX_VERSION_FIRST_SEND_PUBKEY:
            if not self.sender_pubkey:
                base += b"\x00"
            else:
                if len(self.sender_pubkey) != 32:
                    raise ValueError(
                        f"sender_pubkey must be exactly 32 bytes, "
                        f"got {len(self.sender_pubkey)}"
                    )
                base += b"\x01" + self.sender_pubkey
        return base

    @property
    def plaintext(self) -> bytes:
        """The user's original ASCII bytes, decoded from the canonical form."""
        return decode_payload(self.message, self.compression_flag)

    def _compute_hash(self) -> bytes:
        return default_hash(self._signable_data())

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
        d = {
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
        # Only surface `prev` in the dict form for version 2+ txs that
        # actually carry a pointer — version 1 txs and prev-less v2 txs
        # omit the key entirely so JSON output stays clean and
        # deserialize() can round-trip pre-fork wire formats unchanged.
        if self.version >= TX_VERSION_PREV_POINTER and self.prev is not None:
            d["prev"] = self.prev.hex()
        # Same omit-when-empty rule for sender_pubkey: v3 txs from
        # already-on-chain senders carry no pubkey and the dict
        # round-trip stays minimal.
        if self.version >= TX_VERSION_FIRST_SEND_PUBKEY and self.sender_pubkey:
            d["sender_pubkey"] = self.sender_pubkey.hex()
        return d

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
        ]
        # Version 2 wire form: 1-byte presence flag + 32B hash if set.
        # Placed BEFORE the signature blob and tx_hash so the prev-
        # bearing payload travels as a contiguous block — simpler to
        # parse and keeps the layout stable under future additions.
        if self.version >= TX_VERSION_PREV_POINTER:
            if self.prev is None:
                parts.append(b"\x00")
            else:
                parts.append(b"\x01" + self.prev)
        # Version 3 wire form: same presence-flag layout, immediately
        # after the prev block.  Placed before signature so the field
        # is part of the signed payload (mirrors _signable_data).
        if self.version >= TX_VERSION_FIRST_SEND_PUBKEY:
            if not self.sender_pubkey:
                parts.append(b"\x00")
            else:
                parts.append(b"\x01" + self.sender_pubkey)
        parts.extend([
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])
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
        # Version 2 wire form: read the prev presence flag + optional hash.
        # Version 1 blobs skip this section entirely (preserves binary
        # compatibility with pre-fork chain data).
        prev: bytes | None = None
        if version >= TX_VERSION_PREV_POINTER:
            if offset + 1 > len(data):
                raise ValueError("MessageTransaction prev flag truncated")
            prev_flag = data[offset]; offset += 1
            if prev_flag == 0x00:
                prev = None
            elif prev_flag == 0x01:
                if offset + 32 > len(data):
                    raise ValueError("MessageTransaction prev hash truncated")
                prev = bytes(data[offset:offset + 32]); offset += 32
            else:
                raise ValueError(
                    f"MessageTransaction prev flag must be 0 or 1, got {prev_flag}"
                )
        # Version 3 wire form: same presence-flag-then-bytes layout for
        # the optional sender_pubkey field.  v1/v2 blobs skip entirely.
        sender_pubkey: bytes = b""
        if version >= TX_VERSION_FIRST_SEND_PUBKEY:
            if offset + 1 > len(data):
                raise ValueError(
                    "MessageTransaction sender_pubkey flag truncated"
                )
            pk_flag = data[offset]; offset += 1
            if pk_flag == 0x00:
                sender_pubkey = b""
            elif pk_flag == 0x01:
                if offset + 32 > len(data):
                    raise ValueError(
                        "MessageTransaction sender_pubkey truncated"
                    )
                sender_pubkey = bytes(data[offset:offset + 32]); offset += 32
            else:
                raise ValueError(
                    f"MessageTransaction sender_pubkey flag must be "
                    f"0 or 1, got {pk_flag}"
                )
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
            prev=prev,
            sender_pubkey=sender_pubkey,
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
        prev_hex = data.get("prev")
        prev_bytes = bytes.fromhex(prev_hex) if prev_hex else None
        sender_pubkey_hex = data.get("sender_pubkey")
        sender_pubkey = (
            bytes.fromhex(sender_pubkey_hex) if sender_pubkey_hex else b""
        )
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            message=stored,
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            fee=data["fee"],
            signature=sig,
            version=data.get("version", 1),
            compression_flag=flag,
            prev=prev_bytes,
            sender_pubkey=sender_pubkey,
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


def calculate_min_fee(
    message_bytes: bytes,
    signature_bytes: int = 0,
    current_height: int | None = None,
    prev_bytes: int = 0,
) -> int:
    """Calculate the minimum fee floor a tx must pay to be admitted.

    At/after BLOCK_BYTES_RAISE_HEIGHT (Tier 9): same linear formula as
    Tier 8, but with the raised per-byte rate:

        fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * len(message_bytes)

    The per-byte rate triples (1 → 3) in step with the per-block byte
    budget widening (15k → 45k) so bloat discipline scales with the
    wider cap.

    [LINEAR_FEE_HEIGHT, BLOCK_BYTES_RAISE_HEIGHT): linear-in-stored-
    bytes formula at the Tier 8 rate:

        fee_floor = BASE_TX_FEE + FEE_PER_STORED_BYTE * len(message_bytes)

    Pairs with the cap raise (MAX_MESSAGE_CHARS=1024) — long messages
    pay proportionally for the bytes they pin to permanent state.
    ``signature_bytes`` is ignored under the linear rule: the WOTS+
    witness is amortized into BASE_TX_FEE, which is uniform per tx.

    [FLAT_FEE_HEIGHT, LINEAR_FEE_HEIGHT): flat ``MIN_FEE_POST_FLAT``
    regardless of message or signature size.  Retained so blocks in
    this height window replay deterministically.

    Before FLAT_FEE_HEIGHT (and when ``current_height`` is None — the
    legacy default for isolated tests and non-consensus call sites):
    the legacy quadratic formula applies so historical blocks replay
    deterministically:

        Fee = MIN_FEE
            + (bytes * FEE_PER_BYTE)
            + (bytes^2 * FEE_QUADRATIC_COEFF) // 1000

    where ``bytes = len(message_bytes) + signature_bytes``.  The
    ``signature_bytes`` knob matches the pre-flat-fee
    FEE_INCLUDES_SIGNATURE_HEIGHT rule (witness bytes priced alongside
    payload).
    """
    # At/after PREV_POINTER_HEIGHT the `prev` pointer adds 33 stored
    # bytes (1B presence flag + 32B hash) when set.  Charged at the
    # live per-stored-byte rate so pointer txs pay uniformly for their
    # on-chain footprint — keeps the fee market neutral between
    # pointer and non-pointer messages, while still letting users opt
    # into the 33-byte pointer in exchange for not burning ~64 chars
    # of their 1024 text budget on inline hex.
    if current_height is not None and current_height >= BLOCK_BYTES_RAISE_HEIGHT:
        total_bytes = len(message_bytes) + prev_bytes
        return BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * total_bytes
    if current_height is not None and current_height >= LINEAR_FEE_HEIGHT:
        total_bytes = len(message_bytes) + prev_bytes
        return BASE_TX_FEE + FEE_PER_STORED_BYTE * total_bytes
    if current_height is not None and current_height >= FLAT_FEE_HEIGHT:
        return MIN_FEE_POST_FLAT
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

    Pre-FEE_INCLUDES_SIGNATURE_HEIGHT (``current_height`` is None or
    below activation):
      * Accept iff ``tx_fee >= flat_floor``.

    FEE_INCLUDES_SIGNATURE_HEIGHT ≤ ``current_height`` < FLAT_FEE_HEIGHT:
      * Accept iff ``tx_fee >= max(flat_floor, calculate_min_fee(b"",
        signature_bytes=signature_bytes))``.  Pricing the WOTS+ witness
        plugs the R5-A hole where a small-flat-fee tx type (transfer,
        stake, vote, revoke, etc.) could carry a ~2.7 KB signature at
        MIN_FEE and bloat permanent chain state at nearly zero cost.

    ``current_height`` ≥ FLAT_FEE_HEIGHT:
      * Accept iff ``tx_fee >= max(flat_floor, MIN_FEE_POST_FLAT)``.
        Size-indexed pricing is gone — the flat floor subsumes both the
        byte and witness surcharges.  The ``flat_floor`` argument
        (e.g. GOVERNANCE_PROPOSAL_FEE, KEY_ROTATION_FEE) still applies
        for tx types whose own hardcoded minimum exceeds the protocol
        floor.
    """
    if tx_fee < flat_floor:
        return False
    if current_height is not None and current_height >= FLAT_FEE_HEIGHT:
        if tx_fee < MIN_FEE_POST_FLAT:
            return False
        return True
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
    current_height: int | None = None,
    prev: bytes | None = None,
    *,
    include_pubkey: bool = False,
) -> MessageTransaction:
    """
    Create and sign a new message transaction.

    The fee is set by the user — higher fee means higher priority for
    block inclusion (BTC-style fee bidding).

    ``current_height`` selects the fee rule used for the floor check:
    pass the active chain tip so the caller pays the rule that
    verify_transaction will apply.  Default (None) uses the legacy
    rule, which is conservative — for any size, the legacy floor is
    ≥ both the flat and linear floors, so a tx accepted here also
    passes any later height-aware verification.  Tests targeting the
    linear floor exactly must thread the height through.

    ``include_pubkey``: emit a v3 MessageTransaction with the sender's
    public key in the optional sender_pubkey field.  Use on the
    sender's FIRST EVER outgoing message — without this, the chain
    rejects with "Unknown entity — must register first" because the
    pubkey was never installed.  After the first message lands, the
    pubkey is on chain and subsequent sends should leave the flag at
    False.  Mirrors TransferTransaction's first-outgoing-transfer
    pubkey reveal.
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
    # `prev`-bearing txs opt into tx version 2 and get charged 33 extra
    # stored bytes.  The presence-flag byte (+1B) is included even when
    # prev is None if version=2 — but we only bump version when the
    # caller actually provides a pointer, so prev-less senders keep the
    # legacy version=1 bytes-for-bytes.
    # `include_pubkey` bumps further to version 3 so the chain knows
    # to read the optional sender_pubkey block.  v3 also implies the
    # prev block is present (v3 supersedes v2 in the layout), so
    # prev_overhead is added unconditionally for v3 txs even when
    # prev is None — the empty presence flag still costs 1B.
    # Caller-intent → baseline version + per-stored-byte overhead.
    if include_pubkey:
        base_version = TX_VERSION_FIRST_SEND_PUBKEY
        # 33B for the prev block (always present at v3, presence-
        # flag-only when prev is None) + 33B for the sender_pubkey
        # block (presence flag + 32B pubkey since include_pubkey=True).
        # Charged at the per-stored-byte rate so the operator pays for
        # the bytes that pin to permanent state.
        prev_overhead = (
            PREV_POINTER_STORED_BYTES if prev is not None else 1
        ) + SENDER_PUBKEY_STORED_BYTES
    elif prev is not None:
        if len(prev) != 32:
            raise ValueError(
                f"prev must be exactly 32 bytes, got {len(prev)}"
            )
        base_version = TX_VERSION_PREV_POINTER
        prev_overhead = PREV_POINTER_STORED_BYTES
    else:
        base_version = 1
        prev_overhead = 0
    # Tier 12: post-activation, emit v4 (length-prefixed signable_data)
    # for new txs.  v4 inherits the v3 wire layout -- prev + sender_
    # pubkey presence-flag blocks are BOTH always present -- so a v4
    # tx with neither prev nor sender_pubkey carries 2 extra bytes
    # vs v1.  Charge those bytes at the per-stored-byte rate so the
    # fee floor reflects the new on-chain footprint.  Pre-activation
    # falls through to the baseline version (legacy behavior preserved
    # byte-for-byte for historical replay and current-height-None
    # callers like isolated unit tests).
    if (
        current_height is not None
        and current_height >= MESSAGE_TX_LENGTH_PREFIX_HEIGHT
    ):
        tx_version = TX_VERSION_LENGTH_PREFIX
        if not include_pubkey:
            # base_version was 1 or 2 -- v4 wire emits BOTH
            # presence flags, so add the absent ones now.
            if prev is None:
                prev_overhead += 1  # prev presence flag (was 0 for v1/v2-no-prev)
            prev_overhead += 1      # sender_pubkey presence flag (always under v4)
    else:
        tx_version = base_version
    if prev is not None and len(prev) != 32:
        raise ValueError(
            f"prev must be exactly 32 bytes, got {len(prev)}"
        )
    min_required = calculate_min_fee(
        stored,
        current_height=current_height,
        prev_bytes=prev_overhead,
    )
    if fee < min_required:
        raise ValueError(
            f"Fee must be at least {min_required} for this message "
            f"({len(stored)} stored bytes, flag={flag}"
            f"{', prev=set' if prev is not None else ''}"
            f"{', sender_pubkey=set' if include_pubkey else ''})"
        )

    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=stored,
        timestamp=int(time.time()),
        nonce=nonce,
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        version=tx_version,
        compression_flag=flag,
        prev=prev,
        sender_pubkey=entity.public_key if include_pubkey else b"",
    )

    # Sign the transaction data with quantum-resistant signature
    msg_hash = default_hash(tx._signable_data())
    tx.signature = entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    tx.witness_hash = tx._compute_witness_hash()

    return tx


def verify_transaction(
    tx: MessageTransaction,
    public_key: bytes,
    current_height: int | None = None,
    prev_lookup=None,
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
    # ── Version gate for tiers 10 / 11 / 12 ──
    # Pre-activation: only version=1 txs are accepted.  A higher-
    # version tx arriving before its fork point would allow its
    # extra bytes (or, for v4, the new length-prefixed signable
    # commitment) to land in a block whose replay semantics don't
    # know about the change, so we reject at the validation
    # boundary.  Post-PREV_POINTER_HEIGHT: v1, v2 accepted.
    # Post-FIRST_SEND_PUBKEY_HEIGHT: v3 also accepted.
    # Post-MESSAGE_TX_LENGTH_PREFIX_HEIGHT: v4 also accepted (and is
    # the recommended creation path for new txs; v1/v2/v3 remain
    # admissible for backward compatibility).  Any version above
    # v4 is rejected until its own activation fork.
    if tx.version > TX_VERSION_LENGTH_PREFIX:
        return False
    if tx.version >= TX_VERSION_LENGTH_PREFIX:
        if (
            current_height is not None
            and current_height < MESSAGE_TX_LENGTH_PREFIX_HEIGHT
        ):
            return False
        # v4 inherits the full v3 trailer layout (prev + sender_pubkey
        # presence-flag blocks), so the sender_pubkey shape rule below
        # applies identically.  The ONLY semantic delta vs v3 is the
        # >H length prefix on `message` inside `_signable_data`.
        if tx.sender_pubkey and len(tx.sender_pubkey) != 32:
            return False
    elif tx.version >= TX_VERSION_FIRST_SEND_PUBKEY:
        if (
            current_height is not None
            and current_height < FIRST_SEND_PUBKEY_HEIGHT
        ):
            return False
        if tx.sender_pubkey and len(tx.sender_pubkey) != 32:
            return False
    else:
        # v1/v2 MUST NOT carry a sender_pubkey field.
        if tx.sender_pubkey:
            return False
    if tx.version >= TX_VERSION_PREV_POINTER:
        if current_height is not None and current_height < PREV_POINTER_HEIGHT:
            return False
        if tx.prev is not None and len(tx.prev) != 32:
            return False
    else:
        # version=1 MUST NOT carry a prev field.
        if tx.prev is not None:
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
    # Fee rule depends on block height.  Delegate the full dispatch to
    # ``calculate_min_fee`` (single source of truth) instead of branching
    # on each gate locally — this keeps verify in lockstep with the fee
    # routing and is robust to schedule compressions where one fork
    # supersedes another (e.g. bootstrap-compressed LINEAR < FLAT, where
    # Tier 7 is retired in favor of Tier 8).
    #
    # Signature bytes feed the floor only in the legacy-quadratic window
    # (``[FEE_INCLUDES_SIGNATURE_HEIGHT, FLAT_FEE_HEIGHT)``).  At/after
    # FLAT or LINEAR the witness is amortized into the per-tx base and
    # ``calculate_min_fee`` ignores the ``signature_bytes`` argument.
    if (
        current_height is not None
        and current_height >= FEE_INCLUDES_SIGNATURE_HEIGHT
    ):
        sig_len = len(tx.signature.to_bytes())
    else:
        sig_len = 0
    # Stored-bytes overhead from optional fields.  v3 txs always pay
    # the prev presence flag (1B) even when prev is None, plus the
    # sender_pubkey block (33B) when set.  Mirrors create_transaction's
    # accounting so the fee floor a sender computed locally matches
    # what the chain enforces here.
    if tx.version >= TX_VERSION_FIRST_SEND_PUBKEY:
        prev_overhead = (
            PREV_POINTER_STORED_BYTES if tx.prev is not None else 1
        ) + (SENDER_PUBKEY_STORED_BYTES if tx.sender_pubkey else 1)
    else:
        prev_overhead = PREV_POINTER_STORED_BYTES if tx.prev is not None else 0
    if tx.fee < calculate_min_fee(
        tx.message,
        signature_bytes=sig_len,
        current_height=current_height,
        prev_bytes=prev_overhead,
    ):
        return False
    # Reject timestamps too far in the future (clock drift protection)
    if tx.timestamp > time.time() + MAX_TIMESTAMP_DRIFT:
        return False
    # Strict-prev check: when chain context is supplied via `prev_lookup`,
    # the referenced tx_hash MUST resolve to a tx already on-chain.
    # `prev_lookup(tx_hash) -> (block_height, tx_index) | None` — callers
    # without chain context (isolated unit tests, fixture builders) omit
    # the argument and the pointer is treated as structurally valid but
    # unresolved.  Self-reference is rejected unconditionally because the
    # tx can't precede itself.
    if tx.prev is not None:
        if tx.prev == tx.tx_hash:
            return False
        if prev_lookup is not None:
            loc = prev_lookup(tx.prev)
            if loc is None:
                return False
            if current_height is not None:
                prev_height, _prev_index = loc
                # Strictly earlier block.  Same-block-earlier-index is
                # resolved at block-validate time (where tx_index is
                # known); at mempool admit we only require the referent
                # to exist in a prior block.
                if prev_height >= current_height:
                    return False
    msg_hash = default_hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
