"""Attestable submission receipts — gossip-layer censorship defense.

A SubmissionReceipt is a notarized timestamp: the validator's signed
attestation that "I received tx_hash at height H, and the user paid
SUBMISSION_FEE for the privilege."  The receipt is returned to the
user synchronously from the /submit RPC; the user holds it until:

  * The tx is included on-chain — the receipt is discarded.
  * The grace window (CENSORSHIP_GRACE_BLOCKS) elapses without
    inclusion — the receipt becomes slashable evidence (see
    messagechain.consensus.censorship_evidence).

The signature is produced with a DEDICATED WOTS+ subtree kept separate
from the validator's block-signing tree.  Receipt signing consumes
leaves far faster than block signing (per-submission vs per-block), so
mixing them would risk bricking the block-signing key material under
load.  Separation also means an exhausted receipt tree does not lock
the validator out of consensus participation — receipts just stop
being issued, which is a degraded-but-safe failure mode.

Design trade-offs:

  * Receipts are signed with a one-time WOTS+ leaf, same primitive as
    every other signature on the chain.  No new crypto primitive is
    introduced; the existing `messagechain.crypto.keys.KeyPair` does
    the heavy lifting.  Only the leaf-index accounting is distinct.

  * The signable body is a deterministic concatenation of domain tag
    + version + tx_hash + validator_pubkey + height + fee.  Domain
    separation ("receipt") prevents any cross-tx-type signature
    replay under the same WOTS+ leaf (which must not happen anyway,
    because a leaf is one-time; the domain tag is defense in depth).

  * Height is packed as u64 big-endian.  Fee is u64 big-endian.
    Version is u8.  All fixed-width — no varints — because the
    signable body is short and a predictable layout makes both
    Python and future-language verifiers trivial.

  * The wire format trails the signature with explicit length
    prefixes so a mis-parse raises ValueError instead of silently
    decoding a truncated blob into a valid-looking receipt.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from messagechain.config import (
    CHAIN_ID,
    HASH_ALGO,
    RECEIPT_VERSION,
    validate_receipt_version,
)
from messagechain.crypto.keys import KeyPair, Signature, verify_signature


__all__ = [
    "SubmissionReceipt",
    "build_receipt_signable",
    "sign_receipt",
    "verify_receipt",
]


# Domain-separation tag: prevents a receipt signature from ever being
# accepted as any other signed object under the same pubkey.  Kept
# short (single-byte tag would be enough for safety, but we spell it
# out because readability wins in consensus-critical paths).
_RECEIPT_DOMAIN = b"submission-receipt"


def build_receipt_signable(
    tx_hash: bytes,
    validator_pubkey: bytes,
    received_at_height: int,
    submission_fee_paid: int,
    version: int = RECEIPT_VERSION,
) -> bytes:
    """Canonical bytes the validator signs when issuing a receipt.

    Layout:
        CHAIN_ID || "submission-receipt" || u8 version ||
        32 tx_hash || 32 validator_pubkey || u64 height || u64 fee

    The hash algorithm only matters for the caller that hashes the
    output before calling KeyPair.sign; WOTS+ operates on 32-byte
    digests.  We return the pre-hash bytes so the caller can drive
    both signing and verification through the same canonical form.
    """
    if not isinstance(tx_hash, (bytes, bytearray)) or len(tx_hash) != 32:
        raise ValueError("tx_hash must be 32 bytes")
    if not isinstance(validator_pubkey, (bytes, bytearray)) or len(validator_pubkey) != 32:
        raise ValueError("validator_pubkey must be 32 bytes")
    if not isinstance(received_at_height, int) or received_at_height < 0:
        raise ValueError("received_at_height must be non-negative int")
    if not isinstance(submission_fee_paid, int) or submission_fee_paid < 0:
        raise ValueError("submission_fee_paid must be non-negative int")
    ok, reason = validate_receipt_version(version)
    if not ok:
        raise ValueError(reason)
    return (
        CHAIN_ID
        + _RECEIPT_DOMAIN
        + struct.pack(">B", version)
        + bytes(tx_hash)
        + bytes(validator_pubkey)
        + struct.pack(">Q", received_at_height)
        + struct.pack(">Q", submission_fee_paid)
    )


@dataclass
class SubmissionReceipt:
    """Signed attestation: validator saw tx_hash at height H.

    Size (serialized, typical): ~3.5KB at WOTS_KEY_CHAINS=64, h=24.
    The big contributor is the WOTS+ signature itself (64 chain
    hashes * 32 B = 2048 B) plus the 24-level auth path (768 B).
    """

    tx_hash: bytes                # 32 — the tx the user submitted
    validator_pubkey: bytes       # 32 — the validator's receipt-tree root
    received_at_height: int       # u64 — chain height when accepted
    submission_fee_paid: int      # u64 — fee charged to the submitter
    signature: Signature          # WOTS+ sig from the receipt subtree
    version: int = RECEIPT_VERSION

    def signable_data(self) -> bytes:
        return build_receipt_signable(
            tx_hash=self.tx_hash,
            validator_pubkey=self.validator_pubkey,
            received_at_height=self.received_at_height,
            submission_fee_paid=self.submission_fee_paid,
            version=self.version,
        )

    def serialize(self) -> dict:
        return {
            "version": self.version,
            "tx_hash": self.tx_hash.hex(),
            "validator_pubkey": self.validator_pubkey.hex(),
            "received_at_height": self.received_at_height,
            "submission_fee_paid": self.submission_fee_paid,
            "signature": self.signature.serialize(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "SubmissionReceipt":
        version = data.get("version", RECEIPT_VERSION)
        ok, reason = validate_receipt_version(version)
        if not ok:
            raise ValueError(reason)
        return cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            validator_pubkey=bytes.fromhex(data["validator_pubkey"]),
            received_at_height=data["received_at_height"],
            submission_fee_paid=data["submission_fee_paid"],
            signature=Signature.deserialize(data["signature"]),
            version=version,
        )

    def to_bytes(self) -> bytes:
        """Compact binary encoding.

        Layout:
            u8   version
            32   tx_hash
            32   validator_pubkey
            u64  received_at_height
            u64  submission_fee_paid
            u32  sig_blob_len
            N    sig_blob
        """
        ok, reason = validate_receipt_version(self.version)
        if not ok:
            raise ValueError(reason)
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">B", self.version),
            self.tx_hash,
            self.validator_pubkey,
            struct.pack(">Q", self.received_at_height),
            struct.pack(">Q", self.submission_fee_paid),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SubmissionReceipt":
        if len(data) < 1 + 32 + 32 + 8 + 8 + 4:
            raise ValueError("SubmissionReceipt blob too short")
        off = 0
        version = struct.unpack_from(">B", data, off)[0]
        off += 1
        ok, reason = validate_receipt_version(version)
        if not ok:
            raise ValueError(reason)
        tx_hash = bytes(data[off:off + 32]); off += 32
        validator_pubkey = bytes(data[off:off + 32]); off += 32
        received_at_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        submission_fee_paid = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len != len(data):
            raise ValueError("SubmissionReceipt blob has wrong trailing length")
        signature = Signature.from_bytes(bytes(data[off:off + sig_len]))
        return cls(
            tx_hash=tx_hash,
            validator_pubkey=validator_pubkey,
            received_at_height=received_at_height,
            submission_fee_paid=submission_fee_paid,
            signature=signature,
            version=version,
        )


def sign_receipt(
    keypair: KeyPair,
    tx_hash: bytes,
    validator_pubkey: bytes,
    received_at_height: int,
    submission_fee_paid: int,
    version: int = RECEIPT_VERSION,
) -> SubmissionReceipt:
    """Issue a receipt by signing with the validator's receipt-subtree keypair.

    `keypair` MUST be the dedicated receipt-signing tree — the caller
    is responsible for keeping this instance separate from the
    block-signing tree.  Mixing them is a leaf-reuse bug that would
    brick consensus participation.

    `validator_pubkey` is the validator's on-chain identity (their
    block-signing tree root).  It's recorded in the receipt so the
    accuser can prove which validator is being challenged; the
    receipt's SIGNATURE is verified against the RECEIPT tree root
    (carried separately on-chain per validator).
    """
    signable = build_receipt_signable(
        tx_hash=tx_hash,
        validator_pubkey=validator_pubkey,
        received_at_height=received_at_height,
        submission_fee_paid=submission_fee_paid,
        version=version,
    )
    msg_hash = hashlib.new(HASH_ALGO, signable).digest()
    sig = keypair.sign(msg_hash)
    return SubmissionReceipt(
        tx_hash=bytes(tx_hash),
        validator_pubkey=bytes(validator_pubkey),
        received_at_height=received_at_height,
        submission_fee_paid=submission_fee_paid,
        signature=sig,
        version=version,
    )


def verify_receipt(
    receipt: SubmissionReceipt,
    receipt_tree_root: bytes,
) -> bool:
    """Verify the receipt signature against the validator's receipt-tree root.

    Returns False on any structural defect.  Never raises on malformed
    input — all rejection is via False return, so the caller can chain
    verify_receipt(...) && ... safely.

    `receipt_tree_root` is the Merkle root of the validator's dedicated
    receipt-signing tree.  On-chain, validators publish this via a
    separate registration path (future work); for v1 the root is
    accepted out-of-band (the user already trusted the validator enough
    to submit a tx to it).
    """
    if not isinstance(receipt, SubmissionReceipt):
        return False
    if not isinstance(receipt_tree_root, (bytes, bytearray)) or len(receipt_tree_root) != 32:
        return False
    try:
        signable = receipt.signable_data()
    except (ValueError, TypeError):
        return False
    msg_hash = hashlib.new(HASH_ALGO, signable).digest()
    return verify_signature(msg_hash, receipt.signature, receipt_tree_root)
