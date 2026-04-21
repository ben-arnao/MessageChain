"""
SetReceiptSubtreeRoot transaction — registers (or rotates) a validator's
receipt-subtree root public key in chain state.

Submission receipts (messagechain.network.submission_receipt) are signed
by a dedicated WOTS+ subtree — **separate from the block-signing tree** —
so receipt traffic cannot burn leaves the proposer needs for block
production.  Other nodes verify a receipt by pulling the issuer's
receipt-subtree root from chain state (Blockchain.receipt_subtree_roots)
and checking the signature against it.  Without an on-chain root, a
validator's receipts are unverifiable — the whole censorship-evidence
pipeline collapses.

This tx is what a validator uses to publish that root.  It is signed by
the validator's **authority (cold) key** — the same cold-key gate as
RevokeTransaction — because the root binds the validator's identity to
a specific subtree of WOTS+ one-time keys and an attacker who swaps the
root out from under the honest operator would effectively hijack the
receipting identity.

Idempotent: submitting the same root a second time is a no-op.
Rotation-safe: a new root replaces the old one in chain state, so an
operator who regenerates the subtree (e.g., after exhausting leaves)
can re-register without breaking any existing evidence against them
(evidence carries the receipt's root_public_key inline, so past
receipts stay verifiable against the root that was on-chain when they
were issued — see the censorship_evidence module for that binding).

## Why cold-key gated, not hot-key

The receipt-subtree root is a consensus-visible commitment that
identifies the *validator* (not the proposer slot).  A compromised hot
key should not be able to swap the receipting identity — doing so would
let an attacker who briefly controlled the server invalidate all
previously-issued receipts by installing a fresh root they control,
defeating any in-flight censorship evidence.  The cold key is the
correct authority: operators already keep it offline for unstake /
revoke, and a one-time registration at validator onboarding is a
natural fit for the same workflow.
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
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class SetReceiptSubtreeRootTransaction:
    """Register (or rotate) the receipt-subtree root public key for a validator.

    Signed by the entity's **authority (cold) key** — never the hot
    signing key.  Nonce-free: like RevokeTransaction, replay is
    defeated by idempotency (writing the same root a second time is a
    no-op and applying a fresh root after rotation is the intended
    operator workflow).  Pre-signable offline: an operator can sign
    the registration on a cold wallet and the hot node submits it
    without needing to know a live nonce.

    `root_public_key` is the 32-byte Merkle root of the validator's
    RECEIPT subtree (NOT the block-signing tree).  It is a raw public
    key — not an entity reference — so verifiers do not need to
    resolve it through the entity index registry.
    """

    entity_id: bytes
    root_public_key: bytes
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"set_receipt_subtree_root"
            + struct.pack(">B", sig_version)
            + self.entity_id
            + self.root_public_key
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "set_receipt_subtree_root",
            "entity_id": self.entity_id.hex(),
            "root_public_key": self.root_public_key.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    def to_bytes(self, state=None) -> bytes:
        """Binary: ENT entity_ref | 32 root_pk | f64 timestamp | u64 fee |
        u32 sig_len | sig | 32 tx_hash.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.entity_id, state=state),
            self.root_public_key,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(
        cls, data: bytes, state=None,
    ) -> "SetReceiptSubtreeRootTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("SetReceiptSubtreeRoot blob too short")
        entity_id, n = decode_entity_ref(data, off, state=state); off += n
        root_pk = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError(
                "SetReceiptSubtreeRoot truncated at signature/hash"
            )
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SetReceiptSubtreeRoot has trailing bytes")
        tx = cls(
            entity_id=entity_id,
            root_public_key=root_pk,
            timestamp=timestamp,
            fee=fee,
            signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SetReceiptSubtreeRoot hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "SetReceiptSubtreeRootTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            entity_id=bytes.fromhex(data["entity_id"]),
            root_public_key=bytes.fromhex(data["root_public_key"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"SetReceiptSubtreeRoot hash mismatch: declared "
                f"{data['tx_hash'][:16]}, computed {expected.hex()[:16]}"
            )
        return tx


def create_set_receipt_subtree_root_transaction(
    entity_id: bytes,
    root_public_key: bytes,
    authority_signer,
    fee: int = MIN_FEE,
) -> SetReceiptSubtreeRootTransaction:
    """Build and sign a SetReceiptSubtreeRoot tx.

    `authority_signer` is an object exposing a `.keypair` attribute whose
    public key matches the authority (cold) key currently registered for
    `entity_id`.  For single-key entities (no SetAuthorityKey yet applied)
    this is the entity itself; for hot/cold split setups it is the cold
    wallet.  No nonce — see module docstring.
    """
    tx = SetReceiptSubtreeRootTransaction(
        entity_id=entity_id,
        root_public_key=root_public_key,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = authority_signer.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def verify_set_receipt_subtree_root_transaction(
    tx: SetReceiptSubtreeRootTransaction,
    authority_public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify structural fields and the authority-key signature.

    Past timestamps are accepted without bound — pre-signable offline.
    Only future timestamps beyond MAX_TIMESTAMP_DRIFT are rejected.

    `current_height` selects the fee rule: post
    FEE_INCLUDES_SIGNATURE_HEIGHT the floor becomes max(MIN_FEE,
    sig-aware min) so WOTS+ witnesses can't be admitted at MIN_FEE (R5-A).
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    if len(tx.root_public_key) != 32:
        return False
    if len(tx.entity_id) != 32:
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
    return verify_signature(msg_hash, tx.signature, authority_public_key)
