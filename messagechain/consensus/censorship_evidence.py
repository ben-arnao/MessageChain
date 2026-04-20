"""
Censorship-evidence slashing.

A validator who issues a SubmissionReceipt for a tx and then never
includes it (nor lets any peer include it) has censored that tx.  This
module turns that observation into a slashable event.

Pipeline (two-phase):

  1. **Submit** a `CensorshipEvidenceTx` carrying (receipt, tx) such
     that `commit_height + EVIDENCE_INCLUSION_WINDOW < current_height`
     and `tx` is NOT yet on-chain.  At mempool-admission time we
     verify the receipt signature, the window, and that the tx does
     not already appear in chain state.

  2. **Mature**: after EVIDENCE_MATURITY_BLOCKS have elapsed since
     admission, if the tx STILL has not been included on-chain (as
     attested by the processor's observe_block pipeline), the slash
     is applied: the accused validator loses CENSORSHIP_SLASH_BPS of
     their stake, burned.  The accuser gets no reward — this is a
     public-goods slashing path, not a finder-fee one, so honest
     proposers cannot grief one another by racing to submit evidence
     against a validator who happened to delay a single tx.

**Voiding**: at any time during the maturity window, if the receipted
tx lands on-chain (in a block produced by anyone — not necessarily the
accused), the pending evidence is voided without slashing.  This
corrects griefing: an attacker who files evidence the block before
their target was going to include the tx anyway does not land a slash,
because the subsequent block's observe_block() removes the pending
entry.

**Determinism**: processor state (the pending-evidence map and the
already-processed-evidence set) is included in the state snapshot so
every node reaches identical slashing outcomes.

**Double-slash defense**: each evidence_hash is recorded in
processed_evidence on maturity (and on void) so the same evidence can
never be applied twice — even across restarts.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional, Iterable

from messagechain.config import (
    HASH_ALGO, CHAIN_ID, SIG_VERSION_CURRENT,
    EVIDENCE_INCLUSION_WINDOW, EVIDENCE_MATURITY_BLOCKS,
    EVIDENCE_EXPIRY_BLOCKS, CENSORSHIP_SLASH_BPS,
    MIN_FEE,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.core.transaction import MessageTransaction
from messagechain.network.submission_receipt import (
    SubmissionReceipt, verify_receipt,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class CensorshipEvidenceTx:
    """Tx type that submits a receipt + the censored tx as evidence.

    The `message_tx` field carries the RECEIPTED tx.  Including the
    full tx (not just its hash) is what lets observe_block void the
    evidence when any peer lands the tx on-chain: every node can
    compare the tx_hash of a freshly-applied block tx against the
    pending-evidence map.

    Any registered entity can submit.  Submission fee = MIN_FEE
    (small, flat, non-scaling) — just high enough to make bulk
    evidence-spam expensive.  No finder reward: slashed tokens burn.
    """
    receipt: SubmissionReceipt
    # The receipted tx.  Including it here lets every node know which
    # tx needs to appear on-chain for this evidence to void.
    message_tx: MessageTransaction
    submitter_id: bytes
    timestamp: int  # integer seconds (consensus hashing)
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    @property
    def offender_id(self) -> bytes:
        """The validator we are alleging censored the tx."""
        return self.receipt.issuer_id

    @property
    def evidence_hash(self) -> bytes:
        """Uniquely identifies this evidence for dedupe / void /
        mature bookkeeping.  Keyed on the receipt and the receipted
        tx_hash so two evidences for the same (receipt, tx) pair
        collide by design — you cannot re-submit the same censorship
        claim under a different submitter."""
        return _h(
            b"censorship-evidence-v1"
            + self.receipt.receipt_hash
            + self.message_tx.tx_hash
        )

    def _signable_data(self) -> bytes:
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            CHAIN_ID,
            b"censorship-evidence",  # domain-separation tag
            struct.pack(">B", sig_version),
            self.receipt.receipt_hash,
            self.message_tx.tx_hash,
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "censorship_evidence",
            "receipt": self.receipt.serialize(),
            "message_tx": self.message_tx.serialize(),
            "submitter_id": self.submitter_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    def to_bytes(self, state=None) -> bytes:
        r_blob = self.receipt.to_bytes()
        # MessageTransaction encodes with an optional `state` for the
        # varint-index form.  Pass through for on-chain embedding.
        try:
            mtx_blob = self.message_tx.to_bytes(state=state)
        except TypeError:
            mtx_blob = self.message_tx.to_bytes()
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">I", len(r_blob)),
            r_blob,
            struct.pack(">I", len(mtx_blob)),
            mtx_blob,
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "CensorshipEvidenceTx":
        off = 0
        if len(data) < 4 + 4 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("CensorshipEvidenceTx blob too short")
        r_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + r_len > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at receipt")
        receipt = SubmissionReceipt.from_bytes(bytes(data[off:off + r_len]))
        off += r_len
        mtx_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + mtx_len > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at message_tx")
        try:
            message_tx = MessageTransaction.from_bytes(
                bytes(data[off:off + mtx_len]), state=state,
            )
        except TypeError:
            message_tx = MessageTransaction.from_bytes(
                bytes(data[off:off + mtx_len]),
            )
        off += mtx_len
        submitter_id = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">Q", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at sig/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("CensorshipEvidenceTx has trailing bytes")
        tx = cls(
            receipt=receipt, message_tx=message_tx,
            submitter_id=submitter_id, timestamp=timestamp, fee=fee,
            signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"CensorshipEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "CensorshipEvidenceTx":
        tx = cls(
            receipt=SubmissionReceipt.deserialize(data["receipt"]),
            message_tx=MessageTransaction.deserialize(data["message_tx"]),
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=int(data["timestamp"]),
            fee=int(data["fee"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"CensorshipEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx


def verify_censorship_evidence_tx(
    tx: CensorshipEvidenceTx,
    submitter_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless verification of a CensorshipEvidenceTx.

    Checks:
      * receipt signature valid under receipt.issuer_root_public_key
      * receipt.tx_hash matches message_tx.tx_hash (consistent pair)
      * submitter signature valid under submitter_public_key
      * fee is at least MIN_FEE

    Caller (Blockchain) additionally checks that:
      * submitter_id is a registered entity
      * issuer_root_public_key matches the chain's record for the issuer
      * window/expiry/inclusion-status are satisfied
      * evidence_hash has not already been processed
    """
    # Receipt binds tx_hash — reject mismatched pairs.
    if tx.receipt.tx_hash != tx.message_tx.tx_hash:
        return False, "receipt.tx_hash does not match message_tx.tx_hash"
    # Fee floor.
    if tx.fee < MIN_FEE:
        return False, f"fee below MIN_FEE ({MIN_FEE})"
    # Receipt self-validity.
    ok, reason = verify_receipt(tx.receipt)
    if not ok:
        return False, f"invalid receipt: {reason}"
    # Submitter signature.
    if len(submitter_public_key) != 32:
        return False, "submitter public key must be 32 bytes"
    msg_hash = _h(tx._signable_data())
    if not verify_signature(msg_hash, tx.signature, submitter_public_key):
        return False, "invalid submitter signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# Processor: pending-evidence lifecycle
# ─────────────────────────────────────────────────────────────────────

@dataclass
class _PendingEvidence:
    """Internal state kept for each admitted evidence_hash."""
    evidence_hash: bytes
    offender_id: bytes
    tx_hash: bytes
    admitted_height: int
    # Kept for serialization; the processor does not re-verify
    # signatures at mature-time (admission already did).
    evidence_tx_hash: bytes

    def serialize(self) -> dict:
        return {
            "evidence_hash": self.evidence_hash.hex(),
            "offender_id": self.offender_id.hex(),
            "tx_hash": self.tx_hash.hex(),
            "admitted_height": self.admitted_height,
            "evidence_tx_hash": self.evidence_tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "_PendingEvidence":
        return cls(
            evidence_hash=bytes.fromhex(data["evidence_hash"]),
            offender_id=bytes.fromhex(data["offender_id"]),
            tx_hash=bytes.fromhex(data["tx_hash"]),
            admitted_height=int(data["admitted_height"]),
            evidence_tx_hash=bytes.fromhex(data["evidence_tx_hash"]),
        )


@dataclass
class MaturedEvidence:
    """Result of processor.mature(): a now-matured evidence that should
    be applied as a slash by the caller (Blockchain)."""
    evidence_hash: bytes
    offender_id: bytes
    tx_hash: bytes


class CensorshipEvidenceProcessor:
    """Pending-evidence state machine.

    Lifecycle:
      * `submit(evidence_hash, offender_id, tx_hash, admitted_height,
        evidence_tx_hash)` — called when the chain admits a
        CensorshipEvidenceTx in a block.  Adds to pending map.

      * `observe_block(block)` — called from Blockchain._apply_block_state
        once per block apply.  Any pending entry whose tx_hash matches
        a tx in this block (or a later one, since observe_block runs
        on every block) gets voided and recorded in processed.

      * `mature(current_height)` — called at end of each
        _apply_block_state.  Returns list[MaturedEvidence] for any
        pending entry whose admitted_height + EVIDENCE_MATURITY_BLOCKS
        <= current_height.  Caller applies the slash and records the
        evidence_hash in processed.

    State:
      * pending: dict[evidence_hash -> _PendingEvidence]
      * processed: set[evidence_hash] — every evidence ever admitted
        is recorded here on mature() OR void(), so the same evidence
        cannot be admitted twice.

    Both dicts are included in the chain state snapshot (see
    storage.state_snapshot) so every node reaches identical slashing
    outcomes and a cold-booted node inherits the pipeline.
    """

    def __init__(self):
        self.pending: dict[bytes, _PendingEvidence] = {}
        # Processed set: once an evidence_hash lands here, no new
        # CensorshipEvidenceTx with the same hash may be admitted.
        # This is the double-slash defense.
        self.processed: set[bytes] = set()

    def has_processed(self, evidence_hash: bytes) -> bool:
        return evidence_hash in self.processed

    def is_pending(self, evidence_hash: bytes) -> bool:
        return evidence_hash in self.pending

    def submit(
        self,
        evidence_hash: bytes,
        offender_id: bytes,
        tx_hash: bytes,
        admitted_height: int,
        evidence_tx_hash: bytes,
    ) -> bool:
        """Admit an evidence into the pending map.

        Returns False if the evidence is already pending or already
        processed (double-submission prevention).  The chain should
        ALSO check processor.has_processed(evidence_hash) at
        validation time — this method is the apply-time shim.
        """
        if evidence_hash in self.processed:
            return False
        if evidence_hash in self.pending:
            return False
        self.pending[evidence_hash] = _PendingEvidence(
            evidence_hash=evidence_hash,
            offender_id=offender_id,
            tx_hash=tx_hash,
            admitted_height=admitted_height,
            evidence_tx_hash=evidence_tx_hash,
        )
        return True

    def observe_block(self, block) -> list[bytes]:
        """Void any pending evidence whose receipted tx appears in
        `block`.  Returns the list of voided evidence_hashes.

        Voiding also records the evidence_hash in `processed` so a
        future submission of the SAME evidence is rejected — once an
        evidence has been "spent" (voided), it cannot be reused.
        """
        if not self.pending:
            return []
        # Collect tx_hashes in this block.  Block.transactions is the
        # only list CensorshipEvidenceTx's message_tx can target (we
        # only receipt MessageTransactions).
        seen_tx_hashes = {tx.tx_hash for tx in block.transactions}
        voided: list[bytes] = []
        for ev_hash, pending in list(self.pending.items()):
            if pending.tx_hash in seen_tx_hashes:
                voided.append(ev_hash)
        for ev_hash in voided:
            del self.pending[ev_hash]
            self.processed.add(ev_hash)
        return voided

    def mature(self, current_height: int) -> list[MaturedEvidence]:
        """Return evidences whose maturity window has elapsed without
        the tx landing on-chain.  Caller applies the slash and the
        evidence_hash is recorded in `processed`.
        """
        if not self.pending:
            return []
        matured: list[MaturedEvidence] = []
        for ev_hash, pending in list(self.pending.items()):
            if pending.admitted_height + EVIDENCE_MATURITY_BLOCKS <= current_height:
                matured.append(MaturedEvidence(
                    evidence_hash=ev_hash,
                    offender_id=pending.offender_id,
                    tx_hash=pending.tx_hash,
                ))
        for m in matured:
            del self.pending[m.evidence_hash]
            self.processed.add(m.evidence_hash)
        return matured

    # ── Serialization for state root / snapshot ──────────────────────

    def snapshot_dict(self) -> dict:
        """Deterministic dict form for state-snapshot inclusion.

        Keys are hex strings (JSON-friendly); callers computing
        state roots should sort by raw-bytes key (same contract as
        storage.state_snapshot._entries_for_section).
        """
        return {
            "pending": {
                ev_hash.hex(): pending.serialize()
                for ev_hash, pending in self.pending.items()
            },
            "processed": [h.hex() for h in sorted(self.processed)],
        }

    def load_snapshot_dict(self, data: dict) -> None:
        """Replace in-memory state with a previously serialized snapshot."""
        pending_raw = data.get("pending", {})
        processed_raw = data.get("processed", [])
        self.pending = {
            bytes.fromhex(ev_hex): _PendingEvidence.deserialize(entry)
            for ev_hex, entry in pending_raw.items()
        }
        self.processed = {bytes.fromhex(h) for h in processed_raw}


def compute_slash_amount(stake: int) -> int:
    """10% of stake at CENSORSHIP_SLASH_BPS = 1000.  Integer math."""
    if stake <= 0:
        return 0
    return (stake * CENSORSHIP_SLASH_BPS) // 10_000
