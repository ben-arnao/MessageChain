"""Censorship evidence — slashable proof that a validator dropped a tx.

A `CensorshipEvidenceTx` carries:
  * The `SubmissionReceipt` the accused validator issued.
  * The original tx bytes (so any verifier can reconstruct tx_hash
    and check it matches the receipt).
  * The height at which the evidence was filed.

The on-chain verification rule is straightforward:
  1. Receipt signature is valid against the accused validator's
     dedicated receipt-tree root (tracked in chain state).
  2. The tx_hash in the receipt matches the hash of the supplied
     tx bytes.
  3. The grace window has elapsed: the current block height is
     strictly greater than
     `receipt.received_at_height + CENSORSHIP_GRACE_BLOCKS`.
  4. The tx_hash does NOT appear in any block in
     `[received+1, received+CENSORSHIP_GRACE_BLOCKS]` (consensus-
     checkable — every node has the same blocks).
  5. The receipt has not already been used as evidence (single-use).

If verification passes, the evidence is PENDING, not immediately
applied.  Two-phase slashing:

    t = evidence_filed_height
    challenge window = [t+1, t+EVIDENCE_CHALLENGE_BLOCKS]

    * If any block in the window contains the tx_hash, the evidence
      is VOIDED.  The accused validator has defended themselves by
      now-including the tx.  No slash.
    * If the window elapses with no inclusion, the slash FIRES:
      `CENSORSHIP_SLASH_BPS / 10000` of the validator's stake is
      BURNED.  Accuser gets nothing (prevents forge-for-profit).

Why self-contained verification wins over a "non-inclusion witness"
proof system: every node already stores the blocks in the grace
window.  Walking those blocks for a specific tx_hash is O(grace_size)
dict lookups — cheaper than verifying any fancy proof structure.  The
extra block-scan cost is bounded by CENSORSHIP_GRACE_BLOCKS which is a
protocol constant, so no adversarial blow-up.

Evidence is also gated by an `EVIDENCE_SUBMISSION_FEE` at the tx
layer — the accuser pays to file.  Combined with burn-on-slash (no
finder reward), forgery-for-profit is eliminated.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional

from messagechain.config import (
    CENSORSHIP_GRACE_BLOCKS,
    CENSORSHIP_SLASH_BPS,
    CHAIN_ID,
    EVIDENCE_CHALLENGE_BLOCKS,
    EVIDENCE_EXPIRY_BLOCKS,
    EVIDENCE_SUBMISSION_FEE,
    HASH_ALGO,
    SIG_VERSION_CURRENT,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.keys import Signature
from messagechain.network.submission_receipt import (
    SubmissionReceipt,
    verify_receipt,
)


__all__ = [
    "CensorshipEvidenceProcessor",
    "CensorshipEvidenceTx",
    "PendingEvidence",
    "compute_slash_amount",
    "create_censorship_evidence_tx",
    "verify_censorship_evidence",
]


def compute_slash_amount(stake: int) -> int:
    """Amount of stake to burn under CENSORSHIP_SLASH_BPS.

    BPS = basis points = 1/10000.  Integer-only math so the result is
    deterministic across platforms.  Floor on the division means the
    protocol can never burn MORE than the declared percentage — which
    also means a validator with tiny stake (< 10000 / bps tokens) is
    effectively un-slashable at the 10% rate.  That's fine: the only
    validators with material stake are those the protocol cares about
    protecting users from, and for them the 10% bite is meaningful.
    """
    if stake <= 0:
        return 0
    return (stake * CENSORSHIP_SLASH_BPS) // 10_000


@dataclass
class CensorshipEvidenceTx:
    """Tx type carrying censorship evidence into a block.

    Separate from SlashTransaction (which targets double-sign /
    double-attestation) because the verification, challenge, and
    slash-fire rules are fundamentally different:
      * SlashTransaction fires immediately on verification.
      * CensorshipEvidenceTx goes into a pending queue and fires only
        after EVIDENCE_CHALLENGE_BLOCKS elapse without inclusion.

    Mixing them into one type would force every block pipeline to carry
    "is this slash immediate or delayed?" branching, which is
    error-prone.  A distinct tx type keeps the two paths isolated.
    """

    receipt: SubmissionReceipt
    tx: MessageTransaction
    submitter_id: bytes
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
            + b"censorship-evidence"  # domain-separation tag
            + struct.pack(">B", sig_version)
            + self.receipt.to_bytes()
            + self.tx.tx_hash  # commits to the alleged-censored tx
            + self.submitter_id
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return hashlib.new(HASH_ALGO, self._signable_data()).digest()

    @property
    def offender_id(self) -> bytes:
        """The validator being accused — derived from the receipt.

        The receipt carries `validator_pubkey` which is the validator's
        block-signing tree root.  In chain state, entity_id is
        derived from the public key via identity.derive_entity_id —
        but for slashing we look up by the pubkey match since the
        receipt doesn't carry the derived entity_id.  Blockchain state
        maintains the pubkey→entity_id mapping; the caller resolves it.
        """
        return self.receipt.validator_pubkey

    def serialize(self) -> dict:
        return {
            "type": "censorship_evidence",
            "receipt": self.receipt.serialize(),
            "tx": self.tx.serialize(),
            "submitter_id": self.submitter_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "CensorshipEvidenceTx":
        sig = Signature.deserialize(data["signature"])
        receipt = SubmissionReceipt.deserialize(data["receipt"])
        tx = MessageTransaction.deserialize(data["tx"])
        ev = cls(
            receipt=receipt,
            tx=tx,
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected = ev._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"CensorshipEvidenceTx hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return ev

    def to_bytes(self) -> bytes:
        """Binary: length-prefixed receipt, tx, and signature blobs."""
        receipt_blob = self.receipt.to_bytes()
        tx_blob = self.tx.to_bytes()
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">I", len(receipt_blob)), receipt_blob,
            struct.pack(">I", len(tx_blob)), tx_blob,
            self.submitter_id,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)), sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "CensorshipEvidenceTx":
        off = 0
        if len(data) < 4 + 4 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("CensorshipEvidenceTx blob too short")
        r_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + r_len > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at receipt")
        receipt = SubmissionReceipt.from_bytes(bytes(data[off:off + r_len]))
        off += r_len
        t_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + t_len > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at tx")
        tx = MessageTransaction.from_bytes(bytes(data[off:off + t_len]))
        off += t_len
        if off + 32 + 8 + 8 + 4 > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at fixed fields")
        submitter_id = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("CensorshipEvidenceTx truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("CensorshipEvidenceTx has trailing bytes")
        ev = cls(
            receipt=receipt, tx=tx,
            submitter_id=submitter_id,
            timestamp=timestamp, fee=fee, signature=sig,
        )
        expected = ev._compute_hash()
        if expected != declared:
            raise ValueError("CensorshipEvidenceTx hash mismatch on decode")
        return ev


def verify_censorship_evidence(
    ev: CensorshipEvidenceTx,
    *,
    current_height: int,
    receipt_tree_root: bytes,
    blocks_in_window: list,
    already_processed: Optional[set] = None,
) -> tuple[bool, str]:
    """Consensus-deterministic evidence verification.

    `blocks_in_window` is the list of blocks whose heights fall in
    `[receipt.received_at_height + 1, receipt.received_at_height +
    CENSORSHIP_GRACE_BLOCKS]` — the caller (blockchain) extracts
    these from its own chain.  If the validator proposed any of these
    blocks and did NOT include the receipted tx, that's the observable
    censorship.  Empty window (validator never proposed in the window)
    is ALSO censorship — per spec, "didn't propose at all" is a valid
    form of censorship when the validator is actively subject to the
    duty.  In v1 we simplify to "the tx was not included anywhere in
    the window"; pure liveness (offline) censorship punishment is left
    to existing attestation-layer inactivity leak.

    Returns (True, "") on acceptable evidence; (False, reason) otherwise.

    Does NOT apply slashing itself — caller queues pending evidence
    and runs the challenge-window logic before burning stake.
    """
    receipt = ev.receipt

    # Hash consistency: the receipt's tx_hash must equal the supplied
    # tx's hash.  A mismatch means the accuser stitched together a
    # real receipt with a different tx, trying to slash for a tx the
    # validator never attested to.
    if receipt.tx_hash != ev.tx.tx_hash:
        return False, "receipt.tx_hash does not match supplied tx"

    # Window boundary checks.  The grace window ends at
    # received + CENSORSHIP_GRACE_BLOCKS; evidence before that point
    # is premature and rejected.  Evidence past EVIDENCE_EXPIRY is
    # stale and rejected — a receipt cannot overhang indefinitely as
    # a slashing threat.
    window_end = receipt.received_at_height + CENSORSHIP_GRACE_BLOCKS
    if current_height <= window_end:
        return False, (
            f"evidence premature: current_height {current_height} not past "
            f"grace window end {window_end}"
        )
    expiry = receipt.received_at_height + EVIDENCE_EXPIRY_BLOCKS
    if current_height > expiry:
        return False, (
            f"evidence stale: current_height {current_height} past expiry {expiry}"
        )

    # Signature verification.  The receipt must verify against the
    # validator's on-chain receipt-tree root.  A forged receipt (bad
    # sig) is caught here.
    if not verify_receipt(receipt, receipt_tree_root):
        return False, "receipt signature invalid under validator's receipt-tree root"

    # Fee gate: the evidence tx itself must pay at least the spam-
    # deterrent fee.  Without this, any rejected-evidence-for-free
    # path becomes a DoS vector.
    if ev.fee < EVIDENCE_SUBMISSION_FEE:
        return False, (
            f"evidence submission fee {ev.fee} below minimum "
            f"{EVIDENCE_SUBMISSION_FEE}"
        )

    # Non-inclusion witness: the tx_hash must NOT appear in any block
    # of the grace window.  The caller supplies the blocks; we scan
    # their tx lists.  This is O(blocks_in_window * txs_per_block) —
    # bounded by CENSORSHIP_GRACE_BLOCKS * MAX_TXS_PER_BLOCK ~ 120 ops.
    for block in blocks_in_window:
        for tx in getattr(block, "transactions", []) or []:
            if getattr(tx, "tx_hash", None) == receipt.tx_hash:
                return False, (
                    f"tx_hash was included at block height "
                    f"{getattr(block, 'header', None) and block.header.block_number}"
                )

    # Replay: the same receipt cannot be used twice.
    if already_processed is not None and receipt.tx_hash in already_processed:
        return False, "receipt already used as evidence"

    return True, "OK"


def create_censorship_evidence_tx(
    submitter_entity,
    receipt: SubmissionReceipt,
    tx: MessageTransaction,
    fee: int = EVIDENCE_SUBMISSION_FEE,
) -> CensorshipEvidenceTx:
    """Construct and sign a CensorshipEvidenceTx.

    The submitter signs the evidence hash, establishing who filed the
    evidence.  Note: the submitter is NOT paid for a successful slash
    (slash is burned), so the signature is purely for authenticity
    and for the fee-debit path — not an incentive hook.
    """
    ev = CensorshipEvidenceTx(
        receipt=receipt,
        tx=tx,
        submitter_id=submitter_entity.entity_id,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = hashlib.new(HASH_ALGO, ev._signable_data()).digest()
    ev.signature = submitter_entity.keypair.sign(msg_hash)
    ev.tx_hash = ev._compute_hash()
    return ev


# ---------------------------------------------------------------------------
# Two-phase slashing pipeline.
# ---------------------------------------------------------------------------
#
# Evidence fires slashing only AFTER a 24-hour challenge window
# (EVIDENCE_CHALLENGE_BLOCKS).  Between "evidence accepted" and
# "slash fires" the accused validator can void the evidence by
# including the tx in any block.
#
# The processor below keeps the pending state and exposes three
# operations:
#   * submit(evidence, at_height) — verify and queue pending.
#   * observe_block(block) — scan block txs; any pending evidence
#     whose tx_hash appears is voided.
#   * mature(current_height) — returns the list of pending evidences
#     whose challenge window has ELAPSED without a void.  The caller
#     runs the actual stake burn against each.
#
# Keeping the processor stateful but independent from the Blockchain
# class makes it straightforward to test in isolation, and the
# integration with Blockchain._apply_block_state is a thin wire-up
# (add processor, feed blocks, burn stake for matured evidences).

@dataclass
class PendingEvidence:
    """Queued evidence awaiting the end of its challenge window."""
    evidence: CensorshipEvidenceTx
    submitted_at_height: int

    @property
    def challenge_deadline(self) -> int:
        """Height at which the challenge window closes.

        `submitted_at_height + EVIDENCE_CHALLENGE_BLOCKS`: blocks with
        height <= deadline are still INSIDE the window (validator may
        still void); blocks with height > deadline are PAST the window
        (slash fires on next mature() call).
        """
        return self.submitted_at_height + EVIDENCE_CHALLENGE_BLOCKS


class CensorshipEvidenceProcessor:
    """Stateful two-phase slashing pipeline.

    Holds:
      * pending: dict[receipt_tx_hash, PendingEvidence]  — queue of
        evidence awaiting the challenge window's end.
      * processed: set[receipt_tx_hash] — receipts already turned
        into evidence (accepted OR voided OR matured).  Prevents
        replay.
      * voided: set[receipt_tx_hash] — evidence that was voided
        during the challenge window by the accused validator
        including the tx.  Tracked separately from `processed` so
        inspection tests can distinguish outcomes.
      * slashed: list[SlashFireEvent] — evidence that matured
        without a void.  Caller reads this and runs actual stake
        reductions.

    The processor itself does NOT touch stake — it only decides WHEN
    a slash should fire.  Keeping the two concerns separate means
    this module doesn't need to know about SupplyTracker internals,
    and the tests drive slashing decisions independent of token
    accounting.
    """

    def __init__(self):
        self.pending: dict[bytes, PendingEvidence] = {}
        self.processed: set[bytes] = set()
        self.voided: set[bytes] = set()
        # Matured = "challenge window elapsed without void" — the
        # caller burns stake in response.  We keep a tombstone of
        # matured receipt hashes here so replay is still blocked
        # even after the caller has consumed mature().
        self._matured_receipts: set[bytes] = set()

    def submit(
        self,
        evidence: CensorshipEvidenceTx,
        current_height: int,
        receipt_tree_root: bytes,
        blocks_in_window: list,
    ) -> tuple[bool, str]:
        """Verify and queue pending evidence.

        Returns (True, "OK") on acceptance; (False, reason) on any
        verification failure or replay.  A queued evidence stays in
        `pending` until either observe_block voids it or mature()
        sweeps it past its challenge_deadline.
        """
        receipt_hash = evidence.receipt.tx_hash
        if receipt_hash in self.processed:
            return False, "receipt already used as evidence"
        ok, reason = verify_censorship_evidence(
            evidence,
            current_height=current_height,
            receipt_tree_root=receipt_tree_root,
            blocks_in_window=blocks_in_window,
            already_processed=self.processed,
        )
        if not ok:
            return False, reason
        self.pending[receipt_hash] = PendingEvidence(
            evidence=evidence,
            submitted_at_height=current_height,
        )
        self.processed.add(receipt_hash)
        return True, "OK"

    def observe_block(self, block) -> list[bytes]:
        """Scan `block.transactions` for any pending-evidence tx_hash.

        Any match voids the corresponding pending evidence — the
        accused validator (or any other proposer) included the tx,
        defeating the censorship accusation.

        Returns the list of receipt-hashes that were voided by this
        block, for observability.
        """
        if not self.pending:
            return []
        voided_here: list[bytes] = []
        included_hashes = {
            getattr(tx, "tx_hash", None)
            for tx in getattr(block, "transactions", []) or []
        }
        for receipt_hash in list(self.pending):
            ev = self.pending[receipt_hash].evidence
            if ev.receipt.tx_hash in included_hashes:
                self.voided.add(receipt_hash)
                del self.pending[receipt_hash]
                voided_here.append(receipt_hash)
        return voided_here

    def mature(self, current_height: int) -> list[PendingEvidence]:
        """Return pending evidence whose challenge window has ELAPSED.

        Caller is expected to burn stake for each returned item.  The
        processor removes matured items from `pending` and records
        their receipt hashes so a later replay is still blocked.
        """
        matured: list[PendingEvidence] = []
        for receipt_hash in list(self.pending):
            pe = self.pending[receipt_hash]
            if current_height > pe.challenge_deadline:
                matured.append(pe)
                self._matured_receipts.add(receipt_hash)
                del self.pending[receipt_hash]
        return matured

    def is_matured(self, receipt_hash: bytes) -> bool:
        return receipt_hash in self._matured_receipts

    def is_voided(self, receipt_hash: bytes) -> bool:
        return receipt_hash in self.voided
