"""
Bogus-rejection evidence + slashing.

Closes the receipt-less censorship gap.  Today's `SubmissionReceipt`
catches "admit then drop" censorship — a validator promises to include
a tx and then never does.  But the most common nation-state pressure
scenario is different: the validator is coerced to refuse specific
txs while keeping up the appearance of liveness for everyone else.
That validator can simply answer the HTTPS submission with a bogus
rejection ("invalid signature") and never burn a receipt — the
existing slashing path has nothing to attach to.

`SignedRejection` plus this module fix that.  The validator commits
to a reason_code in a signed rejection; when the rejection is
provably bogus (re-verify the embedded tx's signature against its
on-chain pubkey), that's grounds for an immediate stake slash.

Pipeline (one-phase, unlike CensorshipEvidenceTx):

  1. Anyone observes a SignedRejection that doesn't match reality
     (typically: client got a REJECT_INVALID_SIG for a tx whose
     signature actually verifies).
  2. Anyone files `BogusRejectionEvidenceTx(rejection, message_tx)`
     paying MIN_FEE.
  3. At block-apply time, the chain validates and (if the rejection
     reason is currently slashable) re-runs verify_transaction on
     the embedded message_tx using its on-chain public key.
  4. If verify SUCCEEDS, the rejection was bogus → slash the issuer
     CENSORSHIP_SLASH_BPS of stake, burned (no finder reward).
  5. If verify FAILS, the rejection was honest — evidence_tx is
     rejected at apply-time (fee NOT charged, no admission, no slash).

Slashable subset (v1): only REJECT_INVALID_SIG.  Other reason codes
are admitted into the chain (fee paid, evidence recorded as
processed) but produce no slash.  This keeps the on-chain framework
extensible without a hard fork — once on-chain commitments to a
validator's local view of nonces / mempool depth / dynamic fee floor
exist, more codes can be activated by widening the slashable set.

**Determinism**: the `processed` set is included in the state
snapshot (same pattern as CensorshipEvidenceProcessor) so every
node reaches identical slashing outcomes after replay.

**Double-slash defense**: each evidence_hash is recorded in
`processed` on first apply.  A repeat submission of the SAME
(rejection, message_tx) pair is rejected at validation time.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from messagechain.config import (
    HASH_ALGO, CHAIN_ID, SIG_VERSION_CURRENT, MIN_FEE,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.core.transaction import (
    MessageTransaction, verify_transaction,
)
from messagechain.network.submission_receipt import (
    SignedRejection, verify_rejection,
    REJECT_INVALID_SIG,
)
from messagechain.crypto.hashing import default_hash


_DOMAIN_TAG = b"bogus-rejection-evidence"

# Reason codes that are CURRENTLY slashable.  Other codes still admit
# the evidence_tx (it pays a fee + lands in the processed set) but
# trigger no slash.  Frozen so a typo in another module cannot widen
# the slashing surface accidentally.
_SLASHABLE_REASON_CODES = frozenset({REJECT_INVALID_SIG})


def _h(data: bytes) -> bytes:
    return default_hash(data)


@dataclass
class BogusRejectionEvidenceTx:
    """Tx type that submits a SignedRejection + the rejected message_tx
    as evidence that the rejection was bogus.

    Including the full `message_tx` (not just its hash) is what lets
    the chain re-run verify_transaction at apply-time and refute
    REJECT_INVALID_SIG without needing the rejection's victim to be
    online.

    Any registered entity can submit.  Submission fee = MIN_FEE
    (small, flat, non-scaling).  No finder reward — slashed tokens
    burn, same as CensorshipEvidenceTx.  Burning prevents griefing
    races where two evidence-spammers fight over the same victim.
    """
    rejection: SignedRejection
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
        """The validator we are alleging issued the bogus rejection."""
        return self.rejection.issuer_id

    @property
    def evidence_hash(self) -> bytes:
        """Uniquely identifies this evidence for dedupe / processed
        bookkeeping.  Keyed on (rejection_hash, message_tx.tx_hash)
        so two evidences targeting the same (rejection, tx) pair
        collide by design — a re-submission under a different
        submitter is rejected as already-processed."""
        return _h(
            _DOMAIN_TAG
            + self.rejection.rejection_hash
            + self.message_tx.tx_hash
        )

    def _signable_data(self) -> bytes:
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            CHAIN_ID,
            _DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.rejection.rejection_hash,
            self.message_tx.tx_hash,
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "bogus_rejection_evidence",
            "rejection": self.rejection.serialize(),
            "message_tx": self.message_tx.serialize(),
            "submitter_id": self.submitter_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    def to_bytes(self, state=None) -> bytes:
        rej_blob = self.rejection.to_bytes()
        try:
            mtx_blob = self.message_tx.to_bytes(state=state)
        except TypeError:
            mtx_blob = self.message_tx.to_bytes()
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">I", len(rej_blob)),
            rej_blob,
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
    def from_bytes(cls, data: bytes, state=None) -> "BogusRejectionEvidenceTx":
        off = 0
        if len(data) < 4 + 4 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("BogusRejectionEvidenceTx blob too short")
        rej_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + rej_len > len(data):
            raise ValueError("BogusRejectionEvidenceTx truncated at rejection")
        rejection = SignedRejection.from_bytes(bytes(data[off:off + rej_len]))
        off += rej_len
        mtx_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + mtx_len > len(data):
            raise ValueError("BogusRejectionEvidenceTx truncated at message_tx")
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
            raise ValueError(
                "BogusRejectionEvidenceTx truncated at sig/hash"
            )
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("BogusRejectionEvidenceTx has trailing bytes")
        tx = cls(
            rejection=rejection, message_tx=message_tx,
            submitter_id=submitter_id, timestamp=timestamp, fee=fee,
            signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"BogusRejectionEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "BogusRejectionEvidenceTx":
        tx = cls(
            rejection=SignedRejection.deserialize(data["rejection"]),
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
                f"BogusRejectionEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx


def verify_bogus_rejection_evidence_tx(
    tx: BogusRejectionEvidenceTx,
    submitter_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless verification of a BogusRejectionEvidenceTx.

    Checks (cheap-first, mirrors verify_censorship_evidence_tx):
      * rejection.tx_hash matches message_tx.tx_hash
      * fee is at least MIN_FEE
      * rejection signature is valid under issuer_root_public_key
      * submitter signature is valid under submitter_public_key

    Does NOT decide slashability — that depends on chain state
    (re-verifying the message_tx's signature under its on-chain
    pubkey) and lives in BogusRejectionProcessor.process.
    """
    if tx.rejection.tx_hash != tx.message_tx.tx_hash:
        return False, "rejection.tx_hash does not match message_tx.tx_hash"
    if tx.fee < MIN_FEE:
        return False, f"fee below MIN_FEE ({MIN_FEE})"
    ok, reason = verify_rejection(tx.rejection)
    if not ok:
        return False, f"invalid rejection: {reason}"
    if len(submitter_public_key) != 32:
        return False, "submitter public key must be 32 bytes"
    msg_hash = _h(tx._signable_data())
    if not verify_signature(msg_hash, tx.signature, submitter_public_key):
        return False, "invalid submitter signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# Processor
# ─────────────────────────────────────────────────────────────────────

@dataclass
class BogusRejectionResult:
    """Outcome of BogusRejectionProcessor.process().

    Three terminal states:

      * accepted=True, slashed=True   — bogus REJECT_INVALID_SIG
        rejection; offender slashed by `slash_amount`, evidence
        recorded as processed.

      * accepted=True, slashed=False  — non-slashable reason code
        (forward-compat); evidence recorded as processed but no
        stake change.  Evidence_tx still pays its fee.

      * accepted=False, slashed=False — rejection was HONEST (the
        embedded tx's signature actually fails) OR the evidence was
        already processed.  Evidence_tx is rejected; no fee charged.
    """
    accepted: bool
    slashed: bool
    offender_id: bytes = b""
    slash_amount: int = 0
    reason: str = ""


class BogusRejectionProcessor:
    """One-phase processor for BogusRejectionEvidenceTx.

    Unlike CensorshipEvidenceProcessor, there's no maturity window or
    pending map — bogusness is immediately decidable from the tx
    payload + chain state at apply-time.

    State:
      * processed: set[evidence_hash] — every evidence ever applied
        (slashed OR admitted-no-slash) is recorded here so the same
        evidence cannot be processed twice.

    Snapshot: included in the chain state-snapshot so every node
    reaches identical outcomes after replay.
    """

    def __init__(self):
        self.processed: set[bytes] = set()

    def has_processed(self, evidence_hash: bytes) -> bool:
        return evidence_hash in self.processed

    def process(
        self,
        tx: BogusRejectionEvidenceTx,
        blockchain,
    ) -> BogusRejectionResult:
        """Decide the outcome of a BogusRejectionEvidenceTx.

        For REJECT_INVALID_SIG: re-verify the message_tx's signature
        under its on-chain public key.  If verify SUCCEEDS, the
        rejection lied → slash.  If verify FAILS, the rejection was
        honest → reject the evidence_tx (no slash, no admission,
        caller must NOT charge fee).

        For non-slashable reason codes: admit + record processed,
        no slash.  Caller charges the fee normally.

        Already-processed evidence is rejected unconditionally.
        """
        from messagechain.consensus.censorship_evidence import (
            compute_slash_amount,
        )

        if tx.evidence_hash in self.processed:
            return BogusRejectionResult(
                accepted=False, slashed=False,
                reason="evidence already processed",
            )

        offender_id = tx.offender_id
        reason_code = tx.rejection.reason_code

        if reason_code in _SLASHABLE_REASON_CODES:
            # Re-verify the embedded message_tx using its on-chain pubkey.
            offender_pk = blockchain.public_keys.get(
                tx.message_tx.entity_id, b"",
            )
            if not offender_pk:
                # We can't refute a rejection for a tx whose signer has
                # no on-chain pubkey — the validator's REJECT_INVALID_SIG
                # might be honest (no key to verify against).  Treat as
                # honest-rejection: reject evidence, no slash.
                return BogusRejectionResult(
                    accepted=False, slashed=False,
                    reason=(
                        "honest rejection: message_tx signer has no "
                        "on-chain public key to verify against"
                    ),
                )
            sig_verifies = verify_transaction(tx.message_tx, offender_pk)
            if not sig_verifies:
                # Rejection was HONEST — the tx's signature actually
                # fails to verify.  Caller MUST NOT charge fee — the
                # evidence was wrong, not the validator.
                return BogusRejectionResult(
                    accepted=False, slashed=False,
                    reason=(
                        "honest rejection: message_tx signature actually "
                        "fails to verify under on-chain pubkey"
                    ),
                )
            # Bogus rejection — apply the slash.
            current_stake = blockchain.supply.staked.get(offender_id, 0)
            slash_amount = compute_slash_amount(current_stake)
            if slash_amount > 0:
                blockchain.supply.staked[offender_id] = (
                    current_stake - slash_amount
                )
                blockchain.supply.total_supply -= slash_amount
                blockchain.supply.total_burned += slash_amount
            self.processed.add(tx.evidence_hash)
            return BogusRejectionResult(
                accepted=True, slashed=True,
                offender_id=offender_id,
                slash_amount=slash_amount,
                reason="bogus REJECT_INVALID_SIG: slashed",
            )

        # Non-slashable reason code: admit (caller charges fee) + record.
        self.processed.add(tx.evidence_hash)
        return BogusRejectionResult(
            accepted=True, slashed=False,
            offender_id=offender_id,
            reason=(
                f"reason_code {reason_code} accepted as evidence but "
                f"not slashable in v1 (forward-compat)"
            ),
        )

    # ── Snapshot for state-root inclusion ────────────────────────────

    def snapshot_dict(self) -> dict:
        """Deterministic dict form for state-snapshot inclusion."""
        return {
            "processed": [h.hex() for h in sorted(self.processed)],
        }

    def load_snapshot_dict(self, data: dict) -> None:
        """Replace in-memory state with a previously serialized snapshot."""
        processed_raw = data.get("processed", [])
        self.processed = {bytes.fromhex(h) for h in processed_raw}
