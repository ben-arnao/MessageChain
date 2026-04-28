"""
Non-response evidence + slashing.

Closes the silent-TCP-drop censorship gap.  Today's `BogusRejection`
catches validators who answer an HTTPS submission with a bogus
rejection.  Today's `Censorship` catches validators who issue a
receipt and then never include the tx.  Neither catches a validator
who simply drops the TCP connection silently when receiving a
witnessed submission.

Witnessed submission (see consensus.witness_submission) closes this:

  1. Client opts in (paying WITNESS_SURCHARGE) and signs a
     `SubmissionRequest`.
  2. The request is BOTH POSTed to the validator AND gossiped to the
     witness topic.
  3. Target validator MUST publish a `SubmissionAck` within
     WITNESS_RESPONSE_DEADLINE_BLOCKS.
  4. If they don't, peers who saw the gossip sign WitnessObservations.
  5. ANY entity packages Q observations into a NonResponseEvidenceTx.
  6. Processor admits if (a) deadline passed, (b) Q distinct active-set
     witnesses signed valid observations, (c) chain has no record of
     an ack, (d) evidence not yet processed.  On admission: slash the
     target validator WITNESS_NON_RESPONSE_SLASH_BPS of stake (smaller
     than CENSORSHIP_SLASH_BPS because a silent drop is less aggressive
     than admit-then-drop).

Pipeline (one-phase, mirrors bogus_rejection_evidence):

  * Stateless verification: signature shapes, fee floor, Q-of-N quorum
    before active-set filtering.
  * Apply-time decision: deadline + ack-registry + active-set + dedupe.
  * Slashed tokens BURNED — no finder reward (anti-griefing race).

Determinism: `processed` set is included in the state snapshot so
every node reaches identical slashing outcomes after replay.

Double-slash defense: each `evidence_hash` (keyed on `request_hash`)
is recorded in `processed` on first apply.  A repeat submission of the
same request_hash is rejected at validation time.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Mapping

from messagechain.config import (
    CHAIN_ID, HASH_ALGO, MIN_FEE, SIG_VERSION_CURRENT,
    VALIDATOR_MIN_STAKE,
    WITNESS_QUORUM,
    WITNESS_RESPONSE_DEADLINE_BLOCKS,
    WITNESS_NON_RESPONSE_SLASH_BPS,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.consensus.witness_submission import (
    SubmissionRequest,
    WitnessObservation,
    verify_submission_request,
    verify_witness_observation,
)
from messagechain.crypto.hashing import default_hash


# Domain tag — distinct from receipt, rejection, request, ack, and
# observation tags.  Belt-and-braces unit test asserts uniqueness.
_DOMAIN_TAG = b"mc-non-response-evidence-v1"


def _h(data: bytes) -> bytes:
    return default_hash(data)


def compute_non_response_slash_amount(stake: int) -> int:
    """Legacy flat WITNESS_NON_RESPONSE_SLASH_BPS (5%) of stake.

    Pre-Tier-30-sibling (HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT) the
    processor's slash path consults this directly.  Post-fork the
    processor routes through `slashing_severity` instead — see
    `_compute_non_response_slash_amount_curve` below for the curve
    path that closes the flat-BPS first-offense penalty on long-
    tenured honest operators.
    """
    if stake <= 0:
        return 0
    return (stake * WITNESS_NON_RESPONSE_SLASH_BPS) // 10_000


def _compute_non_response_slash_amount_curve(
    stake: int, offender_id: bytes, blockchain,
) -> int:
    """Honesty-curve slash amount for a witness-non-response offense.

    Routes through `slashing_severity` with `Unambiguity.AMBIGUOUS` —
    a single dropped witnessed submission is plausibly transient
    packet loss, not proof of intent.  Repeat patterns escalate via
    the curve's existing slash_offense_counts ramp.
    """
    if stake <= 0:
        return 0
    from messagechain.consensus.honesty_curve import (
        OffenseKind, Unambiguity, slashing_severity,
    )
    sev_pct = slashing_severity(
        offender_id,
        OffenseKind.WITNESS_NON_RESPONSE,
        Unambiguity.AMBIGUOUS,
        blockchain,
    )
    return (stake * sev_pct) // 100


# ─────────────────────────────────────────────────────────────────────
# NonResponseEvidenceTx
# ─────────────────────────────────────────────────────────────────────

@dataclass
class NonResponseEvidenceTx:
    """Tx type that carries a SubmissionRequest + Q WitnessObservations
    as evidence that the request's target validator silently dropped
    the witnessed submission.

    Including the full SubmissionRequest (not just its hash) is what
    lets the chain re-verify the client's signature and bind the
    evidence to a specific (target_validator, request) pair without
    needing the original client to be online.

    Any registered entity can submit.  Submission fee = MIN_FEE.  No
    finder reward — slashed tokens BURN, same as
    BogusRejectionEvidenceTx.  Burning prevents griefing races where
    two evidence-spammers fight over the same victim.
    """

    request: SubmissionRequest
    witness_observations: list[WitnessObservation]
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
        """The validator we are alleging silently dropped the submission."""
        return self.request.target_validator_id

    @property
    def evidence_hash(self) -> bytes:
        """Uniquely identifies this evidence for dedupe / processed
        bookkeeping.  Keyed ONLY on request_hash — a re-submission of
        the same request under a different submitter or a different
        witness set collides by design (same offense, one slash).
        """
        return _h(_DOMAIN_TAG + self.request.request_hash)

    def affected_entities(self) -> set[bytes]:
        """Apply path debits the submitter's fee + bumps their
        leaf_watermark; on accepted slash the target validator
        (offender) is burned in the same block.  Both mutate in the
        admission block.  See CLAUDE.md canonical registry contract.
        """
        return {self.submitter_id, self.offender_id}

    def _signable_data(self) -> bytes:
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        # Bind the observation_hash list (sorted for determinism) so a
        # tampered observation set forces re-signing by the submitter.
        obs_blob = b"".join(
            sorted(o.observation_hash for o in self.witness_observations)
        )
        return b"".join([
            CHAIN_ID,
            _DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.request.request_hash,
            obs_blob,
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "non_response_evidence",
            "request": self.request.serialize(),
            "witness_observations": [
                o.serialize() for o in self.witness_observations
            ],
            "submitter_id": self.submitter_id.hex(),
            "timestamp": int(self.timestamp),
            "fee": int(self.fee),
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        req_blob = self.request.to_bytes()
        sig_blob = self.signature.to_bytes()
        # Encode witness_observations as a count-prefixed list of
        # length-prefixed blobs.  Keeps decoding deterministic when
        # observations have heterogeneous sig sizes.
        obs_section = struct.pack(">I", len(self.witness_observations))
        for o in self.witness_observations:
            o_blob = o.to_bytes()
            obs_section += struct.pack(">I", len(o_blob)) + o_blob
        return b"".join([
            struct.pack(">I", len(req_blob)),
            req_blob,
            obs_section,
            self.submitter_id,
            struct.pack(">Q", int(self.timestamp)),
            struct.pack(">Q", int(self.fee)),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "NonResponseEvidenceTx":
        off = 0
        if len(data) < 4 + 4 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("NonResponseEvidenceTx blob too short")
        req_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + req_len > len(data):
            raise ValueError("NonResponseEvidenceTx truncated at request")
        req = SubmissionRequest.from_bytes(bytes(data[off:off + req_len]))
        off += req_len
        n_obs = struct.unpack_from(">I", data, off)[0]; off += 4
        observations: list[WitnessObservation] = []
        for _ in range(n_obs):
            o_len = struct.unpack_from(">I", data, off)[0]; off += 4
            if off + o_len > len(data):
                raise ValueError(
                    "NonResponseEvidenceTx truncated mid-observation"
                )
            observations.append(
                WitnessObservation.from_bytes(bytes(data[off:off + o_len]))
            )
            off += o_len
        if off + 32 + 8 + 8 + 4 + 32 > len(data):
            raise ValueError("NonResponseEvidenceTx truncated at trailer")
        submitter_id = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">Q", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError(
                "NonResponseEvidenceTx truncated at sig/hash"
            )
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("NonResponseEvidenceTx has trailing bytes")
        tx = cls(
            request=req,
            witness_observations=observations,
            submitter_id=submitter_id,
            timestamp=timestamp,
            fee=fee,
            signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"NonResponseEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "NonResponseEvidenceTx":
        tx = cls(
            request=SubmissionRequest.deserialize(data["request"]),
            witness_observations=[
                WitnessObservation.deserialize(o)
                for o in data["witness_observations"]
            ],
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=int(data["timestamp"]),
            fee=int(data["fee"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = tx._compute_hash()
        declared = bytes.fromhex(data["tx_hash"])
        if expected != declared:
            raise ValueError(
                f"NonResponseEvidenceTx hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return tx


def sign_non_response_evidence(
    submitter,
    request: SubmissionRequest,
    observations: list[WitnessObservation],
    timestamp: int,
    fee: int,
) -> NonResponseEvidenceTx:
    """Build a fully-signed NonResponseEvidenceTx.

    `submitter` is anything with `.entity_id` and `.keypair.sign()` —
    typically an Entity from messagechain.identity.
    """
    placeholder = Signature([], 0, [], b"", b"")
    tx = NonResponseEvidenceTx(
        request=request,
        witness_observations=list(observations),
        submitter_id=submitter.entity_id,
        timestamp=int(timestamp),
        fee=int(fee),
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    sig = submitter.keypair.sign(msg_hash)
    return NonResponseEvidenceTx(
        request=request,
        witness_observations=list(observations),
        submitter_id=submitter.entity_id,
        timestamp=int(timestamp),
        fee=int(fee),
        signature=sig,
    )


def verify_non_response_evidence_tx(
    tx: NonResponseEvidenceTx,
    submitter_public_key: bytes,
    *,
    witness_public_keys: Mapping[bytes, bytes],
    client_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless-ish verification of a NonResponseEvidenceTx.

    Checks (cheap-first):
      * fee >= MIN_FEE
      * client signature on the embedded SubmissionRequest verifies
        under client_public_key
      * every WitnessObservation binds to tx.request.request_hash
      * no duplicate witness_id across observations
      * every WitnessObservation signature verifies under the
        corresponding entry in witness_public_keys
      * len(observations) >= WITNESS_QUORUM (after duplicate filter)
      * submitter signature verifies under submitter_public_key

    Active-set membership is NOT checked here — that's a chain-state
    decision and lives in NonResponseEvidenceProcessor.process.
    """
    if tx.fee < MIN_FEE:
        return False, f"fee below MIN_FEE ({MIN_FEE})"

    # Client signature on the request.
    ok, reason = verify_submission_request(tx.request, client_public_key)
    if not ok:
        return False, f"invalid request: {reason}"

    seen_witnesses: set[bytes] = set()
    for o in tx.witness_observations:
        if o.request_hash != tx.request.request_hash:
            return False, "witness observation does not bind to request_hash"
        if o.witness_id in seen_witnesses:
            return False, (
                f"duplicate witness in observations: "
                f"{o.witness_id.hex()[:16]}"
            )
        seen_witnesses.add(o.witness_id)
        wpk = witness_public_keys.get(o.witness_id)
        if wpk is None:
            return False, (
                f"witness {o.witness_id.hex()[:16]} has no public key on file"
            )
        ok, reason = verify_witness_observation(o, wpk)
        if not ok:
            return False, f"invalid witness observation: {reason}"

    if len(seen_witnesses) < WITNESS_QUORUM:
        return False, (
            f"observations below quorum: have {len(seen_witnesses)}, "
            f"need {WITNESS_QUORUM}"
        )

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
class NonResponseResult:
    """Outcome of NonResponseEvidenceProcessor.process()."""
    accepted: bool
    slashed: bool
    offender_id: bytes = b""
    slash_amount: int = 0
    reason: str = ""


class NonResponseEvidenceProcessor:
    """One-phase processor for NonResponseEvidenceTx.

    State:
      * processed: set[evidence_hash] — every evidence ever applied is
        recorded here so the same evidence cannot be processed twice.

    Snapshot-serialised for replay determinism.

    process() applies ALL admission gates in one pass and returns the
    outcome.  No pending map / no maturity window — by the time a
    NonResponseEvidenceTx hits the chain, the deadline has already
    passed and the slash is decidable from chain state.
    """

    def __init__(self):
        self.processed: set[bytes] = set()

    def has_processed(self, evidence_hash: bytes) -> bool:
        return evidence_hash in self.processed

    def process(
        self,
        tx: NonResponseEvidenceTx,
        blockchain,
        current_height: int,
    ) -> NonResponseResult:
        """Decide the outcome of a NonResponseEvidenceTx.

        Admission gates:
          1. Not already processed.
          2. request_hash NOT in chain's witness_ack_registry with an
             ack_height <= observed_height + DEADLINE_BLOCKS.  If the
             chain saw an ack within the deadline, the obligation was
             met and the evidence is rejected (no slash, no admission).
          3. Each observation: observed_height + DEADLINE < current_height
             (deadline truly passed).
          4. Each observation: witness_id in active validator set at
             observed_height (active = currently has stake >=
             VALIDATOR_MIN_STAKE).
          5. After active-set filter, distinct witness count >= QUORUM.
          6. Each retained observation's signature verifies under the
             chain's public_keys[witness_id].

        On admission: slash the offender by
        WITNESS_NON_RESPONSE_SLASH_BPS, burn the slashed tokens, mark
        evidence processed.  No finder reward — burning prevents
        griefing races.
        """
        if tx.evidence_hash in self.processed:
            return NonResponseResult(
                accepted=False, slashed=False,
                reason="evidence already processed",
            )

        offender_id = tx.offender_id
        request_hash = tx.request.request_hash

        # Ack-registry gate: if the chain has seen an ack and that ack
        # arrived within the deadline of ANY observation, the
        # obligation was met.  We treat the earliest observation height
        # as the binding deadline reference (strictest case for the
        # offender — if any honest peer saw the gossip early, the ack
        # had to land soon after).
        ack_h = blockchain.witness_ack_registry.get(request_hash)
        if ack_h is not None and tx.witness_observations:
            earliest_obs = min(
                o.observed_height for o in tx.witness_observations
            )
            if ack_h <= earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS:
                return NonResponseResult(
                    accepted=False, slashed=False,
                    reason=(
                        f"obligation met: chain recorded ack at "
                        f"height {ack_h} within deadline "
                        f"{earliest_obs + WITNESS_RESPONSE_DEADLINE_BLOCKS}"
                    ),
                )

        # Deadline + active-set filter.
        valid_witnesses: set[bytes] = set()
        for o in tx.witness_observations:
            # Deadline must truly have passed.
            if int(current_height) <= o.observed_height + WITNESS_RESPONSE_DEADLINE_BLOCKS:
                return NonResponseResult(
                    accepted=False, slashed=False,
                    reason=(
                        f"deadline not yet passed for observation "
                        f"observed_height={o.observed_height}, "
                        f"current_height={current_height}, "
                        f"deadline_blocks={WITNESS_RESPONSE_DEADLINE_BLOCKS}"
                    ),
                )
            # Witness must be in the active set at observed_height.
            stake = blockchain.supply.staked.get(o.witness_id, 0)
            if stake < VALIDATOR_MIN_STAKE:
                # Drop this observation.  We don't fail-fast here so a
                # single rogue observation doesn't poison an evidence
                # that still has Q honest active witnesses.
                continue
            # Witness signature verifies under chain pubkey.
            wpk = blockchain.public_keys.get(o.witness_id, b"")
            if not wpk:
                continue
            ok, _ = verify_witness_observation(o, wpk)
            if not ok:
                continue
            valid_witnesses.add(o.witness_id)

        if len(valid_witnesses) < WITNESS_QUORUM:
            return NonResponseResult(
                accepted=False, slashed=False,
                reason=(
                    f"after active-set filter, distinct valid witnesses "
                    f"{len(valid_witnesses)} < quorum {WITNESS_QUORUM}"
                ),
            )

        # All gates passed — apply the slash.  Three regimes:
        #
        #   * Pre-Tier-32 (legacy): flat WITNESS_NON_RESPONSE_SLASH_BPS,
        #     drained from `staked` only.  Byte-identical to historical
        #     replay.
        #   * Tier 32 ≤ height < Tier 33: curve-graded severity (so a
        #     long-tenured operator's first transient drop is not slashed
        #     the same as a deliberate silent-drop), still drained from
        #     `staked` only.
        #   * Tier 33+: curve-graded severity, drained proportionally
        #     from `(staked + pending_unstakes)` via
        #     `burn_slash_proportional`.  Closes the censor-then-unstake
        #     evasion — a coerced/colluding validator who silently drops
        #     a witnessed submission and immediately initiates an
        #     unstake cannot ride out the unbonding window with most of
        #     their stake intact.  Mirrors the Tier 31 patch on
        #     `_apply_censorship_slash` / `process_inclusion_list_violation`.
        from messagechain.config import (
            HONESTY_CURVE_NON_RESPONSE_BOGUS_HEIGHT as _T32_H,
            NON_RESPONSE_BOGUS_PENDING_UNSTAKE_HEIGHT as _T33_H,
        )
        use_curve = int(current_height) >= _T32_H
        use_pending_basis = int(current_height) >= _T33_H
        current_stake = blockchain.supply.staked.get(offender_id, 0)
        if use_pending_basis:
            # Tier 33: curve-graded percent against (staked + pending).
            from messagechain.consensus.honesty_curve import (
                OffenseKind, Unambiguity, slashing_severity,
            )
            sev_pct = slashing_severity(
                offender_id,
                OffenseKind.WITNESS_NON_RESPONSE,
                Unambiguity.AMBIGUOUS,
                blockchain,
            )
            if sev_pct > 0:
                slash_amount = blockchain.supply.burn_slash_proportional(
                    offender_id, sev_pct,
                )
            else:
                # Curve amnesty (perfect-record veteran on first
                # offense): no burn, but the evidence is still recorded
                # and the offense counter still bumps so the next
                # incident escalates.
                slash_amount = 0
        elif use_curve:
            slash_amount = _compute_non_response_slash_amount_curve(
                current_stake, offender_id, blockchain,
            )
            if slash_amount > 0:
                blockchain.supply.staked[offender_id] = (
                    current_stake - slash_amount
                )
                blockchain.supply.total_supply -= slash_amount
                blockchain.supply.total_burned += slash_amount
        else:
            slash_amount = compute_non_response_slash_amount(current_stake)
            if slash_amount > 0:
                blockchain.supply.staked[offender_id] = (
                    current_stake - slash_amount
                )
                blockchain.supply.total_supply -= slash_amount
                blockchain.supply.total_burned += slash_amount
        self.processed.add(tx.evidence_hash)
        # Post-fork: bump slash_offense_counts so the next offense
        # escalates via the curve's repeat-multiplier ramp.  Pre-fork
        # the counter is untouched (legacy replay byte-identity).
        # Route through `_bump_slash_offense_count` chokepoint when
        # available so the chaindb mirror tracks the bump (cold
        # restart determinism — see _bump_slash_offense_count
        # docstring).
        if use_curve and hasattr(blockchain, "slash_offense_counts"):
            if hasattr(blockchain, "_bump_slash_offense_count"):
                blockchain._bump_slash_offense_count(offender_id)
            else:
                cur = blockchain.slash_offense_counts.get(offender_id, 0)
                blockchain.slash_offense_counts[offender_id] = cur + 1
        return NonResponseResult(
            accepted=True, slashed=True,
            offender_id=offender_id,
            slash_amount=slash_amount,
            reason="silent-drop slashed",
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
