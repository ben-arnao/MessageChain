"""Honesty-curve slashing — Tier 23.

Replaces Tier 20's flat ``SOFT_SLASH_PCT`` with a per-offender curve
that reads the offender's chain-recorded track record AND the
unambiguity of the evidence.

Anchored CLAUDE.md properties realized here:

  * "Honest operators are insured against accidents."  Severity is
    informed by track record, not just the single offense — a node
    with a long honest run that trips on one block is not punished
    the same as a node that misbehaves repeatedly.

  * "Catastrophic slashes are reserved for unambiguous, intentional
    protocol violations."  Distinct ``state_root`` / ``prev_hash`` /
    large-timestamp-gap headers, attestation double-votes, finality
    double-votes are classified UNAMBIGUOUS and burn 100% on any
    repeat or 50%+ on first offense.

  * "Consensus-determinism is non-negotiable."  Every input the
    severity function reads is chain-derived: ``proposer_sig_counts``,
    ``reputation``, ``slash_offense_counts`` (added in this fork) all
    live on the Blockchain object and are rebuildable from chain
    replay.  No wall-clock, no RNG, no environment.

  * "A node on a minority/unintentional fork must auto-resync without
    accumulating slashable evidence solely from being briefly on the
    wrong tip."  The persistent ``HeightSignGuard`` (sibling module
    ``height_guard``) refuses a same-height re-sign before any
    signature can leak — preserved across crash-restart by the same
    persist-before-sign ratchet ``crypto.keys`` uses for WOTS+
    leaf indexes.

The fork is gated by ``HONESTY_CURVE_HEIGHT``.  Below that height,
``slash_validator`` is called with the legacy ``SLASH_PENALTY_PCT`` /
``SOFT_SLASH_PCT`` from ``get_slash_pct``.  At/above, the calling
sites consult ``slashing_severity`` instead.

Co-design with ``fix/inclusion-list-wiring``: the ``OffenseKind`` enum
exposes ``INCLUSION_LIST_VIOLATION`` so when the inclusion-list
processor branch lands and starts emitting slash evidence for that
offense type, this curve is already the right shape to grade it.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from messagechain.core.block import BlockHeader
    from messagechain.core.blockchain import Blockchain


class OffenseKind(enum.Enum):
    """Slashable offense the curve grades severity for.

    Order is fixed (used for stable repr / debugging only — not for
    consensus).  Adding a new kind is a fork-time decision; never
    rename or renumber existing entries.
    """

    BLOCK_DOUBLE_PROPOSAL = "block_double_proposal"
    ATTESTATION_DOUBLE_VOTE = "attestation_double_vote"
    FINALITY_DOUBLE_VOTE = "finality_double_vote"
    # Reserved for the inclusion-list-wiring branch.  When that branch
    # lands it will pass this kind into slashing_severity for evidence
    # produced by the inclusion-list processor.  No code path on
    # `main` currently emits it; declaring it here lets that branch
    # rebase cleanly without an enum-extension diff.
    INCLUSION_LIST_VIOLATION = "inclusion_list_violation"


class Unambiguity(enum.Enum):
    """How clearly the evidence demonstrates intentional misbehavior.

    AMBIGUOUS: the evidence COULD be explained by a single honest
    crash-restart on commodity hardware.  Today the only AMBIGUOUS
    pattern is two block headers that differ only in ``merkle_root``
    and have ``|timestamp_a - timestamp_b| <= RESTART_DRIFT_SECS`` —
    i.e. the proposer signed a block, partial-propagated it, the
    process crashed, on restart the rebuilt mempool snapshot had
    shifted (different merkle_root) and the wall-clock had moved a
    few seconds (different timestamp).

    UNAMBIGUOUS: anything else.  Different ``state_root`` (proposer
    chose two parallel post-states), different ``prev_hash``
    (proposer chose two different parents), large timestamp gap
    (cannot be a single restart cycle), attestation double-vote (no
    drift field exists in the signable bytes, so two distinct block
    hashes at the same height is intentional), finality double-vote
    (same).
    """

    AMBIGUOUS = "ambiguous"
    UNAMBIGUOUS = "unambiguous"


def classify_block_evidence(
    header_a: "BlockHeader",
    header_b: "BlockHeader",
) -> Unambiguity:
    """Decide if two conflicting headers look like a restart artifact.

    Reads only the headers' bytes — pure function, suitable for
    consensus-deterministic use.  Caller must already have verified
    that both headers carry valid signatures from the offender (this
    function does not re-verify; that happens upstream in
    ``verify_slashing_evidence``).

    Returns AMBIGUOUS iff:
      * same ``proposer_id``
      * same ``block_number``
      * same ``prev_hash``
      * same ``state_root``
      * same ``state_root_checkpoint``
      * timestamps differ by ≤ ``HONESTY_CURVE_RESTART_DRIFT_SECS``
        seconds

    Otherwise UNAMBIGUOUS.  ``merkle_root`` is allowed to differ
    (that's the whole point — the rebuilt mempool snapshot moved).

    Note: ``mempool_snapshot_root`` is retired post-Tier-X and always
    zero on new blocks; no special-case needed.
    """
    from messagechain.config import HONESTY_CURVE_RESTART_DRIFT_SECS

    # Same height/proposer/parent/state — restart-shape requirement.
    # If any of these differ the evidence cannot be a restart artifact
    # of a single honest signing.
    if header_a.proposer_id != header_b.proposer_id:
        return Unambiguity.UNAMBIGUOUS
    if header_a.block_number != header_b.block_number:
        return Unambiguity.UNAMBIGUOUS
    if header_a.prev_hash != header_b.prev_hash:
        return Unambiguity.UNAMBIGUOUS
    if header_a.state_root != header_b.state_root:
        return Unambiguity.UNAMBIGUOUS
    # state_root_checkpoint: zero on non-checkpoint heights, but if a
    # checkpoint heights' two conflicting headers carry different
    # checkpoint values, that is a deliberate fork-choice between two
    # post-states — UNAMBIGUOUS.
    if (
        getattr(header_a, "state_root_checkpoint", b"\x00" * 32)
        != getattr(header_b, "state_root_checkpoint", b"\x00" * 32)
    ):
        return Unambiguity.UNAMBIGUOUS

    # Timestamp drift: |a - b| within tolerance is restart-shape.
    # Use int(...) to match the on-the-wire encoding (the timestamps
    # in signable_data are pack(">Q", int(timestamp))).
    ts_a = int(header_a.timestamp)
    ts_b = int(header_b.timestamp)
    if abs(ts_a - ts_b) > HONESTY_CURVE_RESTART_DRIFT_SECS:
        return Unambiguity.UNAMBIGUOUS

    # Everything else equal, only merkle_root and timestamp drift —
    # canonical restart artifact shape.
    return Unambiguity.AMBIGUOUS


def _track_record(blockchain: "Blockchain", validator_id: bytes) -> int:
    """Weighted count of accepted block proposals + accepted attestations.

    Reads two existing on-chain counters:
      * ``proposer_sig_counts[validator_id]``: maintained by
        ``Blockchain._apply_block_state`` at every accepted block.
      * ``reputation[validator_id]``: maintained by
        ``Blockchain._process_attestations`` at every accepted
        attestation that lands in a finalized chain block.

    Both are derived state — rebuildable from chain replay — and
    already mirrored to chaindb (``proposer_sig_counts`` table,
    ``reputation`` table) so they survive node restart.  No new
    persisted state is introduced.

    Block proposals weigh ``HONESTY_CURVE_BLOCK_WEIGHT`` × an
    attestation: a successful proposal is a stronger correctness
    signal (the proposer authored every byte; an attester only
    voted on someone else's bytes).

    Post-Tier-24 (``HONESTY_CURVE_RATE_HEIGHT``): the raw weighted
    sum is rate-adjusted by subtracting
    ``BAD_PENALTY_WEIGHT × prior_offenses`` and clamping to ≥ 0.
    This implements the good:bad RATE component of the honesty
    curve — long-tenured validators who have also accumulated many
    slashes lose relief proportional to their bad volume, while
    long-tenured validators with clean records keep full relief.
    Pre-activation: byte-for-byte identical to the Tier 23 formula.
    """
    from messagechain.config import (
        HONESTY_CURVE_ATTEST_WEIGHT,
        HONESTY_CURVE_BLOCK_WEIGHT,
        HONESTY_CURVE_RATE_HEIGHT,
        HONESTY_CURVE_BAD_PENALTY_WEIGHT,
    )
    good_blocks = getattr(blockchain, "proposer_sig_counts", {}).get(
        validator_id, 0,
    )
    good_atts = getattr(blockchain, "reputation", {}).get(
        validator_id, 0,
    )
    raw = (
        HONESTY_CURVE_BLOCK_WEIGHT * good_blocks
        + HONESTY_CURVE_ATTEST_WEIGHT * good_atts
    )
    # Tier 24 rate factor.  Read current chain height from the
    # blockchain object — slash application happens at chain tip,
    # so this is the height the severity decision corresponds to.
    # Defensive getattr: tests construct stripped-down Blockchain
    # mocks without a `height` attribute; treat absence as
    # pre-activation (raw value, no rate adjustment).
    current_height = getattr(blockchain, "height", 0)
    if current_height >= HONESTY_CURVE_RATE_HEIGHT:
        priors = getattr(blockchain, "slash_offense_counts", {}).get(
            validator_id, 0,
        )
        raw = max(0, raw - HONESTY_CURVE_BAD_PENALTY_WEIGHT * priors)
    return raw


def _prior_offenses(blockchain: "Blockchain", validator_id: bytes) -> int:
    """Count of slash-applied offenses against this validator on chain.

    Lives in ``Blockchain.slash_offense_counts``, a dict initialized
    in this fork.  Incremented at slash-apply time, mirrored to
    chaindb so it survives restart, and rebuildable from chain
    replay because the slash-tx stream is fully on-chain.
    """
    return getattr(blockchain, "slash_offense_counts", {}).get(
        validator_id, 0,
    )


def slashing_severity(
    validator_id: bytes,
    offense_kind: OffenseKind,
    evidence_unambiguity: Unambiguity,
    blockchain: "Blockchain",
) -> int:
    """Return the slash percentage in [MIN_PCT, 100] for this offense.

    Pure function of (validator_id, offense_kind, unambiguity,
    blockchain state).  Same chain state ⇒ same answer on every
    node — load-bearing for consensus determinism.

    Shape:
      * UNAMBIGUOUS evidence + any prior offense ⇒ 100%.  No
        long-history relief on repeat unambiguous misbehavior — that
        is the deliberate-Byzantine attack pattern.
      * UNAMBIGUOUS evidence + first offense + short tenure ⇒ 100%.
        A fresh validator who immediately produces unambiguous
        double-sign evidence is treated as Byzantine.
      * UNAMBIGUOUS evidence + first offense + long tenure ⇒
        UNAMBIGUOUS_FIRST_PCT (default 50%).  Even a perfect track
        record cannot soften a deliberate violation below half-stake.
      * AMBIGUOUS evidence ⇒ baseline ``AMBIGUOUS_BASE_PCT`` (default
        5%) modulated up by repeat-offense escalation and down by
        honest-history relief, then clamped into [MIN_PCT, 100].

    All knobs live in config.py under ``HONESTY_CURVE_*`` so a future
    fork can retune the numbers without touching this code.
    """
    from messagechain.config import (
        HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
        HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER,
        HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD,
        HONESTY_CURVE_HONEST_TRACK_FLOOR,
        HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
        HONESTY_CURVE_MIN_PCT,
        HONESTY_CURVE_RATE_HEIGHT,
        HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
    )

    track = _track_record(blockchain, validator_id)
    prior = _prior_offenses(blockchain, validator_id)

    # ---- UNAMBIGUOUS path ------------------------------------------
    if evidence_unambiguity is Unambiguity.UNAMBIGUOUS:
        # Any repeat unambiguous offense ⇒ full burn.  No relief.
        if prior >= 1:
            return 100
        # First unambiguous offense — the floor depends on tenure.
        # Fresh validator with no track record: the prior of "could
        # have been coerced once" doesn't apply; treat as deliberate.
        if track < HONESTY_CURVE_HONEST_TRACK_THRESHOLD:
            return 100
        # Established validator on a first unambiguous offense — the
        # UNAMBIGUOUS_FIRST_PCT band, scaling up with prior offenses
        # (which is 0 here — but the formula is uniform).  The
        # scaling factor is the same +10pct-per-prior pattern that
        # produces a smooth ramp from FIRST_PCT toward 100.
        sev = HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT + 10 * prior
        return _clamp_pct(sev, HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT, 100)

    # ---- AMBIGUOUS path --------------------------------------------
    # Tier 24 perfect-record amnesty.  A validator with no priors AND
    # a track_record clearing AMNESTY_TRACK_THRESHOLD gets full pass
    # (severity 0) on AMBIGUOUS (restart-shape) evidence.  This is the
    # "low CHANCE of getting penalized" half of the CLAUDE.md anchor
    # — veterans with a clean record are insured against a single
    # restart-crash incident, not just slashed at a smaller fraction.
    # Single-shot by construction: the slash apply path bumps
    # slash_offense_counts even on a 0-severity outcome, so the next
    # AMBIGUOUS incident sees prior=1 and falls back to the standard
    # (small) severity.  Pre-Tier-24: amnesty does not apply (returns
    # standard severity instead of 0).  UNAMBIGUOUS evidence is never
    # amnestied — the deliberate-Byzantine bar stands.
    current_height = getattr(blockchain, "height", 0)
    if (
        current_height >= HONESTY_CURVE_RATE_HEIGHT
        and prior == 0
        and track >= HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD
    ):
        return 0

    base = HONESTY_CURVE_AMBIGUOUS_BASE_PCT
    # Repeat-offense escalation: linear-in-prior with multiplier
    # weight, so prior=5 at multiplier=2 gives base × 11.  Quick
    # ramp; the global ceiling at 100% bounds it.
    escalation = 1 + HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER * prior

    # Honest-history relief: scales severity DOWN for established
    # operators.  Applied AFTER escalation so a long-history operator
    # who has already piled up offenses still escalates — they just
    # escalate from a lower base.
    if track >= HONESTY_CURVE_HONEST_TRACK_THRESHOLD:
        # relief in (HONEST_TRACK_FLOOR, 1.0]: tiny when track ≫
        # threshold, capped at floor so even a "perfect" operator
        # cannot escape every slash.
        relief = max(
            HONESTY_CURVE_HONEST_TRACK_FLOOR,
            HONESTY_CURVE_HONEST_TRACK_THRESHOLD / track,
        )
    else:
        relief = 1.0  # No relief for under-tenure operators.

    raw = base * escalation * relief
    # Convert to integer percent.  Use int() (truncation toward zero)
    # for byte-stable consensus determinism — every replayer agrees
    # on the same integer.  Floats are deterministic for the
    # operations involved here (multiplications of rationals with
    # bounded magnitudes) but we explicitly clamp+int at the end.
    sev_int = int(raw)
    return _clamp_pct(sev_int, HONESTY_CURVE_MIN_PCT, 100)


def _clamp_pct(v: int, lo: int, hi: int) -> int:
    """Clamp v into [lo, hi].  Inlined helper to keep severity logic flat."""
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v
