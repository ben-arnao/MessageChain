"""Archive-custody duty: primitives for validator-side enforcement.

Iteration 3b-i of the validator-duty archive-reward redesign.  This
module provides the pure-functional primitives the state machine
consumes at epoch close:

    * ActiveValidatorSnapshot  — frozen active-set + K challenge
                                 heights, captured at the challenge
                                 block and persisted until epoch
                                 close.
    * compute_miss_updates()   — given snapshot + every bundle in the
                                 submission window + current miss
                                 state + bootstrap tracking, return
                                 the new miss counts.
    * withhold_pct()            — graduated reward-withhold tier for a
                                  given miss count.
    * is_bootstrap_exempt()     — true iff a validator is still in
                                  their sync-history grace window.

Why these are pure functions:
    State-machine integration (iteration 3b-ii) wires these into
    `Blockchain._apply_block_state` so that:
        * At a challenge block C: build an ActiveValidatorSnapshot
          from the current active validator set and persist it.
        * At block C + ARCHIVE_SUBMISSION_WINDOW: collect all
          ArchiveProofBundles from the intervening window blocks, run
          compute_miss_updates, and fold the result into state.
        * When minting block rewards, read the proposer's
          validator_archive_misses count, call withhold_pct, and
          route that fraction of their reward into the archive
          reward pool instead of crediting it.
    Pure functions are testable in isolation and deterministic across
    nodes — the consensus-critical property we need.

Duty contract (the rule this module encodes):
    A validator in the active_set at challenge block C must submit a
    valid CustodyProof for EACH of the K challenge_heights.  All-or-
    nothing: K-1 proofs is the same as zero proofs.  The union of
    bundles across the submission window is the ground truth; proofs
    may arrive in any order and any block within the window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from messagechain.config import (
    ARCHIVE_BOOTSTRAP_GRACE_BLOCKS,
    ARCHIVE_MAX_MISS_COUNT,
    ARCHIVE_WITHHOLD_TIERS,
)


@dataclass(frozen=True)
class ActiveValidatorSnapshot:
    """Frozen active-set + K challenge heights for one challenge epoch.

    Captured at the challenge block and kept in state until epoch
    close.  Immutable so two nodes computing the epoch outcome from
    the same snapshot always produce the same miss updates —
    consensus-critical.

    Fields:
        challenge_block:    the block height that fired this challenge.
        active_set:         validators subject to duty for this epoch
                            (frozen for determinism).
        challenge_heights:  the K historical heights challenged this
                            epoch.  Same set derived from
                            compute_challenges() at challenge_block.
    """
    challenge_block: int
    active_set: frozenset
    challenge_heights: tuple


def withhold_pct(miss_count: int) -> int:
    """Graduated reward-withhold percentage for the given miss count.

    Reads tiers from ARCHIVE_WITHHOLD_TIERS so governance can retune
    without code changes.  Caller-side usage:
        pct = withhold_pct(validator_archive_misses.get(entity_id, 0))
        withheld = gross_reward * pct // 100
        net_reward = gross_reward - withheld
        archive_reward_pool += withheld

    Raises:
        ValueError: miss_count < 0.  The state machine maintains the
        invariant miss_count >= 0 (decrements floor at 0); a negative
        count here means a bug in the caller, fail loud rather than
        silently saturating.
    """
    if miss_count < 0:
        raise ValueError(
            f"miss_count must be >= 0, got {miss_count} — "
            "state machine should have floored at 0"
        )
    idx = min(miss_count, ARCHIVE_MAX_MISS_COUNT)
    return ARCHIVE_WITHHOLD_TIERS[idx]


def is_bootstrap_exempt(
    *,
    entity_id: bytes,
    current_block: int,
    validator_first_active_block: dict,
) -> bool:
    """True iff `entity_id` is still inside the bootstrap grace window.

    The grace window is `[first_active, first_active + GRACE)` —
    half-open, so a validator whose first_active_block exactly equals
    `current_block - GRACE` is ALREADY past the grace.  Unknown
    validators (not in the map) are treated as brand-new: exempt.
    That's the conservative bias — never penalize an entity the state
    machine doesn't recognize yet.
    """
    first_active = validator_first_active_block.get(entity_id)
    if first_active is None:
        return True
    age = current_block - first_active
    return age < ARCHIVE_BOOTSTRAP_GRACE_BLOCKS


def compute_miss_updates(
    *,
    snapshot: ActiveValidatorSnapshot,
    bundles_in_window: Iterable,
    current_misses: dict,
    current_block: int,
    validator_first_active_block: dict,
) -> dict:
    """Compute the post-epoch-close miss counter state.

    For each validator v in the snapshot's active_set:
        * If bootstrap-exempt: no change (copy through).
        * Else, check whether some bundle in the window contains
          (v, h) for EVERY h in the K challenge_heights.
        * If all K present: decrement miss counter (floor 0).
        * If any missing: increment miss counter.

    Non-active submitters are ignored — duty is a validator-side rule;
    outside submissions are fine and may still earn the open bounty
    reward separately, but don't affect miss state.

    Returns a NEW dict (doesn't mutate `current_misses`).  Absent
    entries are implicitly 0; we only materialize non-zero counts to
    keep state lean, and omit a key rather than storing a 0.

    Inputs:
        snapshot:                         the challenge epoch.
        bundles_in_window:                every ArchiveProofBundle
                                          committed in blocks
                                          [challenge_block,
                                          challenge_block +
                                          ARCHIVE_SUBMISSION_WINDOW).
        current_misses:                   pre-update miss counts.
        current_block:                    for bootstrap-grace check.
        validator_first_active_block:    per-entity first-active block.

    Notes on determinism:
        * Iteration is over `sorted(active_set)` so the output dict's
          content is order-invariant across nodes.
        * `bundles_in_window` is read-only; ordering doesn't affect
          result (we compute set membership, not ordered folding).
    """
    bundles = list(bundles_in_window)

    # Flatten all (entity_id, target_height) credits across bundles.
    # One lookup table rather than re-querying each bundle per
    # (validator, height) — cheaper when K × N is large.
    credited: set[tuple[bytes, int]] = set()
    for bundle in bundles:
        for (eid, height) in bundle.participants:
            credited.add((eid, int(height)))

    heights = tuple(snapshot.challenge_heights)
    new_misses: dict = {}

    # Sort for determinism — frozenset has no guaranteed iteration
    # order across Python builds.
    for eid in sorted(snapshot.active_set):
        if is_bootstrap_exempt(
            entity_id=eid,
            current_block=current_block,
            validator_first_active_block=validator_first_active_block,
        ):
            # Copy through — grace-window validators don't accrue
            # misses and don't earn decrements either (they haven't
            # completed a duty epoch).
            prior = current_misses.get(eid, 0)
            if prior:
                new_misses[eid] = prior
            continue

        fully_credited = all((eid, h) in credited for h in heights)
        prior = current_misses.get(eid, 0)
        if fully_credited:
            # Successful epoch → decrement toward 0.
            new = max(0, prior - 1)
        else:
            # Missed → increment.  No cap on the raw counter; the
            # withhold_pct tier table saturates at 100% for the
            # consumer side.
            new = prior + 1
        if new:
            new_misses[eid] = new
        # new == 0: omit the key entirely (state-lean invariant)

    # Preserve miss entries for validators NOT in this epoch's active
    # set — they dropped out mid-epoch but may rejoin later, and their
    # prior miss count should persist until they have a chance to
    # earn a decrement via a successful submission.  Rotation in/out
    # mid-epoch is common; we don't reset someone's record when they
    # happen to be inactive for one epoch.
    for eid, count in current_misses.items():
        if eid in snapshot.active_set:
            continue  # already handled above
        if count:
            new_misses[eid] = count

    return new_misses
