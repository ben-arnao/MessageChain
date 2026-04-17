"""
Inactivity leak — Casper-style defense against PoS liveness attacks.

Problem: a 40% malicious stake coalition can halt the chain permanently.
Forced-inclusion uses soft attester veto (2/3 threshold). If 40% of stake
stays silent (doesn't attest), honest 60% can't reach 2/3 finality.  Chain
halts.  No slashing triggers because slashing requires finalization.  No
recovery path exists.

Solution: if finalization stalls for more than
INACTIVITY_LEAK_ACTIVATION_THRESHOLD blocks, enter "leak mode".  During
leak mode, every block penalizes each validator who was expected to attest
but didn't.  The penalty grows quadratically with the number of blocks
since last finalization:

    penalty = base_penalty * (blocks_since_finality ** 2)
              / INACTIVITY_PENALTY_QUOTIENT

Quadratic scaling is critical:
- Early in a stall, penalties are tiny (accidental downtime).
- As the stall persists, penalties grow quadratically — a genuine 40%
  cartel bleeds stake rapidly until honest validators hold 2/3.

Leaked stake is BURNED (not redistributed) to prevent perverse incentives.

Once finalization resumes (honest stake reaches 2/3 after cartel's stake
drains), leak mode deactivates and penalties stop immediately.
"""

from messagechain.config import (
    INACTIVITY_LEAK_ACTIVATION_THRESHOLD,
    INACTIVITY_PENALTY_QUOTIENT,
    INACTIVITY_BASE_PENALTY,
)


def is_leak_active(blocks_since_last_finalization: int) -> bool:
    """Return True if the chain is in inactivity leak mode.

    Leak activates when finalization has stalled for more than
    INACTIVITY_LEAK_ACTIVATION_THRESHOLD blocks.
    """
    return blocks_since_last_finalization > INACTIVITY_LEAK_ACTIVATION_THRESHOLD


def compute_inactivity_penalty(
    blocks_since_finality: int,
    validator_stake: int,
) -> int:
    """Compute the inactivity penalty for one non-attesting validator.

    The penalty is quadratic in blocks_since_finality:
        penalty = base_penalty * blocks_since_finality^2 / quotient

    The result is capped at the validator's current stake (can't go
    negative).  Returns 0 when not in leak mode or when the penalty
    rounds to 0 (early blocks of a stall).
    """
    if blocks_since_finality <= INACTIVITY_LEAK_ACTIVATION_THRESHOLD:
        return 0
    if validator_stake <= 0:
        return 0

    penalty = (
        INACTIVITY_BASE_PENALTY
        * blocks_since_finality
        * blocks_since_finality
        // INACTIVITY_PENALTY_QUOTIENT
    )
    # Cap at current stake — can't drain below 0.
    return min(penalty, validator_stake)


def get_inactive_validators(
    expected_attesters: set[bytes],
    actual_attesters: set[bytes],
) -> set[bytes]:
    """Return the set of validators who were expected to attest but didn't.

    expected_attesters: all validators in the active set (with stake > 0)
    actual_attesters:   validators whose attestations were included in
                        this block
    """
    return expected_attesters - actual_attesters


def apply_inactivity_leak(
    staked: dict[bytes, int],
    blocks_since_finality: int,
    inactive_validators: set[bytes],
    min_stake: int = 0,
) -> tuple[int, set[bytes]]:
    """Apply inactivity penalties to inactive validators.

    Mutates `staked` in place.  Burns stake (reduces values) for each
    inactive validator.  Does NOT apply penalties to validators already
    below min_stake — they should be deactivated instead.

    Returns:
        (total_burned, deactivated) — total tokens burned and the set
        of validators whose stake dropped to or below min_stake.
    """
    total_burned = 0
    deactivated: set[bytes] = set()

    for vid in inactive_validators:
        current_stake = staked.get(vid, 0)
        if current_stake <= 0:
            continue
        # Don't penalize validators already at or below min_stake
        if current_stake <= min_stake:
            continue

        penalty = compute_inactivity_penalty(
            blocks_since_finality, current_stake,
        )
        if penalty <= 0:
            continue

        # Apply penalty — floor at 0
        new_stake = max(0, current_stake - penalty)
        staked[vid] = new_stake
        actual_penalty = current_stake - new_stake
        total_burned += actual_penalty

        # Check if validator should be deactivated
        if new_stake <= min_stake:
            deactivated.add(vid)

    return total_burned, deactivated
