"""Attester committee selection for block rewards.

Instead of every attester sharing the 12-token pool pro-rata by stake
(which pays a 1-token newcomer effectively nothing), a fixed-size
committee is selected per block: up to K attesters, each earning
exactly 1 token.  Unfilled slots (fewer attesters than K) send the
excess tokens to the treasury.

Selection blends uniform and stake-weighted random according to
`bootstrap_progress`:

  * progress = 0.0 → pure uniform (newcomer with 1 token has same
    selection probability as founder with 1M tokens)
  * progress = 1.0 → pure stake-weighted (matches "normal PoS")
  * in between → linear blend

During the first half of bootstrap (progress < 0.5) seeds are
excluded entirely from the committee — they already dominate
proposer rewards via stake-weighted proposer selection, so reserving
the attester pool accelerates external stake accumulation.

Selection is deterministic given `randomness` (the block hash is a
natural source) so every node agrees on the same committee for any
given block.  No consensus protocol change required — this is a
reward-layer mechanism on top of the existing attestation flow.
"""

from __future__ import annotations

import hashlib

from messagechain.config import HASH_ALGO


# Each committee slot pays exactly this many tokens.  Must be integer.
ATTESTER_REWARD_PER_SLOT: int = 1

# Below this bootstrap_progress value, seeds are excluded from the
# attester committee.  Picked at 0.5 (midpoint) so the gradient
# transitions smoothly: first half = pure newcomer faucet, second
# half = everyone competes.
SEED_EXCLUSION_THRESHOLD: float = 0.5


def weights_for_progress(
    stakes: list[int], bootstrap_progress: float,
) -> list[float]:
    """Compute per-candidate selection weights at a given bootstrap progress.

    Linear blend between uniform weighting (1/N for all) and
    stake-weighted (stake_i / total_stake):

        weight_i = (1 - p) * (1/N) + p * (stake_i / total_stake)

    At p=0 this degenerates to uniform; at p=1 to pure stake-weighted.
    In between, small stakers retain meaningful selection probability
    while larger stakers enjoy graduated advantage.

    Returns raw weights (not normalized) — caller feeds them to a
    weighted sampler.
    """
    if not stakes:
        return []
    if not (0.0 <= bootstrap_progress <= 1.0):
        raise ValueError(
            f"bootstrap_progress must be in [0, 1], got {bootstrap_progress}"
        )

    n = len(stakes)
    total_stake = sum(stakes)

    # Uniform component: 1/N for all (scale by total_stake so both
    # components live on the same scale and blend cleanly).
    if total_stake <= 0:
        # All zero stakes — pure uniform is the only sensible output.
        return [1.0] * n

    uniform_unit = total_stake / n  # each gets this "virtual stake" under uniform
    weights = [
        (1.0 - bootstrap_progress) * uniform_unit
        + bootstrap_progress * stake
        for stake in stakes
    ]
    return weights


def _deterministic_weighted_sample(
    items: list[bytes],
    weights: list[float],
    k: int,
    randomness: bytes,
) -> list[bytes]:
    """Deterministic weighted sampling without replacement.

    Uses the efficient "A-Res"-style algorithm adapted for a seeded
    PRNG: for each item, compute a priority key derived from the
    (randomness, item) hash modulated by its weight.  Higher priority
    wins.  With identical inputs, every node arrives at the same k
    items in the same order, which is what consensus needs.

    Priority = hash(randomness || item) / 2^256, scaled by 1/weight
    (smaller = higher priority, since smaller random values among
    heavier items are likelier under the scaling).
    """
    if k >= len(items):
        # All items selected regardless of weight; still sort for
        # determinism.
        return sorted(items)

    priorities: list[tuple[float, bytes]] = []
    for item, w in zip(items, weights):
        h = hashlib.new(HASH_ALGO, randomness + item).digest()
        # Convert hash to a float in (0, 1] — avoid 0 for log-domain safety.
        u = (int.from_bytes(h[:8], "big") + 1) / (2**64)
        # Use exponent 1/w so heavier items produce smaller priorities
        # on average (and are thus more likely to be in the top-k).
        # Mathematically: priority = u ^ (1 / w).  Take log to avoid
        # floating-point issues for extreme weights.
        if w <= 0:
            # Zero-weight items are last-resort; push priority to +inf.
            pri = float("inf")
        else:
            import math
            pri = math.log(u) / w  # higher w → closer to 0, wins more often
        priorities.append((pri, item))

    # Lowest k priorities win.
    priorities.sort(key=lambda p: (p[0], p[1]))
    return [item for _, item in priorities[:k]]


def select_attester_committee(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    bootstrap_progress: float,
    randomness: bytes,
    committee_size: int,
) -> list[bytes]:
    """Select up to `committee_size` attesters to reward for one block.

    Arguments:
        candidates: list of (entity_id, stake) tuples — everyone whose
            attestation was included in the block.
        seed_entity_ids: the pinned genesis-seed set (see
            Blockchain.seed_entity_ids).  These are excluded from the
            committee when bootstrap_progress < SEED_EXCLUSION_THRESHOLD.
        bootstrap_progress: value in [0, 1] from Blockchain.bootstrap_progress.
            Drives both the seed-exclusion rule and the blend between
            uniform and stake-weighted selection.
        randomness: deterministic seed (typically the block hash).
            Must be byte-for-byte identical on every node to ensure
            consensus agreement.
        committee_size: maximum K to select.  Callers typically set
            this to the attester_pool token count (so each slot pays
            ATTESTER_REWARD_PER_SLOT = 1 token).

    Returns a list of entity_ids, sorted canonically.  Length is
    min(len(eligible_candidates), committee_size).
    """
    if committee_size <= 0:
        return []

    # Apply seed exclusion
    if bootstrap_progress < SEED_EXCLUSION_THRESHOLD:
        pool = [(eid, stake) for eid, stake in candidates
                if eid not in seed_entity_ids]
    else:
        pool = list(candidates)

    if not pool:
        return []

    items = [eid for eid, _ in pool]
    stakes = [stake for _, stake in pool]

    if len(items) <= committee_size:
        return sorted(items)

    weights = weights_for_progress(stakes, bootstrap_progress)
    picked = _deterministic_weighted_sample(
        items, weights, committee_size, randomness,
    )
    return sorted(picked)
