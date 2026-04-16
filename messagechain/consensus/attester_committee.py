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

# Seed exclusion is a smooth ramp, not a binary cliff.  Seed weight
# is multiplied by `seed_weight_multiplier(progress)` — 0.0 at
# progress=0 (fully excluded), rising linearly to 1.0 at progress=0.5
# (fully rejoined on equal terms), flat 1.0 past the crossover.
#
# Replaces the earlier binary exclusion at progress=0.5.  The cliff
# was user-observable: at progress=0.4999 newcomers had the entire
# pool; at progress=0.5001 seeds abruptly reclaimed their stake-
# weighted share and newcomer earnings halved in one block.  The
# smooth ramp removes that discontinuity without changing the
# crossover point.
SEED_EXCLUSION_CROSSOVER: float = 0.5


def seed_weight_multiplier(bootstrap_progress: float) -> float:
    """Multiplier applied to a seed's attester-committee weight.

    Linear ramp from 0.0 at progress=0 (fully excluded) to 1.0 at
    progress >= SEED_EXCLUSION_CROSSOVER=0.5 (fully rejoined).

    Deterministic and pure — every node computes the same value for
    the same progress, so the consensus path stays byte-identical.
    """
    if bootstrap_progress >= SEED_EXCLUSION_CROSSOVER:
        return 1.0
    return bootstrap_progress / SEED_EXCLUSION_CROSSOVER


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
    """Deterministic weighted sampling without replacement (A-Res).

    Efraimidis-Spirakis weighted reservoir sampling, made deterministic
    by seeding the per-item "uniform" from (randomness || item) rather
    than drawing live randomness.  Every node computes the same keys
    for the same inputs, so the committee is consensus-safe.

    Algorithm: key_i = u_i^(1/w_i), select TOP-k by key.  Larger
    weights push keys closer to 1; lighter items cluster near 0.
    Selecting the k largest keys yields weighted sampling without
    replacement — heavy items win proportionally more often.

    Works in log-space to avoid precision issues: log(key_i) =
    log(u_i) / w_i.  Since log(u_i) < 0 and w_i > 0, log-keys are
    all negative; heaviest items have log-keys closest to 0 (least
    negative), so we take the top-k by descending order.

    Zero-weight items get log-key = -inf — selected only when there
    are fewer than k eligible items to fill.
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
        if w <= 0:
            # Zero-weight items go last.  log-key = -inf pushes them
            # below every positive-weight item in descending order.
            pri = float("-inf")
        else:
            import math
            pri = math.log(u) / w  # heavier items → closer to 0 → larger
        priorities.append((pri, item))

    # Take top-k: sort descending by priority, tiebreak ascending by
    # item bytes so ties resolve deterministically.
    priorities.sort(key=lambda p: (-p[0], p[1]))
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
            Blockchain.seed_entity_ids).  Their committee weight is
            tilted by seed_weight_multiplier(progress): fully excluded
            at progress=0, fully rejoined at progress>=0.5, smoothly
            ramped in between.
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

    if not candidates:
        return []

    # Seed exclusion: tilt seed weights by seed_weight_multiplier(progress)
    # rather than a binary drop.  At progress=0 the multiplier is 0 so
    # seeds are effectively excluded; by progress>=0.5 it's 1.0 so
    # seeds fully rejoin.  Smooth in between.
    mult = seed_weight_multiplier(bootstrap_progress)
    items: list[bytes] = []
    stakes: list[int] = []
    tilt: list[float] = []
    for eid, stake in candidates:
        items.append(eid)
        stakes.append(stake)
        tilt.append(mult if eid in seed_entity_ids else 1.0)

    # If the effective pool (after tilt) has fewer distinct candidates
    # than committee_size, just return everyone with a positive tilt.
    effective_pool_size = sum(1 for t in tilt if t > 0.0)
    if effective_pool_size <= committee_size:
        return sorted(
            eid for eid, t in zip(items, tilt) if t > 0.0
        )

    base_weights = weights_for_progress(stakes, bootstrap_progress)
    weights = [w * t for w, t in zip(base_weights, tilt)]
    picked = _deterministic_weighted_sample(
        items, weights, committee_size, randomness,
    )
    return sorted(picked)
