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
from decimal import Decimal, localcontext

from messagechain.config import HASH_ALGO
from messagechain.crypto.hashing import default_hash


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


def effective_weight(stake: int, block_height: int | None = None) -> int:
    """Stake-concentration soft-cap curve — the single chokepoint every
    place that maps stake → selection weight must route through.

    Pre-Tier-70 (``block_height`` is ``None`` or below
    ``STAKE_CONCENTRATION_SOFT_CAP_HEIGHT``):
        identity — ``effective_weight(s) == s``.  Byte-identical to
        legacy behavior, so historical blocks replay correctly.

    Post-Tier-70:
        rational form with asymptotic soft cap C:

            effective_weight(s) = s * C / (s + C)

        where C = ``STAKE_CONCENTRATION_SOFT_CAP`` = 1_000_000 tokens.

        Properties (matching CLAUDE.md "Stake concentration is softly
        capped via diminishing returns" anchor exactly):

          * monotonically increasing in s — whale's absolute reward still
            grows when adding stake (24/7 honest operation always preferred
            over withdrawal)
          * per-unit yield w(s)/s = C/(s+C) is monotonically DECREASING
            in s — smaller validators earn at a strictly higher per-unit
            rate than larger ones (anchor's load-bearing property)
          * asymptote: w(s) → C as s → ∞ — anchor's "asymptotic soft cap"
          * no hard cap: w(s) < C always
          * concave; second derivative everywhere negative
          * at s ≪ C: w(s) ≈ s — small stakers see no curve bite
          * at s ≫ C: w(s) ≈ C - C²/s — whales see strongly diminishing
            returns

    Integer-only arithmetic: returns ``(stake * C) // (stake + C)``.
    Down-rounding is consensus-safe (every node computes the same int)
    and the truncation is at most 1 unit of weight per call.

    Active call sites (every consensus path that turns stake into a
    selection weight):

      * ``weights_for_progress`` — attester-committee blend at
        ``progress=1`` becomes effective_weight-based, not raw-stake-based
      * ``select_proposer_vrf`` (consensus/vrf.py) — the active proposer-
        selection path
      * ``Blockchain._selected_proposer_for_slot`` fallback branch — the
        pre-VRF / very-early-chain proposer-selection path

    A new caller MUST route through this helper.  Reading raw stake into
    a weighted sampler post-Tier-70 reintroduces the linear regime and
    diverges state_root across peers that did vs. didn't apply the curve.
    """
    if stake <= 0:
        return 0
    # config import is deferred to function body so module import-time
    # is not coupled to the (large) config module.
    from messagechain.config import (
        STAKE_CONCENTRATION_SOFT_CAP,
        STAKE_CONCENTRATION_SOFT_CAP_HEIGHT,
    )
    if block_height is None or block_height < STAKE_CONCENTRATION_SOFT_CAP_HEIGHT:
        return stake
    C = STAKE_CONCENTRATION_SOFT_CAP
    return (stake * C) // (stake + C)


def weights_for_progress(
    stakes: list[int], bootstrap_progress: float,
    block_height: int | None = None,
) -> list[float]:
    """Compute per-candidate selection weights at a given bootstrap progress.

    Linear blend between uniform weighting (1/N for all) and
    stake-weighted:

        weight_i = (1 - p) * uniform_unit + p * effective_weight(stake_i)

    where ``effective_weight`` applies the Tier 70 stake-concentration
    soft cap at block heights ≥ ``STAKE_CONCENTRATION_SOFT_CAP_HEIGHT``
    and is the identity below.  At p=0 the blend degenerates to uniform;
    at p=1 to pure (effective-weight-weighted) stake selection.

    Both halves of the blend use the same scale (effective weights), so
    the uniform / stake-weighted mix stays well-formed across the fork.

    Returns raw weights (not normalized) — caller feeds them to a
    weighted sampler.

    ``block_height`` defaults to ``None`` for back-compat with tests and
    tooling that don't model the height gate; consensus call sites in
    ``select_attester_committee`` MUST pass ``block_height=`` so the
    Tier 70 fork actually activates at the configured height.
    """
    if not stakes:
        return []
    if not (0.0 <= bootstrap_progress <= 1.0):
        raise ValueError(
            f"bootstrap_progress must be in [0, 1], got {bootstrap_progress}"
        )

    n = len(stakes)
    # Apply Tier 70 stake-concentration soft cap.  Pre-fork this is the
    # identity, so all existing tests and historical blocks see the
    # original raw-stake blend.  Post-fork the weights are bounded by
    # the rational soft-cap curve described in ``effective_weight``.
    effective_stakes = [effective_weight(s, block_height) for s in stakes]
    total = sum(effective_stakes)

    # Uniform component: 1/N for all, scaled by total so both halves of
    # the blend live on the same scale.  Pre-fork ``total`` equals
    # ``sum(stakes)`` (effective is identity); post-fork it equals the
    # sum of effective weights.  Either way the math composes cleanly.
    if total <= 0:
        # All zero stakes — pure uniform is the only sensible output.
        return [1.0] * n

    uniform_unit = total / n
    weights = [
        (1.0 - bootstrap_progress) * uniform_unit
        + bootstrap_progress * eff_stake
        for eff_stake in effective_stakes
    ]
    return weights


def _deterministic_weighted_sample_legacy_float(
    items: list[bytes],
    weights: list[float],
    k: int,
    randomness: bytes,
) -> list[bytes]:
    """Pre-Tier-67 attester-committee sampler -- legacy float-cast A-Res.

    Kept byte-identical to the pre-fix implementation so historical
    blocks (height < ``ATTESTER_COMMITTEE_DECIMAL_HEIGHT``) replay
    byte-for-byte post-upgrade.

    Cross-platform hazard: priorities are computed as Decimal but
    immediately collapsed back to ``float`` before the sort key.
    Two near-equal log-keys can rank-flip on different libc /
    different CPython builds.  Tier 67 keeps the priority as Decimal
    end-to-end, eliminating the hazard.  Same shape as Tier 62 for
    the lottery.
    """
    if k >= len(items):
        # All items selected regardless of weight; still sort for
        # determinism.
        return sorted(items)

    priorities: list[tuple[float, bytes]] = []
    with localcontext() as ctx:
        ctx.prec = 40
        for item, w in zip(items, weights):
            h = default_hash(randomness + item)
            # Convert hash to a value in (0, 1] — avoid 0 for log-domain safety.
            hash_int = int.from_bytes(h[:8], "big") + 1
            if w <= 0:
                # Zero-weight items go last.  log-key = -inf pushes them
                # below every positive-weight item in descending order.
                pri = float("-inf")
            else:
                # Pre-Tier-67: Decimal.ln eliminates the libm hazard,
                # but the float cast at the sort key reintroduces the
                # IEEE-754 ULP rank-flip risk.  Tier 67 drops the
                # cast.
                u = Decimal(hash_int) / Decimal(2**64)
                pri = float(u.ln() / Decimal(w))
            priorities.append((pri, item))

    # Take top-k: sort descending by priority, tiebreak ascending by
    # item bytes so ties resolve deterministically.
    priorities.sort(key=lambda p: (-p[0], p[1]))
    return [item for _, item in priorities[:k]]


def _deterministic_weighted_sample_decimal(
    items: list[bytes],
    weights: list[float],
    k: int,
    randomness: bytes,
) -> list[bytes]:
    """Post-Tier-67 attester-committee sampler -- Decimal end-to-end.

    Same A-Res algorithm shape as the legacy path (Efraimidis-
    Spirakis weighted reservoir sampling, log-key = ln(u_i) / w_i,
    seeded from hash(randomness || item)) but the per-candidate
    priority stays as ``decimal.Decimal`` end-to-end and the sort
    compares Decimals directly.  Decimal compare is exact, so
    near-equal log-keys cannot rank-flip on cross-platform IEEE-754
    rounding -- the consensus-split hazard the legacy float-cast
    introduces is closed.

    Mirrors the pattern ``select_lottery_winner`` adopted in Tier 62
    for the same reason.
    """
    if k >= len(items):
        return sorted(items)

    # Use a Decimal sentinel for zero-weight items so the comparator
    # remains a single homogeneous Decimal sort.  ``Decimal('-Inf')``
    # is exact and below every finite Decimal.
    NEG_INF = Decimal("-Infinity")

    priorities: list[tuple[Decimal, bytes]] = []
    with localcontext() as ctx:
        ctx.prec = 40
        denom = Decimal(2**64)
        for item, w in zip(items, weights):
            h = default_hash(randomness + item)
            hash_int = int.from_bytes(h[:8], "big") + 1
            if w <= 0:
                pri: Decimal = NEG_INF
            else:
                u = Decimal(hash_int) / denom
                pri = u.ln() / Decimal(w)
            priorities.append((pri, item))

    # Decimal supports exact comparison; sort descending by priority,
    # tiebreak ascending by item bytes.  No float collapse anywhere
    # on the sort-key path -- this is what Tier 67 closes.
    priorities.sort(key=lambda p: (-p[0], p[1]))
    return [item for _, item in priorities[:k]]


def _deterministic_weighted_sample(
    items: list[bytes],
    weights: list[float],
    k: int,
    randomness: bytes,
    block_height: int | None = None,
) -> list[bytes]:
    """Height-gated dispatcher between the legacy float-cast branch
    (pre-Tier-67) and the Decimal end-to-end branch (post-Tier-67).

    ``block_height=None`` routes to the legacy branch, preserving
    back-compat for tests and tooling that don't model the height
    gate.  Consensus call sites in ``core/blockchain.py`` MUST pass
    ``block_height=`` so the Tier 67 fork actually activates at the
    configured height.
    """
    if block_height is not None:
        from messagechain.config import ATTESTER_COMMITTEE_DECIMAL_HEIGHT
        if block_height >= ATTESTER_COMMITTEE_DECIMAL_HEIGHT:
            return _deterministic_weighted_sample_decimal(
                items, weights, k, randomness,
            )
    return _deterministic_weighted_sample_legacy_float(
        items, weights, k, randomness,
    )


def select_attester_committee(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    bootstrap_progress: float,
    randomness: bytes,
    committee_size: int,
    block_height: int | None = None,
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
        block_height: the block whose committee is being selected.
            Selects the legacy float-cast backend (pre-Tier-67) or
            the Decimal end-to-end backend (post-Tier-67).  ``None``
            routes to legacy, preserving back-compat for tests and
            tooling that don't model the height gate.  Consensus
            call sites in ``core/blockchain.py`` MUST pass it.

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

    base_weights = weights_for_progress(
        stakes, bootstrap_progress, block_height=block_height,
    )
    weights = [w * t for w, t in zip(base_weights, tilt)]
    picked = _deterministic_weighted_sample(
        items, weights, committee_size, randomness,
        block_height=block_height,
    )
    return sorted(picked)
