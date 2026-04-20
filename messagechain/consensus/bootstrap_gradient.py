"""Bootstrap gradient: a single monotonic value in [0, 1] driving the
free-entry → mature-PoS transition.

Rather than a binary "bootstrap mode" flag that flips at some threshold,
the protocol transitions smoothly along a gradient.  Downstream code
(attester committee selection, min-stake gates, escrow window sizing,
seed-exclusion rules) reads ONE value — `bootstrap_progress` — and
derives its behavior as a function of it.

Design goals:
  * Monotonic: once a peak is observed, the protocol cannot slide back
    to an earlier, more permissive regime.  Sliding back would let
    adversaries grief new validators (e.g. by unstaking to briefly
    trigger "no min-stake" registration windows).
  * Two independent drivers:
      - Time (height / BOOTSTRAP_END_HEIGHT)        — naturally monotonic
      - Stake decentralization (non_seed / total)  — ratcheted in memory
    The max of the two wins; time provides a hard upper bound so
    bootstrap can't persist forever even in pathological cases.
  * Pure arithmetic; no consensus hooks here.  Blockchain wraps this
    module for the ratchet + stake accounting.

This file is stage 1 scaffolding — it computes the value but nothing
yet consumes it.  Later stages wire `bootstrap_progress` into:
    * attester committee selection              (uniform → stake-weighted)
    * min_stake_required at registration        (0 → MIN_STAKE_PRODUCTION)
    * attester-reward escrow window             (90 days → 0 days)
    * seed exclusion from attester committee    (TRUE → FALSE at 0.5)
"""

from __future__ import annotations


# ~2 years at BLOCK_TIME_TARGET=600s (52,596 blocks/year × 2).
# Rationale (see README / design doc): 1.2y is the economic gravity
# point for non-seed stake to collectively match seed stake at the
# current attester-pool rate; 2y gives 67% buffer above that and
# clears the 90-day escrow window with 9 months of real liquid
# earning runway.
BOOTSTRAP_END_HEIGHT: int = 105_192


def compute_bootstrap_progress(
    *,
    height: int,
    seed_stake: int,
    non_seed_stake: int,
) -> float:
    """Compute the raw bootstrap-progress value for a given chain snapshot.

    Returns a float in [0, 1].  Caller is responsible for ratcheting
    (clamping to the max ever observed) — this function is pure.

    Two components:
      - height component: min(1, height / BOOTSTRAP_END_HEIGHT)
      - stake component:  non_seed_stake / (seed_stake + non_seed_stake)

    Result is max(height, stake).

    Structural note on the stake component: under the recommended launch
    allocation in `messagechain/core/bootstrap.py` the seed stakes 99M
    tokens (~9.9% of supply), while total non-seed stake during the
    bootstrap window is capped by mint issuance at ~1.68M tokens (16
    reward floor × 105,192 blocks ≈ 2M tokens even if 100% is captured
    and immediately staked).  That pins the stake component at roughly
    2M / (99M + 2M) ≈ 2% for the entire bootstrap window — nowhere near
    the 1.0 needed to end bootstrap early.  The `max()` is therefore
    cosmetic under the recommended topology: progress is effectively
    `height / BOOTSTRAP_END_HEIGHT`.  The stake term is retained so
    alternative launch topologies (smaller seed stake, or later
    post-bootstrap re-use of the formula) still get the decentralization
    floor, and so the invariant "bootstrap cannot persist forever even
    if height stalls" holds independent of economic assumptions.

    Edge cases:
      - zero total stake → stake component is 0 (not undefined).  This
        matches the "we just launched and nobody has staked anything
        above the seed allocation" state at t=0.
    """
    if height < 0:
        raise ValueError(f"height must be non-negative, got {height}")
    if seed_stake < 0 or non_seed_stake < 0:
        raise ValueError(
            f"stake must be non-negative, got seed={seed_stake}, "
            f"non_seed={non_seed_stake}"
        )

    height_component = min(1.0, height / BOOTSTRAP_END_HEIGHT)

    total = seed_stake + non_seed_stake
    stake_component = (non_seed_stake / total) if total > 0 else 0.0

    return max(height_component, stake_component)


def min_stake_for_progress(
    bootstrap_progress: float,
    *,
    full_min_stake: int,
) -> int:
    """Minimum stake required to register as a validator, by progress.

    Formula: `full_min_stake * bootstrap_progress` (pure linear).

    At progress = 0.0 the minimum is 0 — honest newcomers with no tokens
    can register for free at genesis and start earning via the attester
    committee.  As bootstrap matures, the barrier rises smoothly (no
    knee, no cliff) toward `full_min_stake` at progress = 1.0, at which
    point normal PoS economics apply.

    The earlier design had a knee at progress=0.5 (zero below, linear
    above).  The knee was removed for smoother ramping — a progressive
    barrier that rises monotonically from block 0 gives a cleaner
    signal ("the longer you wait, the more you must stake") than a
    piecewise step function.  Zero-funds registration still works at
    launch; it only gets progressively stricter over the window.

    `full_min_stake` is normally `config.VALIDATOR_MIN_STAKE`.  Passed
    as a kwarg so the formula is testable in isolation without
    importing the full config.

    Returns an integer (token count), floor-rounded.
    """
    if not (0.0 <= bootstrap_progress <= 1.0):
        raise ValueError(
            f"bootstrap_progress must be in [0, 1], got {bootstrap_progress}"
        )
    if full_min_stake < 0:
        raise ValueError(f"full_min_stake must be >= 0, got {full_min_stake}")

    return int(full_min_stake * bootstrap_progress)


def escrow_blocks_for_progress(
    bootstrap_progress: float,
    *,
    max_escrow_blocks: int,
) -> int:
    """Attester-reward escrow window length as a function of progress.

    Linear from `max_escrow_blocks` at progress=0 to 0 at progress=1.
    Rewards earned during bootstrap sit in escrow — slashable if the
    validator misbehaves — and unlock after this many blocks.

    At progress=1.0 the escrow collapses to zero: rewards credit
    straight to balance, matching normal post-bootstrap behavior.

    `max_escrow_blocks` is typically `ATTESTER_ESCROW_BLOCKS` from
    config (12,960 blocks = 90 days at 600s).
    """
    if not (0.0 <= bootstrap_progress <= 1.0):
        raise ValueError(
            f"bootstrap_progress must be in [0, 1], got {bootstrap_progress}"
        )
    if max_escrow_blocks < 0:
        raise ValueError(
            f"max_escrow_blocks must be >= 0, got {max_escrow_blocks}"
        )
    return int(max_escrow_blocks * (1.0 - bootstrap_progress))


class RatchetState:
    """In-memory monotonic accumulator for bootstrap_progress.

    Stores the max value ever observed.  `observe(v)` is idempotent and
    never regresses the stored value.  On restart this is seeded from
    current chain state (height + stake ratio) — any historical peak
    higher than the current value is lost, but this is safe because:

      (a) The height component is always monotonic from the chain,
          so the floor can only rise with time.
      (b) A "peak loss" scenario requires a restart AND a stake ratio
          that is currently lower than it historically was.  In that
          regime, legitimate decentralization has regressed (through
          slashing or unstaking), which is itself a signal that trust
          has weakened — allowing a slight parameter reset is arguably
          the right behavior, not a bug.

    A fully persistent ratchet (committed through the state root) is
    future work.  For now, the height floor is sufficient durability.
    """

    def __init__(self) -> None:
        self._max: float = 0.0

    @property
    def max_progress(self) -> float:
        return self._max

    def observe(self, value: float) -> float:
        """Record a new observation; return the current (post-ratchet) max."""
        if not (0.0 <= value <= 1.0):
            raise ValueError(f"bootstrap_progress must be in [0, 1], got {value}")
        if value > self._max:
            self._max = value
        return self._max
