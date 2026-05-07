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

Coverage-divergence leak (companion mechanism)
==============================================

The finalization-based leak above defends liveness only.  A 1/3 cartel
that ATTESTS to blocks (so the chain finalizes) but selectively
withholds its `AttesterMempoolReport` for targeted txs can defeat the
inclusion-list censorship-resistance lever — no inclusion list ever
forms for the censored txs, the proposer-side slashing path never
engages, and the finalization-based leak doesn't fire because finality
keeps ticking.

`compute_coverage_penalty` + `apply_coverage_leak` handle this
asymmetric attack.  When an inclusion list forms (which by definition
means 2/3+ of stake reported the listed txs), every active-set
attester whose reports lacked any listed tx has their per-attester
`coverage_misses` counter incremented; an attester whose reports
covered every listed tx resets to zero.  Penalties are quadratic in
the consecutive-miss count and scale with the validator's current
stake — so withholding cartels bleed proportionally and quickly fall
below the threshold where their withholding matters.

The activation buffer (COVERAGE_LEAK_ACTIVATION_MISSES) gives honest
gossip-divergent validators slack: 1-3 isolated misses are free.
False-positive defense rests primarily on the 2/3-quorum threshold of
the inclusion-list mechanism itself (the leak only fires for txs that
provably WERE in 2/3+ of mempools).
"""

from messagechain.config import (
    INACTIVITY_LEAK_ACTIVATION_THRESHOLD,
    INACTIVITY_PENALTY_QUOTIENT,
    INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT,
    INACTIVITY_BASE_PENALTY,
    COVERAGE_LEAK_BASE_PENALTY,
    COVERAGE_LEAK_QUOTIENT,
    COVERAGE_LEAK_ACTIVATION_MISSES,
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
    *,
    current_height: int | None = None,
) -> int:
    """Compute the inactivity penalty for one non-attesting validator.

    Two formulae, height-gated by Tier 59
    (``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT``):

      Pre-fork (``current_height`` is None or below
      ``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT``) -- LEGACY FLAT shape::

          penalty = base_penalty * blocks_since_finality^2 / quotient

      ``validator_stake`` is used only as a cap.  Byte-identical to
      the historical formula -- replay determinism on every in-leak
      historical block depends on this branch.

      Post-fork (``current_height >=
      INACTIVITY_LEAK_STAKE_SCALED_HEIGHT``) -- STAKE-SCALED shape::

          penalty = stake * base * blocks_since_finality^2 / QUOTIENT

      Mirrors ``compute_coverage_penalty`` exactly.  Restores the
      "fractional of stake, not flat tokens" property the CLAUDE.md
      honest-operator-insurance anchor calls for: a small validator
      and a whale on the same partition pay the SAME FRACTION of
      stake; in absolute tokens the whale's drain is much larger.

    The Tier-55 honesty-curve relief multiplier (applied in
    ``apply_inactivity_leak``) wraps either shape unchanged -- it
    multiplies whatever nominal this function produces.

    The result is capped at the validator's current stake (can't go
    negative).  Returns 0 when not in leak mode, when the validator
    has no stake, or when the penalty rounds to 0.
    """
    if blocks_since_finality <= INACTIVITY_LEAK_ACTIVATION_THRESHOLD:
        return 0
    if validator_stake <= 0:
        return 0

    # Tier 59 / Tier 61 height gates: pre-Tier-59 uses the flat
    # legacy formula byte-identically; Tier 59 stake-scales nominal
    # but integer-truncates at the per-block level for stake<1M;
    # Tier 61 switches to the cumulative-floor difference so the
    # ~2% target holds for every stake size.  Caller threads
    # ``current_height`` from the apply path; legacy callers
    # (None) get the pre-Tier-59 behavior.
    from messagechain.config import (
        INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT,
        INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
    )
    if (
        current_height is not None
        and current_height >= INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT
    ):
        # Tier 61: cumulative-floor difference.  Per-block integer
        # truncation moves to the cumulative level, where it rounds
        # to <1% even at the smallest validator stake the chain
        # admits -- preserving the ~2% calibration the Tier 59
        # CHANGELOG advertised but couldn't deliver under integer
        # arithmetic.  See config.py Tier 61 block for the
        # numerical-derivation note.
        penalty = (
            _cumulative_inactivity_drain(
                blocks_since_finality, validator_stake,
            )
            - _cumulative_inactivity_drain(
                blocks_since_finality - 1, validator_stake,
            )
        )
    elif (
        current_height is not None
        and current_height >= INACTIVITY_LEAK_STAKE_SCALED_HEIGHT
    ):
        # Tier 59: stake-scaled per-block-real.  Mathematically
        # ~2% cumulative; integer-truncates to 0 for stake<~1M.
        # Preserved here for byte-identical replay of historical
        # blocks at heights [Tier 59, Tier 61).
        penalty = (
            validator_stake
            * INACTIVITY_BASE_PENALTY
            * blocks_since_finality
            * blocks_since_finality
            // INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT
        )
    else:
        penalty = (
            INACTIVITY_BASE_PENALTY
            * blocks_since_finality
            * blocks_since_finality
            // INACTIVITY_PENALTY_QUOTIENT
        )
    # Cap at current stake — can't drain below 0.
    return min(penalty, validator_stake)


def _cumulative_inactivity_drain(blocks: int, stake: int) -> int:
    """Integer-floor of cumulative inactivity-leak drain through
    `blocks` blocks of stall, under the Tier 59 stake-scaled
    calibration constants.

    Closed form: ``sum_{k=1..N} k² = N*(N+1)*(2N+1)/6``.  Used by
    the Tier 61 per-block formula::

        penalty_at_block_k = cum(k) - cum(k-1)

    The cumulative-floor trick integer-truncates at the *cumulative*
    level (which crosses 1-token boundaries even for tiny stakes
    over realistic partitions) instead of at the per-block level
    (which floored to 0 for stake<~1M under Tier 59 calibration).

    Returns 0 for non-positive blocks so the boundary case
    ``cum(blocks_since_finality - 1)`` at blocks_since_finality=1
    is well-defined.
    """
    if blocks <= 0:
        return 0
    sum_squares = blocks * (blocks + 1) * (2 * blocks + 1) // 6
    return (
        stake * INACTIVITY_BASE_PENALTY * sum_squares
        // INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT
    )


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


def _apply_honesty_curve_relief(
    nominal_penalty: int,
    validator_id: bytes,
    current_height: int | None,
    blockchain,
) -> int:
    """Tier 55: scale the per-validator nominal penalty by an honest-
    history relief multiplier when both the chain has activated the
    fork AND the caller threaded a blockchain reference for the
    honesty-curve helpers to consult.

    Pre-fork (current_height < INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT) or
    legacy callers (blockchain is None): byte-identical legacy bleed
    (return ``nominal_penalty`` untouched).

    Post-fork: relief multiplier is :func:`honest_history_relief_
    multiplier_bps` -- 10000 bps for fresh validators or repeat
    offenders (full nominal), down to the FLOOR_NUM/FLOOR_DEN cap for
    long-tenured high-honesty operators.  CLAUDE.md anchor: long-
    tenured operators get fractional penalties at worst.
    """
    if blockchain is None or current_height is None:
        return nominal_penalty
    from messagechain.config import INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT
    if current_height < INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT:
        return nominal_penalty
    from messagechain.consensus.honesty_curve import (
        honest_history_relief_multiplier_bps,
    )
    bps = honest_history_relief_multiplier_bps(blockchain, validator_id)
    return nominal_penalty * bps // 10_000


def apply_inactivity_leak(
    staked: dict[bytes, int],
    blocks_since_finality: int,
    inactive_validators: set[bytes],
    min_stake: int = 0,
    *,
    current_height: int | None = None,
    blockchain=None,
) -> tuple[int, set[bytes]]:
    """Apply inactivity penalties to inactive validators.

    Mutates `staked` in place.  Burns stake (reduces values) for each
    inactive validator.  Does NOT apply penalties to validators already
    below min_stake — they should be deactivated instead.

    `current_height` and `blockchain`: optional Tier-55 hooks.  When
    both are provided AND the chain has activated
    ``INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT``, the per-validator
    nominal penalty is scaled by an honest-history relief multiplier
    routed through the same machinery as ``slashing_severity``.  Pre-
    fork or legacy callers (defaults None): byte-identical legacy
    bleed -- the leak fires at full quadratic rate as before.

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

        # Tier 59 -- thread current_height into the nominal compute
        # so the stake-scaling height gate fires.  Pre-Tier-59
        # callers either pass current_height=None (no kwarg) or
        # pass a pre-fork height; both branches resolve to the
        # legacy flat formula.  Post-Tier-59 the nominal becomes
        # stake-scaled, restoring fractional-of-stake parity across
        # the validator set per CLAUDE.md honest-operator-insurance
        # anchor.
        nominal = compute_inactivity_penalty(
            blocks_since_finality, current_stake,
            current_height=current_height,
        )
        if nominal <= 0:
            continue

        penalty = _apply_honesty_curve_relief(
            nominal, vid, current_height, blockchain,
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


# ─────────────────────────────────────────────────────────────────────
# Coverage-divergence leak — defense against selective AttesterMempool
# Report withholding by a 1/3-stake cartel.
# ─────────────────────────────────────────────────────────────────────


def compute_coverage_penalty(
    attester_stake: int,
    consecutive_misses: int,
) -> int:
    """Stake leak for an attester whose recent mempool reports failed to
    include txs that 2/3+ of peers reported.

    Quadratic in `consecutive_misses`, mirroring
    `compute_inactivity_penalty`.  Each "miss" is one inclusion-list
    cycle in which this attester's `AttesterMempoolReport` did not
    include at least one tx that the aggregated 2/3+ quorum did
    include.

    Returns 0 when:
      * consecutive_misses <= COVERAGE_LEAK_ACTIVATION_MISSES (the
        false-positive buffer for honest mempool divergence).
      * attester_stake <= 0.
      * Either input is negative (defensive — caller bug guard).

    Otherwise:
        penalty = stake * BASE * misses^2 / QUOTIENT,  capped at stake.

    The penalty scales with stake (unlike the finalization-based leak,
    which uses a flat token amount) so a 1/3-stake cartel of
    high-stake validators bleeds proportionally fast — their absolute
    drain is much larger than that of a small staker, but the
    fractional drain after the same consecutive-miss count is
    identical.  This is the desired anti-cartel property: large
    coordinated stake withholding for the same number of cycles
    produces the same fractional collapse, regardless of the cartel's
    absolute size.
    """
    if attester_stake <= 0 or consecutive_misses <= 0:
        return 0
    if consecutive_misses <= COVERAGE_LEAK_ACTIVATION_MISSES:
        return 0
    penalty = (
        attester_stake
        * COVERAGE_LEAK_BASE_PENALTY
        * consecutive_misses
        * consecutive_misses
        // COVERAGE_LEAK_QUOTIENT
    )
    return min(penalty, attester_stake)


def get_coverage_misses(
    active_attesters: set[bytes],
    inclusion_list,
) -> set[bytes]:
    """Return active-set attesters whose reports in this inclusion list
    failed to cover at least one listed tx_hash.

    "Cover" semantics: an attester is COVERED iff the union of
    `tx_hashes` across all of their reports inside
    `inclusion_list.quorum_attestation` is a superset of
    `{e.tx_hash for e in inclusion_list.entries}`.  Otherwise they
    miss.

    A validator that gossiped no report at all (and so doesn't appear
    in `quorum_attestation`) is treated as missing — a totally-silent
    reporter is indistinguishable from a withholding one and the
    posture is identical: the chain CANNOT verify they saw the
    listed txs, so they bear the same coverage cost as a partial
    reporter.  Honest reporter outage is paid for through the
    activation buffer (the first
    COVERAGE_LEAK_ACTIVATION_MISSES misses are free).

    Validators outside `active_attesters` are never returned — they
    are not expected to attest in the first place.

    Returns the empty set when the list has no entries (nothing to
    cover means nothing to fail).
    """
    list_entries = {e.tx_hash for e in inclusion_list.entries}
    if not list_entries:
        return set()

    # Per-reporter union of tx_hashes covered.
    covered: dict[bytes, set[bytes]] = {}
    for r in inclusion_list.quorum_attestation:
        if r.reporter_id not in active_attesters:
            continue
        bag = covered.setdefault(r.reporter_id, set())
        bag.update(r.tx_hashes)

    misses: set[bytes] = set()
    for vid in active_attesters:
        bag = covered.get(vid, set())
        if not list_entries.issubset(bag):
            misses.add(vid)
    return misses


def apply_coverage_leak(
    staked: dict[bytes, int],
    misses_counter: dict[bytes, int],
    active_attesters: set[bytes],
    inclusion_list,
    min_stake: int = 0,
    *,
    current_height: int | None = None,
    blockchain=None,
) -> tuple[int, set[bytes]]:
    """Update per-attester coverage-miss counters from this inclusion
    list and burn stake from any whose counter exceeds the activation
    threshold.

    Mutates `staked` and `misses_counter` in place.

    Empty-list semantics: if the inclusion list has no entries (the
    proposer published no list this cycle, or one with no quorum
    survivors), counters are NOT touched.  Only cycles where a
    non-empty list actually forms count toward the
    consecutive-miss tally.  Cycles without a list don't tell us
    anything about who saw what, so we don't punish or reward.

    `current_height` and `blockchain`: optional Tier-55 hooks.  When
    both are provided AND the chain has activated
    ``INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT``, per-attester nominal
    penalty is scaled by an honest-history relief multiplier (same
    machinery as ``slashing_severity``).  Pre-fork or legacy callers:
    byte-identical legacy bleed.

    Returns (total_burned, deactivated):
      * total_burned: sum of tokens burned this call.
      * deactivated: validators whose stake dropped to or below
        `min_stake`.
    """
    if not inclusion_list.entries:
        return 0, set()

    misses = get_coverage_misses(active_attesters, inclusion_list)

    # Counter updates first, in deterministic order (sorted by attester
    # id) so two replays with the same inputs produce the same
    # mutation order.  Counter mutations are commutative across
    # attesters but we keep the order stable for any future debug-
    # logging hook that consumes the iteration order.
    for vid in sorted(active_attesters):
        if vid in misses:
            misses_counter[vid] = misses_counter.get(vid, 0) + 1
        else:
            # Successful coverage — reset to 0.  We delete the entry
            # rather than store a 0 to keep snapshots tight.
            misses_counter.pop(vid, None)

    # Penalty pass — same deterministic order.
    total_burned = 0
    deactivated: set[bytes] = set()
    for vid in sorted(misses):
        consecutive = misses_counter.get(vid, 0)
        if consecutive <= COVERAGE_LEAK_ACTIVATION_MISSES:
            continue
        current_stake = staked.get(vid, 0)
        if current_stake <= 0:
            continue
        if current_stake <= min_stake:
            continue
        nominal = compute_coverage_penalty(current_stake, consecutive)
        if nominal <= 0:
            continue
        penalty = _apply_honesty_curve_relief(
            nominal, vid, current_height, blockchain,
        )
        if penalty <= 0:
            continue
        new_stake = max(0, current_stake - penalty)
        staked[vid] = new_stake
        actual_penalty = current_stake - new_stake
        total_burned += actual_penalty
        if new_stake <= min_stake:
            deactivated.add(vid)

    return total_burned, deactivated
