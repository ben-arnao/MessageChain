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
        penalty = compute_coverage_penalty(current_stake, consecutive)
        if penalty <= 0:
            continue
        new_stake = max(0, current_stake - penalty)
        staked[vid] = new_stake
        actual_penalty = current_stake - new_stake
        total_burned += actual_penalty
        if new_stake <= min_stake:
            deactivated.add(vid)

    return total_burned, deactivated
