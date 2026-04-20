"""
Shared block production logic for MessageChain.

This module is the single source of truth for "should I produce a block
right now, and if so, which one?" Both server.py and network/node.py call
into it so the slot timing, round rotation, and RANDAO grinding-resistance
fixes don't drift between two implementations.

Key concepts:

- **Slot clock**: blocks are scheduled relative to the parent's timestamp,
  not a per-node local sleep. Every honest validator wakes up at the same
  wall-clock moment regardless of when their process started.

- **Round rotation**: round 0 is the primary proposer for a slot. If they
  fail to produce within BLOCK_TIME_TARGET seconds, round 1 rotates to a
  different validator, and so on. Without this, a single offline validator
  permanently stalls the chain.

- **RANDAO mix**: the parent's randao_mix (derived from its proposer
  signature) feeds into proposer selection. A current proposer cannot
  grind block contents to influence the *next* proposer without burning
  WOTS+ leaves, which are tracked on chain.

- **Empty blocks**: when the mempool is empty we still produce a block.
  Empty blocks carry attestations, advance block-denominated timers
  (unbonding periods), and serve as the chain's heartbeat.
"""

import time
from dataclasses import dataclass
from messagechain.config import BLOCK_TIME_TARGET, MAX_TXS_PER_BLOCK


@dataclass
class SlotInfo:
    """Computed timing for the next/current block production slot."""
    next_slot_time: float       # earliest wall-clock time round 0 may fire
    is_due: bool                # True iff now >= next_slot_time
    round_number: int           # which rotation round we are in (0 = primary)
    seconds_until_due: float    # 0 if already due, else seconds to wait


def compute_slot(latest_block, now: float | None = None) -> SlotInfo:
    """Compute slot timing relative to the latest block.

    The slot for block N+1 starts at parent.timestamp + BLOCK_TIME_TARGET.
    Round R fires at parent.timestamp + (R+1) * BLOCK_TIME_TARGET — that is,
    once round R-1's window has elapsed without a block landing, round R
    becomes eligible.
    """
    if now is None:
        now = time.time()

    parent_ts = latest_block.header.timestamp
    next_slot_time = parent_ts + BLOCK_TIME_TARGET

    if now < next_slot_time:
        return SlotInfo(
            next_slot_time=next_slot_time,
            is_due=False,
            round_number=0,
            seconds_until_due=next_slot_time - now,
        )

    # We're past the round 0 deadline. Compute which round we're in.
    rounds_elapsed = int((now - next_slot_time) // BLOCK_TIME_TARGET)
    return SlotInfo(
        next_slot_time=next_slot_time,
        is_due=True,
        round_number=rounds_elapsed,
        seconds_until_due=0.0,
    )


def _grinding_stake_floor(blockchain) -> int:
    """Minimum stake required to propose — the RANDAO grinding-resistance floor.

    Audit finding M6: a proposer can re-sign the block header (consuming
    WOTS+ leaves) to grind the randao_mix for favorable future proposer
    selection.  The per-grind cost (one WOTS+ leaf) is de-minimis unless
    the proposer's stake is large enough that losing the stake outweighs
    any per-grind payoff.  We gate propose-time eligibility on the
    larger of:
      * `VALIDATOR_MIN_STAKE` — the flat post-bootstrap floor (100 tokens),
        and
      * the progress-graduated minimum derived from current bootstrap
        progress (rises linearly toward `VALIDATOR_MIN_STAKE` over the
        bootstrap window).
    At progress=1.0 these two are equal; pre-progress=1.0 the graduated
    term is smaller, so the `max()` just returns `VALIDATOR_MIN_STAKE`.
    The max() form is kept so the floor cannot silently drop below
    VALIDATOR_MIN_STAKE if either term is ever tuned.
    """
    from messagechain.config import VALIDATOR_MIN_STAKE
    floor = VALIDATOR_MIN_STAKE
    # Blockchain exposes a progress-graduated minimum via
    # bootstrap_gradient.min_stake_for_progress.  If we have a chain
    # reference we honor it; otherwise fall back to the flat floor.
    try:
        from messagechain.consensus.bootstrap_gradient import (
            min_stake_for_progress,
        )
        progress = getattr(blockchain, "bootstrap_progress", None)
        if progress is not None:
            graduated = min_stake_for_progress(
                progress, full_min_stake=VALIDATOR_MIN_STAKE,
            )
            floor = max(floor, graduated)
    except Exception:
        # If the gradient module is unavailable for any reason, we still
        # enforce the flat VALIDATOR_MIN_STAKE floor — never silently
        # relax grinding resistance.
        pass
    return floor


def should_propose(
    blockchain,
    consensus,
    proposer_entity_id: bytes,
    now: float | None = None,
) -> tuple[bool, int, str]:
    """Decide whether `proposer_entity_id` should produce a block right now.

    Returns (should_propose, round_number, reason). reason is a short
    string useful for logging when should_propose is False.

    Enforces a minimum-stake floor at propose time (audit finding M6):
    the proposer's current stake must be ≥ `_grinding_stake_floor(blockchain)`.
    Without this, a low-stake validator picked by the raw stake-weighted
    lottery can cheaply re-sign the block header (each attempt burns one
    WOTS+ leaf, which is de-minimis for a small validator) to grind the
    randao_mix for favorable future proposer selection.  Filtering at
    `should_propose` stops grinding at the eligibility gate: no propose
    → no signature → no mix contribution.
    """
    latest = blockchain.get_latest_block()
    if latest is None:
        return False, 0, "no genesis block"

    slot = compute_slot(latest, now=now)
    if not slot.is_due:
        return False, 0, f"slot not due ({slot.seconds_until_due:.0f}s remaining)"

    selected = consensus.select_proposer(
        latest.block_hash,
        randao_mix=latest.header.randao_mix,
        round_number=slot.round_number,
    )

    if selected is None:
        # No registered validators → bootstrap mode → any node may propose
        if consensus.validator_count > 0:
            return False, slot.round_number, "no proposer selected"
        return True, slot.round_number, "bootstrap (no validators)"

    if selected != proposer_entity_id:
        return False, slot.round_number, "not our slot"

    # M6: grinding-resistance stake floor.  Apply AFTER the "selected"
    # check so a below-floor validator who is not our current candidate
    # still falls through to the normal "not our slot" path; the floor
    # only matters when the low-stake entity is actually being asked to
    # propose.  Read current stake from the chain's authoritative supply
    # state (consensus.stakes may be a cached copy not reflecting
    # slashing / unstakes applied to supply.staked).
    floor = _grinding_stake_floor(blockchain)
    current_stake = 0
    supply = getattr(blockchain, "supply", None)
    if supply is not None:
        staked = getattr(supply, "staked", None)
        if isinstance(staked, dict):
            current_stake = staked.get(proposer_entity_id, 0)
    # Fall back to consensus.stakes if the blockchain doesn't expose a
    # staked dict (unit tests that drive ProofOfStake directly).
    if current_stake == 0:
        current_stake = consensus.stakes.get(proposer_entity_id, 0)
    if current_stake < floor:
        return False, slot.round_number, (
            f"stake {current_stake} below grinding-resistance floor {floor}"
        )

    return True, slot.round_number, "selected for this slot"


def next_wake_seconds(blockchain, now: float | None = None) -> float:
    """Compute how long to sleep before the next production attempt.

    Aligns to slot boundaries so that all honest validators wake up at
    the same wall-clock moment. Floors at 1 second to avoid busy loops.
    """
    if now is None:
        now = time.time()

    latest = blockchain.get_latest_block()
    if latest is None:
        return 1.0

    slot = compute_slot(latest, now=now)
    if not slot.is_due:
        return max(1.0, slot.seconds_until_due)

    # We're already past round 0 — wake at the next round boundary
    next_round_time = slot.next_slot_time + (slot.round_number + 1) * BLOCK_TIME_TARGET
    return max(1.0, next_round_time - now)


_CLOCK_SKEW_KEYWORDS = ("timestamp too early", "too far in the future", "median time past")


def is_clock_skew_reason(reason: str) -> bool:
    """Return True if a block rejection reason suggests system clock skew."""
    lower = reason.lower()
    return any(kw in lower for kw in _CLOCK_SKEW_KEYWORDS)
