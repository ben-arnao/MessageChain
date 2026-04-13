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
  (TTLs, unbonding periods), and serve as the chain's heartbeat.
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


def should_propose(
    blockchain,
    consensus,
    proposer_entity_id: bytes,
    now: float | None = None,
) -> tuple[bool, int, str]:
    """Decide whether `proposer_entity_id` should produce a block right now.

    Returns (should_propose, round_number, reason). reason is a short
    string useful for logging when should_propose is False.
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
