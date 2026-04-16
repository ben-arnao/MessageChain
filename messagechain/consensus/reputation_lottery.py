"""Reputation-weighted bootstrap lottery.

During bootstrap, honest behavior should confer real-time influence —
not just a slow accumulation of escrow that unlocks months later.  The
lottery is the real-time signal: every LOTTERY_INTERVAL blocks, one
non-seed validator wins a bounty, with probability proportional to
their reputation (= accepted attestation count, capped).

Why not add reputation to the attester-committee weights directly?
Two reasons:
  * Per-block committee rewards stay simple and predictable (1 token
    per slot), which is the "I'm earning" feedback signal.  Mixing in
    reputation would make the per-block payout harder to reason
    about and give Sybils a per-block edge we'd have to re-balance.
  * A winner-take-all lottery is asymmetrically harder for Sybils.
    Ten Sybil keys at rep=100 each compete for ONE slot against an
    honest validator at rep=100 — the Sybil operator wins no more
    often than a single honest actor, and per-key wins are rarer.
    Per-block committee rewards, by contrast, let Sybils extract
    value linearly in their key count.

Selection is deterministic given `randomness` (the parent block's
randao mix) so every node agrees on the winner without running a
separate consensus protocol for the lottery.
"""

from __future__ import annotations

import hashlib
import math

from messagechain.config import HASH_ALGO


def effective_reputation(rep: int, cap: int) -> int:
    """Clamp reputation to the cap.  Negative values clamp to 0."""
    if rep <= 0:
        return 0
    if rep > cap:
        return cap
    return rep


def select_lottery_winner(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    randomness: bytes,
    reputation_cap: int,
) -> bytes | None:
    """Pick the single reputation-weighted winner.

    Arguments:
        candidates: list of (entity_id, reputation) tuples.  Typically
            every validator with reputation > 0.  Entities with
            reputation == 0 are eligible if passed but will only win
            if every positive-reputation candidate is a seed.
        seed_entity_ids: excluded from the draw.  Seeds already hold
            majority stake and don't need the bootstrap lottery.
        randomness: deterministic seed, typically the parent block's
            randao_mix.  Every node must supply the same bytes.
        reputation_cap: max effective reputation per candidate.  A
            6-month-old honest validator stops gaining a selection
            advantage once they hit the cap.

    Returns the winning entity_id, or None if no eligible candidate
    exists (empty pool, or all candidates are seeds).

    Algorithm: A-Res weighted reservoir sampling with k=1.  Each
    candidate gets a log-key `log(u_i) / w_i` where u_i is a pseudo-
    random uniform derived from `hash(randomness || entity_id)`.
    Largest log-key (least negative) wins — heavy reputation tilts
    selection toward high-reputation candidates while leaving every
    positive-reputation candidate some probability of winning.
    """
    eligible = [
        (eid, effective_reputation(rep, reputation_cap))
        for eid, rep in candidates
        if eid not in seed_entity_ids
    ]
    if not eligible:
        return None

    # If no candidate has positive reputation, fall back to uniform
    # — this is the degenerate "nobody has attested yet" case at
    # genesis + 1 lottery interval.  Keeps the draw working without
    # pathologically biasing to lexicographically-first entity_ids.
    if not any(r > 0 for _, r in eligible):
        eligible = [(eid, 1) for eid, _ in eligible]

    best_key: float = float("-inf")
    best_eid: bytes | None = None
    for eid, w in eligible:
        if w <= 0:
            continue
        h = hashlib.new(HASH_ALGO, randomness + eid).digest()
        u = (int.from_bytes(h[:8], "big") + 1) / (2**64)
        # Same log-space A-Res key as the attester committee sampler.
        key = math.log(u) / w
        # Tiebreak on entity_id bytes (ascending) for deterministic
        # resolution of astronomically-unlikely key ties.
        if key > best_key or (key == best_key and (best_eid is None or eid < best_eid)):
            best_key = key
            best_eid = eid
    return best_eid
