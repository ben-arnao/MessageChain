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
from decimal import Decimal, localcontext

from messagechain.config import HASH_ALGO
from messagechain.crypto.hashing import default_hash


def effective_reputation(rep: int, cap: int) -> int:
    """Clamp reputation to the cap.  Negative values clamp to 0."""
    if rep <= 0:
        return 0
    if rep > cap:
        return cap
    return rep


def lottery_bounty_for_progress(
    bootstrap_progress: float, *, full_bounty: int,
) -> int:
    """Lottery bounty amount as a function of bootstrap progress.

    Linear fade from `full_bounty` at progress=0 to 0 at progress=1.

        bounty(p) = floor(full_bounty * (1 - p))

    Replaces the earlier cliff behavior (fixed bounty during bootstrap,
    then abruptly zero at progress=1.0).  The smooth fade matches the
    design intent — early bootstrap concentrates the bounty when
    validators most need it, and the incentive winds down on the same
    schedule as every other bootstrap-era mechanic (min-stake ramp,
    escrow-window ramp, seed-exclusion tilt).

    Integrated envelope over the bootstrap window is bounded:
    `sum_{k=0..BOOTSTRAP_END_HEIGHT/INTERVAL} full_bounty * (1 - k*I/H)`
    ≈ full_bounty * (H / I) / 2.  So halving relative to the flat
    curve — still comfortably under 0.01% of supply.

    Returns an integer (token count), floor-rounded.  `full_bounty`
    is typically `config.LOTTERY_BOUNTY`.
    """
    if not (0.0 <= bootstrap_progress <= 1.0):
        raise ValueError(
            f"bootstrap_progress must be in [0, 1], got {bootstrap_progress}"
        )
    if full_bounty < 0:
        raise ValueError(f"full_bounty must be >= 0, got {full_bounty}")
    return int(full_bounty * (1.0 - bootstrap_progress))


def _eligible_pool(
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    reputation_cap: int,
) -> list[tuple[bytes, int]]:
    """Build the seed-filtered, cap-clamped, zero-fallback eligibility
    pool shared by every selection backend.

    Behavior identical across legacy + deterministic paths so a
    backend swap at the activation height is a *math* change only,
    never an *eligibility* change.
    """
    eligible = [
        (eid, effective_reputation(rep, reputation_cap))
        for eid, rep in candidates
        if eid not in seed_entity_ids
    ]
    if not eligible:
        return []
    # If no candidate has positive reputation, fall back to uniform
    # — this is the degenerate "nobody has attested yet" case at
    # genesis + 1 lottery interval.  Keeps the draw working without
    # pathologically biasing to lexicographically-first entity_ids.
    if not any(r > 0 for _, r in eligible):
        eligible = [(eid, 1) for eid, _ in eligible]
    return eligible


def _select_lottery_winner_legacy_float(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    randomness: bytes,
    reputation_cap: int,
) -> bytes | None:
    """Pre-Tier-62 lottery selection — legacy float-math A-Res.

    Kept byte-identical to the pre-fix implementation so historical
    lottery-firing blocks (height < LOTTERY_DETERMINISTIC_HEIGHT)
    replay byte-identically post-upgrade.

    Algorithm: A-Res weighted reservoir sampling with k=1.  Each
    candidate gets a log-key ``log(u_i) / w_i`` where u_i is a
    pseudo-random uniform derived from ``hash(randomness ||
    entity_id)``.  Largest log-key (least negative) wins.  Tiebreak
    on entity_id bytes (ascending).

    Cross-platform hazard: ``math.log`` delegates to a libm whose
    ULP-level rounding is not portable across glibc / musl / MSVC
    libm / macOS libm.  Two heterogeneous-libc validators on the
    same chain could pick different winners for the same
    (randomness, candidates) input.  Tier 62
    (``LOTTERY_DETERMINISTIC_HEIGHT``) replaces this with a
    Decimal-based path that is byte-identical everywhere CPython
    runs.
    """
    eligible = _eligible_pool(candidates, seed_entity_ids, reputation_cap)
    if not eligible:
        return None

    best_key: float = float("-inf")
    best_eid: bytes | None = None
    for eid, w in eligible:
        if w <= 0:
            continue
        h = default_hash(randomness + eid)
        u = (int.from_bytes(h[:8], "big") + 1) / (2**64)
        # Same log-space A-Res key as the attester committee sampler.
        key = math.log(u) / w
        # Tiebreak on entity_id bytes (ascending) for deterministic
        # resolution of astronomically-unlikely key ties.
        if key > best_key or (key == best_key and (best_eid is None or eid < best_eid)):
            best_key = key
            best_eid = eid
    return best_eid


def _select_lottery_winner_decimal(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    randomness: bytes,
    reputation_cap: int,
) -> bytes | None:
    """Post-Tier-62 lottery selection — platform-deterministic A-Res
    using ``decimal.Decimal.ln()`` at 40-digit precision.

    Algorithm matches the legacy path *shape* (A-Res with k=1, log-
    key = ln(u_i) / w_i, tiebreak on entity_id ascending) but
    computes ln() in pure-Python Decimal arithmetic, eliminating the
    libm-rounding cross-platform risk.  Mirrors the pattern
    ``attester_committee._deterministic_weighted_sample`` adopted
    pre-mainnet for the same reason.
    """
    eligible = _eligible_pool(candidates, seed_entity_ids, reputation_cap)
    if not eligible:
        return None

    best_key: Decimal | None = None
    best_eid: bytes | None = None
    with localcontext() as ctx:
        ctx.prec = 40
        denom = Decimal(2**64)
        for eid, w in eligible:
            if w <= 0:
                continue
            h = default_hash(randomness + eid)
            # u in (0, 1] — match the legacy `+1` / `2**64` mapping
            # so the post-fork branch produces structurally the same
            # weighted A-Res distribution as the legacy path, just
            # with deterministic Decimal arithmetic.
            hash_int = int.from_bytes(h[:8], "big") + 1
            u = Decimal(hash_int) / denom
            key = u.ln() / Decimal(w)
            # Decimal compare is exact — no floating-point ULP wobble.
            # Tiebreak on entity_id bytes ascending matches legacy.
            if (
                best_key is None
                or key > best_key
                or (key == best_key and (best_eid is None or eid < best_eid))
            ):
                best_key = key
                best_eid = eid
    return best_eid


def select_lottery_winner(
    *,
    candidates: list[tuple[bytes, int]],
    seed_entity_ids: frozenset[bytes],
    randomness: bytes,
    reputation_cap: int,
    block_height: int | None = None,
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
        block_height: the block whose lottery firing is being
            evaluated.  Selects the legacy float backend (pre-Tier-62)
            or the deterministic Decimal backend (post-Tier-62).
            ``None`` routes to legacy, preserving back-compat for
            tests and tooling that don't model the height gate.

    Returns the winning entity_id, or None if no eligible candidate
    exists (empty pool, or all candidates are seeds).
    """
    if block_height is not None:
        from messagechain.config import LOTTERY_DETERMINISTIC_HEIGHT
        if block_height >= LOTTERY_DETERMINISTIC_HEIGHT:
            return _select_lottery_winner_decimal(
                candidates=candidates,
                seed_entity_ids=seed_entity_ids,
                randomness=randomness,
                reputation_cap=reputation_cap,
            )
    return _select_lottery_winner_legacy_float(
        candidates=candidates,
        seed_entity_ids=seed_entity_ids,
        randomness=randomness,
        reputation_cap=reputation_cap,
    )
