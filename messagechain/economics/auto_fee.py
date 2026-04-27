"""Unified auto-fee helper used by every tx-submitting CLI command.

Single source of truth for "what fee should this transaction pay?"
spanning every tx kind (`message`, `transfer`, `stake`, `unstake`,
`react`, `propose`, `vote`, `rotate-key`).  Replaces the prior
patchwork where each cmd_* in `messagechain/cli.py` computed its own
floor + auto-pick path independently — that was the failure mode
CLAUDE.md anchors against:

    "Auto-fee adjusts to fit this model.  Any wallet/CLI helper that
     picks a fee for the user (message send, transfer, stake op, etc.)
     computes a target fee-per-byte from current mempool conditions
     and multiplies by the tx's stored byte count.  When the fee model
     shifts, every auto-fee path shifts with it -- don't leave a tx
     kind defaulting to a stale flat fee while others auto-bid by
     density."

Three public entry points:

  * ``urgency_to_target_blocks(urgency)`` — maps a UX-level urgency
    label (``low``/``normal``/``high``) onto the ``target_blocks`` axis
    of the existing FeeEstimator percentile ladder
    (90/75/60/25/10).  ``high`` = 1 block (90th percentile), ``normal``
    = 3 blocks (75th), ``low`` = 10 blocks (25th).

  * ``tx_floor(tx_type, *, stored_size, payload_bytes,
    current_height, recipient_is_new)`` — the protocol admission
    floor for the given tx kind at the given chain height.  Mirrors
    the live admission rule each tx kind enforces in its
    ``verify_*_transaction`` path; never returns 0 (CLAUDE.md anchor:
    "Minimum fee is 1, never 0.").

  * ``auto_fee(tx_type, *, stored_size, payload_bytes, urgency,
    current_height, mempool_estimate, recipient_is_new)`` — the
    bid the CLI submits.  Returns ``max(tx_floor, mempool_estimate)``.
    The mempool estimate is computed by the server side at the
    percentile picked by ``urgency_to_target_blocks(urgency)`` and
    multiplied by ``stored_size``; the helper just picks the higher
    of "must clear the floor" vs "outbid the percentile rung."

Per CLAUDE.md fee-model section the helper does NOT introduce new
quadratic / polynomial fee curves.  Urgency lifts the bid above the
flat MARKET_FEE_FLOOR=1 floor only via the percentile estimator —
the tip layer, not floor inflation.
"""

from __future__ import annotations

from typing import Iterable

from messagechain import config
from messagechain.config import (
    BASE_TX_FEE,
    BLOCK_BYTES_RAISE_HEIGHT,
    FEE_PER_STORED_BYTE,
    FEE_PER_STORED_BYTE_POST_RAISE,
    FLAT_FEE_HEIGHT,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19,
    GOVERNANCE_PROPOSAL_FEE_TIER19,
    GOVERNANCE_VOTE_FEE,
    KEY_ROTATION_FEE,
    LINEAR_FEE_HEIGHT,
    MARKET_FEE_FLOOR,
    MARKET_FEE_FLOOR_HEIGHT,
    MIN_FEE,
    MIN_FEE_POST_FLAT,
    NEW_ACCOUNT_FEE,
    PROPOSAL_FEE_TIER19_HEIGHT,
)


# ── Urgency → target_blocks mapping ─────────────────────────────────


# Maps the UX urgency label onto ``target_blocks`` for the FeeEstimator
# percentile ladder (``messagechain/economics/fee_estimator.py``):
#   target_blocks=1   → 90th percentile of recent fees   (high urgency)
#   target_blocks=3   → 75th percentile                  (normal)
#   target_blocks=10  → 25th percentile                  (low urgency)
# These rungs are what makes the helper "drive the percentile estimator"
# rather than always bidding the median.
URGENCY_TARGET_BLOCKS = {
    "low": 10,
    "normal": 3,
    "high": 1,
}

DEFAULT_URGENCY = "normal"


def urgency_to_target_blocks(urgency: str) -> int:
    """Translate ``urgency`` to a ``target_blocks`` value for the estimator.

    Raises ``ValueError`` for anything outside ``{low, normal, high}`` so
    a typo in the CLI surfaces immediately rather than silently defaulting.
    """
    if urgency not in URGENCY_TARGET_BLOCKS:
        raise ValueError(
            f"unknown urgency: {urgency!r} "
            f"(expected one of {sorted(URGENCY_TARGET_BLOCKS)})"
        )
    return URGENCY_TARGET_BLOCKS[urgency]


# ── Tx kinds the unified helper covers ──────────────────────────────


# Every kind the chain admits via a user-submitting RPC.  Slashing /
# release-announce / set-receipt-subtree-root / set-authority-key /
# emergency-revoke are operator-only and not user-facing fee paths,
# so they're not in this set even though they have their own fee
# floors elsewhere in the codebase.
TX_TYPES: tuple[str, ...] = (
    "message",
    "transfer",
    "stake",
    "unstake",
    "react",
    "propose",
    "vote",
    "rotate-key",
)


# Representative stored byte sizes for non-message tx kinds.  These
# kinds have a roughly fixed envelope (entity_ref + amount/nonce/ts/fee
# + signature blob + tx_hash); the actual byte count varies a few
# bytes with the signature size, but for fee-quote purposes a
# representative number is enough — non-message tx kinds are floor-
# dominated, not mempool-percentile-dominated, because they don't
# count against MAX_BLOCK_MESSAGE_BYTES (only message txs do).
#
# The numbers reflect the typical post-Tier-16 binary envelope
# (`to_bytes`) excluding the WOTS+ witness, which is amortised into
# BASE_TX_FEE and not separately priced post-Tier-16.
_REPRESENTATIVE_STORED_SIZES = {
    "transfer": 96,    # ENT + ENT + 8a + 8n + 8t + 8f + sig_len + pk_len + 32 hash
    "stake": 64,       # ENT + 8a + 8n + 8t + 8f + sig_len + pk_len + 32 hash
    "unstake": 64,
    "react": 96,       # ENT + 32 target + 1 flags + 8n + 8t + 8f + sig_len + 32 hash
    "vote": 96,        # voter ENT + 32 proposal_id + 1 approve + 8n + 8t + 8f + ...
    "rotate-key": 96,  # ENT + 32 new_pk + 8n + 8t + 8f + sig + hash
    # `propose` size depends on payload bytes — exposed as a kwarg.
}


def stored_size_for(
    tx_type: str,
    *,
    message_bytes: int = 0,
    has_prev: bool = False,
    payload_bytes: int = 0,
) -> int:
    """Return the deterministic stored byte count for a tx kind.

    The CLI multiplies this by the percentile fee-per-byte estimate to
    arrive at a density-priced bid.  For non-message kinds the value is
    a representative envelope size — those kinds are floor-dominated
    in practice, so exact byte counts don't materially move the bid.

    Parameters
    ----------
    tx_type
        One of ``TX_TYPES``.
    message_bytes
        Length of the canonical message bytes (post-compression) for
        ``tx_type == "message"``.  Ignored for other kinds.
    has_prev
        Whether the message carries a 33-byte prev pointer (1B presence
        flag + 32B hash, per CLAUDE.md "Prev pointer is structural
        metadata, not content").  Ignored for non-message kinds.
    payload_bytes
        Title + description + reference_hash bytes for a
        ``ProposalTransaction``.  Ignored for other kinds.
    """
    if tx_type == "message":
        size = max(0, int(message_bytes))
        if has_prev:
            size += 33  # 1B presence flag + 32B prev hash
        return size
    if tx_type == "propose":
        # Propose tx envelope is ~64 B + payload (title + description +
        # reference_hash).  Payload bytes is the only meaningful axis
        # for the fee floor (the per-byte surcharge bites on payload),
        # so we expose it as a kwarg and add a small fixed overhead.
        return 64 + max(0, int(payload_bytes))
    if tx_type in _REPRESENTATIVE_STORED_SIZES:
        return _REPRESENTATIVE_STORED_SIZES[tx_type]
    raise ValueError(f"unknown tx_type: {tx_type!r}")


# ── Protocol admission floor (height-aware) ─────────────────────────


def _message_floor(stored_size: int, current_height: int | None) -> int:
    """Live admission floor for a MessageTransaction at the given height.

    Mirrors `messagechain.core.transaction.calculate_min_fee` exactly so
    a test that asserts "tx_floor matches the live admission rule"
    doesn't have to second-guess which historical formula is in
    effect.  Pre-fork heights still see the legacy linear-in-stored-
    bytes formulas for replay determinism.
    """
    h = current_height
    if h is not None and h >= MARKET_FEE_FLOOR_HEIGHT:
        # Tier 16: flat protocol baseline.  Bloat discipline lives in
        # the per-block byte budget + EIP-1559 base fee.
        return MARKET_FEE_FLOOR
    if h is not None and h >= BLOCK_BYTES_RAISE_HEIGHT:
        # Tier 9: linear at the post-raise per-byte rate.
        return BASE_TX_FEE + FEE_PER_STORED_BYTE_POST_RAISE * stored_size
    if h is not None and h >= LINEAR_FEE_HEIGHT:
        # Tier 8: linear at the original per-byte rate.
        return BASE_TX_FEE + FEE_PER_STORED_BYTE * stored_size
    if h is not None and h >= FLAT_FEE_HEIGHT:
        # Pre-Tier-8: flat MIN_FEE_POST_FLAT.
        return MIN_FEE_POST_FLAT
    # Pre-FLAT_FEE_HEIGHT: legacy MIN_FEE.
    return MIN_FEE


def _transfer_floor(current_height: int | None, recipient_is_new: bool) -> int:
    """Live admission floor for a TransferTransaction.

    See `verify_transfer_transaction` — flat_floor is MIN_FEE; Tier 16+
    layers MARKET_FEE_FLOOR=1 underneath but MIN_FEE=100 still binds.
    NEW_ACCOUNT_FEE surcharge applies when the recipient is brand-new
    (priced upfront so the user isn't surprised by a chain reject).
    """
    floor = max(MIN_FEE, MARKET_FEE_FLOOR)
    if recipient_is_new:
        floor += NEW_ACCOUNT_FEE
    return floor


def _stake_floor(current_height: int | None) -> int:
    """Live admission floor for StakeTransaction (same shape as transfer)."""
    return max(MIN_FEE, MARKET_FEE_FLOOR)


def _unstake_floor(current_height: int | None) -> int:
    """Live admission floor for UnstakeTransaction (same shape as stake)."""
    return max(MIN_FEE, MARKET_FEE_FLOOR)


def _react_floor(current_height: int | None) -> int:
    """Live admission floor for ReactTransaction.

    Pre-TIER_18_HEIGHT: type-specific REACT_FEE_FLOOR (legacy 10).
    At/after TIER_18_HEIGHT: collapses to MARKET_FEE_FLOOR (=1).
    """
    h = current_height
    tier_18 = getattr(config, "TIER_18_HEIGHT", None)
    react_floor = getattr(config, "REACT_FEE_FLOOR", MARKET_FEE_FLOOR)
    if h is None or tier_18 is None or h >= tier_18:
        return MARKET_FEE_FLOOR
    return max(react_floor, MARKET_FEE_FLOOR)


def _propose_floor(payload_bytes: int, current_height: int | None) -> int:
    """Live admission floor for ProposalTransaction.

    Mirrors `messagechain.governance.governance.proposal_fee_floor`.
    """
    h = current_height
    if h is not None and h >= PROPOSAL_FEE_TIER19_HEIGHT:
        return (
            GOVERNANCE_PROPOSAL_FEE_TIER19
            + GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * max(0, int(payload_bytes))
        )
    return GOVERNANCE_PROPOSAL_FEE


def _vote_floor(current_height: int | None) -> int:
    return GOVERNANCE_VOTE_FEE


def _rotate_key_floor(current_height: int | None) -> int:
    return KEY_ROTATION_FEE


def tx_floor(
    tx_type: str,
    *,
    stored_size: int = 0,
    payload_bytes: int = 0,
    current_height: int | None = None,
    recipient_is_new: bool = False,
) -> int:
    """Return the protocol admission floor for ``tx_type`` at ``current_height``.

    Always ``>= 1`` (CLAUDE.md anchor: "Minimum fee is 1, never 0.").
    Heights are taken at face value — callers that don't know the
    current height should pass ``None`` to get a conservative pre-fork
    floor.

    Parameters
    ----------
    tx_type
        One of ``TX_TYPES``.
    stored_size
        Stored bytes for `message` (post-compression) — drives the
        legacy linear-in-stored-bytes formula at pre-Tier-16 heights.
    payload_bytes
        Title + description + reference_hash bytes for `propose` —
        drives the Tier 19 per-byte surcharge.
    current_height
        Chain height at which the tx will be admitted.  ``None`` →
        legacy floor.
    recipient_is_new
        For `transfer`: tags the recipient as a brand-new entity, so
        the NEW_ACCOUNT_FEE surcharge is included in the quote.
    """
    if tx_type == "message":
        floor = _message_floor(stored_size, current_height)
    elif tx_type == "transfer":
        floor = _transfer_floor(current_height, recipient_is_new)
    elif tx_type == "stake":
        floor = _stake_floor(current_height)
    elif tx_type == "unstake":
        floor = _unstake_floor(current_height)
    elif tx_type == "react":
        floor = _react_floor(current_height)
    elif tx_type == "propose":
        floor = _propose_floor(payload_bytes, current_height)
    elif tx_type == "vote":
        floor = _vote_floor(current_height)
    elif tx_type == "rotate-key":
        floor = _rotate_key_floor(current_height)
    else:
        raise ValueError(f"unknown tx_type: {tx_type!r}")
    # Defence in depth: never return 0.  Every per-kind branch should
    # already produce >=1 (MARKET_FEE_FLOOR=1 is the universal lower
    # bound at current heights), but this max() is the literal
    # enforcement of the CLAUDE.md "Minimum fee is 1, never 0."
    # anchor.  If a future tx kind branches without hitting one of the
    # explicit floors above, this still keeps it from rounding down.
    return max(int(floor), 1)


# ── Auto-fee picker ─────────────────────────────────────────────────


def auto_fee(
    tx_type: str,
    *,
    stored_size: int = 0,
    payload_bytes: int = 0,
    urgency: str = DEFAULT_URGENCY,
    current_height: int | None = None,
    mempool_estimate: int = 0,
    recipient_is_new: bool = False,
) -> int:
    """Pick the fee to bid for ``tx_type`` under current mempool conditions.

    Returns ``max(tx_floor(...), mempool_estimate)``.  The mempool
    estimate is computed externally (server-side, off the percentile
    ladder picked by ``urgency_to_target_blocks(urgency)``) and
    multiplied by ``stored_size``.  This helper just enforces the
    floor and never returns 0.

    Per CLAUDE.md fee-model anchor:

        Selection priority is fee-per-byte, never absolute fee.

    The bid is therefore:

        max(protocol_floor, percentile_estimate * stored_size)

    This helper does the ``max(...)`` step.  The caller is expected to
    have already produced ``mempool_estimate`` as the percentile result
    multiplied by ``stored_size`` for tx kinds where density ranking
    applies (currently `message`).  For non-message kinds the mempool
    estimate is typically 0 and the floor binds.
    """
    # Validate urgency at picker time — a typo here would silently
    # downgrade the bid to the floor without raising, which is the
    # "looks broken" UX the audit is trying to close.
    urgency_to_target_blocks(urgency)
    floor = tx_floor(
        tx_type,
        stored_size=stored_size,
        payload_bytes=payload_bytes,
        current_height=current_height,
        recipient_is_new=recipient_is_new,
    )
    return max(floor, int(mempool_estimate))


# ── Mempool percentile helper (sibling of get_fee_estimate) ─────────


def mempool_percentile_estimate(
    fees_by_block: Iterable[Iterable[int]],
    *,
    target_blocks: int,
    stored_size: int,
) -> int:
    """Compute a percentile-of-recent-block-fees estimate.

    Mirrors `messagechain.economics.fee_estimator.FeeEstimator.estimate_fee`'s
    percentile rungs but operates on raw fee-per-byte densities rather
    than absolute fees, so the value scales with ``stored_size`` and
    matches the proposer's selection axis.

    Used by the server's `_rpc_estimate_fee` path to drive the
    estimator from the actual pending-mempool fee distribution at the
    urgency-derived ``target_blocks`` rung.

    Returns 0 when there's no demand signal (empty / zero-byte input)
    so the caller falls back to ``tx_floor``.
    """
    if stored_size <= 0:
        return 0
    densities: list[float] = []
    for block_fees in fees_by_block:
        for fee in block_fees:
            densities.append(float(fee) / max(1, stored_size))
    if not densities:
        return 0
    densities.sort()
    if target_blocks <= 1:
        percentile = 0.90
    elif target_blocks <= 3:
        percentile = 0.75
    elif target_blocks <= 5:
        percentile = 0.60
    elif target_blocks <= 10:
        percentile = 0.25
    else:
        percentile = 0.10
    idx = min(int(len(densities) * percentile), len(densities) - 1)
    return int(densities[idx] * stored_size)
