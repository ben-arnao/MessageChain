"""
Fee estimation for MessageChain.

Problem: Users must guess fees manually. Too low = stuck transaction.
Too high = wasted tokens.

Solution: Track fee-per-byte densities from recent blocks and estimate
the minimum fee needed to confirm within a target number of blocks.
Quoting uses ``percentile_density × quoting_stored_size`` so the bid
scales with the tx's stored bytes — matching the proposer's selection
axis (CLAUDE.md anchor: "Selection priority is fee-per-byte, never
absolute fee.  Any wallet/CLI helper that picks a fee for the user
computes a target fee-per-byte from current mempool conditions and
multiplies by the tx's stored byte count.").

Similar to Bitcoin Core's estimatesmartfee in shape, but density-based
rather than absolute-fee-based to match MessageChain's fee-per-byte
selection rule.

Backwards compatibility: ``record_block_fees`` still accepts a bare
list of integer fees for legacy callers (the historical "I don't track
sizes" callsite that pre-dated this fix).  Bare ints are treated as
single-byte densities (fee == density) — this preserves the percentile
ordering for those callers while making density math explicit for any
caller that supplies real ``(fee, stored_size)`` pairs.
"""

from collections import deque
from typing import Sequence, Union

from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE


# Number of recent blocks to track for fee estimation
FEE_HISTORY_BLOCKS = 50


# Per-tx record: (fee, stored_size).  Bare int == legacy "fee only".
FeeEntry = Union[int, tuple[int, int]]


class FeeEstimator:
    """Estimates appropriate transaction fees based on recent block history.

    Records the fee-per-byte density of each confirmed tx and uses
    percentile-based estimation to recommend fees for different
    confirmation urgency levels.  Quoting requires the caller's own
    ``stored_size`` so the bid scales linearly with bytes.
    """

    def __init__(self, history_size: int = FEE_HISTORY_BLOCKS):
        self.history_size = history_size
        # Each entry is the list of (fee, stored_size) pairs from one block,
        # sorted by density.  Internal representation is always pairs even
        # when the caller passes bare ints — the legacy path normalises to
        # (fee, 1) so the density rank is preserved.
        self._block_entries: deque[list[tuple[int, int]]] = deque(
            maxlen=history_size,
        )

    def record_block_fees(self, entries: Sequence[FeeEntry]):
        """Record the fee distribution from a confirmed block.

        Args:
            entries: Sequence of either:
                - ``(fee, stored_size)`` pairs (preferred, density-correct),
                - bare ``int`` fees (legacy; treated as 1-byte density so
                  the percentile ranking is preserved).
        """
        if not entries:
            return
        normalised: list[tuple[int, int]] = []
        for entry in entries:
            if isinstance(entry, tuple):
                fee, size = entry
                normalised.append((int(fee), max(1, int(size))))
            else:
                # Legacy bare int: assume 1-byte size so density == fee.
                # This keeps the relative ordering of legacy callers
                # intact — they were already comparing absolute fees,
                # and at uniform implicit size 1 the density rank is
                # identical.
                normalised.append((int(entry), 1))
        normalised.sort(key=lambda fs: fs[0] / fs[1])
        self._block_entries.append(normalised)

    def estimate_fee(
        self,
        target_blocks: int = 1,
        *,
        recipient_is_new: bool = False,
        stored_size: int | None = None,
    ) -> int:
        """Estimate the fee needed to confirm within target_blocks.

        Higher urgency (lower target_blocks) returns higher fee estimates.
        Uses percentile-based estimation over fee-per-byte densities:
        urgent targets use higher percentiles of recent density
        distributions.

        Args:
            target_blocks: Number of blocks within which to target
                confirmation.
            recipient_is_new: If True, add NEW_ACCOUNT_FEE to the estimate
                so the caller pays the surcharge the chain will require on
                apply.  Default False preserves behavior for message-only
                flows and existing-recipient transfers.
            stored_size: Stored byte count for the tx being quoted.  When
                supplied, the returned fee is ``percentile_density ×
                stored_size`` (the density-correct quote).  When omitted,
                the legacy "absolute fee" answer is returned for
                callers/tests that pre-date the density fix — these
                callers should be migrated, and this fallback exists only
                to keep them working while they migrate.

        Returns:
            Estimated fee (always >= MIN_FEE, plus NEW_ACCOUNT_FEE when
            `recipient_is_new` is True).
        """
        surcharge = NEW_ACCOUNT_FEE if recipient_is_new else 0

        if not self._block_entries:
            return MIN_FEE + surcharge

        # Flatten densities across all recorded blocks.
        densities: list[float] = []
        for block_entries in self._block_entries:
            for fee, size in block_entries:
                densities.append(fee / size)

        if not densities:
            return MIN_FEE + surcharge

        densities.sort()

        # Map target_blocks to a percentile rung:
        # 1 block   -> 90th percentile (high urgency)
        # 2-3       -> 75th percentile
        # 4-5       -> 60th percentile (medium)
        # 6-10      -> 25th percentile
        # 11+       -> 10th percentile (low urgency)
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
        density = densities[idx]

        if stored_size is not None and stored_size > 0:
            estimate = int(density * stored_size)
        else:
            # Legacy fallback: caller didn't supply quoting bytes, so we
            # return the density rounded to int (which equals the legacy
            # absolute-fee answer when entries were recorded as bare
            # ints, since those normalise to size=1).  Callers should
            # supply stored_size for a density-correct quote.
            estimate = int(density)

        return max(estimate, MIN_FEE) + surcharge

    @property
    def has_data(self) -> bool:
        return len(self._block_entries) > 0
