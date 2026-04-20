"""
Fee estimation for MessageChain.

Problem: Users must guess fees manually. Too low = stuck transaction.
Too high = wasted tokens.

Solution: Track fee distributions from recent blocks and estimate the
minimum fee needed to confirm within a target number of blocks.

Similar to Bitcoin Core's estimatesmartfee, which uses exponentially
weighted moving averages of recent block fee distributions.
"""

from collections import deque
from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE


# Number of recent blocks to track for fee estimation
FEE_HISTORY_BLOCKS = 50


class FeeEstimator:
    """Estimates appropriate transaction fees based on recent block history.

    Records the fee distribution of each confirmed block and uses
    percentile-based estimation to recommend fees for different
    confirmation urgency levels.
    """

    def __init__(self, history_size: int = FEE_HISTORY_BLOCKS):
        self.history_size = history_size
        # Each entry is a sorted list of fees from one block
        self._block_fees: deque[list[int]] = deque(maxlen=history_size)

    def record_block_fees(self, fees: list[int]):
        """Record the fee distribution from a confirmed block.

        Args:
            fees: List of transaction fees included in the block.
        """
        if fees:
            self._block_fees.append(sorted(fees))

    def estimate_fee(
        self,
        target_blocks: int = 1,
        *,
        recipient_is_new: bool = False,
    ) -> int:
        """Estimate the fee needed to confirm within target_blocks.

        Higher urgency (lower target_blocks) returns higher fee estimates.
        Uses percentile-based estimation: urgent targets use higher
        percentiles of recent fee distributions.

        Args:
            target_blocks: Number of blocks within which to target confirmation.
            recipient_is_new: If True, add NEW_ACCOUNT_FEE to the estimate
                so the caller pays the surcharge the chain will require on
                apply.  Default False preserves behavior for message-only
                flows and existing-recipient transfers.

        Returns:
            Estimated fee (always >= MIN_FEE, plus NEW_ACCOUNT_FEE when
            `recipient_is_new` is True).
        """
        surcharge = NEW_ACCOUNT_FEE if recipient_is_new else 0

        if not self._block_fees:
            return MIN_FEE + surcharge

        # Collect all fees from recent blocks
        all_fees = []
        for block_fees in self._block_fees:
            all_fees.extend(block_fees)

        if not all_fees:
            return MIN_FEE + surcharge

        all_fees.sort()

        # Map target_blocks to a percentile:
        # 1 block  -> 90th percentile (high urgency)
        # 5 blocks -> 60th percentile (medium)
        # 10+ blocks -> 25th percentile (low urgency)
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

        idx = min(int(len(all_fees) * percentile), len(all_fees) - 1)
        estimate = all_fees[idx]

        return max(estimate, MIN_FEE) + surcharge

    @property
    def has_data(self) -> bool:
        return len(self._block_fees) > 0
