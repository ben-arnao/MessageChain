"""
Dynamic minimum relay fee for MessageChain.

Problem: A static MIN_FEE doesn't adapt to spam attacks. When the mempool
is being flooded, the minimum fee should rise to make spam expensive.

Solution: Scale the minimum relay fee based on mempool utilization.
When the mempool is nearly empty, use the base fee. As it fills up,
increase the minimum proportionally up to a configured maximum.

This mirrors Bitcoin Core's incremental relay fee, which rises when
the mempool exceeds its size limit.
"""


class DynamicFeePolicy:
    """Computes a dynamic minimum relay fee based on mempool pressure.

    The fee scales linearly from base_fee (empty mempool) to max_fee
    (full mempool). Transactions below the dynamic minimum are rejected.

    Args:
        base_fee: Minimum fee when mempool has no pressure.
        max_fee: Maximum the dynamic fee can reach.
    """

    def __init__(self, base_fee: int = 1, max_fee: int = 100):
        self.base_fee = base_fee
        self.max_fee = max_fee

    def get_min_relay_fee(self, mempool_size: int, mempool_max: int) -> int:
        """Calculate the current minimum relay fee.

        Args:
            mempool_size: Current number of transactions in mempool.
            mempool_max: Maximum mempool capacity.

        Returns:
            The minimum fee required for relay at current pressure.
        """
        if mempool_max <= 0 or mempool_size <= 0:
            return self.base_fee

        # Linear scale: base_fee at 0% full, max_fee at 100% full
        utilization = min(mempool_size / mempool_max, 1.0)
        fee = self.base_fee + int(utilization * (self.max_fee - self.base_fee))
        return min(fee, self.max_fee)
