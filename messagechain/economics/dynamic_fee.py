"""
Deprecated: dynamic relay-fee scaling is no longer the spam ceiling.

Historical: this module scaled the minimum relay fee linearly from a
base to a ceiling as mempool utilization rose, on the theory that
expensive fees under load would price out spam.

Current model (see CLAUDE.md "Fee model"): the spam ceiling is
delivered by block cadence + per-block byte budget, not per-tx fee
inflation.  Every tx pays a flat ``MARKET_FEE_FLOOR`` (=1); the market
sets the price above the floor via fee-per-byte selection priority.

The class is retained as a no-op so existing constructor-arg callers
(tests, older operator scripts) keep importing cleanly.  ``base_fee``
and ``max_fee`` are accepted but ignored — ``get_min_relay_fee`` now
always returns ``MARKET_FEE_FLOOR``.
"""

from messagechain.config import MARKET_FEE_FLOOR


class DynamicFeePolicy:
    """No-op shim around the flat MARKET_FEE_FLOOR admission floor.

    Old callers passed ``base_fee`` / ``max_fee`` to tune a linear
    pressure curve; both are now accepted-and-ignored.  The relay
    floor is the same flat ``MARKET_FEE_FLOOR`` consensus enforces
    post-Tier-16, regardless of mempool utilization.
    """

    def __init__(self, base_fee: int = MARKET_FEE_FLOOR, max_fee: int = MARKET_FEE_FLOOR):
        # Retained as instance attrs only because some test asserts
        # introspect them.  They have no effect on fee logic.
        self.base_fee = base_fee
        self.max_fee = max_fee

    def get_min_relay_fee(self, mempool_size: int, mempool_max: int) -> int:
        """Always returns the flat ``MARKET_FEE_FLOOR``.

        ``mempool_size`` and ``mempool_max`` are accepted for
        signature stability but no longer influence the floor —
        spam discipline is delivered by block cadence + byte budget.
        """
        return MARKET_FEE_FLOOR
