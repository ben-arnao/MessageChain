"""
Transaction mempool with fee-based priority (BTC-style).

Transactions with higher fees are prioritized for block inclusion.
This creates a free market for block space — users bid what they're
willing to pay, and validators include the most profitable transactions first.
"""

from messagechain.core.transaction import MessageTransaction


class Mempool:
    """Pool of validated transactions, ordered by fee for block inclusion."""

    def __init__(self):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx

    def add_transaction(self, tx: MessageTransaction) -> bool:
        """Add a transaction to the mempool if not already present."""
        if tx.tx_hash in self.pending:
            return False
        self.pending[tx.tx_hash] = tx
        return True

    def get_transactions(self, max_count: int) -> list[MessageTransaction]:
        """
        Get transactions ordered by fee (highest first) — BTC-style.

        Block proposers call this to fill blocks with the most profitable
        transactions. Users who want faster inclusion bid higher fees.
        """
        txs = sorted(self.pending.values(), key=lambda t: t.fee, reverse=True)
        return txs[:max_count]

    def remove_transactions(self, tx_hashes: list[bytes]):
        """Remove transactions after they've been included in a block."""
        for h in tx_hashes:
            self.pending.pop(h, None)

    def get_fee_estimate(self) -> int:
        """Estimate fee needed to get into the next block (median of pending)."""
        if not self.pending:
            return 1
        fees = sorted([tx.fee for tx in self.pending.values()], reverse=True)
        return fees[len(fees) // 2]

    @property
    def size(self) -> int:
        return len(self.pending)
