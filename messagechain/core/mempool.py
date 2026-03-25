"""
Transaction mempool with fee-based priority (BTC-style).

Transactions with higher fees are prioritized for block inclusion.
This creates a free market for block space — users bid what they're
willing to pay, and validators include the most profitable transactions first.

Now supports:
- Maximum size with lowest-fee eviction when full
- Transaction expiry (TTL) — old transactions are pruned automatically
"""

import time
from messagechain.config import MEMPOOL_MAX_SIZE, MEMPOOL_TX_TTL
from messagechain.core.transaction import MessageTransaction


class Mempool:
    """Pool of validated transactions, ordered by fee for block inclusion."""

    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE, tx_ttl: int = MEMPOOL_TX_TTL):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx
        self.max_size = max_size
        self.tx_ttl = tx_ttl

    def add_transaction(self, tx: MessageTransaction) -> bool:
        """
        Add a transaction to the mempool if not already present.

        If the mempool is full, the transaction is accepted only if its fee
        exceeds the lowest-fee transaction currently in the pool. The lowest-fee
        transaction is evicted to make room.
        """
        if tx.tx_hash in self.pending:
            return False

        # Reject expired transactions on arrival
        if self._is_expired(tx):
            return False

        if len(self.pending) >= self.max_size:
            # Find the lowest-fee transaction
            min_tx = min(self.pending.values(), key=lambda t: t.fee)
            if tx.fee <= min_tx.fee:
                return False  # new tx doesn't beat the worst in pool
            # Evict lowest-fee tx
            del self.pending[min_tx.tx_hash]

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

    def expire_transactions(self) -> int:
        """
        Remove transactions that have exceeded the TTL.

        Returns the number of expired transactions removed.
        """
        now = time.time()
        expired = [
            tx_hash for tx_hash, tx in self.pending.items()
            if now - tx.timestamp > self.tx_ttl
        ]
        for tx_hash in expired:
            del self.pending[tx_hash]
        return len(expired)

    def _is_expired(self, tx: MessageTransaction) -> bool:
        """Check if a transaction has exceeded its TTL."""
        return time.time() - tx.timestamp > self.tx_ttl

    def get_fee_estimate(self) -> int:
        """Estimate fee needed to get into the next block (median of pending)."""
        if not self.pending:
            return 1
        fees = sorted([tx.fee for tx in self.pending.values()], reverse=True)
        return fees[len(fees) // 2]

    @property
    def size(self) -> int:
        return len(self.pending)
