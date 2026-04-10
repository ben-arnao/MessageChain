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
from collections import defaultdict
from messagechain.config import MEMPOOL_MAX_SIZE, MEMPOOL_TX_TTL, MEMPOOL_PER_SENDER_LIMIT, MEMPOOL_MAX_ANCESTORS
from messagechain.core.transaction import MessageTransaction


class Mempool:
    """Pool of validated transactions, ordered by fee for block inclusion."""

    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE, tx_ttl: int = MEMPOOL_TX_TTL,
                 per_sender_limit: int = MEMPOOL_PER_SENDER_LIMIT):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx
        self._sender_counts: dict[bytes, int] = defaultdict(int)  # entity_id -> count
        self.max_size = max_size
        self.tx_ttl = tx_ttl
        self.per_sender_limit = per_sender_limit

    def add_transaction(self, tx: MessageTransaction) -> bool:
        """
        Add a transaction to the mempool if not already present.

        Enforces per-sender limits and global size limits. If the mempool is
        full, the transaction is accepted only if its fee exceeds the
        lowest-fee transaction currently in the pool.
        """
        if tx.tx_hash in self.pending:
            return False

        # Reject expired transactions on arrival
        if self._is_expired(tx):
            return False

        # Per-sender ancestor limit: prevent deep unconfirmed chains (BTC-style)
        if self._sender_counts[tx.entity_id] >= min(self.per_sender_limit, MEMPOOL_MAX_ANCESTORS):
            return False

        if len(self.pending) >= self.max_size:
            # Find the lowest-fee transaction
            min_tx = min(self.pending.values(), key=lambda t: t.fee)
            if tx.fee <= min_tx.fee:
                return False  # new tx doesn't beat the worst in pool
            # Evict lowest-fee tx
            self._remove_tx(min_tx)

        self.pending[tx.tx_hash] = tx
        self._sender_counts[tx.entity_id] += 1
        return True

    def get_transactions(self, max_count: int) -> list[MessageTransaction]:
        """
        Get transactions ordered by fee (highest first) — BTC-style.

        Block proposers call this to fill blocks with the most profitable
        transactions. Users who want faster inclusion bid higher fees.
        """
        txs = sorted(self.pending.values(), key=lambda t: t.fee, reverse=True)
        return txs[:max_count]

    def _remove_tx(self, tx: MessageTransaction):
        """Remove a single transaction and update sender count."""
        if tx.tx_hash in self.pending:
            del self.pending[tx.tx_hash]
            self._sender_counts[tx.entity_id] = max(0, self._sender_counts[tx.entity_id] - 1)
            if self._sender_counts[tx.entity_id] == 0:
                del self._sender_counts[tx.entity_id]

    def remove_transactions(self, tx_hashes: list[bytes]):
        """Remove transactions after they've been included in a block."""
        for h in tx_hashes:
            tx = self.pending.get(h)
            if tx:
                self._remove_tx(tx)

    def expire_transactions(self) -> int:
        """
        Remove transactions that have exceeded the TTL.

        Returns the number of expired transactions removed.
        """
        now = time.time()
        expired = [
            tx for tx in self.pending.values()
            if now - tx.timestamp > self.tx_ttl
        ]
        for tx in expired:
            self._remove_tx(tx)
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
