"""
Transaction mempool - holds pending transactions before block inclusion.
"""

from messagechain.core.transaction import MessageTransaction


class Mempool:
    """Pool of validated transactions waiting to be included in a block."""

    def __init__(self):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx

    def add_transaction(self, tx: MessageTransaction) -> bool:
        """Add a transaction to the mempool if not already present."""
        if tx.tx_hash in self.pending:
            return False
        self.pending[tx.tx_hash] = tx
        return True

    def get_transactions(self, max_count: int) -> list[MessageTransaction]:
        """Get transactions ordered by timestamp, up to max_count."""
        txs = sorted(self.pending.values(), key=lambda t: t.timestamp)
        return txs[:max_count]

    def remove_transactions(self, tx_hashes: list[bytes]):
        """Remove transactions after they've been included in a block."""
        for h in tx_hashes:
            self.pending.pop(h, None)

    @property
    def size(self) -> int:
        return len(self.pending)
