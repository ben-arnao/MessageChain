"""
Transaction mempool with fee-based priority (BTC-style).

Transactions with higher fees are prioritized for block inclusion.
This creates a free market for block space — users bid what they're
willing to pay, and validators include the most profitable transactions first.

Now supports:
- Maximum size with lowest-fee eviction when full
- Transaction expiry (TTL) — old transactions are pruned automatically
"""

import os
import time
from collections import defaultdict
from messagechain.config import (
    MEMPOOL_MAX_SIZE, MEMPOOL_TX_TTL, MEMPOOL_PER_SENDER_LIMIT,
    MEMPOOL_MAX_ANCESTORS, MEMPOOL_MAX_ORPHAN_TXS,
    MEMPOOL_MAX_ORPHAN_PER_SENDER, MEMPOOL_MAX_ORPHAN_NONCE_GAP,
    MIN_FEE,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy


class Mempool:
    """Pool of validated transactions, ordered by fee for block inclusion."""

    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE, tx_ttl: int = MEMPOOL_TX_TTL,
                 per_sender_limit: int = MEMPOOL_PER_SENDER_LIMIT,
                 fee_policy: DynamicFeePolicy | None = None):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx
        self._sender_counts: dict[bytes, int] = defaultdict(int)  # entity_id -> count
        self.max_size = max_size
        self.tx_ttl = tx_ttl
        self.per_sender_limit = per_sender_limit
        # M4: Dynamic fee policy — scales min relay fee with mempool pressure
        self.fee_policy = fee_policy or DynamicFeePolicy(base_fee=MIN_FEE, max_fee=10_000)
        # Orphan pool: holds txs with future nonces (out-of-order arrival)
        self.orphan_pool: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx
        self._orphan_sender_counts: dict[bytes, int] = defaultdict(int)
        # Slash pool: holds SlashTransactions received via ANNOUNCE_SLASH
        # gossip so the next time *this* node proposes a block, it can
        # include them. Without this pool, slash txs validated and relayed
        # by non-proposer witnesses are never included in any block — the
        # slashing finder's-reward incentive collapses because only the
        # witness who happens to be the next proposer can collect.
        self.slash_pool: dict[bytes, object] = {}  # tx_hash -> SlashTransaction
        # Hard cap on the slash pool. Slash txs are small and rare; a
        # cap this low is generous but keeps this from becoming a DoS
        # vector if an attacker spams fake slash announcements.
        self.slash_pool_max_size: int = 1000

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

        # M4: Enforce dynamic minimum relay fee based on mempool pressure
        min_relay_fee = self.fee_policy.get_min_relay_fee(len(self.pending), self.max_size)
        if tx.fee < min_relay_fee:
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

    def try_replace_by_fee(
        self, new_tx: MessageTransaction, public_key: bytes | None = None,
    ) -> bool:
        """Replace an existing unconfirmed transaction with a higher-fee version.

        BIP 125-style RBF: the new transaction must have the same sender and
        nonce as an existing mempool transaction, and a strictly higher fee.
        The replacement must also have a valid signature to prevent censorship
        attacks where an attacker evicts valid txns with unsigned replacements.

        Returns True if replacement succeeded, False otherwise.
        """
        # Find existing tx from same sender with same nonce
        existing = None
        for tx in self.pending.values():
            if tx.entity_id == new_tx.entity_id and tx.nonce == new_tx.nonce:
                existing = tx
                break

        if existing is None:
            return False  # nothing to replace

        if new_tx.fee <= existing.fee:
            return False  # new fee must be strictly higher

        # Verify signature on the replacement (prevents censorship via
        # unsigned replacements that evict valid transactions)
        if public_key is not None:
            from messagechain.core.transaction import verify_transaction
            if not verify_transaction(new_tx, public_key):
                return False

        # Remove old, add new
        self._remove_tx(existing)
        self.pending[new_tx.tx_hash] = new_tx
        self._sender_counts[new_tx.entity_id] += 1
        return True

    def get_fee_estimate(self) -> int:
        """Estimate fee needed to get into the next block (median of pending)."""
        if not self.pending:
            return 1
        fees = sorted([tx.fee for tx in self.pending.values()], reverse=True)
        return fees[len(fees) // 2]

    def save_to_file(self, path: str) -> int:
        """Save mempool contents to disk for persistence across restarts.

        Returns the number of transactions saved.
        """
        import json
        txs = [tx.serialize() for tx in self.pending.values()]
        try:
            with open(path, "w") as f:
                json.dump(txs, f)
            return len(txs)
        except Exception:
            return 0

    def load_from_file(self, path: str) -> int:
        """Load mempool contents from disk.

        Skips expired transactions and corrupt entries.
        Returns the number of transactions loaded.
        """
        import json
        try:
            with open(path, "r") as f:
                txs_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0

        loaded = 0
        for tx_data in txs_data:
            try:
                tx = MessageTransaction.deserialize(tx_data)
                if self.add_transaction(tx):
                    loaded += 1
            except Exception:
                continue  # skip corrupt entries
        return loaded

    def add_orphan_tx(self, tx: MessageTransaction, expected_nonce: int) -> bool:
        """Add a transaction with a future nonce to the orphan pool.

        Only accepts transactions within MEMPOOL_MAX_ORPHAN_NONCE_GAP of the
        expected nonce. Enforces per-sender and global limits.

        Returns True if the tx was accepted into the orphan pool.
        """
        if tx.tx_hash in self.orphan_pool:
            return False

        # Reject if nonce gap is too large
        gap = tx.nonce - expected_nonce
        if gap <= 0 or gap > MEMPOOL_MAX_ORPHAN_NONCE_GAP:
            return False

        # Per-sender limit
        if self._orphan_sender_counts[tx.entity_id] >= MEMPOOL_MAX_ORPHAN_PER_SENDER:
            return False

        # Global limit — random eviction when full. Rejecting new entries
        # outright lets an early attacker lock honest orphans out of the
        # pool; random eviction matches Bitcoin Core's approach and keeps
        # the pool rotating under adversarial pressure.
        if len(self.orphan_pool) >= MEMPOOL_MAX_ORPHAN_TXS:
            # os.urandom for unpredictability — an attacker should not be
            # able to predict which entries will be evicted.
            victim_idx = int.from_bytes(os.urandom(4), "big") % len(self.orphan_pool)
            victim_hash = list(self.orphan_pool.keys())[victim_idx]
            victim_tx = self.orphan_pool.pop(victim_hash)
            self._orphan_sender_counts[victim_tx.entity_id] = max(
                0, self._orphan_sender_counts[victim_tx.entity_id] - 1
            )
            if self._orphan_sender_counts[victim_tx.entity_id] == 0:
                del self._orphan_sender_counts[victim_tx.entity_id]

        self.orphan_pool[tx.tx_hash] = tx
        self._orphan_sender_counts[tx.entity_id] += 1
        return True

    def promote_orphans(self, entity_id: bytes, new_nonce: int) -> list[MessageTransaction]:
        """Promote orphan txs whose nonce gap has been filled.

        Called when a transaction is confirmed or added to the main pool,
        advancing the expected nonce for an entity. Returns the list of
        promoted transactions (caller should add them to main pool).
        """
        promoted = []
        to_remove = []
        for tx_hash, tx in self.orphan_pool.items():
            if tx.entity_id == entity_id and tx.nonce == new_nonce:
                promoted.append(tx)
                to_remove.append(tx_hash)

        for tx_hash in to_remove:
            tx = self.orphan_pool.pop(tx_hash)
            self._orphan_sender_counts[tx.entity_id] = max(
                0, self._orphan_sender_counts[tx.entity_id] - 1
            )
            if self._orphan_sender_counts[tx.entity_id] == 0:
                del self._orphan_sender_counts[tx.entity_id]

        return promoted

    def expire_orphans(self) -> int:
        """Remove expired orphan transactions. Returns count removed."""
        now = time.time()
        expired = [
            tx_hash for tx_hash, tx in self.orphan_pool.items()
            if now - tx.timestamp > self.tx_ttl
        ]
        for tx_hash in expired:
            tx = self.orphan_pool.pop(tx_hash)
            self._orphan_sender_counts[tx.entity_id] = max(
                0, self._orphan_sender_counts[tx.entity_id] - 1
            )
            if self._orphan_sender_counts[tx.entity_id] == 0:
                del self._orphan_sender_counts[tx.entity_id]
        return len(expired)

    def add_slash_transaction(self, slash_tx) -> bool:
        """Add a validated SlashTransaction to the slash pool.

        Returns True on insertion, False if the tx is already present or
        the pool is full. The pool is intentionally simple — slash txs
        are rare and high-value, so we accept strict FIFO (refuse new
        entries when full) rather than build another eviction scheme.
        """
        if slash_tx.tx_hash in self.slash_pool:
            return False
        if len(self.slash_pool) >= self.slash_pool_max_size:
            return False
        self.slash_pool[slash_tx.tx_hash] = slash_tx
        return True

    def get_slash_transactions(self, max_count: int | None = None) -> list:
        """Return pending slash transactions for inclusion in a new block."""
        items = list(self.slash_pool.values())
        if max_count is not None:
            items = items[:max_count]
        return items

    def remove_slash_transactions(self, tx_hashes: list[bytes]):
        """Remove slash txs after they've been included in a block."""
        for h in tx_hashes:
            self.slash_pool.pop(h, None)

    @property
    def size(self) -> int:
        return len(self.pending)
