"""
Transaction mempool with fee-per-byte priority.

Block inclusion is ranked by `fee / len(message)` (fee density), not
absolute fee.  The block byte budget (`MAX_BLOCK_MESSAGE_BYTES`) is the
binding constraint on space, so the proposer-revenue-maximizing policy
is greedy knapsack on fee density — a small high-density tx beats a
large tx that pays more in absolute terms but less per byte.

Selecting on absolute fee would systematically prefer larger txs just
because they carry a bigger sticker fee, even when smaller txs offer
the network more revenue per byte of permanent storage they pin.

Now supports:
- Maximum size with lowest-fee eviction when full
- Transaction expiry (TTL) — old transactions are pruned automatically
"""

import os
import secrets
import time
from collections import defaultdict
from messagechain.config import (
    MEMPOOL_MAX_SIZE, MEMPOOL_TX_TTL, MEMPOOL_PER_SENDER_LIMIT,
    MEMPOOL_MAX_ANCESTORS, MEMPOOL_MAX_ORPHAN_TXS,
    MEMPOOL_MAX_ORPHAN_PER_SENDER, MEMPOOL_MAX_ORPHAN_NONCE_GAP,
    MIN_FEE,
    FORCED_INCLUSION_WAIT_BLOCKS, FORCED_INCLUSION_SET_SIZE,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
)
from messagechain.core.transaction import MessageTransaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy


def _fee_per_byte(tx: MessageTransaction) -> float:
    """Selection priority: fee divided by stored message bytes.

    The block byte budget is the binding constraint on inclusion, so
    revenue-per-byte is the right ranking — not absolute fee.  Empty
    messages cannot occur in practice (validator rejects len==0), but
    we guard against div-by-zero defensively.
    """
    return tx.fee / max(1, len(tx.message))


class Mempool:
    """Pool of validated transactions, ordered by fee-per-byte for inclusion."""

    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE, tx_ttl: int = MEMPOOL_TX_TTL,
                 per_sender_limit: int = MEMPOOL_PER_SENDER_LIMIT,
                 fee_policy: DynamicFeePolicy | None = None):
        self.pending: dict[bytes, MessageTransaction] = {}  # tx_hash -> tx
        self._sender_counts: dict[bytes, int] = defaultdict(int)  # entity_id -> count
        # Block height at which each tx first entered THIS mempool.  Used by
        # the forced-inclusion censorship-resistance check: txs that have
        # been pending for >= FORCED_INCLUSION_WAIT_BLOCKS are eligible to
        # appear in the top-N "forced" set that a proposer must include or
        # justify via a structural excuse.  This is per-node subjective (no
        # two nodes necessarily agree on arrival height), which is why the
        # enforcement is attester-layer soft, not block-validity hard.
        self.arrival_heights: dict[bytes, int] = {}
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
        # Finality vote pool: holds FinalityVotes received via
        # ANNOUNCE_FINALITY_VOTE gossip so the next time *this* node
        # proposes a block, it can include them and collect the
        # FINALITY_VOTE_INCLUSION_REWARD.  Same shape as slash_pool;
        # dedupe key is the vote's consensus_hash (not tx_hash, since
        # FinalityVote is not a transaction).
        self.finality_pool: dict[bytes, object] = {}  # consensus_hash -> FinalityVote
        # Hard cap — finality votes are small and arrive roughly once
        # per FINALITY_INTERVAL per validator.  A cap this high lets
        # a moderately large validator set fully gossip a checkpoint
        # without eviction, yet bounds memory against spam.
        self.finality_pool_max_size: int = 2000
        # Censorship-evidence pool: CensorshipEvidenceTx objects
        # awaiting block inclusion.  Shape mirrors slash_pool — small,
        # rare, high-value messages.  Drained by the proposer into
        # the next block's censorship_evidence_txs slot.
        self.censorship_evidence_pool: dict[bytes, object] = {}
        self.censorship_evidence_pool_max_size: int = 1000
        # Tier 17 ReactTransaction pool: keyed by tx_hash so identical
        # (voter, target, choice, nonce, timestamp) txs dedupe at the
        # mempool boundary.  Shape mirrors slash_pool — strict FIFO,
        # no fee-density eviction (the per-tx byte payload is tiny
        # and uniform across votes; ranking by fee/byte adds little).
        # Drained by the proposer into the next block's
        # react_transactions slot via `get_react_transactions`.
        self.react_pool: dict[bytes, object] = {}
        self.react_pool_max_size: int = 10_000

    def add_transaction(
        self,
        tx: MessageTransaction,
        arrival_block_height: int | None = None,
    ) -> bool:
        """
        Add a transaction to the mempool if not already present.

        Enforces per-sender limits and global size limits. If the mempool is
        full, the transaction is accepted only if its fee exceeds the
        lowest-fee transaction currently in the pool.

        `arrival_block_height` records the block height at which this node
        first saw the tx.  Used by the forced-inclusion rule to measure how
        many blocks a tx has been waiting.  Defaults to 0 — a height of 0
        means the tx has "always been here" and qualifies for forced
        inclusion immediately.  Production callers should pass the current
        chain height so a long-waited tx can be distinguished from a fresh
        arrival.
        """
        if tx.tx_hash in self.pending:
            return False

        # Reject expired transactions on arrival
        if self._is_expired(tx):
            return False

        # WOTS+ leaf-reuse defense at admission: if another pending tx from
        # the same entity already uses this leaf_index, reject. Without this
        # guard, two rapid sends from the same wallet (same watermark
        # observation) can both slip through validate_transaction (chain
        # state hasn't bumped yet) and force the block-level dedupe to
        # reject the WHOLE block. Catching it here errors the client
        # immediately on the second attempt instead.
        incoming_leaf = tx.signature.leaf_index
        for existing in self.pending.values():
            if (existing.entity_id == tx.entity_id
                    and existing.signature.leaf_index == incoming_leaf):
                return False

        # M4: Enforce dynamic minimum relay fee based on mempool pressure
        min_relay_fee = self.fee_policy.get_min_relay_fee(len(self.pending), self.max_size)
        if tx.fee < min_relay_fee:
            return False

        # Per-sender ancestor limit: prevent deep unconfirmed chains (BTC-style)
        if self._sender_counts[tx.entity_id] >= min(self.per_sender_limit, MEMPOOL_MAX_ANCESTORS):
            return False

        if len(self.pending) >= self.max_size:
            # Evict the lowest fee-per-byte tx — same priority axis used
            # for block inclusion, so a tx admitted here is one the next
            # proposer would actually pick over what's being kicked out.
            min_tx = min(self.pending.values(), key=_fee_per_byte)
            if _fee_per_byte(tx) <= _fee_per_byte(min_tx):
                return False  # new tx doesn't beat the worst density in pool
            self._remove_tx(min_tx)

        self.pending[tx.tx_hash] = tx
        self._sender_counts[tx.entity_id] += 1
        self.arrival_heights[tx.tx_hash] = (
            arrival_block_height if arrival_block_height is not None else 0
        )
        return True

    def get_transactions(self, max_count: int) -> list[MessageTransaction]:
        """
        Get transactions ordered by fee-per-byte (highest density first).

        Block proposers call this to fill blocks with the highest-revenue
        density transactions under the per-block byte budget.  Users who
        want faster inclusion bid a higher fee relative to their message
        size — a 200-byte tx paying fee=199 beats a 1024-byte tx paying
        fee=200 because it claims fewer bytes of the budget per unit fee.
        """
        txs = sorted(self.pending.values(), key=_fee_per_byte, reverse=True)
        return txs[:max_count]

    def get_transactions_with_entity_cap(
        self, max_count: int,
    ) -> list[MessageTransaction]:
        """Get transactions respecting the per-entity cap.

        Sorted by fee-per-byte (highest density first).  After including
        MAX_TXS_PER_ENTITY_PER_BLOCK txs from any single entity_id,
        further txs from that entity are skipped — even if they have
        higher fee density than txs from other entities.
        """
        txs = sorted(self.pending.values(), key=_fee_per_byte, reverse=True)
        selected: list[MessageTransaction] = []
        entity_counts: dict[bytes, int] = {}
        for tx in txs:
            if len(selected) >= max_count:
                break
            count = entity_counts.get(tx.entity_id, 0)
            if count >= MAX_TXS_PER_ENTITY_PER_BLOCK:
                continue
            selected.append(tx)
            entity_counts[tx.entity_id] = count + 1
        return selected

    def get_forced_inclusion_set(
        self, current_block_height: int,
    ) -> list[MessageTransaction]:
        """Return the top-N highest fee-per-byte txs that have waited >= K blocks.

        The attester-enforced censorship-resistance rule: these are the txs
        the NEXT proposer MUST include (or provide a valid structural
        excuse for omitting).  Ranking is deterministic on a single node:
            1. Fee-per-byte descending (matches normal selection priority)
            2. Arrival height ascending (earlier waiter wins tie)
            3. tx_hash ascending (final deterministic tiebreak)

        Different nodes can see different mempools — that's fine.  Soft
        attester voting converges on the honest subset; see
        messagechain.consensus.forced_inclusion for the enforcement path.
        """
        cutoff = current_block_height - FORCED_INCLUSION_WAIT_BLOCKS
        qualifying = [
            tx for tx in self.pending.values()
            if self.arrival_heights.get(tx.tx_hash, 0) <= cutoff
        ]
        qualifying.sort(
            key=lambda t: (
                -_fee_per_byte(t),
                self.arrival_heights.get(t.tx_hash, 0),
                t.tx_hash,
            )
        )
        return qualifying[:FORCED_INCLUSION_SET_SIZE]

    def get_pending_nonce(self, entity_id: bytes, on_chain_nonce: int) -> int:
        """Return the next expected nonce for *entity_id* considering mempool txs.

        Scans pending transactions for the highest nonce from this entity
        that is >= on_chain_nonce.  If any are found, returns max_nonce + 1.
        Otherwise returns on_chain_nonce unchanged.
        """
        max_nonce = on_chain_nonce - 1  # sentinel: below on_chain
        for tx in self.pending.values():
            if tx.entity_id == entity_id and tx.nonce >= on_chain_nonce:
                if tx.nonce > max_nonce:
                    max_nonce = tx.nonce
        if max_nonce >= on_chain_nonce:
            return max_nonce + 1
        return on_chain_nonce

    def _remove_tx(self, tx: MessageTransaction):
        """Remove a single transaction and update sender count."""
        if tx.tx_hash in self.pending:
            del self.pending[tx.tx_hash]
            self._sender_counts[tx.entity_id] = max(0, self._sender_counts[tx.entity_id] - 1)
            if self._sender_counts[tx.entity_id] == 0:
                del self._sender_counts[tx.entity_id]
        self.arrival_heights.pop(tx.tx_hash, None)

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
        self,
        new_tx: MessageTransaction,
        public_key: bytes | None = None,
        current_height: int | None = None,
    ) -> bool:
        """Replace an existing unconfirmed transaction with a higher fee-per-byte version.

        RBF: the new transaction must have the same sender and nonce as an
        existing mempool transaction, and strictly higher fee-per-byte
        density.  This matches the block-inclusion priority — a replacement
        is only accepted if the proposer would actually prefer it.  The
        replacement must also have a valid signature to prevent censorship
        attacks where an attacker evicts valid txns with unsigned replacements.

        ``current_height`` MUST be the current chain tip so the signature
        check uses the same fee rule consensus is enforcing.  Omitting it
        routes through the legacy quadratic floor, which rejects
        LINEAR-era low-fee replacements that are perfectly valid on-chain.

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

        if _fee_per_byte(new_tx) <= _fee_per_byte(existing):
            return False  # new fee-per-byte density must be strictly higher

        # Verify signature on the replacement (prevents censorship via
        # unsigned replacements that evict valid transactions).
        # public_key is REQUIRED — reject if not provided.
        if public_key is None:
            return False
        from messagechain.core.transaction import verify_transaction
        if not verify_transaction(
            new_tx, public_key, current_height=current_height,
        ):
            return False

        # Remove old, add new.  Carry the original arrival height forward
        # so RBF replacements don't reset the forced-inclusion clock (an
        # attacker should not be able to cancel a pending censorship duty
        # by spamming trivial fee bumps).
        prior_arrival = self.arrival_heights.get(existing.tx_hash, 0)
        self._remove_tx(existing)
        self.pending[new_tx.tx_hash] = new_tx
        self._sender_counts[new_tx.entity_id] += 1
        self.arrival_heights[new_tx.tx_hash] = prior_arrival
        return True

    def get_fee_estimate(self) -> int:
        """Estimate fee needed to get into the next block.

        Returns the median fee of pending txs, floored at MIN_FEE. Never
        suggests a value the chain would reject. Message txs have an
        additional size-dependent minimum (see calculate_min_fee); clients
        should use max(this, local_min) for their actual fee.
        """
        from messagechain.config import MIN_FEE
        if not self.pending:
            return MIN_FEE
        fees = sorted([tx.fee for tx in self.pending.values()], reverse=True)
        return max(MIN_FEE, fees[len(fees) // 2])

    # save_to_file / load_from_file exist so operator tooling (and our
    # own test suite) can round-trip a pending-pool snapshot for debug
    # / forensic dumps.  They are deliberately NOT wired into server
    # startup / shutdown: a persisted mempool would replay stale txs
    # against a chain that moved forward (wrong nonce, stale fee
    # estimate, or already-confirmed tx), so the operational rule is
    # "on restart, pending txs are rebroadcast by their original
    # senders."  Keep both methods available for manual ops but do not
    # add an auto-load.
    def save_to_file(self, path: str) -> int:
        """Serialize the pending-message pool to disk for manual ops
        snapshots (forensics, debugging).  NOT auto-called by the
        server — see module comment for why.  Returns the number of
        transactions saved."""
        import json
        txs = [tx.serialize() for tx in self.pending.values()]
        try:
            with open(path, "w") as f:
                json.dump(txs, f)
            return len(txs)
        except Exception:
            return 0

    def load_from_file(self, path: str) -> int:
        """Reload a previously-saved pending-message pool.  Same caveat
        as save_to_file: not invoked by the server.  Returns the number
        loaded."""
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
            # secrets.choice gives an unbiased pick from the current
            # key set without the modulo-bias that `os.urandom(4) % n`
            # introduces — and crucially without exposing the attacker a
            # modulo-predictable mapping from a 32-bit draw to a victim
            # index.
            victim_hash = secrets.choice(list(self.orphan_pool.keys()))
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

    # ── Finality vote pool ───────────────────────────────────────

    def add_finality_vote(self, vote) -> bool:
        """Add a validated FinalityVote to the finality pool.

        Returns True on insertion, False if the vote is already
        present or the pool is full.  Keyed by consensus_hash so a
        peer can't silently dislodge an existing vote by re-sending
        a structurally-identical one.
        """
        key = vote.consensus_hash()
        if key in self.finality_pool:
            return False
        if len(self.finality_pool) >= self.finality_pool_max_size:
            return False
        self.finality_pool[key] = vote
        return True

    def get_finality_votes(self, max_count: int | None = None) -> list:
        """Return pending finality votes for inclusion in a new block."""
        items = list(self.finality_pool.values())
        if max_count is not None:
            items = items[:max_count]
        return items

    def remove_finality_votes(self, keys: list[bytes]):
        """Remove finality votes after inclusion in a block."""
        for k in keys:
            self.finality_pool.pop(k, None)

    # ── Censorship-evidence pool ─────────────────────────────────

    def add_censorship_evidence_tx(self, tx) -> bool:
        """Admit a CensorshipEvidenceTx into the pool.

        Returns True on insertion, False if the tx is already present
        or the pool is full.  No fee-based eviction — evidence txs
        are small and rare.  Strict FIFO (refuse new entries when
        full).
        """
        if tx.tx_hash in self.censorship_evidence_pool:
            return False
        if len(self.censorship_evidence_pool) >= self.censorship_evidence_pool_max_size:
            return False
        if tx.fee < MIN_FEE:
            return False
        self.censorship_evidence_pool[tx.tx_hash] = tx
        return True

    def get_censorship_evidence_txs(self, max_count: int | None = None) -> list:
        items = list(self.censorship_evidence_pool.values())
        if max_count is not None:
            items = items[:max_count]
        return items

    def remove_censorship_evidence_txs(self, tx_hashes: list[bytes]):
        for h in tx_hashes:
            self.censorship_evidence_pool.pop(h, None)

    # ── Tier 17 ReactTransaction pool ────────────────────────────

    def add_react_transaction(self, tx) -> bool:
        """Admit a ReactTransaction into the pool.

        Returns True on insertion, False if the tx is already present
        or the pool is full.  Strict FIFO — no fee-density eviction.

        The caller must run signature / target-existence / activation-
        gate checks before this call (see `verify_react_transaction`
        + the chain-side checks in `validate_block`); the mempool only
        enforces dedup, the protocol fee floor, and the cap.  This
        mirrors how the message-tx pool admits a tx after the RPC
        validate has succeeded — the mempool itself isn't a second
        verifier.
        """
        if tx.tx_hash in self.react_pool:
            return False
        if len(self.react_pool) >= self.react_pool_max_size:
            return False
        if tx.fee < MIN_FEE:
            return False
        self.react_pool[tx.tx_hash] = tx
        return True

    def get_react_transactions(self, max_count: int | None = None) -> list:
        """Return pending ReactTransactions for inclusion in a new block."""
        items = list(self.react_pool.values())
        if max_count is not None:
            items = items[:max_count]
        return items

    def remove_react_transactions(self, tx_hashes: list[bytes]):
        """Remove react txs after inclusion in a block."""
        for h in tx_hashes:
            self.react_pool.pop(h, None)

    @property
    def size(self) -> int:
        return len(self.pending)
