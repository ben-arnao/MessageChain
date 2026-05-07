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
import threading
import time
from collections import defaultdict
from messagechain.config import (
    MEMPOOL_MAX_SIZE, MEMPOOL_TX_TTL, MEMPOOL_PER_SENDER_LIMIT,
    MEMPOOL_MAX_ANCESTORS, MEMPOOL_MAX_ORPHAN_TXS,
    MEMPOOL_MAX_ORPHAN_PER_SENDER, MEMPOOL_MAX_ORPHAN_NONCE_GAP,
    MIN_FEE,
    FORCED_INCLUSION_ALL_POOLS_HEIGHT,
    FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT,
    FORCED_INCLUSION_WAIT_BLOCKS, FORCED_INCLUSION_SET_SIZE,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
)


def _forced_inclusion_entity_id(tx) -> bytes | None:
    """Resolve the per-entity-cap key for a tx in the forced source set.

    Mirrors ``messagechain.consensus.forced_inclusion._entity_id_of``
    -- the forced-inclusion source set is the union of every pool kind
    once Tier 43 lands, so the per-entity tally must read whichever
    field that kind exposes (``entity_id`` for Message/Transfer/Stake/
    React, ``voter_id`` for governance votes, ``proposer_id`` for
    governance proposals, ``submitter_id`` for slash + censorship
    evidence).  Defined here as a private helper instead of importing
    from ``consensus/`` to avoid the wrong-direction module dependency
    -- mempool is below consensus in the layering.
    """
    return (
        getattr(tx, "entity_id", None)
        or getattr(tx, "voter_id", None)
        or getattr(tx, "proposer_id", None)
        or getattr(tx, "submitter_id", None)
    )
from messagechain.core.transaction import MessageTransaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy


def _stored_bytes(tx, *, cache: dict[bytes, int] | None = None) -> int:
    """Return ``len(tx.to_bytes())``, optionally cached by tx_hash.

    Mempool sorts and re-sorts often (every ``get_transactions``,
    every full-pool eviction probe, every RBF replace).  Recomputing
    the encoding on every comparison is expensive — the canonical
    encoding pulls a fresh signature blob serialization each call.
    Cache hint dict (when provided) keys by ``tx_hash`` so insert /
    eviction can populate / drop entries.
    """
    if cache is not None:
        h = getattr(tx, "tx_hash", None)
        if h is not None:
            cached = cache.get(h)
            if cached is not None:
                return cached
    try:
        n = len(tx.to_bytes())
    except Exception:
        # Defensive: a malformed tx whose to_bytes() raises shouldn't
        # crash ranking — fall back to a sentinel of 1 so ranking
        # collapses to absolute fee for that single tx instead of
        # killing the whole sort.
        return 1
    if cache is not None:
        h = getattr(tx, "tx_hash", None)
        if h is not None:
            cache[h] = n
    return n


def _fee_per_byte(tx, *, cache: dict[bytes, int] | None = None) -> float:
    """Selection priority: fee divided by STORED bytes.

    The block byte budget is the binding constraint on inclusion, so
    revenue-per-stored-byte is the right ranking — not absolute fee,
    and not fee-per-payload-byte either.  Stored bytes for any tx
    kind = ``len(tx.to_bytes())``: the actual on-disk encoding the
    chain pins forever.  This includes the WOTS+ witness, which
    dominates per-tx storage cost regardless of kind.

    Pre-fix this divided by ``len(tx.message)``, which:
      * Over-stated MessageTransaction density by ~50× (witness was
        invisible to the comparator), and
      * Collapsed non-message kinds (Transfer, Stake, Unstake,
        Governance, Authority, Slash, React) to absolute-fee ranking
        because ``getattr(tx, "message", b"")`` falls back to empty.

    A ``cache`` dict (Mempool's ``_stored_bytes`` field) memoizes
    ``len(tx.to_bytes())`` by tx_hash so the sort/comparator path
    doesn't pay the full encoding cost on every comparison.  Module-
    level callers that omit the cache (test helpers, ad-hoc
    introspection) recompute on each call — correct, just slower.
    """
    n = _stored_bytes(tx, cache=cache)
    return tx.fee / max(1, n)


class Mempool:
    """Pool of validated transactions, ordered by fee-per-byte for inclusion."""

    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE, tx_ttl: int = MEMPOOL_TX_TTL,
                 per_sender_limit: int = MEMPOOL_PER_SENDER_LIMIT,
                 fee_policy: DynamicFeePolicy | None = None):
        # Thread-safety: every method that touches mempool state acquires
        # this lock for the full duration of its read or write.  RLock
        # (not plain Lock) because some methods call sibling methods
        # while still holding the lock — e.g. `try_replace_by_fee` calls
        # `_remove_tx`, `add_transaction` calls `_remove_tx` for the
        # full-pool eviction path, `expire_transactions` calls
        # `_remove_tx` per expired tx.  Plain Lock would self-deadlock
        # in those cases; RLock allows reentrant acquisition by the
        # owning thread at the cost of a single-microsecond reentrance
        # check.  See the regression in the 1.28.3/1.28.4 to_thread
        # change — RPC submits AND block production both run on worker
        # threads, so concurrent get_transactions / add_transaction
        # races on `self.pending` raised
        # `RuntimeError: dictionary changed size during iteration` and
        # silently killed proposer slots.
        self._lock = threading.RLock()
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
        # Tier 43: arrival-height tracking for evidence txs so the
        # forced-inclusion source-side can apply the same wait-gate
        # used for messages.  Keyed by tx_hash.  Set on
        # `add_censorship_evidence_tx`; torn down on remove.  An
        # entry missing here defaults to height-0 in the source
        # walk, matching the legacy "always been here" semantics
        # of the messages-pool path when arrival_block_height is
        # not provided.
        self._evidence_arrival_heights: dict[bytes, int] = {}
        # Tier 17 ReactTransaction pool: keyed by tx_hash so identical
        # (voter, target, choice, nonce, timestamp) txs dedupe at the
        # mempool boundary.  Shape mirrors slash_pool — strict FIFO,
        # no fee-density eviction (the per-tx byte payload is tiny
        # and uniform across votes; ranking by fee/byte adds little).
        # Drained by the proposer into the next block's
        # react_transactions slot via `get_react_transactions`.
        self.react_pool: dict[bytes, object] = {}
        self.react_pool_max_size: int = 10_000
        # Tier 43 (audit fix #4): arrival-height tracking for react
        # txs so the forced-inclusion source-side can apply the same
        # wait-gate used for messages and evidence.  Keyed by tx_hash;
        # populated on `add_react_transaction` admission, torn down on
        # every removal path (full-pool fee-density eviction inside
        # `add_react_transaction`, and `remove_react_transactions` on
        # block-include drain).  An entry missing here defaults to
        # height-0 in the source walk, matching the legacy "always
        # been here" semantics — this is what makes the pre-Tier-43
        # carve-out below behave identically to the pre-fork attester
        # rule even when the source is registered.
        self._react_pool_arrival_heights: dict[bytes, int] = {}
        # Stored-byte cache for ``_fee_per_byte`` ranking.  Keys by
        # tx_hash so a single ``len(tx.to_bytes())`` call is enough
        # per tx no matter how many sort / RBF / eviction passes the
        # mempool runs over it.  Populated on insert
        # (``add_transaction`` / ``try_replace_by_fee``) and torn
        # down on remove.
        self._stored_bytes: dict[bytes, int] = {}
        # Tier 43: registered external sources for the forced-inclusion
        # source-side walk.  Each entry is a zero-arg callable returning
        # an iterable of `(tx, arrival_block_height)` pairs.  Used to
        # plug server-local pools (stake / unstake / authority /
        # governance) into the forced-inclusion rule without a circular
        # import — the server registers its pools at construction time;
        # mempool consults them post-Tier-43 only (pre-fork the list
        # is not consulted, preserving byte-identical legacy behavior).
        self._external_forced_sources: list = []
        # Mempool's own censorship-evidence pool is registered as an
        # internal source so the same code path covers it post-fork.
        # (Pre-fork the registration is silently ignored by the
        # activation gate in `get_forced_inclusion_set`.)
        self._external_forced_sources.append(
            self._iter_evidence_pool_with_arrivals,
        )
        # Tier 43 (audit fix #4): the on-mempool react pool is also
        # registered as an internal source so the source-side gate
        # covers React votes (Tier 17 trust signals) post-fork.  This
        # closes the canonical CLAUDE.md threat — a colluding majority
        # suppressing negative-review React DOWN txs without leaving
        # slashable evidence.  Pre-fork the registration is silently
        # ignored by the activation gate in `get_forced_inclusion_set`.
        self._external_forced_sources.append(
            self._iter_react_pool_with_arrivals,
        )

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
        with self._lock:
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

            # Flat admission floor — every tx must pay at least
            # MARKET_FEE_FLOOR (=1).  We no longer scale the relay floor
            # with mempool pressure: the spam ceiling is delivered by block
            # cadence + per-block byte budget, not per-tx fee inflation.
            # See CLAUDE.md "Fee model — minimum fee is 1, never 0."
            from messagechain.config import MARKET_FEE_FLOOR
            if tx.fee < MARKET_FEE_FLOOR:
                return False

            # Per-sender ancestor limit: prevent deep unconfirmed chains (BTC-style)
            if self._sender_counts[tx.entity_id] >= min(self.per_sender_limit, MEMPOOL_MAX_ANCESTORS):
                return False

            if len(self.pending) >= self.max_size:
                # Evict the lowest fee-per-byte tx — same priority axis used
                # for block inclusion, so a tx admitted here is one the next
                # proposer would actually pick over what's being kicked out.
                _key = lambda t: _fee_per_byte(t, cache=self._stored_bytes)
                min_tx = min(self.pending.values(), key=_key)
                if _key(tx) <= _key(min_tx):
                    return False  # new tx doesn't beat the worst density in pool
                self._remove_tx(min_tx)

            self.pending[tx.tx_hash] = tx
            self._sender_counts[tx.entity_id] += 1
            self.arrival_heights[tx.tx_hash] = (
                arrival_block_height if arrival_block_height is not None else 0
            )
            # Pre-populate the stored-bytes cache so the next ranking
            # pass over this tx skips the recompute.
            _stored_bytes(tx, cache=self._stored_bytes)
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
        with self._lock:
            txs = sorted(
                self.pending.values(),
                key=lambda t: _fee_per_byte(t, cache=self._stored_bytes),
                reverse=True,
            )
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
        with self._lock:
            txs = sorted(
                self.pending.values(),
                key=lambda t: _fee_per_byte(t, cache=self._stored_bytes),
                reverse=True,
            )
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

    def register_forced_inclusion_source(self, source_fn) -> None:
        """Register a callable as an extra source for the Tier-43
        forced-inclusion source-side walk.

        Tier 43 closes the source-side gap of the Tier 34 block-side
        gate.  Pre-Tier-34 the gate covered Message + Transfer
        (everything in `self.pending`); Tier 34 made the BLOCK-side
        walk multi-list; Tier 43 makes the SOURCE-side walk multi-pool.
        Server-local pools (stake / unstake / authority / governance)
        live outside `self.pending` because their admission rules need
        chain-state access the mempool deliberately does not have.
        Plugging them in via a zero-arg callable that yields
        `(tx, arrival_height)` pairs avoids a circular import at module
        load time and lets every pool retain its own arrival-height
        bookkeeping.

        `source_fn` MUST return an iterable of `(tx, arrival_height)`
        tuples each call.  Each `tx` MUST expose the same shape the
        per-byte ranker requires: `tx_hash` (bytes), `fee` (int), and
        a `to_bytes()` method (or fallback `len(tx.message)`).  Entity
        ID is read from `entity_id`, falling back to `voter_id` /
        `proposer_id` / `submitter_id` for tx kinds whose primary
        identifier uses a different name.

        Pre-Tier-43 the registered sources are silently ignored — the
        gate continues to consult only `self.pending`, preserving
        byte-identical attester behavior on every historical block.
        """
        with self._lock:
            self._external_forced_sources.append(source_fn)

    def _iter_evidence_pool_with_arrivals(self):
        """Yield `(tx, arrival_height)` pairs for the on-mempool
        censorship-evidence pool — the headline finding of the audit
        Tier 43 closes.  Missing arrival heights default to 0 (legacy
        "always been here" semantics)."""
        # Snapshot under the lock so a concurrent admit doesn't change
        # the iteration size.  Caller is `get_forced_inclusion_set`,
        # which already holds the lock — this access is safe.
        for h, tx in list(self.censorship_evidence_pool.items()):
            yield tx, self._evidence_arrival_heights.get(h, 0)

    def _iter_react_pool_with_arrivals(self):
        """Yield `(tx, arrival_height)` pairs for the on-mempool
        ReactTransaction pool.

        Tier 43 (audit fix #4): React votes live in `react_pool`,
        separate from `pending`.  Without this source-side hook a
        colluding majority could drop arbitrarily-high-fpb React
        DOWN votes (Tier 17 trust signals) without slashable
        evidence — directly enabling the canonical CLAUDE.md threat
        of a corporation suppressing negative reviews.

        Missing arrival heights default to 0 (legacy "always been
        here" semantics — immediately eligible for forced inclusion
        once the activation gate opens).  Caller is
        `get_forced_inclusion_set`, which already holds the lock.
        """
        for h, tx in list(self.react_pool.items()):
            yield tx, self._react_pool_arrival_heights.get(h, 0)

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

        Tier 43: post-fork the source set is the union of `self.pending`
        AND every registered external source (server-local stake /
        unstake / authority / governance pools, plus the on-mempool
        censorship-evidence pool registered internally at construction).
        Pre-fork the set is `self.pending` only — byte-identical to
        legacy attester behavior so historical blocks attest under the
        old rule.
        """
        with self._lock:
            cutoff = current_block_height - FORCED_INCLUSION_WAIT_BLOCKS
            qualifying: list = [
                tx for tx in self.pending.values()
                if self.arrival_heights.get(tx.tx_hash, 0) <= cutoff
            ]
            arrival_for: dict = {
                tx.tx_hash: self.arrival_heights.get(tx.tx_hash, 0)
                for tx in qualifying
            }
            # Tier 43 source-side activation gate.  Pre-fork: short-
            # circuit so the legacy single-pool path is byte-identical
            # to the pre-fork attester rule.
            if int(current_block_height) >= FORCED_INCLUSION_ALL_POOLS_HEIGHT:
                seen_hashes: set = {tx.tx_hash for tx in qualifying}
                for source_fn in self._external_forced_sources:
                    try:
                        items = list(source_fn())
                    except Exception:
                        # An external source that raises must not crash
                        # the attester duty.  A misbehaving registered
                        # callback degrades to "this source contributed
                        # nothing this round" — the same effect as a
                        # cold-loaded server with no pool entries yet.
                        continue
                    for tx, arrival in items:
                        h = getattr(tx, "tx_hash", None)
                        if h is None or h in seen_hashes:
                            continue
                        if (arrival or 0) > cutoff:
                            continue  # still inside the wait window
                        qualifying.append(tx)
                        arrival_for[h] = arrival or 0
                        seen_hashes.add(h)

            qualifying.sort(
                key=lambda t: (
                    -_fee_per_byte(t, cache=self._stored_bytes),
                    arrival_for.get(t.tx_hash, 0),
                    t.tx_hash,
                )
            )
            # Tier 64 per-entity cap on the FORCED SOURCE SET.  Pre-
            # fix a single high-stake entity could flood the mempool
            # with N high-fpb txs and occupy every forced slot,
            # evicting a censored victim's lower-fpb tx without
            # triggering any structural excuse.  Forcing more than
            # MAX_TXS_PER_ENTITY_PER_BLOCK from one entity is
            # meaningless anyway -- the proposer cannot fit them in
            # one block under the existing block-validator cap.
            # Capping at the same constant therefore denies the
            # eviction primitive while preserving every honest
            # forced-inclusion outcome.  Pre-fork (height <
            # FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT) the legacy
            # uncapped path runs byte-identically so historical
            # attester votes replay byte-identically.
            if (
                int(current_block_height)
                >= FORCED_INCLUSION_PER_ENTITY_CAP_HEIGHT
            ):
                capped: list = []
                per_entity: dict[bytes, int] = {}
                for tx in qualifying:
                    eid = _forced_inclusion_entity_id(tx)
                    if eid is None:
                        # No identifiable signer -- pass through
                        # uncapped.  Cannot cap what we can't key.
                        capped.append(tx)
                    else:
                        n = per_entity.get(eid, 0)
                        if n >= MAX_TXS_PER_ENTITY_PER_BLOCK:
                            continue
                        per_entity[eid] = n + 1
                        capped.append(tx)
                    if len(capped) >= FORCED_INCLUSION_SET_SIZE:
                        break
                return capped[:FORCED_INCLUSION_SET_SIZE]
            return qualifying[:FORCED_INCLUSION_SET_SIZE]

    def get_pending_nonce(self, entity_id: bytes, on_chain_nonce: int) -> int:
        """Return the next expected nonce for *entity_id* considering mempool txs.

        Scans pending transactions for the highest nonce from this entity
        that is >= on_chain_nonce.  If any are found, returns max_nonce + 1.
        Otherwise returns on_chain_nonce unchanged.
        """
        with self._lock:
            max_nonce = on_chain_nonce - 1  # sentinel: below on_chain
            for tx in self.pending.values():
                if tx.entity_id == entity_id and tx.nonce >= on_chain_nonce:
                    if tx.nonce > max_nonce:
                        max_nonce = tx.nonce
            if max_nonce >= on_chain_nonce:
                return max_nonce + 1
            return on_chain_nonce

    def _remove_tx(self, tx: MessageTransaction):
        """Remove a single transaction and update sender count.

        Always called from a public method that already holds
        ``self._lock``; the RLock allows the reentrant acquire below
        without self-deadlock.  Wrapping anyway keeps this method
        safe to call from any future entry point.
        """
        with self._lock:
            if tx.tx_hash in self.pending:
                del self.pending[tx.tx_hash]
                self._sender_counts[tx.entity_id] = max(0, self._sender_counts[tx.entity_id] - 1)
                if self._sender_counts[tx.entity_id] == 0:
                    del self._sender_counts[tx.entity_id]
            self.arrival_heights.pop(tx.tx_hash, None)
            # Tear down the stored-bytes cache entry — keeping stale
            # entries here would slowly leak memory across the
            # mempool's lifetime.
            self._stored_bytes.pop(tx.tx_hash, None)

    def remove_transactions(self, tx_hashes: list[bytes]):
        """Remove transactions after they've been included in a block."""
        with self._lock:
            for h in tx_hashes:
                tx = self.pending.get(h)
                if tx:
                    self._remove_tx(tx)

    def expire_transactions(self) -> int:
        """
        Remove transactions that have exceeded the TTL.

        Returns the number of expired transactions removed.
        """
        with self._lock:
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
        with self._lock:
            # Find existing tx from same sender with same nonce
            existing = None
            for tx in self.pending.values():
                if tx.entity_id == new_tx.entity_id and tx.nonce == new_tx.nonce:
                    existing = tx
                    break

            if existing is None:
                return False  # nothing to replace

            if (
                _fee_per_byte(new_tx, cache=self._stored_bytes)
                <= _fee_per_byte(existing, cache=self._stored_bytes)
            ):
                return False  # new fee-per-byte density must be strictly higher

            # Verify signature on the replacement (prevents censorship via
            # unsigned replacements that evict valid transactions).
            # public_key is REQUIRED — reject if not provided.
            if public_key is None:
                return False
            # `verify_transaction` is a pure function over (tx, pubkey,
            # height) that does not re-enter the mempool, so calling it
            # under the lock is safe and adds no deadlock surface.
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
            # Pre-populate the stored-bytes cache for the replacement.
            _stored_bytes(new_tx, cache=self._stored_bytes)
            return True

    def get_fee_estimate(
        self, message_bytes: int = 0, *, target_blocks: int = 3,
    ) -> int:
        """Estimate the absolute fee to bid for inclusion of a tx of given size.

        Walks the pending pool's fee-per-byte densities (the same axis
        the proposer ranks on for selection) and returns
        ``percentile_density × message_bytes``, floored at
        ``MARKET_FEE_FLOOR``.  ``target_blocks`` selects the percentile
        rung — the same ladder the FeeEstimator's recent-blocks path
        uses, so the wallet's auto-fee `urgency` knob produces the same
        shape regardless of which estimator backs the quote:

            target_blocks=1   → 90th percentile (high urgency)
            target_blocks=2-3 → 75th percentile (normal, default)
            target_blocks=4-5 → 60th percentile
            target_blocks=6-10→ 25th percentile
            target_blocks≥11  → 10th percentile (low urgency)

        Audit r25 #3 — pre-fix this method's signature was
        ``(self, message_bytes=0)`` (no ``target_blocks``).  The server-
        side auto-fee call wrapped its invocation in ``try/except
        TypeError`` and silently fell back to the median (50th
        percentile) on every quote, so the urgency knob was echoed in
        the result for display but never bound on the bid.  Adding the
        kwarg here closes the silent regression — every urgency level
        now produces a distinct bid, as the wallet UX promises.

        Empty mempool → returns ``MARKET_FEE_FLOOR`` (no demand signal,
        the cheapest valid fee).  ``message_bytes <= 0`` (legacy callers
        that don't yet pass a size) → also returns the floor; clients
        should pass their actual stored byte count for a useful estimate.
        """
        from messagechain.config import MARKET_FEE_FLOOR
        with self._lock:
            if not self.pending or message_bytes <= 0:
                return MARKET_FEE_FLOOR
            densities = sorted(
                _fee_per_byte(tx, cache=self._stored_bytes)
                for tx in self.pending.values()
            )
            # Percentile ladder mirrors FeeEstimator (recent-blocks
            # path) so the same target_blocks rung returns the same
            # shape from either estimator.  The unified ladder is what
            # makes the auto-fee urgency knob coherent across mempool-
            # demand-driven (this path) and historical-block-driven
            # (FeeEstimator) modes.
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
            estimate = int(density * message_bytes)
            return max(MARKET_FEE_FLOOR, estimate)

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
        # Snapshot under the lock so a concurrent mutation can't corrupt
        # the serialized list mid-iteration; the actual file write is
        # done outside the lock to avoid pinning the mempool on slow I/O.
        with self._lock:
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

        # add_transaction acquires the lock per call; we don't hold it
        # across the whole loop so concurrent block production isn't
        # blocked while a forensic dump replays.
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            if slash_tx.tx_hash in self.slash_pool:
                return False
            if len(self.slash_pool) >= self.slash_pool_max_size:
                return False
            self.slash_pool[slash_tx.tx_hash] = slash_tx
            return True

    def get_slash_transactions(self, max_count: int | None = None) -> list:
        """Return pending slash transactions for inclusion in a new block."""
        with self._lock:
            items = list(self.slash_pool.values())
            if max_count is not None:
                items = items[:max_count]
            return items

    def remove_slash_transactions(self, tx_hashes: list[bytes]):
        """Remove slash txs after they've been included in a block."""
        with self._lock:
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
        # `vote.consensus_hash()` is a pure derivation on the vote
        # object — no mempool re-entry, safe to compute under the lock
        # (and required so the membership check + insert are atomic).
        with self._lock:
            key = vote.consensus_hash()
            if key in self.finality_pool:
                return False
            if len(self.finality_pool) >= self.finality_pool_max_size:
                return False
            self.finality_pool[key] = vote
            return True

    def get_finality_votes(self, max_count: int | None = None) -> list:
        """Return pending finality votes for inclusion in a new block."""
        with self._lock:
            items = list(self.finality_pool.values())
            if max_count is not None:
                items = items[:max_count]
            return items

    def remove_finality_votes(self, keys: list[bytes]):
        """Remove finality votes after inclusion in a block."""
        with self._lock:
            for k in keys:
                self.finality_pool.pop(k, None)

    # ── Censorship-evidence pool ─────────────────────────────────

    def add_censorship_evidence_tx(
        self, tx, arrival_block_height: int | None = None,
    ) -> bool:
        """Admit a CensorshipEvidenceTx into the pool.

        Returns True on insertion, False if the tx is already present
        or the pool is full.  No fee-based eviction — evidence txs
        are small and rare.  Strict FIFO (refuse new entries when
        full).

        Tier 43: `arrival_block_height` records the block height at
        which this node first saw the evidence so the forced-
        inclusion source-side wait-gate works the same way it does
        for messages.  Defaults to 0 (legacy "always been here" —
        immediately eligible for forced inclusion); production
        callers should pass the current chain height so a long-
        waited evidence is distinguishable from a fresh arrival.
        """
        with self._lock:
            if tx.tx_hash in self.censorship_evidence_pool:
                return False
            if len(self.censorship_evidence_pool) >= self.censorship_evidence_pool_max_size:
                return False
            if tx.fee < MIN_FEE:
                return False
            self.censorship_evidence_pool[tx.tx_hash] = tx
            self._evidence_arrival_heights[tx.tx_hash] = (
                arrival_block_height
                if arrival_block_height is not None
                else 0
            )
            return True

    def get_censorship_evidence_txs(self, max_count: int | None = None) -> list:
        with self._lock:
            items = list(self.censorship_evidence_pool.values())
            if max_count is not None:
                items = items[:max_count]
            return items

    def remove_censorship_evidence_txs(self, tx_hashes: list[bytes]):
        with self._lock:
            for h in tx_hashes:
                self.censorship_evidence_pool.pop(h, None)
                self._evidence_arrival_heights.pop(h, None)

    # ── Tier 17 ReactTransaction pool ────────────────────────────

    @staticmethod
    def _react_fee_density(tx) -> float:
        """Tier 18 selection priority for ReactTx: fee divided by
        serialized byte cost (payload + WOTS+ witness).

        Witness bytes dominate (~2.7 KB) and are uniform across react
        txs, so the density collapses to absolute-fee bidding within
        the kind — but expressing it on the same axis the message-tx
        pool ranks on lets a future unified-mempool merge sort across
        kinds with one comparator.
        """
        try:
            return tx.fee / max(1, len(tx.to_bytes()))
        except Exception:
            # Defensive: a tx whose to_bytes() raises shouldn't crash
            # admission ranking — fall back to absolute fee so it
            # ranks correctly relative to its peers.
            return float(tx.fee)

    def add_react_transaction(
        self, tx, arrival_block_height: int | None = None,
    ) -> bool:
        """Admit a ReactTransaction into the pool with fee-density eviction.

        At capacity, accepts the incoming tx iff its fee density
        exceeds that of the lowest-density pending entry (which is
        evicted to make room).  Mirrors the `MessageTransaction`
        admission policy so the same auction dynamics apply to
        ReactTx — wallets that want priority bid a higher fee, the
        proposer always sees the highest-density set when assembling
        the next block.

        Returns True on insertion, False if the tx is already present
        OR the pool is full and the incoming tx does not beat the
        lowest-density pending entry.

        The caller must run signature / target-existence / activation-
        gate checks before this call (see `verify_react_transaction`
        + the chain-side checks in `validate_block`); the mempool
        enforces dedup, the protocol fee floor, and the cap.

        Tier 43 (audit fix #4): `arrival_block_height` records the
        block height at which this node first saw the react tx so the
        forced-inclusion source-side wait-gate works the same way it
        does for messages.  Defaults to 0 (legacy "always been here"
        — immediately eligible for forced inclusion once the
        activation gate opens); production callers (RPC submit,
        gossip relay) should pass the current chain height so a
        long-waited react can be distinguished from a fresh arrival.
        """
        with self._lock:
            if tx.tx_hash in self.react_pool:
                return False
            # Admission floor matches the consensus-side floor exactly.
            # Pre-Tier-16 the protocol baseline was MIN_FEE=100; post-fork
            # the baseline is MARKET_FEE_FLOOR=1.  Using MIN_FEE here would
            # silently reject txs that the chain itself would accept,
            # defeating the Tier-18 Gap-5 work that aligned ReactTx
            # admission with the market floor.  Match it.  (Same pattern
            # the message-tx pool's `add_transaction` uses — see line ~155.)
            from messagechain.config import MARKET_FEE_FLOOR
            if tx.fee < MARKET_FEE_FLOOR:
                return False
            arrival = (
                arrival_block_height if arrival_block_height is not None else 0
            )
            if len(self.react_pool) < self.react_pool_max_size:
                self.react_pool[tx.tx_hash] = tx
                self._react_pool_arrival_heights[tx.tx_hash] = arrival
                return True
            # Pool is full — fee-density eviction.  Find the lowest-density
            # pending entry; admit the incoming tx only if it beats it.
            incoming_density = self._react_fee_density(tx)
            worst_hash = min(
                self.react_pool,
                key=lambda h: self._react_fee_density(self.react_pool[h]),
            )
            worst_density = self._react_fee_density(self.react_pool[worst_hash])
            if incoming_density <= worst_density:
                return False
            del self.react_pool[worst_hash]
            # Tier 43: drop the evicted tx's arrival-tracker entry so
            # the dict cannot leak unboundedly across the chain's
            # lifetime.  A leaked entry would also risk misclassifying
            # a re-arrived tx as "aged from genesis" once the source
            # side starts walking this pool post-fork.
            self._react_pool_arrival_heights.pop(worst_hash, None)
            self.react_pool[tx.tx_hash] = tx
            self._react_pool_arrival_heights[tx.tx_hash] = arrival
            return True

    def get_react_transactions(self, max_count: int | None = None) -> list:
        """Return pending ReactTransactions ordered by fee density (highest first).

        Same ranking the message-tx selector uses, so the proposer
        consistently picks the highest-revenue set under any per-block
        scarcity (count cap or unified byte budget).
        """
        with self._lock:
            items = sorted(
                self.react_pool.values(),
                key=self._react_fee_density,
                reverse=True,
            )
            if max_count is not None:
                items = items[:max_count]
            return items

    def remove_react_transactions(self, tx_hashes: list[bytes]):
        """Remove react txs after inclusion in a block.

        Tier 43 (audit fix #4): also pops the arrival-tracker entry
        so `_react_pool_arrival_heights` cannot leak across the
        chain's lifetime.  Symmetric with the evidence-pool teardown
        in `remove_censorship_evidence_txs`.
        """
        with self._lock:
            for h in tx_hashes:
                self.react_pool.pop(h, None)
                self._react_pool_arrival_heights.pop(h, None)

    @property
    def size(self) -> int:
        # `len()` on a dict is a single C-level read on the dict's
        # ma_used field — atomic under the GIL — but wrapping anyway
        # keeps the policy uniform: every state read holds the lock.
        with self._lock:
            return len(self.pending)
