"""Censorship-resistance forced-inclusion rule (attester-enforced).

Problem: a malicious proposer can silently drop user transactions from
otherwise valid blocks.  Replay-by-fee, Sybil censorship, and outright
content filtering all collapse the same way — the proposer controls
block contents and nothing in consensus forces inclusion of pending
txs.

Defense: every attester independently tracks the txs it has held in
its local mempool for at least FORCED_INCLUSION_WAIT_BLOCKS.  From that
set it picks the top FORCED_INCLUSION_SET_SIZE by fee-per-byte (same
density priority used for normal block selection).  These are the
"forced" txs — the next proposer MUST include them, or justify their
omission via a valid structural excuse.

Valid excuses (explicitly enumerated — anything else is censorship):

    1. Block byte budget exhausted: the included txs already sum to
       MAX_BLOCK_MESSAGE_BYTES (or adding the forced tx would exceed
       it).
    2. Block tx-count cap reached: the block already holds
       MAX_TXS_PER_BLOCK txs.
    3. Tx no longer includable: nonce mismatch, insufficient balance,
       invalid signature under current chain state.  Caller supplies
       an optional `is_includable(tx)` callback that encapsulates the
       proposer-time check.  If omitted, all pending txs are assumed
       includable (they passed admission-time validation).

Why attester-enforced instead of validate_block-hard-fail:

Mempool contents are per-node subjective.  Two honest nodes rarely see
byte-identical mempools at any instant.  Hard-failing a block because
"my mempool has tx X that your block doesn't" would split the network
every time gossip lag differed across peers.  Soft attester voting
avoids this: each attester speaks only for what IT saw.  If 1/3+ of
honest stake saw the censored tx, the block fails the 2/3 finality
quorum — censorship resistance without requiring global mempool
consensus.

Proposer fairness:

Forced inclusion applies to ALL qualifying txs including the
proposer's OWN.  A proposer that floods its own mempool with high-fee
self-txs to crowd out users gains no special privilege — those txs
compete for the same top-N slots as everyone else's.

Tier 34 — multi-list block recognition:

Pre-Tier-34 the gate scoped `included_hashes` to `block.transactions`
(the message-tx list) and the byte-budget excuse to `len(tx.message)`
(payload bytes).  Two correctness gaps fell out: (a) honest blocks
that placed a forced TransferTransaction in `block.transfer_transactions`
were flagged as omitting it (false positive); (b) the entire CLAUDE.md
"high-fpb tx cannot be suppressed without slashable evidence" anchor
silently exempted every non-message tx kind from the gate (false
negative against the audit's primary collusion concern).

Post-Tier-34 the gate walks every known block tx-list field when
building `included_hashes` and accounts for stored bytes via
`len(tx.to_bytes())` — the same axis the mempool's fee-per-byte
ranking already uses.  Pre-fork: byte-identical to legacy attester
behavior so any block accepted under the old rule still attests.

Scope of this fork: covers tx kinds that the consensus mempool
already tracks (Message + Transfer).  Stake / Unstake / Governance /
Authority / React live in server-local pools or separate sub-pools
today; bringing them into the attester-shared mempool is a follow-up
that the multi-list shape established here makes mechanical.
"""

from __future__ import annotations

from typing import Callable, Optional

from messagechain.config import (
    FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_TXS_PER_BLOCK,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
)


# Block tx-list fields the multi-list path walks when building the
# included-hash set and the per-entity tally.  Order does not matter —
# membership is the whole point — but we list them deterministically
# so a future grep stays anchored to one source of truth.  Updating
# this tuple is the single chokepoint that brings a new tx kind under
# the forced-inclusion gate once it joins the attester-shared mempool.
_BLOCK_TX_LIST_ATTRS: tuple[str, ...] = (
    "transactions",
    "transfer_transactions",
    "react_transactions",
    "stake_transactions",
    "unstake_transactions",
    "governance_txs",
    "authority_txs",
)


def _iter_all_block_txs(block):
    """Yield every tx across known block tx-list fields."""
    for attr in _BLOCK_TX_LIST_ATTRS:
        for tx in getattr(block, attr, None) or ():
            yield tx


def _stored_bytes_of(tx) -> int:
    """Stored byte length for fee-per-byte / byte-budget arithmetic.

    Mirrors the mempool's `_stored_bytes` shape (using `to_bytes()`
    for the wire-form length) but is defensive against tx kinds whose
    `to_bytes()` raises — those fall back to `len(tx.message)` if a
    payload is present, else 0.  The fallback is wrong only at the
    margin (excuse #1 may admit one extra forced tx than it should
    on a malformed object) and is preferable to crashing the gate.
    """
    to_bytes_fn = getattr(tx, "to_bytes", None)
    if callable(to_bytes_fn):
        try:
            return len(to_bytes_fn())
        except Exception:
            pass
    msg = getattr(tx, "message", None)
    if msg is not None:
        try:
            return len(msg)
        except Exception:
            pass
    return 0


def check_forced_inclusion(
    block,
    mempool,
    current_block_height: int,
    is_includable: Optional[Callable[[object], bool]] = None,
) -> tuple[bool, str]:
    """Verify the block honors the attester's forced-inclusion duty.

    Returns (True, reason) if the block is acceptable; (False, reason)
    if the attester should vote NO.  `reason` is a short human-readable
    string for logging.

    The checker is deliberately local: it reads the attester's OWN
    mempool view, not any notion of global state.  An attester whose
    mempool is empty imposes no duty on the proposer (it saw no
    pending txs to force).

    Parameters:
        block:               Any object exposing `.transactions` and
                             optionally the sibling tx-list fields
                             (`transfer_transactions`,
                             `react_transactions`, etc.).  Pre-Tier-34
                             only `block.transactions` is consulted;
                             post-Tier-34 every field listed in
                             `_BLOCK_TX_LIST_ATTRS` is walked.
        mempool:             The attester's Mempool instance.
        current_block_height: Height of the block being validated.
                             Used to compute wait time AND to gate
                             the Tier-34 multi-list path.
        is_includable:       Optional callback.  Called with each
                             forced tx to ask "is this tx currently
                             valid to include (nonce/balance/sig)?"
                             Returning False is a valid excuse.  If
                             None, all pending txs are assumed
                             includable.
    """
    forced = mempool.get_forced_inclusion_set(current_block_height)
    if not forced:
        return True, "no forced-inclusion duty"

    use_multi_list = (
        int(current_block_height) >= FORCED_INCLUSION_ALL_TX_KINDS_HEIGHT
    )

    if not use_multi_list:
        # Pre-Tier-34: the gate was MessageTransaction-only by design
        # (the byte-budget excuse read `ftx.message` directly, which
        # raised AttributeError on any non-message kind in the forced
        # set).  TransferTransactions share `mempool.pending` with
        # messages and could legitimately appear in the forced set if
        # they aged past FORCED_INCLUSION_WAIT_BLOCKS — pre-fork the
        # gate would crash on that path instead of voting; in
        # production it has not bitten because mainnet traffic rarely
        # holds a transfer that long.  Filter the forced set to
        # message kinds here so the pre-fork path stays liveness-safe
        # without changing the message-tx semantics that historical
        # blocks were attested under.
        forced = [t for t in forced if hasattr(t, "message")]
        if not forced:
            return True, "no forced-inclusion duty"

    if use_multi_list:
        # Tier 34: walk every known block tx-list field so a forced tx
        # placed in its correct slot (e.g. a TransferTransaction in
        # `block.transfer_transactions`) is recognized as included,
        # not flagged as censored.  Byte budget uses stored bytes
        # (matching the mempool's fee-per-byte ranking axis).
        included_hashes = {
            tx.tx_hash for tx in _iter_all_block_txs(block)
        }
        used_bytes = sum(
            _stored_bytes_of(tx) for tx in _iter_all_block_txs(block)
        )
        used_count = sum(1 for _ in _iter_all_block_txs(block))
        entity_counts: dict[bytes, int] = {}
        for tx in _iter_all_block_txs(block):
            eid = getattr(tx, "entity_id", None) or getattr(
                tx, "voter_id", None,
            )
            if eid is not None:
                entity_counts[eid] = entity_counts.get(eid, 0) + 1
    else:
        # Pre-Tier-34: legacy message-only path.  Byte-identical to
        # historical attester behavior so any block accepted under
        # the old rule still attests.
        included_hashes = {tx.tx_hash for tx in block.transactions}
        used_bytes = sum(len(tx.message) for tx in block.transactions)
        used_count = len(block.transactions)
        entity_counts = {}
        for tx in block.transactions:
            entity_counts[tx.entity_id] = (
                entity_counts.get(tx.entity_id, 0) + 1
            )

    remaining_bytes = MAX_BLOCK_MESSAGE_BYTES - used_bytes
    remaining_count = MAX_TXS_PER_BLOCK - used_count

    for ftx in forced:
        if ftx.tx_hash in included_hashes:
            continue  # proposer did the right thing

        # Valid excuse #1: block byte budget exhausted (or would be by
        # this tx's inclusion).  Use the same byte axis the budget was
        # computed on — stored bytes post-Tier-34, payload bytes pre.
        ftx_bytes = (
            _stored_bytes_of(ftx) if use_multi_list else len(ftx.message)
        )
        if ftx_bytes > remaining_bytes:
            continue

        # Valid excuse #2: block tx-count cap reached.
        if remaining_count <= 0:
            continue

        # Valid excuse #3: per-entity cap reached for this tx's sender.
        ftx_eid = (
            getattr(ftx, "entity_id", None)
            or getattr(ftx, "voter_id", None)
        )
        if (
            ftx_eid is not None
            and entity_counts.get(ftx_eid, 0)
            >= MAX_TXS_PER_ENTITY_PER_BLOCK
        ):
            continue

        # Valid excuse #4: tx is no longer includable per caller-supplied
        # validity oracle (nonce mismatch, insufficient balance, etc.).
        if is_includable is not None and not is_includable(ftx):
            continue

        # No valid excuse — this is censorship.
        return False, (
            f"Block omits forced-inclusion tx {ftx.tx_hash.hex()[:16]}... "
            f"(fee={ftx.fee}, {ftx_bytes}B) with "
            f"{remaining_bytes}B / {remaining_count} slots available"
        )

    return True, "all forced-inclusion txs honored or excused"


def should_attest_block(
    block,
    mempool,
    current_block_height: int,
    is_includable: Optional[Callable[[object], bool]] = None,
) -> bool:
    """Convenience: True if the attester should vote YES on the block.

    Wraps `check_forced_inclusion` for attester code that just wants a
    boolean vote.  Block-level validity (signatures, merkle root,
    consensus rules) is checked separately via `validate_block`; this
    function ONLY covers the forced-inclusion censorship check.
    """
    ok, _reason = check_forced_inclusion(
        block, mempool, current_block_height, is_includable=is_includable,
    )
    return ok
