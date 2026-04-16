"""Censorship-resistance forced-inclusion rule (attester-enforced).

Problem: a malicious proposer can silently drop user transactions from
otherwise valid blocks.  Replay-by-fee, Sybil censorship, and outright
content filtering all collapse the same way — the proposer controls
block contents and nothing in consensus forces inclusion of pending
txs.

Defense: every attester independently tracks the txs it has held in
its local mempool for at least FORCED_INCLUSION_WAIT_BLOCKS.  From that
set it picks the top FORCED_INCLUSION_SET_SIZE by fee.  These are the
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
"""

from __future__ import annotations

from typing import Callable, Optional

from messagechain.config import (
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_TXS_PER_BLOCK,
)


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
        block:               Any object exposing `.transactions`
                             (list[MessageTransaction]) — the message
                             txs in the proposed block.  Other tx
                             types (transfers, slashings, etc.) are
                             not forced — only MessageTransactions in
                             the regular fee-auction mempool are
                             subject to this rule.
        mempool:             The attester's Mempool instance.
        current_block_height: Height of the block being validated.
                             Used to compute wait time.
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

    included_hashes = {tx.tx_hash for tx in block.transactions}

    # Compute remaining block-structural capacity given what the block
    # DID include.  A missing forced tx is excused if it wouldn't have
    # fit anyway.
    used_bytes = sum(len(tx.message) for tx in block.transactions)
    used_count = len(block.transactions)
    remaining_bytes = MAX_BLOCK_MESSAGE_BYTES - used_bytes
    remaining_count = MAX_TXS_PER_BLOCK - used_count

    for ftx in forced:
        if ftx.tx_hash in included_hashes:
            continue  # proposer did the right thing

        # Valid excuse #1: block byte budget exhausted (or would be by
        # this tx's inclusion).  A forced tx larger than the remaining
        # byte room couldn't have fit.
        if len(ftx.message) > remaining_bytes:
            continue

        # Valid excuse #2: block tx-count cap reached.
        if remaining_count <= 0:
            continue

        # Valid excuse #3: tx is no longer includable per caller-supplied
        # validity oracle (nonce mismatch, insufficient balance, etc.).
        if is_includable is not None and not is_includable(ftx):
            continue

        # No valid excuse — this is censorship.
        return False, (
            f"Block omits forced-inclusion tx {ftx.tx_hash.hex()[:16]}... "
            f"(fee={ftx.fee}, {len(ftx.message)}B) with "
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
