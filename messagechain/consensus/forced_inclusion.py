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
    FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_BLOCK_TOTAL_BYTES,
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
    # Tier 35 — non-response evidence first-class block slot.  Listing
    # the field here means a forced NonResponseEvidenceTx placed in
    # its correct slot is recognized as included by Tier 34's multi-
    # list censorship-resistance gate, rather than flagged as omitted.
    # Pre-Tier-35 blocks carry an empty list here (the field defaults
    # to []), which iterates as a no-op — so listing the slot
    # unconditionally does not perturb the gate's pre-fork behavior.
    "non_response_evidence_txs",
    # Tier 43 — censorship-evidence first-class block slot.  Pre-Tier-43
    # the gate's source side did not consult the censorship-evidence
    # pool, so an omitted evidence tx never triggered the gate's
    # block-side check either; placing the slot here unconditionally
    # is safe because every pre-Tier-43 block carries an empty list
    # (or the field is missing entirely; `getattr(..., None) or ()`
    # handles both).  Post-Tier-43 a forced evidence tx placed in
    # this slot is recognized as included rather than flagged as
    # omitted — the same false-positive-resistant pattern Tier 34
    # established for transfers and Tier 35 for non-response.
    "censorship_evidence_txs",
)


# Tx-list fields whose stored bytes / counts the BLOCK VALIDATOR's caps
# actually account for.  The Tier-18 unified-budget check at
# ``blockchain.validate_block`` (and the tx-count cap at the same site)
# sums message + transfer + react and ignores every other kind in
# ``_BLOCK_TX_LIST_ATTRS`` — those kinds are bounded by their own
# admission rules, not by ``MAX_BLOCK_TOTAL_BYTES`` / ``MAX_TXS_PER_BLOCK``.
#
# The forced-inclusion gate's ``used_bytes`` / ``used_count`` /
# per-entity tallies must use this narrower set: a colluding proposer
# who pads the block with their own stake / governance / authority /
# evidence bytes does NOT raise the binding constraint at the validator,
# so the gate must not excuse omission of a forced tx on a constraint
# the validator never enforces.  Inclusion-recognition still walks
# ``_BLOCK_TX_LIST_ATTRS`` (a forced tx in any kind-slot is recognized).
_VALIDATOR_BUDGET_ATTRS: tuple[str, ...] = (
    "transactions",
    "transfer_transactions",
    "react_transactions",
)


def _iter_all_block_txs(block):
    """Yield every tx across known block tx-list fields."""
    for attr in _BLOCK_TX_LIST_ATTRS:
        for tx in getattr(block, attr, None) or ():
            yield tx


def _iter_validator_budget_txs(block):
    """Yield txs from kinds the validator's byte / count caps account for."""
    for attr in _VALIDATOR_BUDGET_ATTRS:
        for tx in getattr(block, attr, None) or ():
            yield tx


def _is_message_tx(tx) -> bool:
    """True iff `tx` is a MessageTransaction.

    The block validator's per-entity cap (``MAX_TXS_PER_ENTITY_PER_BLOCK``)
    is enforced ONLY against ``block.transactions`` — every other kind
    is admitted under its own rules without a per-entity-per-block cap.
    The forced-inclusion gate's per-entity tally and excuse-#3 path
    must therefore key on message-only too: a forced non-message tx is
    never excusable on per-entity-cap grounds, and same-entity
    non-message volume in the block does not legitimize omitting a
    forced message of the same sender.

    Imported lazily to avoid a circular import — this module is loaded
    by ``messagechain.consensus`` initialization, which transitively
    pulls ``messagechain.core``.
    """
    from messagechain.core.transaction import MessageTransaction
    return isinstance(tx, MessageTransaction)


def _entity_id_of(tx) -> bytes | None:
    """Return the per-entity-cap key for `tx`.

    Tier 34 read `entity_id` / `voter_id` (Message + Vote).  Tier 43
    extends source-side coverage to tx kinds whose primary identifier
    uses a different name: `proposer_id` (governance proposals) and
    `submitter_id` (censorship-evidence).  Reading them here keeps the
    per-entity tally consistent across every kind the gate now sees.
    Pre-Tier-43 this is reached only with kinds that already exposed
    `entity_id` or `voter_id`, so the additional fallbacks are silent
    no-ops on every legacy code path.
    """
    return (
        getattr(tx, "entity_id", None)
        or getattr(tx, "voter_id", None)
        or getattr(tx, "proposer_id", None)
        or getattr(tx, "submitter_id", None)
    )


def _is_strictly_lower_fpb(other_tx, ref_tx) -> bool:
    """True iff `other_tx`'s fee-per-stored-byte is STRICTLY LESS than
    `ref_tx`'s.

    Used by the Tier 37 entity-cap fix to decide whether a same-entity
    block tx counts toward the cap when evaluating excuse #3 for a
    forced tx.  A same-entity block tx at strictly lower fpb than the
    forced tx is a proposer-selection artifact (the proposer chose a
    LESS dense tx over the forced one of the same entity), not a real
    structural reason to skip — those txs do NOT count toward the cap.

    Comparison is done as an integer cross-multiplication
    (`a/b < c/d` iff `a*d < c*b` when b, d > 0) so the consensus path
    has no float dependency.  Stored bytes are pinned to >= 1 by
    `_stored_bytes_of`'s fallback so the denominators are always
    positive.
    """
    other_bytes = max(1, _stored_bytes_of(other_tx))
    ref_bytes = max(1, _stored_bytes_of(ref_tx))
    other_fee = getattr(other_tx, "fee", 0) or 0
    ref_fee = getattr(ref_tx, "fee", 0) or 0
    # other.fpb < ref.fpb  ⇔  other_fee * ref_bytes < ref_fee * other_bytes
    return other_fee * ref_bytes < ref_fee * other_bytes


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
    # Tier 37: tighten excuse #3 so a colluding proposer cannot fill
    # the per-entity cap with same-entity LOWER-fpb txs and excuse a
    # higher-fpb forced tx of the same entity.  Pre-activation: legacy
    # excuse-#3 logic preserved byte-for-byte for replay determinism.
    apply_entity_cap_fix = (
        int(current_block_height) >= FORCED_INCLUSION_ENTITY_CAP_FIX_HEIGHT
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

    # `entity_block_txs` is populated only when the Tier 37 cap-fix is
    # active — pre-fork the legacy `entity_counts` int tally is enough
    # and we avoid the extra per-entity list to keep replay byte-
    # identical (same dict shape, same iteration order, no new objects
    # touched on the consensus path).
    entity_block_txs: dict[bytes, list] = {}
    if use_multi_list:
        # Tier 34: inclusion-recognition walks every known block
        # tx-list field so a forced tx placed in its correct slot
        # (e.g. a TransferTransaction in `block.transfer_transactions`)
        # is recognized as included, not flagged as censored.
        included_hashes = {
            tx.tx_hash for tx in _iter_all_block_txs(block)
        }
        # Audit r26 #1: ``used_bytes`` / ``used_count`` / per-entity
        # tallies key on the kind-set the BLOCK VALIDATOR's caps
        # actually account for (message + transfer + react for byte
        # and count caps; message-only for the per-entity cap).
        # Pre-fix the gate walked all 9 kinds in `_BLOCK_TX_LIST_ATTRS`
        # — letting a colluding proposer pad the block with stake /
        # governance / authority / evidence bytes until the gate's
        # tally tripped excuse #1 or excuse #3 while the validator's
        # narrower axis stayed comfortably under cap, silently
        # excusing the omission of any forced tx.  CLAUDE.md anchor:
        # "a tx that pays at least the per-byte floor and fits the
        # byte budget cannot be suppressed by anything weaker than a
        # full validator-set majority" — pre-fix the suppression
        # took one proposer with no slashable trail.
        used_bytes = sum(
            _stored_bytes_of(tx) for tx in _iter_validator_budget_txs(block)
        )
        used_count = sum(1 for _ in _iter_validator_budget_txs(block))
        # Per-entity cap is message-only at the validator —
        # `block.transactions` is the only list it iterates for the
        # `entity_msg_counts` check.
        entity_counts: dict[bytes, int] = {}
        for tx in block.transactions:
            eid = _entity_id_of(tx)
            if eid is not None:
                entity_counts[eid] = entity_counts.get(eid, 0) + 1
                if apply_entity_cap_fix:
                    entity_block_txs.setdefault(eid, []).append(tx)
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

    # Excuse-#1 byte cap: the cap referenced here MUST match the axis
    # ``used_bytes`` was computed on, and the cap must be the one the
    # block validator itself enforces against that axis — otherwise a
    # proposer whose block IS valid (validator's cap unbroken) can be
    # excused for omitting a forced tx whose inclusion the validator
    # would have admitted.  Pre-Tier-34 the legacy path summed
    # ``len(tx.message)`` (payload bytes) and is correctly bounded by
    # ``MAX_BLOCK_MESSAGE_BYTES`` (the payload cap).  Post-Tier-34 the
    # multi-list path sums ``len(tx.to_bytes())`` (stored bytes,
    # matching the mempool's fee-per-byte ranking axis); the cap that
    # actually bounds stored bytes is Tier 18's unified
    # ``MAX_BLOCK_TOTAL_BYTES``.  Pre-fix the post-Tier-34 branch
    # checked stored-byte usage against the payload cap — a unit
    # mismatch that let a colluding proposer fill the block with their
    # own witness-heavy txs (small payloads, ~256× WOTS+ amplification
    # in stored bytes) until ``used_bytes > MAX_BLOCK_MESSAGE_BYTES``,
    # at which point excuse #1 fired for any forced tx while the
    # block's actual ``len(tx.message)`` total was nowhere near the
    # payload cap and the block-level ``MAX_BLOCK_TOTAL_BYTES`` check
    # was nowhere near binding either.  CLAUDE.md anchor: "a tx that
    # pays at least the per-byte floor and fits the byte budget cannot
    # be suppressed by anything weaker than a full validator-set
    # majority" — the suppression took only one proposer pre-fix.
    cap_bytes = MAX_BLOCK_TOTAL_BYTES if use_multi_list else MAX_BLOCK_MESSAGE_BYTES
    remaining_bytes = cap_bytes - used_bytes
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
        # Audit r26 #1: only applies when the FORCED tx itself is a
        # message — the block validator's per-entity cap is enforced
        # only against ``block.transactions`` at validate_block, so a
        # forced non-message tx (transfer / governance / etc.) has no
        # validator-level per-entity cap that could legitimize its
        # omission.  Without this gate a colluding proposer could
        # excuse omitting any forced non-message tx by stacking
        # same-entity messages — a constraint the validator never
        # enforces.
        ftx_eid = _entity_id_of(ftx)
        if ftx_eid is not None and _is_message_tx(ftx):
            if apply_entity_cap_fix:
                # Tier 37: only same-entity block txs at >= the forced
                # tx's fpb count toward the cap.  Same-entity block txs
                # at strictly lower fpb are a proposer-selection
                # artifact (the proposer chose a less-dense tx over the
                # forced one of the same entity) and do not legitimize
                # the omission — those nonces fit BEHIND the forced tx
                # structurally, so the forced tx could replace any one
                # of them without raising the cap.
                effective_count = sum(
                    1
                    for btx in entity_block_txs.get(ftx_eid, ())
                    if not _is_strictly_lower_fpb(btx, ftx)
                )
                if effective_count >= MAX_TXS_PER_ENTITY_PER_BLOCK:
                    continue
            elif (
                entity_counts.get(ftx_eid, 0)
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
