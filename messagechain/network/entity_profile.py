"""
Entity profile aggregator — read-only view served at /v1/entity?id=<hex>.

Walks the chain once to produce a JSON-friendly snapshot of a single
entity: balance, stake, post counts, fee total, mining rewards,
governance activity, reputation (profile-level upvotes + rate),
post-level reputation (distinct upvoters + rate), and cumulative
share of total supply spent on the network.  Designed for the public
site's profile page; nothing here mutates state or participates in
consensus.

Cost model
----------
A profile request runs O(blocks * txs/block) for the chain walk plus
O(R) for reaction aggregation, where R is the global non-CLEAR
reaction count.  At current mainnet size both are sub-millisecond; if
this ever becomes hot it can be denormalized into a per-entity index
the same way ReactionState aggregates message scores.
"""

from __future__ import annotations

from typing import Optional

from messagechain.config import GENESIS_SUPPLY
from messagechain.core.reaction import (
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
)


def _rate_pct(ups: int, downs: int) -> Optional[float]:
    """Upvote rate = ups / (ups + downs), as percent.  None when no votes."""
    total = ups + downs
    return (100.0 * ups / total) if total > 0 else None


def compute_entity_profile(blockchain, entity_id: bytes) -> dict:
    """Build a JSON-serializable profile for `entity_id`.

    Returns a dict with `exists=False` when the entity is unknown to
    chain state and never appears in any tx — callers can render a
    "not found" page in that case.  Everything else (balances, scores,
    counts) defaults to zero/None for an unknown id rather than
    erroring, so the same shape is always returned.
    """
    if not isinstance(entity_id, (bytes, bytearray)) or len(entity_id) != 32:
        raise ValueError("entity_id must be 32 bytes")
    eid = bytes(entity_id)

    # ── chain walk ──────────────────────────────────────────────────
    msg_total = 0
    first_post_ts: Optional[float] = None
    last_post_ts: Optional[float] = None
    first_post_block: Optional[int] = None
    last_post_block: Optional[int] = None
    user_msg_tx_hashes: list[bytes] = []

    # `user_since` = earliest block in which this entity_id appears in
    # ANY capacity (sender, recipient, voter, proposer, etc.).
    first_seen_block: Optional[int] = None
    first_seen_ts: Optional[float] = None

    fees_paid = 0
    blocks_proposed = 0
    estimated_block_rewards = 0
    proposals_made = 0
    votes_cast = 0
    transfers_sent = 0
    transfers_received = 0
    stake_ops = 0
    unstake_ops = 0
    react_tx_count = 0

    # Cumulative share of total supply this entity has spent on the
    # network: for each outflow (any fee, plus transfer-amount-out),
    # accrue (spend / supply_at_block) so two equal-token spends at
    # different points in the supply curve weight differently.  Supply
    # is approximated by GENESIS_SUPPLY + cumulative block rewards;
    # burns are not subtracted (this is a UI stat, not a consensus
    # invariant — the approximation is monotonic and good enough to
    # rank "moved a lot" vs "moved a little").
    genesis_supply = getattr(blockchain.supply, "GENESIS_SUPPLY", GENESIS_SUPPLY)
    running_supply = genesis_supply
    spend_pct_cumulative = 0.0

    def _seen(block_number: int, ts: float) -> None:
        nonlocal first_seen_block, first_seen_ts
        if first_seen_block is None or block_number < first_seen_block:
            first_seen_block = block_number
            first_seen_ts = ts

    for block in blockchain.chain:
        bn = block.header.block_number
        bts = block.header.timestamp

        # Mint the block reward into the running supply BEFORE charging
        # spends in this block — a tx in block N is paid out of the
        # supply that exists once the block is sealed.
        running_supply += blockchain.supply.calculate_block_reward(bn)

        if block.header.proposer_id == eid:
            blocks_proposed += 1
            estimated_block_rewards += blockchain.supply.calculate_block_reward(bn)
            _seen(bn, bts)

        def _charge(amount: int) -> None:
            nonlocal spend_pct_cumulative
            if amount > 0 and running_supply > 0:
                spend_pct_cumulative += 100.0 * amount / running_supply

        for tx in block.transactions:
            if tx.entity_id == eid:
                msg_total += 1
                fees_paid += tx.fee
                _charge(tx.fee)
                user_msg_tx_hashes.append(tx.tx_hash)
                if first_post_ts is None or tx.timestamp < first_post_ts:
                    first_post_ts = tx.timestamp
                    first_post_block = bn
                if last_post_ts is None or tx.timestamp > last_post_ts:
                    last_post_ts = tx.timestamp
                    last_post_block = bn
                _seen(bn, bts)

        for ttx in getattr(block, "transfer_transactions", []) or []:
            if ttx.entity_id == eid:
                transfers_sent += 1
                fees_paid += ttx.fee
                # Transfer is an outflow of (amount + fee) from sender.
                _charge(ttx.fee + getattr(ttx, "amount", 0))
                _seen(bn, bts)
            if getattr(ttx, "recipient_id", None) == eid:
                transfers_received += 1
                _seen(bn, bts)

        for rtx in getattr(block, "react_transactions", []) or []:
            if rtx.voter_id == eid:
                react_tx_count += 1
                fees_paid += rtx.fee
                _charge(rtx.fee)
                _seen(bn, bts)

        for gtx in getattr(block, "governance_txs", []) or []:
            cls_name = type(gtx).__name__
            if cls_name in ("ProposalTransaction", "TreasurySpendTransaction"):
                if getattr(gtx, "proposer_id", None) == eid:
                    proposals_made += 1
                    fee = getattr(gtx, "fee", 0)
                    fees_paid += fee
                    _charge(fee)
                    _seen(bn, bts)
            elif cls_name == "VoteTransaction":
                if getattr(gtx, "voter_id", None) == eid:
                    votes_cast += 1
                    fee = getattr(gtx, "fee", 0)
                    fees_paid += fee
                    _charge(fee)
                    _seen(bn, bts)

        for stx in getattr(block, "stake_transactions", []) or []:
            if getattr(stx, "entity_id", None) == eid:
                stake_ops += 1
                fee = getattr(stx, "fee", 0)
                fees_paid += fee
                _charge(fee)
                _seen(bn, bts)

        for utx in getattr(block, "unstake_transactions", []) or []:
            if getattr(utx, "entity_id", None) == eid:
                unstake_ops += 1
                fee = getattr(utx, "fee", 0)
                fees_paid += fee
                _charge(fee)
                _seen(bn, bts)

    # ── balances / stake ────────────────────────────────────────────
    balance = blockchain.supply.get_balance(eid)
    staked = blockchain.supply.get_staked(eid)
    pending_unstake = sum(
        amt for amt, _release in blockchain.supply.pending_unstakes.get(eid, [])
    )
    total_funds = balance + staked + pending_unstake
    stake_pct = (
        100.0 * staked / total_funds if total_funds > 0 and staked > 0 else None
    )

    # ── reputation: UP/DOWN votes received on the entity's profile ──
    rs = blockchain.reaction_state
    reputation_score = rs.user_trust_score(eid)
    rep_ups = 0
    rep_downs = 0
    for (_voter, target, target_is_user), choice in rs.choices.items():
        if target_is_user and target == eid:
            if choice == REACT_CHOICE_UP:
                rep_ups += 1
            elif choice == REACT_CHOICE_DOWN:
                rep_downs += 1

    # ── post score: UP/DOWN votes received on this user's messages ──
    user_msg_set = set(user_msg_tx_hashes)
    post_score = 0
    post_ups = 0
    post_downs = 0
    distinct_post_upvoters: set[bytes] = set()
    for (voter, target, target_is_user), choice in rs.choices.items():
        if not target_is_user and target in user_msg_set:
            if choice == REACT_CHOICE_UP:
                post_score += 1
                post_ups += 1
                distinct_post_upvoters.add(voter)
            elif choice == REACT_CHOICE_DOWN:
                post_score -= 1
                post_downs += 1

    # Existence check: an entity is "real" if anything on chain
    # references it, or if it carries on-chain state.
    exists = (
        first_seen_block is not None
        or eid in blockchain.public_keys
        or balance > 0
        or staked > 0
        or pending_unstake > 0
    )

    return {
        "entity_id": eid.hex(),
        "exists": exists,
        "user_since": (
            {"block_number": first_seen_block, "timestamp": first_seen_ts}
            if first_seen_block is not None
            else None
        ),
        "messages": {
            "total": msg_total,
            "first_post_timestamp": first_post_ts,
            "first_post_block": first_post_block,
            "last_post_timestamp": last_post_ts,
            "last_post_block": last_post_block,
        },
        "balance": balance,
        "staked": staked,
        "pending_unstake": pending_unstake,
        "total_funds": total_funds,
        "stake_pct_of_funds": stake_pct,
        "reputation": {
            "score": reputation_score,
            "ups_received": rep_ups,
            "downs_received": rep_downs,
            "rate_pct": _rate_pct(rep_ups, rep_downs),
        },
        "post_score": {
            "total": post_score,
            "ups_received": post_ups,
            "downs_received": post_downs,
            "distinct_upvoters": len(distinct_post_upvoters),
            "rate_pct": _rate_pct(post_ups, post_downs),
        },
        "rewards": {
            "blocks_proposed": blocks_proposed,
            "estimated_block_rewards": estimated_block_rewards,
        },
        "fees_paid": fees_paid,
        "supply_spent_pct_cumulative": spend_pct_cumulative,
        "governance": {
            "proposals_made": proposals_made,
            "votes_cast": votes_cast,
        },
        "transfers": {
            "sent": transfers_sent,
            "received": transfers_received,
        },
        "stake_ops": {
            "stakes": stake_ops,
            "unstakes": unstake_ops,
        },
        "reactions_cast": react_tx_count,
    }
