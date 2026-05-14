"""
Vote-weight snapshots — display-layer aggregator for the public feed UI.

Walks the chain once and records, for each (voter, target, target_is_user)
pair currently in ReactionState.choices, a snapshot of the voter's
reconstructed balance / cumulative-spend % / age at the moment the LATEST
non-CLEAR React tx for that pair landed.  The public-feed surfaces
(``/v1/entity`` profile cards, recent-messages lists) consume these
snapshots to render four weighted UP-rate ratios alongside the simple
ratio: balance-weighted, spend-weighted, age-weighted, and a placeholder
"reputation" axis (age × spend) the operator can swap for a richer score
later.

This is NOT a consensus mechanism.  The reputation guide
(``guides/reputation.md``) anchors that the protocol stores flat raw
votes and that any weighting belongs at the app / indexer layer — this
module is the public site's reference weighting, surfaced as four
parallel ratios so a reader can compare them rather than being told one
"true" score.

Balance reconstruction is approximate.  We track per-entity deltas from
the events visible at the tx level (transfers, fees, proposer block
rewards, governance / stake / unstake fees) but ignore attestation
rewards, validator inflation distribution, slashing, and faucet credits
— their omission causes the reconstructed balance to drift slowly from
canonical state.  For ratio weighting that drift is acceptable: the
ordering between voters is what matters, and the missing flows are
proportionally small per-voter.  Spend %, age, and the rep placeholder
are computed from the same delta stream and inherit the same caveat.
"""

from __future__ import annotations

from typing import Iterable

from messagechain.config import (
    GENESIS_SUPPLY,
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
)


def compute_vote_weight_snapshots(blockchain) -> dict:
    """Single chain walk producing per-vote voter snapshots.

    Returns a dict keyed by ``(voter_id, target, target_is_user)`` whose
    values are snapshot dicts with:

        balance_at_vote   : int   (reconstructed, clamped to >= 0)
        spend_pct_at_vote : float (cumulative % of supply spent by this
                                   voter through and including the React tx)
        age_sec_at_vote   : float (block ts of vote - block ts of voter's
                                   first observed activity)
        vote_block        : int
        vote_ts           : float

    Pairs whose latest choice was CLEAR are absent from the result —
    matching ReactionState's behaviour of dropping cleared entries.
    """
    snapshots: dict[tuple[bytes, bytes, bool], dict] = {}
    balances: dict[bytes, int] = {}
    spend_pcts: dict[bytes, float] = {}
    first_seen_ts: dict[bytes, float] = {}

    # Best-effort against partial stubs: bare-Blockchain test fixtures
    # often skip ``supply`` because they only exercise the vote-count
    # code path.  Returning an empty snapshot map in that case lets the
    # downstream helpers fall back to "no weighted_rates field" instead
    # of crashing the whole feed.
    supply = getattr(blockchain, "supply", None)
    if supply is None:
        return snapshots
    genesis_supply = getattr(supply, "GENESIS_SUPPLY", GENESIS_SUPPLY)
    running_supply = genesis_supply
    block_reward_fn = getattr(supply, "calculate_block_reward", None)

    def _seen(eid: bytes, ts: float) -> None:
        if eid not in first_seen_ts:
            first_seen_ts[eid] = ts

    def _spend(eid: bytes, amount: int) -> None:
        if amount > 0 and running_supply > 0:
            spend_pcts[eid] = (
                spend_pcts.get(eid, 0.0) + 100.0 * amount / running_supply
            )

    def _credit(eid: bytes, amount: int) -> None:
        balances[eid] = balances.get(eid, 0) + amount

    def _debit(eid: bytes, amount: int) -> None:
        balances[eid] = balances.get(eid, 0) - amount

    for block in blockchain.chain:
        bn = block.header.block_number
        bts = block.header.timestamp

        reward = block_reward_fn(bn) if block_reward_fn else 0
        running_supply += reward
        proposer = getattr(block.header, "proposer_id", None)
        if proposer:
            _seen(proposer, bts)
            _credit(proposer, reward)

        for tx in block.transactions:
            eid = tx.entity_id
            _seen(eid, bts)
            _debit(eid, tx.fee)
            _spend(eid, tx.fee)

        for ttx in getattr(block, "transfer_transactions", None) or []:
            sender = ttx.entity_id
            recipient = getattr(ttx, "recipient_id", None)
            amount = getattr(ttx, "amount", 0)
            fee = getattr(ttx, "fee", 0)
            _seen(sender, bts)
            _debit(sender, amount + fee)
            _spend(sender, amount + fee)
            if recipient is not None:
                _seen(recipient, bts)
                _credit(recipient, amount)

        for rtx in getattr(block, "react_transactions", None) or []:
            voter = rtx.voter_id
            fee = getattr(rtx, "fee", 0)
            _seen(voter, bts)
            _debit(voter, fee)
            _spend(voter, fee)

            key = (rtx.voter_id, rtx.target, bool(rtx.target_is_user))
            if rtx.choice == REACT_CHOICE_CLEAR:
                snapshots.pop(key, None)
            else:
                snapshots[key] = {
                    "balance_at_vote": max(0, balances.get(voter, 0)),
                    "spend_pct_at_vote": spend_pcts.get(voter, 0.0),
                    "age_sec_at_vote": max(
                        0.0, bts - first_seen_ts[voter],
                    ),
                    "vote_block": bn,
                    "vote_ts": bts,
                }

        for gtx in getattr(block, "governance_txs", None) or []:
            cls_name = type(gtx).__name__
            fee = getattr(gtx, "fee", 0)
            if cls_name in ("ProposalTransaction", "TreasurySpendTransaction"):
                actor = getattr(gtx, "proposer_id", None)
            elif cls_name == "VoteTransaction":
                actor = getattr(gtx, "voter_id", None)
            else:
                actor = None
            if actor is not None:
                _seen(actor, bts)
                _debit(actor, fee)
                _spend(actor, fee)

        for stx in getattr(block, "stake_transactions", None) or []:
            eid = getattr(stx, "entity_id", None)
            fee = getattr(stx, "fee", 0)
            if eid is not None:
                _seen(eid, bts)
                _debit(eid, fee)
                _spend(eid, fee)

        for utx in getattr(block, "unstake_transactions", None) or []:
            eid = getattr(utx, "entity_id", None)
            fee = getattr(utx, "fee", 0)
            if eid is not None:
                _seen(eid, bts)
                _debit(eid, fee)
                _spend(eid, fee)

    return snapshots


def weighted_up_rates(
    weighted_votes: Iterable[tuple[int, dict]],
) -> dict | None:
    """Compute four weighted UP-rate percentages from per-vote snapshots.

    ``weighted_votes`` is an iterable of ``(choice, snapshot)`` pairs.
    ``choice`` is ``REACT_CHOICE_UP`` or ``REACT_CHOICE_DOWN``; CLEAR
    entries should be filtered out before calling.  ``snapshot`` is a
    dict with ``balance_at_vote`` / ``spend_pct_at_vote`` /
    ``age_sec_at_vote`` keys (the output of
    ``compute_vote_weight_snapshots``).

    Returns a dict with:

        by_balance_pct : float | None
        by_spend_pct   : float | None
        by_age_pct     : float | None
        by_rep_pct     : float | None   (age × spend placeholder)

    Each axis is None when the sum of weights over UP + DOWN voters is
    zero — e.g. all voters had no balance reconstructed at vote time, or
    all voted on their first block before any cumulative spend.  Returns
    None when the iterable yields no votes at all so the caller can tell
    "no votes" from "voters had zero weight."
    """
    balance_up = balance_total = 0.0
    spend_up = spend_total = 0.0
    age_up = age_total = 0.0
    rep_up = rep_total = 0.0
    count = 0

    for choice, snap in weighted_votes:
        count += 1
        balance = float(snap.get("balance_at_vote", 0))
        spend = float(snap.get("spend_pct_at_vote", 0.0))
        age = float(snap.get("age_sec_at_vote", 0.0))
        rep = age * spend

        is_up = choice == REACT_CHOICE_UP

        balance_total += balance
        spend_total += spend
        age_total += age
        rep_total += rep
        if is_up:
            balance_up += balance
            spend_up += spend
            age_up += age
            rep_up += rep

    if count == 0:
        return None

    def _pct(num: float, den: float) -> float | None:
        return (100.0 * num / den) if den > 0 else None

    return {
        "by_balance_pct": _pct(balance_up, balance_total),
        "by_spend_pct": _pct(spend_up, spend_total),
        "by_age_pct": _pct(age_up, age_total),
        "by_rep_pct": _pct(rep_up, rep_total),
    }


def compute_message_weighted_rates_map(
    reaction_state, snapshots: dict,
) -> dict:
    """Per-message weighted-rate map keyed by message tx_hash.

    Iterates the message-react entries in ``reaction_state.choices``
    (target_is_user=False), groups by target tx_hash, and computes
    ``weighted_up_rates`` for each.  Used by the recent-messages helpers
    in ``Blockchain`` to surface per-message ``weighted_rates`` alongside
    the simple ``ups`` / ``downs`` / ``up_pct`` triple.

    Messages with no non-CLEAR votes are absent from the result; callers
    should treat their absence as "no weighted_rates to show."
    """
    by_msg: dict[bytes, list[tuple[int, dict]]] = {}
    for (voter, target, target_is_user), choice in reaction_state.choices.items():
        if target_is_user:
            continue
        if choice not in (REACT_CHOICE_UP, REACT_CHOICE_DOWN):
            continue
        snap = snapshots.get((voter, target, target_is_user))
        if snap is None:
            continue
        by_msg.setdefault(target, []).append((choice, snap))
    return {
        tx_hash: weighted_up_rates(votes)
        for tx_hash, votes in by_msg.items()
    }


__all__ = [
    "compute_vote_weight_snapshots",
    "weighted_up_rates",
    "compute_message_weighted_rates_map",
]
