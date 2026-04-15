"""
On-chain voting for MessageChain.

A general-purpose secure voting system that records proposals, votes,
and results on-chain. Stake-holders vote using their staked tokens as
voting weight. Only entities with skin in the game (staked tokens) can
influence vote outcomes.

TERMINOLOGY — "delegation" in this module refers strictly to GOVERNANCE
delegation: a trust signal that routes a holder's VOTING WEIGHT to
chosen validators for proposal tallies.  It does NOT move, lock, or
bond any tokens, and it does NOT grant the delegate any consensus
weight (proposer selection or block finality).  Consensus weight is
determined solely by an entity's own staked balance.  This project
deliberately does NOT implement DPoS-style bonded delegation, where
delegated tokens would count toward a validator's consensus weight;
that model concentrates power into a small set of staking pools and
introduces slashing-cascade complexity without commensurate benefit.

What happens downstream of the vote results is out of scope — this
module provides a tamper-proof record of votes, nothing more.

Transaction types:
- ProposalTransaction: create a proposal (title + description + optional reference hash)
- VoteTransaction: cast a stake-weighted yes/no vote on a proposal
- DelegateTransaction: delegate voting power to another entity (single-hop)

Rules:
- Voting power = entity staked amount at proposal creation (snapshot)
- Votes are immutable — first vote wins, duplicates rejected
- Votes on closed proposals are rejected
- Delegation is single-hop (no transitive chains) and revocable
- A direct vote always overrides delegation for that proposal
- Proposals close after GOVERNANCE_VOTING_WINDOW blocks
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
import math
from messagechain import config
from messagechain.config import (
    HASH_ALGO,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_DELEGATE_FEE,
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    GOVERNANCE_BALANCE_SNAPSHOT_DUST,
    MAX_DELEGATION_TARGETS,
    MIN_FEE,
    TREASURY_ENTITY_ID,
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def voting_power(staked: int, unstaked: int) -> int:
    """Compute an entity's raw voting power from staked + unstaked tokens.

    Rule:
        voting_power = staked + isqrt(unstaked)

    Rationale:
    - Staked tokens get LINEAR weight.  You locked them, you accepted the
      7-day unbonding period, you have skin in the game — you get full voice.
    - Unstaked tokens get SQRT-DAMPENED weight.  Liquid holders still have
      influence (you're a bag holder, you want the network to succeed), but
      whales don't dominate proportionally.  A 1M-token wallet earns
      sqrt(1M) = 1,000 voting power unstaked vs. 1,000,000 staked — a strong
      incentive to stake if you want real voice.
    - Flash-loan governance attacks are largely neutralized: an attacker
      who borrows 10M tokens gets sqrt(10M) ≈ 3,162 voting weight from
      those unstaked tokens, not 10M.  Staking requires a 7-day unbond
      so borrowed tokens cannot cheaply be staked-for-a-vote-and-returned.

    Integer sqrt is used throughout for determinism across platforms.
    """
    staked_part = staked if staked > 0 else 0
    unstaked_part = math.isqrt(unstaked) if unstaked > 0 else 0
    return staked_part + unstaked_part


# --- Transaction types ---


@dataclass
class ProposalTransaction:
    """Create a governance proposal.

    Fields:
        proposer_id: entity creating the proposal
        title: short subject identifying what is being voted on
        description: detailed description of the proposal
        reference_hash: optional SHA3-256 hash of referenced external content
        timestamp: creation time
        fee: must be >= GOVERNANCE_PROPOSAL_FEE
        signature: proposer's quantum-resistant signature
    """
    proposer_id: bytes
    title: str
    description: str
    timestamp: float
    fee: int
    signature: Signature
    reference_hash: bytes = b""
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            config.CHAIN_ID
            + b"governance_proposal"
            + self.proposer_id
            + self.title.encode("utf-8")
            + self.description.encode("utf-8")
            + self.reference_hash
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    @property
    def proposal_id(self) -> bytes:
        """Unique proposal identifier derived from content."""
        return self.tx_hash

    def serialize(self) -> dict:
        return {
            "type": "governance_proposal",
            "proposer_id": self.proposer_id.hex(),
            "title": self.title,
            "description": self.description,
            "reference_hash": self.reference_hash.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ProposalTransaction":
        sig = Signature.deserialize(data["signature"])
        ref_hash_hex = data.get("reference_hash", "")
        ref_hash = bytes.fromhex(ref_hash_hex) if ref_hash_hex else b""
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            title=data["title"],
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            reference_hash=ref_hash,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Proposal tx hash mismatch")
        return tx


@dataclass
class VoteTransaction:
    """Cast a stake-weighted vote on a governance proposal.

    Fields:
        voter_id: entity casting the vote
        proposal_id: tx_hash of the ProposalTransaction being voted on
        approve: True for yes, False for no
        timestamp: vote time
        fee: must be >= GOVERNANCE_VOTE_FEE
        signature: voter's quantum-resistant signature
    """
    voter_id: bytes
    proposal_id: bytes
    approve: bool
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            config.CHAIN_ID
            + b"governance_vote"
            + self.voter_id
            + self.proposal_id
            + struct.pack(">?", self.approve)
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "governance_vote",
            "voter_id": self.voter_id.hex(),
            "proposal_id": self.proposal_id.hex(),
            "approve": self.approve,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "VoteTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            voter_id=bytes.fromhex(data["voter_id"]),
            proposal_id=bytes.fromhex(data["proposal_id"]),
            approve=data["approve"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Vote tx hash mismatch")
        return tx


@dataclass
class DelegateTransaction:
    """Delegate voting power to up to MAX_DELEGATION_TARGETS validators.

    To revoke all delegations, set targets to an empty list.
    Delegation covers all future proposals until changed or revoked.
    A direct vote on a specific proposal always overrides delegation.

    Fields:
        delegator_id: entity giving up their vote
        targets: list of (delegate_id, weight_pct) pairs — pcts must sum to 100
        timestamp: delegation time
        fee: must be >= GOVERNANCE_DELEGATE_FEE
        signature: delegator's quantum-resistant signature
    """
    delegator_id: bytes
    targets: list[tuple[bytes, int]]  # [(delegate_id, pct)] or [] to revoke
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        parts = config.CHAIN_ID + b"governance_delegate" + self.delegator_id
        for delegate_id, pct in sorted(self.targets, key=lambda x: x[0]):
            parts += delegate_id + struct.pack(">B", pct)
        parts += struct.pack(">d", self.timestamp)
        parts += struct.pack(">Q", self.fee)
        return parts

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "governance_delegate",
            "delegator_id": self.delegator_id.hex(),
            "targets": [
                {"delegate_id": did.hex(), "pct": pct}
                for did, pct in self.targets
            ],
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "DelegateTransaction":
        sig = Signature.deserialize(data["signature"])
        targets = [
            (bytes.fromhex(t["delegate_id"]), t["pct"])
            for t in data.get("targets", [])
        ]
        tx = cls(
            delegator_id=bytes.fromhex(data["delegator_id"]),
            targets=targets,
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Delegate tx hash mismatch")
        return tx


@dataclass
class ValidatorEjectionProposal:
    """Proposal to eject a validator from the active set.

    Any holder (validator or liquid) can propose ejection; any holder can
    vote using the standard governance voting-power formula.  On approval
    by 2/3 supermajority after the voting window, the target's stake is
    queued for unbonding and the validator is removed from proposer/
    attester duty.  Ejection is the penalty — no additional slashing.

    This is the on-chain lever for the community to remove a misbehaving
    validator without giving liquid holders direct weight in sub-second
    block confirmation (which would expose consensus to flash-loan attacks).

    Fields:
        proposer_id: entity creating the proposal
        target_validator_id: validator to eject
        title: short subject
        description: justification (typically cites off-chain evidence)
        timestamp: creation time
        fee: must be >= GOVERNANCE_PROPOSAL_FEE
        signature: proposer's quantum-resistant signature
    """
    proposer_id: bytes
    target_validator_id: bytes
    title: str
    description: str
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            config.CHAIN_ID
            + b"validator_ejection"
            + self.proposer_id
            + self.target_validator_id
            + self.title.encode("utf-8")
            + self.description.encode("utf-8")
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    @property
    def proposal_id(self) -> bytes:
        return self.tx_hash

    def serialize(self) -> dict:
        return {
            "type": "validator_ejection",
            "proposer_id": self.proposer_id.hex(),
            "target_validator_id": self.target_validator_id.hex(),
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ValidatorEjectionProposal":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            target_validator_id=bytes.fromhex(data["target_validator_id"]),
            title=data["title"],
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Validator ejection tx hash mismatch")
        return tx


@dataclass
class TreasurySpendTransaction:
    """Proposal to transfer funds from the governance-controlled treasury.

    Fields:
        proposer_id: entity proposing the spend
        recipient_id: entity that will receive the funds
        amount: number of tokens to transfer from treasury
        title: short subject describing the spend
        description: detailed justification
        timestamp: creation time
        fee: must be >= GOVERNANCE_PROPOSAL_FEE
        signature: proposer's quantum-resistant signature
    """
    proposer_id: bytes
    recipient_id: bytes
    amount: int
    title: str
    description: str
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            config.CHAIN_ID
            + b"treasury_spend"
            + self.proposer_id
            + self.recipient_id
            + struct.pack(">Q", self.amount)
            + self.title.encode("utf-8")
            + self.description.encode("utf-8")
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    @property
    def proposal_id(self) -> bytes:
        return self.tx_hash

    def serialize(self) -> dict:
        return {
            "type": "treasury_spend",
            "proposer_id": self.proposer_id.hex(),
            "recipient_id": self.recipient_id.hex(),
            "amount": self.amount,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "TreasurySpendTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            recipient_id=bytes.fromhex(data["recipient_id"]),
            amount=data["amount"],
            title=data["title"],
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Treasury spend tx hash mismatch")
        return tx


# --- Transaction creation helpers ---


def create_proposal(
    proposer_entity,
    title: str,
    description: str,
    reference_hash: bytes = b"",
    fee: int = GOVERNANCE_PROPOSAL_FEE,
) -> ProposalTransaction:
    """Create and sign a governance proposal."""
    tx = ProposalTransaction(
        proposer_id=proposer_entity.entity_id,
        title=title,
        description=description,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        reference_hash=reference_hash,
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = proposer_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def create_vote(
    voter_entity,
    proposal_id: bytes,
    approve: bool,
    fee: int = GOVERNANCE_VOTE_FEE,
) -> VoteTransaction:
    """Create and sign a governance vote."""
    tx = VoteTransaction(
        voter_id=voter_entity.entity_id,
        proposal_id=proposal_id,
        approve=approve,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = voter_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def create_treasury_spend_proposal(
    proposer_entity,
    recipient_id: bytes,
    amount: int,
    title: str,
    description: str,
    fee: int = GOVERNANCE_PROPOSAL_FEE,
) -> TreasurySpendTransaction:
    """Create and sign a treasury spend proposal."""
    tx = TreasurySpendTransaction(
        proposer_id=proposer_entity.entity_id,
        recipient_id=recipient_id,
        amount=amount,
        title=title,
        description=description,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = proposer_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def create_validator_ejection_proposal(
    proposer_entity,
    target_validator_id: bytes,
    title: str,
    description: str,
    fee: int = GOVERNANCE_PROPOSAL_FEE,
) -> ValidatorEjectionProposal:
    """Create and sign a validator ejection proposal."""
    tx = ValidatorEjectionProposal(
        proposer_id=proposer_entity.entity_id,
        target_validator_id=target_validator_id,
        title=title,
        description=description,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = proposer_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def create_delegation(
    delegator_entity,
    targets: list[tuple[bytes, int]],
    fee: int = GOVERNANCE_DELEGATE_FEE,
) -> DelegateTransaction:
    """Create and sign a delegation (or revocation if targets is empty)."""
    tx = DelegateTransaction(
        delegator_id=delegator_entity.entity_id,
        targets=targets,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(tx._signable_data())
    tx.signature = delegator_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


# --- Proposal state ---


class ProposalStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass
class ProposalState:
    """Tracks the on-chain state of a proposal.

    Snapshots captured at proposal creation time and frozen thereafter.
    This prevents manipulation by last-minute staking or balance movement.

    stake_snapshot: validator entity_id -> staked tokens at proposal creation
    balance_snapshot: entity_id -> unstaked balance at proposal creation
        (only entities with balance > GOVERNANCE_BALANCE_SNAPSHOT_DUST are
        included — dust amounts contribute negligible sqrt-voting power)
    """
    proposal: ProposalTransaction
    created_at_block: int
    stake_snapshot: dict  # entity_id -> staked amount at proposal creation
    total_eligible_stake: int
    votes: dict = field(default_factory=dict)  # voter_id -> bool
    balance_snapshot: dict = field(default_factory=dict)  # entity_id -> unstaked


# --- Governance tracker ---


class GovernanceTracker:
    """Tracks all voting state: proposals, votes, and delegations.

    This is the core state machine for on-chain voting. It is updated
    by the blockchain when governance transactions are included in blocks.
    The tracker records votes and tallies results — it does not enforce
    any outcomes.
    """

    def __init__(self):
        self.proposals: dict[bytes, ProposalState] = {}  # proposal_id -> state
        # delegator_id -> list of (delegate_id, weight_pct) — pcts must sum to 100
        self.delegations: dict[bytes, list[tuple[bytes, int]]] = {}
        self._executed_treasury_spends: set[bytes] = set()  # replay protection
        self._executed_ejections: set[bytes] = set()  # replay protection
        # Append-only audit logs — every successful binding execution is
        # recorded with tx_hash, execution_block, and outcome-specific
        # fields.  These survive proposal pruning so post-hoc accountability
        # ("show me every treasury spend that ever executed") always works.
        self.treasury_spend_log: list[dict] = []
        self.ejection_log: list[dict] = []

    def add_proposal(self, tx: ProposalTransaction, block_height: int, supply_tracker):
        """Register a new proposal and snapshot current stake + balance distribution.

        Snapshots:
        - stake_snapshot: every entity with staked > 0 (these are the validators)
        - balance_snapshot: every entity with unstaked balance above dust threshold

        Both are captured as of block_height.  Tally uses snapshots only, never
        live state — so moving tokens after proposal creation cannot swing votes.
        """
        stake_snapshot = {
            eid: amount
            for eid, amount in supply_tracker.staked.items()
            if amount > 0
        }
        balance_snapshot = {
            eid: bal
            for eid, bal in supply_tracker.balances.items()
            if bal > GOVERNANCE_BALANCE_SNAPSHOT_DUST
        }
        total = sum(stake_snapshot.values())
        self.proposals[tx.proposal_id] = ProposalState(
            proposal=tx,
            created_at_block=block_height,
            stake_snapshot=stake_snapshot,
            total_eligible_stake=total,
            balance_snapshot=balance_snapshot,
        )

    def prune_closed_proposals(self, current_block: int) -> int:
        """Remove proposals whose voting window has closed.

        Prevents unbounded growth of self.proposals from governance spam.
        Returns the number of proposals pruned.
        """
        to_remove = [
            pid for pid, state in self.proposals.items()
            if current_block - state.created_at_block > GOVERNANCE_VOTING_WINDOW
        ]
        for pid in to_remove:
            del self.proposals[pid]
        return len(to_remove)

    def add_vote(self, tx: VoteTransaction, current_block: int) -> bool:
        """Record a vote. Returns False if rejected (closed or duplicate)."""
        state = self.proposals.get(tx.proposal_id)
        if state is None:
            return False
        # Reject votes after voting window closes
        if current_block - state.created_at_block > GOVERNANCE_VOTING_WINDOW:
            return False
        # Reject duplicate votes (immutable — first vote wins)
        if tx.voter_id in state.votes:
            return False
        state.votes[tx.voter_id] = tx.approve
        return True

    def set_delegation(
        self, delegator_id: bytes, targets: list[tuple[bytes, int]],
    ) -> bool:
        """Set or revoke delegation to up to MAX_DELEGATION_TARGETS validators.

        targets: list of (delegate_id, weight_pct) pairs. Percentages must
        sum to 100. Empty list revokes all delegations.
        Returns False if validation fails.
        """
        if not targets:
            self.delegations.pop(delegator_id, None)
            return True
        if len(targets) > MAX_DELEGATION_TARGETS:
            return False
        if any(did == delegator_id for did, _ in targets):
            return False
        if sum(pct for _, pct in targets) != 100:
            return False
        if any(pct <= 0 for _, pct in targets):
            return False
        self.delegations[delegator_id] = targets
        return True

    def revoke_delegations_to(self, validator_id: bytes):
        """Revoke all delegations pointing to a validator.

        Called when the validator is "completely kicked from the network":
        - Slashed (stake forcibly confiscated), or
        - Fully unstaked (stake dropped to 0 voluntarily)

        After revocation, the delegators automatically revert to auto-mode
        (sqrt-weighted distribution across current validators) for future
        tallies.  In-flight proposals also reflect the revocation: the
        delegation relationship is LIVE state, not snapshotted.

        Temporary offline does NOT trigger revocation — the user explicitly
        chose this validator and we respect that choice until they're
        permanently removed.  An offline validator's delegated power simply
        doesn't count for proposals the validator misses (since they didn't
        vote); this is the right incentive.
        """
        to_remove = []
        for delegator_id, targets in self.delegations.items():
            if any(did == validator_id for did, _ in targets):
                to_remove.append(delegator_id)
        for delegator_id in to_remove:
            del self.delegations[delegator_id]

    def get_proposal_status(
        self, proposal_id: bytes, current_block: int,
    ) -> ProposalStatus:
        """Determine whether a proposal is OPEN or CLOSED."""
        state = self.proposals.get(proposal_id)
        if state is None:
            raise ValueError("Unknown proposal")

        blocks_elapsed = current_block - state.created_at_block
        if blocks_elapsed > GOVERNANCE_VOTING_WINDOW:
            return ProposalStatus.CLOSED

        return ProposalStatus.OPEN

    def list_proposals(self, current_block: int) -> list[dict]:
        """Return a JSON-friendly snapshot of every tracked proposal.

        Used by the CLI's `proposals` command so operators can see what's
        open, how many blocks remain, and the current tally without
        needing to decode state manually.
        """
        rows = []
        for pid, state in self.proposals.items():
            yes_weight, total_weight = self.tally(pid)
            status = self.get_proposal_status(pid, current_block)
            blocks_remaining = max(
                0,
                GOVERNANCE_VOTING_WINDOW - (current_block - state.created_at_block),
            )
            rows.append({
                "proposal_id": pid.hex(),
                "proposer_id": state.proposal.proposer_id.hex(),
                "title": state.proposal.title,
                "created_at_block": state.created_at_block,
                "blocks_remaining": blocks_remaining,
                "status": status.value,
                "yes_weight": yes_weight,
                "total_weight": total_weight,
                "total_eligible_stake": state.total_eligible_stake,
                "vote_count": len(state.votes),
            })
        rows.sort(key=lambda r: r["created_at_block"], reverse=True)
        return rows

    def tally(self, proposal_id: bytes) -> tuple[int, int]:
        """Tally votes for a proposal, weighted by voting power.

        Returns (yes_weight, total_participating_weight).

        Voting power for entity E at snapshot time:
            vp(E) = staked(E) + isqrt(unstaked_balance(E))

        Staked tokens count linearly (full weight); unstaked tokens count
        with sqrt-dampening.  This rewards committed stakers while still
        letting liquid holders participate at a dampened level.

        Snapshot-based — uses the stake and balance captured at proposal
        creation, NOT live state.  Prevents manipulation by late
        staking/transferring.

        Delegation rules:
        1. Direct vote: voter's full voting power counts.  Overrides any
           delegation for that proposal.
        2. Explicit delegation: delegator's voting power is split across
           their chosen validators per their declared percentages.  If a
           chosen validator did not vote, that portion is not counted.
        3. Auto-delegation (no explicit delegation, no direct vote): the
           entity's voting power is distributed across the validator set
           (from the snapshot), weighted by sqrt(validator_stake), so
           each voting validator receives a share.  Non-voting validators
           receive nothing — passive power only counts via validators who
           actually voted.
        4. Single-hop only — validators' own delegations (if any) do not
           cascade.

        Rationale for auto-delegation via sqrt-weighted validator set:
        big-bag holders want the network to succeed even if they don't
        follow every proposal; their default voice should flow to the
        validators who are actively securing the chain.  sqrt-weighting
        prevents a single mega-validator from absorbing all passive power.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0

        stake_snapshot = state.stake_snapshot
        balance_snapshot = state.balance_snapshot
        direct_votes = dict(state.votes)

        # --- Build voting power per entity at snapshot time ---
        all_entities: set[bytes] = set(stake_snapshot.keys()) | set(balance_snapshot.keys())
        vp: dict[bytes, int] = {}
        for eid in all_entities:
            vp[eid] = voting_power(
                stake_snapshot.get(eid, 0),
                balance_snapshot.get(eid, 0),
            )

        # --- Build reverse explicit-delegation map ---
        reverse_delegations: dict[bytes, list[tuple[bytes, int]]] = {}
        explicitly_delegated: set[bytes] = set()
        for delegator_id, targets in self.delegations.items():
            explicitly_delegated.add(delegator_id)
            for delegate_id, pct in targets:
                reverse_delegations.setdefault(delegate_id, []).append(
                    (delegator_id, pct)
                )

        yes_weight = 0
        total_weight = 0

        # --- 1 & 2: direct votes + explicit delegations flowing into voters ---
        for voter_id, approve in direct_votes.items():
            power = vp.get(voter_id, 0)
            total_weight += power
            if approve:
                yes_weight += power

            # Add explicitly delegated weight flowing to this voter
            for delegator_id, pct in reverse_delegations.get(voter_id, []):
                if delegator_id in direct_votes:
                    continue  # direct vote overrides delegation
                delegator_power = vp.get(delegator_id, 0)
                portion = delegator_power * pct // 100
                total_weight += portion
                if approve:
                    yes_weight += portion

        # --- 3: auto-delegation for passive entities ---
        # Distribute passive voting power across validators who voted,
        # weighted by sqrt(validator_stake_at_snapshot).
        #
        # Only validators present in the snapshot are eligible recipients
        # — new validators who registered after proposal creation cannot
        # absorb passive power.
        voting_validators = {
            v for v in stake_snapshot.keys() if v in direct_votes
        }
        sqrt_weights: dict[bytes, int] = {}
        for v in voting_validators:
            sqrt_weights[v] = math.isqrt(stake_snapshot.get(v, 0))
        total_sqrt = sum(sqrt_weights.values())

        if total_sqrt > 0:
            for entity_id, power in vp.items():
                if power == 0:
                    continue
                if entity_id in direct_votes:
                    continue  # direct vote handled above
                if entity_id in explicitly_delegated:
                    continue  # explicit delegation handled above
                # Distribute across voting validators, sqrt-weighted
                for v, sw in sqrt_weights.items():
                    share = power * sw // total_sqrt
                    if share == 0:
                        continue
                    total_weight += share
                    if direct_votes[v]:
                        yes_weight += share

        return yes_weight, total_weight

    def execute_treasury_spend(
        self,
        tx: TreasurySpendTransaction,
        supply_tracker,
        current_block: int = 0,
    ) -> bool:
        """Execute an approved treasury spend. Returns False if rejected.

        Rejects if:
        - Amount is invalid
        - Treasury has insufficient funds
        - Spend has already been executed (replay protection)
        - Proposal does not exist on-chain
        - Voting window is still open
        - Proposal did not reach the approval threshold
        """
        if tx.amount <= 0:
            return False
        # Replay protection — each tx_hash can only execute once
        if tx.tx_hash in self._executed_treasury_spends:
            return False
        # Require an on-chain proposal for this treasury spend
        state = self.proposals.get(tx.proposal_id)
        if state is None:
            return False
        # Voting must be closed before execution
        status = self.get_proposal_status(tx.proposal_id, current_block)
        if status != ProposalStatus.CLOSED:
            return False
        # Binding-outcome approval: yes must clear 2/3 of TOTAL ELIGIBLE
        # stake (not just participants).  This closes the auto-delegation
        # capture vector — silence cannot be harvested into approval —
        # and provides an implicit 2/3 turnout floor.
        yes_weight, total_weight = self._tally_binding(tx.proposal_id)
        if total_weight == 0:
            return False
        if (yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
                <= total_weight * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR):
            return False
        result = supply_tracker.treasury_spend(tx.recipient_id, tx.amount)
        if result:
            self._executed_treasury_spends.add(tx.tx_hash)
            self.treasury_spend_log.append({
                "tx_hash": tx.tx_hash.hex(),
                "proposal_id": tx.proposal_id.hex(),
                "recipient_id": tx.recipient_id.hex(),
                "amount": tx.amount,
                "execution_block": current_block,
                "yes_weight": yes_weight,
                "total_eligible_weight": total_weight,
            })
        return result

    def _tally_binding(
        self, proposal_id: bytes, exclude: bytes | None = None,
    ) -> tuple[int, int]:
        """Stricter tally used for BINDING governance outcomes (treasury
        spends, validator ejections).  Differs from the general `tally`:

        1. Optional `exclude` entity is removed entirely — used by ejection
           so the target does not vote in their own trial, and their stake
           does not appear anywhere.  Treasury spends pass exclude=None.
        2. Auto-delegation is disabled.  Only DIRECT votes and EXPLICIT
           delegations count toward `yes_weight`.
        3. The denominator is the TOTAL ELIGIBLE VOTING POWER (all snapshot
           entities except `exclude`), not just participating weight.
           Silence counts as "no" — a deliberate bias toward the status quo
           for security-critical decisions.

        Why the stricter rule: under the general tally, auto-delegation
        lets one motivated voter harvest everyone else's passive stake
        during periods of apathy.  For binding outcomes that move funds
        or reshape the validator set, requiring the numerator to clear
        2/3 of the FULL eligible electorate (not just participants)
        forces broad active engagement.  This rule also gives an implicit
        quorum for free: yes can't reach 2/3 of eligible without at least
        2/3 turnout participating in favor.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0

        stake_snapshot = state.stake_snapshot
        balance_snapshot = state.balance_snapshot
        direct_votes = {
            vid: approve for vid, approve in state.votes.items()
            if vid != exclude
        }

        all_entities: set[bytes] = (
            set(stake_snapshot.keys()) | set(balance_snapshot.keys())
        )
        vp: dict[bytes, int] = {}
        for eid in all_entities:
            vp[eid] = voting_power(
                stake_snapshot.get(eid, 0),
                balance_snapshot.get(eid, 0),
            )

        reverse_delegations: dict[bytes, list[tuple[bytes, int]]] = {}
        for delegator_id, targets in self.delegations.items():
            for delegate_id, pct in targets:
                reverse_delegations.setdefault(delegate_id, []).append(
                    (delegator_id, pct)
                )

        # Denominator: total eligible voting power (everyone except exclude).
        total_weight = sum(
            power for eid, power in vp.items() if eid != exclude
        )

        yes_weight = 0
        for voter_id, approve in direct_votes.items():
            if not approve:
                continue
            power = vp.get(voter_id, 0)
            yes_weight += power

            for delegator_id, pct in reverse_delegations.get(voter_id, []):
                if delegator_id in direct_votes:
                    continue  # delegator voted directly — their power counted only if they voted yes
                if delegator_id == exclude:
                    continue
                delegator_power = vp.get(delegator_id, 0)
                yes_weight += delegator_power * pct // 100

        return yes_weight, total_weight

    def execute_validator_ejection(
        self,
        tx: ValidatorEjectionProposal,
        supply_tracker,
        pos_consensus=None,
        current_block: int = 0,
    ) -> bool:
        """Execute an approved validator ejection. Returns False if rejected.

        Rejects if:
        - Ejection has already been executed (replay protection)
        - Proposal does not exist on-chain
        - Voting window is still open
        - Proposal did not reach the approval threshold
        - Target is not an active validator
        - SupplyTracker refuses the unstake (e.g., would drop total network
          stake below the safety floor — better to fail safely than break
          liveness; the community can re-propose once more validators join)

        On success:
        - Target's full stake enters the normal unbonding queue
        - Target removed from the active validator set
        - Any delegations pointing at the target are revoked
        """
        if tx.tx_hash in self._executed_ejections:
            return False
        state = self.proposals.get(tx.proposal_id)
        if state is None:
            return False
        status = self.get_proposal_status(tx.proposal_id, current_block)
        if status != ProposalStatus.CLOSED:
            return False
        target = tx.target_validator_id
        yes_weight, total_weight = self._tally_binding(tx.proposal_id, exclude=target)
        if total_weight == 0:
            return False
        if (yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
                <= total_weight * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR):
            return False

        full_stake = supply_tracker.get_staked(target)
        if full_stake <= 0:
            return False

        # Move entire stake into unbonding.  We pass bootstrap_ended + the
        # projected post-unstake total so SupplyTracker can refuse if this
        # would drop the network below MIN_TOTAL_STAKE.  Failing safely here
        # is the right call: a chain that can't maintain liveness is worse
        # than leaving a bad actor in place until more validators join.
        #
        # The "bootstrap_ended" gate here is a finality-floor concern:
        # it asks whether the chain has enough validators that the
        # MIN_TOTAL_STAKE check is meaningful.  When pos_consensus is
        # provided (normal path), trust its view; otherwise fall back
        # to counting active validators against the finality minimum.
        if pos_consensus is not None:
            bootstrap_ended = not pos_consensus.is_bootstrap_mode
        else:
            from messagechain.config import MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
            active_count = sum(1 for s in supply_tracker.staked.values() if s > 0)
            bootstrap_ended = active_count >= MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
        projected_total = sum(supply_tracker.staked.values()) - full_stake
        unstaked = supply_tracker.unstake(
            target,
            full_stake,
            current_block=current_block,
            total_staked_after_check=projected_total,
            bootstrap_ended=bootstrap_ended,
        )
        if not unstaked:
            return False

        if pos_consensus is not None:
            pos_consensus.remove_validator(target)
        self.revoke_delegations_to(target)
        self._executed_ejections.add(tx.tx_hash)
        self.ejection_log.append({
            "tx_hash": tx.tx_hash.hex(),
            "proposal_id": tx.proposal_id.hex(),
            "target_validator_id": target.hex(),
            "stake_unbonded": full_stake,
            "execution_block": current_block,
            "yes_weight": yes_weight,
            "total_eligible_weight": total_weight,
        })
        return True

    def get_proposal_info(
        self, proposal_id: bytes, current_block: int,
    ) -> dict:
        """Get a summary of a proposal's current state and tally."""
        state = self.proposals.get(proposal_id)
        if state is None:
            raise ValueError("Unknown proposal")

        yes_weight, total_weight = self.tally(proposal_id)
        status = self.get_proposal_status(proposal_id, current_block)
        blocks_remaining = max(
            0,
            GOVERNANCE_VOTING_WINDOW - (current_block - state.created_at_block),
        )

        return {
            "proposal_id": proposal_id.hex(),
            "title": state.proposal.title,
            "description": state.proposal.description,
            "reference_hash": state.proposal.reference_hash.hex() if state.proposal.reference_hash else "",
            "proposer": state.proposal.proposer_id.hex(),
            "status": status.value,
            "yes_weight": yes_weight,
            "total_weight": total_weight,
            "total_eligible_stake": state.total_eligible_stake,
            "approval_pct": (yes_weight / total_weight * 100) if total_weight > 0 else 0,
            "blocks_remaining": blocks_remaining,
            "direct_votes": len(state.votes),
        }


# --- Validation helpers ---


MAX_PROPOSAL_TITLE_LENGTH = 200
MAX_PROPOSAL_DESCRIPTION_LENGTH = 10_000


def verify_proposal(tx: ProposalTransaction, public_key: bytes) -> bool:
    """Verify a proposal transaction's signature."""
    if tx.fee < GOVERNANCE_PROPOSAL_FEE:
        return False
    if not tx.title:
        return False
    # M10: Bound title/description to prevent block bloat
    if len(tx.title) > MAX_PROPOSAL_TITLE_LENGTH:
        return False
    if len(tx.description) > MAX_PROPOSAL_DESCRIPTION_LENGTH:
        return False
    if tx.reference_hash and len(tx.reference_hash) != 32:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_vote(tx: VoteTransaction, public_key: bytes) -> bool:
    """Verify a vote transaction's signature."""
    if tx.fee < GOVERNANCE_VOTE_FEE:
        return False
    if not tx.proposal_id or len(tx.proposal_id) != 32:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_treasury_spend(tx: TreasurySpendTransaction, public_key: bytes) -> bool:
    """Verify a treasury spend proposal's signature and fields."""
    if tx.fee < GOVERNANCE_PROPOSAL_FEE:
        return False
    if not tx.title:
        return False
    if tx.amount <= 0:
        return False
    if not tx.recipient_id:
        return False
    if tx.recipient_id == TREASURY_ENTITY_ID:
        return False  # treasury cannot send to itself
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_validator_ejection(
    tx: ValidatorEjectionProposal, public_key: bytes,
) -> bool:
    """Verify an ejection proposal's signature and fields."""
    if tx.fee < GOVERNANCE_PROPOSAL_FEE:
        return False
    if not tx.title:
        return False
    if len(tx.title) > MAX_PROPOSAL_TITLE_LENGTH:
        return False
    if len(tx.description) > MAX_PROPOSAL_DESCRIPTION_LENGTH:
        return False
    if not tx.target_validator_id:
        return False
    if tx.target_validator_id == tx.proposer_id:
        return False  # proposer cannot eject themselves via this path
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_delegation(tx: DelegateTransaction, public_key: bytes) -> bool:
    """Verify a delegation transaction's signature and targets."""
    if tx.fee < GOVERNANCE_DELEGATE_FEE:
        return False
    if len(tx.targets) > MAX_DELEGATION_TARGETS:
        return False
    if tx.targets:
        if any(did == tx.delegator_id for did, _ in tx.targets):
            return False
        if sum(pct for _, pct in tx.targets) != 100:
            return False
        if any(pct <= 0 for _, pct in tx.targets):
            return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
