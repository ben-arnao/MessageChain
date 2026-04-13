"""
On-chain voting for MessageChain.

A general-purpose secure voting system that records proposals, votes,
and results on-chain. Stake-holders vote using their staked tokens as
voting weight. Only entities with skin in the game (staked tokens) can
influence vote outcomes.

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
from messagechain.config import (
    HASH_ALGO,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_DELEGATE_FEE,
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    MAX_DELEGATION_TARGETS,
    MIN_FEE,
    TREASURY_ENTITY_ID,
)
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


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
            b"governance_proposal"
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
            b"governance_vote"
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
        parts = b"governance_delegate" + self.delegator_id
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
            b"treasury_spend"
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
    """Tracks the on-chain state of a proposal."""
    proposal: ProposalTransaction
    created_at_block: int
    stake_snapshot: dict  # entity_id -> staked amount at proposal creation
    total_eligible_stake: int
    votes: dict = field(default_factory=dict)  # voter_id -> bool


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

    def add_proposal(self, tx: ProposalTransaction, block_height: int, supply_tracker):
        """Register a new proposal and snapshot current stake distribution."""
        snapshot = dict(supply_tracker.staked)
        total = sum(snapshot.values())
        self.proposals[tx.proposal_id] = ProposalState(
            proposal=tx,
            created_at_block=block_height,
            stake_snapshot=snapshot,
            total_eligible_stake=total,
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
        """Revoke all delegations pointing to a validator (e.g. after slashing)."""
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

    def tally(self, proposal_id: bytes) -> tuple[int, int]:
        """Tally votes for a proposal, weighted by snapshotted stake.

        Returns (yes_weight, total_participating_weight).

        Uses the stake snapshot captured at proposal creation — not live
        state — so late staking cannot manipulate results.

        Delegation rules:
        - Explicit delegation: weight is split proportionally across targets
          who voted. If a target didn't vote, that portion is not counted.
        - Default delegation (no explicit delegation): weight is distributed
          to voters using sqrt(stake) weighting.
        - Direct vote always overrides any delegation.
        - Single-hop only: no transitive delegation.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0

        snapshot = state.stake_snapshot
        direct_votes = dict(state.votes)

        # Build reverse delegation map: delegate_id -> [(delegator_id, pct)]
        reverse_delegations: dict[bytes, list[tuple[bytes, int]]] = {}
        explicitly_delegated: set[bytes] = set()
        for delegator_id, targets in self.delegations.items():
            explicitly_delegated.add(delegator_id)
            for delegate_id, pct in targets:
                if delegate_id not in reverse_delegations:
                    reverse_delegations[delegate_id] = []
                reverse_delegations[delegate_id].append((delegator_id, pct))

        yes_weight = 0
        total_weight = 0

        # Count direct votes + explicit delegations
        for voter_id, approve in direct_votes.items():
            stake = snapshot.get(voter_id, 0)
            total_weight += stake
            if approve:
                yes_weight += stake

            # Add explicitly delegated weight (proportional)
            for delegator_id, pct in reverse_delegations.get(voter_id, []):
                if delegator_id not in direct_votes:
                    delegator_stake = snapshot.get(delegator_id, 0)
                    portion = delegator_stake * pct // 100
                    total_weight += portion
                    if approve:
                        yes_weight += portion

        # Passive entities (non-voting, non-delegating) are NOT counted.
        # Auto-assigning passive stake to active voters would let a small
        # number of voters capture the full weight of all offline
        # stakeholders — a governance capture vector. Only explicit votes
        # and explicit delegations count.

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
        # Require approval threshold: yes * DENOM > total * NUM
        yes_weight, total_weight = self.tally(tx.proposal_id)
        if total_weight == 0:
            return False
        if (yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
                <= total_weight * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR):
            return False
        result = supply_tracker.treasury_spend(tx.recipient_id, tx.amount)
        if result:
            self._executed_treasury_spends.add(tx.tx_hash)
        return result

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


def verify_proposal(tx: ProposalTransaction, public_key: bytes) -> bool:
    """Verify a proposal transaction's signature."""
    if tx.fee < GOVERNANCE_PROPOSAL_FEE:
        return False
    if not tx.title:
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
