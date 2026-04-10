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
from messagechain.config import (
    HASH_ALGO,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_DELEGATE_FEE,
    MIN_FEE,
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
    """Delegate voting power to another entity (single-hop, revocable).

    To revoke delegation, set delegate_id to empty bytes (b"").
    Delegation covers all future proposals until revoked.
    A direct vote on a specific proposal always overrides delegation.

    Fields:
        delegator_id: entity giving up their vote
        delegate_id: entity receiving voting power (b"" to revoke)
        timestamp: delegation time
        fee: must be >= GOVERNANCE_DELEGATE_FEE
        signature: delegator's quantum-resistant signature
    """
    delegator_id: bytes
    delegate_id: bytes  # b"" means revoke
    timestamp: float
    fee: int
    signature: Signature
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            b"governance_delegate"
            + self.delegator_id
            + self.delegate_id
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "governance_delegate",
            "delegator_id": self.delegator_id.hex(),
            "delegate_id": self.delegate_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "DelegateTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            delegator_id=bytes.fromhex(data["delegator_id"]),
            delegate_id=bytes.fromhex(data["delegate_id"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Delegate tx hash mismatch")
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


def create_delegation(
    delegator_entity,
    delegate_id: bytes,
    fee: int = GOVERNANCE_DELEGATE_FEE,
) -> DelegateTransaction:
    """Create and sign a delegation (or revocation if delegate_id is empty)."""
    tx = DelegateTransaction(
        delegator_id=delegator_entity.entity_id,
        delegate_id=delegate_id,
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
        self.delegations: dict[bytes, bytes] = {}  # delegator_id -> delegate_id

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

    def set_delegation(self, delegator_id: bytes, delegate_id: bytes):
        """Set or revoke a delegation."""
        if delegate_id == b"":
            self.delegations.pop(delegator_id, None)
        else:
            self.delegations[delegator_id] = delegate_id

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
        - If entity A delegated to entity B, and B voted but A did not,
          then A's snapshot stake counts toward B's vote direction.
        - If A voted directly, their delegation is ignored for this proposal.
        - Single-hop only: if B delegated to C, A's weight does NOT follow.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0

        snapshot = state.stake_snapshot
        direct_votes = dict(state.votes)

        # Build reverse delegation map: delegate_id -> [delegator_ids]
        reverse_delegations: dict[bytes, list[bytes]] = {}
        for delegator_id, delegate_id in self.delegations.items():
            if delegate_id not in reverse_delegations:
                reverse_delegations[delegate_id] = []
            reverse_delegations[delegate_id].append(delegator_id)

        yes_weight = 0
        total_weight = 0

        for voter_id, approve in direct_votes.items():
            stake = snapshot.get(voter_id, 0)
            total_weight += stake
            if approve:
                yes_weight += stake

            # Add delegated weight from entities who didn't vote directly
            for delegator_id in reverse_delegations.get(voter_id, []):
                if delegator_id not in direct_votes:
                    delegator_stake = snapshot.get(delegator_id, 0)
                    total_weight += delegator_stake
                    if approve:
                        yes_weight += delegator_stake

        return yes_weight, total_weight

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


def verify_delegation(tx: DelegateTransaction, public_key: bytes) -> bool:
    """Verify a delegation transaction's signature."""
    if tx.fee < GOVERNANCE_DELEGATE_FEE:
        return False
    if tx.delegate_id == tx.delegator_id:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
