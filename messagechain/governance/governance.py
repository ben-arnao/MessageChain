"""
On-chain governance for MessageChain.

Enables stake-holders to vote on protocol/codebase changes (e.g., GitHub PRs)
using their wallet balance as voting weight. Designed so the community can
signal consensus before changes are merged.

Transaction types:
- ProposalTransaction: create a proposal linked to a PR (URL + content hash)
- VoteTransaction: cast a balance-weighted yes/no vote on a proposal
- DelegateTransaction: delegate voting power to another entity (single-hop)

Rules:
- Voting power = entity wallet balance at time of tally
- Delegation is single-hop (no transitive chains) and revocable
- A direct vote always overrides delegation for that proposal
- Proposals expire after GOVERNANCE_VOTING_WINDOW blocks
- Repo owner can approve unilaterally (bypass consensus)
- Repo owner approval is always sufficient for merge

Proposal references both a human-readable PR URL and a SHA3-256 hash of the
diff content, so voters know exactly what they are approving.
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from messagechain.config import (
    HASH_ALGO,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_APPROVAL_THRESHOLD,
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
    """Create a governance proposal linked to a PR.

    Fields:
        proposer_id: entity creating the proposal
        pr_url: GitHub PR URL (human-readable reference)
        content_hash: SHA3-256 of the diff content (tamper-proof reference)
        description: short description of the proposed change
        timestamp: creation time
        fee: must be >= GOVERNANCE_PROPOSAL_FEE
        signature: proposer's quantum-resistant signature
    """
    proposer_id: bytes
    pr_url: str
    content_hash: bytes
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
            b"governance_proposal"
            + self.proposer_id
            + self.pr_url.encode("utf-8")
            + self.content_hash
            + self.description.encode("utf-8")
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
            "pr_url": self.pr_url,
            "content_hash": self.content_hash.hex(),
            "description": self.description,
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ProposalTransaction":
        sig = Signature.deserialize(data["signature"])
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            pr_url=data["pr_url"],
            content_hash=bytes.fromhex(data["content_hash"]),
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError("Proposal tx hash mismatch")
        return tx


@dataclass
class VoteTransaction:
    """Cast a balance-weighted vote on a governance proposal.

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
    pr_url: str,
    content_hash: bytes,
    description: str,
    fee: int = GOVERNANCE_PROPOSAL_FEE,
) -> ProposalTransaction:
    """Create and sign a governance proposal."""
    tx = ProposalTransaction(
        proposer_id=proposer_entity.entity_id,
        pr_url=pr_url,
        content_hash=content_hash,
        description=description,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
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
    ACTIVE = "active"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ProposalState:
    """Tracks the on-chain state of a governance proposal."""
    proposal: ProposalTransaction
    created_at_block: int
    owner_approved: bool = False
    votes: dict = field(default_factory=dict)  # voter_id -> bool


# --- Governance tracker ---


class GovernanceTracker:
    """Tracks all governance state: proposals, votes, delegations, owner.

    This is the core state machine for on-chain governance. It is updated
    by the blockchain when governance transactions are included in blocks.
    """

    def __init__(self, owner_id: bytes | None = None):
        self.owner_id: bytes | None = owner_id
        self.proposals: dict[bytes, ProposalState] = {}  # proposal_id -> state
        self.delegations: dict[bytes, bytes] = {}  # delegator_id -> delegate_id

    def add_proposal(self, tx: ProposalTransaction, block_height: int):
        """Register a new proposal from a validated ProposalTransaction."""
        self.proposals[tx.proposal_id] = ProposalState(
            proposal=tx,
            created_at_block=block_height,
        )

    def add_vote(self, tx: VoteTransaction):
        """Record a vote from a validated VoteTransaction."""
        state = self.proposals.get(tx.proposal_id)
        if state is None:
            return
        state.votes[tx.voter_id] = tx.approve

    def set_delegation(self, delegator_id: bytes, delegate_id: bytes):
        """Set or revoke a delegation."""
        if delegate_id == b"":
            self.delegations.pop(delegator_id, None)
        else:
            self.delegations[delegator_id] = delegate_id

    def owner_approve(self, proposal_id: bytes):
        """Mark a proposal as owner-approved."""
        state = self.proposals.get(proposal_id)
        if state is not None:
            state.owner_approved = True

    def get_proposal_status(
        self, proposal_id: bytes, current_block: int, supply_tracker
    ) -> ProposalStatus:
        """Determine the current status of a proposal."""
        state = self.proposals.get(proposal_id)
        if state is None:
            raise ValueError("Unknown proposal")

        # Owner approval always results in APPROVED
        if state.owner_approved:
            return ProposalStatus.APPROVED

        # Check if voting window has expired
        blocks_elapsed = current_block - state.created_at_block
        if blocks_elapsed > GOVERNANCE_VOTING_WINDOW:
            # Window closed — check final tally
            yes_weight, total_weight = self.tally(proposal_id, supply_tracker)
            if total_weight > 0 and (yes_weight / total_weight) > GOVERNANCE_APPROVAL_THRESHOLD:
                return ProposalStatus.APPROVED
            return ProposalStatus.EXPIRED

        return ProposalStatus.ACTIVE

    def can_merge(
        self, proposal_id: bytes, current_block: int, supply_tracker
    ) -> bool:
        """Check if a proposal has met the conditions for merge.

        A proposal can be merged if:
        - Owner approved it (always sufficient), OR
        - >50% of participating wallet balance voted yes
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return False

        # Owner can always merge
        if state.owner_approved:
            return True

        # Check consensus
        yes_weight, total_weight = self.tally(proposal_id, supply_tracker)
        if total_weight == 0:
            return False
        return (yes_weight / total_weight) > GOVERNANCE_APPROVAL_THRESHOLD

    def tally(
        self, proposal_id: bytes, supply_tracker
    ) -> tuple[int, int]:
        """Tally votes for a proposal, weighted by wallet balance.

        Returns (yes_weight, total_participating_weight).

        Delegation rules:
        - If entity A delegated to entity B, and B voted but A did not,
          then A's balance counts toward B's vote direction.
        - If A voted directly, their delegation is ignored for this proposal.
        - Single-hop only: if B delegated to C, A's weight does NOT follow.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0

        # Collect direct votes: voter_id -> approve
        direct_votes = dict(state.votes)

        # Build reverse delegation map: delegate_id -> [delegator_ids]
        reverse_delegations: dict[bytes, list[bytes]] = {}
        for delegator_id, delegate_id in self.delegations.items():
            if delegate_id not in reverse_delegations:
                reverse_delegations[delegate_id] = []
            reverse_delegations[delegate_id].append(delegator_id)

        yes_weight = 0
        total_weight = 0

        # Process each direct voter
        for voter_id, approve in direct_votes.items():
            # Voter's own balance
            balance = supply_tracker.get_balance(voter_id)
            total_weight += balance
            if approve:
                yes_weight += balance

            # Add delegated weight from entities who delegated to this voter
            # but did NOT vote directly themselves
            for delegator_id in reverse_delegations.get(voter_id, []):
                if delegator_id not in direct_votes:
                    delegator_balance = supply_tracker.get_balance(delegator_id)
                    total_weight += delegator_balance
                    if approve:
                        yes_weight += delegator_balance

        return yes_weight, total_weight

    def get_proposal_info(
        self, proposal_id: bytes, current_block: int, supply_tracker
    ) -> dict:
        """Get a summary of a proposal's current state."""
        state = self.proposals.get(proposal_id)
        if state is None:
            raise ValueError("Unknown proposal")

        yes_weight, total_weight = self.tally(proposal_id, supply_tracker)
        status = self.get_proposal_status(proposal_id, current_block, supply_tracker)
        blocks_remaining = max(
            0,
            GOVERNANCE_VOTING_WINDOW - (current_block - state.created_at_block),
        )

        return {
            "proposal_id": proposal_id.hex(),
            "pr_url": state.proposal.pr_url,
            "content_hash": state.proposal.content_hash.hex(),
            "description": state.proposal.description,
            "proposer": state.proposal.proposer_id.hex(),
            "status": status.value,
            "owner_approved": state.owner_approved,
            "yes_weight": yes_weight,
            "total_weight": total_weight,
            "approval_pct": (yes_weight / total_weight * 100) if total_weight > 0 else 0,
            "blocks_remaining": blocks_remaining,
            "direct_votes": len(state.votes),
            "can_merge": self.can_merge(proposal_id, current_block, supply_tracker),
        }


# --- Validation helpers ---


def verify_proposal(tx: ProposalTransaction, public_key: bytes) -> bool:
    """Verify a proposal transaction's signature."""
    if tx.fee < GOVERNANCE_PROPOSAL_FEE:
        return False
    if not tx.pr_url:
        return False
    if not tx.content_hash or len(tx.content_hash) != 32:
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
    # Cannot delegate to yourself
    if tx.delegate_id == tx.delegator_id:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
