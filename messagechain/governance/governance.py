"""
On-chain voting for MessageChain.

Model (2026-04-15 redesign — final, pure stakers-only):

- **Only stakers vote.**  A VoteTransaction is accepted into the tally
  only if the voter has own-stake > 0 at proposal creation time.
  Non-stakers have no protocol voice — they must stake if they want one.

- **Voting power = own stake at snapshot.**  No delegation, no aging,
  no sqrt, no liquid-balance routing.  Consensus weight and governance
  weight are both determined solely by an entity's own staked balance.
  This is the same rule Bitcoin uses for de-facto governance:
  participate by acquiring and holding skin-in-the-game, or don't
  participate.

- **Anyone can propose** (pays a proposal fee); the fee is the spam
  brake.

- **Tally.**  For each voting validator V, weight = own_stake(V) at
  snapshot.  yes_weight = sum of yes voters' stakes; no_weight = sum
  of no voters' stakes.  total_participating = yes + no.
  total_eligible = sum of every snapshotted validator's stake
  (voters + silent).  Silence is treated as "no" for binding
  outcomes.

- **General proposals are advisory.**  The tally is recorded on-chain
  for off-chain process to interpret; there is no on-chain effect.

- **Treasury spends are binding.**  A TreasurySpendTransaction
  auto-executes after its voting window closes iff
      yes_weight * 3 > total_eligible * 2
  i.e., strict supermajority of TOTAL ELIGIBLE stake.  Silence counts
  as "no"; there is an implicit 2/3 turnout floor.

Transaction types:
- ProposalTransaction       — advisory proposal with title/description
- TreasurySpendTransaction  — binding proposal to transfer from treasury
- VoteTransaction           — staker's yes/no (non-stakers silently rejected)

Rules:
- Stake snapshot captured at proposal creation, frozen thereafter.
- Votes are immutable — first vote wins, duplicates rejected.
- Votes on closed proposals are rejected.
- Votes from non-stakers are rejected by the tracker.
- Proposals close after GOVERNANCE_VOTING_WINDOW blocks.
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from messagechain import config
from messagechain.config import (
    HASH_ALGO,
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    MIN_FEE,
    SIG_VERSION_CURRENT,
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
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            config.CHAIN_ID
            + b"governance_proposal"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Binary: ENT proposer_ref | u16 title_len | title utf8 | u32 desc_len |
        desc utf8 | u8 ref_len | ref_hash | f64 timestamp | u64 fee |
        u32 sig_len | sig | 32 tx_hash.

        title uses u16 (bounded by MAX_PROPOSAL_TITLE_LENGTH = 200).
        description uses u32 (bounded by MAX_PROPOSAL_DESCRIPTION_LENGTH = 10k).
        reference_hash is 0 or 32 bytes — u8 length lets us distinguish.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.proposer_id, state=state),
            struct.pack(">H", len(title_b)),
            title_b,
            struct.pack(">I", len(desc_b)),
            desc_b,
            struct.pack(">B", len(self.reference_hash)),
            self.reference_hash,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "ProposalTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 2:
            raise ValueError("Proposal blob too short")
        proposer_id, n = decode_entity_ref(data, off, state=state); off += n
        title_len = struct.unpack_from(">H", data, off)[0]; off += 2
        if off + title_len + 4 > len(data):
            raise ValueError("Proposal truncated at title")
        title = data[off:off + title_len].decode("utf-8"); off += title_len
        desc_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + desc_len + 1 > len(data):
            raise ValueError("Proposal truncated at description")
        desc = data[off:off + desc_len].decode("utf-8"); off += desc_len
        ref_len = struct.unpack_from(">B", data, off)[0]; off += 1
        if off + ref_len + 8 + 8 + 4 + 32 > len(data):
            raise ValueError("Proposal truncated at reference_hash/tail")
        ref_hash = bytes(data[off:off + ref_len]); off += ref_len
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("Proposal truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("Proposal has trailing bytes")
        tx = cls(
            proposer_id=proposer_id, title=title, description=desc,
            timestamp=timestamp, fee=fee, signature=sig,
            reference_hash=ref_hash,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError("Proposal tx hash mismatch")
        return tx

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
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            config.CHAIN_ID
            + b"governance_vote"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Binary: ENT voter_ref | 32 proposal_id | u8 approve | f64 timestamp |
        u64 fee | u32 sig_len | sig | 32 tx_hash.

        proposal_id is the target ProposalTransaction's tx_hash (always
        32 bytes), not an entity reference — it doesn't resolve through
        the entity-index registry.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.voter_id, state=state),
            self.proposal_id,
            struct.pack(">B", 1 if self.approve else 0),
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "VoteTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 32 + 1 + 8 + 8 + 4 + 32:
            raise ValueError("Vote blob too short")
        voter_id, n = decode_entity_ref(data, off, state=state); off += n
        proposal_id = bytes(data[off:off + 32]); off += 32
        approve = struct.unpack_from(">B", data, off)[0] != 0; off += 1
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("Vote truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("Vote has trailing bytes")
        tx = cls(
            voter_id=voter_id, proposal_id=proposal_id,
            approve=approve, timestamp=timestamp, fee=fee, signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError("Vote tx hash mismatch")
        return tx

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
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            config.CHAIN_ID
            + b"treasury_spend"
            + struct.pack(">B", sig_version)
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

    def to_bytes(self, state=None) -> bytes:
        """Binary: ENT proposer_ref | ENT recipient_ref | u64 amount |
        u16 title_len | title | u32 desc_len | desc | f64 timestamp |
        u64 fee | u32 sig_len | sig | 32 tx_hash.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        sig_blob = self.signature.to_bytes()
        return b"".join([
            encode_entity_ref(self.proposer_id, state=state),
            encode_entity_ref(self.recipient_id, state=state),
            struct.pack(">Q", self.amount),
            struct.pack(">H", len(title_b)),
            title_b,
            struct.pack(">I", len(desc_b)),
            desc_b,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "TreasurySpendTransaction":
        from messagechain.core.entity_ref import decode_entity_ref
        off = 0
        if len(data) < 1 + 1 + 8 + 2:
            raise ValueError("TreasurySpend blob too short")
        proposer_id, n = decode_entity_ref(data, off, state=state); off += n
        recipient_id, n = decode_entity_ref(data, off, state=state); off += n
        amount = struct.unpack_from(">Q", data, off)[0]; off += 8
        title_len = struct.unpack_from(">H", data, off)[0]; off += 2
        if off + title_len + 4 > len(data):
            raise ValueError("TreasurySpend truncated at title")
        title = data[off:off + title_len].decode("utf-8"); off += title_len
        desc_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + desc_len + 8 + 8 + 4 + 32 > len(data):
            raise ValueError("TreasurySpend truncated at description/tail")
        desc = data[off:off + desc_len].decode("utf-8"); off += desc_len
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("TreasurySpend truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("TreasurySpend has trailing bytes")
        tx = cls(
            proposer_id=proposer_id, recipient_id=recipient_id,
            amount=amount, title=title, description=desc,
            timestamp=timestamp, fee=fee, signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError("Treasury spend tx hash mismatch")
        return tx

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


# --- Proposal state ---


class ProposalStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass
class ProposalState:
    """Tracks the on-chain state of a proposal.

    The stake snapshot is captured at proposal creation and frozen
    thereafter.  This prevents manipulation by last-minute staking or
    unstaking.

    Fields:
        stake_snapshot: {validator_id -> own_stake} for every entity
            with staked > 0 at proposal creation.  This is the entire
            voting electorate.
        total_eligible_stake: sum of stake_snapshot values — the
            denominator for binding-outcome approval checks.
        votes: {voter_id -> approve_bool} — direct votes accepted so
            far.  Only entities with stake_snapshot[voter_id] > 0
            register here; non-stakers' votes are silently dropped
            by add_vote().
    """
    proposal: ProposalTransaction
    created_at_block: int
    stake_snapshot: dict  # entity_id -> staked amount at proposal creation
    total_eligible_stake: int
    votes: dict = field(default_factory=dict)  # voter_id -> bool


# --- Governance tracker ---


class GovernanceTracker:
    """Tracks all voting state: proposals and votes.

    This is the core state machine for on-chain voting. It is updated
    by the blockchain when governance transactions are included in blocks.
    The tracker records votes and tallies results — it does not enforce
    any outcomes beyond the self-executing treasury-spend path.
    """

    def __init__(self):
        self.proposals: dict[bytes, ProposalState] = {}  # proposal_id -> state
        self._executed_treasury_spends: set[bytes] = set()  # replay protection
        # Append-only audit log — every successful binding execution is
        # recorded with tx_hash, execution_block, and outcome-specific
        # fields.  Survives proposal pruning so post-hoc accountability
        # ("show me every treasury spend that ever executed") always works.
        self.treasury_spend_log: list[dict] = []

    def add_proposal(self, tx: ProposalTransaction, block_height: int, supply_tracker):
        """Register a new proposal and snapshot current stake state.

        Snapshot captured as of `block_height` and frozen thereafter:

        - stake_snapshot: {validator_id -> own_stake} for every entity with
          staked > 0.  This is the entire voting electorate for this
          proposal.

        Tally uses this snapshot only, never live state.  Staking or
        unstaking after proposal creation cannot swing the vote.
        """
        stake_snapshot = {
            eid: amount
            for eid, amount in supply_tracker.staked.items()
            if amount > 0
        }
        total_stake = sum(stake_snapshot.values())
        self.proposals[tx.proposal_id] = ProposalState(
            proposal=tx,
            created_at_block=block_height,
            stake_snapshot=stake_snapshot,
            total_eligible_stake=total_stake,
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
        """Record a vote. Returns False if rejected.

        Rejected when:
        - The proposal does not exist (or has already been pruned)
        - The voting window has closed
        - The voter has already voted on this proposal (first-vote-wins)
        - The voter has own_stake == 0 in the snapshot (non-stakers have
          no protocol voice; they must stake to participate)
        """
        state = self.proposals.get(tx.proposal_id)
        if state is None:
            return False
        # Reject votes after voting window closes
        if current_block - state.created_at_block > GOVERNANCE_VOTING_WINDOW:
            return False
        # Reject duplicate votes (immutable — first vote wins)
        if tx.voter_id in state.votes:
            return False
        # Staker-only voting.  Non-stakers' VoteTxs stay in the block but
        # are silently dropped from the tally — they carry no weight.
        if state.stake_snapshot.get(tx.voter_id, 0) <= 0:
            return False
        state.votes[tx.voter_id] = tx.approve
        return True

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
            yes_w, no_w, participating, eligible = self.tally(pid)
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
                "yes_weight": yes_w,
                "no_weight": no_w,
                "total_participating": participating,
                "total_eligible": eligible,
                "vote_count": len(state.votes),
            })
        rows.sort(key=lambda r: r["created_at_block"], reverse=True)
        return rows

    def tally(self, proposal_id: bytes) -> tuple[int, int, int, int]:
        """Stakers-only tally for a proposal.

        Returns (yes_weight, no_weight, total_participating, total_eligible).

        Voting rules:

        - Only stakers (entities with stake_snapshot[v] > 0) can
          register a vote.  Non-stakers are rejected by add_vote.
        - Each voting validator V contributes V_weight = own_stake(V)
          at snapshot.  yes_weight sums the stakes of yes voters;
          no_weight sums the stakes of no voters.
        - total_eligible = sum of every snapshotted validator's stake,
          voter or silent.  Silence is counted in the denominator so
          it functions as "no" for binding outcomes.

        All arithmetic is integer and order-independent (sums), so
        tally results are deterministic across nodes.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0, 0, 0

        stake_snapshot = state.stake_snapshot
        direct_votes = state.votes  # voter_id -> bool

        yes_weight = 0
        no_weight = 0
        for voter_id, approve in direct_votes.items():
            own_stake = stake_snapshot.get(voter_id, 0)
            if own_stake <= 0:
                # add_vote() rejects these, but be defensive: a zero-
                # stake voter in the record contributes nothing.
                continue
            if approve:
                yes_weight += own_stake
            else:
                no_weight += own_stake

        total_participating = yes_weight + no_weight
        total_eligible = sum(stake_snapshot.values())
        return yes_weight, no_weight, total_participating, total_eligible

    def execute_treasury_spend(
        self,
        tx: TreasurySpendTransaction,
        supply_tracker,
        current_block: int = 0,
        *,
        is_new_account=None,
    ) -> bool:
        """Execute an approved treasury spend. Returns False if rejected.

        Rejects if:
        - Amount is invalid
        - Treasury has insufficient funds (including any new-account
          surcharge required for a brand-new recipient)
        - Spend has already been executed (replay protection)
        - Proposal does not exist on-chain
        - Voting window is still open
        - yes_weight does not clear strict 2/3 of TOTAL ELIGIBLE stake
          at snapshot.  Silence counts as "no" — a sleepy electorate
          defaults to status quo.

        `is_new_account`, if provided, is a callable that returns True
        iff the recipient has no on-chain state.  When True, the
        treasury is additionally charged NEW_ACCOUNT_FEE (burned, not
        credited to the recipient), matching the surcharge the chain
        imposes on ordinary Transfer→brand-new flows.  When None, the
        supply_tracker's own balances dict is consulted as a best-
        effort fallback; this is suitable only for tests and non-chain
        paths that don't have a full blockchain view.
        """
        from messagechain.config import NEW_ACCOUNT_FEE
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
        yes_weight, _no_weight, _participating, total_eligible = self.tally(
            tx.proposal_id,
        )
        if total_eligible == 0:
            return False
        # Strict supermajority of the full electorate: yes * 3 > total * 2.
        if (yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
                <= total_eligible * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR):
            return False
        # New-account surcharge: if caller supplied a recipient-novelty
        # check, use it; otherwise fall back to the supply_tracker's
        # balances/staked dicts as a best-effort approximation (fine for
        # isolated tests, inadequate for live chain code).
        if is_new_account is not None:
            recipient_is_new = bool(is_new_account(tx.recipient_id))
        else:
            recipient_is_new = (
                tx.recipient_id not in supply_tracker.balances
                and supply_tracker.get_staked(tx.recipient_id) == 0
            )
        surcharge = NEW_ACCOUNT_FEE if recipient_is_new else 0
        result = supply_tracker.treasury_spend(
            tx.recipient_id, tx.amount,
            new_account_surcharge=surcharge,
        )
        if result:
            self._executed_treasury_spends.add(tx.tx_hash)
            self.treasury_spend_log.append({
                "tx_hash": tx.tx_hash.hex(),
                "proposal_id": tx.proposal_id.hex(),
                "recipient_id": tx.recipient_id.hex(),
                "amount": tx.amount,
                "execution_block": current_block,
                "yes_weight": yes_weight,
                "total_eligible_weight": total_eligible,
            })
        return result

    def get_proposal_info(
        self, proposal_id: bytes, current_block: int,
    ) -> dict:
        """Get a summary of a proposal's current state and tally."""
        state = self.proposals.get(proposal_id)
        if state is None:
            raise ValueError("Unknown proposal")

        yes_w, no_w, participating, eligible = self.tally(proposal_id)
        status = self.get_proposal_status(proposal_id, current_block)
        blocks_remaining = max(
            0,
            GOVERNANCE_VOTING_WINDOW - (current_block - state.created_at_block),
        )
        participation_pct = (
            participating / eligible * 100 if eligible > 0 else 0
        )
        approval_pct_of_participating = (
            yes_w / participating * 100 if participating > 0 else 0
        )
        approval_pct_of_eligible = (
            yes_w / eligible * 100 if eligible > 0 else 0
        )

        return {
            "proposal_id": proposal_id.hex(),
            "title": state.proposal.title,
            "description": state.proposal.description,
            "reference_hash": (
                state.proposal.reference_hash.hex()
                if state.proposal.reference_hash else ""
            ),
            "proposer": state.proposal.proposer_id.hex(),
            "status": status.value,
            "yes_weight": yes_w,
            "no_weight": no_w,
            "total_participating": participating,
            "total_eligible": eligible,
            "participation_pct": participation_pct,
            "approval_pct_of_participating": approval_pct_of_participating,
            "approval_pct_of_eligible": approval_pct_of_eligible,
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
