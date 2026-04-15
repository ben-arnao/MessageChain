"""
On-chain voting for MessageChain.

Model (2026-04-15 redesign — simplified):

- **Stakers vote directly.**  A VoteTransaction is accepted into the
  tally only if the voter has own-stake > 0 at proposal creation time.
  Non-stakers cannot vote directly.

- **Holders participate by delegating.**  A holder (validator or liquid-
  balance holder) submits a DelegateTransaction naming 1–3 validators
  with percentages summing to 100.  The delegator's LIQUID BALANCE (not
  stake) is then added LINEARLY to the chosen validator(s) when they
  vote.  No sqrt dampening.  No auto-delegation.  A validator who
  doesn't vote does not harvest their delegators' weight — silence is
  silence.

- **Delegation aging is the flash-loan defense.**  A delegation counts
  toward a proposal's tally only if it was registered at least
  GOVERNANCE_DELEGATION_AGING_BLOCKS (default = voting window, 1008
  blocks / ~7 days) before the proposal's creation block.  A fresh
  re-delegation resets the age clock.  Flash-loan attackers would need
  to hold the borrowed tokens for a full voting window before the
  *next* proposal — by which point they have real skin in the game.

- **Unified tally.**  For each validator V who cast a direct vote:
      V_weight = own_stake(V) + sum over aged delegators D
                 of (D.liquid_balance × pct_to_V ÷ 100)
      yes_weight += V_weight if V voted yes, else no_weight += V_weight.
  total_participating = yes + no.
  total_eligible       = sum(all validator own-stakes) +
                         sum(all aged delegator liquid balances).
  Non-participating validators and unchosen delegators are silent but
  still count in total_eligible — silence is treated as "no" for
  binding outcomes.

- **General proposals are advisory.**  The tally is recorded on-chain
  for off-chain process to interpret; there is no on-chain effect.

- **Treasury spends are binding.**  A TreasurySpendTransaction
  auto-executes after its voting window closes iff
      yes_weight * 3 > total_eligible * 2
  i.e., strict supermajority of TOTAL ELIGIBLE (not participating).
  Silence counts as "no"; there is an implicit 2/3 turnout floor.

- **Delegation splits apply per validator.**  If D allocates 50/50 to
  V1 and V2 and V1 votes yes while V2 votes no, 50% of D's balance
  goes to yes and 50% to no.  If V2 doesn't vote, V2's share is silent
  but still appears in total_eligible.

Transaction types:
- ProposalTransaction       — advisory proposal with title/description
- TreasurySpendTransaction  — binding proposal to transfer from treasury
- VoteTransaction           — staker's yes/no (non-stakers ignored)
- DelegateTransaction       — route liquid balance to up to 3 validators

Rules:
- Snapshots captured at proposal creation, frozen thereafter.
- Votes are immutable — first vote wins, duplicates rejected.
- Votes on closed proposals are rejected.
- Delegation is single-hop (no chains).
- A direct vote always overrides delegation from the same entity for
  that proposal.
- Proposals close after GOVERNANCE_VOTING_WINDOW blocks.

TERMINOLOGY — "delegation" here is strictly GOVERNANCE delegation: a
signal routing a holder's VOTING WEIGHT to chosen validators.  It does
NOT move, lock, or bond any tokens, and it does NOT grant the delegate
any consensus weight (proposer selection / block finality).  Consensus
weight is determined solely by own staked balance.  MessageChain
deliberately does NOT implement DPoS-style bonded delegation, which
concentrates power and introduces slashing-cascade complexity.
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
    GOVERNANCE_DELEGATE_FEE,
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    GOVERNANCE_DELEGATION_AGING_BLOCKS,
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
    This prevents manipulation by last-minute staking, balance movement,
    or last-minute delegation (aging gate in add_proposal).

    Fields:
        stake_snapshot: {validator_id -> own_stake} for every entity
            with staked > 0 at proposal creation.  This is the direct-
            voting electorate.
        delegation_snapshot: {delegator_id -> (targets, liquid_balance)}
            for every delegator whose current delegation was registered
            at least GOVERNANCE_DELEGATION_AGING_BLOCKS before this
            proposal's creation block.  Fresh delegations are absent
            (flash-loan defense).  `targets` is the list of
            (validator_id, pct) at snapshot time; `liquid_balance` is
            the delegator's unstaked balance at snapshot time.
        total_eligible_stake: sum of stake_snapshot values — kept for
            backward-compatible reporting.  The full 2/3 denominator
            for binding outcomes is computed in tally() and combines
            stake + aged-delegation balance.
        votes: {voter_id -> approve_bool} — direct votes accepted so
            far.  Only entities with stake_snapshot[voter_id] > 0
            register in the tally; non-stakers' votes are silently
            dropped by add_vote().
    """
    proposal: ProposalTransaction
    created_at_block: int
    stake_snapshot: dict  # entity_id -> staked amount at proposal creation
    total_eligible_stake: int
    # {delegator_id -> (list[(validator_id, pct)], liquid_balance_snapshot)}
    # captured only for delegations that satisfy the aging requirement.
    delegation_snapshot: dict = field(default_factory=dict)
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
        # delegator_id -> block_height at which current delegation was set.
        # Used by add_proposal() to apply the delegation-aging gate.  Any
        # re-delegation (set_delegation with non-empty targets) resets this.
        # Revocation removes the entry entirely.
        self.delegation_set_at: dict[bytes, int] = {}
        self._executed_treasury_spends: set[bytes] = set()  # replay protection
        # Append-only audit log — every successful binding execution is
        # recorded with tx_hash, execution_block, and outcome-specific
        # fields.  Survives proposal pruning so post-hoc accountability
        # ("show me every treasury spend that ever executed") always works.
        self.treasury_spend_log: list[dict] = []

    def add_proposal(self, tx: ProposalTransaction, block_height: int, supply_tracker):
        """Register a new proposal and snapshot current stake + aged-delegation state.

        Snapshots captured as of `block_height` and frozen thereafter:

        - stake_snapshot: {validator_id -> own_stake} for every entity with
          staked > 0.  This is the direct-voting electorate.
        - delegation_snapshot: {delegator_id -> (targets, liquid_balance)}
          for each delegator whose current delegation was registered at
          least GOVERNANCE_DELEGATION_AGING_BLOCKS before `block_height`.
          Fresh delegations are EXCLUDED — this is the flash-loan defense.

        Tally uses these snapshots only, never live state.  Moving tokens,
        staking, or delegating after proposal creation cannot swing the
        vote.
        """
        stake_snapshot = {
            eid: amount
            for eid, amount in supply_tracker.staked.items()
            if amount > 0
        }
        # Capture only AGED delegations.  An "aged" delegation is one whose
        # delegation_set_at is at least GOVERNANCE_DELEGATION_AGING_BLOCKS
        # before block_height.  Fresh delegations are silently excluded
        # for this proposal (but remain in self.delegations, and will age
        # in for future proposals).
        delegation_snapshot: dict[bytes, tuple[list[tuple[bytes, int]], int]] = {}
        for delegator_id, targets in self.delegations.items():
            set_at = self.delegation_set_at.get(delegator_id)
            if set_at is None:
                continue  # no timestamp recorded — treat as not-yet-aged
            if block_height - set_at < GOVERNANCE_DELEGATION_AGING_BLOCKS:
                continue  # too fresh — flash-loan defense
            liquid_balance = supply_tracker.balances.get(delegator_id, 0)
            if liquid_balance <= 0:
                # Delegator has no liquid balance to contribute — skip.
                # (Keeping them out of the snapshot also keeps them out of
                # total_eligible, so they don't pad the denominator.)
                continue
            # Deep-copy the targets list so later mutation of
            # self.delegations can't retroactively affect this snapshot.
            delegation_snapshot[delegator_id] = (
                [(did, pct) for did, pct in targets],
                liquid_balance,
            )
        total_stake = sum(stake_snapshot.values())
        self.proposals[tx.proposal_id] = ProposalState(
            proposal=tx,
            created_at_block=block_height,
            stake_snapshot=stake_snapshot,
            total_eligible_stake=total_stake,
            delegation_snapshot=delegation_snapshot,
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
        - The voter has own_stake == 0 in the snapshot (non-stakers cannot
          vote directly; they must delegate).  A non-staker's VoteTx stays
          in the block but is silently dropped from the tally.
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
        # Staker-only direct voting.  Non-stakers must participate via
        # delegation, not direct vote.  Dropping silently keeps the block
        # valid but stops non-stakers from bloating the vote record with
        # zero-weight entries.
        if state.stake_snapshot.get(tx.voter_id, 0) <= 0:
            return False
        state.votes[tx.voter_id] = tx.approve
        return True

    def set_delegation(
        self,
        delegator_id: bytes,
        targets: list[tuple[bytes, int]],
        current_block: int | None = None,
    ) -> bool:
        """Set or revoke delegation to up to MAX_DELEGATION_TARGETS validators.

        targets: list of (delegate_id, weight_pct) pairs.  Percentages must
        sum to 100.  Empty list revokes all delegations.  Returns False
        if validation fails.

        current_block: the block height at which this delegation was
        registered.  Stored so that add_proposal() can apply the
        delegation-aging gate (GOVERNANCE_DELEGATION_AGING_BLOCKS).  Any
        re-delegation RESETS the age clock — an attacker cannot amass
        stake over time and then re-aim it fresh without forfeiting the
        next proposal cycle.  `None` is accepted for test/utility paths
        that don't care about aging (aging then treats the delegation as
        "never aged" for any future proposal, which is the safe default).
        """
        if not targets:
            self.delegations.pop(delegator_id, None)
            self.delegation_set_at.pop(delegator_id, None)
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
        if current_block is not None:
            self.delegation_set_at[delegator_id] = current_block
        else:
            # Callers that omit current_block get no aging — the
            # delegation will be ignored for every future proposal.
            # This is the safe default for setup helpers / tests.
            self.delegation_set_at.pop(delegator_id, None)
        return True

    def revoke_delegations_to(self, validator_id: bytes):
        """Revoke all delegations pointing to a validator.

        Called when the validator is "completely kicked from the network":
        - Slashed (stake forcibly confiscated), or
        - Fully unstaked (stake dropped to 0 voluntarily)

        After revocation, the delegators have no active delegation — their
        holdings are silent in future tallies until they submit a new
        DelegateTransaction.  In-flight proposals also reflect the
        revocation: the delegation relationship is LIVE state, not
        snapshotted.

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
            self.delegation_set_at.pop(delegator_id, None)

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
        """Unified tally for a proposal.

        Returns (yes_weight, no_weight, total_participating, total_eligible).

        Voting rules (from the 2026-04-15 redesign):

        - Only STAKERS (entities with stake_snapshot[v] > 0) can register
          a direct vote.  Non-stakers are rejected by add_vote.
        - Each voting validator V contributes:
              V_weight = own_stake(V)
                       + sum over aged delegators D of
                         (D.liquid_balance × pct_to_V ÷ 100)
          If V voted yes → yes_weight += V_weight.
          If V voted no  → no_weight  += V_weight.
        - total_eligible = sum(all own-stakes) + sum(all aged delegators'
          liquid balances).  This includes validators who did not vote
          and delegations pointing at validators who did not vote — their
          weight is silent (not counted in yes/no) but still sits in the
          denominator so silence can count as "no" for binding outcomes.

        All arithmetic is integer, iteration over snapshots is
        order-independent (sums), and floor-division matches across
        implementations — tally results are deterministic across nodes.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0, 0, 0

        stake_snapshot = state.stake_snapshot
        delegation_snapshot = state.delegation_snapshot
        direct_votes = state.votes  # voter_id -> bool

        yes_weight = 0
        no_weight = 0

        # 1. Each voting validator contributes their own stake plus their
        #    slice of every aged delegator's balance.
        #
        #    We iterate delegators once and route each percentage share
        #    to its validator's tally.  A single delegator can split
        #    across up to MAX_DELEGATION_TARGETS validators; different
        #    validators can vote differently, which cleanly routes each
        #    slice to yes / no / silent.
        for voter_id, approve in direct_votes.items():
            own_stake = stake_snapshot.get(voter_id, 0)
            if own_stake <= 0:
                # add_vote() should have rejected this, but be defensive:
                # a zero-stake voter in the record contributes nothing.
                continue
            if approve:
                yes_weight += own_stake
            else:
                no_weight += own_stake

        # 2. Aged delegators: route each (delegator, validator, pct) slice
        #    to yes / no / silent based on the validator's direct vote.
        for delegator_id, (targets, liquid_balance) in delegation_snapshot.items():
            if liquid_balance <= 0:
                continue
            for validator_id, pct in targets:
                share = liquid_balance * pct // 100
                if share == 0:
                    continue
                approve = direct_votes.get(validator_id)
                if approve is True:
                    yes_weight += share
                elif approve is False:
                    no_weight += share
                # else: validator did not vote — share is silent
                #       (not in yes/no, but still in total_eligible below).

        total_participating = yes_weight + no_weight

        # 3. total_eligible = all snapshotted stake + all snapshotted aged
        #    delegation balance, regardless of whether the delegate voted.
        #    Note: a delegator's entire balance is counted once here even
        #    when split across multiple validators — percentages sum to
        #    100 by validation, so floor-division on individual shares
        #    can produce at most (n_targets - 1) lost units per delegator.
        #    We compute the denominator from raw balances to avoid that
        #    rounding leak in the floor.  Total yes+no+silent shares may
        #    be slightly less than total_eligible due to floor-division;
        #    this is deterministic and intentional (strict inequality in
        #    the approval check means it's always conservative).
        total_eligible = sum(stake_snapshot.values())
        for _, (_, liquid_balance) in delegation_snapshot.items():
            if liquid_balance > 0:
                total_eligible += liquid_balance

        return yes_weight, no_weight, total_participating, total_eligible

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
        - yes_weight does not clear strict 2/3 of TOTAL ELIGIBLE weight
          (stake + aged-delegation balance).  Silence counts as "no" — a
          sleepy electorate defaults to status quo.
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
        yes_weight, _no_weight, _participating, total_eligible = self.tally(
            tx.proposal_id,
        )
        if total_eligible == 0:
            return False
        # Strict supermajority of the full electorate: yes * 3 > total * 2.
        if (yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
                <= total_eligible * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR):
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
