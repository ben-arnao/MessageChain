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
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


# Governance-tx logic versions.
# v1: legacy form -- title/description/reference_hash concatenated raw
# in `_signable_data` (no length prefixes).  Allows two parses of the
# same signed bytes to yield different (title, description, reference_hash)
# tuples -- a relay can rewrite the on-chain text of an approved
# proposal without breaking the signature.  Pre-Tier-15 chain history
# uses this form; never change it (replay-determinism).
# v2: GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT (Tier 15) length-prefixes
# every variable-length field in `_signable_data` so the parsed tuple
# is uniquely committed.  Same defect class + fix shape as v4
# message tx (TX_VERSION_LENGTH_PREFIX).
GOVERNANCE_TX_VERSION_V1 = 1
GOVERNANCE_TX_VERSION_LENGTH_PREFIX = 2


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
    # Governance-tx version.  v1 = legacy (no length prefixes in
    # signable_data; vulnerable to text-rewrite collision).  v2 =
    # length-prefixed (Tier 15 hard fork, GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT).
    # Default 1 keeps existing test fixtures and historical replay
    # working byte-for-byte; production creation post-activation
    # emits v2 explicitly.
    version: int = GOVERNANCE_TX_VERSION_V1

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        # v2 (GOVERNANCE_TX_VERSION_LENGTH_PREFIX) closes the legacy
        # length-prefix collision: title (>H), description (>I), and
        # reference_hash (>B) each carry their length.  v1 keeps the
        # legacy raw concatenation byte-for-byte for historical replay.
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        if self.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
            # v2: length-prefixed body + version byte committed
            # (so a v2 tx_hash is structurally distinct from any v1
            # tx_hash even when title/description happen to coincide).
            body = (
                struct.pack(">B", self.version)
                + struct.pack(">H", len(title_b)) + title_b
                + struct.pack(">I", len(desc_b)) + desc_b
                + struct.pack(">B", len(self.reference_hash)) + self.reference_hash
            )
        else:
            # v1: legacy form -- raw concatenation, NO version byte,
            # preserved byte-for-byte for historical replay.
            body = title_b + desc_b + self.reference_hash
        return (
            config.CHAIN_ID
            + b"governance_proposal"
            + struct.pack(">B", sig_version)
            + self.proposer_id
            + body
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def affected_entities(self) -> set[bytes]:
        """Apply path debits the proposer's fee (+ Tier-22 voter-reward
        surcharge) and bumps their leaf_watermark.  Single touched
        entity at proposal-admission time.  Treasury is mutated only
        when a proposal closes/auto-executes — that is captured by
        the block-level sweep, not the proposal tx itself.
        See CLAUDE.md canonical registry contract.
        """
        return {self.proposer_id}

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
            "version": self.version,
        }

    def to_bytes(self, state=None) -> bytes:
        """Binary: [SENTINEL 0xC1 | version u8] ENT proposer_ref |
        u16 title_len | title utf8 | u32 desc_len | desc utf8 |
        u8 ref_len | ref_hash | f64 timestamp | u64 fee |
        u32 sig_len | sig | 32 tx_hash.

        v1 wire form OMITS the leading sentinel + version pair (legacy
        layout, byte-for-byte unchanged).  v2+ wire form prepends
        ``0xC1 || version`` so the decoder can distinguish.  The
        sentinel is unambiguous because the legacy first byte is the
        entity_ref tag (0x00 or 0x01); 0xC1 cannot collide.

        title uses u16 (bounded by MAX_PROPOSAL_TITLE_LENGTH = 200).
        description uses u32 (bounded by MAX_PROPOSAL_DESCRIPTION_LENGTH = 10k).
        reference_hash is 0 or 32 bytes — u8 length lets us distinguish.
        """
        from messagechain.core.entity_ref import encode_entity_ref
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        sig_blob = self.signature.to_bytes()
        prefix: list[bytes] = []
        if self.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
            prefix.append(b"\xc1")
            prefix.append(struct.pack(">B", self.version))
        return b"".join(prefix + [
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
        # v2+ blobs begin with the 0xC1 sentinel followed by a version
        # byte.  Legacy v1 blobs begin with the entity_ref tag (0x00 or
        # 0x01) and have no leading sentinel.  Peek the first byte.
        version = GOVERNANCE_TX_VERSION_V1
        if data[0] == 0xC1:
            if len(data) < 2:
                raise ValueError("Proposal blob truncated at version sentinel")
            version = data[1]
            off = 2
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
            version=version,
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
        # Default v1 if absent so pre-fix snapshots/JSON dumps deserialize
        # cleanly; v2+ JSON producers MUST emit the field explicitly.
        version = int(data.get("version", GOVERNANCE_TX_VERSION_V1))
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            title=data["title"],
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            reference_hash=ref_hash,
            version=version,
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

    def affected_entities(self) -> set[bytes]:
        """Apply path debits the voter's fee and bumps their
        leaf_watermark.  Single touched entity per vote tx.  Voter
        rewards (Tier 22) are credited when the proposal closes —
        captured by a separate proposal-close sweep, not the vote
        tx itself.  See CLAUDE.md canonical registry contract.
        """
        return {self.voter_id}

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
    # See ProposalTransaction.version for the full rationale.
    version: int = GOVERNANCE_TX_VERSION_V1

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit sig_version into tx_hash.  getattr fallback
        # keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        # v2 (GOVERNANCE_TX_VERSION_LENGTH_PREFIX) closes the legacy
        # length-prefix collision: title (>H) and description (>I)
        # each carry their length, plus the version byte is committed
        # so a v2 tx_hash is structurally distinct from v1 even when
        # the human-readable text coincides.  recipient_id and amount
        # are fixed-width binary -- they couldn't be shifted under v1
        # either, so they don't need a length tag.  v1 keeps the
        # legacy raw concatenation byte-for-byte for historical replay.
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        if self.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
            body = (
                struct.pack(">B", self.version)
                + struct.pack(">H", len(title_b)) + title_b
                + struct.pack(">I", len(desc_b)) + desc_b
            )
        else:
            body = title_b + desc_b
        return (
            config.CHAIN_ID
            + b"treasury_spend"
            + struct.pack(">B", sig_version)
            + self.proposer_id
            + self.recipient_id
            + struct.pack(">Q", self.amount)
            + body
            + struct.pack(">d", self.timestamp)
            + struct.pack(">Q", self.fee)
        )

    def affected_entities(self) -> set[bytes]:
        """Apply path debits the proposer's fee (proposal-admission
        time).  recipient_id receives funds only on auto-execute when
        the proposal CLOSES — that mutation is captured by the
        proposal-close sweep, not the spend-tx admission.  Single
        touched entity at admission.  See CLAUDE.md canonical registry
        contract.
        """
        return {self.proposer_id}

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
            "version": self.version,
        }

    def to_bytes(self, state=None) -> bytes:
        """Binary: [SENTINEL 0xC1 | version u8] ENT proposer_ref |
        ENT recipient_ref | u64 amount | u16 title_len | title |
        u32 desc_len | desc | f64 timestamp | u64 fee | u32 sig_len |
        sig | 32 tx_hash.

        v1 wire form OMITS the leading sentinel + version pair (legacy
        layout, byte-for-byte unchanged).  v2+ wire form prepends
        ``0xC1 || version`` (sentinel cannot collide with the legacy
        first byte, which is the entity_ref tag 0x00 or 0x01).
        """
        from messagechain.core.entity_ref import encode_entity_ref
        title_b = self.title.encode("utf-8")
        desc_b = self.description.encode("utf-8")
        sig_blob = self.signature.to_bytes()
        prefix: list[bytes] = []
        if self.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
            prefix.append(b"\xc1")
            prefix.append(struct.pack(">B", self.version))
        return b"".join(prefix + [
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
        # v2+ blobs prepend 0xC1 sentinel + version byte; v1 has neither.
        version = GOVERNANCE_TX_VERSION_V1
        if data[0] == 0xC1:
            if len(data) < 2:
                raise ValueError(
                    "TreasurySpend blob truncated at version sentinel"
                )
            version = data[1]
            off = 2
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
            version=version,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError("Treasury spend tx hash mismatch")
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "TreasurySpendTransaction":
        sig = Signature.deserialize(data["signature"])
        version = int(data.get("version", GOVERNANCE_TX_VERSION_V1))
        tx = cls(
            proposer_id=bytes.fromhex(data["proposer_id"]),
            recipient_id=bytes.fromhex(data["recipient_id"]),
            amount=data["amount"],
            title=data["title"],
            description=data["description"],
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
            version=version,
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
    fee: int | None = None,
    current_height: int | None = None,
) -> ProposalTransaction:
    """Create and sign a governance proposal.

    `current_height`: when supplied and at/after
    GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT (Tier 15), the recommended v2
    form is emitted -- length-prefixed signable_data closes the
    text-rewrite collision.  Pre-activation (or current_height=None
    for legacy callers / isolated unit tests), v1 is emitted to
    preserve byte-for-byte signing compatibility with the existing
    chain.

    `fee`: when None, defaults to ``proposal_fee_floor(payload_bytes,
    current_height)`` -- the height-aware floor (legacy 10_000 pre-
    Tier-19, or ``100_000 + 50 * payload_bytes`` post-Tier-19).
    Callers who want to overpay (e.g. wallet auto-fee bidding above
    a congested mempool) supply an explicit value.
    """
    version = GOVERNANCE_TX_VERSION_V1
    if (
        current_height is not None
        and current_height >= config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
    ):
        version = GOVERNANCE_TX_VERSION_LENGTH_PREFIX
    if fee is None:
        payload_bytes = (
            len(title.encode("utf-8"))
            + len(description.encode("utf-8"))
            + len(reference_hash)
        )
        fee = proposal_fee_floor(payload_bytes, current_height)
    tx = ProposalTransaction(
        proposer_id=proposer_entity.entity_id,
        title=title,
        description=description,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        reference_hash=reference_hash,
        version=version,
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
        timestamp=int(time.time()),
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
    fee: int | None = None,
    current_height: int | None = None,
) -> TreasurySpendTransaction:
    """Create and sign a treasury spend proposal.  See `create_proposal`
    for the version-gating and fee-default rationale (Tier 19 surcharge
    applies symmetrically to treasury-spend)."""
    version = GOVERNANCE_TX_VERSION_V1
    if (
        current_height is not None
        and current_height >= config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
    ):
        version = GOVERNANCE_TX_VERSION_LENGTH_PREFIX
    if fee is None:
        payload_bytes = (
            len(title.encode("utf-8"))
            + len(description.encode("utf-8"))
        )
        fee = proposal_fee_floor(payload_bytes, current_height)
    tx = TreasurySpendTransaction(
        proposer_id=proposer_entity.entity_id,
        recipient_id=recipient_id,
        amount=amount,
        title=title,
        description=description,
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
        version=version,
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
    # Per-proposal escrow funded by VOTER_REWARD_SURCHARGE at apply time
    # (Tier 22, VOTER_REWARD_HEIGHT).  Zero on pre-fork proposals and on
    # any proposal whose chain apply path didn't pass the surcharge in.
    # Distributed pro-rata-by-live-stake to YES voters at close if the
    # 2/3 supermajority test passes; otherwise burned in full.  Reset
    # to 0 by finalize_voter_rewards so a redundant call is a no-op.
    voter_reward_pool: int = 0


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

    def add_proposal(
        self,
        tx: ProposalTransaction,
        block_height: int,
        supply_tracker,
        *,
        voter_reward_pool: int = 0,
    ):
        """Register a new proposal and snapshot current stake state.

        Snapshot captured as of `block_height` and frozen thereafter:

        - stake_snapshot: {validator_id -> own_stake} for every entity with
          staked > 0.  This is the entire voting electorate for this
          proposal.

        Tally uses this snapshot only, never live state.  Staking or
        unstaking after proposal creation cannot swing the vote.

        Caps the active-proposals map at MAX_ACTIVE_PROPOSALS.  Without
        a cap, a well-funded attacker could submit proposals at the
        PROPOSAL_FEE every block for the full voting window (~1008
        blocks = ~7 days), and each proposal's stake_snapshot copies
        the whole staking electorate.  A 10k-validator chain with 1000
        active proposals is ~320 MB of governance state.  The cap
        caller-side is preferable to forcing opportunistic pruning of
        older active proposals (which would let an attacker squeeze
        out honest ones by timing).
        """
        from messagechain.config import MAX_ACTIVE_PROPOSALS
        if len(self.proposals) >= MAX_ACTIVE_PROPOSALS:
            return False
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
            voter_reward_pool=voter_reward_pool,
        )
        return True

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

    def list_proposals(
        self, current_block: int, voter_id: bytes | None = None,
    ) -> list[dict]:
        """Return a JSON-friendly snapshot of every tracked proposal.

        Used by the CLI's `proposals` command so operators can see what's
        open, how many blocks remain, and the current tally without
        needing to decode state manually.

        When ``voter_id`` is provided, each row includes a ``voted``
        boolean indicating whether that entity has cast a vote on this
        proposal — the in-CLI banner uses it to suppress a "vote
        needed" alert for proposals the operator has already voted on.
        Field is omitted (not False) when no voter_id is supplied so
        existing consumers see byte-identical rows.
        """
        rows = []
        for pid, state in self.proposals.items():
            yes_w, no_w, participating, eligible = self.tally(pid)
            status = self.get_proposal_status(pid, current_block)
            blocks_remaining = max(
                0,
                GOVERNANCE_VOTING_WINDOW - (current_block - state.created_at_block),
            )
            row = {
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
            }
            if voter_id is not None:
                row["voted"] = voter_id in state.votes
            rows.append(row)
        rows.sort(key=lambda r: r["created_at_block"], reverse=True)
        return rows

    def tally(
        self, proposal_id: bytes, supply_tracker=None,
    ) -> tuple[int, int, int, int]:
        """Stakers-only tally for a proposal.

        Returns (yes_weight, no_weight, total_participating, total_eligible).

        Two tally modes:

        - **Snapshot mode** (supply_tracker=None) — weights come from
          the stake snapshot captured at proposal creation.  Used for
          informational views (list_proposals, get_proposal_info) where
          freezing the electorate at proposal time makes the display
          stable and order-independent.

        - **Live-weight mode** (supply_tracker given) — weights come
          from CURRENT stake, with eligibility still gated by the
          snapshot.  Used for BINDING outcomes (H6 fix): a voter
          slashed mid-window must contribute 0; a voter whose stake
          shrank must count only at current weight.  The snapshot
          still defines WHO may vote (no late joiners), but HOW MUCH
          each voter/silent-electorate-member weighs is evaluated at
          tally time against live state.

        Voting rules:

        - Only stakers (entities with stake_snapshot[v] > 0) can
          register a vote.  Non-stakers are rejected by add_vote.
        - In snapshot mode: each voter's weight = snapshot_stake.
          total_eligible = sum of snapshot stakes.
        - In live-weight mode: each voter's weight = current_stake.
          total_eligible = sum of current_stake for every entity in
          the snapshot (voters AND silent).  Silent voters whose
          stake was slashed vanish from the denominator too,
          otherwise a whale slashing would make supermajority
          impossible for any proposal.

        All arithmetic is integer and order-independent (sums), so
        tally results are deterministic across nodes.
        """
        state = self.proposals.get(proposal_id)
        if state is None:
            return 0, 0, 0, 0

        stake_snapshot = state.stake_snapshot
        direct_votes = state.votes  # voter_id -> bool

        def weight_for(entity_id: bytes) -> int:
            """Weight for an entity in the electorate at tally time."""
            if supply_tracker is None:
                return stake_snapshot.get(entity_id, 0)
            # Live-weight mode: only entities in the snapshot are
            # eligible (no late joiners).  Weight is current stake;
            # slashed → 0, partial unstake → reduced, etc.
            if entity_id not in stake_snapshot:
                return 0
            return supply_tracker.get_staked(entity_id)

        yes_weight = 0
        no_weight = 0
        for voter_id, approve in direct_votes.items():
            w = weight_for(voter_id)
            if w <= 0:
                # add_vote() rejects non-snapshot voters, but a
                # post-snapshot slashing (live-weight mode) drops the
                # voter's weight to 0.  Be defensive either way.
                continue
            if approve:
                yes_weight += w
            else:
                no_weight += w

        total_participating = yes_weight + no_weight
        if supply_tracker is None:
            total_eligible = sum(stake_snapshot.values())
        else:
            total_eligible = sum(
                weight_for(eid) for eid in stake_snapshot.keys()
            )
        return yes_weight, no_weight, total_participating, total_eligible

    def finalize_voter_rewards(
        self, proposal_id: bytes, supply_tracker, current_block: int,
    ) -> dict:
        """Settle the voter-reward escrow at proposal close (Tier 22).

        Behavior:

        - **Pool == 0** (pre-fork proposal, or chain apply path didn't
          escrow): no-op.  Returns ``{"passed": False, "payouts": {},
          "burned": 0}`` — no balance, no supply mutation.

        - **Pool > 0, proposal failed** (yes_weight × 3 ≤
          total_eligible × 2 in live-weight mode): burn the entire
          pool — decrement ``total_supply``, increment
          ``total_burned``.  No yes-voter is paid.

        - **Pool > 0, proposal passed**: distribute pro-rata-by-live-
          stake to YES voters whose ``get_staked > 0`` at close.  Any
          single voter's share is capped at
          ``VOTER_REWARD_MAX_SHARE_BPS / 10_000`` of the pool; the
          excess from the cap burns.  Integer-division dust burns
          (deterministic — no "lucky voter" picks up the remainder).

        After the call, ``state.voter_reward_pool`` is reset to 0 so a
        redundant invocation by replay or by an out-of-order block-
        apply path is a clean no-op.  The chain's
        ``_apply_governance_block`` calls this once per closing
        proposal, immediately before ``prune_closed_proposals``.

        The net-inflation invariant
        (``total_supply == GENESIS_SUPPLY + total_minted -
        total_burned``) is preserved because:

          * Distribution: tokens move from the pool into voter
            balances; ``total_supply``/``total_minted``/
            ``total_burned`` are all unchanged (the escrow accounting
            sits outside ``total_supply``'s definition — see
            VOTER_REWARD_HEIGHT in config.py).
          * Burn (full pool or cap excess + dust): each burned token
            decrements ``total_supply`` AND increments
            ``total_burned`` in lockstep.

        Returns a dict ``{"passed": bool, "payouts": dict[bytes, int],
        "burned": int}`` for inspection; chain code does not need it.
        """
        from messagechain.config import VOTER_REWARD_MAX_SHARE_BPS

        state = self.proposals.get(proposal_id)
        if state is None:
            return {"passed": False, "payouts": {}, "burned": 0}

        pool = state.voter_reward_pool
        if pool <= 0:
            # Pre-fork or already-finalized → no-op.
            return {"passed": False, "payouts": {}, "burned": 0}

        # Live-weight tally — same semantics as the H6 binding-execution
        # path.  Voters slashed or fully-unstaked between vote-cast and
        # close contribute 0 weight.
        yes_weight, _no_weight, _participating, total_eligible = self.tally(
            proposal_id, supply_tracker=supply_tracker,
        )
        # Strict 2/3 supermajority: yes × 3 > total × 2.  Matches the
        # rule in execute_treasury_spend so advisory and binding
        # proposals share the same passage threshold.
        passed = (
            total_eligible > 0
            and yes_weight * GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR
            > total_eligible * GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR
        )

        if not passed:
            # Burn the entire pool.  Decrement state's pool to 0 so a
            # replay/idempotent call is a no-op.
            state.voter_reward_pool = 0
            supply_tracker.total_supply -= pool
            supply_tracker.total_burned += pool
            return {"passed": False, "payouts": {}, "burned": pool}

        # Build the winners set: yes-voters with live stake > 0.
        winners = {}  # voter_id -> live_stake
        for voter_id, approve in state.votes.items():
            if not approve:
                continue
            live = supply_tracker.get_staked(voter_id)
            if live > 0:
                winners[voter_id] = live

        if not winners:
            # Edge case: proposal "passed" via silent supermajority
            # math somehow (e.g., zero eligible after slashing — but
            # passed is False then).  Defensive: burn pool.
            state.voter_reward_pool = 0
            supply_tracker.total_supply -= pool
            supply_tracker.total_burned += pool
            return {"passed": True, "payouts": {}, "burned": pool}

        cap = pool * VOTER_REWARD_MAX_SHARE_BPS // 10_000
        winners_total = sum(winners.values())
        # Iterate in a deterministic order (sorted by entity_id) so
        # the dust calculation is reproducible across nodes.  The
        # individual share = pool * stake // winners_total; dust =
        # pool - sum(shares) - sum(cap_excess).  Both burn.
        payouts: dict[bytes, int] = {}
        capped_excess = 0
        distributed = 0
        for voter_id in sorted(winners.keys()):
            share = pool * winners[voter_id] // winners_total
            if share > cap:
                capped_excess += share - cap
                share = cap
            payouts[voter_id] = share
            distributed += share

        # Credit each winner's balance.  No supply mutation — the
        # tokens are moving from escrow (outside any balance) back
        # into circulation in the recipients' balances.
        for voter_id, amount in payouts.items():
            if amount > 0:
                supply_tracker.balances[voter_id] = (
                    supply_tracker.balances.get(voter_id, 0) + amount
                )

        # Anything not paid out (dust + cap_excess) burns.
        burned = pool - distributed
        if burned > 0:
            supply_tracker.total_supply -= burned
            supply_tracker.total_burned += burned

        state.voter_reward_pool = 0
        return {"passed": True, "payouts": payouts, "burned": burned}

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
        # H6: binding tally MUST use live stake weights, not the frozen
        # snapshot.  A voter slashed or who unstaked after casting must
        # contribute their CURRENT stake (zero if slashed).  Otherwise a
        # whale attacker could cast a dispositive YES, get slashed for
        # an unrelated offense, and still carry the proposal.
        yes_weight, _no_weight, _participating, total_eligible = self.tally(
            tx.proposal_id, supply_tracker=supply_tracker,
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
            current_block=current_block,
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
# UTF-8 byte caps close the emoji/CJK amplification gap.  A 200-char
# title can be 800 bytes of emoji; a 10k-char description can be 40
# KB.  Because every byte of an admitted governance tx is permanent,
# the on-chain ceiling is the byte count, not the character count.
# Set to 2x the char cap so ASCII inputs always pass (same UX as
# before) while pure emoji hits the cap at half the char count.
MAX_PROPOSAL_TITLE_BYTES = 400
MAX_PROPOSAL_DESCRIPTION_BYTES = 20_000

# Tier 19 monotonicity invariant: the post-fork byte caps must
# tighten (never loosen) the legacy caps, otherwise the per-byte
# surcharge can be re-amortized away by a wider cap.  Use raise (not
# assert) so the check survives ``python -O`` -- consensus-critical
# files in this scope are required to use raise rather than assert
# (see tests/test_invariants_survive_optimize_mode.py).
if config.MAX_PROPOSAL_TITLE_BYTES_TIER19 > MAX_PROPOSAL_TITLE_BYTES:
    raise RuntimeError(
        "MAX_PROPOSAL_TITLE_BYTES_TIER19 must be <= legacy "
        "MAX_PROPOSAL_TITLE_BYTES (Tier 19 only tightens the cap)"
    )
if (
    config.MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19
    > MAX_PROPOSAL_DESCRIPTION_BYTES
):
    raise RuntimeError(
        "MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19 must be <= legacy "
        "MAX_PROPOSAL_DESCRIPTION_BYTES (Tier 19 only tightens the cap)"
    )


def proposal_payload_bytes(tx) -> int:
    """Return the variable-length payload (title + description +
    reference_hash) bytes that Tier 19's per-byte surcharge prices.

    Operates on either a ProposalTransaction or a
    TreasurySpendTransaction; the latter has no reference_hash so a
    getattr fallback returns 0 bytes for that field.
    """
    return (
        len(tx.title.encode("utf-8"))
        + len(tx.description.encode("utf-8"))
        + len(getattr(tx, "reference_hash", b""))
    )


def proposal_fee_floor(payload_bytes: int, current_height: int | None) -> int:
    """Return the active flat-fee floor for a proposal-class tx.

    Pre-PROPOSAL_FEE_TIER19_HEIGHT (or unknown height): the legacy
    flat ``GOVERNANCE_PROPOSAL_FEE`` (10_000), which historical chain
    state was admitted under.

    At/after the fork height: ``GOVERNANCE_PROPOSAL_FEE_TIER19 +
    GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * payload_bytes``.  The
    per-byte term locks the fee/byte invariant intrinsically — a
    future cap-raise can no longer re-amortize the floor away.
    """
    if (
        current_height is not None
        and current_height >= config.PROPOSAL_FEE_TIER19_HEIGHT
    ):
        return (
            config.GOVERNANCE_PROPOSAL_FEE_TIER19
            + config.GOVERNANCE_PROPOSAL_FEE_PER_BYTE_TIER19 * payload_bytes
        )
    return GOVERNANCE_PROPOSAL_FEE


def _proposal_byte_caps(current_height: int | None) -> tuple[int, int]:
    """(title_byte_cap, description_byte_cap) active at ``current_height``.

    Pre-PROPOSAL_FEE_TIER19_HEIGHT: legacy 400 / 20_000.  Post-fork:
    tightened 200 / 2_000 — long-form rationale must live off-chain
    behind ``reference_hash`` (already on the tx).
    """
    if (
        current_height is not None
        and current_height >= config.PROPOSAL_FEE_TIER19_HEIGHT
    ):
        return (
            config.MAX_PROPOSAL_TITLE_BYTES_TIER19,
            config.MAX_PROPOSAL_DESCRIPTION_BYTES_TIER19,
        )
    return MAX_PROPOSAL_TITLE_BYTES, MAX_PROPOSAL_DESCRIPTION_BYTES


def verify_proposal(
    tx: ProposalTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a proposal transaction's signature.

    `current_height`: post FEE_INCLUDES_SIGNATURE_HEIGHT the admission
    floor is max(GOVERNANCE_PROPOSAL_FEE, sig-aware min).  The flat
    governance floor remains an absolute lower bound pre- and
    post-activation (R5-A).
    """
    # Tier 15 version gate.  Reject any version above the highest
    # known release.  Reject v2 admission strictly before
    # GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT -- pre-activation only v1
    # txs are accepted, so an early v2 submission can't slip past
    # peers running pre-fork binaries.  Post-activation: REJECT v1
    # admission too -- v1 and v2 of the SAME logical proposal text
    # produce different tx_hashes (v2 commits version + length
    # prefixes), so allowing both creates a vote-splitting attack
    # surface (and for TreasurySpend, a double-spend attack: both
    # can clear 2/3 independently and each debits the treasury for
    # the same logical spend).  Closing v1 admission post-fork makes
    # this structurally impossible.  Historical pre-fork v1 blocks
    # still replay correctly because verify_proposal is called with
    # the historical block's height, not the live tip.
    if tx.version > GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
        return False
    if (
        current_height is not None
        and current_height >= config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
        and tx.version < GOVERNANCE_TX_VERSION_LENGTH_PREFIX
    ):
        return False
    if tx.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
        if (
            current_height is not None
            and current_height < config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
        ):
            return False
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    # Tier 19: flat_floor is height-aware -- post-fork it is
    # ``100_000 + 50 * payload_bytes`` (locks proposal fee/byte above
    # any plausible message fee/byte); pre-fork it is the legacy
    # flat 10_000 so historical blocks replay byte-for-byte.
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=proposal_fee_floor(
            proposal_payload_bytes(tx), current_height,
        ),
    ):
        return False
    if not tx.title:
        return False
    # M10: Bound title/description to prevent block bloat.  Tier 19
    # tightens the byte caps (title 400→200, description 20_000→
    # 2_000); the character-count caps stay as a fast-path rejection.
    if len(tx.title) > MAX_PROPOSAL_TITLE_LENGTH:
        return False
    if len(tx.description) > MAX_PROPOSAL_DESCRIPTION_LENGTH:
        return False
    title_byte_cap, desc_byte_cap = _proposal_byte_caps(current_height)
    if len(tx.title.encode("utf-8")) > title_byte_cap:
        return False
    if len(tx.description.encode("utf-8")) > desc_byte_cap:
        return False
    if tx.reference_hash and len(tx.reference_hash) != 32:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_vote(
    tx: VoteTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a vote transaction's signature.

    Post FEE_INCLUDES_SIGNATURE_HEIGHT the floor is
    max(GOVERNANCE_VOTE_FEE, sig-aware min) (R5-A).
    """
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=GOVERNANCE_VOTE_FEE,
    ):
        return False
    if not tx.proposal_id or len(tx.proposal_id) != 32:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)


def verify_treasury_spend(
    tx: TreasurySpendTransaction,
    public_key: bytes,
    current_height: int | None = None,
) -> bool:
    """Verify a treasury spend proposal's signature and fields.

    Post FEE_INCLUDES_SIGNATURE_HEIGHT the floor is
    max(GOVERNANCE_PROPOSAL_FEE, sig-aware min) (R5-A).
    """
    # Tier 15 version gate.  See verify_proposal for the full
    # rationale -- in particular the post-activation v1 rejection
    # that closes the vote-split + treasury-double-spend attack.
    if tx.version > GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
        return False
    if (
        current_height is not None
        and current_height >= config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
        and tx.version < GOVERNANCE_TX_VERSION_LENGTH_PREFIX
    ):
        return False
    if tx.version >= GOVERNANCE_TX_VERSION_LENGTH_PREFIX:
        if (
            current_height is not None
            and current_height < config.GOVERNANCE_TX_LENGTH_PREFIX_HEIGHT
        ):
            return False
    from messagechain.core.transaction import enforce_signature_aware_min_fee
    # Tier 19: same height-aware floor as plain ProposalTransaction --
    # treasury-spends carry identical permanent-state weight (snapshot,
    # active-proposal slot, full voting window) so the surcharge applies
    # symmetrically.
    if not enforce_signature_aware_min_fee(
        tx.fee,
        signature_bytes=len(tx.signature.to_bytes()),
        current_height=current_height,
        flat_floor=proposal_fee_floor(
            proposal_payload_bytes(tx), current_height,
        ),
    ):
        return False
    if not tx.title:
        return False
    if tx.amount <= 0:
        return False
    if not tx.recipient_id:
        return False
    if tx.recipient_id == TREASURY_ENTITY_ID:
        return False  # treasury cannot send to itself
    # Same length/byte caps as ProposalTransaction — treasury-spend
    # proposals were missing these entirely, which left their
    # title/description fields as an unbounded escape hatch.  Tier 19
    # tightens the byte caps for both classes.
    if len(tx.title) > MAX_PROPOSAL_TITLE_LENGTH:
        return False
    if len(tx.description) > MAX_PROPOSAL_DESCRIPTION_LENGTH:
        return False
    title_byte_cap, desc_byte_cap = _proposal_byte_caps(current_height)
    if len(tx.title.encode("utf-8")) > title_byte_cap:
        return False
    if len(tx.description.encode("utf-8")) > desc_byte_cap:
        return False
    msg_hash = _hash(tx._signable_data())
    return verify_signature(msg_hash, tx.signature, public_key)
