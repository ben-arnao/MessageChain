"""
Attestation layer for MessageChain.

Validators don't just propose blocks — they must also attest (vote) for blocks
they consider valid. A block needs 2/3+ of total stake attesting to become
"justified." A justified block cannot be reverted by reorganization.

This solves two critical PoS problems:

1. **Single-proposer authority**: Without attestations, a lone proposer can
   produce blocks unilaterally. With attestations, 2/3+ of stake must agree.

2. **Nothing-at-stake**: Without finality, validators can cheaply vote on
   every fork. With attestation-based finality, voting for conflicting blocks
   at the same height is a slashable offense (just like double-proposal).

Design:
- After a block is proposed, validators verify it and sign an Attestation.
- The next block includes attestations for its parent.
- When a block accumulates >= FINALITY_THRESHOLD of stake in attestations,
  it becomes justified (finalized). Reorgs cannot go past finalized blocks.
"""

import hashlib
import struct
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, FINALITY_THRESHOLD_NUMERATOR, FINALITY_THRESHOLD_DENOMINATOR, CHAIN_ID
from messagechain.crypto.keys import Signature, verify_signature


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class Attestation:
    """A validator's vote for a specific block.

    Each attestation commits to a specific block_hash at a specific height.
    Signing two different attestations for the same height is slashable.
    """
    validator_id: bytes
    block_hash: bytes
    block_number: int
    signature: Signature

    def signable_data(self) -> bytes:
        """Data that the validator signs to create this attestation."""
        return (
            CHAIN_ID
            + b"attestation"
            + self.validator_id
            + self.block_hash
            + struct.pack(">Q", self.block_number)
        )

    def serialize(self) -> dict:
        return {
            "validator_id": self.validator_id.hex(),
            "block_hash": self.block_hash.hex(),
            "block_number": self.block_number,
            "signature": self.signature.serialize(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "Attestation":
        return cls(
            validator_id=bytes.fromhex(data["validator_id"]),
            block_hash=bytes.fromhex(data["block_hash"]),
            block_number=data["block_number"],
            signature=Signature.deserialize(data["signature"]),
        )


def create_attestation(validator_entity, block_hash: bytes, block_number: int) -> Attestation:
    """Create a signed attestation for a block.

    The validator asserts: "I have verified this block and consider it valid."
    """
    att = Attestation(
        validator_id=validator_entity.entity_id,
        block_hash=block_hash,
        block_number=block_number,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(att.signable_data())
    att.signature = validator_entity.keypair.sign(msg_hash)
    return att


def verify_attestation(attestation: Attestation, public_key: bytes) -> bool:
    """Verify that an attestation signature is valid."""
    msg_hash = _hash(attestation.signable_data())
    return verify_signature(msg_hash, attestation.signature, public_key)


class FinalityTracker:
    """Tracks which blocks have been justified (finalized) via attestations.

    A block is justified when attestations from >= 2/3 of total stake
    have been collected for it. Justified blocks form the finality boundary:
    no reorganization can revert a justified block.
    """

    def __init__(self):
        # block_hash -> set of validator_ids that attested
        self.attestations: dict[bytes, set[bytes]] = {}
        # block_hash -> total attested stake
        self.attested_stake: dict[bytes, int] = {}
        # Finalized block hashes (justified and irreversible)
        self.finalized: set[bytes] = set()
        # Height of the last finalized block
        self.finalized_height: int = 0
        # Track which block each validator attested to at each height
        # (validator_id, block_number) -> block_hash — prevents conflicting attestations
        self._attestation_by_height: dict[tuple[bytes, int], bytes] = {}
        # (validator_id, block_number) -> Attestation — needed for auto-slashing evidence
        self._attestation_objects: dict[tuple[bytes, int], Attestation] = {}
        # Auto-generated slashing evidence for equivocating validators
        self.pending_slashing_evidence: list = []

    def add_attestation(
        self,
        attestation: Attestation,
        validator_stake: int,
        total_stake: int,
    ) -> bool:
        """Record an attestation. Returns True if the block becomes justified."""
        bh = attestation.block_hash
        vid = attestation.validator_id
        height = attestation.block_number

        if bh not in self.attestations:
            self.attestations[bh] = set()
            self.attested_stake[bh] = 0

        # Don't double-count same validator
        if vid in self.attestations[bh]:
            return bh in self.finalized

        # Reject conflicting attestation: same validator, same height, different block.
        # This is a nothing-at-stake defense — validators must not vote on multiple forks.
        # Auto-generate slashing evidence so the network can punish the equivocator
        # without waiting for a third party to notice and submit evidence manually.
        key = (vid, height)
        if key in self._attestation_by_height:
            existing_bh = self._attestation_by_height[key]
            if existing_bh != bh:
                # Auto-generate slashing evidence
                existing_att = self._attestation_objects.get(key)
                if existing_att is not None:
                    from messagechain.consensus.slashing import AttestationSlashingEvidence
                    evidence = AttestationSlashingEvidence(
                        offender_id=vid,
                        attestation_a=existing_att,
                        attestation_b=attestation,
                    )
                    self.pending_slashing_evidence.append(evidence)
                return False

        self._attestation_by_height[key] = bh
        self._attestation_objects[key] = attestation
        self.attestations[bh].add(vid)
        self.attested_stake[bh] = self.attested_stake.get(bh, 0) + validator_stake

        # Check justification threshold
        # Integer arithmetic to avoid floating-point rounding errors.
        # attested/total >= NUM/DEN  ↔  attested * DEN >= total * NUM
        if total_stake > 0 and (
            self.attested_stake[bh] * FINALITY_THRESHOLD_DENOMINATOR
            >= total_stake * FINALITY_THRESHOLD_NUMERATOR
        ):
            if bh not in self.finalized:
                self.finalized.add(bh)
                if attestation.block_number > self.finalized_height:
                    self.finalized_height = attestation.block_number
                return True

        return bh in self.finalized

    def is_finalized(self, block_hash: bytes) -> bool:
        return block_hash in self.finalized

    def get_pending_slashing_evidence(self) -> list:
        """Return and clear auto-generated slashing evidence.

        Callers should broadcast the evidence as SlashTransactions so the
        equivocating validator is penalized on-chain.
        """
        evidence = list(self.pending_slashing_evidence)
        self.pending_slashing_evidence.clear()
        return evidence

    def get_attested_stake_ratio(self, block_hash: bytes, total_stake: int) -> float:
        """Return the fraction of stake that has attested to this block."""
        if total_stake == 0:
            return 0.0
        return self.attested_stake.get(block_hash, 0) / total_stake
