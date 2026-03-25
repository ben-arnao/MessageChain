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
from messagechain.config import HASH_ALGO, FINALITY_THRESHOLD
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
            b"attestation"
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

    def add_attestation(
        self,
        attestation: Attestation,
        validator_stake: int,
        total_stake: int,
    ) -> bool:
        """Record an attestation. Returns True if the block becomes justified."""
        bh = attestation.block_hash
        if bh not in self.attestations:
            self.attestations[bh] = set()
            self.attested_stake[bh] = 0

        # Don't double-count same validator
        if attestation.validator_id in self.attestations[bh]:
            return bh in self.finalized

        self.attestations[bh].add(attestation.validator_id)
        self.attested_stake[bh] = self.attested_stake.get(bh, 0) + validator_stake

        # Check justification threshold
        if total_stake > 0 and (self.attested_stake[bh] / total_stake) >= FINALITY_THRESHOLD:
            if bh not in self.finalized:
                self.finalized.add(bh)
                if attestation.block_number > self.finalized_height:
                    self.finalized_height = attestation.block_number
                return True

        return bh in self.finalized

    def is_finalized(self, block_hash: bytes) -> bool:
        return block_hash in self.finalized

    def get_attested_stake_ratio(self, block_hash: bytes, total_stake: int) -> float:
        """Return the fraction of stake that has attested to this block."""
        if total_stake == 0:
            return 0.0
        return self.attested_stake.get(block_hash, 0) / total_stake
