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

    def to_bytes(self) -> bytes:
        """Binary: 32 validator_id | 32 block_hash | u64 block_number |
        u32 sig_len | sig.
        """
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.validator_id,
            self.block_hash,
            struct.pack(">Q", self.block_number),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "Attestation":
        off = 0
        if len(data) < 32 + 32 + 8 + 4:
            raise ValueError("Attestation blob too short")
        validator_id = bytes(data[off:off + 32]); off += 32
        block_hash = bytes(data[off:off + 32]); off += 32
        block_number = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len > len(data):
            raise ValueError("Attestation truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        if off != len(data):
            raise ValueError("Attestation has trailing bytes")
        return cls(
            validator_id=validator_id, block_hash=block_hash,
            block_number=block_number, signature=sig,
        )

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


def attest_block_if_allowed(
    validator_entity,
    block,
    mempool,
    current_block_height: int,
    is_includable=None,
):
    """Create an attestation for `block` iff the forced-inclusion rule allows it.

    Single choke-point for the censorship-resistance defense.  Every
    production code path that signs an attestation MUST route through
    this function rather than calling `create_attestation` directly —
    otherwise an attester could accidentally (or maliciously) sign a
    block that drops long-waited user txs without the check firing.

    Returns the signed Attestation on a YES vote, or None on a NO vote.
    Callers who get None should log and silently skip — in the soft-
    vote model, a NO is simply the absence of an affirmative
    attestation.  If 2/3+ of stake similarly declines, the block fails
    finality.

    Parameters:
        validator_entity:     The Entity whose keypair signs the
                              attestation.
        block:                The block being voted on.
        mempool:              The attester's local Mempool — the
                              subjective view that drives the forced-
                              inclusion duty.
        current_block_height: Height of the block being voted on.
                              Used to compute "how long has this tx
                              waited?" against mempool arrival heights.
        is_includable:        Optional callback `(tx) -> bool` —
                              treats a forced tx as legitimately
                              excluded if it returns False (stale
                              nonce, insufficient balance, bad sig).
                              Pass None to default to "assume
                              includable".

    Design: this is deliberately a thin wrapper.  Keeping the
    forced-inclusion logic in forced_inclusion.py (pure, no key
    material, no network I/O) makes it easy to fuzz and audit; this
    function composes it with signing so callers have one call to
    make.  Tests that want to inspect the decision without signing
    keys can still call `should_attest_block` directly.
    """
    # Import inside the function to avoid a circular dep.  attestation.py
    # is imported by other consensus modules; forced_inclusion.py reads
    # config and has no consensus-layer dependency, so the one-way
    # direction at module load time stays clean.
    from messagechain.consensus.forced_inclusion import should_attest_block
    if not should_attest_block(
        block, mempool, current_block_height, is_includable=is_includable,
    ):
        return None
    return create_attestation(
        validator_entity, block.block_hash, block.header.block_number,
    )


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
        public_keys: dict[bytes, bytes] | None = None,
        min_validator_count: int = 0,
    ) -> bool:
        """Record an attestation. Returns True if the block becomes justified.

        If public_keys is provided, the attestation signature is verified
        before counting. Unverifiable attestations are rejected.

        If min_validator_count > 0, finalization additionally requires that
        at least that many distinct validators have attested for the block.
        This is the post-bootstrap safety floor: bootstrap exit is one-way,
        but if validators later leave and the active set thins out, the
        surviving one or two must NOT be able to finalize blocks alone
        (they would trivially hold 100% of remaining stake).  Finality
        simply halts in that regime — liveness degrades, but irreversibility
        is preserved.
        """
        bh = attestation.block_hash
        vid = attestation.validator_id
        height = attestation.block_number

        # H2: Verify attestation signature if public keys are available.
        # This prevents forged attestations from reaching finality.
        if public_keys is not None:
            pub = public_keys.get(vid)
            if pub is None:
                return False  # unknown validator
            if not verify_attestation(attestation, pub):
                return False  # bad signature

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
        stake_ok = total_stake > 0 and (
            self.attested_stake[bh] * FINALITY_THRESHOLD_DENOMINATOR
            >= total_stake * FINALITY_THRESHOLD_NUMERATOR
        )
        count_ok = len(self.attestations[bh]) >= min_validator_count
        if stake_ok and count_ok:
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

    def prune(self, below_height: int):
        """Remove attestation data for blocks below the given height.

        Prevents unbounded memory growth over the chain's lifetime.
        """
        keys_to_remove = [
            k for k in self._attestation_by_height if k[1] < below_height
        ]
        for k in keys_to_remove:
            bh = self._attestation_by_height.pop(k, None)
            self._attestation_objects.pop(k, None)
            # Clean up block-level tracking if no more attestations reference it
            if bh is not None and bh in self.attestations:
                vid = k[0]
                self.attestations[bh].discard(vid)
                if not self.attestations[bh]:
                    del self.attestations[bh]
                    self.attested_stake.pop(bh, None)

    def get_attested_stake_ratio(self, block_hash: bytes, total_stake: int) -> float:
        """Return the fraction of stake that has attested to this block."""
        if total_stake == 0:
            return 0.0
        return self.attested_stake.get(block_hash, 0) / total_stake
