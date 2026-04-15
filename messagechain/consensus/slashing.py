"""
Slashing for MessageChain.

Two slashable offenses currently implemented:

1. **Double-proposal**: Signing two different block headers at the same height.
   A proposer who equivocates is attacking consensus.

2. **Double-attestation**: Signing two attestations for different blocks at the
   same height. A validator who votes for conflicting blocks is attacking
   finality (nothing-at-stake).

Both offenses carry the same penalty: 100% stake destruction AND
full burn of the offender's bootstrap-era escrow (see stage 3 /
`Blockchain._escrow`).  Burning escrow matters because during the
free-entry bootstrap window an attacker can earn substantial rewards
with minimal stake — without escrow burn, the stake-only penalty is
a negligible deterrent.  Escrow burn is applied by the Blockchain
(apply_slash_transaction and the slash_transactions loop in
_apply_block_state); the SupplyTracker-level slash_validator handles
only the stake portion.

Evidence is self-contained: two conflicting signed messages from the same
validator at the same height. Anyone can verify the evidence using only the
offender's public key — no external state required.

Anyone can submit evidence. The submitter receives a finder's reward
(a percentage of the slashed stake) to incentivize monitoring.

---

**Deliberately NOT implemented: censorship as a slashable offense.**

An earlier design draft considered a third slashable offense — a
proposer excluding a fee-paying tx from their block despite having
room.  We decided NOT to add this, for two reasons:

1. Censorship is inherent to permissionless block production.
   Every blockchain gives the proposer of block N unilateral
   discretion over block contents.  Removing that discretion means
   someone ELSE dictates contents, and that someone becomes a new
   censor.  A proposer's ability to skip a tx once is a property,
   not a bug.

2. Censorship is self-limiting by redundancy.  Validators rotate
   through proposer slots; a hostile proposer only produces their
   stake-weighted fraction of blocks.  The next honest proposer
   happily includes the skipped tx (and collects the tip for it).
   Expected inclusion delay with a single censor is 1-2 blocks.
   Adding a slashing rule buys very little because the behavior
   is already self-correcting.

The real consensus-critical misbehaviors are equivocation
(attacking liveness by signing two blocks at the same height) and
double-attestation (attacking finality by voting for conflicting
blocks).  Both corrupt consensus state itself — that's why they
ARE slashable here.  Sustained censorship by a colluding majority
falls under the 51% attack class and is handled by stake economics
(the attackers lose stake faster than they can maintain the
attack), not by a dedicated evidence type.

Users who worry about delivery timing raise the fee to make their
tx more attractive to the next honest proposer.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, SLASH_FINDER_REWARD_PCT, CHAIN_ID
from messagechain.core.block import BlockHeader, _hash
from messagechain.crypto.keys import Signature, verify_signature, KeyPair
from messagechain.consensus.attestation import Attestation, verify_attestation


@dataclass
class SlashingEvidence:
    """Proof that a validator signed two different blocks at the same height.

    Both headers must:
    - Have the same proposer_id (the offender)
    - Have the same block_number
    - Have different signable_data (actually conflicting)
    - Both carry valid signatures from the offender's key
    """
    offender_id: bytes
    header_a: BlockHeader
    header_b: BlockHeader
    evidence_hash: bytes = b""

    def __post_init__(self):
        if not self.evidence_hash:
            self.evidence_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        return _hash(
            self.offender_id
            + self.header_a.signable_data()
            + self.header_b.signable_data()
        )

    def serialize(self) -> dict:
        return {
            "offender_id": self.offender_id.hex(),
            "header_a": self.header_a.serialize(),
            "header_b": self.header_b.serialize(),
            "evidence_hash": self.evidence_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "SlashingEvidence":
        ev = cls(
            offender_id=bytes.fromhex(data["offender_id"]),
            header_a=BlockHeader.deserialize(data["header_a"]),
            header_b=BlockHeader.deserialize(data["header_b"]),
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = ev._compute_hash()
        declared_hash = bytes.fromhex(data["evidence_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"SlashingEvidence hash mismatch: declared {data['evidence_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return ev


@dataclass
class AttestationSlashingEvidence:
    """Proof that a validator attested to two different blocks at the same height.

    Both attestations must:
    - Have the same validator_id (the offender)
    - Have the same block_number
    - Have different block_hashes (actually conflicting)
    - Both carry valid signatures from the offender's key
    """
    offender_id: bytes
    attestation_a: Attestation
    attestation_b: Attestation
    evidence_hash: bytes = b""

    def __post_init__(self):
        if not self.evidence_hash:
            self.evidence_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        return _hash(
            b"attestation_slash"
            + self.offender_id
            + self.attestation_a.signable_data()
            + self.attestation_b.signable_data()
        )

    def serialize(self) -> dict:
        return {
            "type": "attestation_slash",
            "offender_id": self.offender_id.hex(),
            "attestation_a": self.attestation_a.serialize(),
            "attestation_b": self.attestation_b.serialize(),
            "evidence_hash": self.evidence_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "AttestationSlashingEvidence":
        ev = cls(
            offender_id=bytes.fromhex(data["offender_id"]),
            attestation_a=Attestation.deserialize(data["attestation_a"]),
            attestation_b=Attestation.deserialize(data["attestation_b"]),
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = ev._compute_hash()
        declared_hash = bytes.fromhex(data["evidence_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"AttestationSlashingEvidence hash mismatch: declared {data['evidence_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return ev


def verify_attestation_slashing_evidence(
    evidence: AttestationSlashingEvidence,
    offender_public_key: bytes,
) -> tuple[bool, str]:
    """
    Verify that attestation slashing evidence is valid.

    Checks:
    1. Both attestations name the same validator (the offender)
    2. Both attestations are at the same block height
    3. The attestations are for different blocks (actually conflicting)
    4. Both signatures are valid under the offender's public key
    """
    # Same validator
    if evidence.attestation_a.validator_id != evidence.offender_id:
        return False, "attestation_a validator does not match offender"
    if evidence.attestation_b.validator_id != evidence.offender_id:
        return False, "attestation_b validator does not match offender"

    # Same height
    if evidence.attestation_a.block_number != evidence.attestation_b.block_number:
        return False, "attestations are at different heights"

    # Actually different blocks
    if evidence.attestation_a.block_hash == evidence.attestation_b.block_hash:
        return False, "attestations are for the same block — not conflicting"

    # Verify both signatures
    if not verify_attestation(evidence.attestation_a, offender_public_key):
        return False, "attestation_a signature is invalid"

    if not verify_attestation(evidence.attestation_b, offender_public_key):
        return False, "attestation_b signature is invalid"

    return True, "Valid double-attestation evidence"


@dataclass
class SlashTransaction:
    """A transaction that submits slashing evidence.

    Supports both evidence types:
    - SlashingEvidence (double-proposal)
    - AttestationSlashingEvidence (double-attestation)
    """
    evidence: SlashingEvidence | AttestationSlashingEvidence
    submitter_id: bytes
    timestamp: float
    fee: int
    signature: Signature  # submitter signs the evidence hash
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        return (
            CHAIN_ID
            + self.evidence.evidence_hash
            + self.submitter_id
            + struct.pack(">Q", int(self.timestamp))
            + struct.pack(">Q", self.fee)
        )

    def _compute_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "type": "slash",
            "evidence": self.evidence.serialize(),
            "submitter_id": self.submitter_id.hex(),
            "timestamp": self.timestamp,
            "fee": self.fee,
            "signature": self.signature.serialize(),
            "tx_hash": self.tx_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "SlashTransaction":
        sig = Signature.deserialize(data["signature"])
        ev_data = data["evidence"]
        if ev_data.get("type") == "attestation_slash":
            evidence = AttestationSlashingEvidence.deserialize(ev_data)
        else:
            evidence = SlashingEvidence.deserialize(ev_data)
        tx = cls(
            evidence=evidence,
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        # Recompute hash and verify integrity — never trust declared hashes
        expected_hash = tx._compute_hash()
        declared_hash = bytes.fromhex(data["tx_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"SlashTransaction hash mismatch: declared {data['tx_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return tx


def verify_slashing_evidence(
    evidence: SlashingEvidence,
    offender_public_key: bytes,
) -> tuple[bool, str]:
    """
    Verify that slashing evidence is valid.

    Checks:
    1. Both headers name the same proposer (the offender)
    2. Both headers are at the same block height
    3. The headers are actually different (conflicting)
    4. Both signatures are valid under the offender's public key
    """
    # Same proposer
    if evidence.header_a.proposer_id != evidence.offender_id:
        return False, "header_a proposer does not match offender"
    if evidence.header_b.proposer_id != evidence.offender_id:
        return False, "header_b proposer does not match offender"

    # Same height
    if evidence.header_a.block_number != evidence.header_b.block_number:
        return False, "headers are at different heights"

    # Actually different
    if evidence.header_a.signable_data() == evidence.header_b.signable_data():
        return False, "headers are identical — not conflicting"

    # Both signatures present
    if evidence.header_a.proposer_signature is None:
        return False, "header_a has no signature"
    if evidence.header_b.proposer_signature is None:
        return False, "header_b has no signature"

    # Verify signature A
    hash_a = _hash(evidence.header_a.signable_data())
    if not verify_signature(hash_a, evidence.header_a.proposer_signature, offender_public_key):
        return False, "header_a signature is invalid"

    # Verify signature B
    hash_b = _hash(evidence.header_b.signable_data())
    if not verify_signature(hash_b, evidence.header_b.proposer_signature, offender_public_key):
        return False, "header_b signature is invalid"

    return True, "Valid double-sign evidence"


def create_slash_transaction(
    submitter_entity,
    evidence: SlashingEvidence | AttestationSlashingEvidence,
    fee: int = 1,
) -> SlashTransaction:
    """
    Create a slash transaction submitting evidence of a slashable offense.

    Accepts either double-proposal evidence (SlashingEvidence) or
    double-attestation evidence (AttestationSlashingEvidence).

    The submitter signs the evidence hash to prove they are the one
    reporting the offense (for finder's reward attribution).
    """
    tx = SlashTransaction(
        evidence=evidence,
        submitter_id=submitter_entity.entity_id,
        timestamp=time.time(),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    msg_hash = _hash(tx._signable_data())
    tx.signature = submitter_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx
