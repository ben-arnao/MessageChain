"""
Slashing for MessageChain.

Validators who double-sign (sign two different blocks at the same height)
are punished by having their entire stake destroyed. This is the maximum
deterrent — a double-signing validator is actively attacking the network.

Evidence is self-contained: two conflicting signed block headers from the
same proposer at the same height. Anyone can verify the evidence using only
the offender's public key — no external state required.

Anyone can submit evidence. The submitter receives a finder's reward
(a percentage of the slashed stake) to incentivize monitoring.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import HASH_ALGO, SLASH_FINDER_REWARD_PCT
from messagechain.core.block import BlockHeader, _hash
from messagechain.crypto.keys import Signature, verify_signature, KeyPair


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
        ev.evidence_hash = bytes.fromhex(data["evidence_hash"])
        return ev


@dataclass
class SlashTransaction:
    """A transaction that submits slashing evidence against a double-signer."""
    evidence: SlashingEvidence
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
            self.evidence.evidence_hash
            + self.submitter_id
            + struct.pack(">d", self.timestamp)
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
        tx = cls(
            evidence=SlashingEvidence.deserialize(data["evidence"]),
            submitter_id=bytes.fromhex(data["submitter_id"]),
            timestamp=data["timestamp"],
            fee=data["fee"],
            signature=sig,
        )
        tx.tx_hash = bytes.fromhex(data["tx_hash"])
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
    evidence: SlashingEvidence,
    fee: int = 1,
) -> SlashTransaction:
    """
    Create a slash transaction submitting evidence of double-signing.

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
