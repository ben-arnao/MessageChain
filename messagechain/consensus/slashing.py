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
from messagechain.config import (
    HASH_ALGO, SLASH_FINDER_REWARD_PCT, CHAIN_ID, SIG_VERSION_CURRENT,
)
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

    def to_bytes(self) -> bytes:
        """Binary: 32 offender_id | u32 hdr_a_len | hdr_a | u32 hdr_b_len |
        hdr_b | 32 evidence_hash.
        """
        a = self.header_a.to_bytes()
        b = self.header_b.to_bytes()
        return b"".join([
            self.offender_id,
            struct.pack(">I", len(a)), a,
            struct.pack(">I", len(b)), b,
            self.evidence_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SlashingEvidence":
        from messagechain.core.block import BlockHeader
        off = 0
        if len(data) < 32 + 4:
            raise ValueError("SlashingEvidence blob too short")
        offender_id = bytes(data[off:off + 32]); off += 32
        a_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + a_len + 4 > len(data):
            raise ValueError("SlashingEvidence truncated at header_a")
        header_a = BlockHeader.from_bytes(bytes(data[off:off + a_len])); off += a_len
        b_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + b_len + 32 > len(data):
            raise ValueError("SlashingEvidence truncated at header_b")
        header_b = BlockHeader.from_bytes(bytes(data[off:off + b_len])); off += b_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SlashingEvidence has trailing bytes")
        ev = cls(offender_id=offender_id, header_a=header_a, header_b=header_b)
        expected = ev._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SlashingEvidence hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return ev

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

    def to_bytes(self) -> bytes:
        a = self.attestation_a.to_bytes()
        b = self.attestation_b.to_bytes()
        return b"".join([
            self.offender_id,
            struct.pack(">I", len(a)), a,
            struct.pack(">I", len(b)), b,
            self.evidence_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "AttestationSlashingEvidence":
        off = 0
        if len(data) < 32 + 4:
            raise ValueError("AttestationSlashingEvidence blob too short")
        offender_id = bytes(data[off:off + 32]); off += 32
        a_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + a_len + 4 > len(data):
            raise ValueError("AttestationSlashingEvidence truncated at attestation_a")
        att_a = Attestation.from_bytes(bytes(data[off:off + a_len])); off += a_len
        b_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + b_len + 32 > len(data):
            raise ValueError("AttestationSlashingEvidence truncated at attestation_b")
        att_b = Attestation.from_bytes(bytes(data[off:off + b_len])); off += b_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("AttestationSlashingEvidence has trailing bytes")
        ev = cls(offender_id=offender_id, attestation_a=att_a, attestation_b=att_b)
        expected = ev._compute_hash()
        if expected != declared:
            raise ValueError(
                f"AttestationSlashingEvidence hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return ev

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
    offender_public_key,
) -> tuple[bool, str]:
    """
    Verify that attestation slashing evidence is valid.

    Checks:
    1. Both attestations name the same validator (the offender)
    2. Both attestations are at the same block height
    3. The attestations are for different blocks (actually conflicting)
    4. Each attestation's signature is valid under SOME candidate
       public key for the offender.

    `offender_public_key` accepts either a single ``bytes`` (legacy
    single-key call sites: tests, ad-hoc scripts) or a list/iterable
    of ``bytes`` (the canonical post-fix call shape from
    ``Blockchain.validate_slash_transaction``, which assembles
    candidates from the offender's full key_history + their current
    pubkey).

    The multi-key form closes a slash-evasion attack: an equivocator
    can rotate keys between conflicting attestations -- att_a signed
    with K1, att_b signed with K2 -- and the pre-fix single-key call
    that resolved the offender's pubkey at the TARGET height would
    only see K1.  ``verify_attestation(att_b, K1)`` then fails and the
    evidence is dismissed.  The multi-key form accepts the evidence
    iff each attestation matches ANY of the offender's historical
    keys, defeating the rotation laundering.

    An attacker cannot exploit the multi-key acceptance to forge
    evidence: every candidate key in the list MUST come from the
    offender's on-chain key_history (or current public_keys).  The
    attacker would need to install a fake KeyRotation tx to plant a
    candidate, which is itself signed by the offender's prior key --
    so the candidate set only contains keys the offender has
    legitimately controlled at some point.
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

    # Normalise candidates to a list.  bytes -> [bytes].  Iterable[bytes]
    # passed through.  Filter out None / empty so a missing history
    # entry doesn't waste a verify call.
    if isinstance(offender_public_key, (bytes, bytearray)):
        candidates = [bytes(offender_public_key)]
    else:
        candidates = [bytes(pk) for pk in offender_public_key if pk]

    if not candidates:
        return False, "no candidate offender public keys"

    # Verify both signatures against ANY candidate.
    if not any(
        verify_attestation(evidence.attestation_a, pk) for pk in candidates
    ):
        return False, "attestation_a signature is invalid"

    if not any(
        verify_attestation(evidence.attestation_b, pk) for pk in candidates
    ):
        return False, "attestation_b signature is invalid"

    return True, "Valid double-attestation evidence"


@dataclass
class SlashTransaction:
    """A transaction that submits slashing evidence.

    Supports three evidence types:
    - SlashingEvidence (double-proposal)
    - AttestationSlashingEvidence (double-attestation)
    - FinalityDoubleVoteEvidence (double-finality-vote, long-range defense)
    """
    evidence: "SlashingEvidence | AttestationSlashingEvidence | FinalityDoubleVoteEvidence"
    submitter_id: bytes
    timestamp: float
    fee: int
    signature: Signature  # submitter signs the evidence hash
    tx_hash: bytes = b""

    def __post_init__(self):
        if not self.tx_hash:
            self.tx_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # Crypto-agility: commit the submitter's sig_version into tx_hash.
        # getattr fallback keeps None-signature test fixtures working.
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + b"slash"  # domain-separation tag: prevents cross-type sig replay
            + struct.pack(">B", sig_version)
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

    def to_bytes(self) -> bytes:
        """Binary: u8 evidence_kind (0=block, 1=attestation,
        2=finality-vote) | u32 ev_len | ev | 32 submitter_id | f64
        timestamp | u64 fee | u32 sig_len | sig | 32 tx_hash.
        """
        from messagechain.consensus.finality import FinalityDoubleVoteEvidence
        if isinstance(self.evidence, AttestationSlashingEvidence):
            kind = 1
        elif isinstance(self.evidence, FinalityDoubleVoteEvidence):
            kind = 2
        elif isinstance(self.evidence, SlashingEvidence):
            kind = 0
        else:
            raise ValueError(f"Unknown evidence type: {type(self.evidence).__name__}")
        ev_blob = self.evidence.to_bytes()
        sig_blob = self.signature.to_bytes()
        return b"".join([
            struct.pack(">B", kind),
            struct.pack(">I", len(ev_blob)),
            ev_blob,
            self.submitter_id,
            struct.pack(">d", float(self.timestamp)),
            struct.pack(">Q", self.fee),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.tx_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SlashTransaction":
        off = 0
        if len(data) < 1 + 4 + 32 + 8 + 8 + 4 + 32:
            raise ValueError("SlashTransaction blob too short")
        kind = struct.unpack_from(">B", data, off)[0]; off += 1
        ev_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + ev_len > len(data):
            raise ValueError("SlashTransaction truncated at evidence")
        ev_bytes = bytes(data[off:off + ev_len]); off += ev_len
        if kind == 0:
            evidence = SlashingEvidence.from_bytes(ev_bytes)
        elif kind == 1:
            evidence = AttestationSlashingEvidence.from_bytes(ev_bytes)
        elif kind == 2:
            from messagechain.consensus.finality import (
                FinalityDoubleVoteEvidence,
            )
            evidence = FinalityDoubleVoteEvidence.from_bytes(ev_bytes)
        else:
            raise ValueError(f"Unknown slash evidence kind: {kind}")
        submitter_id = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">d", data, off)[0]; off += 8
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SlashTransaction truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SlashTransaction has trailing bytes")
        tx = cls(
            evidence=evidence, submitter_id=submitter_id,
            timestamp=timestamp, fee=fee, signature=sig,
        )
        expected = tx._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SlashTransaction hash mismatch: declared {declared.hex()[:16]}, "
                f"computed {expected.hex()[:16]}"
            )
        return tx

    @classmethod
    def deserialize(cls, data: dict) -> "SlashTransaction":
        sig = Signature.deserialize(data["signature"])
        ev_data = data["evidence"]
        ev_type = ev_data.get("type")
        if ev_type == "attestation_slash":
            evidence = AttestationSlashingEvidence.deserialize(ev_data)
        elif ev_type == "finality_double_vote":
            from messagechain.consensus.finality import (
                FinalityDoubleVoteEvidence,
            )
            evidence = FinalityDoubleVoteEvidence.deserialize(ev_data)
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
    offender_public_key,
) -> tuple[bool, str]:
    """
    Verify that double-proposal slashing evidence is valid.

    Same multi-key candidate semantics as
    ``verify_attestation_slashing_evidence`` -- accepts either a
    single ``bytes`` key (legacy) or an iterable of candidate keys
    drawn from the offender's full key_history.  Closes the same
    rotation-evasion attack: an equivocator who rotates between
    signing two conflicting block headers escapes the slash if only
    a single (target-height) key is consulted.
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

    # Normalise candidates (see verify_attestation_slashing_evidence
    # for the full rationale on multi-key acceptance).
    if isinstance(offender_public_key, (bytes, bytearray)):
        candidates = [bytes(offender_public_key)]
    else:
        candidates = [bytes(pk) for pk in offender_public_key if pk]
    if not candidates:
        return False, "no candidate offender public keys"

    # Verify signature A against any candidate
    hash_a = _hash(evidence.header_a.signable_data())
    if not any(
        verify_signature(hash_a, evidence.header_a.proposer_signature, pk)
        for pk in candidates
    ):
        return False, "header_a signature is invalid"

    # Verify signature B against any candidate
    hash_b = _hash(evidence.header_b.signable_data())
    if not any(
        verify_signature(hash_b, evidence.header_b.proposer_signature, pk)
        for pk in candidates
    ):
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
        timestamp=int(time.time()),
        fee=fee,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )

    msg_hash = _hash(tx._signable_data())
    tx.signature = submitter_entity.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()

    return tx
