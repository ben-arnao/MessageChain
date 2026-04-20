"""
Finality signing — long-range-attack defense for MessageChain.

The existing PoS fork-choice rule picks the chain with the highest
cumulative stake weight.  That works against contemporary attackers
but is vulnerable to long-range attacks: in year 500, an attacker who
has acquired (leak, coercion, purchase) early validator keys could
produce a competing history from an old block and claim a longer
stake-weight chain.  Explicit, persistent finality signatures defeat
this attack by creating cryptographic commitments that no later reorg
can undo, regardless of how much stake weight the attacker can
fabricate over ancient history.

Design (a simple finality gadget):

1. **Checkpoints**: every FINALITY_INTERVAL blocks, validators may sign
   a FinalityVote(target_block_hash, target_block_number,
   signer_entity_id, wots_signature).

2. **Gossip + mempool**: FinalityVotes propagate through the p2p
   network and are collected in Mempool.finality_pool, analogous to
   the existing slash_pool.

3. **Inclusion**: when a validator proposes a block, they attach any
   valid FinalityVotes from the pool in block.finality_votes.
   Including votes earns the proposer a small bounty from treasury
   (FINALITY_VOTE_INCLUSION_REWARD tokens per vote) — mirrors the
   finder's-reward incentive from slashing.

4. **Finalization rule**: a block B becomes FINALIZED when cumulative
   >= 2/3 of total-stake-at-block-B has signed FinalityVotes for
   B.block_hash and those votes have been included in any block C
   with C.number > B.number.  Matches the existing
   FINALITY_THRESHOLD_NUMERATOR/DENOMINATOR fraction.

5. **Fork-choice interaction**: MAX_REORG_DEPTH still bounds normal
   reorgs.  ADDITIONALLY: no chain that contradicts a finalized block
   is accepted, regardless of stake weight.  Finalized-block hashes
   are persisted so the rule survives restart — this is the critical
   piece that makes long-range-attack defense actually durable across
   node lifetime.

6. **Slashing**: signing two different FinalityVotes for the same
   target_block_number is a new slashable offense.  Evidence is
   self-contained (two conflicting signed votes); penalty is 100%
   stake destruction + escrow burn, same pattern as double-sign or
   double-attestation.

Signature domain: FinalityVote signs a distinct tag byte
("FINALITY_VOTE_V1") to prevent cross-type signature reuse — a
FinalityVote signature can never be replayed as a block proposer
signature, attestation, or slashing submission.
"""

import hashlib
import struct
import time
from dataclasses import dataclass
from messagechain.config import (
    HASH_ALGO, CHAIN_ID, SIG_VERSION_CURRENT,
    FINALITY_THRESHOLD_NUMERATOR, FINALITY_THRESHOLD_DENOMINATOR,
)
from messagechain.crypto.keys import Signature, verify_signature


# Distinct domain tag.  A finality vote must NEVER collide with any
# other signable data in this protocol — the tag is the first
# component of _signable_data and differs from attestations (which
# use b"attestation"), block headers (unprefixed BlockHeader bytes),
# slashing (which hashes evidence hashes), and every tx type.
_FINALITY_VOTE_DOMAIN_TAG = b"FINALITY_VOTE_V1"


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class FinalityVote:
    """A validator's signed commitment to a specific block hash at height N.

    Unlike attestations (which gossip every slot for the immediate
    parent), finality votes are persistent checkpoints: the hash of a
    finalized block enters permanent storage and no later fork may
    rewrite it.

    Fields:
        signer_entity_id:    validator that signed this vote
        target_block_hash:   block hash being committed to
        target_block_number: height of the committed block
        signature:           WOTS+ signature over _signable_data()
    """
    signer_entity_id: bytes
    target_block_hash: bytes
    target_block_number: int
    signature: Signature

    def _signable_data(self) -> bytes:
        """Bytes the signer commits to.

        Crypto-agility: sig_version from the attached signature is
        included so a downstream byte-flip of the scheme invalidates
        the vote's identity hash.  getattr fallback keeps None-
        signature test fixtures working during construction-before-
        signing.
        """
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return (
            CHAIN_ID
            + _FINALITY_VOTE_DOMAIN_TAG
            + struct.pack(">B", sig_version)
            + self.target_block_hash
            + struct.pack(">Q", self.target_block_number)
            + self.signer_entity_id
        )

    def consensus_hash(self) -> bytes:
        """Stable identity hash of this vote for dedupe / mempool keying."""
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "signer_entity_id": self.signer_entity_id.hex(),
            "target_block_hash": self.target_block_hash.hex(),
            "target_block_number": self.target_block_number,
            "signature": self.signature.serialize(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "FinalityVote":
        return cls(
            signer_entity_id=bytes.fromhex(data["signer_entity_id"]),
            target_block_hash=bytes.fromhex(data["target_block_hash"]),
            target_block_number=data["target_block_number"],
            signature=Signature.deserialize(data["signature"]),
        )

    def to_bytes(self, state=None) -> bytes:
        """Binary: 32 signer_id | 32 target_hash | u64 target_number |
        u32 sig_len | sig_blob.

        signer_entity_id stays full-width (32 bytes) — finality votes
        may target and gossip across validators that predate the
        current entity-index registry, and keeping the encoding state-
        free avoids the cross-chain encoding footgun where a vote
        decodes differently on a node with a different index map.
        """
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.signer_entity_id,
            self.target_block_hash,
            struct.pack(">Q", self.target_block_number),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ])

    @classmethod
    def from_bytes(cls, data: bytes, state=None) -> "FinalityVote":
        if len(data) < 32 + 32 + 8 + 4:
            raise ValueError("FinalityVote blob too short")
        off = 0
        signer_id = bytes(data[off:off + 32]); off += 32
        target_hash = bytes(data[off:off + 32]); off += 32
        target_num = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len > len(data):
            raise ValueError("FinalityVote truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        if off != len(data):
            raise ValueError("FinalityVote has trailing bytes")
        return cls(
            signer_entity_id=signer_id,
            target_block_hash=target_hash,
            target_block_number=target_num,
            signature=sig,
        )


def create_finality_vote(
    signer_entity,
    target_block_hash: bytes,
    target_block_number: int,
) -> FinalityVote:
    """Sign a FinalityVote for (target_block_hash, target_block_number).

    Consumes one WOTS+ leaf from signer_entity.keypair — finality
    signing is leaf-budget-visible just like block proposal and
    attestation.  Validators that sign votes every FINALITY_INTERVAL
    blocks use leaves at roughly 1/100 the attestation rate.
    """
    vote = FinalityVote(
        signer_entity_id=signer_entity.entity_id,
        target_block_hash=target_block_hash,
        target_block_number=target_block_number,
        signature=Signature([], 0, [], b"", b""),  # placeholder
    )
    msg_hash = _hash(vote._signable_data())
    vote.signature = signer_entity.keypair.sign(msg_hash)
    return vote


def verify_finality_vote(vote: FinalityVote, public_key: bytes) -> bool:
    """Verify that the vote's signature is valid under `public_key`."""
    msg_hash = _hash(vote._signable_data())
    return verify_signature(msg_hash, vote.signature, public_key)


@dataclass
class FinalityDoubleVoteEvidence:
    """Proof that a validator signed two conflicting FinalityVotes.

    Both votes must:
    - Be signed by the same signer_entity_id (the offender)
    - Reference the same target_block_number
    - Reference DIFFERENT target_block_hashes (actually conflicting)
    - Carry valid signatures from the offender's key

    Nothing-at-stake defense for the finality layer: a validator that
    signs two different hashes at the same checkpoint height is
    equivocating, and every honest node will 100% slash them upon
    seeing this evidence.
    """
    offender_id: bytes
    vote_a: FinalityVote
    vote_b: FinalityVote
    evidence_hash: bytes = b""

    def __post_init__(self):
        if not self.evidence_hash:
            self.evidence_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        return _hash(
            b"finality_double_vote"
            + self.offender_id
            + self.vote_a._signable_data()
            + self.vote_b._signable_data()
        )

    def serialize(self) -> dict:
        return {
            "type": "finality_double_vote",
            "offender_id": self.offender_id.hex(),
            "vote_a": self.vote_a.serialize(),
            "vote_b": self.vote_b.serialize(),
            "evidence_hash": self.evidence_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        """Binary: 32 offender_id | u32 a_len | a | u32 b_len | b | 32 evidence_hash."""
        a = self.vote_a.to_bytes()
        b = self.vote_b.to_bytes()
        return b"".join([
            self.offender_id,
            struct.pack(">I", len(a)), a,
            struct.pack(">I", len(b)), b,
            self.evidence_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "FinalityDoubleVoteEvidence":
        off = 0
        if len(data) < 32 + 4:
            raise ValueError("FinalityDoubleVoteEvidence blob too short")
        offender_id = bytes(data[off:off + 32]); off += 32
        a_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + a_len + 4 > len(data):
            raise ValueError("FinalityDoubleVoteEvidence truncated at vote_a")
        vote_a = FinalityVote.from_bytes(bytes(data[off:off + a_len])); off += a_len
        b_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + b_len + 32 > len(data):
            raise ValueError("FinalityDoubleVoteEvidence truncated at vote_b")
        vote_b = FinalityVote.from_bytes(bytes(data[off:off + b_len])); off += b_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("FinalityDoubleVoteEvidence has trailing bytes")
        ev = cls(offender_id=offender_id, vote_a=vote_a, vote_b=vote_b)
        expected = ev._compute_hash()
        if expected != declared:
            raise ValueError(
                f"FinalityDoubleVoteEvidence hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return ev

    @classmethod
    def deserialize(cls, data: dict) -> "FinalityDoubleVoteEvidence":
        ev = cls(
            offender_id=bytes.fromhex(data["offender_id"]),
            vote_a=FinalityVote.deserialize(data["vote_a"]),
            vote_b=FinalityVote.deserialize(data["vote_b"]),
        )
        expected_hash = ev._compute_hash()
        declared_hash = bytes.fromhex(data["evidence_hash"])
        if expected_hash != declared_hash:
            raise ValueError(
                f"FinalityDoubleVoteEvidence hash mismatch: declared "
                f"{data['evidence_hash'][:16]}, "
                f"computed {expected_hash.hex()[:16]}"
            )
        return ev


def verify_finality_double_vote_evidence(
    evidence: FinalityDoubleVoteEvidence,
    offender_public_key: bytes,
) -> tuple[bool, str]:
    """Verify self-contained double-vote evidence.

    Checks:
    1. Both votes name the same signer (the offender)
    2. Both votes target the same block_number
    3. The target hashes differ (actually conflicting)
    4. Both signatures verify under the offender's public key
    """
    if evidence.vote_a.signer_entity_id != evidence.offender_id:
        return False, "vote_a signer does not match offender"
    if evidence.vote_b.signer_entity_id != evidence.offender_id:
        return False, "vote_b signer does not match offender"
    if evidence.vote_a.target_block_number != evidence.vote_b.target_block_number:
        return False, "votes are at different heights"
    if evidence.vote_a.target_block_hash == evidence.vote_b.target_block_hash:
        return False, "votes are for the same block — not conflicting"
    if not verify_finality_vote(evidence.vote_a, offender_public_key):
        return False, "vote_a signature is invalid"
    if not verify_finality_vote(evidence.vote_b, offender_public_key):
        return False, "vote_b signature is invalid"
    return True, "Valid double-vote evidence"


class FinalityCheckpoints:
    """Tracks which block hashes have been FINALIZED via FinalityVotes.

    Separate from the attestation-layer FinalityTracker: those votes
    are ephemeral and in-memory for immediate-parent finality.  These
    are persistent checkpoints.  The set of finalized block hashes is
    the cryptographic commitment a long-range attacker cannot rewrite.

    Intentionally simple: just a (height, hash) registry plus per-
    target accumulators for votes still below threshold.  The
    reorg-rejection rule reads from `finalized_hashes` directly, and
    storage persists that same set verbatim via chaindb.
    """

    def __init__(self):
        # target_block_hash -> set of signer_entity_ids that voted
        self._signers_by_hash: dict[bytes, set[bytes]] = {}
        # target_block_hash -> cumulative stake of signers
        self._stake_by_hash: dict[bytes, int] = {}
        # target_block_hash -> target_block_number (for prune / finalize)
        self._height_by_hash: dict[bytes, int] = {}
        # Finalized block hashes (set, for O(1) contains)
        self.finalized_hashes: set[bytes] = set()
        # height -> block_hash map for finalized blocks.  Used by reorg
        # logic (reject competing block at a finalized height) and by
        # external queries.
        self.finalized_by_height: dict[int, bytes] = {}
        # Auto-generated slashing evidence for equivocating signers
        self.pending_slashing_evidence: list = []
        # Track (signer, target_height) -> (target_hash, FinalityVote)
        # so that a second vote for a DIFFERENT hash at the same height
        # is detected and evidence is built.
        self._vote_by_signer_height: dict[
            tuple[bytes, int], tuple[bytes, FinalityVote]
        ] = {}

    def add_vote(
        self,
        vote: FinalityVote,
        signer_stake: int,
        total_stake_at_target: int,
    ) -> bool:
        """Record a finality vote.  Returns True iff the target block
        CROSSES the finalization threshold as a result of this call.

        Idempotent: a duplicate (same signer + same hash) returns
        False without double-counting stake.  A CONFLICTING vote
        (same signer, same height, different hash) auto-generates
        slashing evidence and returns False — the second vote is
        NOT credited toward either target.
        """
        sh = vote.target_block_hash
        sid = vote.signer_entity_id
        height = vote.target_block_number

        # Conflicting-vote detection: same signer + same height +
        # different target hash → auto-slashing evidence.
        key = (sid, height)
        prior = self._vote_by_signer_height.get(key)
        if prior is not None:
            prior_hash, prior_vote = prior
            if prior_hash != sh:
                evidence = FinalityDoubleVoteEvidence(
                    offender_id=sid,
                    vote_a=prior_vote,
                    vote_b=vote,
                )
                self.pending_slashing_evidence.append(evidence)
                return False
            # Same hash → duplicate; see below

        # Dedupe by signer-per-target-hash
        if sh not in self._signers_by_hash:
            self._signers_by_hash[sh] = set()
            self._stake_by_hash[sh] = 0
            self._height_by_hash[sh] = height

        if sid in self._signers_by_hash[sh]:
            # Already counted.  Idempotent no-op.
            return False

        # Record the vote
        self._vote_by_signer_height[key] = (sh, vote)
        self._signers_by_hash[sh].add(sid)
        self._stake_by_hash[sh] = self._stake_by_hash.get(sh, 0) + signer_stake

        # Check the 2/3-stake threshold (integer arithmetic to match
        # the existing attestation-layer check: stake*DEN >= total*NUM).
        already_finalized = sh in self.finalized_hashes
        stake_ok = total_stake_at_target > 0 and (
            self._stake_by_hash[sh] * FINALITY_THRESHOLD_DENOMINATOR
            >= total_stake_at_target * FINALITY_THRESHOLD_NUMERATOR
        )
        if stake_ok and not already_finalized:
            self.finalized_hashes.add(sh)
            self.finalized_by_height[height] = sh
            return True
        return False

    def is_finalized(self, block_hash: bytes) -> bool:
        return block_hash in self.finalized_hashes

    def is_height_finalized(self, block_number: int) -> bool:
        return block_number in self.finalized_by_height

    def highest_finalized_height(self) -> int:
        if not self.finalized_by_height:
            return -1
        return max(self.finalized_by_height.keys())

    def mark_finalized(self, block_hash: bytes, block_number: int):
        """Load a (height, hash) pair directly — used on restart to
        rehydrate from persistent storage without replaying votes."""
        self.finalized_hashes.add(block_hash)
        self.finalized_by_height[block_number] = block_hash

    def get_pending_slashing_evidence(self) -> list:
        """Return and clear auto-generated slashing evidence."""
        evidence = list(self.pending_slashing_evidence)
        self.pending_slashing_evidence.clear()
        return evidence

    def get_attested_stake(self, block_hash: bytes) -> int:
        return self._stake_by_hash.get(block_hash, 0)
