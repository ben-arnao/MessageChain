"""
Signed state-snapshot checkpoints — bootstrap-speed sync for new nodes.

Every STATE_CHECKPOINT_INTERVAL blocks, validators sign a
`StateCheckpoint(block_hash, block_number, state_root)` committing to the
chain state at block X.  When >= 2/3 of stake-at-X has signed, the
checkpoint is "verified" and becomes safe for new nodes to bootstrap from.

This is NOT about pruning — the chain itself remains permanent.  Archive
nodes keep everything.  The checkpoint merely lets a new full node / new
validator skip the replay cost of ancient history when joining late.

Security model:

* **Double-signing is slashable.**  Signing two different state_roots for
  the same block_number is equivocation — it would fracture the network
  because different peers would serve conflicting snapshots of the same
  height, and a Sybil attacker could sell an attack state.  Penalty:
  100% stake + full escrow burn, same as double-proposal / double-
  attestation / double-finality-vote.

* **Signature verification uses the validator's existing public key.**
  StateCheckpointSignature signs a distinct domain tag (b"STATE_CKPT_V1")
  so the signature can never be replayed as any other signed object
  (block header, attestation, finality vote, slashing evidence).

Shape mirrors FinalityVote: one-signer-at-a-time signed votes over a
canonical target, accumulated into a collection that crosses threshold
when 2/3 of stake-at-X has signed.  Reusing the existing multi-sig
aggregation pattern keeps behavior predictable for validators.
"""

import hashlib
import struct
from dataclasses import dataclass

from messagechain.config import (
    HASH_ALGO, CHAIN_ID, SIG_VERSION_CURRENT,
    STATE_CHECKPOINT_THRESHOLD_NUMERATOR,
    STATE_CHECKPOINT_THRESHOLD_DENOMINATOR,
)
from messagechain.crypto.keys import Signature, verify_signature


_STATE_CKPT_DOMAIN_TAG = b"STATE_CKPT_V1"


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class StateCheckpoint:
    """Canonical (block_number, block_hash, state_root) triple.

    Fields:
        block_number: checkpoint height
        block_hash:   block hash at that height
        state_root:   snapshot root committed to (from state_snapshot.
                      compute_state_root, NOT the per-entity header root)
    """
    block_number: int
    block_hash: bytes
    state_root: bytes

    def _signable_data(self) -> bytes:
        return (
            CHAIN_ID
            + _STATE_CKPT_DOMAIN_TAG
            + struct.pack(">Q", self.block_number)
            + self.block_hash
            + self.state_root
        )

    def consensus_hash(self) -> bytes:
        return _hash(self._signable_data())

    def serialize(self) -> dict:
        return {
            "block_number": self.block_number,
            "block_hash": self.block_hash.hex(),
            "state_root": self.state_root.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "StateCheckpoint":
        return cls(
            block_number=data["block_number"],
            block_hash=bytes.fromhex(data["block_hash"]),
            state_root=bytes.fromhex(data["state_root"]),
        )

    def to_bytes(self) -> bytes:
        # u64 block_number | 32 block_hash | 32 state_root
        return (
            struct.pack(">Q", self.block_number)
            + self.block_hash
            + self.state_root
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "StateCheckpoint":
        if len(data) != 8 + 32 + 32:
            raise ValueError(
                f"StateCheckpoint blob must be 72 bytes, got {len(data)}"
            )
        (block_number,) = struct.unpack_from(">Q", data, 0)
        block_hash = bytes(data[8:40])
        state_root = bytes(data[40:72])
        return cls(
            block_number=block_number,
            block_hash=block_hash,
            state_root=state_root,
        )


@dataclass
class StateCheckpointSignature:
    """One validator's signature over a StateCheckpoint.

    Collect >=2/3 of stake's worth of these to verify a checkpoint.
    """
    signer_entity_id: bytes
    block_number: int
    block_hash: bytes
    state_root: bytes
    signature: Signature

    def _signable_data(self) -> bytes:
        # Must match what create_state_checkpoint_signature signs.
        return StateCheckpoint(
            block_number=self.block_number,
            block_hash=self.block_hash,
            state_root=self.state_root,
        )._signable_data()

    def consensus_hash(self) -> bytes:
        return _hash(self._signable_data() + self.signer_entity_id)

    def serialize(self) -> dict:
        return {
            "signer_entity_id": self.signer_entity_id.hex(),
            "block_number": self.block_number,
            "block_hash": self.block_hash.hex(),
            "state_root": self.state_root.hex(),
            "signature": self.signature.serialize(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "StateCheckpointSignature":
        return cls(
            signer_entity_id=bytes.fromhex(data["signer_entity_id"]),
            block_number=data["block_number"],
            block_hash=bytes.fromhex(data["block_hash"]),
            state_root=bytes.fromhex(data["state_root"]),
            signature=Signature.deserialize(data["signature"]),
        )

    def to_bytes(self) -> bytes:
        """32 signer_id | u64 block_number | 32 block_hash |
        32 state_root | u32 sig_len | sig_blob."""
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.signer_entity_id,
            struct.pack(">Q", self.block_number),
            self.block_hash,
            self.state_root,
            struct.pack(">I", len(sig_blob)),
            sig_blob,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "StateCheckpointSignature":
        if len(data) < 32 + 8 + 32 + 32 + 4:
            raise ValueError("StateCheckpointSignature blob too short")
        off = 0
        signer = bytes(data[off:off + 32]); off += 32
        (block_number,) = struct.unpack_from(">Q", data, off); off += 8
        block_hash = bytes(data[off:off + 32]); off += 32
        state_root = bytes(data[off:off + 32]); off += 32
        (sig_len,) = struct.unpack_from(">I", data, off); off += 4
        if off + sig_len > len(data):
            raise ValueError("StateCheckpointSignature truncated at signature")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        if off != len(data):
            raise ValueError("StateCheckpointSignature has trailing bytes")
        return cls(
            signer_entity_id=signer,
            block_number=block_number,
            block_hash=block_hash,
            state_root=state_root,
            signature=sig,
        )


def create_state_checkpoint_signature(
    signer_entity,
    checkpoint: StateCheckpoint,
) -> StateCheckpointSignature:
    """Sign a StateCheckpoint with the signer's hot key.

    Consumes one WOTS+ leaf just like block proposal / attestation /
    finality voting.  Checkpoint signing cadence is one signature per
    STATE_CHECKPOINT_INTERVAL blocks, a small fraction of normal
    per-block signing.
    """
    msg_hash = _hash(checkpoint._signable_data())
    signature = signer_entity.keypair.sign(msg_hash)
    return StateCheckpointSignature(
        signer_entity_id=signer_entity.entity_id,
        block_number=checkpoint.block_number,
        block_hash=checkpoint.block_hash,
        state_root=checkpoint.state_root,
        signature=signature,
    )


def verify_state_checkpoint_signature(
    checkpoint: StateCheckpoint,
    signature: StateCheckpointSignature,
    public_key: bytes,
) -> bool:
    """Verify that `signature` covers `checkpoint` under `public_key`.

    Strict: the signature's embedded (block_number, block_hash, state_root)
    must match the checkpoint exactly.  A signature whose inner values
    disagree with the checkpoint is rejected — prevents a forwarder from
    reusing a valid signature on a shifted checkpoint.
    """
    if signature.block_number != checkpoint.block_number:
        return False
    if signature.block_hash != checkpoint.block_hash:
        return False
    if signature.state_root != checkpoint.state_root:
        return False
    msg_hash = _hash(checkpoint._signable_data())
    return verify_signature(msg_hash, signature.signature, public_key)


def verify_state_checkpoint(
    checkpoint: StateCheckpoint,
    signatures: list[StateCheckpointSignature],
    stake_at_checkpoint: dict[bytes, int],
    public_keys_at_checkpoint: dict[bytes, bytes],
) -> tuple[bool, str]:
    """Verify that >= 2/3 of stake-at-checkpoint has signed `checkpoint`.

    Arguments:
        checkpoint: the (block_number, block_hash, state_root) triple
        signatures: one StateCheckpointSignature per signer
        stake_at_checkpoint: entity_id -> stake, snapshotted at block
            `checkpoint.block_number` (the denominator is the total of
            values in this map)
        public_keys_at_checkpoint: entity_id -> public_key, as-of the
            checkpoint height.  A signer not in this map cannot be
            verified and contributes nothing.

    Returns (ok, reason).  ok=True iff the summed stake of signers whose
    signatures individually verify meets the threshold.
    """
    total_stake = sum(stake_at_checkpoint.values())
    if total_stake <= 0:
        return False, "No stake at checkpoint height"

    seen_signers: set[bytes] = set()
    accumulated_stake = 0
    for sig in signatures:
        if sig.signer_entity_id in seen_signers:
            # Dedupe — one signer can only contribute once.
            continue
        pk = public_keys_at_checkpoint.get(sig.signer_entity_id)
        if pk is None:
            # Signer unknown at checkpoint height — ignore (cannot verify).
            continue
        if not verify_state_checkpoint_signature(checkpoint, sig, pk):
            continue
        signer_stake = stake_at_checkpoint.get(sig.signer_entity_id, 0)
        if signer_stake <= 0:
            # A validator with no stake has no voting weight.
            continue
        seen_signers.add(sig.signer_entity_id)
        accumulated_stake += signer_stake

    # Integer-arithmetic 2/3 threshold: stake * DEN >= total * NUM.
    meets_threshold = (
        accumulated_stake * STATE_CHECKPOINT_THRESHOLD_DENOMINATOR
        >= total_stake * STATE_CHECKPOINT_THRESHOLD_NUMERATOR
    )
    if not meets_threshold:
        return False, (
            f"Insufficient stake signed checkpoint: "
            f"{accumulated_stake} / {total_stake} "
            f"(threshold {STATE_CHECKPOINT_THRESHOLD_NUMERATOR}/"
            f"{STATE_CHECKPOINT_THRESHOLD_DENOMINATOR})"
        )
    return True, "OK"


# ── Double-sign slashing ─────────────────────────────────────────────

@dataclass
class StateCheckpointDoubleSignEvidence:
    """Proof that a validator signed two different state_roots at the
    same block_number — a slashable equivocation.

    A validator who publishes two different snapshot roots for block X
    is fracturing the network: different new nodes would bootstrap to
    different states.  Penalty: 100% stake + full escrow burn, same as
    double-proposal / double-attestation / double-finality-vote.
    """
    offender_id: bytes
    checkpoint_a: StateCheckpoint
    signature_a: StateCheckpointSignature
    checkpoint_b: StateCheckpoint
    signature_b: StateCheckpointSignature
    evidence_hash: bytes = b""

    def __post_init__(self):
        if not self.evidence_hash:
            self.evidence_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        return _hash(
            b"state_ckpt_double_sign"
            + self.offender_id
            + self.checkpoint_a._signable_data()
            + self.checkpoint_b._signable_data()
        )

    def serialize(self) -> dict:
        return {
            "type": "state_ckpt_double_sign",
            "offender_id": self.offender_id.hex(),
            "checkpoint_a": self.checkpoint_a.serialize(),
            "signature_a": self.signature_a.serialize(),
            "checkpoint_b": self.checkpoint_b.serialize(),
            "signature_b": self.signature_b.serialize(),
            "evidence_hash": self.evidence_hash.hex(),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "StateCheckpointDoubleSignEvidence":
        ev = cls(
            offender_id=bytes.fromhex(data["offender_id"]),
            checkpoint_a=StateCheckpoint.deserialize(data["checkpoint_a"]),
            signature_a=StateCheckpointSignature.deserialize(data["signature_a"]),
            checkpoint_b=StateCheckpoint.deserialize(data["checkpoint_b"]),
            signature_b=StateCheckpointSignature.deserialize(data["signature_b"]),
        )
        declared = bytes.fromhex(data["evidence_hash"])
        if ev._compute_hash() != declared:
            raise ValueError("StateCheckpointDoubleSignEvidence hash mismatch")
        return ev

    def to_bytes(self) -> bytes:
        a = self.checkpoint_a.to_bytes()
        sa = self.signature_a.to_bytes()
        b = self.checkpoint_b.to_bytes()
        sb = self.signature_b.to_bytes()
        return b"".join([
            self.offender_id,
            struct.pack(">I", len(a)), a,
            struct.pack(">I", len(sa)), sa,
            struct.pack(">I", len(b)), b,
            struct.pack(">I", len(sb)), sb,
            self.evidence_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "StateCheckpointDoubleSignEvidence":
        if len(data) < 32 + 4 * 4 + 32:
            raise ValueError("StateCheckpointDoubleSignEvidence blob too short")
        off = 0
        offender = bytes(data[off:off + 32]); off += 32

        def _take():
            nonlocal off
            (ln,) = struct.unpack_from(">I", data, off); off += 4
            if off + ln > len(data):
                raise ValueError("truncated")
            blob = bytes(data[off:off + ln])
            off += ln
            return blob

        cp_a_blob = _take()
        sig_a_blob = _take()
        cp_b_blob = _take()
        sig_b_blob = _take()
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("trailing bytes in evidence")
        ev = cls(
            offender_id=offender,
            checkpoint_a=StateCheckpoint.from_bytes(cp_a_blob),
            signature_a=StateCheckpointSignature.from_bytes(sig_a_blob),
            checkpoint_b=StateCheckpoint.from_bytes(cp_b_blob),
            signature_b=StateCheckpointSignature.from_bytes(sig_b_blob),
        )
        if ev._compute_hash() != declared:
            raise ValueError(
                "StateCheckpointDoubleSignEvidence hash mismatch"
            )
        return ev


def verify_state_checkpoint_double_sign_evidence(
    evidence: StateCheckpointDoubleSignEvidence,
    offender_public_key: bytes,
) -> tuple[bool, str]:
    """Verify self-contained double-sign evidence.

    Checks:
        1. Both signatures name the same signer (offender).
        2. Both checkpoints have the same block_number.
        3. The state_roots actually differ (genuine conflict; same
           checkpoint signed twice is not slashable — it's just a
           duplicate gossip message).
        4. Both signatures verify under the offender's public key.
    """
    sa = evidence.signature_a
    sb = evidence.signature_b
    if sa.signer_entity_id != evidence.offender_id:
        return False, "signature_a signer does not match offender"
    if sb.signer_entity_id != evidence.offender_id:
        return False, "signature_b signer does not match offender"
    if evidence.checkpoint_a.block_number != evidence.checkpoint_b.block_number:
        return False, "checkpoints are at different heights"
    if evidence.checkpoint_a.state_root == evidence.checkpoint_b.state_root:
        return False, (
            "checkpoints have identical state_root — not a conflicting "
            "signature, so no equivocation took place"
        )
    if not verify_state_checkpoint_signature(
        evidence.checkpoint_a, sa, offender_public_key,
    ):
        return False, "signature_a does not verify"
    if not verify_state_checkpoint_signature(
        evidence.checkpoint_b, sb, offender_public_key,
    ):
        return False, "signature_b does not verify"
    return True, "Valid state-checkpoint double-sign evidence"
