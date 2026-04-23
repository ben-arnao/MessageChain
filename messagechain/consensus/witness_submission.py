"""
Witnessed-submission wire types.

Closes the silent-TCP-drop censorship gap remaining after the
signed-rejection slashing work.  Today's `SignedRejection` catches
validators who answer an HTTPS submission with a bogus rejection
reason — but it does NOT catch validators who simply hang up the TCP
connection silently.  The user has no proof the validator received the
submission, so no on-chain evidence can be filed.

Witnessed submission closes this:

  1. Client opts in (paying WITNESS_SURCHARGE on top of the normal fee),
     signs a `SubmissionRequest` blob covering
     `(tx_hash, target_validator_id, timestamp, client_nonce)`.
  2. Sends the request to the target validator's HTTPS endpoint with
     header `X-MC-Witnessed-Submission: <hex(request_hash)>` AND
     gossips the digest to a witness topic.
  3. Target validator MUST publish a signed `SubmissionAck` within
     `WITNESS_RESPONSE_DEADLINE_BLOCKS`.  If they do, peers who saw
     the gossip can mark the obligation discharged.
  4. If they don't, peers who saw the gossip submit a
     `NonResponseEvidenceTx` (see consensus.non_response_evidence) and
     the validator gets slashed `WITNESS_NON_RESPONSE_SLASH_BPS` of
     stake.

Design constraints (from CLAUDE.md):
  * OPT-IN per submission — default submission path is unchanged.
  * Costs a fee surcharge so it can't be used to grief validators.
  * Stdlib only.  No external deps.
  * Witness gossip is best-effort; Q-of-N attestations are sufficient
    for slashing — we don't try to make this BFT-reliable.

Key invariants:
  * `_REQUEST_DOMAIN_TAG`, `_ACK_DOMAIN_TAG`, `_OBSERVATION_DOMAIN_TAG`
    are distinct from each other AND from every other domain tag in
    the codebase, so a signature on one wire type can never be
    replayed as another.
  * `SubmissionAck` reuses the validator's RECEIPT subtree (same
    WOTS+ keypair as `SubmissionReceipt` and `SignedRejection`).
    Sharing the subtree means one root-pubkey commitment on-chain
    covers all three paths.  Acks are opt-in + rate-limited by the
    client-paid surcharge so the leaf-budget impact is bounded.
  * `request_hash` binds every signed object — the client's signature
    on the request, the validator's signature on the ack, and the
    witness's signature on the observation all commit to the same
    32-byte digest, so a bait-and-switch is impossible.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from messagechain.config import (
    CHAIN_ID, HASH_ALGO, MIN_FEE, SIG_VERSION_CURRENT, WITNESS_SURCHARGE,
)
from messagechain.crypto.keys import Signature, verify_signature
from messagechain.crypto.hashing import default_hash


# ─────────────────────────────────────────────────────────────────────
# Domain tags — all four MUST be distinct from each other and from
# every other `mc-*` tag in the codebase.  See
# tests/test_witness_submission.py::TestDomainTagsAreDistinct.
# ─────────────────────────────────────────────────────────────────────

_REQUEST_DOMAIN_TAG = b"mc-submission-request-v1"
_ACK_DOMAIN_TAG = b"mc-submission-ack-v1"
_OBSERVATION_DOMAIN_TAG = b"mc-witness-observation-v1"


# ─────────────────────────────────────────────────────────────────────
# Action codes for SubmissionAck.action_code.  Plain int constants
# (NOT an Enum) so the wire format is consensus-stable and the
# encoding stays stdlib-only — same pattern as the REJECT_* codes in
# submission_receipt.
# ─────────────────────────────────────────────────────────────────────

ACK_ADMITTED = 1
"""Validator accepted the witnessed submission into its mempool."""

ACK_REJECTED = 2
"""Validator rejected the witnessed submission (validation failure)."""

_VALID_ACK_CODES: frozenset = frozenset({ACK_ADMITTED, ACK_REJECTED})


def _h(data: bytes) -> bytes:
    return default_hash(data)


# ─────────────────────────────────────────────────────────────────────
# SubmissionRequest — client-signed.
# ─────────────────────────────────────────────────────────────────────

@dataclass
class SubmissionRequest:
    """Client-signed: 'I am submitting tx_hash to target_validator at
    time T, paying WITNESS_SURCHARGE on top of the normal fee'.

    The same blob is BOTH posted to the target validator's
    /v1/submit endpoint (as the X-MC-Witnessed-Submission digest) AND
    gossiped to the witness topic.  Witnesses who see the gossip but
    do not see a corresponding SubmissionAck within
    WITNESS_RESPONSE_DEADLINE_BLOCKS can later sign a
    WitnessObservation that becomes part of a NonResponseEvidenceTx.

    Fields are sized for fixed-width binary encoding so the witness
    topic carries minimal bytes.
    """

    tx_hash: bytes              # 32 B — the tx being submitted
    target_validator_id: bytes  # 32 B — entity_id of target validator
    timestamp: int              # integer seconds, consensus-hashed
    client_nonce: bytes         # 16 B random — prevents request collision
    submitter_id: bytes         # 32 B — client entity_id (witness fee payer)
    fee: int                    # >= MIN_FEE + WITNESS_SURCHARGE
    signature: Signature        # WOTS+ signature from submitter_id's keypair
    request_hash: bytes = b""   # 32 B — auto-computed

    def __post_init__(self):
        if not self.request_hash:
            self.request_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # CHAIN_ID binding so a request can never be replayed across
        # chains that share the submitter's entity_id (e.g. a re-mint
        # of the same hot key on a fresh devnet).  Matches the
        # SubmissionReceipt pattern.
        import messagechain.consensus.witness_submission as _self_mod
        chain_id = getattr(_self_mod, "CHAIN_ID", CHAIN_ID)
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            chain_id,
            _REQUEST_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.tx_hash,
            self.target_validator_id,
            struct.pack(">Q", int(self.timestamp)),
            self.client_nonce,
            self.submitter_id,
            struct.pack(">Q", int(self.fee)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "tx_hash": self.tx_hash.hex(),
            "target_validator_id": self.target_validator_id.hex(),
            "timestamp": int(self.timestamp),
            "client_nonce": self.client_nonce.hex(),
            "submitter_id": self.submitter_id.hex(),
            "fee": int(self.fee),
            "signature": self.signature.serialize(),
            "request_hash": self.request_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.tx_hash,                              # 32
            self.target_validator_id,                  # 32
            struct.pack(">Q", int(self.timestamp)),    # 8
            self.client_nonce,                         # 16
            self.submitter_id,                         # 32
            struct.pack(">Q", int(self.fee)),          # 8
            struct.pack(">I", len(sig_blob)),          # 4
            sig_blob,
            self.request_hash,                         # 32
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SubmissionRequest":
        off = 0
        # 32+32+8+16+32+8+4+32 = 164 minimum
        if len(data) < 32 + 32 + 8 + 16 + 32 + 8 + 4 + 32:
            raise ValueError("SubmissionRequest blob too short")
        tx_hash = bytes(data[off:off + 32]); off += 32
        target = bytes(data[off:off + 32]); off += 32
        timestamp = struct.unpack_from(">Q", data, off)[0]; off += 8
        client_nonce = bytes(data[off:off + 16]); off += 16
        submitter_id = bytes(data[off:off + 32]); off += 32
        fee = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SubmissionRequest truncated at sig/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SubmissionRequest has trailing bytes")
        r = cls(
            tx_hash=tx_hash, target_validator_id=target,
            timestamp=timestamp, client_nonce=client_nonce,
            submitter_id=submitter_id, fee=fee, signature=sig,
        )
        expected = r._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SubmissionRequest hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r

    @classmethod
    def deserialize(cls, data: dict) -> "SubmissionRequest":
        r = cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            target_validator_id=bytes.fromhex(data["target_validator_id"]),
            timestamp=int(data["timestamp"]),
            client_nonce=bytes.fromhex(data["client_nonce"]),
            submitter_id=bytes.fromhex(data["submitter_id"]),
            fee=int(data["fee"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = r._compute_hash()
        declared = bytes.fromhex(data["request_hash"])
        if expected != declared:
            raise ValueError(
                f"SubmissionRequest hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r


def sign_submission_request(
    submitter,
    target_validator_id: bytes,
    tx_hash: bytes,
    timestamp: int,
    client_nonce: bytes,
    fee: int,
) -> SubmissionRequest:
    """Build a fully-signed SubmissionRequest.

    `submitter` is anything with `.entity_id` and `.keypair.sign()` —
    typically an Entity from messagechain.identity.

    The signature covers (chain_id || _REQUEST_DOMAIN_TAG || sig_version
    || every field but `signature` and `request_hash`).
    """
    if len(target_validator_id) != 32:
        raise ValueError("target_validator_id must be 32 bytes")
    if len(tx_hash) != 32:
        raise ValueError("tx_hash must be 32 bytes")
    if len(client_nonce) != 16:
        raise ValueError("client_nonce must be 16 bytes")
    if fee < MIN_FEE + WITNESS_SURCHARGE:
        raise ValueError(
            f"fee {fee} below MIN_FEE + WITNESS_SURCHARGE "
            f"({MIN_FEE + WITNESS_SURCHARGE})"
        )
    placeholder = Signature([], 0, [], b"", b"")
    r = SubmissionRequest(
        tx_hash=tx_hash,
        target_validator_id=target_validator_id,
        timestamp=int(timestamp),
        client_nonce=client_nonce,
        submitter_id=submitter.entity_id,
        fee=int(fee),
        signature=placeholder,
    )
    msg_hash = _h(r._signable_data())
    sig = submitter.keypair.sign(msg_hash)
    return SubmissionRequest(
        tx_hash=tx_hash,
        target_validator_id=target_validator_id,
        timestamp=int(timestamp),
        client_nonce=client_nonce,
        submitter_id=submitter.entity_id,
        fee=int(fee),
        signature=sig,
    )


def verify_submission_request(
    request: SubmissionRequest,
    submitter_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless verification of a SubmissionRequest.

    Checks:
      * fixed-length fields have correct sizes
      * fee meets MIN_FEE + WITNESS_SURCHARGE
      * request_hash matches _compute_hash()
      * WOTS+ signature verifies under `submitter_public_key`
    """
    if len(request.tx_hash) != 32:
        return False, "tx_hash must be 32 bytes"
    if len(request.target_validator_id) != 32:
        return False, "target_validator_id must be 32 bytes"
    if len(request.client_nonce) != 16:
        return False, "client_nonce must be 16 bytes"
    if len(request.submitter_id) != 32:
        return False, "submitter_id must be 32 bytes"
    if request.timestamp < 0:
        return False, "timestamp must be non-negative"
    if request.fee < MIN_FEE + WITNESS_SURCHARGE:
        return False, (
            f"fee {request.fee} below MIN_FEE + WITNESS_SURCHARGE "
            f"({MIN_FEE + WITNESS_SURCHARGE}) — witness surcharge required"
        )
    if len(submitter_public_key) != 32:
        return False, "submitter public key must be 32 bytes"
    expected = request._compute_hash()
    if expected != request.request_hash:
        return False, "request_hash mismatch"
    msg_hash = _h(request._signable_data())
    if not verify_signature(msg_hash, request.signature, submitter_public_key):
        return False, "invalid request signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# SubmissionAck — validator-signed.
# ─────────────────────────────────────────────────────────────────────

@dataclass
class SubmissionAck:
    """Validator-signed: 'I received and processed request_hash at
    height H, with outcome action_code'.

    Issued from the same WOTS+ subtree as `SubmissionReceipt` and
    `SignedRejection` — one root-pubkey commitment on-chain
    covers all three paths.  Witnessed-submission acks are opt-in and
    rate-limited by the client-paid surcharge, so leaf-budget impact
    is bounded.

    `action_code` is one of `ACK_ADMITTED` / `ACK_REJECTED`; bound by
    the signature so the validator cannot publish ACK_ADMITTED on the
    HTTPS path and then claim ACK_REJECTED later.
    """

    request_hash: bytes              # 32 B — binds to the SubmissionRequest
    issuer_id: bytes                 # 32 B — validator entity_id
    issuer_root_public_key: bytes    # 32 B — receipt-subtree root
    action_code: int                 # ACK_ADMITTED | ACK_REJECTED
    commit_height: int               # block height at ack time
    signature: Signature             # WOTS+ from receipt subtree
    ack_hash: bytes = b""            # 32 B — auto-computed

    def __post_init__(self):
        if not self.ack_hash:
            self.ack_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # CHAIN_ID lazily so tests can monkeypatch this module's
        # CHAIN_ID name without editing config.
        import messagechain.consensus.witness_submission as _self_mod
        chain_id = getattr(_self_mod, "CHAIN_ID", CHAIN_ID)
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            chain_id,
            _ACK_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.request_hash,
            self.issuer_id,
            self.issuer_root_public_key,
            struct.pack(">I", int(self.action_code)),
            struct.pack(">Q", int(self.commit_height)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "request_hash": self.request_hash.hex(),
            "issuer_id": self.issuer_id.hex(),
            "issuer_root_public_key": self.issuer_root_public_key.hex(),
            "action_code": int(self.action_code),
            "commit_height": int(self.commit_height),
            "signature": self.signature.serialize(),
            "ack_hash": self.ack_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.request_hash,                          # 32
            self.issuer_id,                             # 32
            self.issuer_root_public_key,                # 32
            struct.pack(">I", int(self.action_code)),   # 4
            struct.pack(">Q", int(self.commit_height)), # 8
            struct.pack(">I", len(sig_blob)),           # 4
            sig_blob,
            self.ack_hash,                              # 32
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SubmissionAck":
        off = 0
        # 32+32+32+4+8+4+32 = 144 minimum
        if len(data) < 32 + 32 + 32 + 4 + 8 + 4 + 32:
            raise ValueError("SubmissionAck blob too short")
        request_hash = bytes(data[off:off + 32]); off += 32
        issuer_id = bytes(data[off:off + 32]); off += 32
        issuer_root = bytes(data[off:off + 32]); off += 32
        action_code = struct.unpack_from(">I", data, off)[0]; off += 4
        commit_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SubmissionAck truncated at sig/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SubmissionAck has trailing bytes")
        a = cls(
            request_hash=request_hash, issuer_id=issuer_id,
            issuer_root_public_key=issuer_root,
            action_code=action_code, commit_height=commit_height,
            signature=sig,
        )
        expected = a._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SubmissionAck hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return a

    @classmethod
    def deserialize(cls, data: dict) -> "SubmissionAck":
        action_code = int(data["action_code"])
        if action_code not in _VALID_ACK_CODES:
            raise ValueError(
                f"SubmissionAck has unknown action_code {action_code}; "
                f"valid codes = {sorted(_VALID_ACK_CODES)}"
            )
        a = cls(
            request_hash=bytes.fromhex(data["request_hash"]),
            issuer_id=bytes.fromhex(data["issuer_id"]),
            issuer_root_public_key=bytes.fromhex(
                data["issuer_root_public_key"]
            ),
            action_code=action_code,
            commit_height=int(data["commit_height"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = a._compute_hash()
        declared = bytes.fromhex(data["ack_hash"])
        if expected != declared:
            raise ValueError(
                f"SubmissionAck hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return a


def verify_submission_ack(ack: SubmissionAck) -> tuple[bool, str]:
    """Stateless verification of a SubmissionAck.

    Checks:
      * fixed-length fields have correct sizes
      * action_code is one of the defined ACK_* sentinels
      * ack_hash matches _compute_hash()
      * WOTS+ signature verifies under issuer_root_public_key

    Does NOT consult chain state — slashing-path callers additionally
    check that issuer_root_public_key matches the chain's record for
    issuer_id (Blockchain.receipt_subtree_roots).
    """
    if len(ack.request_hash) != 32:
        return False, "request_hash must be 32 bytes"
    if len(ack.issuer_id) != 32:
        return False, "issuer_id must be 32 bytes"
    if len(ack.issuer_root_public_key) != 32:
        return False, "issuer_root_public_key must be 32 bytes"
    if ack.commit_height < 0:
        return False, "commit_height must be non-negative"
    if ack.action_code not in _VALID_ACK_CODES:
        return False, f"unknown action_code {ack.action_code}"
    expected = ack._compute_hash()
    if expected != ack.ack_hash:
        return False, "ack_hash mismatch"
    msg_hash = _h(ack._signable_data())
    if not verify_signature(msg_hash, ack.signature, ack.issuer_root_public_key):
        return False, "invalid ack signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# WitnessObservation — peer-signed.
# ─────────────────────────────────────────────────────────────────────

@dataclass
class WitnessObservation:
    """Peer-signed attestation: 'I (witness_id) saw the gossip for
    request_hash at height observed_height, but I never saw a
    corresponding SubmissionAck within
    WITNESS_RESPONSE_DEADLINE_BLOCKS'.

    The on-chain `NonResponseEvidenceTx` aggregates Q of these into a
    single slashable evidence.  Each witness must be in the active
    validator set at observed_height (enforced by the evidence-admission
    gate), and the same witness cannot sign two observations for the
    same request_hash (also enforced at admission).

    Witnesses sign the canonical bytes; the signature uses the
    witness's normal block-signing keypair (NOT the receipt subtree —
    witnesses might not have one configured, and observations are
    cheap enough to burn block-signing leaves).
    """

    request_hash: bytes        # 32 B — the request being attested about
    witness_id: bytes          # 32 B — entity_id of the witness
    observed_height: int       # block height at which the witness saw the gossip
    signature: Signature       # WOTS+ signature from witness's keypair
    observation_hash: bytes = b""  # 32 B — auto-computed

    def __post_init__(self):
        if not self.observation_hash:
            self.observation_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        import messagechain.consensus.witness_submission as _self_mod
        chain_id = getattr(_self_mod, "CHAIN_ID", CHAIN_ID)
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            chain_id,
            _OBSERVATION_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.request_hash,
            self.witness_id,
            struct.pack(">Q", int(self.observed_height)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "request_hash": self.request_hash.hex(),
            "witness_id": self.witness_id.hex(),
            "observed_height": int(self.observed_height),
            "signature": self.signature.serialize(),
            "observation_hash": self.observation_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.request_hash,                              # 32
            self.witness_id,                                # 32
            struct.pack(">Q", int(self.observed_height)),   # 8
            struct.pack(">I", len(sig_blob)),               # 4
            sig_blob,
            self.observation_hash,                          # 32
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "WitnessObservation":
        off = 0
        # 32+32+8+4+32 = 108 minimum
        if len(data) < 32 + 32 + 8 + 4 + 32:
            raise ValueError("WitnessObservation blob too short")
        request_hash = bytes(data[off:off + 32]); off += 32
        witness_id = bytes(data[off:off + 32]); off += 32
        observed_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("WitnessObservation truncated at sig/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len]))
        off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("WitnessObservation has trailing bytes")
        o = cls(
            request_hash=request_hash, witness_id=witness_id,
            observed_height=observed_height, signature=sig,
        )
        expected = o._compute_hash()
        if expected != declared:
            raise ValueError(
                f"WitnessObservation hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return o

    @classmethod
    def deserialize(cls, data: dict) -> "WitnessObservation":
        o = cls(
            request_hash=bytes.fromhex(data["request_hash"]),
            witness_id=bytes.fromhex(data["witness_id"]),
            observed_height=int(data["observed_height"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = o._compute_hash()
        declared = bytes.fromhex(data["observation_hash"])
        if expected != declared:
            raise ValueError(
                f"WitnessObservation hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return o


def sign_witness_observation(
    witness,
    request_hash: bytes,
    observed_height: int,
) -> WitnessObservation:
    """Build a fully-signed WitnessObservation.

    `witness` is anything with `.entity_id` and `.keypair.sign()` —
    typically an Entity from messagechain.identity.
    """
    if len(request_hash) != 32:
        raise ValueError("request_hash must be 32 bytes")
    placeholder = Signature([], 0, [], b"", b"")
    o = WitnessObservation(
        request_hash=request_hash,
        witness_id=witness.entity_id,
        observed_height=int(observed_height),
        signature=placeholder,
    )
    msg_hash = _h(o._signable_data())
    sig = witness.keypair.sign(msg_hash)
    return WitnessObservation(
        request_hash=request_hash,
        witness_id=witness.entity_id,
        observed_height=int(observed_height),
        signature=sig,
    )


def verify_witness_observation(
    obs: WitnessObservation,
    witness_public_key: bytes,
) -> tuple[bool, str]:
    """Stateless verification of a WitnessObservation.

    Checks:
      * fixed-length fields have correct sizes
      * observation_hash matches _compute_hash()
      * WOTS+ signature verifies under `witness_public_key`

    Does NOT check active-set membership — that's a chain-state
    decision and lives in the evidence-admission gate.
    """
    if len(obs.request_hash) != 32:
        return False, "request_hash must be 32 bytes"
    if len(obs.witness_id) != 32:
        return False, "witness_id must be 32 bytes"
    if obs.observed_height < 0:
        return False, "observed_height must be non-negative"
    if len(witness_public_key) != 32:
        return False, "witness public key must be 32 bytes"
    expected = obs._compute_hash()
    if expected != obs.observation_hash:
        return False, "observation_hash mismatch"
    msg_hash = _h(obs._signable_data())
    if not verify_signature(msg_hash, obs.signature, witness_public_key):
        return False, "invalid observation signature"
    return True, "Valid"


# ─────────────────────────────────────────────────────────────────────
# WitnessObservationStore — in-memory registry of observed gossip.
# ─────────────────────────────────────────────────────────────────────

class WitnessObservationStore:
    """In-memory store of observed (request_hash → observed_height) and
    discharge state (request_hash → ack_height).

    Used by witness peers to decide whether to sign a
    `WitnessObservation` at evidence-assembly time: if the store
    already records an ack at height <= observed + DEADLINE, the
    obligation was met and no observation is signed.

    Memory bound: capped to `max_entries` entries; older entries
    pruned via `prune(current_height)` when the height window has
    passed.  Per CLAUDE.md, this is ephemeral metadata — the chain
    state of record is the on-chain ack registry, not this store.

    Thread-safe via a single Lock — gossip handlers and the evidence-
    assembly path may run on different threads.
    """

    def __init__(self, max_entries: int = 10_000):
        from threading import Lock
        self._lock = Lock()
        self._observations: dict[bytes, int] = {}  # request_hash -> observed_height
        self._acks: dict[bytes, int] = {}          # request_hash -> ack_height
        self._max_entries = int(max_entries)

    def record_request(self, request_hash: bytes, observed_height: int) -> None:
        """Record that we saw `request_hash` gossiped at `observed_height`.

        First-write wins — a re-gossip of the same request keeps the
        original observation height (the binding contract is "earliest
        observation establishes the deadline").
        """
        if len(request_hash) != 32:
            raise ValueError("request_hash must be 32 bytes")
        with self._lock:
            if request_hash in self._observations:
                return
            # Memory bound: evict oldest by observed_height when full.
            if len(self._observations) >= self._max_entries:
                # Drop the oldest 1% to amortize the cost.
                drop_n = max(1, self._max_entries // 100)
                oldest = sorted(
                    self._observations.items(), key=lambda kv: kv[1],
                )[:drop_n]
                for k, _ in oldest:
                    del self._observations[k]
                    self._acks.pop(k, None)
            self._observations[request_hash] = int(observed_height)

    def record_ack(self, request_hash: bytes, ack_height: int) -> None:
        """Record that we saw an ack for `request_hash` at `ack_height`.

        First-write wins.  An ack discharges the obligation regardless
        of whether the observation has been recorded yet — a
        well-connected peer that sees the ack before the request still
        marks the request done so a later-arriving observation is
        immediately discharged.
        """
        if len(request_hash) != 32:
            raise ValueError("request_hash must be 32 bytes")
        with self._lock:
            if request_hash in self._acks:
                return
            self._acks[request_hash] = int(ack_height)

    def has_ack(self, request_hash: bytes) -> bool:
        with self._lock:
            return request_hash in self._acks

    def get_observation_height(self, request_hash: bytes) -> Optional[int]:
        with self._lock:
            return self._observations.get(request_hash)

    def get_ack_height(self, request_hash: bytes) -> Optional[int]:
        with self._lock:
            return self._acks.get(request_hash)

    def is_overdue(
        self,
        request_hash: bytes,
        current_height: int,
        deadline_blocks: int,
    ) -> bool:
        """True iff we observed the gossip and the deadline has passed
        without an ack.  Drives the witness's decision to sign an
        observation at evidence-assembly time.
        """
        with self._lock:
            obs_h = self._observations.get(request_hash)
            if obs_h is None:
                return False  # We never saw the gossip — can't attest
            if request_hash in self._acks:
                return False  # Obligation discharged
            return current_height > obs_h + int(deadline_blocks)

    def prune(self, current_height: int, retention_blocks: int) -> int:
        """Drop observations / acks older than `retention_blocks`.

        Returns the number of entries dropped.  Call periodically from
        the node's housekeeping loop.  Anything older than
        retention_blocks is past the WITNESS_RESPONSE_DEADLINE_BLOCKS
        window anyway, so evidence cannot be assembled from it.
        """
        cutoff = int(current_height) - int(retention_blocks)
        dropped = 0
        with self._lock:
            for k, h in list(self._observations.items()):
                if h < cutoff:
                    del self._observations[k]
                    dropped += 1
            for k, h in list(self._acks.items()):
                if h < cutoff:
                    del self._acks[k]
                    dropped += 1
        return dropped

    def size(self) -> tuple[int, int]:
        """(observations, acks) — for observability."""
        with self._lock:
            return (len(self._observations), len(self._acks))

    def list_acks(self) -> list[tuple[bytes, int]]:
        """Snapshot the (request_hash, ack_height) entries currently
        in the ack table.

        Returned entries are sorted by ack_height ascending so a
        block-proposer can take the OLDEST unrecorded acks first when
        deciding what to embed in `Block.acks_observed_this_block`.
        Pure read; the lock is released before returning.
        """
        with self._lock:
            entries = sorted(
                self._acks.items(), key=lambda kv: (kv[1], kv[0]),
            )
        return [(rh, h) for rh, h in entries]
