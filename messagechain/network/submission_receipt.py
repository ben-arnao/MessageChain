"""
Attestable submission receipts.

When a validator's submission endpoint admits a tx into its mempool,
it can return a signed *receipt* committing (tx_hash, commit_height,
issuer_id).  If the tx does NOT appear on-chain within
EVIDENCE_INCLUSION_WINDOW blocks of `commit_height`, anyone holding
the receipt can submit a `CensorshipEvidenceTx` proving the validator
receipted-then-censored.  The processor at
messagechain.consensus.censorship_evidence turns matured evidence
into a stake slash (CENSORSHIP_SLASH_BPS).

Key design points:

1. **Content-neutral**: the receipt binds only (tx_hash, height,
   issuer_id).  A validator MUST issue a receipt for any tx their
   mempool accepts, regardless of content — no blocklists, no
   discretionary suppression.  The security property ("included or
   slashed") attaches to the validator, not the tx.

2. **Dedicated WOTS+ subtree**: receipt signatures come from a
   separate WOTS+ Merkle tree than block-signing, so receipt traffic
   cannot burn leaves that the proposer needs for block production.
   See config.RECEIPT_SUBTREE_HEIGHT.

3. **Self-contained verification**: verify_receipt() needs only the
   issuer's receipt-subtree root public key + the receipt bytes.  No
   chain state required — the slashing path accepts receipts from any
   subtree the chain has seen the root of.

4. **Domain-separated**: signable bytes carry the literal tag
   b"mc-submission-receipt-v1" so a receipt signature can never be
   replayed as a block or tx signature (the chain's other signing
   paths use different domain tags).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from messagechain.config import CHAIN_ID, HASH_ALGO, SIG_VERSION_CURRENT
from messagechain.crypto.keys import Signature, KeyPair, verify_signature


_DOMAIN_TAG = b"mc-submission-receipt-v1"

# Domain tag for SignedRejection.  Differs from _DOMAIN_TAG so a
# rejection signature can never be replayed as a receipt signature
# (and vice versa).  Critical: an honest validator who issues a
# rejection must not have that signature reusable to forge a "receipt"
# claiming admission, because admission triggers a different (more
# severe) chain of accountability.
_REJECTION_DOMAIN_TAG = b"mc-submission-rejection-v1"


# ─────────────────────────────────────────────────────────────────────
# Reason codes for SignedRejection.
#
# Plain int constants (NOT an Enum) so the wire format is consensus-
# stable and the encoding stays stdlib-only.  Each code maps to a
# concrete validation failure path in submit_transaction_to_mempool.
#
# Slashable subset (v1): only REJECT_INVALID_SIG is slashable today —
# bogusness is immediately provable (re-verify the embedded tx's sig
# under its on-chain pubkey).  Other codes are accepted as evidence
# but produce no slash; the framework is extensible to more codes
# without a hard fork once on-chain commitments to the validator's
# local state (mempool depth, dynamic fee floor, key revocation set)
# exist that let an external auditor refute them.
# ─────────────────────────────────────────────────────────────────────

REJECT_INVALID_SIG = 1
"""Validator claims the tx signature failed to verify."""

REJECT_INVALID_NONCE = 2
"""Validator claims the tx nonce did not match the expected next nonce."""

REJECT_FEE_TOO_LOW = 3
"""Validator claims the tx fee fell below the dynamic minimum relay fee."""

REJECT_MEMPOOL_FULL = 4
"""Validator claims the mempool is at capacity / per-sender cap reached."""

REJECT_REVOKED_KEY = 5
"""Validator claims the signer's key was revoked / entity slashed."""

REJECT_MALFORMED = 6
"""Validator claims the tx structure is invalid (size, encoding, etc.)."""

REJECT_OTHER = 99
"""Catch-all for validation failures that don't map to a specific code."""

_VALID_REASON_CODES = frozenset({
    REJECT_INVALID_SIG, REJECT_INVALID_NONCE, REJECT_FEE_TOO_LOW,
    REJECT_MEMPOOL_FULL, REJECT_REVOKED_KEY, REJECT_MALFORMED,
    REJECT_OTHER,
})


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class SubmissionReceipt:
    """A validator's commitment that they accepted `tx_hash` at height
    `commit_height`, with issuer_id `issuer_id`.

    `issuer_root_public_key` is the 32-byte root of the issuer's
    RECEIPT subtree (NOT the block-signing root).  Verification uses
    this root directly; nodes that want to trust a given issuer's
    receipts must learn this root through the chain (installed at
    validator-registration time — see Blockchain.receipt_subtree_roots).

    `signature` is a WOTS+ signature over _signable_data().
    """

    tx_hash: bytes             # 32 B — the tx that was accepted
    commit_height: int         # block height at receipt time
    issuer_id: bytes           # 32 B — validator entity_id
    issuer_root_public_key: bytes  # 32 B — receipt-subtree root
    signature: Signature       # WOTS+ sig from the receipt subtree
    receipt_hash: bytes = b""

    def __post_init__(self):
        if not self.receipt_hash:
            self.receipt_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # CHAIN_ID binding (read lazily via the module's current
        # binding so a test can monkeypatch this module's CHAIN_ID
        # name without editing config).  Pre-fix this was omitted;
        # receipts therefore verified on any chain that happened to
        # share the issuer's receipt-subtree root — a cross-chain
        # replay vector when the founder's hot key is reused across
        # re-mints (the receipt-subtree root is deterministic in the
        # private key).  Matches the MessageTransaction pattern.
        import messagechain.network.submission_receipt as _self_mod
        chain_id = getattr(_self_mod, "CHAIN_ID", CHAIN_ID)
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            chain_id,
            _DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.tx_hash,
            struct.pack(">Q", int(self.commit_height)),
            self.issuer_id,
            self.issuer_root_public_key,
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "tx_hash": self.tx_hash.hex(),
            "commit_height": self.commit_height,
            "issuer_id": self.issuer_id.hex(),
            "issuer_root_public_key": self.issuer_root_public_key.hex(),
            "signature": self.signature.serialize(),
            "receipt_hash": self.receipt_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.tx_hash,
            struct.pack(">Q", int(self.commit_height)),
            self.issuer_id,
            self.issuer_root_public_key,
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.receipt_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SubmissionReceipt":
        off = 0
        if len(data) < 32 + 8 + 32 + 32 + 4 + 32:
            raise ValueError("SubmissionReceipt blob too short")
        tx_hash = bytes(data[off:off + 32]); off += 32
        commit_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        issuer_id = bytes(data[off:off + 32]); off += 32
        issuer_root_public_key = bytes(data[off:off + 32]); off += 32
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SubmissionReceipt truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SubmissionReceipt has trailing bytes")
        r = cls(
            tx_hash=tx_hash,
            commit_height=commit_height,
            issuer_id=issuer_id,
            issuer_root_public_key=issuer_root_public_key,
            signature=sig,
        )
        expected = r._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SubmissionReceipt hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r

    @classmethod
    def deserialize(cls, data: dict) -> "SubmissionReceipt":
        r = cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            commit_height=int(data["commit_height"]),
            issuer_id=bytes.fromhex(data["issuer_id"]),
            issuer_root_public_key=bytes.fromhex(data["issuer_root_public_key"]),
            signature=Signature.deserialize(data["signature"]),
        )
        expected = r._compute_hash()
        declared = bytes.fromhex(data["receipt_hash"])
        if expected != declared:
            raise ValueError(
                f"SubmissionReceipt hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r


def verify_receipt(receipt: SubmissionReceipt) -> tuple[bool, str]:
    """Stateless verification of a submission receipt.

    Checks:
      * fixed-length fields have correct sizes
      * receipt_hash matches _compute_hash()
      * WOTS+ signature is valid under issuer_root_public_key

    Does NOT consult chain state — so a receipt is verifiable by any
    client that holds the bytes.  The slashing path additionally
    checks that issuer_root_public_key matches the on-chain record
    for issuer_id (via Blockchain.receipt_subtree_roots).
    """
    if len(receipt.tx_hash) != 32:
        return False, "tx_hash must be 32 bytes"
    if len(receipt.issuer_id) != 32:
        return False, "issuer_id must be 32 bytes"
    if len(receipt.issuer_root_public_key) != 32:
        return False, "issuer_root_public_key must be 32 bytes"
    if receipt.commit_height < 0:
        return False, "commit_height must be non-negative"
    # Recompute hash.
    expected = receipt._compute_hash()
    if expected != receipt.receipt_hash:
        return False, "receipt_hash mismatch"
    msg_hash = _h(receipt._signable_data())
    if not verify_signature(
        msg_hash, receipt.signature, receipt.issuer_root_public_key,
    ):
        return False, "invalid receipt signature"
    return True, "Valid"


@dataclass
class SignedRejection:
    """A validator's signed commitment that they REJECTED `tx_hash` for
    `reason_code` at height `commit_height`.

    Mirrors SubmissionReceipt's shape with two changes:
      * `reason_code` slot — which failure path the validator is
        claiming the tx hit (REJECT_INVALID_SIG, REJECT_INVALID_NONCE,
        ...).  Bound by the signature so an attacker cannot mutate
        the code without forging a fresh signature.
      * Domain tag is `mc-submission-rejection-v1`, NOT
        `mc-submission-receipt-v1`.  A rejection signature CANNOT be
        replayed as a receipt signature and vice versa.

    Signature comes from the SAME WOTS+ subtree as receipts (the
    validator's receipt-subtree keypair) — sharing the subtree means
    one root-pubkey commitment on-chain covers both paths.

    Why this matters: `SubmissionReceipt` only catches "admit then
    drop" censorship.  `SignedRejection` catches "answer with a lie"
    censorship — the most common nation-state pressure scenario where
    a validator is coerced to reject specific txs but keep up
    appearances of liveness.  When the rejection is provably bogus
    (re-verify the embedded tx's sig), the issuer is slashable.
    """

    tx_hash: bytes             # 32 B — the rejected tx
    commit_height: int         # block height at rejection time
    issuer_id: bytes           # 32 B — validator entity_id
    issuer_root_public_key: bytes  # 32 B — receipt-subtree root
    reason_code: int           # one of the REJECT_* constants
    signature: Signature       # WOTS+ sig from the receipt subtree
    rejection_hash: bytes = b""

    def __post_init__(self):
        if not self.rejection_hash:
            self.rejection_hash = self._compute_hash()

    def _signable_data(self) -> bytes:
        # CHAIN_ID binding — same rationale as SubmissionReceipt above.
        # Rejections are also replay-prone across chains that share
        # the validator's receipt-subtree root.
        import messagechain.network.submission_receipt as _self_mod
        chain_id = getattr(_self_mod, "CHAIN_ID", CHAIN_ID)
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
            chain_id,
            _REJECTION_DOMAIN_TAG,
            struct.pack(">B", sig_version),
            self.tx_hash,
            struct.pack(">Q", int(self.commit_height)),
            self.issuer_id,
            self.issuer_root_public_key,
            struct.pack(">I", int(self.reason_code)),
        ])

    def _compute_hash(self) -> bytes:
        return _h(self._signable_data())

    def serialize(self) -> dict:
        return {
            "tx_hash": self.tx_hash.hex(),
            "commit_height": self.commit_height,
            "issuer_id": self.issuer_id.hex(),
            "issuer_root_public_key": self.issuer_root_public_key.hex(),
            "reason_code": int(self.reason_code),
            "signature": self.signature.serialize(),
            "rejection_hash": self.rejection_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        sig_blob = self.signature.to_bytes()
        return b"".join([
            self.tx_hash,
            struct.pack(">Q", int(self.commit_height)),
            self.issuer_id,
            self.issuer_root_public_key,
            struct.pack(">I", int(self.reason_code)),
            struct.pack(">I", len(sig_blob)),
            sig_blob,
            self.rejection_hash,
        ])

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedRejection":
        off = 0
        if len(data) < 32 + 8 + 32 + 32 + 4 + 4 + 32:
            raise ValueError("SignedRejection blob too short")
        tx_hash = bytes(data[off:off + 32]); off += 32
        commit_height = struct.unpack_from(">Q", data, off)[0]; off += 8
        issuer_id = bytes(data[off:off + 32]); off += 32
        issuer_root_public_key = bytes(data[off:off + 32]); off += 32
        reason_code = struct.unpack_from(">I", data, off)[0]; off += 4
        sig_len = struct.unpack_from(">I", data, off)[0]; off += 4
        if off + sig_len + 32 > len(data):
            raise ValueError("SignedRejection truncated at signature/hash")
        sig = Signature.from_bytes(bytes(data[off:off + sig_len])); off += sig_len
        declared = bytes(data[off:off + 32]); off += 32
        if off != len(data):
            raise ValueError("SignedRejection has trailing bytes")
        r = cls(
            tx_hash=tx_hash,
            commit_height=commit_height,
            issuer_id=issuer_id,
            issuer_root_public_key=issuer_root_public_key,
            reason_code=reason_code,
            signature=sig,
        )
        expected = r._compute_hash()
        if expected != declared:
            raise ValueError(
                f"SignedRejection hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r

    @classmethod
    def deserialize(cls, data: dict) -> "SignedRejection":
        # Fail-fast on unknown reason_code so relay / indexer caches
        # can't hold a consensus-invalid rejection that verify_rejection
        # would reject downstream anyway.  Keeps the off-chain view of
        # rejection state consistent with what the slashing path will
        # eventually accept.
        reason_code = int(data["reason_code"])
        if reason_code not in _VALID_REASON_CODES:
            raise ValueError(
                f"SignedRejection has unknown reason_code {reason_code}; "
                f"valid codes = {sorted(_VALID_REASON_CODES)}"
            )
        r = cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            commit_height=int(data["commit_height"]),
            issuer_id=bytes.fromhex(data["issuer_id"]),
            issuer_root_public_key=bytes.fromhex(data["issuer_root_public_key"]),
            reason_code=reason_code,
            signature=Signature.deserialize(data["signature"]),
        )
        expected = r._compute_hash()
        declared = bytes.fromhex(data["rejection_hash"])
        if expected != declared:
            raise ValueError(
                f"SignedRejection hash mismatch: declared "
                f"{declared.hex()[:16]}, computed {expected.hex()[:16]}"
            )
        return r


def verify_rejection(rejection: SignedRejection) -> tuple[bool, str]:
    """Stateless verification of a SignedRejection.

    Checks (mirrors verify_receipt):
      * fixed-length fields have correct sizes
      * reason_code is one of the defined REJECT_* sentinels
      * rejection_hash matches _compute_hash()
      * WOTS+ signature is valid under issuer_root_public_key

    Does NOT consult chain state.  Slashing path additionally checks
    issuer_root_public_key matches the on-chain record for issuer_id.
    """
    if len(rejection.tx_hash) != 32:
        return False, "tx_hash must be 32 bytes"
    if len(rejection.issuer_id) != 32:
        return False, "issuer_id must be 32 bytes"
    if len(rejection.issuer_root_public_key) != 32:
        return False, "issuer_root_public_key must be 32 bytes"
    if rejection.commit_height < 0:
        return False, "commit_height must be non-negative"
    if rejection.reason_code not in _VALID_REASON_CODES:
        return False, f"unknown reason_code {rejection.reason_code}"
    expected = rejection._compute_hash()
    if expected != rejection.rejection_hash:
        return False, "rejection_hash mismatch"
    msg_hash = _h(rejection._signable_data())
    if not verify_signature(
        msg_hash, rejection.signature, rejection.issuer_root_public_key,
    ):
        return False, "invalid rejection signature"
    return True, "Valid"


class ReceiptIssuer:
    """Wraps a validator's receipt-subtree keypair and issues receipts.

    Callers are the submission endpoint + the local RPC submit path.
    Every accepted tx triggers exactly one issue() call.

    `subtree_keypair` MUST be a distinct KeyPair from the
    block-signing keypair.  Using the block-signing keypair would
    burn leaves needed for block production — the spec calls for a
    dedicated subtree here.  Enforcement lives in the server-side
    wiring that constructs the issuer (see server.py), not in this
    class: we cannot detect an aliased keypair from here, but any
    caller that misuses this will find their block-signing leaves
    burned by receipt traffic.
    """

    def __init__(
        self,
        issuer_id: bytes,
        subtree_keypair: KeyPair,
        height_fn=None,
    ):
        if len(issuer_id) != 32:
            raise ValueError("issuer_id must be 32 bytes")
        self.issuer_id = issuer_id
        self.subtree_keypair = subtree_keypair
        # height_fn() -> int, callable returning current chain height.
        # Injected so the issuer is testable without a live chain.
        self._height_fn = height_fn or (lambda: 0)

    @property
    def root_public_key(self) -> bytes:
        return self.subtree_keypair.public_key

    def issue(self, tx_hash: bytes) -> SubmissionReceipt:
        """Produce a signed receipt for `tx_hash` at current chain height.

        Consumes exactly one WOTS+ leaf from the receipt subtree.
        """
        if len(tx_hash) != 32:
            raise ValueError("tx_hash must be 32 bytes")
        height = int(self._height_fn())
        # Build the receipt with a placeholder signature, compute
        # _signable_data, sign it, then re-stamp the signature + hash.
        placeholder = Signature([], 0, [], b"", b"")
        r = SubmissionReceipt(
            tx_hash=tx_hash,
            commit_height=height,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            signature=placeholder,
        )
        msg_hash = _h(r._signable_data())
        sig = self.subtree_keypair.sign(msg_hash)
        # Re-instantiate with real signature so receipt_hash is
        # freshly computed.  The _signable_data is sig-agnostic
        # (signature is not part of it) so the hash is stable.
        return SubmissionReceipt(
            tx_hash=tx_hash,
            commit_height=height,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            signature=sig,
        )

    def issue_ack(
        self, request_hash: bytes, action_code: int,
    ):
        """Produce a signed SubmissionAck for `request_hash` at current
        chain height.

        Consumes exactly one WOTS+ leaf from the receipt subtree (same
        subtree as receipts and rejections).  `action_code` MUST be one
        of the defined ACK_* sentinels — unknown codes raise ValueError
        so a bug in the call site cannot land an unverifiable ack on
        the wire.

        Use case: when a validator's HTTPS submission endpoint is hit
        with the X-MC-Witnessed-Submission opt-in header, the validator
        publishes a SubmissionAck (admitted or rejected) so that
        peers who saw the witness gossip can mark the obligation
        discharged.  If the validator silently drops the request
        instead of issuing an ack, peers can submit a
        NonResponseEvidenceTx after WITNESS_RESPONSE_DEADLINE_BLOCKS
        and the validator gets slashed — closing the silent-TCP-drop
        censorship gap left by SignedRejection (which only catches
        validators who answer with a lie, not those who hang up).

        Lazy import of witness_submission to avoid a top-level cycle:
        witness_submission imports from this module's domain (signature
        primitives) but the wire types live in the consensus package.
        """
        from messagechain.consensus.witness_submission import (
            SubmissionAck, _VALID_ACK_CODES,
        )
        if len(request_hash) != 32:
            raise ValueError("request_hash must be 32 bytes")
        if action_code not in _VALID_ACK_CODES:
            raise ValueError(
                f"unknown SubmissionAck action_code {action_code}; "
                f"must be one of {sorted(_VALID_ACK_CODES)}"
            )
        height = int(self._height_fn())
        placeholder = Signature([], 0, [], b"", b"")
        a = SubmissionAck(
            request_hash=request_hash,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            action_code=action_code,
            commit_height=height,
            signature=placeholder,
        )
        msg_hash = _h(a._signable_data())
        sig = self.subtree_keypair.sign(msg_hash)
        return SubmissionAck(
            request_hash=request_hash,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            action_code=action_code,
            commit_height=height,
            signature=sig,
        )

    def issue_rejection(
        self, tx_hash: bytes, reason_code: int,
    ) -> SignedRejection:
        """Produce a signed REJECTION for `tx_hash` at current chain height.

        Consumes exactly one WOTS+ leaf from the receipt subtree (same
        subtree as receipts).  reason_code MUST be one of the defined
        REJECT_* sentinels — unknown codes raise ValueError so a bug in
        the call site cannot land an unverifiable rejection on the wire.

        Use case: when a validator's HTTPS submission endpoint returns
        a rejection, an opt-in client can request a SignedRejection
        binding the validator to that reason.  If the rejection is
        provably bogus (e.g., REJECT_INVALID_SIG against a tx whose
        signature actually verifies), the validator is slashable via
        BogusRejectionEvidenceTx — closing the receipt-less censorship
        gap where a coerced validator answers honest submissions with
        a lie.
        """
        if len(tx_hash) != 32:
            raise ValueError("tx_hash must be 32 bytes")
        if reason_code not in _VALID_REASON_CODES:
            raise ValueError(
                f"unknown rejection reason_code {reason_code}; "
                f"must be one of {sorted(_VALID_REASON_CODES)}"
            )
        height = int(self._height_fn())
        placeholder = Signature([], 0, [], b"", b"")
        r = SignedRejection(
            tx_hash=tx_hash,
            commit_height=height,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            reason_code=reason_code,
            signature=placeholder,
        )
        msg_hash = _h(r._signable_data())
        sig = self.subtree_keypair.sign(msg_hash)
        return SignedRejection(
            tx_hash=tx_hash,
            commit_height=height,
            issuer_id=self.issuer_id,
            issuer_root_public_key=self.subtree_keypair.public_key,
            reason_code=reason_code,
            signature=sig,
        )
