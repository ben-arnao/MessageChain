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

from messagechain.config import HASH_ALGO, SIG_VERSION_CURRENT
from messagechain.crypto.keys import Signature, KeyPair, verify_signature


_DOMAIN_TAG = b"mc-submission-receipt-v1"


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
        sig_version = getattr(self.signature, "sig_version", SIG_VERSION_CURRENT)
        return b"".join([
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
