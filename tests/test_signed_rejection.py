"""Tests for SignedRejection — validators' attestable rejection of a tx.

A coerced validator that responds to a public submission with a bogus
rejection reason becomes slashable evidence: the rejection is
domain-tag-separated from a SubmissionReceipt so the two cannot be
cross-replayed, and the signature comes from the SAME WOTS+ subtree
the validator uses for receipts.

These tests exercise:
  * round-trip serialize/deserialize (dict + binary)
  * verify_rejection accepts honest signatures, rejects tampered fields
  * domain-tag separation: receipt and rejection over identical fields
    produce DIFFERENT signatures
  * ReceiptIssuer.issue_rejection consumes a fresh leaf each call
  * issue_rejection rejects unknown reason_codes
"""

import hashlib
import unittest

from messagechain.config import HASH_ALGO
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair
from messagechain.network.submission_receipt import (
    ReceiptIssuer,
    SubmissionReceipt,
    SignedRejection,
    verify_rejection,
    REJECT_INVALID_SIG,
    REJECT_INVALID_NONCE,
    REJECT_FEE_TOO_LOW,
    REJECT_MEMPOOL_FULL,
    REJECT_REVOKED_KEY,
    REJECT_MALFORMED,
    REJECT_OTHER,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    """Dedicated WOTS+ subtree keypair for receipt + rejection signing."""
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


class TestSignedRejectionBasics(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-rej".ljust(32, b"\x00"))

    def test_issue_rejection_signs_and_verifies(self):
        kp = _make_receipt_subtree_keypair(b"rej-basic")
        issuer = ReceiptIssuer(
            issuer_id=self.alice.entity_id,
            subtree_keypair=kp,
            height_fn=lambda: 17,
        )
        tx_hash = _h(b"some tx")
        rej = issuer.issue_rejection(tx_hash, REJECT_INVALID_SIG)
        self.assertEqual(rej.tx_hash, tx_hash)
        self.assertEqual(rej.commit_height, 17)
        self.assertEqual(rej.issuer_id, self.alice.entity_id)
        self.assertEqual(rej.issuer_root_public_key, kp.public_key)
        self.assertEqual(rej.reason_code, REJECT_INVALID_SIG)
        ok, reason = verify_rejection(rej)
        self.assertTrue(ok, reason)

    def test_rejection_dict_roundtrip(self):
        kp = _make_receipt_subtree_keypair(b"rej-dict")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        rej = issuer.issue_rejection(_h(b"tx"), REJECT_INVALID_NONCE)
        decoded = SignedRejection.deserialize(rej.serialize())
        self.assertEqual(decoded.tx_hash, rej.tx_hash)
        self.assertEqual(decoded.reason_code, rej.reason_code)
        self.assertEqual(decoded.rejection_hash, rej.rejection_hash)
        ok, reason = verify_rejection(decoded)
        self.assertTrue(ok, reason)

    def test_rejection_binary_roundtrip(self):
        kp = _make_receipt_subtree_keypair(b"rej-bin")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        rej = issuer.issue_rejection(_h(b"tx"), REJECT_FEE_TOO_LOW)
        blob = rej.to_bytes()
        decoded = SignedRejection.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, rej.tx_hash)
        self.assertEqual(decoded.commit_height, rej.commit_height)
        self.assertEqual(decoded.reason_code, rej.reason_code)
        self.assertEqual(decoded.rejection_hash, rej.rejection_hash)
        ok, reason = verify_rejection(decoded)
        self.assertTrue(ok, reason)

    def test_tampering_tx_hash_detected(self):
        kp = _make_receipt_subtree_keypair(b"rej-tamp")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        rej = issuer.issue_rejection(_h(b"tx"), REJECT_MALFORMED)
        tampered = SignedRejection(
            tx_hash=_h(b"different tx"),
            commit_height=rej.commit_height,
            issuer_id=rej.issuer_id,
            issuer_root_public_key=rej.issuer_root_public_key,
            reason_code=rej.reason_code,
            signature=rej.signature,
            rejection_hash=rej.rejection_hash,  # stale
        )
        ok, _ = verify_rejection(tampered)
        self.assertFalse(ok)

    def test_tampering_reason_code_detected(self):
        kp = _make_receipt_subtree_keypair(b"rej-rcode")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        rej = issuer.issue_rejection(_h(b"tx"), REJECT_INVALID_SIG)
        # Mutate reason_code post-signing.  The signature was made over
        # REJECT_INVALID_SIG; flipping to REJECT_OTHER must produce
        # both a hash mismatch and a signature mismatch.
        tampered = SignedRejection(
            tx_hash=rej.tx_hash,
            commit_height=rej.commit_height,
            issuer_id=rej.issuer_id,
            issuer_root_public_key=rej.issuer_root_public_key,
            reason_code=REJECT_OTHER,
            signature=rej.signature,
            rejection_hash=rej.rejection_hash,  # stale wrt new reason
        )
        ok, _ = verify_rejection(tampered)
        self.assertFalse(ok)

    def test_domain_tag_separation_from_receipt(self):
        """A rejection over the SAME tx_hash + issuer + height + root
        must NOT verify as a SubmissionReceipt (different domain tag)
        and vice versa.  Otherwise an attacker could forge a fake
        receipt out of an honest rejection (or vice versa)."""
        kp = _make_receipt_subtree_keypair(b"rej-domain")
        issuer = ReceiptIssuer(
            self.alice.entity_id, kp, height_fn=lambda: 100,
        )
        tx_hash = _h(b"shared tx hash")
        receipt = issuer.issue(tx_hash)
        rej = issuer.issue_rejection(tx_hash, REJECT_INVALID_SIG)

        # Both signatures verify under their own domain tag.
        from messagechain.network.submission_receipt import verify_receipt
        ok_r, _ = verify_receipt(receipt)
        self.assertTrue(ok_r)
        ok_j, _ = verify_rejection(rej)
        self.assertTrue(ok_j)

        # Cross: try to forge a SubmissionReceipt that reuses the
        # rejection's signature.  The receipt's _signable_data uses the
        # receipt domain tag and OMITS reason_code, so the WOTS+
        # signature over the rejection's signable_data cannot satisfy it.
        forged = SubmissionReceipt(
            tx_hash=tx_hash,
            commit_height=rej.commit_height,
            issuer_id=rej.issuer_id,
            issuer_root_public_key=rej.issuer_root_public_key,
            signature=rej.signature,
        )
        ok_forge, _ = verify_receipt(forged)
        self.assertFalse(
            ok_forge,
            "rejection signature must not satisfy the receipt domain",
        )

        # Conversely: a SignedRejection that reuses the receipt's
        # signature must not verify.
        forged_rej = SignedRejection(
            tx_hash=tx_hash,
            commit_height=receipt.commit_height,
            issuer_id=receipt.issuer_id,
            issuer_root_public_key=receipt.issuer_root_public_key,
            reason_code=REJECT_INVALID_SIG,
            signature=receipt.signature,
        )
        ok_forge_r, _ = verify_rejection(forged_rej)
        self.assertFalse(
            ok_forge_r,
            "receipt signature must not satisfy the rejection domain",
        )

    def test_issue_rejection_consumes_fresh_leaf_each_call(self):
        kp = _make_receipt_subtree_keypair(b"rej-leaves")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        before = kp._next_leaf
        issuer.issue_rejection(_h(b"a"), REJECT_INVALID_SIG)
        issuer.issue_rejection(_h(b"b"), REJECT_MEMPOOL_FULL)
        issuer.issue_rejection(_h(b"c"), REJECT_REVOKED_KEY)
        self.assertEqual(kp._next_leaf, before + 3)

    def test_issue_rejection_rejects_unknown_reason(self):
        kp = _make_receipt_subtree_keypair(b"rej-unk")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        with self.assertRaises(ValueError):
            issuer.issue_rejection(_h(b"x"), 0)
        with self.assertRaises(ValueError):
            issuer.issue_rejection(_h(b"x"), 7)
        with self.assertRaises(ValueError):
            issuer.issue_rejection(_h(b"x"), 100)
        # The valid sentinels all work.
        for rc in (
            REJECT_INVALID_SIG, REJECT_INVALID_NONCE, REJECT_FEE_TOO_LOW,
            REJECT_MEMPOOL_FULL, REJECT_REVOKED_KEY, REJECT_MALFORMED,
            REJECT_OTHER,
        ):
            issuer.issue_rejection(_h(b"x" + bytes([rc])), rc)

    def test_issue_rejection_validates_tx_hash_length(self):
        kp = _make_receipt_subtree_keypair(b"rej-len")
        issuer = ReceiptIssuer(self.alice.entity_id, kp)
        with self.assertRaises(ValueError):
            issuer.issue_rejection(b"too short", REJECT_INVALID_SIG)


if __name__ == "__main__":
    unittest.main()
