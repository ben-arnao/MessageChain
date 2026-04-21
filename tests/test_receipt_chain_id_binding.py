"""Receipt and rejection signatures bind CHAIN_ID (HIGH hardening).

Pre-fix gap: `SubmissionReceipt._signable_data` and
`SignedRejection._signable_data` omitted CHAIN_ID.  MessageTransaction
and other tx types bind CHAIN_ID (see transaction.py:70-82).  Receipts
did not.

Exploit class: a receipt captured on chain X (e.g., the pre-reset
mainnet, any testnet that ran with the same hot key, a future re-mint)
replays onto chain Y if (1) the issuer has the same entity_id, and
(2) the issuer's receipt-subtree root matches.  Both are true when the
founder's hot key is reused across re-mints — the receipt-subtree
keypair is deterministic in (private_key, RECEIPT_SUBTREE_HEIGHT).  The
replayed receipt verifies under the current chain's copy of the
issuer_root_public_key, and `CensorshipEvidenceTx` binding it becomes
a slashable accusation against the validator on the wrong chain.

Fix: prepend CHAIN_ID to both receipt types' _signable_data.  A
receipt signed under CHAIN_ID_A cannot be verified under CHAIN_ID_B
because the msg_hash differs and WOTS+ verify fails.

Secondary: SignedRejection.deserialize now rejects unknown reason_code
eagerly (mirrors verify_rejection's check at deserialization time so
relays and indexers can't cache invalid rejections).
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import messagechain.config as cfg
from messagechain.crypto.keys import KeyPair
from messagechain.network.submission_receipt import (
    SubmissionReceipt,
    SignedRejection,
    ReceiptIssuer,
    REJECT_INVALID_SIG,
    verify_receipt,
    verify_rejection,
)


def _make_issuer(tag: bytes = b"chainid-test", tree_height: int = 4):
    """Small-tree issuer for fast tests.  tag differentiates keypairs
    across tests so none of them share WOTS+ leaves."""
    kp = KeyPair.generate(seed=b"receipt-subtree-" + tag, height=tree_height)
    entity_id = b"\xaa" * 32
    issuer = ReceiptIssuer(
        issuer_id=entity_id,
        subtree_keypair=kp,
        height_fn=lambda: 10,
    )
    return kp, issuer, entity_id


class TestReceiptChainIdBinding(unittest.TestCase):
    """A receipt produced under CHAIN_ID A does not verify as a valid
    receipt under CHAIN_ID B — signature binds the chain."""

    def test_receipt_signable_data_starts_with_chain_id(self):
        _, issuer, _ = _make_issuer(b"signable-start")
        r = issuer.issue(tx_hash=b"\x01" * 32)
        self.assertTrue(
            r._signable_data().startswith(cfg.CHAIN_ID),
            "SubmissionReceipt._signable_data must start with CHAIN_ID "
            "so cross-chain replay fails signature verification.",
        )

    def test_receipt_signed_on_chain_a_fails_on_chain_b(self):
        """The load-bearing test: a receipt's signature was produced
        against _signable_data that includes CHAIN_ID.  If we flip the
        ambient CHAIN_ID without changing the receipt, verify_receipt
        must fail — this is what stops a cross-chain replay."""
        original_chain_id = cfg.CHAIN_ID
        _, issuer, _ = _make_issuer(b"cross-chain-a")
        r = issuer.issue(tx_hash=b"\x02" * 32)
        # Sanity: it verifies on its own chain.
        ok, _ = verify_receipt(r)
        self.assertTrue(ok, "self-chain verify baseline")

        # Flip the chain_id and re-verify.  This simulates "receipt
        # from chain A arrives at a node running chain B."
        with patch.object(cfg, "CHAIN_ID", b"messagechain-OTHER"):
            # Also patch the re-imported name in the receipt module.
            import messagechain.network.submission_receipt as sr
            with patch.object(sr, "CHAIN_ID", b"messagechain-OTHER"):
                ok, reason = verify_receipt(r)
                self.assertFalse(
                    ok,
                    "cross-chain replay must fail signature verification; "
                    "got OK which means CHAIN_ID is not in the signed data.",
                )


class TestRejectionChainIdBinding(unittest.TestCase):

    def test_rejection_signable_data_starts_with_chain_id(self):
        _, issuer, _ = _make_issuer(b"rej-signable")
        r = issuer.issue_rejection(
            tx_hash=b"\x03" * 32,
            reason_code=REJECT_INVALID_SIG,
        )
        self.assertTrue(
            r._signable_data().startswith(cfg.CHAIN_ID),
            "SignedRejection._signable_data must start with CHAIN_ID.",
        )

    def test_rejection_signed_on_chain_a_fails_on_chain_b(self):
        _, issuer, _ = _make_issuer(b"rej-cross")
        r = issuer.issue_rejection(
            tx_hash=b"\x04" * 32,
            reason_code=REJECT_INVALID_SIG,
        )
        ok, _ = verify_rejection(r)
        self.assertTrue(ok, "self-chain verify baseline")

        with patch.object(cfg, "CHAIN_ID", b"messagechain-OTHER"):
            import messagechain.network.submission_receipt as sr
            with patch.object(sr, "CHAIN_ID", b"messagechain-OTHER"):
                ok, reason = verify_rejection(r)
                self.assertFalse(ok, "cross-chain replay must fail")


class TestRejectionDeserializeValidatesReasonCode(unittest.TestCase):
    """SignedRejection.deserialize must reject unknown reason_code at
    deserialization time, not silently accept and defer to
    verify_rejection.  Fail-fast keeps relay/indexer caches from
    storing consensus-invalid evidence that would never slash anyway."""

    def test_deserialize_rejects_unknown_reason_code(self):
        _, issuer, _ = _make_issuer(b"deser-bad-reason")
        good = issuer.issue_rejection(
            tx_hash=b"\x05" * 32,
            reason_code=REJECT_INVALID_SIG,
        )
        wire = good.serialize()
        # Tamper reason_code to an unknown sentinel.  Since we also
        # need rejection_hash to match, compute it ourselves using the
        # same _compute_hash path with the tampered value — mimic what
        # a malicious constructor would do to pass the current
        # hash-check.
        tampered = dict(wire)
        tampered["reason_code"] = 0xDEADBEEF
        # Recompute the hash that the tampered object WOULD produce so
        # the existing hash-mismatch guard doesn't trip before the
        # reason_code guard does.
        bogus = SignedRejection(
            tx_hash=good.tx_hash,
            commit_height=good.commit_height,
            issuer_id=good.issuer_id,
            issuer_root_public_key=good.issuer_root_public_key,
            reason_code=0xDEADBEEF,
            signature=good.signature,
        )
        tampered["rejection_hash"] = bogus.rejection_hash.hex()

        with self.assertRaises(ValueError) as cm:
            SignedRejection.deserialize(tampered)
        self.assertIn("reason_code", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
