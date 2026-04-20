"""Tests for submission server's receipt issuance.

The submission server's RPC helper, `submit_transaction_to_mempool`,
must:
  * Return a signed SubmissionReceipt when a tx is accepted AND a
    `ReceiptIssuer` is configured AND the tx paid at least
    SUBMISSION_FEE.
  * NOT return a receipt when the tx is rejected (bad sig, bad nonce,
    etc.) — a receipt is a notarized attestation of custody, which we
    must never issue for a tx we refused.
  * Consume exactly ONE receipt-tree leaf per accepted submission
    (receipt-subtree leaf accounting is distinct from block-signing
    tree).
  * Issue an identical-structured receipt on idempotent re-submission
    (a network-retried /submit for a tx already in the pool still
    deserves proof-of-custody).
"""

import os
import unittest

from messagechain.config import (
    MIN_FEE, FEE_PER_BYTE, SUBMISSION_FEE,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import verify_receipt
from messagechain.network.submission_server import (
    ReceiptIssuer,
    submit_transaction_to_mempool,
)
from tests import register_entity_for_test


_TEST_FEE = MIN_FEE + 40 * FEE_PER_BYTE


class SubmissionReceiptIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-priv".ljust(32, b"\0"))
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=DynamicFeePolicy(base_fee=100, max_fee=100))
        # Dedicated receipt tree — height=4 for tests.
        self.receipt_kp = KeyPair(os.urandom(32), height=4)
        self.issuer = ReceiptIssuer(
            receipt_keypair=self.receipt_kp,
            validator_pubkey=self.alice.public_key,
        )

    def _new_tx(self, nonce=0, fee=_TEST_FEE):
        return create_transaction(self.alice, f"hi-{nonce}", fee=fee, nonce=nonce)

    def test_accepted_tx_yields_receipt(self):
        tx = self._new_tx(nonce=0)
        result = submit_transaction_to_mempool(
            tx, self.chain, self.mempool, receipt_issuer=self.issuer,
        )
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.receipt)
        self.assertEqual(result.receipt.tx_hash, tx.tx_hash)
        self.assertEqual(result.receipt.validator_pubkey, self.alice.public_key)
        self.assertEqual(result.receipt.submission_fee_paid, SUBMISSION_FEE)
        # Signature verifies against the receipt tree's root.
        self.assertTrue(verify_receipt(result.receipt, self.issuer.receipt_tree_root))

    def test_no_issuer_no_receipt(self):
        tx = self._new_tx(nonce=0)
        result = submit_transaction_to_mempool(tx, self.chain, self.mempool)
        self.assertTrue(result.ok)
        self.assertIsNone(result.receipt)

    def test_rejected_tx_no_receipt(self):
        """A tx with a bad entity_id is rejected — we never attest to rejections."""
        tx = self._new_tx(nonce=0)
        # Mutate entity_id to an unknown entity: validate_transaction must fail
        # because the entity has no registered public key.  We bypass the
        # usual tamper-evident path by building the object directly; the
        # server does not re-check tx_hash integrity (from_bytes would, but
        # we're calling the in-process helper).
        tx.entity_id = b"\xaa" * 32
        result = submit_transaction_to_mempool(
            tx, self.chain, self.mempool, receipt_issuer=self.issuer,
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.receipt)

    def test_duplicate_submission_re_issues_receipt(self):
        """An honest retry of the same tx still gets proof-of-custody."""
        tx = self._new_tx(nonce=0)
        r1 = submit_transaction_to_mempool(
            tx, self.chain, self.mempool, receipt_issuer=self.issuer,
        )
        self.assertIsNotNone(r1.receipt)
        # Re-submit the exact same tx.
        r2 = submit_transaction_to_mempool(
            tx, self.chain, self.mempool, receipt_issuer=self.issuer,
        )
        self.assertTrue(r2.ok)
        self.assertTrue(r2.duplicate)
        self.assertIsNotNone(r2.receipt)
        self.assertEqual(r2.receipt.tx_hash, tx.tx_hash)
        # Each issuance consumes a distinct receipt-tree leaf.
        self.assertNotEqual(r1.receipt.signature.leaf_index,
                            r2.receipt.signature.leaf_index)

    def test_receipt_tree_leaves_distinct_from_block_tree(self):
        """Receipt issuance must not advance the validator's block-signing tree.

        This is the core safety property: a flood of /submit requests
        must never consume the leaf budget used for block / attestation
        signing.
        """
        # Build tx first (create_transaction consumes a block-tree leaf
        # for the SENDER's signing key — not ours, since the sender here
        # IS Alice in this single-entity test, so we capture AFTER).
        tx = self._new_tx(nonce=0)
        block_leaf_before_submit = self.alice.keypair._next_leaf
        receipt_leaf_before_submit = self.receipt_kp._next_leaf
        submit_transaction_to_mempool(
            tx, self.chain, self.mempool, receipt_issuer=self.issuer,
        )
        # Block-signing tree unchanged — the submit path does NOT sign
        # with Alice's block-signing tree.  Only the receipt tree moves.
        self.assertEqual(self.alice.keypair._next_leaf, block_leaf_before_submit)
        self.assertEqual(self.receipt_kp._next_leaf, receipt_leaf_before_submit + 1)


class ReceiptIssuerValidationTest(unittest.TestCase):
    def test_rejects_bad_pubkey(self):
        kp = KeyPair(os.urandom(32), height=4)
        with self.assertRaises(ValueError):
            ReceiptIssuer(receipt_keypair=kp, validator_pubkey=b"short")

    def test_receipt_tree_root_property(self):
        kp = KeyPair(os.urandom(32), height=4)
        issuer = ReceiptIssuer(receipt_keypair=kp, validator_pubkey=b"\x11" * 32)
        self.assertEqual(issuer.receipt_tree_root, kp.public_key)


if __name__ == "__main__":
    unittest.main()
