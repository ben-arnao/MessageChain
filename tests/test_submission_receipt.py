"""Tests for attestable submission receipts — format, sign, verify.

Covers:
  * Sign/verify round-trip under WOTS+ (using a dedicated receipt tree).
  * Binary and dict serialization round-trip.
  * Forged receipts (bad signature / mutated fields) are rejected.
  * Receipt-tree WOTS+ leaves are distinct from block-signing-tree
    leaves — a receipt signed with leaf i of the receipt tree must
    NOT verify against the block-signing tree's root, and the two
    trees are sized independently.

These are the bedrock tests for censorship_evidence and the
submission_server path; downstream tests assume the primitives here
behave as spec'd.
"""

import hashlib
import os
import unittest

from messagechain.config import (
    HASH_ALGO,
    MERKLE_TREE_HEIGHT,
    RECEIPT_VERSION,
    SUBMISSION_FEE,
)
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.network.submission_receipt import (
    SubmissionReceipt,
    build_receipt_signable,
    sign_receipt,
    verify_receipt,
)


def _fake_tx_hash(nonce: int = 0) -> bytes:
    return hashlib.new(HASH_ALGO, b"tx-" + str(nonce).encode()).digest()


def _fake_pubkey(tag: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b"pubkey-" + tag).digest()


class SignableFormTest(unittest.TestCase):
    """build_receipt_signable is deterministic and domain-separated."""

    def test_deterministic(self):
        tx_hash = _fake_tx_hash(1)
        pubkey = _fake_pubkey(b"v1")
        a = build_receipt_signable(tx_hash, pubkey, 100, SUBMISSION_FEE)
        b = build_receipt_signable(tx_hash, pubkey, 100, SUBMISSION_FEE)
        self.assertEqual(a, b)

    def test_field_mutation_changes_bytes(self):
        tx_hash = _fake_tx_hash(2)
        pubkey = _fake_pubkey(b"v2")
        base = build_receipt_signable(tx_hash, pubkey, 100, SUBMISSION_FEE)
        other_tx = build_receipt_signable(_fake_tx_hash(999), pubkey, 100, SUBMISSION_FEE)
        other_pk = build_receipt_signable(tx_hash, _fake_pubkey(b"other"), 100, SUBMISSION_FEE)
        other_h = build_receipt_signable(tx_hash, pubkey, 101, SUBMISSION_FEE)
        other_f = build_receipt_signable(tx_hash, pubkey, 100, SUBMISSION_FEE + 1)
        self.assertNotEqual(base, other_tx)
        self.assertNotEqual(base, other_pk)
        self.assertNotEqual(base, other_h)
        self.assertNotEqual(base, other_f)

    def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            build_receipt_signable(b"short", _fake_pubkey(b"x"), 0, 0)
        with self.assertRaises(ValueError):
            build_receipt_signable(_fake_tx_hash(), b"x" * 31, 0, 0)
        with self.assertRaises(ValueError):
            build_receipt_signable(_fake_tx_hash(), _fake_pubkey(b"x"), -1, 0)
        with self.assertRaises(ValueError):
            build_receipt_signable(_fake_tx_hash(), _fake_pubkey(b"x"), 0, -1)


class SignVerifyRoundtripTest(unittest.TestCase):
    """Receipt signed with a KeyPair verifies against that keypair's root."""

    def setUp(self):
        # Dedicated receipt tree (small for fast tests).  In production
        # the tree is RECEIPT_MERKLE_TREE_HEIGHT = 24 leaves deep.
        self.receipt_seed = os.urandom(32)
        self.receipt_kp = KeyPair(self.receipt_seed, height=4)
        # Separate block-signing tree — different seed, different root.
        self.block_seed = os.urandom(32)
        self.block_kp = KeyPair(self.block_seed, height=MERKLE_TREE_HEIGHT)
        # The validator's on-chain identity is the BLOCK-signing tree root.
        self.validator_pubkey = self.block_kp.public_key

    def test_roundtrip(self):
        tx_hash = _fake_tx_hash(42)
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=tx_hash,
            validator_pubkey=self.validator_pubkey,
            received_at_height=123,
            submission_fee_paid=SUBMISSION_FEE,
        )
        # Verifies against the receipt-tree root (NOT the validator pubkey).
        self.assertTrue(verify_receipt(receipt, self.receipt_kp.public_key))

    def test_mutated_tx_hash_fails(self):
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=_fake_tx_hash(1),
            validator_pubkey=self.validator_pubkey,
            received_at_height=1,
            submission_fee_paid=SUBMISSION_FEE,
        )
        # Tamper: replace tx_hash after signing.
        bad = SubmissionReceipt(
            tx_hash=_fake_tx_hash(99),
            validator_pubkey=receipt.validator_pubkey,
            received_at_height=receipt.received_at_height,
            submission_fee_paid=receipt.submission_fee_paid,
            signature=receipt.signature,
            version=receipt.version,
        )
        self.assertFalse(verify_receipt(bad, self.receipt_kp.public_key))

    def test_mutated_height_fails(self):
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=_fake_tx_hash(2),
            validator_pubkey=self.validator_pubkey,
            received_at_height=5,
            submission_fee_paid=SUBMISSION_FEE,
        )
        bad = SubmissionReceipt(
            tx_hash=receipt.tx_hash,
            validator_pubkey=receipt.validator_pubkey,
            received_at_height=9999,
            submission_fee_paid=receipt.submission_fee_paid,
            signature=receipt.signature,
            version=receipt.version,
        )
        self.assertFalse(verify_receipt(bad, self.receipt_kp.public_key))

    def test_mutated_fee_fails(self):
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=_fake_tx_hash(3),
            validator_pubkey=self.validator_pubkey,
            received_at_height=10,
            submission_fee_paid=SUBMISSION_FEE,
        )
        bad = SubmissionReceipt(
            tx_hash=receipt.tx_hash,
            validator_pubkey=receipt.validator_pubkey,
            received_at_height=receipt.received_at_height,
            submission_fee_paid=SUBMISSION_FEE * 10,
            signature=receipt.signature,
            version=receipt.version,
        )
        self.assertFalse(verify_receipt(bad, self.receipt_kp.public_key))

    def test_wrong_root_fails(self):
        """Receipt from tree A must NOT verify against tree B's root."""
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=_fake_tx_hash(4),
            validator_pubkey=self.validator_pubkey,
            received_at_height=10,
            submission_fee_paid=SUBMISSION_FEE,
        )
        # Block-signing tree root != receipt tree root; verify must fail.
        self.assertFalse(verify_receipt(receipt, self.block_kp.public_key))

    def test_non_receipt_input_rejected(self):
        self.assertFalse(verify_receipt(None, self.receipt_kp.public_key))
        self.assertFalse(verify_receipt("not a receipt", self.receipt_kp.public_key))

    def test_short_root_rejected(self):
        receipt = sign_receipt(
            keypair=self.receipt_kp,
            tx_hash=_fake_tx_hash(5),
            validator_pubkey=self.validator_pubkey,
            received_at_height=10,
            submission_fee_paid=SUBMISSION_FEE,
        )
        self.assertFalse(verify_receipt(receipt, b"\x00" * 31))
        self.assertFalse(verify_receipt(receipt, None))


class SerializationRoundtripTest(unittest.TestCase):
    """Dict and binary forms survive round-trip unchanged."""

    def setUp(self):
        self.kp = KeyPair(os.urandom(32), height=4)
        self.validator_pubkey = _fake_pubkey(b"vpub")
        self.receipt = sign_receipt(
            keypair=self.kp,
            tx_hash=_fake_tx_hash(7),
            validator_pubkey=self.validator_pubkey,
            received_at_height=42,
            submission_fee_paid=SUBMISSION_FEE,
        )

    def test_dict_roundtrip(self):
        raw = self.receipt.serialize()
        rebuilt = SubmissionReceipt.deserialize(raw)
        self.assertEqual(rebuilt.tx_hash, self.receipt.tx_hash)
        self.assertEqual(rebuilt.validator_pubkey, self.receipt.validator_pubkey)
        self.assertEqual(rebuilt.received_at_height, self.receipt.received_at_height)
        self.assertEqual(rebuilt.submission_fee_paid, self.receipt.submission_fee_paid)
        self.assertEqual(rebuilt.version, self.receipt.version)
        # Signature round-trip preserves verifiability.
        self.assertTrue(verify_receipt(rebuilt, self.kp.public_key))

    def test_binary_roundtrip(self):
        blob = self.receipt.to_bytes()
        rebuilt = SubmissionReceipt.from_bytes(blob)
        self.assertEqual(rebuilt.tx_hash, self.receipt.tx_hash)
        self.assertEqual(rebuilt.received_at_height, self.receipt.received_at_height)
        self.assertTrue(verify_receipt(rebuilt, self.kp.public_key))

    def test_binary_truncation_rejected(self):
        blob = self.receipt.to_bytes()
        with self.assertRaises(ValueError):
            SubmissionReceipt.from_bytes(blob[:20])
        with self.assertRaises(ValueError):
            SubmissionReceipt.from_bytes(blob[:-1])  # one byte short of sig
        with self.assertRaises(ValueError):
            SubmissionReceipt.from_bytes(blob + b"X")  # trailing byte


class LeafSeparationTest(unittest.TestCase):
    """The receipt-signing tree does not share leaves with block-signing.

    This is the core safety property from the spec: receipt signing
    must NEVER consume a leaf from the block-signing tree, because
    that would brick consensus participation.
    """

    def test_receipt_leaf_advances_only_receipt_tree(self):
        receipt_kp = KeyPair(os.urandom(32), height=4)
        block_kp = KeyPair(os.urandom(32), height=4)

        initial_block_next = block_kp._next_leaf
        initial_receipt_next = receipt_kp._next_leaf

        sign_receipt(
            keypair=receipt_kp,
            tx_hash=_fake_tx_hash(1),
            validator_pubkey=block_kp.public_key,
            received_at_height=1,
            submission_fee_paid=SUBMISSION_FEE,
        )

        self.assertEqual(block_kp._next_leaf, initial_block_next)
        self.assertEqual(receipt_kp._next_leaf, initial_receipt_next + 1)

    def test_two_receipts_consume_two_receipt_leaves(self):
        receipt_kp = KeyPair(os.urandom(32), height=4)
        validator_pk = _fake_pubkey(b"v")
        r1 = sign_receipt(
            keypair=receipt_kp,
            tx_hash=_fake_tx_hash(1),
            validator_pubkey=validator_pk,
            received_at_height=1,
            submission_fee_paid=SUBMISSION_FEE,
        )
        r2 = sign_receipt(
            keypair=receipt_kp,
            tx_hash=_fake_tx_hash(2),
            validator_pubkey=validator_pk,
            received_at_height=2,
            submission_fee_paid=SUBMISSION_FEE,
        )
        # Distinct leaves.
        self.assertNotEqual(r1.signature.leaf_index, r2.signature.leaf_index)
        # Both verify.
        self.assertTrue(verify_receipt(r1, receipt_kp.public_key))
        self.assertTrue(verify_receipt(r2, receipt_kp.public_key))


class VersionTest(unittest.TestCase):
    def test_current_version(self):
        self.assertEqual(RECEIPT_VERSION, 1)

    def test_unknown_version_rejected_in_signable(self):
        with self.assertRaises(ValueError):
            build_receipt_signable(
                _fake_tx_hash(), _fake_pubkey(b"v"),
                0, 0, version=99,
            )


if __name__ == "__main__":
    unittest.main()
