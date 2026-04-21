"""Tests for BogusRejectionEvidenceTx + BogusRejectionProcessor.

Closes the receipt-less censorship gap: a coerced validator that
answers a public submission with a bogus rejection becomes slashable.

Pipeline (one-phase, unlike CensorshipEvidenceTx — bogusness is
immediately provable):
  1. Validator issues a SignedRejection claiming reason X.
  2. Anyone files BogusRejectionEvidenceTx carrying (rejection,
     message_tx).
  3. Processor checks: for v1, only REJECT_INVALID_SIG is slashable.
     If the message_tx's signature actually verifies under its
     on-chain pubkey, the rejection is bogus → slash the issuer
     CENSORSHIP_SLASH_BPS.  If the signature actually fails, the
     rejection was honest → reject the evidence_tx.
  4. processed set prevents double-slash.

Other reason_codes are accepted into the chain as evidence (the
tx pays a fee + gets recorded) but produce no slash — leaves the
framework extensible without a hard fork.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import HASH_ALGO, MIN_FEE, CENSORSHIP_SLASH_BPS
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import (
    create_transaction, MessageTransaction,
)
from messagechain.network.submission_receipt import (
    ReceiptIssuer, SignedRejection,
    REJECT_INVALID_SIG, REJECT_INVALID_NONCE,
    REJECT_FEE_TOO_LOW, REJECT_OTHER,
)
from messagechain.consensus.bogus_rejection_evidence import (
    BogusRejectionEvidenceTx,
    BogusRejectionProcessor,
    verify_bogus_rejection_evidence_tx,
)
from messagechain.consensus.censorship_evidence import compute_slash_amount


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


def _sign_evidence(
    submitter: Entity,
    rejection: SignedRejection,
    message_tx: MessageTransaction,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> BogusRejectionEvidenceTx:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = BogusRejectionEvidenceTx(
        rejection=rejection,
        message_tx=message_tx,
        submitter_id=submitter.entity_id,
        timestamp=ts,
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


class TestBogusRejectionEvidenceTxSerialization(unittest.TestCase):

    def test_dict_roundtrip(self):
        alice = Entity.create(b"alice-bres".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-bres".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"bres-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hello", MIN_FEE + 100, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)

        etx = _sign_evidence(bob, rej, mtx, fee=MIN_FEE)
        round_tripped = BogusRejectionEvidenceTx.deserialize(etx.serialize())
        self.assertEqual(round_tripped.tx_hash, etx.tx_hash)
        self.assertEqual(round_tripped.evidence_hash, etx.evidence_hash)

    def test_binary_roundtrip(self):
        alice = Entity.create(b"alice-brbin".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-brbin".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"brbin-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_NONCE)

        etx = _sign_evidence(bob, rej, mtx, fee=MIN_FEE)
        blob = etx.to_bytes()
        decoded = BogusRejectionEvidenceTx.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertEqual(decoded.evidence_hash, etx.evidence_hash)
        self.assertEqual(decoded.rejection.reason_code, REJECT_INVALID_NONCE)


class TestBogusRejectionEvidenceTxVerify(unittest.TestCase):

    def test_verify_accepts_valid_evidence(self):
        alice = Entity.create(b"alice-vok".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-vok".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"vok-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hi", MIN_FEE + 100, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)
        etx = _sign_evidence(bob, rej, mtx, fee=MIN_FEE)

        ok, reason = verify_bogus_rejection_evidence_tx(etx, bob.public_key)
        self.assertTrue(ok, reason)

    def test_verify_rejects_mismatched_tx_hash(self):
        """rejection.tx_hash must equal message_tx.tx_hash — otherwise the
        evidence isn't actually evidence about that tx."""
        alice = Entity.create(b"alice-mm".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-mm".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"mm-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "real", MIN_FEE + 100, nonce=0)
        # Issue a rejection over a DIFFERENT tx_hash.
        rej = issuer.issue_rejection(_h(b"unrelated"), REJECT_INVALID_SIG)
        etx = _sign_evidence(bob, rej, mtx, fee=MIN_FEE)

        ok, reason = verify_bogus_rejection_evidence_tx(etx, bob.public_key)
        self.assertFalse(ok)
        self.assertIn("tx_hash", reason.lower())

    def test_verify_rejects_underfee(self):
        alice = Entity.create(b"alice-fee".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-fee".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"fee-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hi", MIN_FEE + 100, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)
        etx = _sign_evidence(bob, rej, mtx, fee=1)

        ok, reason = verify_bogus_rejection_evidence_tx(etx, bob.public_key)
        self.assertFalse(ok)
        self.assertIn("fee", reason.lower())

    def test_verify_rejects_bad_submitter_sig(self):
        alice = Entity.create(b"alice-bs".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-bs".ljust(32, b"\x00"))
        carl = Entity.create(b"carl-bs".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"bs-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hi", MIN_FEE + 100, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, REJECT_INVALID_SIG)
        etx = _sign_evidence(bob, rej, mtx, fee=MIN_FEE)

        # Verify against carl's pubkey — should fail.
        ok, reason = verify_bogus_rejection_evidence_tx(etx, carl.public_key)
        self.assertFalse(ok)
        self.assertIn("submitter", reason.lower())


class TestBogusRejectionProcessor(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(b"alice-proc".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-proc".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        self.chain.supply.staked[self.alice.entity_id] = 100_000

        self.alice_receipt_kp = _make_receipt_subtree_keypair(b"proc-alice")
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.alice_receipt_kp.public_key
        )

    def _make_rejection(self, mtx, reason_code):
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: self.chain.height,
        )
        return issuer.issue_rejection(mtx.tx_hash, reason_code)

    def test_bogus_invalid_sig_triggers_slash(self):
        """Issuer claims REJECT_INVALID_SIG but the message_tx signature
        actually verifies — slash the issuer."""
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = _sign_evidence(self.bob, rej, mtx)

        proc = BogusRejectionProcessor()
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        result = proc.process(etx, self.chain)
        self.assertTrue(result.slashed)
        self.assertEqual(result.offender_id, self.alice.entity_id)
        self.assertEqual(
            result.slash_amount, compute_slash_amount(stake_before),
        )
        self.assertIn(etx.evidence_hash, proc.processed)

    def test_honest_invalid_sig_rejection_no_slash(self):
        """Issuer claims REJECT_INVALID_SIG and the message_tx signature
        ACTUALLY fails — rejection was honest, evidence_tx is rejected."""
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        # Mutate the tx's fee so the signature no longer covers it.
        bad_tx = MessageTransaction(
            entity_id=mtx.entity_id,
            message=mtx.message,
            timestamp=mtx.timestamp,
            nonce=mtx.nonce,
            fee=mtx.fee + 1,
            signature=mtx.signature,
            compression_flag=mtx.compression_flag,
        )
        rej = self._make_rejection(bad_tx, REJECT_INVALID_SIG)
        etx = _sign_evidence(self.bob, rej, bad_tx)

        proc = BogusRejectionProcessor()
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        result = proc.process(etx, self.chain)
        self.assertFalse(result.slashed)
        self.assertFalse(result.accepted)
        self.assertIn("honest", result.reason.lower())
        self.assertEqual(
            self.chain.supply.staked[self.alice.entity_id], stake_before,
        )

    def test_other_reason_codes_admitted_no_slash(self):
        """v1 only slashes on REJECT_INVALID_SIG.  Other codes are
        admitted (evidence accepted, fee paid, recorded) but no slash."""
        for rc in (
            REJECT_INVALID_NONCE, REJECT_FEE_TOO_LOW, REJECT_OTHER,
        ):
            mtx = create_transaction(
                self.bob, f"hi-{rc}", MIN_FEE + 100, nonce=0,
            )
            rej = self._make_rejection(mtx, rc)
            etx = _sign_evidence(self.bob, rej, mtx)

            proc = BogusRejectionProcessor()
            stake_before = self.chain.supply.staked[self.alice.entity_id]
            result = proc.process(etx, self.chain)
            self.assertFalse(result.slashed, f"reason {rc} must not slash")
            self.assertTrue(result.accepted, f"reason {rc} must be accepted")
            self.assertIn(etx.evidence_hash, proc.processed)
            self.assertEqual(
                self.chain.supply.staked[self.alice.entity_id], stake_before,
            )

    def test_double_submit_prevented(self):
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 100, nonce=0)
        rej = self._make_rejection(mtx, REJECT_INVALID_SIG)
        etx = _sign_evidence(self.bob, rej, mtx)

        proc = BogusRejectionProcessor()
        first = proc.process(etx, self.chain)
        self.assertTrue(first.slashed)
        # Second submission of identical evidence: rejected as already-processed.
        second = proc.process(etx, self.chain)
        self.assertFalse(second.slashed)
        self.assertFalse(second.accepted)
        self.assertIn("processed", second.reason.lower())

    def test_snapshot_roundtrip_preserves_processed(self):
        proc = BogusRejectionProcessor()
        proc.processed.add(_h(b"a"))
        proc.processed.add(_h(b"b"))
        snap = proc.snapshot_dict()

        proc2 = BogusRejectionProcessor()
        proc2.load_snapshot_dict(snap)
        self.assertEqual(proc.processed, proc2.processed)


class TestBlockchainWiring(unittest.TestCase):
    """End-to-end: a BogusRejectionEvidenceTx in a block triggers a slash."""

    def setUp(self):
        from messagechain.consensus.pos import ProofOfStake
        self.alice = Entity.create(b"alice-bw".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-bw".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        self.chain.supply.staked[self.alice.entity_id] = 100_000

        self.alice_receipt_kp = _make_receipt_subtree_keypair(b"bw-alice")
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.alice_receipt_kp.public_key
        )
        self.pos = ProofOfStake()

    def _build_evidence(self, reason_code=REJECT_INVALID_SIG):
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: self.chain.height,
        )
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 200, nonce=0)
        rej = issuer.issue_rejection(mtx.tx_hash, reason_code)
        return _sign_evidence(self.bob, rej, mtx)

    def test_bogus_rejection_evidence_in_block_slashes(self):
        etx = self._build_evidence(REJECT_INVALID_SIG)
        stake_before = self.chain.supply.staked[self.alice.entity_id]
        burned_before = self.chain.supply.total_burned

        block = self.chain.propose_block(
            self.pos, self.alice, [],
            bogus_rejection_evidence_txs=[etx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

        stake_after = self.chain.supply.staked[self.alice.entity_id]
        burned_after = self.chain.supply.total_burned
        expected_slash = compute_slash_amount(stake_before)
        self.assertEqual(stake_before - stake_after, expected_slash)
        self.assertGreaterEqual(burned_after - burned_before, expected_slash)
        self.assertIn(
            etx.evidence_hash,
            self.chain.bogus_rejection_processor.processed,
        )

    def test_double_submit_rejected_at_admission(self):
        etx = self._build_evidence(REJECT_INVALID_SIG)
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            bogus_rejection_evidence_txs=[etx],
        )
        self.assertTrue(self.chain.add_block(block)[0])
        # Re-validate the same etx — already processed.
        ok, reason = self.chain.validate_bogus_rejection_evidence_tx(etx)
        self.assertFalse(ok)
        self.assertIn("processed", reason.lower())


if __name__ == "__main__":
    unittest.main()
