"""Tests for attestable-submission-receipts + censorship-evidence slashing.

Covers the full end-to-end wiring:

  * ReceiptIssuer produces verifiable receipts over a dedicated subtree
  * CensorshipEvidenceTx round-trips through binary + dict
  * Mempool admission respects MIN_FEE
  * CensorshipEvidenceProcessor.submit/observe_block/mature lifecycle
  * Blockchain integration: admitted evidence becomes pending; voided
    evidence is never slashed; matured evidence slashes stake by
    CENSORSHIP_SLASH_BPS
  * Snapshot round-trip: serialize + decode + install preserves
    processor state bit-for-bit
  * Double-submission of a processed evidence is rejected
  * Stale evidence (beyond EVIDENCE_EXPIRY_BLOCKS) is rejected at
    validation time
  * Dedicated receipt subtree does NOT advance block-signing leaf index
  * Cold restart reloads pending evidence from ChainDB

Many tests build blocks with `Blockchain.propose_block`, which threads
censorship_evidence_txs through to the sim + apply paths.
"""

import hashlib
import tempfile
import time
import unittest

from tests import register_entity_for_test
import messagechain.config as _mcfg

# Tests run at MERKLE_TREE_HEIGHT=4 (16 leaves / keypair) — the
# production window constants are too large to exercise end-to-end
# without exhausting a proposer's keypair.  Shrink the key
# lifecycle-sensitive ones for the duration of this module.  Restore
# on teardown is not strictly needed since the test suite always
# imports fresh, but documenting intent here matters for future edits.
_mcfg.EVIDENCE_INCLUSION_WINDOW = 4
_mcfg.EVIDENCE_MATURITY_BLOCKS = 2
# Keep EVIDENCE_EXPIRY_BLOCKS large enough that the window can be
# exercised but small enough that a stale-check negative test is
# reachable from the test heights we reach.
_mcfg.EVIDENCE_EXPIRY_BLOCKS = 64

# Re-export the adjusted constants from messagechain.config so the
# *.py modules that import them (e.g., blockchain.py) keep working
# under the test-adjusted values.  The blockchain module already
# re-imported these during initial test-discovery, so we patch those
# module-level aliases too.
import messagechain.core.blockchain as _bc_mod
_bc_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_bc_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

import messagechain.consensus.censorship_evidence as _ce_mod
_ce_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_ce_mod.EVIDENCE_MATURITY_BLOCKS = _mcfg.EVIDENCE_MATURITY_BLOCKS
_ce_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

from messagechain.config import (
    HASH_ALGO, MIN_FEE, CHAIN_ID,
    EVIDENCE_INCLUSION_WINDOW, EVIDENCE_MATURITY_BLOCKS,
    EVIDENCE_EXPIRY_BLOCKS, CENSORSHIP_SLASH_BPS,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.network.submission_receipt import (
    SubmissionReceipt, ReceiptIssuer, verify_receipt,
)
from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceTx, CensorshipEvidenceProcessor,
    verify_censorship_evidence_tx, compute_slash_amount,
)
from messagechain.storage.state_snapshot import (
    serialize_state, encode_snapshot, decode_snapshot, compute_state_root,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    """Dedicated WOTS+ subtree — MUST be distinct from block-signing
    keypair per spec.  Using a separate seed guarantees a different
    public-key root even at test height 4."""
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


def _sign_evidence_tx(
    submitter: Entity,
    receipt: SubmissionReceipt,
    message_tx: MessageTransaction,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> CensorshipEvidenceTx:
    """Helper: build and sign a CensorshipEvidenceTx from test fixtures."""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = CensorshipEvidenceTx(
        receipt=receipt,
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


# ─────────────────────────────────────────────────────────────────────
# Unit tests: receipts, tx serialization, processor state machine
# ─────────────────────────────────────────────────────────────────────

class TestSubmissionReceipt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice".ljust(32, b"\x00"))

    def test_receipt_signs_and_verifies(self):
        issuer_keypair = _make_receipt_subtree_keypair(b"alice")
        issuer = ReceiptIssuer(
            issuer_id=self.alice.entity_id,
            subtree_keypair=issuer_keypair,
            height_fn=lambda: 42,
        )
        tx_hash = _h(b"some tx")
        receipt = issuer.issue(tx_hash)
        self.assertEqual(receipt.tx_hash, tx_hash)
        self.assertEqual(receipt.commit_height, 42)
        self.assertEqual(receipt.issuer_id, self.alice.entity_id)
        self.assertEqual(receipt.issuer_root_public_key, issuer_keypair.public_key)
        ok, reason = verify_receipt(receipt)
        self.assertTrue(ok, reason)

    def test_receipt_tampering_detected(self):
        issuer_keypair = _make_receipt_subtree_keypair(b"alice2")
        issuer = ReceiptIssuer(
            issuer_id=self.alice.entity_id,
            subtree_keypair=issuer_keypair,
        )
        receipt = issuer.issue(_h(b"tx"))
        # Mutate tx_hash post-signing — the stored receipt_hash no
        # longer matches _compute_hash(), so verify must reject.
        tampered = SubmissionReceipt(
            tx_hash=_h(b"different tx"),
            commit_height=receipt.commit_height,
            issuer_id=receipt.issuer_id,
            issuer_root_public_key=receipt.issuer_root_public_key,
            signature=receipt.signature,
            receipt_hash=receipt.receipt_hash,  # stale
        )
        ok, _ = verify_receipt(tampered)
        self.assertFalse(ok)

    def test_receipt_binary_roundtrip(self):
        issuer_keypair = _make_receipt_subtree_keypair(b"alice3")
        issuer = ReceiptIssuer(
            issuer_id=self.alice.entity_id,
            subtree_keypair=issuer_keypair,
        )
        receipt = issuer.issue(_h(b"tx"))
        blob = receipt.to_bytes()
        decoded = SubmissionReceipt.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, receipt.tx_hash)
        self.assertEqual(decoded.receipt_hash, receipt.receipt_hash)

    def test_dedicated_subtree_independent_from_block_signing(self):
        """Spec: issuing receipts must NOT advance the block-signing
        keypair's leaf counter.  Uses a distinct subtree."""
        block_signing_kp = self.alice.keypair
        block_leaf_before = block_signing_kp._next_leaf

        receipt_kp = _make_receipt_subtree_keypair(b"alice4")
        issuer = ReceiptIssuer(self.alice.entity_id, receipt_kp)
        receipt_leaf_before = receipt_kp._next_leaf

        issuer.issue(_h(b"tx1"))
        issuer.issue(_h(b"tx2"))

        # Block-signing keypair untouched.
        self.assertEqual(block_signing_kp._next_leaf, block_leaf_before)
        # Receipt keypair advanced by two.
        self.assertEqual(receipt_kp._next_leaf, receipt_leaf_before + 2)


class TestCensorshipEvidenceTxSerialization(unittest.TestCase):

    def test_roundtrip_dict(self):
        alice = Entity.create(b"alice-s".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-s".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"s-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hello", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)

        etx = _sign_evidence_tx(bob, receipt, mtx, fee=MIN_FEE)
        round_tripped = CensorshipEvidenceTx.deserialize(etx.serialize())
        self.assertEqual(round_tripped.tx_hash, etx.tx_hash)
        self.assertEqual(round_tripped.evidence_hash, etx.evidence_hash)
        self.assertEqual(round_tripped.offender_id, alice.entity_id)

    def test_roundtrip_binary(self):
        alice = Entity.create(b"alice-b".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-b".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"b-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)

        etx = _sign_evidence_tx(bob, receipt, mtx, fee=MIN_FEE)
        blob = etx.to_bytes()
        decoded = CensorshipEvidenceTx.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertEqual(decoded.evidence_hash, etx.evidence_hash)

    def test_evidence_tx_fee_floor(self):
        alice = Entity.create(b"alice-f".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-f".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"f-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        # fee below MIN_FEE → verify rejects.
        etx = _sign_evidence_tx(bob, receipt, mtx, fee=1)
        ok, reason = verify_censorship_evidence_tx(etx, bob.public_key)
        self.assertFalse(ok)
        self.assertIn("fee", reason.lower())


class TestCensorshipEvidenceProcessor(unittest.TestCase):

    def test_submit_then_mature_produces_slash_request(self):
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev1")
        tx_hash = _h(b"tx1")
        offender = b"o" * 32
        self.assertTrue(proc.submit(ev_hash, offender, tx_hash, 10, _h(b"etx")))
        # Just before maturity — nothing returned.
        pre = proc.mature(10 + EVIDENCE_MATURITY_BLOCKS - 1)
        self.assertEqual(pre, [])
        # At maturity — returned and marked processed.
        mat = proc.mature(10 + EVIDENCE_MATURITY_BLOCKS)
        self.assertEqual(len(mat), 1)
        self.assertEqual(mat[0].offender_id, offender)
        self.assertIn(ev_hash, proc.processed)
        self.assertNotIn(ev_hash, proc.pending)

    def test_observe_block_voids_pending_when_tx_lands(self):
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev2")
        tx_hash = _h(b"tx2")
        proc.submit(ev_hash, b"o" * 32, tx_hash, 5, _h(b"etx"))

        class FakeTx:
            def __init__(self, h):
                self.tx_hash = h

        class FakeBlock:
            transactions = [FakeTx(tx_hash)]

        voided = proc.observe_block(FakeBlock())
        self.assertIn(ev_hash, voided)
        self.assertNotIn(ev_hash, proc.pending)
        self.assertIn(ev_hash, proc.processed)

    def test_double_submission_rejected(self):
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev3")
        self.assertTrue(proc.submit(ev_hash, b"o" * 32, _h(b"tx"), 1, _h(b"e")))
        # Same evidence_hash — second attempt refused while pending.
        self.assertFalse(proc.submit(ev_hash, b"o" * 32, _h(b"tx"), 1, _h(b"e")))
        # Mature, then try again: still refused (processed set).
        proc.mature(1 + EVIDENCE_MATURITY_BLOCKS)
        self.assertFalse(proc.submit(ev_hash, b"o" * 32, _h(b"tx"), 1, _h(b"e")))


# ─────────────────────────────────────────────────────────────────────
# Blockchain integration: admission, voiding, maturation, slashing
# ─────────────────────────────────────────────────────────────────────

class TestBlockchainWiring(unittest.TestCase):

    def setUp(self):
        self.alice = Entity.create(b"alice-int".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-int".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        # Fund alice with real stake so a slash has something to cut.
        self.chain.supply.staked[self.alice.entity_id] = 100_000

        # Dedicated receipt subtree for alice.
        self.alice_receipt_kp = _make_receipt_subtree_keypair(
            self.alice.entity_id[:16]
        )
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.alice_receipt_kp.public_key
        )
        self.pos = ProofOfStake()

    def _make_censored_tx_and_receipt(self, commit_height: int):
        """Build (orphan) MessageTransaction + receipt from alice."""
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: commit_height,
        )
        mtx = create_transaction(self.bob, "hi", MIN_FEE + 200, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        return mtx, receipt

    def _add_empty_block(self, proposer: Entity):
        block = self.chain.propose_block(
            self.pos, proposer, [],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_admission_rejects_fresh_receipt(self):
        """Receipt not yet past EVIDENCE_INCLUSION_WINDOW — rejected."""
        mtx, receipt = self._make_censored_tx_and_receipt(
            commit_height=self.chain.height,
        )
        etx = _sign_evidence_tx(self.bob, receipt, mtx)
        ok, reason = self.chain.validate_censorship_evidence_tx(etx)
        self.assertFalse(ok)
        self.assertIn("too fresh", reason.lower())

    def test_admission_accepts_after_window(self):
        """Advance past the window; validate_censorship_evidence_tx
        should accept the claim."""
        commit_h = self.chain.height
        mtx, receipt = self._make_censored_tx_and_receipt(commit_h)
        # Advance chain past the window.
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            self._add_empty_block(self.alice)
        etx = _sign_evidence_tx(self.bob, receipt, mtx)
        ok, reason = self.chain.validate_censorship_evidence_tx(etx)
        self.assertTrue(ok, reason)

    def test_stale_receipt_rejected(self):
        """Receipt older than EVIDENCE_EXPIRY_BLOCKS is rejected."""
        mtx, receipt = self._make_censored_tx_and_receipt(
            commit_height=0,
        )
        # Skip ahead past EVIDENCE_EXPIRY_BLOCKS via direct height
        # hack — we only need validate_censorship_evidence_tx to see
        # the current height as huge.
        etx = _sign_evidence_tx(self.bob, receipt, mtx)
        ok, reason = self.chain.validate_censorship_evidence_tx(
            etx, chain_height=EVIDENCE_EXPIRY_BLOCKS + 1,
        )
        self.assertFalse(ok)
        self.assertIn("expired", reason.lower())

    def test_evidence_admitted_and_matures_to_slash(self):
        """Full pipeline: receipt → advance → admit evidence →
        advance maturity → slashed 10%.  Verifies total supply
        decreases and stake decreases."""
        commit_h = self.chain.height
        mtx, receipt = self._make_censored_tx_and_receipt(commit_h)
        # Advance past inclusion window.
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            self._add_empty_block(self.alice)

        etx = _sign_evidence_tx(self.bob, receipt, mtx)

        # Propose a block carrying the evidence.
        stake_before = self.chain.supply.staked.get(self.alice.entity_id, 0)
        burned_before = self.chain.supply.total_burned
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            censorship_evidence_txs=[etx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

        # Pending set now contains the evidence.
        self.assertIn(
            etx.evidence_hash, self.chain.censorship_processor.pending,
        )

        # Advance past maturity.
        for _ in range(EVIDENCE_MATURITY_BLOCKS + 1):
            self._add_empty_block(self.alice)

        # Slashed: stake reduced by CENSORSHIP_SLASH_BPS, and the slash
        # amount is burned (total_burned grows by >= slash_amount —
        # inclusive-of because empty blocks also burn base fees).
        stake_after = self.chain.supply.staked.get(self.alice.entity_id, 0)
        burned_after = self.chain.supply.total_burned
        expected_slash = compute_slash_amount(stake_before)
        self.assertEqual(stake_before - stake_after, expected_slash)
        self.assertGreaterEqual(burned_after - burned_before, expected_slash)
        # Evidence in processed set, not pending.
        self.assertNotIn(
            etx.evidence_hash, self.chain.censorship_processor.pending,
        )
        self.assertIn(
            etx.evidence_hash, self.chain.censorship_processor.processed,
        )
        # Cannot be re-submitted.
        ok, reason = self.chain.validate_censorship_evidence_tx(etx)
        self.assertFalse(ok)

    def test_evidence_voided_when_tx_lands(self):
        """If the receipted tx lands on-chain during the maturity
        window, the evidence is voided and NO slash is applied."""
        commit_h = self.chain.height
        mtx, receipt = self._make_censored_tx_and_receipt(commit_h)
        # Advance past inclusion window but give bob balance so mtx
        # is valid.
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            self._add_empty_block(self.alice)

        etx = _sign_evidence_tx(self.bob, receipt, mtx)

        # Propose a block carrying the evidence.
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            censorship_evidence_txs=[etx],
        )
        self.assertTrue(self.chain.add_block(block)[0])
        self.assertIn(
            etx.evidence_hash, self.chain.censorship_processor.pending,
        )

        stake_before = self.chain.supply.staked.get(self.alice.entity_id, 0)

        # Next block includes the "censored" tx — voids the pending
        # evidence.
        block = self.chain.propose_block(
            self.pos, self.alice, [mtx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertNotIn(
            etx.evidence_hash, self.chain.censorship_processor.pending,
        )
        self.assertIn(
            etx.evidence_hash, self.chain.censorship_processor.processed,
        )
        # Advance past maturity — no slash should be applied.
        for _ in range(EVIDENCE_MATURITY_BLOCKS + 2):
            self._add_empty_block(self.alice)
        stake_after = self.chain.supply.staked.get(self.alice.entity_id, 0)
        self.assertEqual(stake_before, stake_after)


class TestSnapshotRoundTrip(unittest.TestCase):

    def test_snapshot_includes_pending_and_processed(self):
        alice = Entity.create(b"alice-snap".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(alice)
        chain.supply.staked[alice.entity_id] = 1_000

        # Inject a pending evidence + processed hash + receipt root
        # directly (tests snapshot round-trip, not the full wiring).
        ev_hash = _h(b"ev-snap")
        proc_hash = _h(b"ev-proc")
        chain.censorship_processor.submit(
            ev_hash, alice.entity_id, _h(b"tx-snap"), 1, _h(b"etx"),
        )
        chain.censorship_processor.processed.add(proc_hash)
        chain.receipt_subtree_roots[alice.entity_id] = b"\xab" * 32

        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertIn(ev_hash, decoded["censorship_pending"])
        self.assertIn(proc_hash, decoded["censorship_processed"])
        self.assertEqual(
            decoded["receipt_subtree_roots"][alice.entity_id], b"\xab" * 32,
        )

        # Install the decoded snapshot into a fresh chain via
        # _install_state_snapshot — pending map must re-appear.
        fresh = Blockchain()
        fresh.supply.total_supply = 0  # _install_state_snapshot replaces this
        fresh._install_state_snapshot(decoded)
        self.assertIn(
            ev_hash, fresh.censorship_processor.pending,
        )
        self.assertIn(
            proc_hash, fresh.censorship_processor.processed,
        )

    def test_state_root_changes_when_pending_added(self):
        """Pending evidence is in the state-root commitment."""
        alice = Entity.create(b"alice-sr".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(alice)

        root_before = compute_state_root(serialize_state(chain))
        chain.censorship_processor.submit(
            _h(b"ev-sr"), alice.entity_id, _h(b"tx"), 0, _h(b"e"),
        )
        root_after = compute_state_root(serialize_state(chain))
        self.assertNotEqual(
            root_before, root_after,
            "pending-evidence admission must change the state root",
        )


class TestColdRestart(unittest.TestCase):
    """Pending evidence persisted to SQLite survives restart."""

    def test_pending_evidence_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            from messagechain.storage.chaindb import ChainDB
            db_path = os.path.join(tmp, "chain.db")

            alice = Entity.create(b"alice-cold".ljust(32, b"\x00"))
            alice.keypair._next_leaf = 0
            db = ChainDB(db_path)
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            chain.supply.staked[alice.entity_id] = 10_000

            ev_hash = _h(b"cold-ev")
            tx_hash = _h(b"cold-tx")
            chain.censorship_processor.submit(
                ev_hash, alice.entity_id, tx_hash, 1, _h(b"etx-cold"),
            )
            chain._persist_state()
            db.close()

            # Reopen.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            self.assertIn(
                ev_hash, chain2.censorship_processor.pending,
                "pending evidence must rehydrate from ChainDB on cold start",
            )
            db2.close()


# ─────────────────────────────────────────────────────────────────────
# Mempool admission
# ─────────────────────────────────────────────────────────────────────

class TestMempoolAdmission(unittest.TestCase):

    def test_mempool_admits_evidence_tx_with_fee(self):
        from messagechain.core.mempool import Mempool
        alice = Entity.create(b"alice-mp".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-mp".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"mp-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx, fee=MIN_FEE)

        mp = Mempool()
        self.assertTrue(mp.add_censorship_evidence_tx(etx))
        # Duplicate rejected.
        self.assertFalse(mp.add_censorship_evidence_tx(etx))
        self.assertEqual(len(mp.get_censorship_evidence_txs()), 1)

    def test_submit_transaction_to_mempool_issues_receipt(self):
        """submission_server's helper returns a receipt when an issuer
        is wired."""
        from messagechain.core.mempool import Mempool
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        alice = Entity.create(b"alice-rcpt".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-rcpt".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        bob.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[bob.entity_id] = 1_000_000

        mp = Mempool()
        kp = _make_receipt_subtree_keypair(b"alice-rcpt")
        issuer = ReceiptIssuer(
            alice.entity_id, kp, height_fn=lambda: chain.height,
        )
        mtx = create_transaction(bob, "hello rcpt", MIN_FEE + 200, nonce=0)
        result = submit_transaction_to_mempool(
            mtx, chain, mp, receipt_issuer=issuer,
        )
        self.assertTrue(result.ok)
        self.assertTrue(result.receipt_hex,
                        "issuer must produce a non-empty receipt_hex")
        # Decode: round-trip must succeed and match the submitted tx.
        decoded = SubmissionReceipt.from_bytes(
            bytes.fromhex(result.receipt_hex),
        )
        self.assertEqual(decoded.tx_hash, mtx.tx_hash)
        self.assertEqual(decoded.issuer_id, alice.entity_id)
        ok, reason = verify_receipt(decoded)
        self.assertTrue(ok, reason)

    def test_mempool_rejects_underfee(self):
        from messagechain.core.mempool import Mempool
        alice = Entity.create(b"alice-mp2".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-mp2".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"mp2-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx, fee=1)

        mp = Mempool()
        self.assertFalse(mp.add_censorship_evidence_tx(etx))


if __name__ == "__main__":
    unittest.main()
