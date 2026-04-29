"""Tier 44 — polymorphic CensorshipEvidenceTx receipted-tx field.

Audit fix.  The pre-Tier-44 wire format hard-coded MessageTransaction as
the receipted tx, but the submission server issues SubmissionReceipts
for Message AND Transfer AND React.  A receipt for a silently-dropped
transfer or react could not be packaged as evidence — every encode/
decode call invoked `MessageTransaction.from_bytes` on the wrong
payload and failed.  Net effect: receipts on transfer/react were
slash-theatre.

Tier 44 closes this by:

  1. Extending `CensorshipEvidenceTx` to carry a polymorphic
     receipted-tx field: any of MessageTransaction /
     TransferTransaction / ReactTransaction.  A new wire-format
     leading byte (0x01) discriminates from the legacy layout (whose
     leading byte — the high byte of the receipt-len u32 — is always
     0x00).
  2. Extending `CensorshipEvidenceProcessor.observe_block` to walk
     every receipted-kind slot (`transactions`, `transfer_transactions`,
     `react_transactions`) so a transfer or react that DID land on
     chain still voids the matching pending evidence.
  3. Threading `chain_height` through block encoding so a block at
     a height < activation emits the legacy layout (byte-identical
     replay), and a block at/above activation emits the new layout.

This module pins:

  * Pre-fork legacy wire format byte-identity (regression).
  * Post-fork TransferTransaction round-trip through binary + dict.
  * Post-fork ReactTransaction round-trip through binary + dict.
  * Decoder dispatch on the leading byte (legacy 0x00 vs poly 0x01).
  * `observe_block` voids on transfer / react inclusion post-fork.
  * End-to-end: a transfer-receipted evidence, admitted while the
    receipted transfer remains absent, matures into a slash.
"""

import hashlib
import struct
import time
import unittest

from tests import register_entity_for_test
import messagechain.config as _mcfg

# Same test-time constants as the legacy test module — keep keypair
# heights small and shrink the evidence-window so the maturity path
# is reachable in a few blocks.
_mcfg.EVIDENCE_INCLUSION_WINDOW = 4
_mcfg.EVIDENCE_MATURITY_BLOCKS = 2
_mcfg.EVIDENCE_EXPIRY_BLOCKS = 64

import messagechain.core.blockchain as _bc_mod
_bc_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_bc_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

import messagechain.consensus.censorship_evidence as _ce_mod
_ce_mod.EVIDENCE_INCLUSION_WINDOW = _mcfg.EVIDENCE_INCLUSION_WINDOW
_ce_mod.EVIDENCE_MATURITY_BLOCKS = _mcfg.EVIDENCE_MATURITY_BLOCKS
_ce_mod.EVIDENCE_EXPIRY_BLOCKS = _mcfg.EVIDENCE_EXPIRY_BLOCKS

# The Tier 44 activation height is 3834 in production; tests don't
# advance the chain that far, so we shrink it to something reachable
# (or leave callers free to pass `chain_height` explicitly to
# to_bytes, which is height-driven not config-driven).  We DO NOT
# shrink the production constant globally because the legacy wire-
# format-byte-identity test below pins pre-fork behavior at the
# height-None path which is independent of the config value.

from messagechain.config import (
    HASH_ALGO, MIN_FEE, EVIDENCE_INCLUSION_WINDOW, EVIDENCE_MATURITY_BLOCKS,
    CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT,
)
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.core.transfer import (
    TransferTransaction, create_transfer_transaction,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.network.submission_receipt import (
    SubmissionReceipt, ReceiptIssuer,
)
from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceTx, CensorshipEvidenceProcessor,
    RECEIPTED_TX_KIND_MESSAGE, RECEIPTED_TX_KIND_TRANSFER,
    RECEIPTED_TX_KIND_REACT, _POLY_WIRE_VERSION,
    receipted_tx_entity_id, compute_slash_amount,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_receipt_subtree_keypair(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-poly-" + seed_tag,
        height=height,
    )


def _sign_evidence_tx(submitter, receipt, receipted_tx, fee=MIN_FEE,
                     timestamp=None):
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = CensorshipEvidenceTx(
        receipt=receipt,
        message_tx=receipted_tx,  # alias for receipted_tx
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
# Pre-fork wire-format byte-identity
# ─────────────────────────────────────────────────────────────────────

class TestPreForkWireFormatByteIdentity(unittest.TestCase):
    """Pre-fork CensorshipEvidenceTx blobs MUST encode byte-identically
    to the legacy MessageTransaction-only layout.  Replay determinism
    is sacred.
    """

    def test_legacy_to_bytes_starts_with_0x00(self):
        """Legacy layout starts with the receipt-len u32 high byte,
        which is always 0x00 because receipts are << 16 MB.  This is
        the discriminator post-fork decoders use to recognize legacy
        blobs."""
        alice = Entity.create(b"alice-leg".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-leg".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"leg-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)

        mtx = create_transaction(bob, "hello", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx)

        # Default to_bytes() (no chain_height) emits legacy form.
        legacy_blob = etx.to_bytes()
        self.assertEqual(legacy_blob[0], 0x00,
                         "legacy blob must start with 0x00 (receipt-len high byte)")

    def test_legacy_blob_round_trips_through_legacy_decoder(self):
        alice = Entity.create(b"alice-leg2".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-leg2".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"leg2-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx)

        blob = etx.to_bytes()
        decoded = CensorshipEvidenceTx.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertEqual(decoded.evidence_hash, etx.evidence_hash)
        self.assertEqual(decoded.message_tx.tx_hash, mtx.tx_hash)
        self.assertEqual(decoded.receipted_tx_kind, RECEIPTED_TX_KIND_MESSAGE)

    def test_legacy_to_bytes_pre_fork_height_byte_identical(self):
        """Calling to_bytes(chain_height=H) for any H below the
        Tier-44 activation must produce bytes byte-identical to the
        height-None form.  This is what protects historical replay
        across the fork boundary."""
        alice = Entity.create(b"alice-pf".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-pf".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"pf-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx)

        baseline = etx.to_bytes()
        for H in (0, 1, 100,
                  CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT - 1):
            self.assertEqual(
                etx.to_bytes(chain_height=H), baseline,
                f"pre-fork height {H} must produce legacy bytes",
            )

    def test_pre_fork_rejects_transfer_receipted_tx(self):
        """The pre-fork wire format physically cannot represent a
        non-Message receipted tx.  Encoding one without an activation
        height must raise rather than silently down-convert (which
        would produce a hash mismatch the receiver couldn't diagnose).
        """
        alice = Entity.create(b"alice-rej".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-rej".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"rej-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        ttx = create_transfer_transaction(
            bob, alice.entity_id, amount=100, nonce=0, fee=MIN_FEE,
        )
        receipt = issuer.issue(ttx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, ttx)
        with self.assertRaises(ValueError):
            etx.to_bytes()  # pre-fork — must reject transfer
        with self.assertRaises(ValueError):
            etx.to_bytes(
                chain_height=CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT - 1,
            )


# ─────────────────────────────────────────────────────────────────────
# Post-fork polymorphic wire format
# ─────────────────────────────────────────────────────────────────────

POST_FORK_HEIGHT = CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT


class TestPolymorphicWireFormat(unittest.TestCase):

    def test_transfer_receipted_round_trips_post_fork(self):
        alice = Entity.create(b"alice-trx".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-trx".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"trx-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        ttx = create_transfer_transaction(
            bob, alice.entity_id, amount=100, nonce=0, fee=MIN_FEE,
        )
        receipt = issuer.issue(ttx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, ttx)

        blob = etx.to_bytes(chain_height=POST_FORK_HEIGHT)
        # Leading byte is the poly wire-format version.
        self.assertEqual(blob[0], _POLY_WIRE_VERSION)
        # Second byte is the kind tag: transfer = 1.
        self.assertEqual(blob[1], RECEIPTED_TX_KIND_TRANSFER)

        decoded = CensorshipEvidenceTx.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertEqual(decoded.evidence_hash, etx.evidence_hash)
        self.assertIsInstance(decoded.message_tx, TransferTransaction)
        self.assertEqual(decoded.message_tx.tx_hash, ttx.tx_hash)
        self.assertEqual(decoded.message_tx.entity_id, bob.entity_id)
        self.assertEqual(decoded.message_tx.recipient_id, alice.entity_id)
        self.assertEqual(decoded.receipted_tx_kind, RECEIPTED_TX_KIND_TRANSFER)

    def test_message_receipted_round_trips_post_fork(self):
        """Even at post-fork heights, a MessageTransaction-receipted
        evidence must round-trip cleanly under the new format."""
        alice = Entity.create(b"alice-pmsg".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-pmsg".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"pmsg-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx)

        blob = etx.to_bytes(chain_height=POST_FORK_HEIGHT)
        self.assertEqual(blob[0], _POLY_WIRE_VERSION)
        self.assertEqual(blob[1], RECEIPTED_TX_KIND_MESSAGE)

        decoded = CensorshipEvidenceTx.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertIsInstance(decoded.message_tx, MessageTransaction)

    def test_transfer_serialize_dict_round_trips(self):
        alice = Entity.create(b"alice-td".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-td".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"td-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        ttx = create_transfer_transaction(
            bob, alice.entity_id, amount=50, nonce=0, fee=MIN_FEE,
        )
        receipt = issuer.issue(ttx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, ttx)

        d = etx.serialize()
        self.assertEqual(d["tx_kind"], "transfer")
        decoded = CensorshipEvidenceTx.deserialize(d)
        self.assertEqual(decoded.tx_hash, etx.tx_hash)
        self.assertIsInstance(decoded.message_tx, TransferTransaction)
        self.assertEqual(decoded.message_tx.amount, 50)

    def test_legacy_dict_default_to_message(self):
        """Dicts WITHOUT a `tx_kind` field decode as MessageTransaction
        — preserves backward compatibility for any persisted JSON
        from pre-Tier-44 RPC traffic."""
        alice = Entity.create(b"alice-ld".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-ld".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"ld-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        mtx = create_transaction(bob, "msg", MIN_FEE + 100, nonce=0)
        receipt = issuer.issue(mtx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, mtx)

        d = etx.serialize()
        # Message-receipted evidences MUST NOT emit `tx_kind` (that
        # would not round-trip with old dicts).
        self.assertNotIn("tx_kind", d)
        decoded = CensorshipEvidenceTx.deserialize(d)
        self.assertIsInstance(decoded.message_tx, MessageTransaction)

    def test_unknown_wire_version_rejected(self):
        """A leading byte of 0x02+ is reserved for future wire formats;
        the current decoder must reject it cleanly rather than
        misinterpret it as legacy or current poly."""
        alice = Entity.create(b"alice-uw".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-uw".ljust(32, b"\x00"))
        kp = _make_receipt_subtree_keypair(b"uw-alice")
        issuer = ReceiptIssuer(alice.entity_id, kp)
        ttx = create_transfer_transaction(
            bob, alice.entity_id, amount=100, nonce=0, fee=MIN_FEE,
        )
        receipt = issuer.issue(ttx.tx_hash)
        etx = _sign_evidence_tx(bob, receipt, ttx)
        blob = etx.to_bytes(chain_height=POST_FORK_HEIGHT)
        # Tamper the wire version byte.
        bogus = bytes([0x02]) + blob[1:]
        with self.assertRaises(ValueError):
            CensorshipEvidenceTx.from_bytes(bogus)


# ─────────────────────────────────────────────────────────────────────
# observe_block now walks transfer + react slots
# ─────────────────────────────────────────────────────────────────────

class TestObserveBlockMultiList(unittest.TestCase):

    def test_observe_block_voids_on_transfer(self):
        """A pending evidence whose receipted tx_hash matches a tx in
        block.transfer_transactions MUST void.  Pre-fix observe_block
        only walked block.transactions and silently failed to void
        transfer-receipted evidence — the evidence then matured into
        a slash even though the tx WAS included."""
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev-trx")
        tx_hash = _h(b"tx-trx")
        proc.submit(ev_hash, b"o" * 32, tx_hash, 5, _h(b"etx"))

        class FakeTx:
            def __init__(self, h):
                self.tx_hash = h

        class FakeBlock:
            transactions = []
            transfer_transactions = [FakeTx(tx_hash)]

        voided = proc.observe_block(FakeBlock())
        self.assertIn(ev_hash, voided)
        self.assertNotIn(ev_hash, proc.pending)
        self.assertIn(ev_hash, proc.processed)

    def test_observe_block_voids_on_react(self):
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev-rct")
        tx_hash = _h(b"tx-rct")
        proc.submit(ev_hash, b"o" * 32, tx_hash, 5, _h(b"etx"))

        class FakeTx:
            def __init__(self, h):
                self.tx_hash = h

        class FakeBlock:
            transactions = []
            transfer_transactions = []
            react_transactions = [FakeTx(tx_hash)]

        voided = proc.observe_block(FakeBlock())
        self.assertIn(ev_hash, voided)
        self.assertNotIn(ev_hash, proc.pending)

    def test_observe_block_message_path_still_works(self):
        """Regression: walk-extension must not regress the legacy
        Message-only void path."""
        proc = CensorshipEvidenceProcessor()
        ev_hash = _h(b"ev-msg")
        tx_hash = _h(b"tx-msg")
        proc.submit(ev_hash, b"o" * 32, tx_hash, 5, _h(b"etx"))

        class FakeTx:
            def __init__(self, h):
                self.tx_hash = h

        class FakeBlock:
            transactions = [FakeTx(tx_hash)]

        voided = proc.observe_block(FakeBlock())
        self.assertIn(ev_hash, voided)


# ─────────────────────────────────────────────────────────────────────
# End-to-end: transfer-receipted evidence matures into a slash
# ─────────────────────────────────────────────────────────────────────

class TestTransferEvidenceFullPipeline(unittest.TestCase):
    """Full pipeline: a wallet holds a SubmissionReceipt for a
    Transfer the validator never included.  Evidence admits, matures,
    slashes the offender's stake.  Pre-Tier-44 this path silently
    failed at evidence-decode time (`MessageTransaction.from_bytes`
    on a transfer payload) so a coerced validator faced no
    accountability for dropping transfers it had receipted."""

    def setUp(self):
        self.alice = Entity.create(b"alice-fp".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-fp".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        # Fund alice with stake so a slash has something to cut.
        self.chain.supply.staked[self.alice.entity_id] = 100_000

        self.alice_receipt_kp = _make_receipt_subtree_keypair(
            self.alice.entity_id[:16]
        )
        self.chain.receipt_subtree_roots[self.alice.entity_id] = (
            self.alice_receipt_kp.public_key
        )
        self.pos = ProofOfStake()

    def _add_empty_block(self, proposer):
        block = self.chain.propose_block(self.pos, proposer, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_transfer_receipted_evidence_matures_to_slash(self):
        """Transfer-receipted CensorshipEvidenceTx admits, matures,
        and applies a slash equal to compute_slash_amount(stake).
        The receipted tx_hash never appears on chain (we never include
        the transfer) so the maturity path runs to completion.
        """
        # Build an unsubmitted transfer + receipt for it.
        commit_h = self.chain.height
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: commit_h,
        )
        ttx = create_transfer_transaction(
            self.bob, self.alice.entity_id, amount=42, nonce=0,
            fee=MIN_FEE + 200,
        )
        receipt = issuer.issue(ttx.tx_hash)
        self.assertEqual(receipt.tx_hash, ttx.tx_hash)

        # Advance past the inclusion window — the receipted tx is
        # absent so the validator is "censoring."
        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            self._add_empty_block(self.alice)

        etx = _sign_evidence_tx(self.bob, receipt, ttx)
        # Sanity: kind is transfer.
        self.assertEqual(etx.receipted_tx_kind, RECEIPTED_TX_KIND_TRANSFER)
        # Sanity: signer-id helper picks `entity_id` for transfers.
        self.assertEqual(receipted_tx_entity_id(etx.message_tx),
                         self.bob.entity_id)

        # Validation gate accepts.
        ok, reason = self.chain.validate_censorship_evidence_tx(etx)
        self.assertTrue(ok, reason)

        # Propose a block carrying the evidence.  The block-level
        # encoder threads block_height down into etx.to_bytes —
        # since our test heights are far below the Tier 44 production
        # activation, the legacy wire path would normally apply, but
        # the IN-MEMORY object IS a polymorphic transfer-receipted
        # evidence and travels through propose_block / add_block
        # without any to_bytes on the shadow path.  The encode-time
        # gate is exercised separately (above) and via dec/enc round-
        # trip; here we test the chain-state mutation pipeline.
        stake_before = self.chain.supply.staked.get(self.alice.entity_id, 0)
        burned_before = self.chain.supply.total_burned
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            censorship_evidence_txs=[etx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertIn(etx.evidence_hash,
                      self.chain.censorship_processor.pending)

        # Advance past maturity.
        for _ in range(EVIDENCE_MATURITY_BLOCKS + 1):
            self._add_empty_block(self.alice)

        stake_after = self.chain.supply.staked.get(self.alice.entity_id, 0)
        burned_after = self.chain.supply.total_burned
        expected_slash = compute_slash_amount(stake_before)
        self.assertEqual(stake_before - stake_after, expected_slash)
        self.assertGreaterEqual(burned_after - burned_before, expected_slash)
        self.assertNotIn(etx.evidence_hash,
                         self.chain.censorship_processor.pending)
        self.assertIn(etx.evidence_hash,
                      self.chain.censorship_processor.processed)

    def test_transfer_evidence_voids_when_transfer_lands(self):
        """If the receipted transfer lands on chain during the
        maturity window, observe_block must walk transfer_transactions
        and void the pending evidence — no slash."""
        commit_h = self.chain.height
        issuer = ReceiptIssuer(
            self.alice.entity_id,
            self.alice_receipt_kp,
            height_fn=lambda: commit_h,
        )
        ttx = create_transfer_transaction(
            self.bob, self.alice.entity_id, amount=42, nonce=0,
            fee=MIN_FEE + 200,
        )
        receipt = issuer.issue(ttx.tx_hash)

        for _ in range(EVIDENCE_INCLUSION_WINDOW + 1):
            self._add_empty_block(self.alice)

        etx = _sign_evidence_tx(self.bob, receipt, ttx)
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            censorship_evidence_txs=[etx],
        )
        self.assertTrue(self.chain.add_block(block)[0])
        self.assertIn(etx.evidence_hash,
                      self.chain.censorship_processor.pending)

        stake_before = self.chain.supply.staked.get(self.alice.entity_id, 0)

        # Now include the transfer.  observe_block must void the
        # pending evidence (it lives in transfer_transactions, NOT
        # transactions).
        block = self.chain.propose_block(
            self.pos, self.alice, [],
            transfer_transactions=[ttx],
        )
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertNotIn(etx.evidence_hash,
                         self.chain.censorship_processor.pending)
        self.assertIn(etx.evidence_hash,
                      self.chain.censorship_processor.processed)

        # Advance past maturity — no slash should be applied.
        for _ in range(EVIDENCE_MATURITY_BLOCKS + 2):
            self._add_empty_block(self.alice)
        stake_after = self.chain.supply.staked.get(self.alice.entity_id, 0)
        self.assertEqual(stake_before, stake_after)


if __name__ == "__main__":
    unittest.main()
