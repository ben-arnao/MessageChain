"""RPC transfer / react submit endpoints must route through the
central submit-to-mempool helper so they get the SAME censorship-
evidence defenses (signed receipt on admission, signed rejection on
opt-in failure, ack on witnessed submission) as the message-tx
submit endpoint.

Pre-fix headline: a coerced validator that fronts only RPC could
silently admit-and-drop a transfer (balance manipulation, double-spend
race front-running) or a react vote (Tier 17 trust score) with ZERO
on-chain accountability — the receipt issuer was never consulted on
those paths.  CLAUDE.md anchors transfer as "first-class, fully
supported tx type" held to "mainstream-asset quality bars";
silently-droppable transfers fail that bar.

Post-fix: when the client opts in via `request_receipt: True`, the
RPC handler returns a SubmissionReceipt the user can later weaponize
as a CensorshipEvidenceTx — same as the HTTPS submission endpoint
already provided for messages.

Tests are TDD: at least one (test_coerced_validator_dropping_transfer
_produces_evidence) MUST fail on origin/main and pass on this branch.
"""

import os
import tempfile
import unittest
from unittest import mock

import messagechain.config as _config
from messagechain.config import REACT_CHOICE_UP
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.reaction import (
    create_react_transaction,
    ReactTransaction,
)
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.core.transfer import create_transfer_transaction, TransferTransaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import (
    ReceiptIssuer,
    SubmissionReceipt,
    verify_receipt,
)
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _receipt_subtree_kp(seed_tag: bytes, height: int = 4) -> KeyPair:
    return KeyPair.generate(
        seed=b"receipt-subtree-" + seed_tag,
        height=height,
    )


class _BaseRPCFixture(unittest.TestCase):
    """Shared scaffolding for transfer + react RPC tests.

    Builds:
      * A Blockchain with three registered entities (sender, recipient,
        target).
      * A Mempool.
      * A bare-bones `Server` instance with the minimum attributes the
        RPC handlers reach into.
      * A ReceiptIssuer wired to the validator's identity.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Lower the React activation gate so admission tests work at
        # height 0.  Restored in tearDown.
        self._orig_react_height = _config.REACT_TX_HEIGHT
        _config.REACT_TX_HEIGHT = 0
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        self._orig_bc_h = _bc.REACT_TX_HEIGHT
        self._orig_rxn_h = _rxn.REACT_TX_HEIGHT
        _bc.REACT_TX_HEIGHT = 0
        _rxn.REACT_TX_HEIGHT = 0

        self.proposer = Entity.create(b"trxr_prop".ljust(32, b"\x00"))
        self.sender = Entity.create(b"trxr_sender".ljust(32, b"\x00"))
        self.recipient = Entity.create(b"trxr_recip".ljust(32, b"\x00"))
        self.target = Entity.create(b"trxr_target".ljust(32, b"\x00"))

        db = ChainDB(db_path=os.path.join(self.tmp.name, "chain.db"))
        self.chain = Blockchain(db=db)
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        register_entity_for_test(self.chain, self.sender)
        register_entity_for_test(self.chain, self.recipient)
        register_entity_for_test(self.chain, self.target)
        # Fund the sender so transfers can pay amount+fee.
        self.chain.supply.balances[self.sender.entity_id] = 1_000_000_000
        self.mempool = Mempool()

        # Bare Server stub.  __new__ skips __init__ which would try to
        # bind sockets and create event loops we don't need.
        from server import Server
        self.server = Server.__new__(Server)
        self.server.blockchain = self.chain
        self.server.mempool = self.mempool
        # _main_loop=None makes _schedule_coro_threadsafe a no-op.
        self.server._main_loop = None
        # Stub the seen-tx tracker so post-admit accounting works.
        self.server._track_seen_tx = lambda h: None

        # Override _schedule_coro_threadsafe so we close any coroutine
        # the RPC handler hands us — without this, the test fixture's
        # no-loop posture leaks "coroutine was never awaited"
        # RuntimeWarnings on every successful submit.
        def _consume_coro(coro, label):
            try:
                coro.close()
            except Exception:
                pass
            return None
        self.server._schedule_coro_threadsafe = _consume_coro
        # Pending pools that the all-pools nonce scan reaches into.
        self.server._pending_stake_txs = {}
        self.server._pending_unstake_txs = {}
        self.server._pending_authority_txs = {}
        self.server._pending_governance_txs = {}

        # Issuer wired to the proposer (the "validator" running this
        # node).  Receipt subtree keypair is distinct from any tx-
        # signing keypair — see ReceiptIssuer docstring.
        self.issuer_kp = _receipt_subtree_kp(b"trxr-issuer")
        self.server.receipt_issuer = ReceiptIssuer(
            issuer_id=self.proposer.entity_id,
            subtree_keypair=self.issuer_kp,
            height_fn=lambda: self.chain.height,
        )

    def tearDown(self):
        _config.REACT_TX_HEIGHT = self._orig_react_height
        from messagechain.core import blockchain as _bc
        from messagechain.core import reaction as _rxn
        _bc.REACT_TX_HEIGHT = self._orig_bc_h
        _rxn.REACT_TX_HEIGHT = self._orig_rxn_h
        if self.chain.db is not None:
            self.chain.db.close()
        try:
            self.tmp.cleanup()
        except (OSError, PermissionError):
            pass

    def _make_transfer(self, amount=1000, fee=10_000, nonce=0):
        return create_transfer_transaction(
            self.sender,
            recipient_id=self.recipient.entity_id,
            amount=amount,
            nonce=nonce,
            fee=fee,
        )

    def _make_react(self, nonce=0, fee=10_000):
        return create_react_transaction(
            self.sender,
            target=self.target.entity_id,
            target_is_user=True,
            choice=REACT_CHOICE_UP,
            nonce=nonce,
            fee=fee,
        )


# ─────────────────────────────────────────────────────────────────────
# Test 1: transfer + request_receipt: True returns a verifiable receipt
# ─────────────────────────────────────────────────────────────────────


class TestTransferReceiptOptIn(_BaseRPCFixture):

    def test_rpc_submit_transfer_with_receipt_returns_receipt(self):
        """request_receipt=True on a valid transfer must return a
        SubmissionReceipt the user can later file as
        CensorshipEvidenceTx if the receipted tx is dropped."""
        before_leaf = self.issuer_kp._next_leaf
        tx = self._make_transfer()
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
            "request_receipt": True,
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        result = resp["result"]
        self.assertIn(
            "receipt", result,
            "Transfer submitted with request_receipt=True MUST return "
            "a signed receipt — same parity the message path provides "
            "post-1.28.4.  Without it, a coerced validator can admit-"
            "and-drop a transfer with no on-chain accountability.",
        )
        # Receipt is hex-encoded SubmissionReceipt bytes; decode it and
        # assert it commits to the right tx_hash and is signed by the
        # validator's receipt-subtree key.
        receipt = SubmissionReceipt.from_bytes(bytes.fromhex(result["receipt"]))
        self.assertEqual(receipt.tx_hash, tx.tx_hash)
        self.assertEqual(receipt.issuer_id, self.proposer.entity_id)
        self.assertEqual(
            receipt.issuer_root_public_key, self.issuer_kp.public_key,
        )
        ok, why = verify_receipt(receipt)
        self.assertTrue(ok, why)
        # And exactly one leaf was consumed from the receipt subtree.
        self.assertEqual(self.issuer_kp._next_leaf, before_leaf + 1)


# ─────────────────────────────────────────────────────────────────────
# Test 2: react + request_receipt: True returns a verifiable receipt
# ─────────────────────────────────────────────────────────────────────


class TestReactReceiptOptIn(_BaseRPCFixture):

    def test_rpc_submit_react_with_receipt_returns_receipt(self):
        before_leaf = self.issuer_kp._next_leaf
        tx = self._make_react()
        resp = self.server._rpc_submit_react({
            "transaction": tx.serialize(),
            "request_receipt": True,
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        result = resp["result"]
        self.assertIn(
            "receipt", result,
            "ReactTransaction submitted with request_receipt=True MUST "
            "return a signed receipt — Tier 17 trust votes are also a "
            "censorship-attack target (a coerced validator dropping "
            "DOWN votes on a target it favors).",
        )
        receipt = SubmissionReceipt.from_bytes(bytes.fromhex(result["receipt"]))
        self.assertEqual(receipt.tx_hash, tx.tx_hash)
        ok, why = verify_receipt(receipt)
        self.assertTrue(ok, why)
        self.assertEqual(self.issuer_kp._next_leaf, before_leaf + 1)


# ─────────────────────────────────────────────────────────────────────
# Test 3 + 4: opt-out path must NOT consume a receipt-subtree leaf
# ─────────────────────────────────────────────────────────────────────


class TestNoReceiptWhenOptedOut(_BaseRPCFixture):

    def test_rpc_submit_transfer_without_receipt_no_subtree_leaf_consumed(self):
        before_leaf = self.issuer_kp._next_leaf
        tx = self._make_transfer()
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
            # request_receipt omitted (default False)
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        self.assertNotIn(
            "receipt", resp["result"],
            "Default-path transfers must NOT return a receipt — the "
            "receipt-subtree leaf budget is finite (65k leaves total) "
            "and must not be drained by every default-path submit.",
        )
        self.assertEqual(
            self.issuer_kp._next_leaf, before_leaf,
            "No leaf must be consumed when request_receipt is absent.",
        )

    def test_rpc_submit_react_without_receipt_no_subtree_leaf_consumed(self):
        before_leaf = self.issuer_kp._next_leaf
        tx = self._make_react()
        resp = self.server._rpc_submit_react({
            "transaction": tx.serialize(),
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        self.assertNotIn("receipt", resp["result"])
        self.assertEqual(self.issuer_kp._next_leaf, before_leaf)


# ─────────────────────────────────────────────────────────────────────
# Test 4 (HEADLINE): coerced-validator-drop produces evidence
# ─────────────────────────────────────────────────────────────────────


class TestCoercedValidatorDropProducesEvidence(_BaseRPCFixture):
    """The headline test for this fix.

    Threat model: a coerced validator silently admits a transfer into
    its mempool then drops it before block production — leaving no
    on-chain trace of the censorship.  Pre-fix the RPC submit_transfer
    path NEVER consulted receipt_issuer, so the user had no signed
    proof of admission to file as CensorshipEvidenceTx.  Post-fix the
    user holds a SubmissionReceipt the moment admission completes.

    This test asserts the receipt is signed by the validator's
    receipt-subtree key, commits to the dropped tx_hash, and includes
    the admission timestamp (commit_height).  Together those properties
    are what makes the receipt a slashing weapon against the validator
    if the tx never lands on chain within EVIDENCE_INCLUSION_WINDOW.
    """

    def test_coerced_validator_dropping_transfer_produces_evidence(self):
        # 1. User submits a valid transfer with request_receipt=True.
        tx = self._make_transfer()
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
            "request_receipt": True,
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        receipt_hex = resp["result"].get("receipt")
        self.assertIsNotNone(
            receipt_hex,
            "Pre-fix, RPC transfer submissions did not return a "
            "receipt at all — the user had NO evidence weapon for a "
            "subsequent silent drop.  This test must fail on origin/"
            "main and pass on this branch.",
        )

        # 2. Validator (under coercion) drops the tx from mempool —
        # simulate by manually clearing the pool.  The receipt the
        # user already holds must remain a binding commitment.
        self.mempool.pending.clear()

        # 3. The receipt the user holds must be cryptographically
        # binding: signed by the validator's receipt-subtree key,
        # committing to the exact tx_hash and an admission height.
        receipt = SubmissionReceipt.from_bytes(bytes.fromhex(receipt_hex))
        self.assertEqual(
            receipt.tx_hash, tx.tx_hash,
            "Receipt MUST commit to the exact tx_hash so the user can "
            "later prove the validator saw THIS transfer.",
        )
        self.assertEqual(
            receipt.issuer_id, self.proposer.entity_id,
            "Receipt MUST identify the validator who admitted it — "
            "the slash target.",
        )
        self.assertEqual(
            receipt.issuer_root_public_key, self.issuer_kp.public_key,
            "Receipt MUST carry the issuer's receipt-subtree root pubkey "
            "so verification needs no chain state lookup.",
        )
        self.assertGreaterEqual(
            receipt.commit_height, 0,
            "Receipt MUST include the admission height so "
            "EVIDENCE_INCLUSION_WINDOW can be measured from it.",
        )
        # Signature actually verifies under the issuer's key.
        ok, why = verify_receipt(receipt)
        self.assertTrue(
            ok,
            "Receipt signature MUST verify under the issuer's "
            "receipt-subtree root key — otherwise the user cannot use "
            f"it as evidence.  Failure: {why}",
        )


# ─────────────────────────────────────────────────────────────────────
# Test 5: react validation behavior unchanged
# ─────────────────────────────────────────────────────────────────────


class TestReactValidationUnchanged(_BaseRPCFixture):
    """The receipt-issuance refactor must NOT change WHICH txs are
    admitted vs rejected.  Only the post-admission receipt return
    behavior is new.
    """

    def test_unknown_voter_rejected(self):
        stranger = Entity.create(b"trxr_stranger".ljust(32, b"\x00"))
        rtx = create_react_transaction(
            stranger, target=self.target.entity_id, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self.server._rpc_submit_react({
            "transaction": rtx.serialize(),
            "request_receipt": True,
        })
        self.assertFalse(resp["ok"])
        self.assertIn("voter", resp["error"].lower())

    def test_unknown_user_target_rejected(self):
        unknown = b"\xee" * 32
        rtx = create_react_transaction(
            self.sender, target=unknown, target_is_user=True,
            choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
        )
        resp = self.server._rpc_submit_react({
            "transaction": rtx.serialize(),
        })
        self.assertFalse(resp["ok"])
        self.assertIn("target", resp["error"].lower())

    def test_valid_react_admitted(self):
        rtx = self._make_react()
        resp = self.server._rpc_submit_react({
            "transaction": rtx.serialize(),
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        self.assertEqual(self.mempool.get_react_transactions(), [rtx])


# ─────────────────────────────────────────────────────────────────────
# Test 6: transfer validation behavior unchanged
# ─────────────────────────────────────────────────────────────────────


class TestTransferValidationUnchanged(_BaseRPCFixture):

    def test_invalid_nonce_rejected(self):
        # nonce=99 is way ahead of expected nonce 0.
        tx = self._make_transfer(nonce=99)
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
        })
        self.assertFalse(resp["ok"])
        self.assertIn("nonce", resp["error"].lower())

    def test_insufficient_balance_rejected(self):
        # Drain the sender so they cannot afford the transfer.
        self.chain.supply.balances[self.sender.entity_id] = 0
        tx = self._make_transfer(amount=1_000_000)
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
        })
        self.assertFalse(resp["ok"])
        self.assertIn("balance", resp["error"].lower())

    def test_valid_transfer_admitted(self):
        tx = self._make_transfer()
        resp = self.server._rpc_submit_transfer({
            "transaction": tx.serialize(),
        })
        self.assertTrue(resp["ok"], resp.get("error"))
        self.assertIn(tx.tx_hash, self.mempool.pending)


# ─────────────────────────────────────────────────────────────────────
# Test 7: central helper dispatches on tx.__class__
# ─────────────────────────────────────────────────────────────────────


class TestCentralHelperDispatchesOnTxClass(unittest.TestCase):
    """Unit test: the central helper used by the RPC layer must
    dispatch on `tx.__class__` (Option A from the design doc).  Pass a
    MessageTransaction, a TransferTransaction, and a ReactTransaction
    and verify the helper invokes the correct validator + add path
    for each.

    This locks in the structural invariant: there is ONE central
    helper for tx submission, NOT three parallel ones drifting apart.
    """

    def test_dispatches_message_transaction(self):
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        # Build a real MessageTransaction so the helper's idempotency
        # / nonce / validate path exercises the message branch.
        alice = Entity.create(b"disp-alice".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)
        chain.supply.balances[alice.entity_id] = 1_000_000_000
        mempool = Mempool()

        msg = create_transaction(alice, "hi", fee=10_000, nonce=0)
        with mock.patch.object(
            chain, "validate_transaction",
            wraps=chain.validate_transaction,
        ) as mv, mock.patch.object(
            chain, "validate_transfer_transaction",
            wraps=chain.validate_transfer_transaction,
        ) as mvt:
            res = submit_transaction_to_mempool(msg, chain, mempool)
            self.assertTrue(res.ok, res.error)
            self.assertEqual(
                mv.call_count, 1,
                "MessageTransaction must dispatch to validate_transaction",
            )
            self.assertEqual(
                mvt.call_count, 0,
                "MessageTransaction must NOT touch validate_transfer_transaction",
            )

    def test_dispatches_transfer_transaction(self):
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        alice = Entity.create(b"disp-tr-alice".ljust(32, b"\x00"))
        bob = Entity.create(b"disp-tr-bob".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[alice.entity_id] = 1_000_000_000
        mempool = Mempool()

        ttx = create_transfer_transaction(
            alice, recipient_id=bob.entity_id,
            amount=1000, nonce=0, fee=10_000,
        )
        with mock.patch.object(
            chain, "validate_transaction",
            wraps=chain.validate_transaction,
        ) as mv, mock.patch.object(
            chain, "validate_transfer_transaction",
            wraps=chain.validate_transfer_transaction,
        ) as mvt:
            res = submit_transaction_to_mempool(ttx, chain, mempool)
            self.assertTrue(res.ok, res.error)
            self.assertEqual(
                mvt.call_count, 1,
                "TransferTransaction must dispatch to "
                "validate_transfer_transaction",
            )
            self.assertEqual(
                mv.call_count, 0,
                "TransferTransaction must NOT touch validate_transaction",
            )

    def test_dispatches_react_transaction(self):
        from messagechain.network.submission_server import (
            submit_transaction_to_mempool,
        )
        # React activation gate disabled at module load (conftest).
        # Ensure the gate is open here regardless of test order.
        self._orig_h = _config.REACT_TX_HEIGHT
        _config.REACT_TX_HEIGHT = 0
        from messagechain.core import reaction as _rxn
        self._orig_rxn_h = _rxn.REACT_TX_HEIGHT
        _rxn.REACT_TX_HEIGHT = 0
        try:
            voter = Entity.create(b"disp-rx-voter".ljust(32, b"\x00"))
            target = Entity.create(b"disp-rx-target".ljust(32, b"\x00"))
            proposer = Entity.create(b"disp-rx-prop".ljust(32, b"\x00"))
            chain = Blockchain()
            chain.initialize_genesis(proposer)
            register_entity_for_test(chain, proposer)
            register_entity_for_test(chain, voter)
            register_entity_for_test(chain, target)
            chain.supply.balances[voter.entity_id] = 1_000_000_000
            mempool = Mempool()

            rtx = create_react_transaction(
                voter, target=target.entity_id, target_is_user=True,
                choice=REACT_CHOICE_UP, nonce=0, fee=10_000,
            )

            from messagechain.core import reaction as _react_mod
            with mock.patch.object(
                chain, "validate_transaction",
                wraps=chain.validate_transaction,
            ) as mv, mock.patch.object(
                chain, "validate_transfer_transaction",
                wraps=chain.validate_transfer_transaction,
            ) as mvt, mock.patch.object(
                _react_mod, "verify_react_transaction",
                wraps=_react_mod.verify_react_transaction,
            ) as mvr:
                res = submit_transaction_to_mempool(rtx, chain, mempool)
                self.assertTrue(res.ok, res.error)
                self.assertEqual(
                    mv.call_count, 0,
                    "ReactTransaction must NOT touch validate_transaction",
                )
                self.assertEqual(
                    mvt.call_count, 0,
                    "ReactTransaction must NOT touch "
                    "validate_transfer_transaction",
                )
                self.assertGreaterEqual(
                    mvr.call_count, 1,
                    "ReactTransaction must dispatch to "
                    "verify_react_transaction",
                )
        finally:
            _config.REACT_TX_HEIGHT = self._orig_h
            from messagechain.core import reaction as _rxn
            _rxn.REACT_TX_HEIGHT = self._orig_rxn_h


if __name__ == "__main__":
    unittest.main()
