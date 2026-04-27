"""Per-IP receipt-budget gate on the RPC `submit_transaction` path.

Audit (2026-04-27): the just-shipped 1.28.4 fix made the RPC
`request_receipt` flag opt-in, but it has NO per-IP budget cap.  An
attacker over RPC carrying `request_receipt: True` burns one WOTS+
leaf per submission from the validator's RECEIPT_SUBTREE (65,536
leaves at height 16).  The HTTPS surface already defends this
vector via `_HandlerContext.rejection_budget_check(ip)` — RPC must
mirror the same budget, sharing the same buckets so an attacker
cannot drain twice by splitting traffic across HTTPS+RPC.

Fix: thread `client_ip` from `_process_rpc` into
`_rpc_submit_transaction`; consult the shared rejection-budget
bucket when `request_receipt=True`; on exhaustion, drop the
issuer to None and proceed (submission still processes; the
attacker just doesn't get a receipt and no leaf burns).

These tests pin:
  * fresh-IP within-budget submits return a receipt;
  * exhaustion-state submits succeed but return NO receipt;
  * the audit headline — sustained RPC-only spam can't drain the
    receipt subtree;
  * HTTPS and RPC share the same per-IP buckets;
  * `request_receipt=False` is unaffected;
  * a warning is logged when the budget kicks in.
"""

from __future__ import annotations

import unittest

import messagechain.config as _config_mod
import messagechain.core.mempool as _mempool_mod
from tests import register_entity_for_test
from messagechain.config import (
    SUBMISSION_REJECTION_BURST,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import ReceiptIssuer


def _make_receipt_issuer(seed_tag: bytes, entity_id: bytes) -> ReceiptIssuer:
    """Build a real (small-tree) ReceiptIssuer for tests.

    Tree height 4 (16 leaves) keeps per-test cost low while exercising
    the same code path that production uses.  Tests that exhaust the
    budget cap their N below the tree's leaf count so we don't OOM the
    issuer's leaf cursor inside the budget gate's own test.
    """
    kp = KeyPair.generate(
        seed=b"receipt-subtree-rpc-budget-" + seed_tag,
        height=4,
    )
    return ReceiptIssuer(entity_id, kp)


class _BudgetTestBase(unittest.TestCase):
    """Common setUp/tearDown — bumps the mempool per-sender ancestor
    cap so a single funded entity (alice) can submit >5 receipted txs
    in one test without the *separate* per-sender mempool defense
    intervening.  We're isolating the receipt-budget gate, not
    co-testing mempool admission.
    """

    def setUp(self):
        self._orig_max_anc = _mempool_mod.MEMPOOL_MAX_ANCESTORS
        _mempool_mod.MEMPOOL_MAX_ANCESTORS = 10_000
        # Defend against cross-test config leaks (xdist workers
        # share a process across tests, and tests that toggle
        # DEVNET / PINNED_GENESIS_HASH for their own assertions
        # don't always restore on failure).  Force devnet posture
        # for the duration of this test and restore in tearDown.
        self._orig_pinned = _config_mod.PINNED_GENESIS_HASH
        self._orig_devnet = _config_mod.DEVNET
        self._orig_network = _config_mod.NETWORK_NAME
        _config_mod.PINNED_GENESIS_HASH = None
        _config_mod.DEVNET = True
        _config_mod.NETWORK_NAME = "devnet"

    def tearDown(self):
        _mempool_mod.MEMPOOL_MAX_ANCESTORS = self._orig_max_anc
        _config_mod.PINNED_GENESIS_HASH = self._orig_pinned
        _config_mod.DEVNET = self._orig_devnet
        _config_mod.NETWORK_NAME = self._orig_network


def _make_server_with_chain(seed: bytes):
    """Spin up a minimally-viable Server stub for RPC submit tests.

    Uses Server.__new__ to skip the heavy network/disk setup.  We only
    need: blockchain (with a registered entity so submissions
    validate), mempool, receipt_issuer, receipt_budget_tracker, and
    enough plumbing for `_rpc_submit_transaction` to relay the tx.

    Returns (server, alice).  Tests bump MEMPOOL_MAX_ANCESTORS in
    `_BudgetTestBase.setUp` so a single funded entity can submit
    enough txs to exhaust the receipt budget (default cap is 5
    pending per sender, which would otherwise mask the gate).
    """
    from server import Server
    from messagechain.network.submission_server import (
        ReceiptBudgetTracker,
    )

    # Tree height 6 (64 leaves) so alice can sign enough messages to
    # exhaust the budget (3) AND test post-budget behavior across
    # ~20 submits without running out of WOTS+ leaves.  Tests'
    # default MERKLE_TREE_HEIGHT=4 (16 leaves) is too tight.
    alice = Entity.create(seed, tree_height=6)
    chain = Blockchain()
    # Generous genesis allocation so tests that submit transfer +
    # react in addition to messages don't blow alice's spendable
    # balance budget (default GENESIS_ALLOCATION = 10k, which is too
    # tight once we add a 10-token-floor transfer + REACT_FEE_FLOOR).
    chain.initialize_genesis(alice, allocation_table={alice.entity_id: 10_000_000})
    register_entity_for_test(chain, alice)
    # Roomy per-sender cap so a test that submits >5 receipted txs
    # from one funded entity doesn't bounce on the mempool's
    # default 5-per-sender throttle (which is a separate defense
    # from the receipt budget — the test wants to isolate the
    # budget-gate effect, not entangle it with mempool admission).
    mempool = Mempool(per_sender_limit=10_000)

    srv = Server.__new__(Server)
    srv.blockchain = chain
    srv.mempool = mempool
    srv.receipt_issuer = _make_receipt_issuer(seed, alice.entity_id)
    # Production wiring constructs this in Server.__init__; we are
    # bypassing that, so wire it explicitly so the gate is exercised.
    srv.receipt_budget_tracker = ReceiptBudgetTracker()
    # Stub helpers the RPC handler calls after admission.
    srv._track_seen_tx = lambda h: None
    # Close any incoming coroutine so we don't leak an "un-awaited"
    # RuntimeWarning each time the handler tries to relay.
    def _drop_coro(coro, *_a, **_kw):
        try:
            coro.close()
        except Exception:
            pass
    srv._schedule_coro_threadsafe = _drop_coro
    # Pending-nonce helper — RPC submit consults this through
    # validate_transaction internally; the chain handles real lookup.
    return srv, alice


def _new_signed_tx(entity: Entity, chain: Blockchain, *, nonce: int) -> bytes:
    """Build a real signed MessageTransaction and return its serialized bytes.

    `_rpc_submit_transaction` deserializes from `params["transaction"]`
    so the test mirrors the wire path exactly.
    """
    tx = create_transaction(
        entity, f"rpc-budget-{nonce}", nonce=nonce,
        fee=10_000,
        current_height=chain.height + 1,
    )
    return tx.serialize()


class TestRpcReceiptBudgetWithinLimit(_BudgetTestBase):
    """A single submit with `request_receipt=True` from a fresh IP
    must succeed AND return a receipt — the budget gate kicks in only
    when the bucket is empty, never on the first call."""

    def test_request_receipt_within_budget_returns_receipt(self):
        srv, alice = _make_server_with_chain(b"r-budget-fresh".ljust(32, b"\x00"))
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=0)

        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip="10.0.0.1",
        )

        self.assertTrue(resp["ok"], resp)
        self.assertIn("receipt", resp["result"])
        self.assertTrue(resp["result"]["receipt"])


class TestRpcReceiptBudgetSilentDowngrade(_BudgetTestBase):
    """When the per-IP rejection-budget bucket is exhausted, the
    submission MUST still process but NO receipt is issued and NO
    leaf is consumed.  Mirrors the HTTPS silent-downgrade semantics."""

    def test_request_receipt_over_budget_drops_issuer_silently(self):
        srv, alice = _make_server_with_chain(b"r-budget-over".ljust(32, b"\x00"))
        ip = "10.0.0.2"

        # Burn through the burst.  SUBMISSION_REJECTION_BURST tokens
        # available; we send N+2 submissions to make sure we cross
        # the depleted threshold.  All from alice (genesis-funded);
        # the test mempool was constructed with a roomy per-sender
        # cap so this doesn't bounce on a separate defense.
        receipt_count = 0
        nonce = 0
        for i in range(SUBMISSION_REJECTION_BURST + 2):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            nonce += 1
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)
            if resp["result"].get("receipt"):
                receipt_count += 1

        # The first ≤ SUBMISSION_REJECTION_BURST submits issued a
        # receipt; the rest fell through to the silent-downgrade path.
        # Allow +1 slack for the bucket's fractional refill across the
        # test's wall time.
        self.assertLessEqual(receipt_count, SUBMISSION_REJECTION_BURST + 1)
        # And we definitely saw at least one budget-drop (last submit
        # in the loop must have hit the empty bucket).
        self.assertLess(receipt_count, SUBMISSION_REJECTION_BURST + 2)

        # Final probe: one more from the SAME IP returns no receipt.
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip=ip,
        )
        self.assertTrue(resp["ok"])
        self.assertNotIn("receipt", resp["result"])


class TestRpcAttackerCannotDrainReceiptSubtree(_BudgetTestBase):
    """Headline test: simulate the audit's attack scenario — sustained
    receipted submissions from one RPC IP — and assert the receipt
    subtree's leaf cursor barely advances.  Without the budget gate
    the attacker could burn 21k leaves/day from one IP."""

    def test_attacker_cannot_drain_receipt_subtree_via_rpc(self):
        srv, alice = _make_server_with_chain(b"r-budget-drain".ljust(32, b"\x00"))
        ip = "10.0.0.3"
        # Receipt subtree leaf counter before the spam.
        leaves_before = srv.receipt_issuer.subtree_keypair._next_leaf

        # Spam N=15 receipted submits from one IP.  Pre-fix this
        # consumed 15 leaves.  Post-fix, only the first
        # SUBMISSION_REJECTION_BURST consume leaves; the rest are
        # budget-dropped (issuer=None, no leaf consumption).
        n_spam = 15
        for nonce in range(n_spam):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)

        leaves_after = srv.receipt_issuer.subtree_keypair._next_leaf
        leaves_consumed = leaves_after - leaves_before

        # Strict cap: leaves consumed cannot exceed
        # SUBMISSION_REJECTION_BURST + a small slack (the bucket may
        # refill ~0.05/sec * test wall time).  Definitely fewer than
        # the n_spam attempts.
        self.assertLess(
            leaves_consumed, n_spam,
            f"attacker drained {leaves_consumed} leaves in {n_spam} "
            f"spam submits — budget gate is not effective",
        )
        self.assertLessEqual(
            leaves_consumed, SUBMISSION_REJECTION_BURST + 1,
            f"leaves consumed ({leaves_consumed}) exceeds "
            f"rejection-burst ceiling ({SUBMISSION_REJECTION_BURST})",
        )


class TestHttpsAndRpcShareBudgetBuckets(_BudgetTestBase):
    """The HTTPS `_HandlerContext` and the RPC `Server` MUST consult
    the SAME per-IP rejection-budget buckets — otherwise an attacker
    can split traffic across both surfaces and drain twice.  The
    invariant: alternating HTTPS-style budget consumption with RPC
    submission decrements one shared counter."""

    def test_https_and_rpc_share_budget_buckets(self):
        from messagechain.network.submission_server import _HandlerContext

        srv, alice = _make_server_with_chain(b"r-budget-share".ljust(32, b"\x00"))
        ip = "10.0.0.4"

        # The Server must expose a tracker that _HandlerContext can
        # plug into.  Same instance, same dict of buckets.
        self.assertTrue(
            hasattr(srv, "receipt_budget_tracker"),
            "Server must expose receipt_budget_tracker so HTTPS and "
            "RPC surfaces consult the same per-IP buckets.",
        )

        ctx = _HandlerContext(
            blockchain=srv.blockchain, mempool=srv.mempool,
            relay_callback=None,
            receipt_issuer=srv.receipt_issuer,
            budget_tracker=srv.receipt_budget_tracker,
        )

        # Drain the bucket from the HTTPS side.
        for _ in range(SUBMISSION_REJECTION_BURST):
            ctx.rejection_budget_check(ip)

        # The same bucket should now be empty when consulted from the
        # RPC side.  Probe by attempting one receipted RPC submit and
        # asserting no receipt comes back.
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=0)
        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip=ip,
        )
        self.assertTrue(resp["ok"])
        self.assertNotIn(
            "receipt", resp["result"],
            "HTTPS-drained bucket did not affect the RPC path — the "
            "budget buckets are NOT shared, defeating the cross-surface "
            "drain defense.",
        )


class TestRequestReceiptFalseUnchanged(_BudgetTestBase):
    """When `request_receipt` is False (the default), the budget gate
    must NOT consume a token.  Otherwise non-receipted RPC traffic
    would slowly drain the budget and break receipted clients on the
    same IP."""

    def test_request_receipt_false_unchanged_behavior(self):
        srv, alice = _make_server_with_chain(b"r-budget-false".ljust(32, b"\x00"))
        ip = "10.0.0.5"

        # Many non-receipted submits.
        for nonce in range(10):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": False},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)
            self.assertNotIn("receipt", resp["result"])

        # The bucket for this IP must still be at full burst — we did
        # not touch it.  Probe by reading the tracker directly.
        tracker = srv.receipt_budget_tracker
        bucket = tracker._rejection_buckets.get(ip)
        self.assertIsNone(
            bucket,
            "request_receipt=False traffic must NOT create or consume "
            "a rejection-budget bucket — bucket should be absent.",
        )


class TestWarningLogOnBudgetExhaustion(_BudgetTestBase):
    """When the budget kicks in and an issuer is dropped, log a
    warning so the operator can correlate complaints from receipted
    clients with the budget event.  Per-IP rate-limited (or
    unconditional, per task spec)."""

    def test_warning_log_fires_on_budget_exhaustion(self):
        srv, alice = _make_server_with_chain(b"r-budget-warn".ljust(32, b"\x00"))
        ip = "10.0.0.6"

        # Exhaust budget first — alice with sequential nonces, the
        # roomy mempool per-sender cap from the test helper allows
        # >5 pending pre-confirmation submits.
        for nonce in range(SUBMISSION_REJECTION_BURST):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )

        # Now the over-budget submit should log a warning.
        # Logger name is `messagechain.server` (server.py uses
        # `logger = logging.getLogger("messagechain.server")`).
        with self.assertLogs("messagechain.server", level="WARNING") as cm:
            tx_blob = _new_signed_tx(
                alice, srv.blockchain, nonce=SUBMISSION_REJECTION_BURST,
            )
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )

        self.assertTrue(resp["ok"])
        # At least one warning must mention "receipt" or "budget".
        self.assertTrue(
            any(
                ("receipt" in m.lower() or "budget" in m.lower())
                for m in cm.output
            ),
            f"expected receipt-budget warning, got: {cm.output}",
        )


class TestRpcSubmitTransferAndReactShareGate(_BudgetTestBase):
    """The same receipt-budget gate must apply to `_rpc_submit_transfer`
    and `_rpc_submit_react` — the sibling fix routed those handlers
    through `submit_transaction_to_mempool` and they now also accept
    `request_receipt: True`.  Without the gate an attacker draining
    via transfers / react votes would still drain the same subtree
    (it's one shared 65k-leaf pool, regardless of which RPC flavor
    burns it).

    A single shared bucket per IP guards all three surfaces: even an
    attacker alternating between message + transfer + react submits
    can't get more than SUBMISSION_REJECTION_BURST receipts before
    the silent-downgrade kicks in.
    """

    def test_transfer_path_consumes_same_bucket_as_message(self):
        from messagechain.core.transfer import create_transfer_transaction
        srv, alice = _make_server_with_chain(b"r-budget-mix-tr".ljust(32, b"\x00"))
        bob = Entity.create(b"r-budget-mix-tr-bob".ljust(32, b"\x00"))
        register_entity_for_test(srv.blockchain, bob)
        ip = "10.0.0.7"

        # Exhaust budget via the MESSAGE surface.
        for nonce in range(SUBMISSION_REJECTION_BURST):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)

        # Now a TRANSFER from the same IP must NOT receive a receipt
        # (shared bucket is empty).  Tiny amount + minimal fee — alice
        # only has GENESIS_ALLOCATION (10k) on chain, so the transfer
        # has to fit inside that budget after the message fees we
        # already paid.  Both message admission and transfer admission
        # consult chain-only `spendable_balance` (mempool charges
        # aren't deducted until block production), so 10k is enough
        # for one transfer regardless of pending messages.
        transfer = create_transfer_transaction(
            entity=alice,
            recipient_id=bob.entity_id,
            amount=100,
            fee=10_000,
            nonce=SUBMISSION_REJECTION_BURST,
        )
        resp = srv._rpc_submit_transfer(
            {"transaction": transfer.serialize(), "request_receipt": True},
            client_ip=ip,
        )
        self.assertTrue(resp["ok"], resp)
        self.assertNotIn(
            "receipt", resp["result"],
            "transfer surface did NOT honor the shared receipt-budget "
            "bucket — an attacker can drain via the transfer surface "
            "even after the message surface ran dry.",
        )

    def test_react_path_consumes_same_bucket_as_message(self):
        # ReactTransaction has its own activation gate / target shape;
        # the simpler shared-bucket invariant we want to prove is that
        # the gate fires.  Use the same scaffolding as the transfer
        # test but with a react tx.
        from messagechain.core.reaction import (
            create_react_transaction,
            REACT_CHOICE_UP,
        )
        # Force the react activation height to 0 so the test doesn't
        # need to advance the chain past REACT_TX_HEIGHT.
        import messagechain.core.reaction as _reaction_mod
        orig_height = _reaction_mod.REACT_TX_HEIGHT
        _reaction_mod.REACT_TX_HEIGHT = 0
        try:
            srv, alice = _make_server_with_chain(b"r-budget-mix-rx".ljust(32, b"\x00"))
            bob = Entity.create(b"r-budget-mix-rx-bob".ljust(32, b"\x00"))
            register_entity_for_test(srv.blockchain, bob)
            ip = "10.0.0.8"

            # Exhaust budget via MESSAGE.
            for nonce in range(SUBMISSION_REJECTION_BURST):
                tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
                resp = srv._rpc_submit_transaction(
                    {"transaction": tx_blob, "request_receipt": True},
                    client_ip=ip,
                )
                self.assertTrue(resp["ok"], resp)

            # React from same IP must come back receipt-less.
            react = create_react_transaction(
                entity=alice,
                target=bob.entity_id,
                target_is_user=True,
                choice=REACT_CHOICE_UP,
                fee=10_000,
                nonce=SUBMISSION_REJECTION_BURST,
            )
            resp = srv._rpc_submit_react(
                {"transaction": react.serialize(), "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)
            self.assertNotIn(
                "receipt", resp["result"],
                "react surface did NOT honor the shared receipt-budget "
                "bucket — an attacker can drain via the react surface "
                "even after the message surface ran dry.",
            )
        finally:
            _reaction_mod.REACT_TX_HEIGHT = orig_height


if __name__ == "__main__":
    unittest.main()
