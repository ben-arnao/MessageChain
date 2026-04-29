"""RPC success-path receipt issuance MUST drain the receipt bucket,
not the rejection bucket.

Audit (2026-04-29 / #1): the 1.42.0 ReceiptBudgetTracker introduced a
DEDICATED success-path receipt bucket (`_receipt_buckets`) backed by
`SUBMISSION_RECEIPT_*` constants — distinct from the rejection bucket
(`_rejection_buckets`) backed by `SUBMISSION_REJECTION_*` constants.
The HTTPS submission path (`submission_server.py:1281`) correctly
calls `ctx.receipt_budget_check(client_ip)`.  The RPC submit path
(`server.py:1942`) however still calls
`budget_tracker.rejection_budget_check(client_ip)` — the WRONG
bucket.

Net effect:
  * RPC success-path receipt issuance drains the rejection bucket,
    starving SignedRejection issuance for that IP (and its global
    cap).
  * The dedicated `_receipt_buckets` dict on the RPC surface is dead
    code.
  * An attacker rotating across HTTPS+RPC drains BOTH per-IP buckets
    in a single burst — twice the burst the design intended.

Fix: swap one call in `_resolve_rpc_receipt_issuer`:
`rejection_budget_check` -> `receipt_budget_check`.

These tests pin:
  * a /32 spamming `request_receipt: True` over RPC drains
    `_receipt_buckets[ip]`, NOT `_rejection_buckets[ip]`;
  * exhausting the receipt bucket eventually causes the receipt to
    be omitted from the response (silent downgrade);
  * the global cap still fires when the per-IP receipt bucket is
    exhausted (defense against IPv6-rotation drain).
"""

from __future__ import annotations

import unittest

import messagechain.config as _config_mod
import messagechain.core.mempool as _mempool_mod
from tests import register_entity_for_test
from messagechain.config import (
    SUBMISSION_RECEIPT_BURST,
    SUBMISSION_REJECTION_BURST,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.network.submission_receipt import ReceiptIssuer


def _make_receipt_issuer(seed_tag: bytes, entity_id: bytes) -> ReceiptIssuer:
    """Build a real (small-tree) ReceiptIssuer for tests."""
    kp = KeyPair.generate(
        seed=b"rpc-correct-bucket-" + seed_tag,
        height=4,
    )
    return ReceiptIssuer(entity_id, kp)


class _BudgetTestBase(unittest.TestCase):
    """Common setUp/tearDown — bumps the mempool per-sender ancestor
    cap so a single funded entity can submit many receipted txs in one
    test without the per-sender mempool defense intervening.
    """

    def setUp(self):
        self._orig_max_anc = _mempool_mod.MEMPOOL_MAX_ANCESTORS
        _mempool_mod.MEMPOOL_MAX_ANCESTORS = 10_000
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
    """Spin up a minimal Server stub for RPC submit tests (mirrors the
    helper used by test_rpc_receipt_budget.py — same shape, separate
    seeds so xdist workers don't collide on the receipt subtree)."""
    from server import Server
    from messagechain.network.submission_server import (
        ReceiptBudgetTracker,
    )

    alice = Entity.create(seed, tree_height=6)
    chain = Blockchain()
    chain.initialize_genesis(
        alice, allocation_table={alice.entity_id: 10_000_000},
    )
    register_entity_for_test(chain, alice)
    mempool = Mempool(per_sender_limit=10_000)

    srv = Server.__new__(Server)
    srv.blockchain = chain
    srv.mempool = mempool
    srv.receipt_issuer = _make_receipt_issuer(seed, alice.entity_id)
    srv.receipt_budget_tracker = ReceiptBudgetTracker()
    srv._track_seen_tx = lambda h: None

    def _drop_coro(coro, *_a, **_kw):
        try:
            coro.close()
        except Exception:
            pass

    srv._schedule_coro_threadsafe = _drop_coro
    return srv, alice


def _new_signed_tx(entity: Entity, chain: Blockchain, *, nonce: int) -> bytes:
    tx = create_transaction(
        entity, f"rpc-correct-bucket-{nonce}", nonce=nonce,
        fee=10_000,
        current_height=chain.height + 1,
    )
    return tx.serialize()


class TestRpcReceiptDrainsReceiptBucketNotRejectionBucket(_BudgetTestBase):
    """Headline regression: a /32 spamming `request_receipt: True`
    over RPC must drain `_receipt_buckets[ip]`, NOT
    `_rejection_buckets[ip]`.  Pre-fix this drained the rejection
    bucket, leaving `_receipt_buckets` empty (dead code on RPC) and
    silently halving the design's two-burst defense across surfaces.
    """

    def test_rpc_receipted_submit_drains_receipt_bucket(self):
        srv, alice = _make_server_with_chain(
            b"correct-bucket-receipt".ljust(32, b"\x00"),
        )
        ip = "10.99.0.1"
        tracker = srv.receipt_budget_tracker

        # Pre-condition: both bucket dicts are empty for this IP.
        self.assertNotIn(ip, tracker._receipt_buckets)
        self.assertNotIn(ip, tracker._rejection_buckets)

        # One receipted submit over RPC.
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=0)
        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip=ip,
        )

        # Submission succeeded with a receipt.
        self.assertTrue(resp["ok"], resp)
        self.assertIn("receipt", resp["result"])

        # CORE INVARIANT: the RECEIPT bucket got created (and
        # consumed) — the REJECTION bucket was NOT touched.  Pre-fix
        # this asserts in reverse.
        self.assertIn(
            ip, tracker._receipt_buckets,
            "RPC success-path receipt issuance did NOT consult the "
            "receipt bucket — `_receipt_buckets` is dead code on RPC. "
            "Fix: swap `rejection_budget_check` -> `receipt_budget_check` "
            "in _resolve_rpc_receipt_issuer.",
        )
        self.assertNotIn(
            ip, tracker._rejection_buckets,
            "RPC success-path receipt issuance drained the WRONG "
            "bucket (rejection).  This starves SignedRejection issuance "
            "and lets an attacker rotating across HTTPS+RPC drain both "
            "per-IP buckets in one burst.",
        )

    def test_rpc_receipt_bucket_drains_to_zero_then_silent_downgrade(self):
        """Exhausting the receipt bucket via RPC eventually causes the
        receipt to be omitted from the response — silent downgrade,
        same shape as HTTPS.  Confirms the gate fires when the
        receipt bucket (not the rejection bucket) hits zero."""
        srv, alice = _make_server_with_chain(
            b"correct-bucket-drain".ljust(32, b"\x00"),
        )
        ip = "10.99.0.2"
        tracker = srv.receipt_budget_tracker

        # Submit SUBMISSION_RECEIPT_BURST + 2 receipted txs.
        # Pre-fix: the rejection bucket (smaller burst) drains first,
        # so the silent downgrade trips at SUBMISSION_REJECTION_BURST,
        # not SUBMISSION_RECEIPT_BURST — which is the bug.
        # Post-fix: receipts are issued for the first
        # SUBMISSION_RECEIPT_BURST submits; the rest fall through.
        receipt_count = 0
        n_total = SUBMISSION_RECEIPT_BURST + 2
        for nonce in range(n_total):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)
            if resp["result"].get("receipt"):
                receipt_count += 1

        # Receipt bucket got drained (the bucket was created and now
        # has < 1 token after refill across the loop's wall time).
        self.assertIn(ip, tracker._receipt_buckets)
        # Rejection bucket was never touched.
        self.assertNotIn(ip, tracker._rejection_buckets)

        # We saw at least one budget-drop in the loop (last submit
        # in the loop crossed the empty threshold).
        self.assertLess(receipt_count, n_total)
        # And the count is bounded by the receipt-burst constant
        # (+1 for fractional refill across wall time).
        self.assertLessEqual(receipt_count, SUBMISSION_RECEIPT_BURST + 1)

        # Final probe: another submit from the SAME IP returns no
        # receipt.
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=n_total)
        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip=ip,
        )
        self.assertTrue(resp["ok"])
        self.assertNotIn("receipt", resp["result"])


class TestRpcReceiptGlobalCapStillFires(_BudgetTestBase):
    """The global cap (RECEIPT_GLOBAL_BURST + refill) is the IPv6 /
    botnet-rotation defense — it must still fire on the RPC success-
    path.  Cheap version: drain the global bucket directly on the
    tracker (avoids the cost of running RECEIPT_GLOBAL_BURST=6553
    real RPC submits with WOTS+ verify) and assert the next RPC
    submit comes back receipt-less even from a fresh /32.
    """

    def test_global_cap_fires_on_rpc_when_globally_exhausted(self):
        srv, alice = _make_server_with_chain(
            b"correct-bucket-global".ljust(32, b"\x00"),
        )
        tracker = srv.receipt_budget_tracker

        # Drain the global bucket directly.  This is the same gate
        # that the per-IP receipt-budget path consults via
        # `_consume_global_locked`, so a fully-empty global bucket
        # MUST cause the next receipt_budget_check to fail regardless
        # of per-IP state.
        with tracker._buckets_lock:
            tracker._global_bucket._refill()
            tracker._global_bucket.tokens = 0.0

        # Submit a receipted RPC tx from a FRESH IP.  Per-IP bucket
        # would normally allow it (full burst), but the global cap
        # is empty — receipt MUST be omitted.
        fresh_ip = "10.99.123.1"
        tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=0)
        resp = srv._rpc_submit_transaction(
            {"transaction": tx_blob, "request_receipt": True},
            client_ip=fresh_ip,
        )

        self.assertTrue(resp["ok"], resp)
        self.assertNotIn(
            "receipt", resp["result"],
            "global cap did not fire on the RPC success-path: "
            "an empty global bucket should silently drop the receipt "
            "regardless of per-IP state, but a receipt was issued.",
        )

        # And the per-IP RECEIPT bucket for the fresh IP must NOT be
        # debited (per-IP-first-then-global-no-double-spend rule:
        # global denial leaves the per-IP bucket untouched, so the
        # bucket entry should not even be created on this code path).
        self.assertNotIn(fresh_ip, tracker._rejection_buckets)
        # Receipt bucket for fresh_ip will exist (it was peeked) but
        # must not have lost its leading token to a global-denied
        # request.
        bucket = tracker._receipt_buckets.get(fresh_ip)
        if bucket is not None:
            bucket._refill()
            self.assertGreaterEqual(
                bucket.tokens, bucket.max_tokens - 0.01,
                "global denial must not consume a per-IP receipt "
                "token (no-double-spend invariant violated)",
            )


class TestRpcReceiptRejectionBucketUnaffectedBySuccessPath(_BudgetTestBase):
    """The RPC success path must NOT consume a rejection-bucket token —
    that's the bug.  Confirms surgical bucket targeting: a flood of
    receipted-success submissions leaves the rejection bucket fully
    available for actual SignedRejection issuance later.
    """

    def test_success_path_preserves_rejection_bucket(self):
        srv, alice = _make_server_with_chain(
            b"correct-bucket-preserve".ljust(32, b"\x00"),
        )
        ip = "10.99.0.3"
        tracker = srv.receipt_budget_tracker

        # Spam SUBMISSION_RECEIPT_BURST + 1 receipted submits.  Pre-
        # fix this drains the rejection bucket; post-fix only the
        # receipt bucket moves.
        for nonce in range(SUBMISSION_RECEIPT_BURST + 1):
            tx_blob = _new_signed_tx(alice, srv.blockchain, nonce=nonce)
            resp = srv._rpc_submit_transaction(
                {"transaction": tx_blob, "request_receipt": True},
                client_ip=ip,
            )
            self.assertTrue(resp["ok"], resp)

        # The rejection bucket must still be at full burst — never
        # touched by the success path.  An honest client could now
        # opt into a SignedRejection from a malformed submission and
        # get the full SUBMISSION_REJECTION_BURST allowance.
        self.assertNotIn(
            ip, tracker._rejection_buckets,
            "RPC success-path receipt issuance silently drained the "
            "rejection bucket — an honest client requesting a "
            "SignedRejection from this IP would now be denied "
            "incorrectly.",
        )


if __name__ == "__main__":
    unittest.main()
