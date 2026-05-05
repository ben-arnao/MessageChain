"""Critical-severity audit fix -- round 14 (2026-04-28).

CRITICAL: default-success receipt issuance is uncapped; one /24 can
permanently brick a validator's censorship-evidence pipeline.

`messagechain/network/submission_server.py:472-479` -- the message-
path success branch unconditionally calls `receipt_issuer.issue(tx_hash)`
with NO `_budget_tracker` consultation.  The
`RECEIPT_GLOBAL_BURST=6553` / `REFILL_PER_SEC=0.05` cap (lines
134/1471) only fires inside the opt-in `rejection_budget_check` /
`ack_budget_check` paths.

Attack: pay `MIN_FEE * 65k` floor-fee txs at the standard
`SUBMISSION_RATE_LIMIT_PER_SEC=2` / `SUBMISSION_BURST=10` per-IP rate.
From a /24 that drains in minutes.  Once the receipt subtree's WOTS+
leaves are exhausted, `KeyPair.sign` raises `Key exhausted` -- caught
silently, and the validator can NEVER issue another censorship-
evidence receipt for the rest of that subtree's natural lifespan.
Combined with the silent-drop gap, this neutralizes the only working
remedy.

Adversary defended: validator collusion (PRIMARY).

CLAUDE.md anchor: "a tx that is well-formed, pays at least the per-
byte floor, and fits the byte budget cannot be suppressed by anything
weaker than a full validator-set majority actively colluding *and*
willing to absorb the slashing risk that exposed collusion produces."
A bricked receipt-issuer means colluding validators get to drop
messages without ever producing slashable evidence.

Fix: gate the success-path `receipt_issuer.issue` call through a
DEDICATED per-IP + global cap on the shared `ReceiptBudgetTracker`
(separate bucket dict from rejection / ack so receipt issuance
isn't competing with them, but feeding the same global cap that
defends the underlying receipt-subtree from total drain).  Fail-open
semantics on exhaustion: tx still admitted; receipt_hex is empty
(same shape as the "broken issuer" path that already exists).

These tests pin:
  (a) per-IP rate-limiting fires before draining the receipt subtree
      on the success path (single-IP attacker can't burn more than
      the per-IP burst before the cap kicks in);
  (b) global cap fires across IPs (a botnet rotating through fresh
      source IPs can't drain more than RECEIPT_GLOBAL_BURST receipts
      total);
  (c) when budget is exhausted, the success path falls open
      -- tx still admitted, just no receipt issued (same fail-open
      semantics as the broken-issuer path).
"""

from __future__ import annotations

import unittest

from messagechain.config import MIN_FEE
from messagechain.network.submission_server import (
    ReceiptBudgetTracker,
    RECEIPT_GLOBAL_BURST,
)


class TestReceiptBudgetCheckPerIPCap(unittest.TestCase):
    """Per-IP cap -- a single attacker IP must not drain more than
    its per-IP burst of receipt-subtree leaves on the success path.

    Without this gate, an attacker's submissions at the standard
    SUBMISSION_BURST=10 per-IP rate burn one leaf per success in a
    tight loop and exhaust the 65k-leaf RECEIPT_SUBTREE in minutes.
    """

    def test_per_ip_cap_fires_before_draining_subtree(self):
        tracker = ReceiptBudgetTracker()
        ip = "10.0.0.1"

        granted = 0
        # 50 attempts is comfortably above any reasonable per-IP
        # receipt burst -- if the cap doesn't fire, the test fails
        # because granted == 50 (== unbounded).
        for _ in range(50):
            if tracker.receipt_budget_check(ip):
                granted += 1

        # Per-IP burst MUST be << 50 -- the gate must have fired.
        self.assertLess(
            granted, 50,
            "per-IP receipt-budget cap did NOT fire -- a single IP "
            "drained an unbounded number of receipt-subtree leaves "
            "in 50 calls.  Pre-fix this lets one /24 brick the "
            "validator's censorship-evidence pipeline in minutes.",
        )


class TestReceiptBudgetCheckGlobalCap(unittest.TestCase):
    """Global cap -- a botnet rotating fresh source IPs must not drain
    more than RECEIPT_GLOBAL_BURST receipt-subtree leaves regardless of
    how many distinct IPs the attacker rotates through.

    Mirrors the existing rejection/ack global-cap defense for the
    success-path receipt issuance.
    """

    def test_global_cap_bounds_total_receipts_across_ips(self):
        # max_tracked_ips ≥ n_ips so we don't trip the per-IP bucket
        # LRU eviction path (quadratic scan); we're testing the global
        # cap, not eviction.
        tracker = ReceiptBudgetTracker(max_tracked_ips=4096 + 256)
        # Rotate through enough IPs that, without a global cap, a
        # per-IP-only defense would let the attacker drain far more
        # than RECEIPT_GLOBAL_BURST leaves total.  Each fresh IP
        # gets a fresh per-IP burst; with 4096 IPs * 3-leaf burst
        # = 12,288 leaves -- nearly twice RECEIPT_GLOBAL_BURST.
        granted = 0
        n_ips = 4096
        # A handful of attempts per IP is enough to exhaust each
        # fresh per-IP burst; we only care about the global ceiling.
        per_ip_attempts = 4
        for ip_n in range(n_ips):
            ip = f"10.{(ip_n >> 8) & 0xff}.{ip_n & 0xff}.1"
            for _ in range(per_ip_attempts):
                if tracker.receipt_budget_check(ip):
                    granted += 1

        self.assertLessEqual(
            granted, RECEIPT_GLOBAL_BURST,
            f"global receipt cap did NOT bound total issuance: "
            f"{granted} receipts granted across {n_ips} IPs, "
            f"limit is RECEIPT_GLOBAL_BURST={RECEIPT_GLOBAL_BURST}. "
            f"Botnet rotation drains the whole subtree.",
        )


class TestReceiptBudgetCheckSharesGlobalBucketWithRejection(unittest.TestCase):
    """The dedicated receipt bucket MUST share the SAME global bucket
    as the rejection / ack buckets.

    Rationale: every issuance path (receipt, rejection, ack) burns one
    leaf from the same finite RECEIPT_SUBTREE.  A separate global cap
    per family would let an attacker drain ~3x the intended ceiling
    by alternating across paths.  The single shared global cap is
    exactly the cross-path defense.
    """

    def test_receipt_bucket_consumes_same_global_as_rejection(self):
        # max_tracked_ips comfortably exceeds RECEIPT_GLOBAL_BURST so the
        # drain loop never triggers per-IP-bucket LRU eviction (an O(N)
        # scan that turns this test quadratic at the default 4096 cap).
        tracker = ReceiptBudgetTracker(max_tracked_ips=RECEIPT_GLOBAL_BURST + 256)
        # Drain the global bucket via the rejection path (using fresh
        # IPs so per-IP cap never fires before global).
        drained = 0
        n_ips = RECEIPT_GLOBAL_BURST + 256
        for ip_n in range(n_ips):
            ip = f"172.16.{(ip_n >> 8) & 0xff}.{ip_n & 0xff}"
            if tracker.rejection_budget_check(ip):
                drained += 1
            if drained >= RECEIPT_GLOBAL_BURST:
                break

        self.assertGreaterEqual(
            drained, 1,
            "rejection bucket gave zero tokens on fresh IPs",
        )

        # Now the receipt bucket on a totally fresh IP should ALSO be
        # blocked by the shared global cap -- if the receipt bucket
        # had its own private global, this would fail because that
        # one is still full.
        for ip_n in range(50):
            ip = f"192.168.99.{ip_n}"
            tracker.receipt_budget_check(ip)
        # Hard to assert exact zero (the rejection-drain loop may not
        # have hit the exact ceiling), but the receipt-side issuance
        # should be at most the per-IP burst on the very last IP --
        # nowhere near "unbounded".  More robust: directly check the
        # global bucket has fewer tokens after the receipt calls than
        # before, IF it had any.  Simpler: confirm that issuing
        # receipts from a fresh IP after global drain returns False
        # at least once (it will, because per-IP burst is small).
        post_drain_grants = 0
        for ip_n in range(100):
            ip = f"192.168.100.{ip_n}"
            if tracker.receipt_budget_check(ip):
                post_drain_grants += 1
        # If the global cap is shared, post_drain_grants must be 0
        # (global is empty).  If receipt has its own global, this
        # would be >> 0.
        self.assertEqual(
            post_drain_grants, 0,
            "receipt bucket did NOT share the global cap with the "
            "rejection bucket -- 100 fresh IPs received receipts "
            "even though rejection-side already drained the global "
            "bucket.  An attacker could drain ~3x the intended "
            "subtree budget by alternating paths.",
        )


class TestReceiptBudgetExhaustionFallsOpen(unittest.TestCase):
    """Critical: receipt-budget exhaustion MUST NOT block the underlying
    submission.  Same fail-open semantics as the existing broken-issuer
    path: tx still admitted, receipt_hex empty.

    A fail-CLOSED gate would itself be a censorship vector -- an
    attacker draining the budget would also block honest submissions.
    """

    def test_submit_with_exhausted_budget_still_admits_tx(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.core.transaction import create_transaction
        from messagechain.crypto.keys import KeyPair
        from messagechain.identity.identity import Entity
        from messagechain.network.submission_receipt import ReceiptIssuer
        from messagechain.network.submission_server import (
            _HandlerContext,
            ReceiptBudgetTracker,
        )
        from tests import register_entity_for_test

        alice = Entity.create(b"alice-r14".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(alice)
        mempool = Mempool()

        # Real receipt issuer (small subtree -- we only need 1 leaf
        # for the within-budget call below, then exhaust the budget
        # tracker and verify the second submit still admits).
        receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-r14-exhaust", height=4,
        )
        issuer = ReceiptIssuer(alice.entity_id, receipt_kp)

        tracker = ReceiptBudgetTracker()

        ctx = _HandlerContext(
            blockchain=chain,
            mempool=mempool,
            relay_callback=None,
            receipt_issuer=issuer,
            budget_tracker=tracker,
        )

        ip = "203.0.113.42"

        # First submit from fresh IP: receipt issued normally.
        tx0 = create_transaction(
            alice, "audit-r14-msg-0", fee=MIN_FEE + 200, nonce=0,
        )
        result0 = ctx.submit(
            tx0, receipt_allowed=ctx.receipt_budget_check(ip),
        )
        self.assertTrue(result0.ok, result0.error)
        self.assertTrue(
            result0.receipt_hex,
            "first within-budget submit must produce a receipt",
        )

        # Drain the per-IP receipt bucket by repeatedly consulting it.
        for _ in range(50):
            tracker.receipt_budget_check(ip)
        # Sanity: per-IP bucket is now empty.
        self.assertFalse(tracker.receipt_budget_check(ip))

        # Now submit again from the same IP -- the gate fails, so
        # receipt_allowed is False.  The submit MUST still admit the
        # tx (fail-open) but produce no receipt_hex.
        tx1 = create_transaction(
            alice, "audit-r14-msg-1", fee=MIN_FEE + 200, nonce=1,
        )
        result1 = ctx.submit(
            tx1, receipt_allowed=ctx.receipt_budget_check(ip),
        )
        self.assertTrue(
            result1.ok,
            "submit must STILL succeed when receipt budget is "
            "exhausted (fail-open) -- a fail-closed gate would "
            "itself become a censorship vector.",
        )
        # tx is in the mempool -- the chain admitted it.
        self.assertIn(tx1.tx_hash, mempool.pending)
        # No receipt issued (budget said no).
        self.assertEqual(
            result1.receipt_hex, "",
            "receipt_hex MUST be empty when the per-IP budget is "
            "exhausted -- otherwise the gate did nothing.",
        )


class TestSuccessPathDoesNotBurnLeafWhenBudgetExhausted(unittest.TestCase):
    """Stronger version of the fail-open test: when receipt_allowed is
    False, NO WOTS+ leaf must be consumed from the receipt subtree.
    The attack the audit describes is leaf exhaustion -- a fix that
    fails open by SWALLOWING the issued receipt but still burning the
    leaf is not a fix at all.
    """

    def test_no_leaf_consumed_when_budget_says_no(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.core.transaction import create_transaction
        from messagechain.crypto.keys import KeyPair
        from messagechain.identity.identity import Entity
        from messagechain.network.submission_receipt import ReceiptIssuer
        from messagechain.network.submission_server import (
            _HandlerContext,
            ReceiptBudgetTracker,
        )

        alice = Entity.create(b"alice-r14b".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(alice)
        mempool = Mempool()

        receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-r14-noleak", height=4,
        )
        issuer = ReceiptIssuer(alice.entity_id, receipt_kp)
        leaf_before = receipt_kp._next_leaf

        tracker = ReceiptBudgetTracker()
        ctx = _HandlerContext(
            blockchain=chain,
            mempool=mempool,
            relay_callback=None,
            receipt_issuer=issuer,
            budget_tracker=tracker,
        )

        ip = "203.0.113.43"
        # Drain the per-IP receipt budget.
        for _ in range(50):
            tracker.receipt_budget_check(ip)

        # Submit with receipt_allowed=False (budget says no) and
        # confirm NO leaf was consumed from the receipt subtree.
        tx = create_transaction(
            alice, "audit-r14b-msg", fee=MIN_FEE + 200, nonce=0,
        )
        result = ctx.submit(
            tx, receipt_allowed=ctx.receipt_budget_check(ip),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.receipt_hex, "")

        leaf_after = receipt_kp._next_leaf
        self.assertEqual(
            leaf_before, leaf_after,
            f"receipt subtree's WOTS+ leaf cursor advanced from "
            f"{leaf_before} to {leaf_after} despite the budget gate "
            f"refusing issuance -- the leaf was burned anyway.  This "
            f"is the EXACT exhaustion vector the audit flagged.",
        )


if __name__ == "__main__":
    unittest.main()
