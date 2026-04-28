"""Global receipt-subtree cap layered on top of the per-IP budget.

Audit (2026-04-27): the round-8 ``ReceiptBudgetTracker`` defends
against single-IP drain via a per-IP token bucket
(``SUBMISSION_REJECTION_BURST=3`` + 0.05/sec refill, ``_max_tracked_ips
=4096``), but a botnet-style attacker rotating through fresh source
IPs (e.g. an IPv6 /64 cycling through addresses) gets a fresh burst
of 3 leaves per IP.  At 4096 distinct buckets that is 12,288 leaves
in the burst alone plus ~205 leaves/sec sustained — enough to drain
the 65,536-leaf ``RECEIPT_SUBTREE`` in ~4-5 minutes.

Once drained, every receipt / rejection / ack issuance silently
breaks until the operator rotates the on-chain subtree
(``SetReceiptSubtreeRootTransaction`` + ~9 minute keygen on a
modest VM).  During that gap a colluding validator can ignore
submissions with no chain-level evidence — defeating the
censorship-evidence framework, which is the chain's primary
defense against the primary anchored adversary (validator
collusion / coerced suppression — see CLAUDE.md).

The fix layers a SECOND token bucket on the SAME tracker, applied
AFTER the per-IP gate passes:

  * Per-IP first  — keeps fairness for honest opt-in clients;
    a single IP cannot drain more than ``SUBMISSION_REJECTION_BURST``
    leaves before its own bucket runs dry, regardless of the
    global state.
  * Global second — caps the network-wide leaf-issuance rate at
    a level honest workload never reaches but a botnet cannot
    sustain.  Sized at 10% of the receipt-subtree (6,553 leaves
    burst) with refill 0.05 leaves/sec ≈ 4,320/day, so a
    sustained drain takes ~15 days to consume one full subtree
    even after burning the burst — well above the operator
    rotation cadence (which the comment in config.py pegs at
    ~22 days at full network capacity).

These tests pin:
  1. botnet rotation through 4096 fresh IPs MUST NOT drain more
     than ``RECEIPT_GLOBAL_BURST`` leaves (the headline);
  2. honest single-IP within-burst behavior unchanged;
  3. honest sustained workload at expected mainnet rates does
     not hit the global cap;
  4. when the global cap saturates, the issuer is dropped to
     None silently — submission still processes, no receipt;
  5. exhaustion warning is logged, rate-limited to one per
     minute (no per-event log spam);
  6. HTTPS and RPC paths consume from the SAME global bucket
     (single shared tracker instance);
  7. existing per-IP gate behavior is byte-identical (regression).
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    SUBMISSION_REJECTION_BURST,
)
from messagechain.network.submission_server import ReceiptBudgetTracker


class _GlobalCapBase(unittest.TestCase):
    """Common helpers for the global-cap test suite.

    ``ReceiptBudgetTracker`` exposes pure per-IP / global tracking
    that does NOT depend on a real chain or issuer — these tests
    isolate the budget logic from the surrounding submission stack
    so they run in <1s.

    NB: we intentionally do NOT patch ``time.time``.  ``TokenBucket``
    captures ``time.time`` as a dataclass ``default_factory`` at
    class-definition time, so a ``mock.patch("time.time", ...)`` does
    NOT influence the bucket's initial ``last_refill`` (the factory
    was bound to the original C function before the patch).  Tests
    that need to exercise the 60s warning rate-limit poke
    ``_global_warn_last`` directly instead of advancing a fake clock.
    """


class TestBotnetRotationDoesNotDrainSubtree(_GlobalCapBase):
    """HEADLINE: simulate the audit's attack and assert the global cap
    bites.

    Pre-fix: 4096 distinct IPs each consume a fresh burst of 3 leaves
    → 12,288 leaves drained in seconds.  Post-fix: the global token
    bucket caps the burst at ``RECEIPT_GLOBAL_BURST`` (6,553) and the
    total drained over the whole burst is bounded by it, regardless
    of how many fresh IPs the attacker rotates through.
    """

    def test_botnet_rotation_does_not_drain_subtree(self):
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        tracker = ReceiptBudgetTracker(max_tracked_ips=8192)
        n_ips = 4096
        per_ip_attempts = SUBMISSION_REJECTION_BURST  # = 3
        consumed = 0

        # Tight loop — wall-clock elapsed across the whole burst is
        # well under 1 second, and global refill is 0.05/sec, so
        # at-most ~0 fractional tokens refill during the run.
        for ip_idx in range(n_ips):
            ip = f"10.{(ip_idx >> 16) & 0xff}.{(ip_idx >> 8) & 0xff}.{ip_idx & 0xff}"
            for _ in range(per_ip_attempts):
                if tracker.rejection_budget_check(ip):
                    consumed += 1

        # Pre-fix this would be 12,288.  Post-fix the global cap keeps
        # it at-or-below RECEIPT_GLOBAL_BURST (+ a small slack for any
        # bucket refill that drips during the loop's wall-clock time).
        self.assertLessEqual(
            consumed, RECEIPT_GLOBAL_BURST + 5,
            f"botnet rotation drained {consumed} leaves; global cap "
            f"({RECEIPT_GLOBAL_BURST}) was bypassed",
        )
        # Sanity floor: with 4096 fresh IPs we DID hit the cap, so we
        # consumed at least the burst.  If consumed << burst something
        # else (e.g. eviction) is masking the test.
        self.assertGreaterEqual(
            consumed, RECEIPT_GLOBAL_BURST,
            f"global cap should saturate on a 12,288-attempt burst; "
            f"consumed only {consumed} — eviction or another gate is "
            f"dropping tokens before the global gate sees them",
        )


class TestHonestSingleIpUnaffected(_GlobalCapBase):
    """A single IP submitting within its per-IP burst gets a receipt
    every time, AND consumes one global token per receipt — the
    global cap does NOT free-pass nor double-charge."""

    def test_honest_single_ip_within_burst_consumes_per_ip_and_global(self):
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        tracker = ReceiptBudgetTracker()
        ip = "10.0.0.1"

        # Drain global bucket counter: snapshot before, snapshot after.
        global_before = tracker._global_bucket.tokens

        passes = 0
        for _ in range(SUBMISSION_REJECTION_BURST):
            if tracker.rejection_budget_check(ip):
                passes += 1

        self.assertEqual(passes, SUBMISSION_REJECTION_BURST)

        global_after = tracker._global_bucket.tokens
        self.assertAlmostEqual(
            global_before - global_after,
            float(SUBMISSION_REJECTION_BURST),
            places=5,
            msg="global bucket should consume exactly N tokens for N passes",
        )
        # Per-IP bucket should be drained.
        per_ip = tracker._rejection_buckets[ip]
        self.assertLess(per_ip.tokens, 1.0)


class TestHonestWorkloadWellBelowGlobalCap(_GlobalCapBase):
    """A realistic honest mainnet workload — opt-in receipts spread
    across a handful of distinct IPs at well under each IP's per-IP
    rate — does not hit the global cap.

    Honest receipt-opt-in is rare (most clients don't request
    receipts; the opt-in is for slash-evidence-grade callers).
    Realistic upper bound: a few hundred receipts/day total.  This
    test pins that a workload of 1,000 receipts (massive overestimate)
    spread across ~50 distinct IPs at each IP's per-IP burst limit
    fits comfortably below the 6,553-leaf global burst.
    """

    def test_honest_workload_does_not_hit_global_cap(self):
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        tracker = ReceiptBudgetTracker()
        passes = 0

        # 50 IPs × 3-burst per IP = 150 immediate receipts.  Repeat
        # this volume ~7x with a fresh IP-set each round to push the
        # total well above any realistic honest workload.  Total
        # attempted: 50 × 3 × 7 = 1,050.  All should pass — well
        # under the 6,553-leaf global burst.
        attempts = 0
        for round_idx in range(7):
            for ip_offset in range(50):
                ip = f"10.{round_idx}.0.{ip_offset}"
                for _ in range(SUBMISSION_REJECTION_BURST):
                    attempts += 1
                    if tracker.rejection_budget_check(ip):
                        passes += 1

        self.assertEqual(attempts, 1050)
        self.assertEqual(
            passes, 1050,
            f"honest workload was throttled — only {passes}/{attempts} "
            f"receipts issued; global cap "
            f"({RECEIPT_GLOBAL_BURST}) should leave plenty of headroom",
        )
        # And we still have substantial global headroom (≥ 80% of
        # burst remaining is the contract here — honest workload
        # should NOT visibly deplete the bucket).
        self.assertGreaterEqual(
            tracker._global_bucket.tokens,
            0.8 * RECEIPT_GLOBAL_BURST,
            f"global bucket dropped below 80% during honest workload — "
            f"too tight a cap for realistic mainnet traffic",
        )


class TestGlobalCapDropsIssuerSilently(_GlobalCapBase):
    """When the global cap is exhausted, ``rejection_budget_check``
    returns False on a fresh IP whose per-IP bucket would otherwise
    pass.  Callers respond by dropping the issuer to None — the
    submission still processes; the client just doesn't get a
    receipt.  This test pins the gate-level behavior; the
    submission-still-processes invariant is a property of the
    callers (``_should_request_rejection`` and
    ``_resolve_rpc_receipt_issuer``) which return None on False."""

    def test_global_cap_exhaustion_returns_false_on_fresh_ip(self):
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        tracker = ReceiptBudgetTracker(max_tracked_ips=RECEIPT_GLOBAL_BURST + 100)
        # Drain the global bucket via many fresh IPs (each gets one
        # per-IP token; we stop calling each IP after one pass).
        for ip_idx in range(RECEIPT_GLOBAL_BURST):
            ip = f"172.16.{(ip_idx >> 8) & 0xff}.{ip_idx & 0xff}"
            ok = tracker.rejection_budget_check(ip)
            self.assertTrue(ok, f"unexpected reject at #{ip_idx}")

        # One more IP — per-IP bucket is fresh (full 3 tokens), but
        # global is empty.  Must return False.
        ip = "172.31.31.31"
        self.assertFalse(
            tracker.rejection_budget_check(ip),
            "fresh IP got a receipt despite global cap being drained",
        )


class TestWarningLogFiresOnGlobalExhaustionRateLimited(_GlobalCapBase):
    """When the global cap kicks in, a warning is logged so the
    operator can correlate complaints with a possible drain attack —
    rate-limited to one per minute so a sustained drain doesn't
    fill the journal."""

    def test_warning_log_fires_once_per_minute(self):
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        tracker = ReceiptBudgetTracker(max_tracked_ips=RECEIPT_GLOBAL_BURST + 100)
        # Drain global.
        for ip_idx in range(RECEIPT_GLOBAL_BURST):
            ip = f"172.16.{(ip_idx >> 8) & 0xff}.{ip_idx & 0xff}"
            tracker.rejection_budget_check(ip)

        with self.assertLogs(
            "messagechain.submission", level="WARNING",
        ) as cm:
            # Five rejections in immediate succession — should produce
            # at most ONE global-cap warning (the others are within
            # the 60s rate-limit window and should be suppressed).
            for i in range(5):
                tracker.rejection_budget_check(f"192.168.0.{i}")

        warns = [
            m for m in cm.output
            if "global cap" in m.lower() or "drain" in m.lower()
        ]
        self.assertEqual(
            len(warns), 1,
            f"expected exactly 1 global-cap warning across 5 in-window "
            f"rejections, got {len(warns)}: {cm.output}",
        )

        # Simulate 60s elapsed by setting `_global_warn_last` 61s in
        # the past (avoids a real sleep in the test path; this
        # directly exercises the 60s-window comparison without
        # needing freezegun-style time mocking).
        tracker._global_warn_last -= 61.0
        with self.assertLogs(
            "messagechain.submission", level="WARNING",
        ) as cm2:
            tracker.rejection_budget_check("192.168.1.1")

        warns2 = [
            m for m in cm2.output
            if "global cap" in m.lower() or "drain" in m.lower()
        ]
        self.assertEqual(
            len(warns2), 1,
            f"expected exactly 1 follow-up warning after the 60s "
            f"window expires, got {len(warns2)}: {cm2.output}",
        )


class TestHttpsAndRpcShareGlobalCap(_GlobalCapBase):
    """The HTTPS handler and the RPC handler MUST consult the SAME
    tracker instance so the global bucket is shared.  Alternating
    calls between the surfaces decrements one shared global counter.
    """

    def test_alternating_surfaces_share_global_bucket(self):
        from messagechain.network.submission_server import _HandlerContext

        tracker = ReceiptBudgetTracker()
        # Bare _HandlerContext exercises the HTTPS path's wiring; an
        # RPC path's call is just `tracker.rejection_budget_check(ip)`
        # because the Server stores the same tracker on
        # `Server.receipt_budget_tracker` (see
        # `_resolve_rpc_receipt_issuer`).
        ctx = _HandlerContext(
            blockchain=None, mempool=None, relay_callback=None,
            budget_tracker=tracker,
        )

        global_start = tracker._global_bucket.tokens

        # Alternate: HTTPS-side check, RPC-side check, repeat.
        # Use distinct IPs so per-IP doesn't deplete (each IP takes
        # at most 1 of its 3-token burst this round).
        for i in range(20):
            ip = f"10.1.0.{i}"
            if i % 2 == 0:
                self.assertTrue(ctx.rejection_budget_check(ip))  # HTTPS
            else:
                self.assertTrue(tracker.rejection_budget_check(ip))  # RPC

        global_end = tracker._global_bucket.tokens
        consumed = global_start - global_end
        self.assertAlmostEqual(
            consumed, 20.0, places=5,
            msg="alternating HTTPS+RPC submissions did not consume "
                "from one shared global bucket",
        )


class TestPerIpGateStillWorks(_GlobalCapBase):
    """Regression: the existing per-IP gate behavior must survive the
    global-cap layering — same IP repeatedly hitting the per-IP cap
    is rejected even when global has plenty.
    """

    def test_per_ip_gate_runs_first(self):
        tracker = ReceiptBudgetTracker()
        ip = "10.0.0.1"

        # Burst tokens available for this IP.
        for _ in range(SUBMISSION_REJECTION_BURST):
            self.assertTrue(tracker.rejection_budget_check(ip))

        # Per-IP exhausted; global is fine.  Must reject.
        self.assertFalse(tracker.rejection_budget_check(ip))

        # AND: a per-IP rejection must NOT have consumed a global
        # token (the gate order is per-IP first; failure consumes
        # nothing from global).  Verify by snapshotting and comparing.
        global_before = tracker._global_bucket.tokens
        for _ in range(50):
            tracker.rejection_budget_check(ip)
        global_after = tracker._global_bucket.tokens
        self.assertAlmostEqual(
            global_before, global_after, places=5,
            msg="per-IP rejected requests consumed global tokens — "
                "global gate should run only after per-IP passes",
        )


class TestGlobalCapDoesNotAffectAckBudget(_GlobalCapBase):
    """The ack budget is a SEPARATE per-IP bucket family (also draws
    from the receipt subtree).  The global cap layered on
    ``rejection_budget_check`` must ALSO apply to ``ack_budget_check``
    — both surfaces burn from the same finite subtree, so any
    fairness/cap argument that holds for receipts holds for acks.
    """

    def test_ack_path_also_consumes_global(self):
        tracker = ReceiptBudgetTracker()
        # Drain via ack path with many fresh IPs.  Ack burst is 5 per
        # IP; with the global cap layered, the total acks issued is
        # bounded by global burst regardless of IP count.
        from messagechain.network.submission_server import (
            RECEIPT_GLOBAL_BURST,
        )

        consumed = 0
        # 4000 fresh IPs * 5 ack burst = 20,000 attempted, but global
        # cap binds.
        for ip_idx in range(4000):
            ip = f"10.{(ip_idx >> 8) & 0xff}.{ip_idx & 0xff}.1"
            for _ in range(5):
                if tracker.ack_budget_check(ip):
                    consumed += 1
                else:
                    break  # global drained, no point in this IP's remaining

        self.assertLessEqual(
            consumed, RECEIPT_GLOBAL_BURST,
            f"ack-budget botnet drained {consumed}, exceeding "
            f"global cap ({RECEIPT_GLOBAL_BURST})",
        )


if __name__ == "__main__":
    unittest.main()
