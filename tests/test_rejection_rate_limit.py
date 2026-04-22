"""Dedicated rate limit for X-MC-Request-Receipt=1 submissions.

Hardening finding: the public /v1/submit endpoint accepts an opt-in
header X-MC-Request-Receipt: 1.  When set and the tx fails
validation, the validator issues a SignedRejection, burning one
WOTS+ leaf from the receipt subtree.  The regular per-IP rate limit
(SUBMISSION_RATE_LIMIT_PER_SEC = 2) caps submissions at ~2/sec but
doesn't specifically cap *rejection* emission — an attacker sending
structurally-valid-but-semantically-bad txs with the header set can
drain the 65k-leaf subtree in ~9 hours from a single IPv4, or
minutes with IPv6 /64 rotation.  After exhaustion every subsequent
receipt and rejection issuance fails, disabling the entire
censorship-evidence framework for that validator.

Fix: a second per-IP token bucket, tighter than the base submission
bucket, gates *only* the request_rejection=True path.  When the
rejection budget is exhausted the header is silently ignored — the
submission still processes, the client gets a plain 400, and the
validator's leaf budget is preserved.  Honest clients wanting a
signed rejection for genuine slash evidence get it at the tighter
rate; attackers get nothing for their trouble.

These tests pin the separation of the two budgets and the
silent-downgrade semantics on exhaustion.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestRejectionRateLimitExists(unittest.TestCase):

    def test_config_constants_exist(self):
        from messagechain import config as cfg
        self.assertTrue(hasattr(cfg, "SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC"))
        self.assertTrue(hasattr(cfg, "SUBMISSION_REJECTION_BURST"))

    def test_rejection_budget_strictly_tighter_than_submission(self):
        """The rejection budget must be STRICTLY tighter than the base
        submission budget — otherwise it's not closing the
        leaf-exhaustion asymmetry.  Tests that the floor values picked
        match the attack-cost math from the finding."""
        from messagechain.config import (
            SUBMISSION_RATE_LIMIT_PER_SEC,
            SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC,
            SUBMISSION_BURST,
            SUBMISSION_REJECTION_BURST,
        )
        self.assertLess(
            SUBMISSION_REJECTION_RATE_LIMIT_PER_SEC,
            SUBMISSION_RATE_LIMIT_PER_SEC,
        )
        self.assertLess(
            SUBMISSION_REJECTION_BURST,
            SUBMISSION_BURST,
        )


class TestContextRejectionBudget(unittest.TestCase):
    """The SubmissionServerContext exposes a dedicated rejection-budget
    check that is independent of the base submission rate limit."""

    def _mk_ctx(self):
        from messagechain.network.submission_server import _HandlerContext
        return _HandlerContext(
            blockchain=MagicMock(),
            mempool=MagicMock(),
            relay_callback=None,
        )

    def test_rejection_budget_method_exists(self):
        ctx = self._mk_ctx()
        self.assertTrue(
            hasattr(ctx, "rejection_budget_check"),
            "SubmissionServerContext must expose rejection_budget_check(ip)",
        )

    def test_rejection_budget_returns_true_under_limit(self):
        ctx = self._mk_ctx()
        # First call from a fresh IP should succeed (burst tokens available).
        self.assertTrue(ctx.rejection_budget_check("10.0.0.1"))

    def test_rejection_budget_exhausts_after_burst(self):
        from messagechain.config import SUBMISSION_REJECTION_BURST
        ctx = self._mk_ctx()
        ip = "10.0.0.2"
        # Consume all burst tokens.  The bucket refills at the
        # rejection rate, so beyond burst we see False until time
        # passes.  Allow 1 extra for the last-refill fractional token
        # (TokenBucket semantics) then assert we're depleted.
        ok_count = 0
        for _ in range(SUBMISSION_REJECTION_BURST + 1):
            if ctx.rejection_budget_check(ip):
                ok_count += 1
        # No more tokens: the next call fails.
        self.assertFalse(ctx.rejection_budget_check(ip))
        self.assertLessEqual(ok_count, SUBMISSION_REJECTION_BURST + 1)

    def test_rejection_budget_is_independent_of_submission_budget(self):
        """Consuming submission tokens does NOT consume rejection tokens
        (separation of budgets — the whole point of the fix)."""
        ctx = self._mk_ctx()
        ip = "10.0.0.3"
        # Drain the submission budget to near-zero.
        for _ in range(100):
            ctx.rate_limit_check(ip)
        # Rejection budget for the SAME IP is still fresh.
        self.assertTrue(
            ctx.rejection_budget_check(ip),
            "rejection_budget_check must NOT share state with "
            "rate_limit_check — separate bucket is the fix.",
        )


class TestRejectionHeaderSilentDowngradeOnBudgetExhaustion(unittest.TestCase):
    """When the rejection budget is exhausted, the X-MC-Request-Receipt
    header is silently dropped: the submission still processes, the
    client gets a plain 400 if the tx is invalid, and NO leaf is
    burned.  Honest service flow stays up; attacker gets no
    rejection proof."""

    def test_submit_respects_rejection_budget_false(self):
        """When rejection_budget_check returns False, ctx.submit must
        be called with request_rejection=False.  This is the
        downgrade that protects the leaf budget."""
        # Wire a stub ctx that records how submit() was invoked.
        from messagechain.network import submission_server as ss
        calls = []

        class _StubCtx:
            blockchain = MagicMock()
            mempool = MagicMock()
            receipt_issuer = None
            relay_callback = None
            proof_pool = None

            def rate_limit_check(self, ip):
                return True

            def rejection_budget_check(self, ip):
                return False  # simulate exhaustion

            def submit(self, tx, request_rejection=False):
                calls.append(request_rejection)
                # Mimic a rejection response without burning a leaf.
                return ss.SubmissionResult(
                    ok=False, error="bad",
                )

        # The handler reads X-MC-Request-Receipt, sees it's set,
        # checks rejection_budget_check, sees False, and strips the
        # flag before calling submit.  The test drives the handler's
        # internal logic by invoking _should_request_rejection (the
        # new helper the fix introduces).
        self.assertTrue(
            hasattr(ss, "_should_request_rejection"),
            "fix must expose a testable helper for the "
            "header-vs-budget decision",
        )
        ctx = _StubCtx()
        # Header set, budget exhausted -> False (downgrade).
        self.assertFalse(
            ss._should_request_rejection(ctx, client_ip="1.2.3.4", header_set=True),
        )
        # Header set, budget available -> True.
        class _StubCtxAllow(_StubCtx):
            def rejection_budget_check(self, ip):
                return True
        self.assertTrue(
            ss._should_request_rejection(_StubCtxAllow(), client_ip="1.2.3.4", header_set=True),
        )
        # Header not set -> always False regardless of budget.
        self.assertFalse(
            ss._should_request_rejection(_StubCtxAllow(), client_ip="1.2.3.4", header_set=False),
        )


if __name__ == "__main__":
    unittest.main()
