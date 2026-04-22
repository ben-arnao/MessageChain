"""RPC rate limiter must bill expensive methods more than cheap ones.

Before this change, `RPCRateLimiter.check(ip)` was called once per
RPC request with the default `cost=1`, so a flood of
`submit_transaction` (WOTS+ signature verify, ~50ms CPU) consumed
the same 300-req/min budget as `get_chain_info` (dict lookup,
microseconds).  An attacker burned real CPU at negligible rate-
limit cost.

Fix: `_process_rpc` now routes each method through a cost table
and charges `rpc_rate_limiter.check(ip, cost=N)` a second time
with a method-specific cost *before* dispatching to the handler.
Cheap methods still cost 1 (preserving the ~300/min budget for
honest sessions); expensive methods cost 20, throttling an
attacker to ~15 expensive reqs/min.

This file covers four properties:

  A. An expensive method exhausts the 300-token budget at roughly
     300/20 = 15 submissions per minute.
  B. A cheap method still gets the full 300/min budget.
  C. A mixed workload debits the shared budget correctly — total
     spent = sum(costs).
  D. `check(ip)` with no cost arg still behaves as cost=1 (back-
     compat for un-migrated callers).
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock

from messagechain.network.ratelimit import RPCRateLimiter


class TestRateLimiterCostWeighting(unittest.TestCase):
    """Low-level behavior of `RPCRateLimiter.check(ip, cost=N)`."""

    def test_expensive_method_exhausts_budget_in_15_calls(self):
        """Cost=20 with max_requests=300 → 15 passes, 16th blocks."""
        rl = RPCRateLimiter(max_requests=300, window_seconds=60.0)
        ip = "10.0.0.1"
        # 15 calls each charging 20 tokens = 300 tokens exactly.
        for i in range(15):
            self.assertTrue(
                rl.check(ip, cost=20),
                f"call #{i + 1} at cost=20 should pass "
                f"(cumulative {20 * (i + 1)} ≤ 300)",
            )
        # 16th call would push us to 320, which exceeds 300.
        self.assertFalse(
            rl.check(ip, cost=20),
            "16th expensive call should be rate-limited",
        )

    def test_cheap_method_full_300_budget(self):
        """Cost=1 gets the full 300-per-minute budget."""
        rl = RPCRateLimiter(max_requests=300, window_seconds=60.0)
        ip = "10.0.0.2"
        for i in range(300):
            self.assertTrue(
                rl.check(ip, cost=1),
                f"call #{i + 1} at cost=1 should pass",
            )
        self.assertFalse(
            rl.check(ip, cost=1),
            "301st cheap call should be rate-limited",
        )

    def test_mixed_workload_shares_budget(self):
        """10 cheap (cost=1) + 10 expensive (cost=20) = 210 tokens.

        After that, there are 90 tokens left; 4 more expensive calls
        fit (210 + 80 = 290), a 5th would be 310 → rate-limited.
        """
        rl = RPCRateLimiter(max_requests=300, window_seconds=60.0)
        ip = "10.0.0.3"
        for i in range(10):
            self.assertTrue(rl.check(ip, cost=1), f"cheap #{i + 1}")
        for i in range(10):
            self.assertTrue(rl.check(ip, cost=20), f"expensive #{i + 1}")
        # 210 tokens spent; 90 remaining.
        # 4 more cost=20 calls → 210 + 80 = 290 ≤ 300, should pass.
        for i in range(4):
            self.assertTrue(
                rl.check(ip, cost=20),
                f"follow-on expensive #{i + 1} should pass (budget 290)",
            )
        # 5th would be 310 > 300.
        self.assertFalse(
            rl.check(ip, cost=20),
            "15th expensive call (310 cumulative) should rate-limit",
        )

    def test_default_cost_backcompat(self):
        """A caller that doesn't pass `cost=` still gets cost=1."""
        rl = RPCRateLimiter(max_requests=5, window_seconds=60.0)
        ip = "10.0.0.4"
        for _ in range(5):
            self.assertTrue(rl.check(ip))
        self.assertFalse(rl.check(ip))


class TestProcessRpcChargesMethodCost(unittest.IsolatedAsyncioTestCase):
    """`Server._process_rpc` must charge a second, cost-weighted token
    against the rate limiter based on method name, before dispatching
    the handler.

    These tests stub out blockchain/mempool entirely — we only care
    about *whether the rate-limit token is charged* and *whether the
    handler is invoked on rate-limit block*.
    """

    def _build_stub_server(self, rate_limit_cost_tracker):
        """Return a Server-shaped stub with a tracking rate limiter.

        `rate_limit_cost_tracker` is a list that will receive one
        entry per `.check(ip, cost=N)` call so the test can inspect
        exactly which cost was charged for a given method.
        """
        import server as server_mod

        class _TrackingLimiter:
            """Records every (ip, cost) pair and always allows."""
            def __init__(self, calls_list):
                self._calls = calls_list

            def check(self, ip, cost=1):
                self._calls.append((ip, cost))
                return True

        stub = server_mod.Server.__new__(server_mod.Server)
        stub.rpc_rate_limiter = _TrackingLimiter(rate_limit_cost_tracker)

        # Minimal blockchain stub — _process_rpc's cheap branches do
        # attribute lookups on `self.blockchain`, but we only care about
        # rate-limit bookkeeping, not return shape.  Use MagicMock so
        # any method chain returns sanely.
        stub.blockchain = MagicMock()
        stub.blockchain.height = 0
        stub.blockchain.get_chain_info.return_value = {"height": 0}
        stub.mempool = MagicMock()
        stub.syncer = MagicMock()
        stub.syncer.get_sync_status.return_value = {}
        stub.ban_manager = MagicMock()
        stub.peers = {}
        return stub, server_mod

    async def _dispatch(self, stub, server_mod, method, params=None):
        req = {"method": method, "params": params or {}}
        return await server_mod.Server._process_rpc(
            stub, req, client_ip="1.2.3.4",
        )

    async def test_cheap_method_not_double_charged(self):
        """get_chain_info is already paid for by the outer 1-token
        charge in `_handle_rpc_connection`.  `_process_rpc` must NOT
        charge again — otherwise every cheap request costs 2 tokens
        and the effective budget is halved.
        """
        charges = []
        stub, server_mod = self._build_stub_server(charges)
        await self._dispatch(stub, server_mod, "get_chain_info")
        # _process_rpc itself should not have charged — the outer
        # handler already paid cost=1 per connection.
        self.assertEqual(
            charges, [],
            f"cheap method shouldn't double-charge; got {charges}",
        )

    async def test_expensive_method_charged_cost_20(self):
        """submit_transaction triggers WOTS+ verify — cost=20."""
        charges = []
        stub, server_mod = self._build_stub_server(charges)
        # The handler body will blow up on bad params, but the rate-
        # limit check fires BEFORE the handler runs.  That's the point.
        await self._dispatch(
            stub, server_mod, "submit_transaction",
            params={"transaction": ""},
        )
        self.assertTrue(charges, "expected rate-limit charge")
        self.assertEqual(
            charges[0], ("1.2.3.4", server_mod.RPC_COST_EXPENSIVE),
            f"submit_transaction should charge RPC_COST_EXPENSIVE, "
            f"got {charges}",
        )

    async def test_all_wots_methods_charge_expensive(self):
        """Every method that runs a WOTS+ verify must be in the
        cost map as RPC_COST_EXPENSIVE.  If a new crypto-heavy RPC
        is added later without a cost entry, this test reminds us.
        """
        import server as server_mod
        expected_expensive = {
            "submit_transaction", "submit_transfer",
            "stake", "unstake",
            "submit_proposal", "submit_vote",
            "rotate_key", "set_authority_key",
            "emergency_revoke", "set_receipt_subtree_root",
        }
        for m in expected_expensive:
            self.assertEqual(
                server_mod._RPC_METHOD_COST.get(m),
                server_mod.RPC_COST_EXPENSIVE,
                f"method {m!r} should charge RPC_COST_EXPENSIVE",
            )

    async def test_rate_limit_block_short_circuits_handler(self):
        """If the method-cost check fails, the handler never runs and
        the response is a rate-limit error."""
        import server as server_mod

        class _BlockingLimiter:
            def check(self, ip, cost=1):
                return False  # always block

        stub = server_mod.Server.__new__(server_mod.Server)
        stub.rpc_rate_limiter = _BlockingLimiter()
        # Poison the handler — if the short-circuit fails, this
        # AttributeError will surface.
        stub.blockchain = None
        stub.mempool = None

        resp = await server_mod.Server._process_rpc(
            stub, {"method": "submit_transaction",
                   "params": {"transaction": ""}},
            client_ip="9.9.9.9",
        )
        self.assertFalse(resp.get("ok"))
        self.assertIn("rate", (resp.get("error") or "").lower())

    async def test_client_ip_optional_for_test_harness(self):
        """Existing unit tests call `_process_rpc(stub, req)` without
        client_ip.  The signature must stay compatible — the per-method
        cost check should be skipped (or harmless) when client_ip is
        empty so legacy tests still pass."""
        charges = []
        stub, server_mod = self._build_stub_server(charges)
        # No client_ip arg.
        resp = await server_mod.Server._process_rpc(
            stub, {"method": "get_chain_info", "params": {}},
        )
        self.assertTrue(resp.get("ok"))


if __name__ == "__main__":
    unittest.main()
