"""Audit r60 #3 -- ``_upgrade_health_check`` was called with a
hardcoded 60 s primary budget + 10 s post-rollback confirm.  WAL
recovery + replay of recent blocks on a populated mainnet chain.db
routinely takes longer than 60 s on commodity validator hardware;
the upgrade path then logs "Health check FAILED. Rolling back..."
and silently restores the prior binary -- silently downgrading the
node across the next consensus-affecting release.  On a hard fork,
that's chain split with no operator-visible signal.

CLAUDE.md anchors at risk:
  * Honest-operators-insured -- a populated DB is the EXPECTED
    operational state; an upgrade path that punishes it is the
    opposite of accident insurance.
  * Hard-fork minimization risk -- a stuck-on-old-binary node
    across a tier-gated activation produces the worst-class fork
    (different validators on different protocol versions).
  * Operator UX -- "the upgrade succeeded but I'm on the old
    binary" is the kind of state-surgery footgun the operator-
    recovery surface (1.89.0+) exists to eliminate.

The fix scales the budget proportionally to chain height
(``max(60, 60 + tip_height // 1000)``) by querying the live
daemon's RPC pre-stop, exposes ``--health-timeout`` as an explicit
operator override, and routes BOTH the primary and post-rollback
budgets through a single resolver (``_resolve_upgrade_health_budget``)
so future drift can't reintroduce the asymmetry.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from messagechain.cli import _resolve_upgrade_health_budget


class ResolveUpgradeHealthBudget(unittest.TestCase):
    """The resolver is the single source of truth for the upgrade
    health-check budget.  Tests pin its three resolution paths
    (override, auto, fallback) plus the rollback-confirm ratio.
    """

    def test_override_wins_outright_no_rpc_call(self):
        """Operator override skips the RPC query entirely -- so a
        deliberately-set ``--health-timeout`` survives even when
        the daemon's RPC is wedged."""
        with patch("client.rpc_call") as rpc:
            primary, rollback, via = _resolve_upgrade_health_budget(
                "127.0.0.1", 9334, override=300,
            )
            rpc.assert_not_called()
        self.assertEqual(primary, 300)
        self.assertEqual(rollback, 50)  # max(10, 300 // 6) = 50
        self.assertEqual(via, "override")

    def test_override_clamps_rollback_to_floor(self):
        """A tiny override still leaves rollback >= 10 s -- a
        post-rollback poll smaller than that is just churn."""
        primary, rollback, via = _resolve_upgrade_health_budget(
            "127.0.0.1", 9334, override=12,
        )
        self.assertEqual(primary, 12)
        self.assertEqual(rollback, 10)
        self.assertEqual(via, "override")

    def test_auto_scales_with_tip_height(self):
        """Without override, query the live daemon's RPC and scale
        ``primary = max(60, 60 + h // 1000)``.  A populated mainnet
        DB at tip ~3000 gets ~63 s; at tip ~50_000 gets ~110 s; at
        tip ~500_000 gets ~560 s."""
        for tip_height, expected_primary in [
            (0,        60),
            (1_000,    61),
            (3_000,    63),
            (50_000,  110),
            (500_000, 560),
        ]:
            with patch(
                "client.rpc_call",
                return_value={"ok": True, "result": {"tip_height": tip_height}},
            ):
                primary, rollback, via = _resolve_upgrade_health_budget(
                    "127.0.0.1", 9334, override=None,
                )
            self.assertEqual(
                primary, expected_primary,
                f"tip_height={tip_height} expected primary "
                f"{expected_primary}, got {primary}",
            )
            self.assertEqual(rollback, max(10, expected_primary // 6))
            self.assertTrue(via.startswith("auto("))
            self.assertIn(str(tip_height), via)

    def test_rpc_failure_falls_back_to_legacy_60_10(self):
        """If the daemon's RPC is unreachable pre-stop, fall back
        to the legacy 60 / 10 so behaviour is no worse than pre-r60.
        An upgrade where the daemon isn't reachable pre-stop is a
        deeper problem than budget scaling can solve, but the
        upgrade shouldn't BLOCK on the resolver."""
        with patch(
            "client.rpc_call", side_effect=ConnectionError("nope"),
        ):
            primary, rollback, via = _resolve_upgrade_health_budget(
                "127.0.0.1", 9334, override=None,
            )
        self.assertEqual(primary, 60)
        self.assertEqual(rollback, 10)
        self.assertEqual(via, "fallback")

    def test_rpc_not_ok_response_falls_back(self):
        """A daemon that responds with ``{"ok": False}`` (the
        normal shape for a wedged-but-listening RPC) also falls
        back to the legacy budget rather than raising."""
        with patch(
            "client.rpc_call",
            return_value={"ok": False, "error": "syncing"},
        ):
            primary, rollback, via = _resolve_upgrade_health_budget(
                "127.0.0.1", 9334, override=None,
            )
        self.assertEqual(primary, 60)
        self.assertEqual(rollback, 10)
        self.assertEqual(via, "fallback")

    def test_resolver_is_single_source_of_truth(self):
        """The primary and rollback-confirm budgets MUST come from
        the SAME resolver call -- not two parallel hardcoded
        constants -- so drift can't silently reintroduce the
        asymmetry the fix removes.  We assert the helper returns
        BOTH values from one entry point and the rollback is a
        deterministic function of the primary."""
        primary, rollback, _via = _resolve_upgrade_health_budget(
            "127.0.0.1", 9334, override=600,
        )
        self.assertEqual(primary, 600)
        self.assertEqual(rollback, 100)  # 600 // 6
        # Same call shape, same coupling -- not two independent
        # consts that could drift again.
        self.assertGreaterEqual(rollback, 10)
        self.assertLessEqual(rollback, primary)


if __name__ == "__main__":
    unittest.main()
