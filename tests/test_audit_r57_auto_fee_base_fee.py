"""Audit r57 #1: auto-fee quotes must clear the live ``supply.base_fee``.

The chain admits txs to the mempool whenever ``tx.fee >= per_kind_floor``,
but block-apply (`SupplyTracker.pay_fee_with_burn`) rejects any tx whose
fee is below the current EIP-1559 ``supply.base_fee``.  Pre-r57 the
auto-fee helper (`tx_floor` / `auto_fee` / `_rpc_estimate_fee`) only
knew about the per-kind floor and ignored ``base_fee`` entirely, so
under any sustained over-target burst the CLI would quote the per-kind
floor (`MARKET_FEE_FLOOR=1` at current heights), the mempool would
admit, and every block-include would reject — a silent wedge at the
exact moment congestion matters.

These tests pin:

  1. ``tx_floor`` accepts a ``base_fee`` kwarg and never returns less
     than ``base_fee`` (for every tx kind).
  2. ``auto_fee`` plumbs ``base_fee`` through to ``tx_floor``.
  3. Default ``base_fee=0`` keeps behaviour byte-identical to pre-r57
     (no behavioural drift on the no-base-fee path).
  4. ``_rpc_estimate_fee`` reads ``supply.base_fee`` and surfaces it on
     the result, AND folds it into ``min_fee`` / ``recommended_fee`` for
     every tx kind (message included — its `calculate_min_fee` path is
     parallel and must also clear base_fee).
"""

import unittest
from unittest.mock import MagicMock

from messagechain.config import (
    GOVERNANCE_PROPOSAL_FEE_TIER19,
    KEY_ROTATION_FEE,
    MARKET_FEE_FLOOR,
    MARKET_FEE_FLOOR_HEIGHT,
    NEW_ACCOUNT_FEE,
    PROPOSAL_FEE_TIER19_HEIGHT,
    UNIFIED_FEE_FLOOR_HEIGHT,
)
from messagechain.economics.auto_fee import auto_fee, tx_floor


# A height past every floor-unification activation so every tx kind
# resolves to MARKET_FEE_FLOOR=1 as its per-kind admission floor.  This
# is the live-mainnet regime — pre-r57 the auto-fee path returned 1
# everywhere here and the chain rejected anything below base_fee.
POST_MARKET_FLOOR_HEIGHT = max(MARKET_FEE_FLOOR_HEIGHT, UNIFIED_FEE_FLOOR_HEIGHT) + 10


# ── 1. tx_floor clears base_fee for every tx kind ───────────────────


class TestTxFloorClearsBaseFee(unittest.TestCase):
    """``tx_floor`` must never return less than ``base_fee``."""

    def test_message_floor_clears_base_fee(self):
        # At post-Tier-16 heights the per-kind floor is MARKET_FEE_FLOOR=1.
        # A base_fee of 500 (mid-congestion) must lift the quote.
        floor = tx_floor(
            "message",
            stored_size=64,
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_transfer_floor_clears_base_fee(self):
        floor = tx_floor(
            "transfer",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_transfer_new_account_floor_still_dominates(self):
        # NEW_ACCOUNT_FEE branch already costs MIN_FEE + NEW_ACCOUNT_FEE
        # (=1100 at current params), which is well above a modest
        # base_fee — tx_floor must return the max of (per-kind floor,
        # base_fee), not silently downgrade to base_fee.
        floor = tx_floor(
            "transfer",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            recipient_is_new=True,
            base_fee=200,
        )
        self.assertGreaterEqual(floor, NEW_ACCOUNT_FEE)  # surcharge intact

    def test_transfer_new_account_clears_high_base_fee(self):
        # The reverse: a base_fee bigger than the new-account surcharge
        # must still bind.
        big = NEW_ACCOUNT_FEE + 5000
        floor = tx_floor(
            "transfer",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            recipient_is_new=True,
            base_fee=big,
        )
        self.assertGreaterEqual(floor, big)

    def test_stake_floor_clears_base_fee(self):
        floor = tx_floor(
            "stake",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_unstake_floor_clears_base_fee(self):
        floor = tx_floor(
            "unstake",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_react_floor_clears_base_fee(self):
        floor = tx_floor(
            "react",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_propose_floor_clears_base_fee_when_above_propose_floor(self):
        # The Tier 19 propose floor is large (GOVERNANCE_PROPOSAL_FEE_TIER19);
        # base_fee binds only when it exceeds the propose floor.
        big = GOVERNANCE_PROPOSAL_FEE_TIER19 + 5000
        floor = tx_floor(
            "propose",
            payload_bytes=64,
            current_height=max(
                POST_MARKET_FLOOR_HEIGHT, PROPOSAL_FEE_TIER19_HEIGHT + 1
            ),
            base_fee=big,
        )
        self.assertGreaterEqual(floor, big)

    def test_vote_floor_clears_base_fee(self):
        floor = tx_floor(
            "vote",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=500,
        )
        self.assertGreaterEqual(floor, 500)

    def test_rotate_key_floor_clears_base_fee_when_above_rotation_fee(self):
        big = KEY_ROTATION_FEE + 5000
        floor = tx_floor(
            "rotate-key",
            current_height=POST_MARKET_FLOOR_HEIGHT,
            base_fee=big,
        )
        self.assertGreaterEqual(floor, big)


# ── 2. auto_fee plumbs base_fee through to tx_floor ─────────────────


class TestAutoFeePlumbsBaseFee(unittest.TestCase):
    def test_auto_fee_clears_base_fee(self):
        bid = auto_fee(
            "transfer",
            stored_size=64,
            current_height=POST_MARKET_FLOOR_HEIGHT,
            mempool_estimate=0,
            base_fee=500,
        )
        self.assertGreaterEqual(bid, 500)

    def test_auto_fee_max_of_floor_mempool_basefee(self):
        # If all three rungs are non-zero, the returned bid must be the
        # max of (per-kind floor, mempool estimate, base_fee).
        bid = auto_fee(
            "message",
            stored_size=128,
            current_height=POST_MARKET_FLOOR_HEIGHT,
            mempool_estimate=300,
            base_fee=700,
        )
        self.assertGreaterEqual(bid, 700)

    def test_auto_fee_mempool_can_still_dominate_base_fee(self):
        # When the mempool percentile estimate is higher than base_fee,
        # the mempool estimate must still bind (don't downgrade an
        # urgent-density bid because base_fee happens to be lower).
        bid = auto_fee(
            "message",
            stored_size=128,
            current_height=POST_MARKET_FLOOR_HEIGHT,
            mempool_estimate=2000,
            base_fee=300,
        )
        self.assertGreaterEqual(bid, 2000)


# ── 3. default base_fee=0 keeps pre-r57 behaviour byte-identical ────


class TestNoBaseFeeBackwardsCompat(unittest.TestCase):
    """Existing call sites that don't pass base_fee see no behavioural drift."""

    def test_tx_floor_default_matches_market_floor(self):
        # At post-Tier-16 heights, no-base_fee returns MARKET_FEE_FLOOR=1
        # for the cheapest tx kinds — same as pre-r57.
        for kind in ("message", "stake", "unstake", "react"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    tx_floor(kind, current_height=POST_MARKET_FLOOR_HEIGHT),
                    MARKET_FEE_FLOOR,
                )

    def test_auto_fee_default_matches_pre_r57(self):
        # Without base_fee or mempool_estimate, the bid is the per-kind
        # floor — same number every existing test on the pre-r57 surface
        # expects.
        bid = auto_fee(
            "stake",
            stored_size=64,
            current_height=POST_MARKET_FLOOR_HEIGHT,
        )
        self.assertEqual(bid, MARKET_FEE_FLOOR)


# ── 4. _rpc_estimate_fee folds supply.base_fee in + surfaces it ─────


class TestEstimateFeeRpcSurfacesBaseFee(unittest.TestCase):
    """``_rpc_estimate_fee`` must read ``supply.base_fee`` and:
      (a) include it in ``min_fee`` / ``recommended_fee`` for every kind,
      (b) surface it as ``base_fee`` on the result so the CLI / wallet
          UI can show it.
    """

    def _make_server(self, height, base_fee, mempool_fee=0):
        # Lightweight stand-in.  The server method only touches
        # blockchain.height, blockchain.supply.base_fee,
        # blockchain._recipient_is_new (transfer branch only), and
        # mempool.get_fee_estimate.
        srv = MagicMock()
        srv.blockchain = MagicMock()
        srv.blockchain.height = height
        srv.blockchain.supply = MagicMock()
        srv.blockchain.supply.base_fee = base_fee
        srv.blockchain._recipient_is_new = MagicMock(return_value=False)
        srv.mempool = MagicMock()
        srv.mempool.get_fee_estimate = MagicMock(return_value=mempool_fee)
        # Bind the real _rpc_estimate_fee onto the mock.
        from server import Server
        srv._rpc_estimate_fee = Server._rpc_estimate_fee.__get__(srv, Server)
        return srv

    def test_message_floor_clears_base_fee(self):
        srv = self._make_server(POST_MARKET_FLOOR_HEIGHT, base_fee=500)
        out = srv._rpc_estimate_fee({"kind": "message", "message": "hi"})
        self.assertTrue(out["ok"], out)
        r = out["result"]
        self.assertGreaterEqual(r["min_fee"], 500)
        self.assertGreaterEqual(r["recommended_fee"], 500)
        self.assertEqual(r.get("base_fee"), 500)

    def test_transfer_floor_clears_base_fee(self):
        srv = self._make_server(POST_MARKET_FLOOR_HEIGHT, base_fee=500)
        out = srv._rpc_estimate_fee({"kind": "transfer"})
        self.assertTrue(out["ok"], out)
        r = out["result"]
        self.assertGreaterEqual(r["min_fee"], 500)
        self.assertGreaterEqual(r["recommended_fee"], 500)
        self.assertEqual(r.get("base_fee"), 500)

    def test_stake_floor_clears_base_fee(self):
        srv = self._make_server(POST_MARKET_FLOOR_HEIGHT, base_fee=500)
        out = srv._rpc_estimate_fee({"kind": "stake"})
        self.assertTrue(out["ok"], out)
        r = out["result"]
        self.assertGreaterEqual(r["min_fee"], 500)
        self.assertGreaterEqual(r["recommended_fee"], 500)
        self.assertEqual(r.get("base_fee"), 500)

    def test_base_fee_zero_surfaces_zero(self):
        # Pre-r57 surface remains identical when base_fee is 0.
        srv = self._make_server(POST_MARKET_FLOOR_HEIGHT, base_fee=0)
        out = srv._rpc_estimate_fee({"kind": "stake"})
        self.assertTrue(out["ok"], out)
        r = out["result"]
        # base_fee=0 → no lift; recommended_fee is the per-kind floor.
        self.assertEqual(r.get("base_fee"), 0)
        self.assertEqual(r["min_fee"], MARKET_FEE_FLOOR)
        self.assertEqual(r["recommended_fee"], MARKET_FEE_FLOOR)


# ── 5. structural pin: tx_floor's signature carries base_fee ────────


class TestTxFloorSignaturePin(unittest.TestCase):
    """If a future refactor drops the ``base_fee`` kwarg from ``tx_floor``
    or ``auto_fee``, every caller silently re-acquires the pre-r57
    blind-spot.  Pin the signature explicitly.
    """

    def test_tx_floor_accepts_base_fee_kwarg(self):
        import inspect
        sig = inspect.signature(tx_floor)
        self.assertIn("base_fee", sig.parameters)

    def test_auto_fee_accepts_base_fee_kwarg(self):
        import inspect
        sig = inspect.signature(auto_fee)
        self.assertIn("base_fee", sig.parameters)


if __name__ == "__main__":
    unittest.main()
