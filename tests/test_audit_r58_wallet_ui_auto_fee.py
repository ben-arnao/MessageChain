"""Audit r58 #2 (UX / value-prop / economics top-1) -- wallet-UI
auto-fee path was byte-count-only against the legacy
``get_fee_estimate`` mempool helper, silently underbidding any
non-message tx (any ``base_fee > 1``) and any transfer to a brand-
new recipient (``NEW_ACCOUNT_FEE`` surcharge missed by 1099 tokens).

CLAUDE.md anchors at risk:
  * "Any wallet/CLI helper that picks a fee for the user computes a
    target fee-per-byte from current mempool conditions and
    multiplies by the tx's stored byte count.  When the fee model
    shifts, every auto-fee path shifts with it -- don't leave a tx
    kind defaulting to a stale flat fee while others auto-bid by
    density." -- the wallet-UI was the parallel hole audit r57 #1's
    CLI fix didn't close.
  * "wallet, transfer, and balance-handling code is held to
    mainstream-asset quality bars" -- silent underbid is exactly the
    fee-volatility footgun the anchor forbids treating as user
    error.
  * Principle #3 Simplicity -- blank-fee should mean live auto-fee,
    not "field cleared" as a footgun.

Tier-less, no fork.  Single chokepoint widening: ``op_estimate_fee``
gains ``tx_type`` + ``payload_bytes`` + ``recipient_id`` kwargs and
routes through the unified ``estimate_fee`` RPC (the same chokepoint
the CLI's ``estimate-fee --tx-type`` lifts onto post-r57 #1).
Wallet UI's hardcoded ``value="100"`` on transfer / stake / unstake
fee inputs is replaced with ``placeholder="auto"`` + a blank-fee
submit path that calls ``liveFee(kind, opts)``.
"""

from __future__ import annotations

import inspect
import re
import unittest
from pathlib import Path

from messagechain.network import wallet_ops
from messagechain.economics.auto_fee import TX_TYPES


_WALLET_HTML = (
    Path(wallet_ops.__file__).parent.parent
    / "static" / "wallet" / "index.html"
)


class TestOpEstimateFeeAcceptsTxType(unittest.TestCase):
    """Structural: ``op_estimate_fee`` MUST accept a ``tx_type`` kwarg
    so the wallet UI can quote each kind correctly.  A regression
    where the kwarg is dropped reintroduces the audit r58 #2 defect by
    definition."""

    def test_signature_has_tx_type(self):
        sig = inspect.signature(wallet_ops.op_estimate_fee)
        self.assertIn("tx_type", sig.parameters)
        self.assertIn("payload_bytes", sig.parameters)
        self.assertIn("recipient_id", sig.parameters)
        self.assertIn("urgency", sig.parameters)

    def test_default_tx_type_is_message(self):
        """Back-compat: pre-r58 callers that pass only message_bytes
        must continue to work without specifying tx_type."""
        sig = inspect.signature(wallet_ops.op_estimate_fee)
        self.assertEqual(
            sig.parameters["tx_type"].default, "message",
        )

    def test_rejects_unknown_tx_type(self):
        """A typo'd tx_type must fail fast at the op layer -- silent
        fallback to the message floor would underbid every other
        kind."""
        def _no_rpc(method, params):
            raise AssertionError("RPC must NOT be called on unknown kind")
        resp = wallet_ops.op_estimate_fee(_no_rpc, tx_type="bogus_kind")
        self.assertFalse(resp["ok"])
        self.assertIn("tx_type", resp["error"].lower())

    def test_known_kinds_dispatch_unified_rpc(self):
        """For every known TX_TYPE, op_estimate_fee MUST dispatch the
        unified ``estimate_fee`` RPC (not the legacy
        ``get_fee_estimate``).  Sweeps the canonical TX_TYPES so a
        future tx kind added to the helper inherits the discipline
        without anyone having to remember to also lift it here."""
        for kind in TX_TYPES:
            captured = {}
            def _rpc(method, params, _captured=captured):
                _captured["method"] = method
                _captured["params"] = params
                return {"ok": True, "result": {"recommended_fee": 1}}
            resp = wallet_ops.op_estimate_fee(_rpc, tx_type=kind)
            self.assertTrue(resp["ok"], f"{kind}: {resp}")
            self.assertEqual(
                captured["method"], "estimate_fee",
                f"{kind} must dispatch unified estimate_fee RPC",
            )
            self.assertEqual(captured["params"]["kind"], kind)


class TestWalletUIFeeInputsHaveNoHardcodedValue(unittest.TestCase):
    """Structural pin: the wallet UI must NOT hardcode ``value="100"``
    on any fee input.  The hardcoded constant was a 100x silent
    overpay against the post-Tier-18 MARKET_FEE_FLOOR=1 AND silently
    underbid whenever live base_fee > 100 (audit r57 #1's CLI fix
    has no effect when the wallet UI defaults to a stale flat 100).

    Per CLAUDE.md "Any wallet/CLI helper that picks a fee for the
    user computes a target fee-per-byte from current mempool
    conditions."  Adding a new fee input with a hardcoded value
    reintroduces the defect class by definition."""

    def test_no_value_100_on_any_fee_input(self):
        html = _WALLET_HTML.read_text(encoding="utf-8")
        # Match any <input ... id="...-fee" ... value="100" ... > in
        # the rendered HTML.  Order-of-attributes-tolerant via two
        # separate regexes (the input could be value-before-id or
        # id-before-value).
        order_a = re.compile(
            r'<input[^>]*\bid="[a-z-]*fee"[^>]*\bvalue="100"', re.I,
        )
        order_b = re.compile(
            r'<input[^>]*\bvalue="100"[^>]*\bid="[a-z-]*fee"', re.I,
        )
        self.assertIsNone(
            order_a.search(html),
            "Fee input hardcodes value=\"100\" -- audit r58 #2 "
            "abstraction-fix requires placeholder=\"auto\" with "
            "live auto-fee on submit",
        )
        self.assertIsNone(
            order_b.search(html),
            "Fee input hardcodes value=\"100\" -- audit r58 #2 "
            "abstraction-fix requires placeholder=\"auto\" with "
            "live auto-fee on submit",
        )

    def test_live_fee_helper_uses_recommended_fee(self):
        """The JS ``liveFee`` helper must read ``recommended_fee``
        from the unified RPC response, not the legacy
        ``fee_estimate`` (a stale wallet UI that still reads
        ``fee_estimate`` silently underbids by exactly the live
        base_fee + NEW_ACCOUNT_FEE / propose payload-byte surcharge
        every time)."""
        html = _WALLET_HTML.read_text(encoding="utf-8")
        # The unified RPC field name MUST appear in the helper.
        self.assertIn(
            "recommended_fee", html,
            "JS liveFee must read recommended_fee from the unified "
            "estimate_fee RPC response",
        )


if __name__ == "__main__":
    unittest.main()
