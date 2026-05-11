"""Audit r45 #2 — CLI transfer floor must follow the chain's live
fee model, not the legacy ``MIN_FEE=100`` constant.

Pre-fix ``cmd_transfer`` (and the client.py mirror) computed::

    required_floor = max(MIN_FEE, server_min_fee)
    ...
    fee = max(fee, required_floor)            # auto-fee path
    elif fee < required_floor: error          # explicit-fee path

``MIN_FEE`` is the legacy pre-FLAT_FEE_HEIGHT constant of 100.  The
unified Tier-49 fork (``UNIFIED_FEE_FLOOR_HEIGHT``, height 1750)
collapsed the transfer / stake / unstake admission floor to
``MARKET_FEE_FLOOR=1`` -- the server's ``estimate_fee`` RPC returns
this correctly for an existing recipient at any post-Tier-49 height
(today's mainnet is well past that), and ``auto_fee("transfer", ...)``
picks the right number via the height-aware ``tx_floor`` helper.  But
the CLI clamped the result back up to 100, silently over-charging
every wallet user 100x the protocol floor on every transfer for the
~9 months since Tier 49 activated.

The brand-new-recipient branch is left alone: the chain validator
hard-codes ``MIN_FEE + NEW_ACCOUNT_FEE`` with no Tier-49 height gate
(see ``_transfer_floor`` in messagechain/economics/auto_fee.py), and
the server's ``estimate_fee`` reflects that.  Trusting
``server_min_fee`` covers both branches correctly.

CLAUDE.md anchors at risk:
  * Dual-purpose-token / "mainstream-asset quality bar" -- wallet /
    transfer / balance code is held to mainstream-asset standards.
  * Fee model -- "Auto-fee adjusts to fit this model ... don't leave
    a tx kind defaulting to a stale flat fee while others auto-bid
    by density."

Fix: drop the ``max(MIN_FEE, server_min_fee)`` clamp and trust
``server_min_fee`` (which is the height-aware ``tx_floor`` result).
``auto_fee`` already enforces the right floor internally; the post-
auto-fee re-clamp is redundant.  Error messages on explicit-fee
under-payment quote the LIVE server floor, not the stale ``MIN_FEE``
constant.

Surfaced by audit r45 economics axis #1.  Same drift fixed
simultaneously in ``client.py``'s transfer helper.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch


def _write_keyfile(raw_seed: bytes) -> tuple[str, str]:
    """Write a properly-checksummed keyfile so cmd_transfer's
    `_resolve_private_key` accepts it.
    """
    from messagechain.identity.key_encoding import encode_private_key
    d = tempfile.mkdtemp()
    p = os.path.join(d, "key.txt")
    with open(p, "w", encoding="ascii") as f:
        f.write(encode_private_key(raw_seed))
    return d, p


def _make_recipient_address() -> tuple[bytes, str]:
    """Return a (raw_32_bytes, checksummed_mc1_string) recipient."""
    from messagechain.identity.address import encode_address
    raw = b"\x42" * 32
    return raw, encode_address(raw)


class TestCmdTransferFeeFloorFollowsServer(unittest.TestCase):
    """``cmd_transfer`` must not clamp the picked fee to the legacy
    ``MIN_FEE=100`` when the chain's live floor is lower.  Mocks the
    RPC surface end-to-end so the test exercises the real fee-policy
    branch in cli.cmd_transfer.
    """

    def setUp(self):
        seed = b"alice-r45-transfer".ljust(32, b"\x00")
        self._key_dir, self.key_path = _write_keyfile(seed)
        self._recipient_raw, self._recipient_addr = _make_recipient_address()
        # Mark the recipient as an existing entity in our fake RPC so
        # the NEW_ACCOUNT_FEE surcharge branch doesn't kick in -- the
        # bug we're chasing is on the regular-recipient path.
        self._server_min_fee = 1   # what tx_floor returns post-Tier-49

    def tearDown(self):
        shutil.rmtree(self._key_dir, ignore_errors=True)

    # ── Test helpers ───────────────────────────────────────────────
    def _args(self, **overrides):
        base = dict(
            to=self._recipient_addr,
            amount=10,
            fee=None,
            keyfile=self.key_path,
            data_dir=None,
            server="127.0.0.1:9334",
            yes=True,
            urgency="normal",
            allow_raw_hex_address=False,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def _build_fake_rpc(self, captured_tx: dict, server_min_fee: int = 1):
        def fake_rpc_call(host, port, method, params):
            if method == "estimate_fee":
                # Live server reports the unified Tier-49 floor.
                return {
                    "ok": True,
                    "result": {
                        "min_fee": server_min_fee,
                        "mempool_fee": 0,
                        "recipient_is_new": False,
                    },
                }
            if method == "get_nonce":
                return {
                    "ok": True,
                    "result": {"nonce": 0, "leaf_watermark": 0},
                }
            if method == "reserve_leaf":
                # Older-daemon fallback path: return not-ok so the
                # caller falls back to leaf_watermark.
                return {"ok": False, "error": "not implemented"}
            if method == "get_key_status":
                # Existing key — is_first_spend = False.
                return {
                    "ok": True,
                    "result": {"public_key": "aa" * 32},
                }
            if method == "get_chain_info":
                # Far past UNIFIED_FEE_FLOOR_HEIGHT so the auto-fee
                # helper sees the right height-aware floor.
                from messagechain.config import UNIFIED_FEE_FLOOR_HEIGHT
                return {
                    "ok": True,
                    "result": {"height": UNIFIED_FEE_FLOOR_HEIGHT + 1000},
                }
            if method == "submit_transfer":
                # Capture the tx for assertions.
                from messagechain.core.transfer import TransferTransaction
                tx = TransferTransaction.deserialize(params["transaction"])
                captured_tx["tx"] = tx
                return {
                    "ok": True,
                    "result": {
                        "tx_hash": tx.tx_hash,
                        "amount": tx.amount,
                        "fee": tx.fee,
                    },
                }
            return {"ok": True, "result": {}}
        return fake_rpc_call

    # ── (1) Auto-fee path: no --fee, server returns min_fee=1 ──────
    def test_auto_fee_does_not_clamp_up_to_legacy_min_fee(self):
        """At a post-Tier-49 height the server's transfer min_fee is
        ``MARKET_FEE_FLOOR = 1``.  The wallet must NOT inflate that
        to ``MIN_FEE = 100`` via a stale local ``max(MIN_FEE, ...)``.
        """
        from messagechain import cli as mod
        from messagechain.config import MIN_FEE

        captured = {}
        with patch("client.rpc_call",
                   self._build_fake_rpc(captured, server_min_fee=1)):
            buf = StringIO()
            with redirect_stdout(buf):
                # cmd_transfer doesn't return; SystemExit on failure.
                try:
                    mod.cmd_transfer(self._args())
                except SystemExit as e:
                    self.fail(
                        f"cmd_transfer exited unexpectedly: code={e.code}\n"
                        f"output:\n{buf.getvalue()}",
                    )

        self.assertIn("tx", captured, "transfer must have been submitted")
        tx = captured["tx"]
        # The bug: the wallet was clamping to MIN_FEE=100 even though
        # the server reported min_fee=1.  Post-fix the fee must be at
        # most a small auto-fee result anchored on the server's 1, not
        # the stale 100.
        self.assertLess(
            tx.fee, MIN_FEE,
            f"auto-fee for an existing-recipient transfer at a post-"
            f"Tier-49 height must follow the server's live floor (1), "
            f"not the legacy MIN_FEE={MIN_FEE} constant -- got fee={tx.fee}",
        )
        self.assertGreaterEqual(
            tx.fee, 1,
            "fee must clear the protocol floor (>=1)",
        )

    # ── (2) Explicit --fee 50 is accepted (below MIN_FEE, above floor) ─
    def test_explicit_fee_below_legacy_min_but_above_live_floor_accepted(self):
        """A user passing ``--fee 50`` at post-Tier-49 height must NOT
        be rejected with "below MIN_FEE 100" -- the live server floor
        is 1, and 50 clears it.  This is the headline UX symptom of
        the audit r45 #2 drift.
        """
        from messagechain import cli as mod

        captured = {}
        with patch("client.rpc_call",
                   self._build_fake_rpc(captured, server_min_fee=1)):
            buf = StringIO()
            with redirect_stdout(buf):
                try:
                    mod.cmd_transfer(self._args(fee=50))
                except SystemExit as e:
                    self.fail(
                        f"cmd_transfer rejected --fee 50 with exit code "
                        f"{e.code}; pre-r45 this was the silent-overcharge "
                        f"path that rejected legitimate sub-MIN_FEE bids.\n"
                        f"output:\n{buf.getvalue()}",
                    )

        self.assertIn("tx", captured)
        self.assertEqual(captured["tx"].fee, 50)

    # ── (3) Explicit --fee BELOW live server floor still rejected ─────
    def test_explicit_fee_below_live_server_floor_rejected(self):
        """The error path must still reject under-payments -- but the
        comparison must use the LIVE server floor, not the stale
        constant.  Server reports min_fee=5 -> --fee 3 rejected;
        --fee 5 accepted.
        """
        from messagechain import cli as mod

        captured = {}
        # Reject path: server says min_fee=5, user offers 3.
        with patch("client.rpc_call",
                   self._build_fake_rpc(captured, server_min_fee=5)):
            buf = StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit):
                mod.cmd_transfer(self._args(fee=3))
            err_msg = buf.getvalue()
        self.assertIn(
            "Error", err_msg,
            f"--fee 3 vs server min_fee=5 must error; got:\n{err_msg}",
        )
        self.assertNotIn(
            "tx", captured,
            "rejected transfer must not reach submit_transfer",
        )

        # Accept path: same server, --fee 5 (== floor) accepted.
        captured2 = {}
        with patch("client.rpc_call",
                   self._build_fake_rpc(captured2, server_min_fee=5)):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_transfer(self._args(fee=5))
        self.assertIn("tx", captured2)
        self.assertEqual(captured2["tx"].fee, 5)

    # ── (4) New-recipient surcharge still binds via server fee ─────
    def test_new_recipient_surcharge_still_binds(self):
        """When the recipient is brand-new on chain, ``estimate_fee``
        returns ``min_fee = MIN_FEE + NEW_ACCOUNT_FEE`` (the chain
        validator hard-codes this and the Tier-49 unification doesn't
        touch the new-account surcharge branch).  Trusting
        ``server_min_fee`` covers this case correctly -- the fix does
        NOT under-charge new-recipient transfers.
        """
        from messagechain import cli as mod
        from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE

        new_account_min = MIN_FEE + NEW_ACCOUNT_FEE  # what server returns

        def fake_rpc_call(host, port, method, params):
            if method == "estimate_fee":
                return {
                    "ok": True,
                    "result": {
                        "min_fee": new_account_min,
                        "mempool_fee": 0,
                        "recipient_is_new": True,
                    },
                }
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "reserve_leaf":
                return {"ok": False, "error": "not impl"}
            if method == "get_key_status":
                return {"ok": True, "result": {"public_key": "aa" * 32}}
            if method == "get_chain_info":
                from messagechain.config import UNIFIED_FEE_FLOOR_HEIGHT
                return {"ok": True,
                        "result": {"height": UNIFIED_FEE_FLOOR_HEIGHT + 1000}}
            if method == "submit_transfer":
                from messagechain.core.transfer import TransferTransaction
                tx = TransferTransaction.deserialize(params["transaction"])
                fake_rpc_call.captured = tx
                return {"ok": True, "result": {
                    "tx_hash": tx.tx_hash, "amount": tx.amount, "fee": tx.fee,
                }}
            return {"ok": True, "result": {}}

        with patch("client.rpc_call", fake_rpc_call):
            buf = StringIO()
            with redirect_stdout(buf):
                # Auto-fee path: --fee omitted.  The picked fee must
                # cover the new-account surcharge (i.e. >= new_account_min).
                mod.cmd_transfer(self._args(fee=None))

        tx = fake_rpc_call.captured  # type: ignore[attr-defined]
        self.assertGreaterEqual(
            tx.fee, new_account_min,
            f"new-recipient auto-fee must cover server's "
            f"MIN_FEE+NEW_ACCOUNT_FEE={new_account_min}; got {tx.fee}",
        )

    # ── (5) Structural: cli.cmd_transfer does NOT do max(MIN_FEE, ...) ─
    def test_cli_source_does_not_clamp_against_legacy_min_fee(self):
        """Belt-and-suspenders: pin the structural shape so a future
        copy-paste regression doesn't reintroduce the same drift in
        another sibling command (cmd_react / cmd_propose / etc.).
        """
        import messagechain.cli as cli_mod
        src = open(cli_mod.__file__, encoding="utf-8").read()
        # The exact bug literal -- if this string is back we have
        # regressed.
        self.assertNotIn(
            "max(MIN_FEE, server_min_fee)",
            src,
            "cli must not clamp the live server fee floor against "
            "the legacy MIN_FEE constant -- the unified Tier-49 fee "
            "model is the source of truth.",
        )

    # ── (6) client.py mirror: same structural assertion ─────────────
    def test_client_source_does_not_clamp_against_legacy_min_fee(self):
        import client as client_mod
        src = open(client_mod.__file__, encoding="utf-8").read()
        self.assertNotIn(
            "max(MIN_FEE, server_min_fee)",
            src,
            "client.py must not clamp the live server fee floor "
            "against the legacy MIN_FEE constant",
        )


if __name__ == "__main__":
    unittest.main()
