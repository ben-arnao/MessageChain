"""cmd_stake / cmd_unstake auto-fee must match the live admission floor.

Regression: the CLI used to clamp its auto-computed fee to
``MIN_FEE_POST_FLAT`` (= 1000), a pre-Tier-16 floor.  Post-Tier-16 the
chain admits stake/unstake at fee >= ``max(MIN_FEE=100,
MARKET_FEE_FLOOR=1) = 100``, and Tier 29 (height 755) anchors a
"1 faucet drip = end-to-end validator stake" flow where one drip (300
tokens) funds the stake (200) + the fee (100) exactly.  A 1000-token
CLI floor breaks that anchor — a fresh 300-drip operator can't stake.

This test asserts cmd_stake / cmd_unstake at a post-Tier-29 height with
``--fee None`` produce the protocol's actual stake floor (100), not the
stale 1000.  If someone re-introduces the clamp the test fires.
"""

import argparse
import unittest
from unittest.mock import MagicMock, patch

from messagechain import cli as cli_mod
from messagechain.config import (
    MIN_FEE,
    VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT,
)


_REAL_STAKE_RESPONSE = {
    "ok": True,
    "result": {
        "entity_id": "7a72f1ec1ff9df12" + "0" * 48,
        "tx_hash": "deadbeef" + "0" * 56,
        "status": "pending",
    },
}


def _build_args(amount=200):
    return argparse.Namespace(
        amount=amount,
        fee=None,
        server="127.0.0.1:9334",
        yes=True,
        keyfile="/dev/null",
        data_dir="/var/lib/messagechain",
        urgency="normal",
    )


class TestCliStakeFeeFloor(unittest.TestCase):
    """The CLI must NOT clamp its auto-fee above the live admission rule."""

    def _run_capture_fee(self, cmd_fn, rpc_method, real_response,
                         create_tx_path):
        """Drive cmd_fn through a stub RPC.  Capture the fee that was
        passed into create_*_transaction — that's the bid that would
        hit the chain."""
        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "7a72f1ec1ff9df12" + "0" * 48
        cached_entity.keypair = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        # Tip > VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT so the live
        # admission rule (max(MIN_FEE, MARKET_FEE_FLOOR) = 100) is
        # what auto_fee returns.
        live_height = VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT + 200

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {
                    "ok": True,
                    "result": {"nonce": 3, "leaf_watermark": 5},
                }
            if method == rpc_method:
                return real_response
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": live_height}}
            if method == "estimate_fee":
                return {"ok": True, "result": {"mempool_fee": 0}}
            return {"ok": True, "result": {}}

        captured = {}

        def _capture(entity, amount, *, nonce, fee):
            captured["fee"] = fee
            captured["amount"] = amount
            return fake_tx

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_load_cached_entity",
                          return_value=cached_entity), \
             patch(create_tx_path, side_effect=_capture), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            try:
                cmd_fn(_build_args())
            except SystemExit as e:
                self.assertEqual(e.code, 0,
                    f"{cmd_fn.__name__} must succeed on a healthy "
                    f"stub RPC (exit code {e.code}).")
        return captured

    def test_cmd_stake_uses_live_admission_floor_not_stale_clamp(self):
        captured = self._run_capture_fee(
            cli_mod.cmd_stake,
            "stake",
            _REAL_STAKE_RESPONSE,
            "messagechain.core.staking.create_stake_transaction",
        )
        # Anchored: post-Tier-16, the stake admission floor is
        # max(MIN_FEE, MARKET_FEE_FLOOR) = MIN_FEE = 100.  A stale
        # MIN_FEE_POST_FLAT clamp (=1000) would 10x the bid and break
        # the Tier 29 1-drip flow (drip=300 = 200 stake + 100 fee).
        self.assertEqual(captured["fee"], MIN_FEE,
            f"cmd_stake auto-fee must match the live admission floor "
            f"({MIN_FEE}), got {captured['fee']}.  A 1000-token clamp "
            f"breaks the Tier 29 anchored 1-drip validator onboarding "
            f"flow.")

    def test_cmd_unstake_uses_live_admission_floor_not_stale_clamp(self):
        captured = self._run_capture_fee(
            cli_mod.cmd_unstake,
            "unstake",
            _REAL_STAKE_RESPONSE,
            "messagechain.core.staking.create_unstake_transaction",
        )
        self.assertEqual(captured["fee"], MIN_FEE,
            f"cmd_unstake auto-fee must match the live admission "
            f"floor ({MIN_FEE}), got {captured['fee']}.  Same shape "
            f"bug as cmd_stake — a 1000-token clamp pins unstake "
            f"fees 10x above the chain's actual rule.")


if __name__ == "__main__":
    unittest.main()
