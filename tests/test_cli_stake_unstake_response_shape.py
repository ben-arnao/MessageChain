"""cmd_stake / cmd_unstake must not KeyError on the real server response.

Regression: the RPC handlers `_rpc_stake` and `_rpc_unstake` return
{entity_id, tx_hash, status}.  The CLI previously tried to print
result['staked'] and result['balance'] — fields that don't exist in
the real response — and crashed with KeyError AFTER the tx had already
been submitted.  The existing unit tests passed because they mocked
the RPC response with fictional fields that matched the CLI's stale
assumptions.

This test mocks the RPC response with the ACTUAL shape defined in
server.py's _rpc_stake / _rpc_unstake and asserts the CLI path
completes cleanly.  If someone reintroduces a field that isn't in
the server contract, this test fails deterministically.
"""

import argparse
import unittest
from unittest.mock import MagicMock, patch

from messagechain import cli as cli_mod


# Must match server.py:_rpc_stake / _rpc_unstake return dicts.
# Update here AND in the handlers if the contract changes.
_REAL_STAKE_RESPONSE = {
    "ok": True,
    "result": {
        "entity_id": "7a72f1ec1ff9df12" + "0" * 48,
        "tx_hash": "deadbeef" + "0" * 56,
        "status": "pending — will be included in next block",
    },
}

_REAL_UNSTAKE_RESPONSE = {
    "ok": True,
    "result": {
        "entity_id": "7a72f1ec1ff9df12" + "0" * 48,
        "tx_hash": "deadbeef" + "0" * 56,
        "status": "pending — will be included in next block",
    },
}


def _build_args(amount=1000):
    return argparse.Namespace(
        amount=amount,
        fee=None,
        server="127.0.0.1:9334",
        yes=True,
        keyfile="/dev/null",
        data_dir="/var/lib/messagechain",
    )


class TestCliStakeUnstakeResponseShape(unittest.TestCase):

    def _run_cmd_against_real_shape(self, cmd_fn, rpc_method, real_response,
                                     create_tx_path):
        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "7a72f1ec1ff9df12" + "0" * 48
        cached_entity.keypair = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 3, "leaf_watermark": 5}}
            if method == rpc_method:
                return real_response
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 180}}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_load_cached_entity",
                          return_value=cached_entity), \
             patch(create_tx_path, return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            try:
                cmd_fn(_build_args())
            except SystemExit as e:
                self.assertEqual(e.code, 0,
                    f"{cmd_fn.__name__} must not exit nonzero on a "
                    f"successful RPC response — got exit code {e.code}. "
                    f"Almost certainly a KeyError on a field missing "
                    f"from the server's real response shape.")
            except KeyError as e:
                self.fail(
                    f"{cmd_fn.__name__} raised KeyError({e}) on the "
                    f"real server response shape. The CLI is reading "
                    f"a field that server.py's RPC handler does not "
                    f"return. Fix the CLI to use only fields in "
                    f"the real response, or extend the RPC handler "
                    f"to include the missing field.")

    def test_cmd_stake_handles_real_response(self):
        self._run_cmd_against_real_shape(
            cli_mod.cmd_stake,
            "stake",
            _REAL_STAKE_RESPONSE,
            "messagechain.core.staking.create_stake_transaction",
        )

    def test_cmd_unstake_handles_real_response(self):
        self._run_cmd_against_real_shape(
            cli_mod.cmd_unstake,
            "unstake",
            _REAL_UNSTAKE_RESPONSE,
            "messagechain.core.staking.create_unstake_transaction",
        )


if __name__ == "__main__":
    unittest.main()
