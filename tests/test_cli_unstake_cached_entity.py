"""cmd_unstake --data-dir must use the cached entity, not fresh keygen.

Observed on live mainnet 2026-04-24: `python -m messagechain unstake
--data-dir /var/lib/messagechain --keyfile /dev/shm/mc-key ...` ran
at 97% CPU for 10+ minutes without finishing.  Root cause: cmd_unstake
skips the `_load_cached_entity(private_key, data_dir)` fast-path that
cmd_stake / cmd_transfer / cmd_send use, and instead calls
`Entity.create(private_key)` unconditionally — regenerating the full
65,536-leaf WOTS+ Merkle tree from scratch on every invocation.

On an e2-small that keygen is ~20–30 min; on a production
tree_height=20 wallet it's ~30 min.  The fix is trivial: mirror the
cmd_stake pattern so --data-dir reuses the daemon's cached keypair.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import argparse


class TestCmdUnstakeUsesCachedEntity(unittest.TestCase):

    def test_unstake_with_data_dir_uses_cached_entity(self):
        """When --data-dir is provided, cmd_unstake must prefer
        _load_cached_entity over Entity.create — the same pattern
        cmd_stake already uses.  Without this, unstake forces a
        multi-minute Merkle-tree regen on every invocation and is
        effectively unusable on the wallet sizes mainnet validators
        run today."""
        from messagechain import cli as cli_mod

        args = argparse.Namespace(
            amount=1000,
            fee=None,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",   # _resolve_private_key is patched below
            data_dir="/var/lib/messagechain",
        )

        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "7a72f1ec1ff9df12" + "0" * 48
        cached_entity.keypair = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        entity_create_called = {"n": 0}

        def fake_entity_create(pk):
            entity_create_called["n"] += 1
            return cached_entity  # shouldn't be used

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_load_cached_entity",
                          return_value=cached_entity) as mock_cached, \
             patch("messagechain.identity.identity.Entity.create",
                   side_effect=fake_entity_create), \
             patch("messagechain.core.staking.create_unstake_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call") as mock_rpc, \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):

            def rpc_side(host, port, method, params):
                if method == "get_nonce":
                    return {"ok": True, "result": {"nonce": 3, "leaf_watermark": 5}}
                if method == "unstake":
                    return {"ok": True, "result": {
                        "tx_hash": "deadbeef",
                        "staked": 50000000,
                        "balance": 0,
                        "unstaking": 47494250,
                    }}
                if method == "get_chain_info":
                    return {"ok": True, "result": {"height": 180}}
                return {"ok": True, "result": {}}

            mock_rpc.side_effect = rpc_side

            try:
                cli_mod.cmd_unstake(args)
            except SystemExit as e:
                # cmd_unstake can sys.exit(0) on success paths; any
                # nonzero exit means it failed, which is a test bug.
                self.assertEqual(e.code, 0, "unstake should succeed")

            mock_cached.assert_called_once_with(b"\x01" * 32, "/var/lib/messagechain")
            self.assertEqual(
                entity_create_called["n"], 0,
                "Entity.create must NOT be called when the cache "
                "provides a usable entity — otherwise every unstake "
                "invocation eats a 20–30 min Merkle-tree regen.",
            )


if __name__ == "__main__":
    unittest.main()
