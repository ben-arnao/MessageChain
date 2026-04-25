"""cmd_set_authority_key / cmd_rotate_key --data-dir must use the cached entity.

Observed on live mainnet 2026-04-24: `python -m messagechain
set-authority-key --data-dir /var/lib/messagechain --keyfile /dev/shm/mc-key
...` wedged for 10+ minutes with no output. Root cause: same
anti-pattern that test_cli_unstake_cached_entity.py was created
to prevent — these signing commands skipped the
`_load_cached_entity(private_key, data_dir)` fast-path and
unconditionally regenerated the WOTS+ Merkle tree from scratch
(~30 min at production tree_height=20). The fix mirrors the
cmd_stake / cmd_unstake pattern so --data-dir reuses the daemon's
cached keypair.

This regression test guards the same fast-path for cmd_set_authority_key
and cmd_rotate_key. If a future refactor reintroduces a bare
`Entity.create(private_key)` in either, this test fails fast at
test time instead of after a real operator wedge on a live host.
"""

from __future__ import annotations

import argparse
import unittest
from unittest.mock import MagicMock, patch


class TestCmdSetAuthorityKeyUsesCachedEntity(unittest.TestCase):

    def test_set_authority_key_with_data_dir_uses_cached_entity(self):
        from messagechain import cli as cli_mod

        args = argparse.Namespace(
            authority_pubkey="9c" + "f" * 62,
            fee=None,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir="/var/lib/messagechain",
        )

        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "7a72f1ec1ff9df12" + "0" * 48
        cached_entity.entity_id = bytes.fromhex(cached_entity.entity_id_hex)
        cached_entity.keypair = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        entity_create_called = {"n": 0}

        def fake_entity_create(pk):
            entity_create_called["n"] += 1
            return cached_entity

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_load_cached_entity",
                          return_value=cached_entity) as mock_cached, \
             patch("messagechain.identity.identity.Entity.create",
                   side_effect=fake_entity_create), \
             patch("messagechain.core.authority_key.create_set_authority_key_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call") as mock_rpc, \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):

            def rpc_side(host, port, method, params):
                if method == "get_nonce":
                    return {"ok": True, "result": {"nonce": 3, "leaf_watermark": 5}}
                if method == "set_authority_key":
                    return {"ok": True, "result": {
                        "entity_id": cached_entity.entity_id_hex,
                        "tx_hash": "deadbeef",
                        "authority_key": args.authority_pubkey,
                    }}
                return {"ok": True, "result": {}}

            mock_rpc.side_effect = rpc_side

            try:
                cli_mod.cmd_set_authority_key(args)
            except SystemExit as e:
                self.assertEqual(e.code, 0,
                    "set-authority-key should succeed")

            mock_cached.assert_called_once_with(b"\x01" * 32, "/var/lib/messagechain")
            self.assertEqual(
                entity_create_called["n"], 0,
                "Entity.create must NOT be called when the cache "
                "provides a usable entity — otherwise every "
                "set-authority-key invocation eats a 20-30 min "
                "Merkle-tree regen on production wallets.",
            )


class TestCmdRotateKeyUsesCachedEntity(unittest.TestCase):

    def test_rotate_key_with_data_dir_uses_cached_entity(self):
        from messagechain import cli as cli_mod

        args = argparse.Namespace(
            fee=None,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir="/var/lib/messagechain",
        )

        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "7a72f1ec1ff9df12" + "0" * 48
        cached_entity.entity_id = bytes.fromhex(cached_entity.entity_id_hex)
        cached_entity.keypair = MagicMock()

        fake_new_kp = MagicMock()
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        entity_create_called = {"n": 0}

        def fake_entity_create(pk):
            entity_create_called["n"] += 1
            return cached_entity

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_load_cached_entity",
                          return_value=cached_entity) as mock_cached, \
             patch("messagechain.identity.identity.Entity.create",
                   side_effect=fake_entity_create), \
             patch("messagechain.core.key_rotation.derive_rotated_keypair",
                   return_value=fake_new_kp), \
             patch("messagechain.core.key_rotation.create_key_rotation",
                   return_value=fake_tx), \
             patch("client.rpc_call") as mock_rpc, \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):

            def rpc_side(host, port, method, params):
                if method == "get_key_status":
                    return {"ok": True, "result": {
                        "rotation_number": 0,
                        "leaf_watermark": 5,
                    }}
                if method == "rotate_key":
                    return {"ok": True, "result": {
                        "entity_id": cached_entity.entity_id_hex,
                        "new_public_key": "ab" * 32,
                        "rotation_number": 1,
                        "tx_hash": "deadbeef",
                        "status": "pending — will be included in next block",
                    }}
                return {"ok": True, "result": {}}

            mock_rpc.side_effect = rpc_side

            try:
                cli_mod.cmd_rotate_key(args)
            except SystemExit as e:
                self.assertEqual(e.code, 0,
                    "rotate-key should succeed")

            mock_cached.assert_called_once_with(b"\x01" * 32, "/var/lib/messagechain")
            self.assertEqual(
                entity_create_called["n"], 0,
                "Entity.create must NOT be called for the CURRENT "
                "tree when the cache provides a usable entity — "
                "every rotate-key invocation otherwise eats a "
                "20-30 min Merkle-tree regen on the old tree, "
                "BEFORE deriving the new one.",
            )


if __name__ == "__main__":
    unittest.main()
