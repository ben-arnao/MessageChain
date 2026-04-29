"""Leaf-usage % must be computed against the per-entity tree_height.

Observed on live mainnet 2026-04-29: ``messagechain status --entity ...``
reported ``524288/65536 (800.0%) ROTATE NOW`` when the validator was
actually at 50% real capacity (tree_height=20 → 1,048,576 leaves).
Root cause: cmd_status (and the sibling cmd_key_status / cmd_rotate_key
display) hard-coded ``1 << 16`` or the global ``MERKLE_TREE_HEIGHT``
constant rather than consulting the per-entity ``tree_height`` from
chain state.  Personal wallets at h=16 and validators at h=20 coexist,
so a single global constant cannot be correct for both.

The reference implementation at ``cmd_rotate_key_if_needed`` already
does the right thing — it queries ``get_entity`` and reads
``tree_height`` from the result.  These tests pin the same behavior
into the three operator-facing display sites so a future revert
fails immediately rather than after another mainnet UX bug.

CLAUDE.md anchor: Simplicity (Principle #3) — operator-facing UX
shouldn't lie.  The status command is the primary operator
dashboard; reporting >100% usage trains operators to ignore the
traffic light.
"""

from __future__ import annotations

import argparse
import io
import unittest
from unittest.mock import MagicMock, patch


class TestCmdStatusLeafPctUsesPerEntityTreeHeight(unittest.TestCase):
    """``messagechain status --entity <hex>`` must compute leaf-usage %
    against the entity's stored ``tree_height``, not a hard-coded
    ``1 << 16``.
    """

    def _run_cmd_status(self, *, tree_height_in_response, leaf_watermark):
        """Drive cmd_status with stubbed RPC and return captured stdout."""
        from messagechain import cli as cli_mod

        # 64-hex entity ID (32 bytes).
        entity_hex = "ab" * 32
        args = argparse.Namespace(
            server=None, entity=entity_hex, full=False,
        )

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {
                    "height": 100,
                    "latest_block_hash": "cd" * 32,
                    "seconds_since_last_block": 5,
                    "sync_status": {"state": "idle"},
                }}
            if method == "get_entity":
                result = {
                    "entity_id": entity_hex,
                    "balance": 100,
                    "staked": 0,
                    "messages_posted": 0,
                    "nonce": 0,
                    "pubkey_registered": True,
                }
                if tree_height_in_response is not None:
                    result["tree_height"] = tree_height_in_response
                return {"ok": True, "result": result}
            if method == "get_leaf_watermark":
                return {"ok": True, "result": {
                    "leaf_watermark": leaf_watermark,
                }}
            return {"ok": True, "result": {}}

        buf = io.StringIO()
        with patch("client.rpc_call", side_effect=rpc_side), \
             patch("sys.stdout", new=buf):
            try:
                cli_mod.cmd_status(args)
            except SystemExit:
                pass
        return buf.getvalue()

    def test_validator_h20_at_50_percent_real_capacity(self):
        """A validator at tree_height=20 with watermark at 524288 is at
        EXACTLY 50% real capacity and must report ~50.0%, not 800%.
        """
        out = self._run_cmd_status(
            tree_height_in_response=20,
            leaf_watermark=524288,  # 50% of 1<<20
        )
        self.assertIn("524288/1048576", out,
                      "denominator must be 1<<20 for h=20 validator")
        self.assertIn("50.0%", out,
                      "leaf usage must report 50%, not 800%")
        self.assertNotIn("800.0%", out)
        self.assertNotIn("ROTATE NOW", out)

    def test_validator_h20_at_85_percent_yields_yellow(self):
        """h=20, 891289 leaves used = 85.0% — yellow band."""
        out = self._run_cmd_status(
            tree_height_in_response=20,
            leaf_watermark=891289,  # ~85.00%
        )
        self.assertIn("891289/1048576", out)
        self.assertIn("85.0%", out)
        # Yellow-band hint should fire, but not the red ROTATE NOW.
        self.assertNotIn("ROTATE NOW", out)

    def test_personal_wallet_h16_at_50_percent_real_capacity(self):
        """A personal wallet at tree_height=16 with watermark at 32768
        is at 50% — must use 65536 as the denominator.
        """
        out = self._run_cmd_status(
            tree_height_in_response=16,
            leaf_watermark=32768,
        )
        self.assertIn("32768/65536", out)
        self.assertIn("50.0%", out)

    def test_falls_back_to_wallet_default_when_entity_unknown(self):
        """First-touch: entity not on chain yet, so no tree_height in
        response.  Fall back to WALLET_DEFAULT_TREE_HEIGHT (16 in
        production; tests pin it lower to keep keygen cheap, so we
        assert the denominator matches the configured default rather
        than a hard-coded 65536).
        """
        from messagechain.config import WALLET_DEFAULT_TREE_HEIGHT
        out = self._run_cmd_status(
            tree_height_in_response=None,
            leaf_watermark=0,
        )
        expected_denom = 1 << WALLET_DEFAULT_TREE_HEIGHT
        self.assertIn(f"0/{expected_denom}", out,
                      "fallback denom must be 1 << WALLET_DEFAULT_TREE_HEIGHT")


class TestCmdKeyStatusUsesPerEntityTreeHeight(unittest.TestCase):
    """``messagechain key-status`` must compute capacity against the
    entity's stored ``tree_height``, not the local ``MERKLE_TREE_HEIGHT``.
    """

    def _run_cmd_key_status(
        self, *, tree_height_in_response, leaf_watermark, address=None,
    ):
        from messagechain import cli as cli_mod

        entity_hex = "ab" * 32
        args = MagicMock(
            spec=[
                "address", "entity_id", "data_dir", "key_file", "keyfile",
                "server",
            ],
        )
        args.address = address
        args.entity_id = entity_hex if address is None else None
        args.data_dir = None
        args.key_file = None
        args.keyfile = None
        args.server = None

        def rpc_side(host, port, method, params):
            if method == "get_key_status":
                result = {
                    "leaf_watermark": leaf_watermark,
                    "rotation_number": 0,
                    "public_key": "00" * 32,
                }
                return {"ok": True, "result": result}
            if method == "get_entity":
                result = {
                    "entity_id": entity_hex,
                    "balance": 0,
                    "staked": 0,
                    "messages_posted": 0,
                    "nonce": 0,
                    "pubkey_registered": True,
                }
                if tree_height_in_response is not None:
                    result["tree_height"] = tree_height_in_response
                return {"ok": True, "result": result}
            return {"ok": True, "result": {}}

        buf = io.StringIO()
        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_read_only_entity_id_hex",
                          return_value=entity_hex), \
             patch("sys.stdout", new=buf):
            try:
                cli_mod.cmd_key_status(args)
            except SystemExit:
                pass
        return buf.getvalue()

    def test_validator_h20_at_50_percent(self):
        out = self._run_cmd_key_status(
            tree_height_in_response=20,
            leaf_watermark=524288,
        )
        self.assertIn("524288 / 1048576", out)
        self.assertIn("50%", out)
        self.assertNotIn("800%", out)

    def test_personal_wallet_h16_at_50_percent(self):
        out = self._run_cmd_key_status(
            tree_height_in_response=16,
            leaf_watermark=32768,
        )
        self.assertIn("32768 / 65536", out)
        self.assertIn("50%", out)

    def test_h20_unknown_entity_falls_back_to_wallet_default(self):
        """When get_entity returns no tree_height, fall back to the
        personal-wallet default (16) — same fallback shape as
        cmd_rotate_key_if_needed, scaled to "first-touch state".
        Tests pin the wallet default lower for cheap keygen, so we
        assert against the configured value rather than 65536.
        """
        from messagechain.config import WALLET_DEFAULT_TREE_HEIGHT
        out = self._run_cmd_key_status(
            tree_height_in_response=None,
            leaf_watermark=0,
        )
        expected_denom = 1 << WALLET_DEFAULT_TREE_HEIGHT
        self.assertIn(f"/ {expected_denom}", out)


class TestCmdRotateKeyDisplayUsesPerEntityTreeHeight(unittest.TestCase):
    """The watermark line printed by ``cmd_rotate_key`` (before the
    actual rotation runs) must show ``watermark / (1 << tree_height)``
    using the entity's stored height, not the global config.
    """

    def test_validator_h20_watermark_display(self):
        from messagechain import cli as cli_mod

        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "ab" * 32
        cached_entity.entity_id = bytes.fromhex(cached_entity.entity_id_hex)
        cached_entity.keypair = MagicMock()
        cached_entity.public_key = b"\x00" * 32

        args = argparse.Namespace(
            fee=1000,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir=None,
            urgency="normal",
        )

        fake_new_kp = MagicMock()
        fake_new_kp.public_key = b"\x11" * 32
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "get_key_status":
                return {"ok": True, "result": {
                    "rotation_number": 0,
                    "leaf_watermark": 524288,
                }}
            if method == "get_entity":
                return {"ok": True, "result": {
                    "entity_id": cached_entity.entity_id_hex,
                    "tree_height": 20,
                }}
            if method == "rotate_key":
                return {"ok": True, "result": {
                    "entity_id": cached_entity.entity_id_hex,
                    "new_public_key": "ab" * 32,
                    "rotation_number": 1,
                }}
            return {"ok": True, "result": {}}

        buf = io.StringIO()
        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_resolve_signing_entity",
                          return_value=cached_entity), \
             patch.object(cli_mod, "_bind_persistent_leaf_index"), \
             patch("messagechain.core.key_rotation.derive_rotated_keypair",
                   return_value=fake_new_kp), \
             patch("messagechain.core.key_rotation.create_key_rotation",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch.object(cli_mod, "_make_progress_reporter",
                          return_value=None), \
             patch("sys.stdout", new=buf):
            try:
                cli_mod.cmd_rotate_key(args)
            except SystemExit:
                pass

        out = buf.getvalue()
        # Validator at h=20: denominator must be 2**20=1048576.
        self.assertIn("524288 / 1048576", out,
                      f"watermark display should use h=20 denom; got:\n{out}")

    def test_personal_wallet_h16_watermark_display(self):
        from messagechain import cli as cli_mod

        cached_entity = MagicMock()
        cached_entity.entity_id_hex = "cd" * 32
        cached_entity.entity_id = bytes.fromhex(cached_entity.entity_id_hex)
        cached_entity.keypair = MagicMock()
        cached_entity.public_key = b"\x00" * 32

        args = argparse.Namespace(
            fee=1000,
            server="127.0.0.1:9334",
            yes=True,
            keyfile="/dev/null",
            data_dir=None,
            urgency="normal",
        )

        fake_new_kp = MagicMock()
        fake_new_kp.public_key = b"\x11" * 32
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "get_key_status":
                return {"ok": True, "result": {
                    "rotation_number": 0,
                    "leaf_watermark": 32768,
                }}
            if method == "get_entity":
                return {"ok": True, "result": {
                    "entity_id": cached_entity.entity_id_hex,
                    "tree_height": 16,
                }}
            if method == "rotate_key":
                return {"ok": True, "result": {
                    "entity_id": cached_entity.entity_id_hex,
                    "new_public_key": "cd" * 32,
                    "rotation_number": 1,
                }}
            return {"ok": True, "result": {}}

        buf = io.StringIO()
        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x01" * 32), \
             patch.object(cli_mod, "_resolve_signing_entity",
                          return_value=cached_entity), \
             patch.object(cli_mod, "_bind_persistent_leaf_index"), \
             patch("messagechain.core.key_rotation.derive_rotated_keypair",
                   return_value=fake_new_kp), \
             patch("messagechain.core.key_rotation.create_key_rotation",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch.object(cli_mod, "_make_progress_reporter",
                          return_value=None), \
             patch("sys.stdout", new=buf):
            try:
                cli_mod.cmd_rotate_key(args)
            except SystemExit:
                pass

        out = buf.getvalue()
        self.assertIn("32768 / 65536", out,
                      f"watermark display should use h=16 denom; got:\n{out}")


if __name__ == "__main__":
    unittest.main()
