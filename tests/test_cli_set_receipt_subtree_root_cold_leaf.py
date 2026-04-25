"""cmd_set_receipt_subtree_root --cold-leaf advances past prior uses.

Cold-key leaf state is not tracked on chain (apply_set_receipt_subtree_root
deliberately does NOT bump the hot-key watermark, and the cold key's
own entity is rarely a registered chain entity), so an operator who
runs the command twice with the default leaf 0 produces two
different messages signed at the same WOTS+ leaf -- a leaf-reuse
violation that the chain will reject.

The 1.7.7 fix adds a --cold-leaf flag for explicit operator control
and surfaces the leaf used after signing so the operator knows what
to pass next time. This test pins both behaviors.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


def _cold_args(**overrides):
    base = dict(
        server="127.0.0.1:9334",
        root=None,
        entity_id=None,
        fee=None,
        yes=True,
        print_tx=False,
        cold_leaf=0,
        keyfile="/dev/null",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class TestColdLeafAdvancement(unittest.TestCase):

    def test_cold_leaf_flag_advances_keypair_before_signing(self):
        from messagechain import cli as cli_mod

        v2_id_hex = "89" * 32
        root_hex = "7b" * 32

        cold = MagicMock()
        cold.entity_id_hex = v2_id_hex
        cold.entity_id = bytes.fromhex(v2_id_hex)
        cold.public_key = b"\x01" * 32
        cold.keypair = MagicMock()
        cold.keypair.advance_to_leaf = MagicMock()

        fake_sig = MagicMock()
        fake_sig.leaf_index = 5
        fake_tx = MagicMock()
        fake_tx.signature = fake_sig
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "set_receipt_subtree_root":
                return {"ok": True, "result": {
                    "entity_id": v2_id_hex,
                    "root_public_key": root_hex,
                    "tx_hash": "deadbeef",
                    "status": "pending",
                }}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=cold), \
             patch("messagechain.core.receipt_subtree_root."
                   "create_set_receipt_subtree_root_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli_mod.cmd_set_receipt_subtree_root(
                    _cold_args(
                        root=root_hex, entity_id=v2_id_hex, cold_leaf=5,
                    )
                )

        cold.keypair.advance_to_leaf.assert_called_once_with(5)
        out = buf.getvalue()
        self.assertIn("Cold leaf:  5", out,
            "must surface the leaf used so operator can self-track")
        self.assertIn("--cold-leaf 6", out,
            "must tell the operator the next leaf to pass")

    def test_cold_leaf_zero_does_not_call_advance(self):
        """Default cold-leaf=0 must not call advance_to_leaf -- leaving
        the keypair at its fresh _next_leaf=0 is the correct behavior
        for the first-ever cold-key signing.
        """
        from messagechain import cli as cli_mod

        v2_id_hex = "89" * 32
        root_hex = "7b" * 32

        cold = MagicMock()
        cold.entity_id_hex = v2_id_hex
        cold.entity_id = bytes.fromhex(v2_id_hex)
        cold.public_key = b"\x01" * 32
        cold.keypair = MagicMock()
        cold.keypair.advance_to_leaf = MagicMock()

        fake_sig = MagicMock()
        fake_sig.leaf_index = 0
        fake_tx = MagicMock()
        fake_tx.signature = fake_sig
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "set_receipt_subtree_root":
                return {"ok": True, "result": {
                    "entity_id": v2_id_hex,
                    "root_public_key": root_hex,
                    "tx_hash": "deadbeef",
                    "status": "pending",
                }}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=cold), \
             patch("messagechain.core.receipt_subtree_root."
                   "create_set_receipt_subtree_root_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli_mod.cmd_set_receipt_subtree_root(
                    _cold_args(root=root_hex, entity_id=v2_id_hex)
                )

        cold.keypair.advance_to_leaf.assert_not_called()


class TestServerMismatchActionableError(unittest.TestCase):

    def test_remote_entity_mismatch_suggests_root_flag(self):
        """When --server points at a different validator than the cold
        key controls, the CLI must explain the situation and tell the
        operator to pass --root <hex> to broadcast through the peer.
        Pre-1.7.7 the error was 'Refusing to register a root for the
        wrong entity.' with no clue what to do.
        """
        from messagechain import cli as cli_mod

        v1_id_hex = "7a" * 32
        v2_id_hex = "89" * 32

        cold = MagicMock()
        cold.entity_id_hex = v2_id_hex
        cold.entity_id = bytes.fromhex(v2_id_hex)
        cold.public_key = b"\x01" * 32
        cold.keypair = MagicMock()
        cold.keypair.advance_to_leaf = MagicMock()

        def rpc_side(host, port, method, params):
            if method == "get_local_receipt_root":
                # Server reports v1 (peer) but operator targets v2.
                return {"ok": True, "result": {
                    "installed": True,
                    "entity_id": v1_id_hex,
                    "root_public_key": "ab" * 32,
                    "registered_root": None,
                    "registration_needed": True,
                }}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=cold), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    cli_mod.cmd_set_receipt_subtree_root(_cold_args())
        self.assertNotEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertIn("--root", out,
            "must point the operator at the --root workaround")
        self.assertIn("PEER", out)
        self.assertIn("Receipt issuer installed", out,
            "must tell operator where to find the root in logs")


if __name__ == "__main__":
    unittest.main()
