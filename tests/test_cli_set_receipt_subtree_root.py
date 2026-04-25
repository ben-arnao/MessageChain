"""cmd_set_receipt_subtree_root + the get_local_receipt_root RPC.

Background — observed on live mainnet 2026-04-25 (validator-2): after
the cold-authority-key promotion, the boot-time receipt-subtree
auto-submit path correctly detects that the cold key is offline and
prints an actionable warning telling the operator to run
`messagechain set-receipt-subtree-root`. The command did not exist.
Net effect: v2's receipt-subtree root sat unregistered, breaking
receipt verification for anything routed through that node.

This test pins the new operator path:

  * `get_local_receipt_root` RPC reports the in-memory root + whether
    a registration is needed (used by the CLI to skip when on-chain
    already matches).
  * `cmd_set_receipt_subtree_root` fetches the local root, signs with
    the cold key, broadcasts via `set_receipt_subtree_root`, and
    refuses to sign the wrong entity's root.
  * `--root` skips the RPC fetch (air-gapped flow).
  * `--print-tx` emits the signed tx as JSON without broadcasting,
    so an operator on a cold host can sign and hand the blob off to
    a network-connected host for submission.
  * No-op when the local root already matches the on-chain root.
"""

from __future__ import annotations

import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


def _cold_args(**overrides):
    """Default Namespace for cmd_set_receipt_subtree_root tests."""
    base = dict(
        server="127.0.0.1:9334",
        root=None,
        entity_id=None,
        fee=None,
        yes=True,
        print_tx=False,
        keyfile="/dev/null",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class TestCmdSetReceiptSubtreeRoot(unittest.TestCase):

    def _patch_cold_entity(self, entity_id_hex: str):
        """Patch _resolve_private_key + Entity.create to yield a fake
        cold entity with the given entity_id. Returns the MagicMock so
        callers can assert against .keypair.sign etc.
        """
        cold = MagicMock()
        cold.entity_id_hex = entity_id_hex
        cold.entity_id = bytes.fromhex(entity_id_hex)
        cold.public_key = b"\x01" * 32
        cold.keypair = MagicMock()
        return cold

    def test_fetches_root_signs_and_broadcasts(self):
        from messagechain import cli as cli_mod

        v2_id_hex = "8954a7196026ef9586c57ab88ec8c2240d664585b84eb6fdc4b2333f859edc8f"
        local_root_hex = "7bdaabe7656390690000000000000000000000000000000000000000000000aa"

        cold = self._patch_cold_entity(v2_id_hex)
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        rpc_calls = []

        def rpc_side(host, port, method, params):
            rpc_calls.append((method, params))
            if method == "get_local_receipt_root":
                return {"ok": True, "result": {
                    "installed": True,
                    "entity_id": v2_id_hex,
                    "root_public_key": local_root_hex,
                    "registered_root": None,
                    "registration_needed": True,
                }}
            if method == "set_receipt_subtree_root":
                return {"ok": True, "result": {
                    "entity_id": v2_id_hex,
                    "root_public_key": local_root_hex,
                    "tx_hash": "deadbeef",
                    "status": "pending — will be included in next block",
                }}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=cold), \
             patch("messagechain.core.receipt_subtree_root."
                   "create_set_receipt_subtree_root_transaction",
                   return_value=fake_tx) as mock_create, \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli_mod.cmd_set_receipt_subtree_root(_cold_args())

        methods = [m for m, _ in rpc_calls]
        self.assertEqual(methods, [
            "get_local_receipt_root",
            "set_receipt_subtree_root",
        ], "must fetch root first then broadcast")

        # The tx was built for the v2 entity using the fetched root,
        # signed by the cold (authority) entity.
        kwargs = mock_create.call_args.kwargs
        self.assertEqual(kwargs["entity_id"], bytes.fromhex(v2_id_hex))
        self.assertEqual(kwargs["root_public_key"], bytes.fromhex(local_root_hex))
        self.assertIs(kwargs["authority_signer"], cold)

    def test_refuses_when_remote_entity_does_not_match_cold_key(self):
        """Safety check: if the server is a different validator than
        the cold key controls, sign-and-broadcast would publish a root
        for the wrong entity. The CLI must refuse rather than guess.
        """
        from messagechain import cli as cli_mod

        v1_id_hex = "7a72f1ec1ff9df12318043c91a444daecf7b82731c072371479fba371d6b930e"
        v2_id_hex = "8954a7196026ef9586c57ab88ec8c2240d664585b84eb6fdc4b2333f859edc8f"

        # Cold key controls v2 but the operator is talking to v1 by mistake.
        cold = self._patch_cold_entity(v2_id_hex)

        def rpc_side(host, port, method, params):
            if method == "get_local_receipt_root":
                return {"ok": True, "result": {
                    "installed": True,
                    "entity_id": v1_id_hex,  # wrong validator
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
        self.assertNotEqual(cm.exception.code, 0,
            "must exit non-zero when entity mismatch detected")

    def test_no_op_when_already_registered(self):
        """If the local root already matches the on-chain root the
        CLI must exit 0 without broadcasting — otherwise re-running
        post-rollout is a noisy no-op tx.
        """
        from messagechain import cli as cli_mod

        v2_id_hex = "89" * 32
        root_hex = "7b" * 32

        cold = self._patch_cold_entity(v2_id_hex)

        broadcasts = []

        def rpc_side(host, port, method, params):
            if method == "get_local_receipt_root":
                return {"ok": True, "result": {
                    "installed": True,
                    "entity_id": v2_id_hex,
                    "root_public_key": root_hex,
                    "registered_root": root_hex,
                    "registration_needed": False,
                }}
            if method == "set_receipt_subtree_root":
                broadcasts.append(params)
                return {"ok": True, "result": {}}
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
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(broadcasts, [],
            "must not broadcast when on-chain root already matches")

    def test_root_flag_skips_rpc_fetch(self):
        """--root <hex> bypasses get_local_receipt_root entirely so an
        operator on an air-gapped host can sign without contacting the
        validator. Pair with --print-tx for full air-gap.
        """
        from messagechain import cli as cli_mod

        v2_id_hex = "89" * 32
        root_hex = "7b" * 32

        cold = self._patch_cold_entity(v2_id_hex)
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"signed": True}

        rpc_calls = []

        def rpc_side(host, port, method, params):
            rpc_calls.append(method)
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

        self.assertNotIn("get_local_receipt_root", rpc_calls,
            "--root must skip the RPC fetch")
        self.assertIn("set_receipt_subtree_root", rpc_calls)

    def test_print_tx_emits_json_without_broadcasting(self):
        """--print-tx + --root + --entity-id is the air-gapped flow:
        sign on the cold host, print signed tx JSON, broadcast later
        from a separate machine.
        """
        from messagechain import cli as cli_mod

        v2_id_hex = "89" * 32
        root_hex = "7b" * 32

        cold = self._patch_cold_entity(v2_id_hex)
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"signed": True, "tx_hash": "abc"}

        broadcasts = []

        def rpc_side(host, port, method, params):
            broadcasts.append(method)
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
                        root=root_hex, entity_id=v2_id_hex, print_tx=True,
                    )
                )

        self.assertEqual(broadcasts, [],
            "--print-tx must not broadcast")
        out = buf.getvalue()
        # The serialized tx blob is in the output as JSON.
        parsed = None
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("{"):
                try:
                    parsed = json.loads(out[out.index(stripped):])
                    break
                except json.JSONDecodeError:
                    continue
        self.assertIsNotNone(parsed, "must emit JSON for the signed tx")
        self.assertEqual(parsed.get("signed"), True)


class TestGetLocalReceiptRootRPC(unittest.TestCase):
    """The RPC the CLI relies on. Lightweight smoke test — exercises
    the dispatch path against a stub server with a fake receipt issuer.
    """

    def test_returns_root_and_registration_needed(self):
        import server as server_mod

        stub = MagicMock(spec=server_mod.Server)
        stub.receipt_issuer = MagicMock()
        stub.receipt_issuer.issuer_id = bytes.fromhex("89" * 32)
        stub.receipt_issuer.subtree_keypair = MagicMock()
        stub.receipt_issuer.subtree_keypair.public_key = bytes.fromhex("7b" * 32)
        stub.blockchain = MagicMock()
        stub.blockchain.receipt_subtree_roots = {}

        result = server_mod.Server._rpc_get_local_receipt_root(stub, {})
        self.assertTrue(result["ok"])
        body = result["result"]
        self.assertTrue(body["installed"])
        self.assertEqual(body["entity_id"], "89" * 32)
        self.assertEqual(body["root_public_key"], "7b" * 32)
        self.assertIsNone(body["registered_root"])
        self.assertTrue(body["registration_needed"])

    def test_reports_no_op_when_root_matches(self):
        import server as server_mod

        same_root = bytes.fromhex("7b" * 32)
        stub = MagicMock(spec=server_mod.Server)
        stub.receipt_issuer = MagicMock()
        stub.receipt_issuer.issuer_id = bytes.fromhex("89" * 32)
        stub.receipt_issuer.subtree_keypair = MagicMock()
        stub.receipt_issuer.subtree_keypair.public_key = same_root
        stub.blockchain = MagicMock()
        stub.blockchain.receipt_subtree_roots = {
            stub.receipt_issuer.issuer_id: same_root,
        }

        body = server_mod.Server._rpc_get_local_receipt_root(stub, {})["result"]
        self.assertFalse(body["registration_needed"])
        self.assertEqual(body["registered_root"], "7b" * 32)

    def test_relay_only_node_reports_not_installed(self):
        import server as server_mod

        stub = MagicMock(spec=server_mod.Server)
        stub.receipt_issuer = None
        body = server_mod.Server._rpc_get_local_receipt_root(stub, {})["result"]
        self.assertFalse(body["installed"])


if __name__ == "__main__":
    unittest.main()
