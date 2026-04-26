"""cmd_send must thread current_height into create_transaction.

Observed on mainnet 2026-04-25 during the first-ever user-message
probe (block 431): CLI's local_min computed 223 under the LINEAR
fee rule (LINEAR_FEE_HEIGHT had been pulled forward to 300, well
under the live tip), but `create_transaction` was called WITHOUT
`current_height`, so it fell back to the LEGACY quadratic floor and
demanded 323. Auto-fee submissions hit
`Fee must be at least 323 ...` and bounced.

Fixed by passing the same target_height the CLI used for its local
fee estimate. This regression test pins the behavior so a future
refactor doesn't drop the kwarg again.

Also covers the two friendlier-error fixes shipped alongside:
non-ASCII messages produce a clean diagnostic (not a Python
traceback) and the cold-start "Unknown entity" failure surfaces
the receive-to-exist explanation instead of a bare `Failed: ...`.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


def _send_args(message: str, **overrides):
    base = dict(
        message=message,
        fee=None,
        server="127.0.0.1:9334",
        prev=None,
        keyfile="/dev/null",
        data_dir=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class TestCmdSendThreadsCurrentHeight(unittest.TestCase):

    def test_create_transaction_called_with_current_height(self):
        """Reproduces the mainnet 2026-04-25 auto-fee bug.

        LINEAR_FEE_HEIGHT is currently 300 in production; chain tip
        sits well past that. The CLI MUST pass current_height to
        create_transaction so client-side fee enforcement matches the
        server-side LINEAR rule. Without it, create_transaction
        defaults to legacy quadratic and rejects auto-fee txs.
        """
        from messagechain import cli as cli_mod

        entity = MagicMock()
        entity.entity_id = b"\x01" * 32
        entity.entity_id_hex = "01" * 32
        entity.keypair = MagicMock()
        entity.keypair.advance_to_leaf = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        captured = {}

        def fake_create_transaction(*args, **kwargs):
            captured.update(kwargs)
            return fake_tx

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "reserve_leaf":
                return {"ok": True, "result": {"leaf": 0}}
            if method == "get_chain_info":
                # Live mainnet at the time of the probe was at h=432;
                # past LINEAR_FEE_HEIGHT (300) but well before the
                # FEE_INCLUDES_SIGNATURE_HEIGHT (64000).
                return {"ok": True, "result": {"height": 432}}
            if method == "get_fee_estimate":
                return {"ok": True, "result": {"fee_estimate": 100}}
            if method == "submit_transaction":
                return {"ok": True, "result": {"tx_hash": "deadbeef", "fee": 223}}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=entity), \
             patch("messagechain.core.transaction.create_transaction",
                   side_effect=fake_create_transaction), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch.object(cli_mod, "_reserve_leaf_via_rpc",
                          return_value=0):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli_mod.cmd_send(_send_args("hello world"))

        self.assertIn("current_height", captured,
            "cmd_send must pass current_height to create_transaction "
            "so the client-side fee floor matches the live LINEAR rule.")
        # get_chain_info reports `height` as the block count, so
        # tip_height = count - 1 = 431, and target_height = tip+1 = 432.
        # Threading that produces the LINEAR floor (BASE_TX_FEE +
        # FEE_PER_STORED_BYTE * stored).
        self.assertEqual(captured["current_height"], 432)


class TestCmdSendOversizeFriendlyError(unittest.TestCase):

    def test_oversize_message_emits_diagnostic_not_traceback(self):
        """A message exceeding MAX_MESSAGE_CHARS UTF-8 bytes must be
        caught early with a friendly diagnostic.  Replaces the pre-Tier-12
        em-dash diagnostic: post-INTL_MESSAGE_HEIGHT, em-dash and other
        Unicode punctuation are valid input — only the byte cap is
        client-side-rejectable without a chain round-trip.
        """
        from messagechain import cli as cli_mod
        from messagechain.config import MAX_MESSAGE_CHARS

        message = "a" * (MAX_MESSAGE_CHARS + 1)

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32):
            buf = io.StringIO()
            with redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    cli_mod.cmd_send(_send_args(message))

        self.assertNotEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertIn(f"max {MAX_MESSAGE_CHARS}", out)
        self.assertNotIn("Traceback", out,
            "must NOT expose a Python traceback to the user")


class TestCmdSendUnknownEntityFriendlyError(unittest.TestCase):

    def test_unknown_entity_response_explains_receive_to_exist(self):
        """When the chain rejects with 'Unknown entity', the CLI must
        explain the receive-to-exist model and the bootstrap path.
        Pre-1.7.7 this was a bare `Failed: Unknown entity ...` with
        no actionable next step -- the dominant cold-start failure.
        """
        from messagechain import cli as cli_mod

        entity = MagicMock()
        entity.entity_id = b"\x01" * 32
        entity.entity_id_hex = "01" * 32
        entity.keypair = MagicMock()
        entity.keypair.advance_to_leaf = MagicMock()

        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"fake": "tx"}

        def rpc_side(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 432}}
            if method == "get_fee_estimate":
                return {"ok": True, "result": {"fee_estimate": 100}}
            if method == "submit_transaction":
                return {"ok": False, "error": "Unknown entity -- must register first"}
            return {"ok": True, "result": {}}

        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=b"\x02" * 32), \
             patch("messagechain.identity.identity.Entity.create",
                   return_value=entity), \
             patch("messagechain.core.transaction.create_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch.object(cli_mod, "_reserve_leaf_via_rpc",
                          return_value=0):
            buf = io.StringIO()
            with redirect_stdout(buf):
                with self.assertRaises(SystemExit):
                    cli_mod.cmd_send(_send_args("hello"))

        out = buf.getvalue()
        self.assertIn("receive-to-exist", out)
        self.assertIn("Bootstrap path", out,
            "must surface the actionable bootstrap path")
        self.assertIn(entity.entity_id_hex, out,
            "must echo the user's address so they can ask someone "
            "to send tokens to it")


if __name__ == "__main__":
    unittest.main()
