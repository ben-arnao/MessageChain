"""cmd_react submits a `submit_react` RPC with the right shape.

Pins the user-facing surface: target hex parsed to 32 bytes, choice
string mapped to REACT_CHOICE_*, target_type mapped to target_is_user,
and the resulting tx round-tripped through serialize() into the
`submit_react` params.  Self-trust votes refuse before signing.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from messagechain.core.reaction import (
    REACT_CHOICE_CLEAR,
    REACT_CHOICE_UP,
    REACT_CHOICE_DOWN,
)


def _react_args(target_hex: str, choice: str, **overrides):
    base = dict(
        target=target_hex,
        choice=choice,
        target_type="message",
        fee=None,
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
        urgency="normal",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _drive_cmd_react(args):
    """Run cmd_react with all RPCs stubbed; return (stdout, captured_calls).

    captured_calls lists every (method, params) pair the CLI sends to
    rpc_call.  The submit_react entry is the one the assertions key on.
    """
    from messagechain import cli as cli_mod

    captured = []

    def rpc_side(host, port, method, params):
        captured.append((method, params))
        if method == "get_nonce":
            return {"ok": True, "result": {"nonce": 7, "leaf_watermark": 7}}
        if method == "get_chain_info":
            return {"ok": True, "result": {"height": 10000}}
        if method == "estimate_fee":
            return {"ok": True, "result": {"mempool_fee": 5}}
        if method == "submit_react":
            return {
                "ok": True,
                "result": {"tx_hash": "ab" * 32, "fee": params["transaction"]["fee"]},
            }
        return {"ok": True, "result": {}}

    fake_tx = MagicMock()

    def fake_create_react(entity, *, target, target_is_user, choice, nonce, fee):
        fake_tx.target = target
        fake_tx.target_is_user = target_is_user
        fake_tx.choice = choice
        fake_tx.nonce = nonce
        fake_tx.fee = fee
        fake_tx.serialize.return_value = {
            "type": "react",
            "voter_id": "01" * 32,
            "target": target.hex(),
            "target_is_user": target_is_user,
            "choice": choice,
            "nonce": nonce,
            "fee": fee,
            "timestamp": 0.0,
            "signature": {},
            "tx_hash": "ab" * 32,
        }
        return fake_tx

    entity = MagicMock()
    entity.entity_id = b"\x01" * 32
    entity.entity_id_hex = "01" * 32
    entity.keypair = MagicMock()

    with patch.object(cli_mod, "_resolve_private_key", return_value=b"\x02" * 32), \
         patch("messagechain.identity.identity.Entity.create", return_value=entity), \
         patch("messagechain.core.reaction.create_react_transaction",
               side_effect=fake_create_react), \
         patch("client.rpc_call", side_effect=rpc_side), \
         patch.object(cli_mod, "_parse_server",
                      return_value=("127.0.0.1", 9334)), \
         patch.object(cli_mod, "_bind_persistent_leaf_index"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                cli_mod.cmd_react(args)
            except SystemExit:
                pass
        return buf.getvalue(), captured


class TestCmdReactSubmitsRPC(unittest.TestCase):
    def test_message_react_up_submits_correct_payload(self):
        target = "de" + "ad" * 31  # 64 chars
        out, calls = _drive_cmd_react(_react_args(target, "up"))
        submits = [p for m, p in calls if m == "submit_react"]
        self.assertEqual(len(submits), 1, f"expected one submit_react; got calls:\n{calls}")
        tx_dict = submits[0]["transaction"]
        self.assertEqual(tx_dict["target"], target)
        self.assertEqual(tx_dict["target_is_user"], False)
        self.assertEqual(tx_dict["choice"], REACT_CHOICE_UP)
        self.assertIn("Reaction submitted!", out)

    def test_message_react_down_maps_to_down_choice(self):
        target = "ca" + "fe" * 31
        _, calls = _drive_cmd_react(_react_args(target, "down"))
        submits = [p for m, p in calls if m == "submit_react"]
        self.assertEqual(submits[0]["transaction"]["choice"], REACT_CHOICE_DOWN)

    def test_message_react_clear_maps_to_clear_choice(self):
        target = "0a" + "1b" * 31
        _, calls = _drive_cmd_react(_react_args(target, "clear"))
        submits = [p for m, p in calls if m == "submit_react"]
        self.assertEqual(submits[0]["transaction"]["choice"], REACT_CHOICE_CLEAR)

    def test_user_target_type_sets_target_is_user_true(self):
        target = "be" + "ef" * 31
        _, calls = _drive_cmd_react(
            _react_args(target, "up", target_type="user"),
        )
        submits = [p for m, p in calls if m == "submit_react"]
        self.assertEqual(submits[0]["transaction"]["target_is_user"], True)


class TestCmdReactInputValidation(unittest.TestCase):
    def test_short_target_hex_rejected(self):
        out, calls = _drive_cmd_react(_react_args("dead", "up"))
        self.assertFalse(any(m == "submit_react" for m, _ in calls))
        self.assertIn("64 hex chars", out)

    def test_non_hex_target_rejected(self):
        out, calls = _drive_cmd_react(_react_args("zz" * 32, "up"))
        self.assertFalse(any(m == "submit_react" for m, _ in calls))
        self.assertIn("not valid hex", out)

    def test_self_user_trust_rejected_before_signing(self):
        # entity_id stub is b"\x01" * 32 -> "01" * 32 hex
        self_hex = "01" * 32
        out, calls = _drive_cmd_react(
            _react_args(self_hex, "up", target_type="user"),
        )
        self.assertFalse(any(m == "submit_react" for m, _ in calls))
        self.assertIn("yourself", out.lower())


class TestCmdReactSubcommandIsRegistered(unittest.TestCase):
    """Smoke test: the subparser exists and the dispatcher knows it."""

    def test_react_subcommand_in_parser(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        # argparse stashes choices on the sub-action; the subparser
        # registry is the easiest cross-version handle.
        sub_actions = [
            a for a in parser._actions
            if getattr(a, "choices", None) and "send" in a.choices
        ]
        self.assertTrue(sub_actions, "could not locate top-level subparsers")
        self.assertIn("react", sub_actions[0].choices)


if __name__ == "__main__":
    unittest.main()
