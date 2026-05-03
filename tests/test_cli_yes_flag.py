"""Script-friendliness: every interactive CLI subcommand honors --yes / -y.

Today most destructive subcommands (`stake`, `unstake`, `set-authority-key`,
`rotate-key`, `emergency-revoke`, `broadcast-revoke`,
`set-receipt-subtree-root`) already skip their "type 'yes' to proceed"
prompt when `args.yes` is true.  `transfer` did NOT -- which silently
hangs when the CLI is driven over `gcloud compute ssh ... -- ...
messagechain transfer ...` because the SSH+sudo wrapper does not deliver
piped stdin to `input()`.  This file pins the script-friendly contract
for ALL prompting subcommands so adding a new one in the future does not
silently regress the same way.

Test strategy: patch `builtins.input` with `side_effect=AssertionError`
so any call to `input()` blows up loudly.  With `--yes` honored, the
confirmation `input()` must never fire (key prompts are out of scope --
those are stubbed via `_resolve_private_key`).
"""

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock

from messagechain import cli


_TEST_PRIVKEY = bytes(range(32))


def _stub_rpc(method_returns):
    """Build an rpc_call stub that dispatches on the `method` arg."""
    calls = []

    def _call(host, port, method, params=None):
        calls.append((method, params))
        if method in method_returns:
            return method_returns[method]
        return {"ok": False, "error": f"unexpected method {method}"}

    _call.calls = calls
    return _call


def _common_args(**kw):
    ns = argparse.Namespace(
        keyfile=None,
        server="127.0.0.1:9334",
        fee=None,
        yes=True,  # the whole point of these tests
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# Per-command fixtures: each returns (cmd_func, args, rpc_returns,
# extra_patches).  All confirmation prompts must be skipped under --yes.
# ---------------------------------------------------------------------------
def _fx_transfer():
    recipient_hex = "cc" * 32
    args = _common_args(
        to=recipient_hex,
        amount=10,
        allow_raw_hex_address=True,
        urgency="normal",
    )
    rpc_returns = {
        "estimate_fee": {
            "ok": True,
            "result": {"recipient_is_new": False, "min_fee": 1},
        },
        "get_nonce": {
            "ok": True,
            "result": {"nonce": 0, "leaf_watermark": 0},
        },
        "reserve_leaf": {"ok": False, "error": "n/a"},
        "get_key_status": {
            "ok": True,
            "result": {
                "public_key": "dd" * 32,
                "rotation_number": 0,
                "leaf_watermark": 0,
            },
        },
        "get_chain_info": {
            "ok": True,
            "result": {"height": 1},
        },
        "submit_transfer": {
            "ok": True,
            "result": {"tx_hash": "00" * 32, "amount": 10, "fee": 1},
        },
    }
    return cli.cmd_transfer, args, rpc_returns, []


def _fx_stake():
    args = _common_args(amount=100, urgency="normal")
    rpc_returns = {
        "get_nonce": {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}},
        "get_chain_info": {"ok": True, "result": {"height": 1}},
        "estimate_fee": {"ok": True, "result": {"mempool_fee": 0}},
        "stake": {
            "ok": True,
            "result": {"tx_hash": "00" * 32, "staked": 100, "balance": 0},
        },
    }
    return cli.cmd_stake, args, rpc_returns, []


def _fx_unstake():
    args = _common_args(amount=50, urgency="normal")
    rpc_returns = {
        "get_nonce": {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}},
        "get_chain_info": {"ok": True, "result": {"height": 1}},
        "estimate_fee": {"ok": True, "result": {"mempool_fee": 0}},
        "unstake": {
            "ok": True,
            "result": {"tx_hash": "00" * 32, "staked": 50, "balance": 0},
        },
    }
    return cli.cmd_unstake, args, rpc_returns, []


def _fx_set_authority_key():
    pubkey_hex = "aa" * 32
    args = _common_args(authority_pubkey=pubkey_hex, cold_key_path=None)
    rpc_returns = {
        "get_nonce": {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}},
        "get_authority_key": {"ok": True, "result": {"authority_key": None}},
        "set_authority_key": {
            "ok": True,
            "result": {
                "entity_id": "11" * 32,
                "authority_key": pubkey_hex,
                "tx_hash": "00" * 32,
            },
        },
    }
    return cli.cmd_set_authority_key, args, rpc_returns, []


def _fx_rotate_key():
    new_pk = b"\x55" * 32
    mock_kp = MagicMock()
    mock_kp.public_key = new_pk
    mock_tx = MagicMock()
    mock_tx.serialize.return_value = {"rotation": "stubbed"}

    args = _common_args(urgency="normal")
    rpc_returns = {
        "get_key_status": {
            "ok": True,
            "result": {
                "rotation_number": 0,
                "leaf_watermark": 0,
                "public_key": "00" * 32,
                "tree_height": 4,
            },
        },
        "get_chain_info": {"ok": True, "result": {"height": 1}},
        "estimate_fee": {"ok": True, "result": {"mempool_fee": 0}},
        "rotate_key": {
            "ok": True,
            "result": {
                "entity_id": "11" * 32,
                "new_public_key": new_pk.hex(),
                "rotation_number": 1,
            },
        },
    }
    extra = [
        patch(
            "messagechain.core.key_rotation.derive_rotated_keypair",
            return_value=mock_kp,
        ),
        patch(
            "messagechain.core.key_rotation.create_key_rotation",
            return_value=mock_tx,
        ),
        patch("messagechain.cli._make_progress_reporter", return_value=None),
    ]
    return cli.cmd_rotate_key, args, rpc_returns, extra


def _fx_emergency_revoke():
    target_id = "bb" * 32
    args = _common_args(
        entity_id=target_id,
        print_only=False,
        valid_for_blocks=None,
    )
    rpc_returns = {
        "get_chain_info": {"ok": True, "result": {"height": 1}},
        "emergency_revoke": {
            "ok": True,
            "result": {"entity_id": target_id, "tx_hash": "00" * 32},
        },
    }
    return cli.cmd_emergency_revoke, args, rpc_returns, []


# Map of human label -> fixture builder.
FIXTURES = {
    "transfer": _fx_transfer,
    "stake": _fx_stake,
    "unstake": _fx_unstake,
    "set_authority_key": _fx_set_authority_key,
    "rotate_key": _fx_rotate_key,
    "emergency_revoke": _fx_emergency_revoke,
}


class TestYesFlagSkipsInput(unittest.TestCase):
    """`--yes` (`args.yes=True`) skips every confirmation `input()` call.

    Patches `builtins.input` with side_effect=AssertionError so any
    `input()` invocation explodes loudly with a name-tagged failure.
    """

    def _run(self, name):
        cmd_func, args, rpc_returns, extra = FIXTURES[name]()
        rpc_stub = _stub_rpc(rpc_returns)

        patches = [
            patch(
                "messagechain.cli._resolve_private_key",
                return_value=_TEST_PRIVKEY,
            ),
            patch("client.rpc_call", side_effect=rpc_stub),
            patch(
                "builtins.input",
                side_effect=AssertionError(
                    f"input() was called by cmd_{name} despite args.yes=True"
                ),
            ),
        ]
        patches.extend(extra)

        exit_code = None
        buf = io.StringIO()
        try:
            for p in patches:
                p.start()
            try:
                with redirect_stdout(buf):
                    cmd_func(args)
            finally:
                for p in reversed(patches):
                    p.stop()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

        return {
            "exit_code": exit_code,
            "stdout": buf.getvalue(),
            "rpc_methods": [m for (m, _p) in rpc_stub.calls],
        }

    def test_transfer_yes_skips_prompt(self):
        r = self._run("transfer")
        # The cancellation banner is the smoking gun for the prompt
        # path having been hit (it only prints when input() returned
        # something other than "yes").  Under --yes that branch must
        # be unreachable.
        self.assertNotIn("Transfer cancelled", r["stdout"])
        self.assertNotIn("cancelled", r["stdout"].lower())

    def test_stake_yes_skips_prompt(self):
        r = self._run("stake")
        self.assertNotIn("Stake cancelled", r["stdout"])

    def test_unstake_yes_skips_prompt(self):
        r = self._run("unstake")
        self.assertNotIn("Unstake cancelled", r["stdout"])

    def test_set_authority_key_yes_skips_prompt(self):
        r = self._run("set_authority_key")
        self.assertNotIn("Set-authority-key cancelled", r["stdout"])

    def test_rotate_key_yes_skips_prompt(self):
        r = self._run("rotate_key")
        self.assertNotIn("Rotate-key cancelled", r["stdout"])

    def test_emergency_revoke_yes_skips_prompt(self):
        r = self._run("emergency_revoke")
        self.assertNotIn("Emergency-revoke cancelled", r["stdout"])


class TestYesFlagParses(unittest.TestCase):
    """The argparse layer accepts --yes and -y on every prompting cmd."""

    def setUp(self):
        self.parser = cli.build_parser()

    def test_transfer_yes_long(self):
        args = self.parser.parse_args([
            "transfer", "--to", "mc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "--amount", "1", "--yes",
        ])
        self.assertTrue(args.yes)

    def test_transfer_yes_short(self):
        args = self.parser.parse_args([
            "transfer", "--to", "mc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "--amount", "1", "-y",
        ])
        self.assertTrue(args.yes)


if __name__ == "__main__":
    unittest.main()
