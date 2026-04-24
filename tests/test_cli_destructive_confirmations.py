"""RB-3: destructive CLI commands must prompt for user confirmation.

Five commands (`stake`, `unstake`, `set-authority-key`, `rotate-key`,
`emergency-revoke`) submit irreversible on-chain transactions.  Before
this change they executed with no confirmation gate, so a typo on
`--amount` or `--entity-id` was enough to lock funds, disable a
validator, or permanently bind the wrong cold authority key.  These
tests pin the new behavior: an interactive "type 'yes' to proceed"
prompt by default, a `--yes` / `-y` flag for scripted automation, and
a clean exit-0 on decline (user explicitly cancelled, not an error).

The `cmd_transfer` regression path is also covered so the existing
confirmation gate stays intact.
"""

import argparse
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock

from messagechain import cli


# A deterministic 32-byte private key.  The CLI derives an Entity from
# it; the exact bytes do not matter, only that it is a valid private
# key the key-encoding + Entity paths accept.
_TEST_PRIVKEY = bytes(range(32))


def _stub_rpc(method_returns):
    """Build an rpc_call stub that dispatches on the `method` arg.

    `method_returns` is a dict mapping RPC method name -> response dict.
    Unknown methods return {"ok": False, "error": "unexpected"}.
    """
    calls = []

    def _call(host, port, method, params=None):
        calls.append((method, params))
        if method in method_returns:
            return method_returns[method]
        return {"ok": False, "error": f"unexpected method {method}"}

    _call.calls = calls
    return _call


# ---------------------------------------------------------------------------
# Per-command fixtures: each builds an argparse.Namespace plus the set
# of rpc_call responses the command needs up until the destructive call
# site.  `submit_method` is the RPC method whose presence (or absence)
# in the call log we use to assert "destructive call fired" /
# "destructive call skipped".
# ---------------------------------------------------------------------------
def _args(**kw):
    ns = argparse.Namespace(
        keyfile=None,
        server="127.0.0.1:9334",
        fee=None,
        yes=False,
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _fx_stake():
    return {
        "func": cli.cmd_stake,
        "args": _args(amount=100),
        "submit_method": "stake",
        "rpc_returns": {
            "get_nonce": {
                "ok": True,
                "result": {"nonce": 0, "leaf_watermark": 0},
            },
            "stake": {
                "ok": True,
                "result": {
                    "tx_hash": "00" * 32,
                    "staked": 100,
                    "balance": 0,
                },
            },
        },
        "extra_patches": [],
    }


def _fx_unstake():
    return {
        "func": cli.cmd_unstake,
        "args": _args(amount=50),
        "submit_method": "unstake",
        "rpc_returns": {
            "get_nonce": {
                "ok": True,
                "result": {"nonce": 0, "leaf_watermark": 0},
            },
            "unstake": {
                "ok": True,
                "result": {
                    "tx_hash": "00" * 32,
                    "staked": 50,
                    "balance": 0,
                },
            },
        },
        "extra_patches": [],
    }


def _fx_set_authority_key():
    # A valid-looking 32-byte hex blob; content is not validated past
    # length by the CLI, because the server does the real binding
    # check.  This is sufficient to exercise the confirm gate.
    pubkey_hex = "aa" * 32
    return {
        "func": cli.cmd_set_authority_key,
        "args": _args(authority_pubkey=pubkey_hex),
        "submit_method": "set_authority_key",
        "rpc_returns": {
            "get_nonce": {
                "ok": True,
                "result": {"nonce": 0, "leaf_watermark": 0},
            },
            "set_authority_key": {
                "ok": True,
                "result": {
                    "entity_id": "11" * 32,
                    "authority_key": pubkey_hex,
                    "tx_hash": "00" * 32,
                },
            },
        },
        "extra_patches": [],
    }


def _fx_rotate_key():
    # Avoid the expensive tree-derivation path by swapping
    # derive_rotated_keypair for a stub that returns a MagicMock with
    # the single `.public_key` attribute the confirm prompt reads.
    new_pk = b"\x55" * 32
    mock_kp = MagicMock()
    mock_kp.public_key = new_pk

    # create_key_rotation builds a real rotation tx by default; stub
    # it to a MagicMock whose .serialize() returns a dict (what the
    # rpc_call payload needs).  The only thing the CLI does with the
    # return value is pass it into the rpc call.
    mock_tx = MagicMock()
    mock_tx.serialize.return_value = {"rotation": "stubbed"}

    return {
        "func": cli.cmd_rotate_key,
        "args": _args(),
        "submit_method": "rotate_key",
        "rpc_returns": {
            "get_key_status": {
                "ok": True,
                "result": {
                    "rotation_number": 0,
                    "leaf_watermark": 0,
                    "public_key": "00" * 32,
                },
            },
            "rotate_key": {
                "ok": True,
                "result": {
                    "entity_id": "11" * 32,
                    "new_public_key": new_pk.hex(),
                    "rotation_number": 1,
                },
            },
        },
        "extra_patches": [
            patch(
                "messagechain.core.key_rotation.derive_rotated_keypair",
                return_value=mock_kp,
            ),
            patch(
                "messagechain.core.key_rotation.create_key_rotation",
                return_value=mock_tx,
            ),
            patch("messagechain.cli._make_progress_reporter", return_value=None),
        ],
    }


def _fx_emergency_revoke():
    target_id = "bb" * 32
    return {
        "func": cli.cmd_emergency_revoke,
        "args": _args(entity_id=target_id),
        "submit_method": "emergency_revoke",
        "rpc_returns": {
            # emergency_revoke does NOT fetch a nonce first; the only
            # destructive call is the submission itself.
            "emergency_revoke": {
                "ok": True,
                "result": {
                    "entity_id": target_id,
                    "tx_hash": "00" * 32,
                },
            },
        },
        "extra_patches": [],
    }


FIXTURES = {
    "stake": _fx_stake,
    "unstake": _fx_unstake,
    "set_authority_key": _fx_set_authority_key,
    "rotate_key": _fx_rotate_key,
    "emergency_revoke": _fx_emergency_revoke,
}


class DestructiveConfirmationMixin:
    """Shared helpers for exercising the 5 commands."""

    def _run_with(self, name, input_side_effect=None, yes=False):
        """Invoke the command under test, capturing stdout and rpc log.

        `input_side_effect` may be a string (what input() returns), a
        list (returned in order), or a callable (e.g. side-effect=
        RuntimeError to assert input() is NOT invoked).
        """
        fx = FIXTURES[name]()
        args = fx["args"]
        if yes:
            args.yes = True
        rpc_stub = _stub_rpc(fx["rpc_returns"])

        patches = [
            patch("messagechain.cli._resolve_private_key",
                  return_value=_TEST_PRIVKEY),
            patch("client.rpc_call", side_effect=rpc_stub),
        ]
        patches.extend(fx["extra_patches"])

        if input_side_effect is not None:
            if callable(input_side_effect):
                input_patch = patch("builtins.input",
                                    side_effect=input_side_effect)
            elif isinstance(input_side_effect, list):
                input_patch = patch("builtins.input",
                                    side_effect=input_side_effect)
            else:
                input_patch = patch("builtins.input",
                                    return_value=input_side_effect)
        else:
            # input() should not be called; if it is, raise loudly.
            input_patch = patch(
                "builtins.input",
                side_effect=AssertionError(
                    "input() was called but should not have been"),
            )

        exit_code = None
        buf = io.StringIO()
        try:
            with input_patch:
                for p in patches:
                    p.start()
                try:
                    with redirect_stdout(buf):
                        fx["func"](args)
                finally:
                    for p in reversed(patches):
                        p.stop()
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

        return {
            "exit_code": exit_code,
            "stdout": buf.getvalue(),
            "rpc_methods": [m for (m, _p) in rpc_stub.calls],
            "submit_method": fx["submit_method"],
        }


class TestDeclineDoesNotSubmit(DestructiveConfirmationMixin,
                               unittest.TestCase):
    """Test A: decline at the prompt => no destructive submit, exit 0."""

    def _check_decline(self, name, response):
        r = self._run_with(name, input_side_effect=response)
        self.assertEqual(
            r["exit_code"], 0,
            f"{name}: declining should exit 0, got {r['exit_code']}",
        )
        self.assertNotIn(
            r["submit_method"], r["rpc_methods"],
            f"{name}: destructive rpc {r['submit_method']!r} fired "
            f"despite user declining",
        )
        self.assertIn("cancelled", r["stdout"].lower())

    def test_stake_decline_no(self):
        self._check_decline("stake", "no")

    def test_stake_decline_empty(self):
        self._check_decline("stake", "")

    def test_unstake_decline_no(self):
        self._check_decline("unstake", "no")

    def test_unstake_decline_empty(self):
        self._check_decline("unstake", "")

    def test_set_authority_key_decline_no(self):
        self._check_decline("set_authority_key", "no")

    def test_set_authority_key_decline_empty(self):
        self._check_decline("set_authority_key", "")

    def test_rotate_key_decline_no(self):
        self._check_decline("rotate_key", "no")

    def test_rotate_key_decline_empty(self):
        self._check_decline("rotate_key", "")

    def test_emergency_revoke_decline_no(self):
        self._check_decline("emergency_revoke", "no")

    def test_emergency_revoke_decline_empty(self):
        self._check_decline("emergency_revoke", "")


class TestYesSubmits(DestructiveConfirmationMixin, unittest.TestCase):
    """Test B: answering 'yes' at the prompt => destructive submit fires."""

    def _check_yes(self, name):
        r = self._run_with(name, input_side_effect="yes")
        self.assertIn(
            r["submit_method"], r["rpc_methods"],
            f"{name}: destructive rpc {r['submit_method']!r} did NOT "
            f"fire despite user typing yes",
        )

    def test_stake_yes(self):
        self._check_yes("stake")

    def test_unstake_yes(self):
        self._check_yes("unstake")

    def test_set_authority_key_yes(self):
        self._check_yes("set_authority_key")

    def test_rotate_key_yes(self):
        self._check_yes("rotate_key")

    def test_emergency_revoke_yes(self):
        self._check_yes("emergency_revoke")


class TestYesFlagSkipsPrompt(DestructiveConfirmationMixin,
                             unittest.TestCase):
    """Test C: --yes flag bypasses prompt entirely.

    Passing input_side_effect=None wires input() to raise
    AssertionError if called, so we catch any accidental prompt.
    """

    def _check_flag(self, name):
        r = self._run_with(name, input_side_effect=None, yes=True)
        self.assertIn(
            r["submit_method"], r["rpc_methods"],
            f"{name}: --yes should submit without prompting",
        )

    def test_stake_yes_flag(self):
        self._check_flag("stake")

    def test_unstake_yes_flag(self):
        self._check_flag("unstake")

    def test_set_authority_key_yes_flag(self):
        self._check_flag("set_authority_key")

    def test_rotate_key_yes_flag(self):
        self._check_flag("rotate_key")

    def test_emergency_revoke_yes_flag(self):
        self._check_flag("emergency_revoke")


class TestYesFlagParses(unittest.TestCase):
    """The argparse layer accepts --yes and -y on each command."""

    def setUp(self):
        self.parser = cli.build_parser()

    def test_stake_yes_long(self):
        args = self.parser.parse_args(
            ["stake", "--amount", "1", "--yes"])
        self.assertTrue(args.yes)

    def test_stake_yes_short(self):
        args = self.parser.parse_args(
            ["stake", "--amount", "1", "-y"])
        self.assertTrue(args.yes)

    def test_unstake_yes(self):
        args = self.parser.parse_args(
            ["unstake", "--amount", "1", "-y"])
        self.assertTrue(args.yes)

    def test_set_authority_key_yes(self):
        args = self.parser.parse_args([
            "set-authority-key",
            "--authority-pubkey", "aa" * 32,
            "-y",
        ])
        self.assertTrue(args.yes)

    def test_rotate_key_yes(self):
        args = self.parser.parse_args(["rotate-key", "-y"])
        self.assertTrue(args.yes)

    def test_emergency_revoke_yes(self):
        args = self.parser.parse_args([
            "emergency-revoke",
            "--entity-id", "bb" * 32,
            "-y",
        ])
        self.assertTrue(args.yes)


class TestTransferRegression(unittest.TestCase):
    """Test D: cmd_transfer's existing confirmation gate still works.

    The transfer command had the pattern we mirrored; make sure we
    did not break it while adding the same gate to the other five.
    """

    def _run_transfer(self, confirm_response):
        # Address for a freshly-deterministic recipient - the CLI
        # decodes it via messagechain.identity.address.decode_address,
        # which accepts either a checksummed "mc1..." form or raw hex.
        # Raw hex avoids the extra dependency on the address encoder's
        # internals in the test.
        recipient_hex = "cc" * 32

        args = argparse.Namespace(
            keyfile=None,
            to=recipient_hex,
            amount=10,
            fee=None,
            server="127.0.0.1:9334",
            # This test exercises the confirmation gate, not the
            # raw-hex safety gate; opt in so the raw-hex form reaches
            # the confirmation prompt.
            allow_raw_hex_address=True,
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
            "get_key_status": {
                "ok": True,
                "result": {"public_key": "dd" * 32, "rotation_number": 0,
                           "leaf_watermark": 0},
            },
            "submit_transfer": {
                "ok": True,
                "result": {
                    "tx_hash": "00" * 32,
                    "amount": 10,
                    "fee": 1,
                },
            },
        }
        rpc_stub = _stub_rpc(rpc_returns)

        exit_code = None
        buf = io.StringIO()
        patches = [
            patch("messagechain.cli._resolve_private_key",
                  return_value=_TEST_PRIVKEY),
            patch("client.rpc_call", side_effect=rpc_stub),
            patch("builtins.input", return_value=confirm_response),
        ]
        try:
            for p in patches:
                p.start()
            try:
                with redirect_stdout(buf):
                    cli.cmd_transfer(args)
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

    def test_transfer_decline_does_not_submit(self):
        r = self._run_transfer("no")
        self.assertEqual(r["exit_code"], 0)
        self.assertNotIn("submit_transfer", r["rpc_methods"])
        self.assertIn("cancelled", r["stdout"].lower())

    def test_transfer_yes_submits(self):
        r = self._run_transfer("yes")
        self.assertIn("submit_transfer", r["rpc_methods"])


if __name__ == "__main__":
    unittest.main()
