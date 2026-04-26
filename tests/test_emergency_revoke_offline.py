"""Tests for the offline pre-sign / pre-broadcast revoke workflow.

`emergency-revoke --print-only` is the air-gapped branch of the kill-
switch CLI: the operator builds and signs a revoke on a cold machine,
prints the bytes, and stores them offline.  `broadcast-revoke` is the
companion on the network-attached side: it parses the saved hex and
fires the existing emergency_revoke RPC.

Together they let an operator pre-sign a revoke once, while the cold
key is conveniently available, and broadcast it later under duress
without ever bringing the cold key online again.

These tests pin three properties:

1. --print-only does NOT touch the network at all (no rpc_call).
2. The printed hex round-trips back into a valid RevokeTransaction
   that the chain's verify path accepts under the cold pubkey.
3. broadcast-revoke parses the saved hex and submits via the
   emergency_revoke RPC method, with the same tx the print-only run
   produced (no re-signing, no re-hashing).
"""

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from messagechain import cli
from messagechain.core.emergency_revoke import (
    RevokeTransaction,
    verify_revoke_transaction,
)
from messagechain.identity.identity import Entity


# Same convention as test_cli_destructive_confirmations.py: a
# deterministic 32-byte private key.  Exact bytes are arbitrary, only
# matters that Entity.create accepts them.
_TEST_PRIVKEY = bytes(range(32))


def _args(**kw):
    ns = argparse.Namespace(
        keyfile=None,
        server="127.0.0.1:9334",
        fee=None,
        yes=False,
        print_only=False,
        tx_hex=None,
        tx_file=None,
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _run_cmd(func, args, input_responses=None):
    """Run a CLI command function with stdout captured.

    Returns (exit_code, stdout, rpc_calls_log).
    """
    rpc_calls = []

    def _rpc(host, port, method, params=None):
        rpc_calls.append((method, params))
        if method == "emergency_revoke":
            return {
                "ok": True,
                "result": {
                    "entity_id": params["transaction"]["entity_id"],
                    "tx_hash": params["transaction"]["tx_hash"],
                },
            }
        return {"ok": False, "error": f"unexpected method {method}"}

    if input_responses is None:
        input_patch = patch(
            "builtins.input",
            side_effect=AssertionError(
                "input() should not be called in this test"),
        )
    else:
        input_patch = patch(
            "builtins.input",
            side_effect=(
                input_responses
                if isinstance(input_responses, list)
                else [input_responses]
            ),
        )

    exit_code = None
    buf = io.StringIO()
    try:
        with input_patch, \
             patch("messagechain.cli._resolve_private_key",
                   return_value=_TEST_PRIVKEY), \
             patch("client.rpc_call", side_effect=_rpc), \
             redirect_stdout(buf):
            func(args)
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0

    return exit_code, buf.getvalue(), rpc_calls


# ---------------------------------------------------------------------------
# --print-only: no RPC, prints round-trippable hex.
# ---------------------------------------------------------------------------
class TestPrintOnlyBranch(unittest.TestCase):

    def test_print_only_makes_no_rpc_calls(self):
        """The whole point of the offline workflow is that the cold
        machine never touches a network.  Assert no rpc_call invocation
        slips through (a regression here would reach for /etc/resolv.conf
        or worse on a truly air-gapped box)."""
        args = _args(entity_id="bb" * 32, print_only=True)
        exit_code, stdout, rpc_calls = _run_cmd(
            cli.cmd_emergency_revoke, args,
        )
        self.assertIn(exit_code, (None, 0))
        self.assertEqual(
            rpc_calls, [],
            "rpc_call invoked during --print-only run; this defeats "
            "the air-gapped pre-sign workflow",
        )
        self.assertIn("DO NOT BROADCAST YET", stdout)
        self.assertIn("bb" * 32, stdout)

    def test_print_only_output_round_trips_to_valid_tx(self):
        """Extract the hex from stdout, parse it back, verify the
        signature against the cold pubkey.  This is the one property
        that actually matters for the offline workflow: the saved
        bytes will fire when broadcast."""
        target_id = "cc" * 32
        args = _args(entity_id=target_id, print_only=True)
        _, stdout, _ = _run_cmd(cli.cmd_emergency_revoke, args)

        # The hex blob is the sole all-hex line in stdout.  Pull it
        # by length: the only line longer than 100 hex chars is the
        # serialized tx (the entity_id is 64).
        hex_blob = None
        for line in stdout.splitlines():
            stripped = line.strip()
            if (
                len(stripped) > 100
                and all(c in "0123456789abcdef" for c in stripped)
            ):
                hex_blob = stripped
                break
        self.assertIsNotNone(
            hex_blob, f"no hex blob found in stdout:\n{stdout}",
        )

        tx_bytes = bytes.fromhex(hex_blob)
        tx = RevokeTransaction.from_bytes(tx_bytes)

        # Target binding is intact.
        self.assertEqual(tx.entity_id.hex(), target_id)

        # Signature verifies against the cold key's pubkey.
        cold = Entity.create(_TEST_PRIVKEY)
        self.assertTrue(
            verify_revoke_transaction(tx, cold.public_key),
            "saved revoke fails verify under cold pubkey -- the "
            "round-trip lost or corrupted the signature",
        )

    def test_print_only_pads_fee_above_current_floor(self):
        """A pre-signed revoke that pays exactly today's fee floor is
        invalid the moment governance bumps that floor.  --print-only
        defaults to 10x the current floor so a single fork worth of
        fee inflation does not invalidate the saved bytes."""
        from messagechain.config import MIN_FEE_POST_FLAT
        args = _args(entity_id="dd" * 32, print_only=True)
        _, stdout, _ = _run_cmd(cli.cmd_emergency_revoke, args)
        hex_blob = next(
            line.strip() for line in stdout.splitlines()
            if len(line.strip()) > 100
            and all(c in "0123456789abcdef" for c in line.strip())
        )
        tx = RevokeTransaction.from_bytes(bytes.fromhex(hex_blob))
        self.assertEqual(tx.fee, MIN_FEE_POST_FLAT * 10)

    def test_print_only_explicit_fee_overrides_pad(self):
        """If the operator wants to pay a specific fee (e.g. they have
        their own model of future inflation), --fee on the CLI wins."""
        args = _args(entity_id="ee" * 32, print_only=True, fee=50_000)
        _, stdout, _ = _run_cmd(cli.cmd_emergency_revoke, args)
        hex_blob = next(
            line.strip() for line in stdout.splitlines()
            if len(line.strip()) > 100
            and all(c in "0123456789abcdef" for c in line.strip())
        )
        tx = RevokeTransaction.from_bytes(bytes.fromhex(hex_blob))
        self.assertEqual(tx.fee, 50_000)


# ---------------------------------------------------------------------------
# broadcast-revoke: parses saved hex, submits via existing RPC.
# ---------------------------------------------------------------------------
class TestBroadcastRevoke(unittest.TestCase):

    def _make_pre_signed_hex(self, target_id_hex: str) -> str:
        args = _args(entity_id=target_id_hex, print_only=True)
        _, stdout, _ = _run_cmd(cli.cmd_emergency_revoke, args)
        for line in stdout.splitlines():
            s = line.strip()
            if (
                len(s) > 100
                and all(c in "0123456789abcdef" for c in s)
            ):
                return s
        raise AssertionError(f"no hex blob in stdout:\n{stdout}")

    def test_broadcast_submits_emergency_revoke_rpc(self):
        target_id = "f1" * 32
        hex_blob = self._make_pre_signed_hex(target_id)

        args = _args(tx_hex=hex_blob, yes=True)
        exit_code, _stdout, rpc_calls = _run_cmd(
            cli.cmd_broadcast_revoke, args,
        )
        self.assertIn(exit_code, (None, 0))
        methods = [m for (m, _p) in rpc_calls]
        self.assertEqual(methods, ["emergency_revoke"])
        # Submitted tx targets the same entity the saved hex did.
        params = rpc_calls[0][1]
        self.assertEqual(params["transaction"]["entity_id"], target_id)

    def test_broadcast_from_file(self):
        """--file should accept a path containing the same hex with
        any whitespace (newlines from a paper printout, e.g.).
        """
        import os
        import tempfile

        target_id = "f2" * 32
        hex_blob = self._make_pre_signed_hex(target_id)
        # Inject newlines and spaces to simulate paper-typed input.
        chunked = "\n".join(
            hex_blob[i:i + 40] for i in range(0, len(hex_blob), 40)
        )

        with tempfile.NamedTemporaryFile(
            "w", suffix=".hex", delete=False, encoding="utf-8",
        ) as f:
            f.write(chunked + "\n")
            path = f.name
        try:
            args = _args(tx_file=path, yes=True)
            _, _stdout, rpc_calls = _run_cmd(
                cli.cmd_broadcast_revoke, args,
            )
            self.assertEqual(
                [m for (m, _p) in rpc_calls], ["emergency_revoke"],
            )
            params = rpc_calls[0][1]
            self.assertEqual(
                params["transaction"]["entity_id"], target_id,
            )
        finally:
            os.unlink(path)

    def test_broadcast_rejects_non_hex(self):
        args = _args(tx_hex="not-hex", yes=True)
        exit_code, stdout, rpc_calls = _run_cmd(
            cli.cmd_broadcast_revoke, args,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(rpc_calls, [],
                         "rejected input must not reach the network")
        self.assertIn("not valid hex", stdout)

    def test_broadcast_rejects_truncated_tx(self):
        target_id = "f3" * 32
        hex_blob = self._make_pre_signed_hex(target_id)
        truncated = hex_blob[:-40]  # lop off the last 20 bytes

        args = _args(tx_hex=truncated, yes=True)
        exit_code, stdout, rpc_calls = _run_cmd(
            cli.cmd_broadcast_revoke, args,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(rpc_calls, [])
        self.assertIn("RevokeTransaction", stdout)

    def test_broadcast_decline_does_not_submit(self):
        """Without --yes, the operator must type 'yes' at the prompt.
        Anything else cancels the broadcast and exits cleanly."""
        target_id = "f4" * 32
        hex_blob = self._make_pre_signed_hex(target_id)

        args = _args(tx_hex=hex_blob, yes=False)
        exit_code, stdout, rpc_calls = _run_cmd(
            cli.cmd_broadcast_revoke, args, input_responses=["no"],
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(rpc_calls, [])
        self.assertIn("cancelled", stdout.lower())


# ---------------------------------------------------------------------------
# Argparse layer: the new flags / subcommand actually parse.
# ---------------------------------------------------------------------------
class TestArgparseWiring(unittest.TestCase):

    def setUp(self):
        self.parser = cli.build_parser()

    def test_emergency_revoke_print_only_parses(self):
        args = self.parser.parse_args([
            "emergency-revoke",
            "--entity-id", "ab" * 32,
            "--print-only",
        ])
        self.assertTrue(args.print_only)

    def test_emergency_revoke_print_only_default_false(self):
        args = self.parser.parse_args([
            "emergency-revoke",
            "--entity-id", "ab" * 32,
        ])
        self.assertFalse(args.print_only)

    def test_broadcast_revoke_hex_parses(self):
        args = self.parser.parse_args([
            "broadcast-revoke", "--hex", "deadbeef",
        ])
        self.assertEqual(args.tx_hex, "deadbeef")
        self.assertIsNone(args.tx_file)

    def test_broadcast_revoke_file_parses(self):
        args = self.parser.parse_args([
            "broadcast-revoke", "--file", "/tmp/revoke.hex",
        ])
        self.assertEqual(args.tx_file, "/tmp/revoke.hex")
        self.assertIsNone(args.tx_hex)

    def test_broadcast_revoke_requires_source(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["broadcast-revoke"])

    def test_broadcast_revoke_hex_and_file_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args([
                "broadcast-revoke",
                "--hex", "dead",
                "--file", "/tmp/x.hex",
            ])


if __name__ == "__main__":
    unittest.main()
