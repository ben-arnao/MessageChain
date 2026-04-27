"""Tests for `messagechain receipt <tx_hash>` and `submit-evidence` CLI commands.

The receipt command is the user-visible surface that names the
slashing-backed permanence guarantee.  After `messagechain send`, a
user gets a tx hash and ten minutes of nothing — there is no way to
distinguish "block hasn't mined yet" from "validators colluding".

`messagechain receipt <tx_hash>` closes that gap: it queries the node,
classifies the tx as INCLUDED / PENDING / NOT_FOUND, and prints a
plain-language receipt that names the protocol's defining property
("permanent", "can never be deleted", "slashable evidence").

These tests pin the user-facing copy AND the RPC plumbing.  The literal
phrase tests are deliberate — the receipt is a value-prop fix, so the
words matter.
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


def _receipt_args(tx_hash: str, **overrides) -> argparse.Namespace:
    base = dict(
        tx_hash=tx_hash,
        server="127.0.0.1:9334",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _evidence_args(tx_hash: str, **overrides) -> argparse.Namespace:
    base = dict(
        tx_hash=tx_hash,
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# Helper: a 64-char hex string we can use as a fake tx_hash.
_FAKE_TX_HASH = "ab" * 32


class TestReceiptIncludedPath(unittest.TestCase):
    """A tx that has been included on-chain prints the permanence guarantee."""

    def test_included_tx_prints_block_height_attesters_and_permanence(self):
        from messagechain import cli as cli_mod

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {
                    "height": 14600, "latest_block_hash": "ee" * 32,
                }}
            if method == "get_tx_status":
                self.assertEqual(params["tx_hash"], _FAKE_TX_HASH)
                return {"ok": True, "result": {
                    "status": "included",
                    "block_height": 14523,
                    "block_hash": "cd" * 32,
                    "tx_index": 3,
                    "merkle_root": "ff" * 32,
                    "attesters": 12,
                    "total_validators": 14,
                    "attesting_stake": 800_000,
                    "total_stake": 1_000_000,
                    "finality_threshold_met": True,
                    "finality_numerator": 2,
                    "finality_denominator": 3,
                    "merkle_proof": {
                        "tx_hash": _FAKE_TX_HASH,
                        "tx_index": 3,
                        "siblings": ["aa" * 32, "bb" * 32],
                        "directions": [False, True],
                    },
                    "submission_validators": ["v1abc", "v2def", "v3ghi"],
                    "seconds_since_submission": 552,  # 9m12s
                }}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(_FAKE_TX_HASH))

        out = buf.getvalue()
        # The defining-property language is required.
        self.assertTrue(
            "permanent" in out.lower() or "can never be deleted" in out.lower(),
            f"receipt must name the permanence guarantee; got:\n{out}",
        )
        self.assertIn("slashable", out.lower(),
            "receipt must reference slashable evidence backing the guarantee")
        # Block placement is named.
        self.assertIn("14523", out, "block height must appear")
        # Attester counts are surfaced.
        self.assertIn("12", out)
        self.assertIn("14", out)
        # Inclusion proof is surfaced (hex form).
        self.assertIn("ff" * 16, out, "merkle root prefix should appear")
        # Successful exit.
        self.assertEqual(rc, 0)


class TestReceiptPendingPath(unittest.TestCase):
    """A tx still in mempool prints the wait estimate AND the escalation hint."""

    def test_pending_tx_names_wait_and_submit_evidence_escalation(self):
        from messagechain import cli as cli_mod

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {
                    "height": 432, "latest_block_hash": "ee" * 32,
                    "seconds_since_last_block": 120,
                }}
            if method == "get_tx_status":
                return {"ok": True, "result": {
                    "status": "pending",
                    "in_mempool": True,
                    "submitted_at_height": 430,
                    "blocks_waited": 2,
                    "expected_next_block_seconds": 480,
                }}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(_FAKE_TX_HASH))

        out = buf.getvalue()
        self.assertIn("PENDING", out.upper())
        # Names the wait surface.
        self.assertTrue(
            "minute" in out.lower() or "second" in out.lower()
            or "block" in out.lower(),
            "pending receipt must name the wait estimate",
        )
        # Names the escalation path.
        self.assertIn("submit-evidence", out,
            "pending receipt must name the submit-evidence escalation")
        # Still mentions the guarantee — the user shouldn't lose context.
        self.assertTrue(
            "permanent" in out.lower() or "can never be deleted" in out.lower()
            or "slashable" in out.lower(),
            "pending receipt must still name the inclusion guarantee",
        )
        self.assertEqual(rc, 0)


class TestReceiptNotFoundPath(unittest.TestCase):
    """A tx neither in mempool nor in a block prints the diagnostic."""

    def test_not_found_tx_lists_three_possible_causes(self):
        from messagechain import cli as cli_mod

        def rpc_side(host, port, method, params):
            if method == "get_chain_info":
                return {"ok": True, "result": {
                    "height": 432, "latest_block_hash": "ee" * 32,
                }}
            if method == "get_tx_status":
                return {"ok": True, "result": {"status": "not_found"}}
            return {"ok": False, "error": f"unexpected method {method}"}

        with patch("client.rpc_call", side_effect=rpc_side), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_mod.cmd_receipt(_receipt_args(_FAKE_TX_HASH))

        out = buf.getvalue()
        self.assertIn("NOT FOUND", out.upper())
        # Must explain the three failure modes.
        self.assertIn("never submitted", out.lower())
        self.assertIn("collusion", out.lower())
        self.assertIn("malformed", out.lower())
        self.assertIn("submit-evidence", out)
        self.assertEqual(rc, 0)


class TestReceiptInputValidation(unittest.TestCase):
    """Bad tx hashes should be caught client-side without an RPC roundtrip."""

    def test_invalid_hex_rejected_with_clean_diagnostic(self):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_receipt(_receipt_args("not-hex"))

        self.assertNotEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertNotIn("Traceback", out)
        self.assertTrue(
            "hex" in out.lower() or "tx hash" in out.lower(),
            f"must explain the input was malformed; got: {out}",
        )

    def test_wrong_length_rejected(self):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                cli_mod.cmd_receipt(_receipt_args("ab" * 16))  # 32 hex chars not 64

        self.assertNotIn("Traceback", buf.getvalue())


class TestSubmitEvidenceStub(unittest.TestCase):
    """`submit-evidence` lands in CLI surface even as a stub.

    The full evidence-tx-construction pipeline is large enough that the
    receipt half ships first (per audit guidance).  But the stub MUST
    exist in the CLI so users who follow the receipt's escalation hint
    don't hit "Unknown command".
    """

    def test_submit_evidence_command_exists(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        # Should parse without SystemExit.
        ns = parser.parse_args(["submit-evidence", "--tx", _FAKE_TX_HASH])
        self.assertEqual(ns.command, "submit-evidence")
        self.assertEqual(ns.tx_hash, _FAKE_TX_HASH)

    def test_submit_evidence_stub_prints_actionable_message(self):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.cmd_submit_evidence(_evidence_args(_FAKE_TX_HASH))
        out = buf.getvalue()
        # The stub at least names the user action and the slashing target.
        self.assertIn(_FAKE_TX_HASH[:16], out,
            "stub must echo the tx hash so the user sees their input was parsed")
        self.assertTrue(
            "evidence" in out.lower(),
            "stub must name what it would do",
        )


class TestReceiptParser(unittest.TestCase):
    """The receipt subcommand is registered in build_parser."""

    def test_receipt_subcommand_registered(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        ns = parser.parse_args(["receipt", _FAKE_TX_HASH])
        self.assertEqual(ns.command, "receipt")
        self.assertEqual(ns.tx_hash, _FAKE_TX_HASH)

    def test_receipt_accepts_server_override(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        ns = parser.parse_args([
            "receipt", _FAKE_TX_HASH, "--server", "10.0.0.1:9334",
        ])
        self.assertEqual(ns.server, "10.0.0.1:9334")


if __name__ == "__main__":
    unittest.main()
