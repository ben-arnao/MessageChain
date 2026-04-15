"""Tests for the unified CLI entry point."""

import unittest
from unittest.mock import patch, MagicMock
import argparse

from messagechain.cli import build_parser, resolve_defaults


class TestCLIParser(unittest.TestCase):
    """Test that the CLI parser accepts the expected simple commands."""

    def setUp(self):
        self.parser = build_parser()

    def test_start_minimal(self):
        """'start' with no args should work — relay-only node."""
        args = self.parser.parse_args(["start"])
        self.assertEqual(args.command, "start")
        self.assertFalse(args.mine)

    def test_start_mine(self):
        """'start --mine' enables block production."""
        args = self.parser.parse_args(["start", "--mine"])
        self.assertTrue(args.mine)

    def test_start_custom_port(self):
        """Power users can override port."""
        args = self.parser.parse_args(["start", "--port", "9999"])
        self.assertEqual(args.port, 9999)

    def test_start_with_seed(self):
        """Can specify seed nodes."""
        args = self.parser.parse_args(["start", "--seed", "10.0.0.1:9333"])
        self.assertEqual(args.seed, ["10.0.0.1:9333"])

    def test_start_with_data_dir(self):
        """Can specify data directory."""
        args = self.parser.parse_args(["start", "--data-dir", "./mydata"])
        self.assertEqual(args.data_dir, "./mydata")

    def test_account_create(self):
        """'account' command for creating an account."""
        args = self.parser.parse_args(["account"])
        self.assertEqual(args.command, "account")

    def test_account_with_server(self):
        """Can specify server address."""
        args = self.parser.parse_args(["account", "--server", "10.0.0.1:9334"])
        self.assertEqual(args.server, "10.0.0.1:9334")

    def test_send_with_message(self):
        """'send' with positional message."""
        args = self.parser.parse_args(["send", "Hello world!"])
        self.assertEqual(args.command, "send")
        self.assertEqual(args.message, "Hello world!")

    def test_send_with_fee(self):
        """Power users can set fee explicitly."""
        args = self.parser.parse_args(["send", "Hello", "--fee", "50"])
        self.assertEqual(args.fee, 50)

    def test_send_with_server(self):
        """Can specify server address for send."""
        args = self.parser.parse_args(["send", "Hi", "--server", "10.0.0.1:9334"])
        self.assertEqual(args.server, "10.0.0.1:9334")

    def test_info_command(self):
        """'info' shows chain info."""
        args = self.parser.parse_args(["info"])
        self.assertEqual(args.command, "info")

    def test_proposals_command(self):
        """'proposals' lists open governance proposals."""
        args = self.parser.parse_args(["proposals"])
        self.assertEqual(args.command, "proposals")

    def test_validators_command(self):
        """'validators' lists the current validator set."""
        args = self.parser.parse_args(["validators"])
        self.assertEqual(args.command, "validators")

    def test_estimate_fee_message(self):
        """'estimate-fee --message' prices a prospective message."""
        args = self.parser.parse_args(["estimate-fee", "--message", "hi"])
        self.assertEqual(args.command, "estimate-fee")
        self.assertEqual(args.message, "hi")

    def test_estimate_fee_transfer(self):
        """'estimate-fee --transfer' prices a funds transfer."""
        args = self.parser.parse_args(["estimate-fee", "--transfer"])
        self.assertTrue(args.transfer)

    def test_estimate_fee_requires_mode(self):
        """'estimate-fee' with no --message or --transfer fails."""
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["estimate-fee"])


class TestResolveDefaults(unittest.TestCase):
    """Test that resolve_defaults fills in sensible values."""

    def test_start_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["start"])
        resolved = resolve_defaults(args)
        self.assertEqual(resolved.port, 9333)
        self.assertEqual(resolved.rpc_port, 9334)
        self.assertIsNotNone(resolved.data_dir)

    def test_send_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["send", "Hello"])
        resolved = resolve_defaults(args)
        # Server defaults to localhost
        self.assertEqual(resolved.server, "127.0.0.1:9334")

    def test_account_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["account"])
        resolved = resolve_defaults(args)
        self.assertEqual(resolved.server, "127.0.0.1:9334")

    def test_start_data_dir_auto(self):
        """If no --data-dir, should auto-create a default path."""
        parser = build_parser()
        args = parser.parse_args(["start"])
        resolved = resolve_defaults(args)
        self.assertIn("chaindata", resolved.data_dir)


if __name__ == "__main__":
    unittest.main()
