"""
Tests for the Tor hidden-service config helper.

MessageChain does NOT speak Tor itself — the external `tor` daemon
handles the protocol. Our helper only generates the torrc snippet that
points a hidden service at the validator's local RPC socket, and warns
if the operator has misconfigured RPC to bind on a public interface
(hidden services should tunnel to 127.0.0.1 only).
"""

import unittest

from messagechain.network.tor_config import (
    generate_torrc_snippet,
    InvalidTorBindError,
)


class TestGenerateTorrcSnippet(unittest.TestCase):
    """The snippet should be valid torrc that maps an onion port to local RPC."""

    def test_contains_hidden_service_dir(self):
        snippet = generate_torrc_snippet(
            rpc_bind_addr="127.0.0.1",
            rpc_port=9334,
            hidden_service_dir="/var/lib/tor/messagechain",
        )
        self.assertIn("HiddenServiceDir", snippet)
        self.assertIn("/var/lib/tor/messagechain", snippet)

    def test_contains_hidden_service_port_directive(self):
        snippet = generate_torrc_snippet(
            rpc_bind_addr="127.0.0.1",
            rpc_port=9334,
            hidden_service_dir="/var/lib/tor/messagechain",
        )
        self.assertIn("HiddenServicePort", snippet)

    def test_maps_to_localhost_rpc(self):
        """Snippet must forward the onion port to the local RPC port."""
        snippet = generate_torrc_snippet(
            rpc_bind_addr="127.0.0.1",
            rpc_port=9334,
            hidden_service_dir="/var/lib/tor/messagechain",
        )
        # HiddenServicePort <external> <internal-host>:<internal-port>
        self.assertIn("127.0.0.1:9334", snippet)

    def test_uses_127_0_0_1_not_0_0_0_0(self):
        """Even if caller passed a wider bind, snippet routes to loopback."""
        # The helper must refuse rather than silently rewrite — catching
        # the misconfig is the whole point.
        with self.assertRaises(InvalidTorBindError):
            generate_torrc_snippet(
                rpc_bind_addr="0.0.0.0",
                rpc_port=9334,
                hidden_service_dir="/var/lib/tor/messagechain",
            )

    def test_rejects_public_ipv4(self):
        """A validator that bound RPC to a public IP is misconfigured."""
        with self.assertRaises(InvalidTorBindError):
            generate_torrc_snippet(
                rpc_bind_addr="203.0.113.7",
                rpc_port=9334,
                hidden_service_dir="/var/lib/tor/messagechain",
            )

    def test_accepts_loopback_variants(self):
        # Any obvious loopback form should work.
        for addr in ("127.0.0.1", "localhost", "::1"):
            snippet = generate_torrc_snippet(
                rpc_bind_addr=addr,
                rpc_port=9334,
                hidden_service_dir="/etc/tor/mc",
            )
            self.assertIn("HiddenServiceDir", snippet)

    def test_snippet_is_well_formed(self):
        """Two directives, no blank-line mid-block, no shell-injection junk."""
        snippet = generate_torrc_snippet(
            rpc_bind_addr="127.0.0.1",
            rpc_port=9334,
            hidden_service_dir="/var/lib/tor/messagechain",
        )
        lines = [ln for ln in snippet.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        directives = [ln.split()[0] for ln in lines]
        self.assertIn("HiddenServiceDir", directives)
        self.assertIn("HiddenServicePort", directives)

    def test_custom_external_port(self):
        """Operator can expose onion on a different external port (e.g. 80)."""
        snippet = generate_torrc_snippet(
            rpc_bind_addr="127.0.0.1",
            rpc_port=9334,
            hidden_service_dir="/var/lib/tor/messagechain",
            external_port=80,
        )
        # external_port first, then internal mapping
        self.assertIn("HiddenServicePort 80 127.0.0.1:9334", snippet)

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            generate_torrc_snippet(
                rpc_bind_addr="127.0.0.1",
                rpc_port=0,
                hidden_service_dir="/var/lib/tor/messagechain",
            )
        with self.assertRaises(ValueError):
            generate_torrc_snippet(
                rpc_bind_addr="127.0.0.1",
                rpc_port=70000,
                hidden_service_dir="/var/lib/tor/messagechain",
            )

    def test_rejects_empty_hidden_service_dir(self):
        with self.assertRaises(ValueError):
            generate_torrc_snippet(
                rpc_bind_addr="127.0.0.1",
                rpc_port=9334,
                hidden_service_dir="",
            )

    def test_rejects_hidden_service_dir_with_newline(self):
        """Prevent injection of extra torrc directives via the dir path."""
        with self.assertRaises(ValueError):
            generate_torrc_snippet(
                rpc_bind_addr="127.0.0.1",
                rpc_port=9334,
                hidden_service_dir="/var/lib/tor/mc\nHiddenServicePort 666 evil:6666",
            )


class TestGenTorConfigCLI(unittest.TestCase):
    """The `messagechain gen-tor-config` subcommand is plumbed through CLI."""

    def test_parser_accepts_subcommand(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "gen-tor-config",
            "--rpc-bind", "127.0.0.1",
            "--rpc-port", "9334",
            "--hidden-service-dir", "/var/lib/tor/mc",
        ])
        self.assertEqual(args.command, "gen-tor-config")
        self.assertEqual(args.rpc_bind, "127.0.0.1")
        self.assertEqual(args.rpc_port, 9334)
        self.assertEqual(args.hidden_service_dir, "/var/lib/tor/mc")

    def test_cli_prints_snippet_on_stdout(self):
        """Running the command should put the snippet on stdout."""
        import io
        import sys
        from unittest.mock import patch
        from messagechain.cli import cmd_gen_tor_config

        args = type("Args", (), {
            "rpc_bind": "127.0.0.1",
            "rpc_port": 9334,
            "hidden_service_dir": "/var/lib/tor/mc",
            "external_port": None,
        })()
        captured = io.StringIO()
        with patch.object(sys, "stdout", captured), \
             patch.object(sys, "stderr", io.StringIO()):
            cmd_gen_tor_config(args)
        output = captured.getvalue()
        self.assertIn("HiddenServiceDir", output)
        self.assertIn("HiddenServicePort", output)
        self.assertIn("127.0.0.1:9334", output)

    def test_cli_rejects_public_bind(self):
        """If RPC is bound to 0.0.0.0, CLI exits with error code."""
        import io
        import sys
        from unittest.mock import patch
        from messagechain.cli import cmd_gen_tor_config

        args = type("Args", (), {
            "rpc_bind": "0.0.0.0",
            "rpc_port": 9334,
            "hidden_service_dir": "/var/lib/tor/mc",
            "external_port": None,
        })()
        err = io.StringIO()
        with patch.object(sys, "stdout", io.StringIO()), \
             patch.object(sys, "stderr", err), \
             self.assertRaises(SystemExit) as cm:
            cmd_gen_tor_config(args)
        self.assertNotEqual(cm.exception.code, 0)
        self.assertIn("Refusing", err.getvalue())


if __name__ == "__main__":
    unittest.main()
