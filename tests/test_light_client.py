"""Light-client UX: `ping` sanity command + friendly connection errors.

A non-validator user should never have to run `start` locally.  All
CLI commands already route RPC to a seed via `_parse_server`, but two
UX gaps make the light-client path hostile for newcomers:

  1. There is no quick "am I connected?" command.  Users who typo a
     --server flag or have a dead CLIENT_SEED_ENDPOINTS config discover
     it only when `send` / `balance` produce a raw socket stack trace.
  2. When no endpoint is reachable, the CLI currently falls back to
     localhost:9333 and then emits an unhandled ConnectionRefusedError.
     That is actively confusing: it makes users think the problem is
     on their machine when it's actually that no seed is reachable.

These tests pin the fix: a `ping` command and a friendly RPC error
wrapper that explains the three recovery paths (configure seeds, pass
--server, run a local validator).
"""

import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from messagechain import cli


# ───────────────────────────────────────────────────────────────────────
# Parser wiring
# ───────────────────────────────────────────────────────────────────────

class TestPingParser(unittest.TestCase):
    """The `ping` subcommand must be registered and accept --server."""

    def setUp(self):
        self.parser = cli.build_parser()

    def test_ping_minimal(self):
        args = self.parser.parse_args(["ping"])
        self.assertEqual(args.command, "ping")

    def test_ping_with_explicit_server(self):
        args = self.parser.parse_args(["ping", "--server", "example.com:9334"])
        self.assertEqual(args.command, "ping")
        self.assertEqual(args.server, "example.com:9334")

    def test_ping_default_server_is_none(self):
        """No --server => auto-discovery path (matches every other cmd)."""
        args = self.parser.parse_args(["ping"])
        self.assertIsNone(args.server)


# ───────────────────────────────────────────────────────────────────────
# cmd_ping happy path
# ───────────────────────────────────────────────────────────────────────

class TestPingHappyPath(unittest.TestCase):
    """When the RPC target is reachable, ping prints endpoint + chain info."""

    def test_ping_prints_endpoint_and_chain_info(self):
        """Output must include the resolved host:port and key chain stats.

        The endpoint line is load-bearing: this is the ONLY way a user
        can tell whether they ended up on a seed, a non-seed validator,
        or a local node after the auto-discovery logic runs.
        """
        fake_info = {
            "height": 1234,
            "best_hash": "ab" * 32,
            "validator_count": 7,
            "total_supply": 1_000_000_000,
        }
        fake_response = {"ok": True, "result": fake_info}

        args = cli.build_parser().parse_args(["ping", "--server", "seed1.example:9334"])
        buf = io.StringIO()
        with patch.object(cli, "_parse_server", return_value=("seed1.example", 9334)), \
             patch("client.rpc_call", return_value=fake_response), \
             redirect_stdout(buf):
            cli.cmd_ping(args)

        out = buf.getvalue()
        self.assertIn("seed1.example:9334", out)  # resolved endpoint visible
        self.assertIn("1234", out)                # chain height visible
        self.assertIn("7", out)                   # validator count visible

    def test_ping_does_not_require_private_key(self):
        """ping is a purely read-only sanity check: never prompts.

        Regression guard — a previous draft accidentally wired ping
        through `_collect_private_key`, which would defeat the point
        (the whole reason ping exists is the pre-key first-run check).
        """
        fake_response = {"ok": True, "result": {
            "height": 0, "best_hash": "00" * 32,
            "validator_count": 0, "total_supply": 0,
        }}
        args = cli.build_parser().parse_args(["ping"])
        with patch.object(cli, "_parse_server", return_value=("x", 1)), \
             patch("client.rpc_call", return_value=fake_response), \
             patch.object(cli, "_collect_private_key") as mock_collect, \
             redirect_stdout(io.StringIO()):
            cli.cmd_ping(args)
        mock_collect.assert_not_called()


# ───────────────────────────────────────────────────────────────────────
# Friendly connection errors
# ───────────────────────────────────────────────────────────────────────

class TestFriendlyConnectionErrors(unittest.TestCase):
    """When the RPC endpoint is dead, error text must be actionable.

    The three recovery paths differ by how the user got here:
      - Explicit --server: they picked the address; tell them that
        address is unreachable.  Don't lecture them about
        CLIENT_SEED_ENDPOINTS — they already bypassed it.
      - Auto-discovery: mention the three options explicitly so a
        user with a default config can figure out what to do.
    """

    def _trigger_friendly_error(self, explicit_server, endpoint=("127.0.0.1", 9333)):
        """Run cmd_ping with a rigged unreachable endpoint and capture stderr."""
        argv = ["ping"]
        if explicit_server:
            argv += ["--server", f"{endpoint[0]}:{endpoint[1]}"]
        args = cli.build_parser().parse_args(argv)

        buf_out, buf_err = io.StringIO(), io.StringIO()
        with patch.object(cli, "_parse_server", return_value=endpoint), \
             patch("client.rpc_call", side_effect=ConnectionRefusedError()), \
             redirect_stdout(buf_out), redirect_stderr(buf_err), \
             self.assertRaises(SystemExit) as ctx:
            cli.cmd_ping(args)
        return ctx.exception, buf_out.getvalue() + buf_err.getvalue()

    def test_connection_refused_exits_nonzero(self):
        exc, _ = self._trigger_friendly_error(explicit_server=False)
        self.assertNotEqual(exc.code, 0)

    def test_error_with_explicit_server_names_that_address(self):
        """If the user passed --server, the error must cite their address."""
        _, output = self._trigger_friendly_error(
            explicit_server=True, endpoint=("10.0.0.99", 9334),
        )
        self.assertIn("10.0.0.99", output)
        self.assertIn("9334", output)

    def test_error_without_explicit_server_mentions_recovery_paths(self):
        """Auto-discovery failure must hint at all three fixes.

        A newcomer whose config has an empty CLIENT_SEED_ENDPOINTS (the
        shipped default) hits this path.  They need to know:
          (a) they can configure seeds,
          (b) they can pass --server, or
          (c) they can run a local node.
        """
        _, output = self._trigger_friendly_error(explicit_server=False)
        lower = output.lower()
        self.assertIn("--server", lower)
        # One of the two: mentions configuring seeds OR running a node.
        self.assertTrue(
            ("seed" in lower) or ("validator" in lower) or ("node" in lower),
            f"expected recovery-path hint in error output, got: {output!r}",
        )

    def test_timeout_produces_same_friendly_error(self):
        """socket.timeout must not leak as an unhandled exception."""
        import socket as _socket
        args = cli.build_parser().parse_args(["ping"])
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with patch.object(cli, "_parse_server", return_value=("x", 1)), \
             patch("client.rpc_call", side_effect=_socket.timeout()), \
             redirect_stdout(buf_out), redirect_stderr(buf_err), \
             self.assertRaises(SystemExit):
            cli.cmd_ping(args)
        # The test passes iff SystemExit was raised — i.e. the timeout
        # was caught and converted to a clean exit, not a stack trace.


# ───────────────────────────────────────────────────────────────────────
# Helper is reusable by other commands
# ───────────────────────────────────────────────────────────────────────

class TestFriendlyRpcHelperSharable(unittest.TestCase):
    """The friendly-RPC wrapper must be callable from any command handler.

    Exposing it as a module-level helper (not inlined in cmd_ping) is
    how we'll convert other read-only commands over time without
    duplicating the error-formatting logic.  This test exists purely to
    guard against the helper getting inlined during cleanup.
    """

    def test_helper_symbol_exists(self):
        # Accept either name; the intent is "a callable helper exists."
        candidates = ("_rpc_call_or_friendly_exit", "_friendly_rpc_call")
        found = any(hasattr(cli, name) for name in candidates)
        self.assertTrue(
            found,
            "Expected a shared friendly-RPC helper in messagechain.cli "
            "(one of: _rpc_call_or_friendly_exit, _friendly_rpc_call).",
        )


if __name__ == "__main__":
    unittest.main()
