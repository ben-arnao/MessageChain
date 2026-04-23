"""Tests for MESSAGECHAIN_RPC_AUTH_TOKEN env-var override.

Background: RPC_AUTH_TOKEN was hardcoded to None, so server auto-generated
a fresh random token on every startup — which rotates the admin token
and invalidates every external client / deployment tooling.  The new
env-var lets operators pin a stable token across restarts.

Precedence (mirrors _profile_bool / _profile_int):
  MESSAGECHAIN_RPC_AUTH_TOKEN (env)  >  profile  >  hardcoded default (None)

Behavior contract:
  unset          → RPC_AUTH_TOKEN is None → server auto-generates
  set non-empty  → RPC_AUTH_TOKEN is that string → server pins it
  set empty      → treated as unset (same as no env var)
  set < 16 chars → accepted with a warning (operator discretion)

The token value itself is NEVER logged — neither the generated one nor
the env-supplied one. Log lines only distinguish "loaded from env" from
"generated" so operators can tell which source is active.
"""

import logging
import os
import subprocess
import sys
import unittest
from unittest import mock


def _run_config_probe(env_overrides: dict, probe: str) -> str:
    """Run `probe` in a subprocess with a clean MESSAGECHAIN_* env.

    Same shape as tests/test_config_profile.py — spawns a fresh Python
    so messagechain.config picks up env vars at import time without
    fighting the tests/__init__.py harness.
    """
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("MESSAGECHAIN_")}
    env.update(env_overrides)
    env.setdefault("PYTHONPATH", os.getcwd())
    result = subprocess.run(
        [sys.executable, "-c", probe],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return f"__ERROR__\n{result.stderr.strip()}"
    return result.stdout.strip()


_PROBE_TOKEN = (
    "import messagechain.config as c; "
    "v = c.RPC_AUTH_TOKEN; "
    "print('NONE' if v is None else repr(v))"
)


class TestRpcAuthTokenEnvSet(unittest.TestCase):
    """Test A: env var set → config uses it → server_auth_token matches."""

    def test_env_var_sets_config_value(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_RPC_AUTH_TOKEN": "mysecret123456789"},
            _PROBE_TOKEN,
        )
        self.assertEqual(out, "'mysecret123456789'")

    def test_env_var_pins_server_auth_token(self):
        """End-to-end: with the env var set, the Server instance's
        rpc_auth_token attribute matches the pinned value exactly."""
        pinned = "mysecret123456789"
        with mock.patch.dict(os.environ,
                             {"MESSAGECHAIN_RPC_AUTH_TOKEN": pinned}):
            # Reload config so it re-reads the env at module scope.
            import importlib
            import messagechain.config as cfg
            importlib.reload(cfg)
            try:
                self.assertEqual(cfg.RPC_AUTH_TOKEN, pinned)

                # Also reload server so its `from config import ...` line
                # sees the new value.
                import server as server_mod
                importlib.reload(server_mod)
                srv = server_mod.Server(
                    p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None,
                )
                self.assertEqual(srv.rpc_auth_token, pinned)
                self.assertEqual(
                    getattr(srv, "_rpc_auth_token_source", None), "env",
                )
            finally:
                # Restore module state for subsequent tests.
                import importlib as _il
                _il.reload(cfg)
                import server as _sm
                _il.reload(_sm)


class TestRpcAuthTokenEnvUnset(unittest.TestCase):
    """Test B: env var unset → RPC_AUTH_TOKEN is None → server auto-generates."""

    def test_unset_yields_none(self):
        # Explicitly clear the env var in the subprocess.
        out = _run_config_probe({}, _PROBE_TOKEN)
        self.assertEqual(out, "NONE")

    def test_unset_server_generates_random_token(self):
        """When config.RPC_AUTH_TOKEN is None, Server sets a 64-char hex
        token (32 random bytes hex-encoded) — the pre-existing behavior."""
        import importlib
        import messagechain.config as cfg
        # Ensure env var is cleared in this process too.
        os.environ.pop("MESSAGECHAIN_RPC_AUTH_TOKEN", None)
        importlib.reload(cfg)
        try:
            self.assertIsNone(cfg.RPC_AUTH_TOKEN)
            import server as server_mod
            importlib.reload(server_mod)
            srv = server_mod.Server(
                p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None,
            )
            self.assertIsInstance(srv.rpc_auth_token, str)
            self.assertEqual(len(srv.rpc_auth_token), 64)  # 32 bytes hex
            # Hex-only characters
            int(srv.rpc_auth_token, 16)  # raises if not hex
            self.assertEqual(
                getattr(srv, "_rpc_auth_token_source", None), "generated",
            )
        finally:
            import importlib as _il
            _il.reload(cfg)
            import server as _sm
            _il.reload(_sm)


class TestRpcAuthTokenEmptyStringTreatedAsUnset(unittest.TestCase):
    """Test C: env var set to "" → treated as unset → falls back to default."""

    def test_empty_string_falls_back_to_none(self):
        out = _run_config_probe(
            {"MESSAGECHAIN_RPC_AUTH_TOKEN": ""},
            _PROBE_TOKEN,
        )
        self.assertEqual(out, "NONE")


class TestRpcAuthTokenShortWarns(unittest.TestCase):
    """Test D: env var shorter than 16 chars → warning logged, accepted."""

    def test_short_token_logs_warning_but_accepted(self):
        short = "shortkey"  # 8 chars
        self.assertLess(len(short), 16)
        import importlib
        import messagechain.config as cfg
        with mock.patch.dict(os.environ,
                             {"MESSAGECHAIN_RPC_AUTH_TOKEN": short}):
            importlib.reload(cfg)
            try:
                self.assertEqual(cfg.RPC_AUTH_TOKEN, short)
                import server as server_mod
                importlib.reload(server_mod)
                with self.assertLogs(server_mod.logger, level="WARNING") as cm:
                    srv = server_mod.Server(
                        p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None,
                    )
                # Token is still set to the short value (accepted).
                self.assertEqual(srv.rpc_auth_token, short)
                # Warning was emitted.
                warning_msgs = [r.getMessage() for r in cm.records
                                if r.levelno >= logging.WARNING]
                self.assertTrue(
                    any("shorter than 16" in m for m in warning_msgs),
                    f"expected short-token warning, got: {warning_msgs}",
                )
                # Critical: the token VALUE must never appear in any log.
                for msg in warning_msgs:
                    self.assertNotIn(short, msg)
            finally:
                import importlib as _il
                _il.reload(cfg)
                import server as _sm
                _il.reload(_sm)


if __name__ == "__main__":
    unittest.main()
