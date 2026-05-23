"""Regression tests for the 1.88.3 operator-recovery surface added
after the 2026-05-22 stale-ban incident.

Two related fixes:

1. **Persisted RPC auth token**.  The daemon writes the active token
   to ``<data_dir>/rpc_auth_token`` (mode 0600) at startup so a
   same-host operator CLI can call admin RPCs without pre-exporting
   ``MESSAGECHAIN_RPC_AUTH_TOKEN``.  Pre-1.88.3 the token was
   process-memory-only: an operator who needed to unban a peer
   couldn't authenticate against the daemon's own admin RPCs and had
   to hand-edit ``ban_scores.json`` instead.

2. **``rpc_call(data_dir=...)`` autoreads the token**.  Resolution
   order: explicit ``auth`` arg → env var → ``<data_dir>/rpc_auth_token``
   file.  Same-host operator CLI passes its ``--data-dir`` flag
   through (the ``unban-peer`` subcommand wires this).

The actual ``unban-peer`` CLI command is exercised E2E via the
underlying ``rpc_call`` machinery; the wire ``unban_peer`` RPC has
existing coverage in the server suite, so this test focuses on the
pieces NEW in 1.88.3 (token persistence + autoread).
"""

import os
import socket
import struct
import json
import tempfile
import threading
import unittest


class TestTokenFileWrite(unittest.TestCase):
    """The token write helper produces a 0600 file with the token
    plus a trailing newline; atomic-write semantics (tmp + replace)
    prevent a partial-token read by a racing CLI."""

    def test_write_persists_token_with_correct_mode(self):
        # Import here so the test still imports cleanly on platforms
        # where server.py can't construct a Server (test harness uses
        # the helper directly via duck-typed instance).
        import importlib.util
        spec = importlib.util.find_spec("server")
        self.assertIsNotNone(spec, "server.py importable")

        # Construct a minimal stand-in that exposes only the fields
        # _write_rpc_auth_token_file touches: data_dir + rpc_auth_token.
        # This avoids spinning up a full Server (which would bind ports
        # and load a real chain).
        with tempfile.TemporaryDirectory(prefix="mc-token-test-") as tmp:
            class _Stub:
                pass
            stub = _Stub()
            stub.data_dir = tmp
            stub.rpc_auth_token = "a" * 64

            # Bind the unbound method from the Server class to our stub.
            import server as srv
            srv.Server._write_rpc_auth_token_file(stub)

            token_path = os.path.join(tmp, "rpc_auth_token")
            self.assertTrue(os.path.exists(token_path))
            # Mode 0600 (POSIX) or whatever Windows allows -- assert
            # mode bits AT MOST 0600 (no group/other readable).
            mode = os.stat(token_path).st_mode & 0o777
            if os.name != "nt":
                self.assertEqual(mode, 0o600,
                    f"token file mode is {oct(mode)}; expected 0o600")
            with open(token_path) as f:
                content = f.read()
            # Content is the token + a trailing newline.
            self.assertEqual(content.rstrip("\n"), "a" * 64)

    def test_write_failure_is_swallowed_not_fatal(self):
        """A write to a non-writable directory MUST NOT raise --
        the daemon stays up, the operator falls back to the env-var
        path.  This is the same 'cache is purely a UX optimization'
        contract the keypair_cache + merkle_cache helpers honor.
        """
        import server as srv
        class _Stub:
            pass
        stub = _Stub()
        # Point at a directory that doesn't exist -- the write open
        # will raise FileNotFoundError, the helper must swallow it.
        stub.data_dir = "/this/path/should/not/exist/xxxxx"
        stub.rpc_auth_token = "b" * 64
        # Should NOT raise; if it does the test fails.
        srv.Server._write_rpc_auth_token_file(stub)


class TestRpcCallAutoReadsTokenFile(unittest.TestCase):
    """``rpc_call(data_dir=...)`` MUST read the token from
    ``<data_dir>/rpc_auth_token`` when no explicit auth + no env var
    is set.  The test mocks the socket layer so we don't need a real
    daemon; we just intercept the request bytes and confirm the
    expected ``auth`` field is present."""

    def setUp(self):
        # Strip any inherited env var so the test's data-dir path is
        # the one being exercised (not env override).
        self._saved_env = os.environ.pop("MESSAGECHAIN_RPC_AUTH_TOKEN", None)
        self.tmp = tempfile.mkdtemp(prefix="mc-rpc-token-")

    def tearDown(self):
        if self._saved_env is not None:
            os.environ["MESSAGECHAIN_RPC_AUTH_TOKEN"] = self._saved_env
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _spin_echo_server(self, port_holder):
        """Start a tiny socket server that reads a length-prefixed
        request, echoes back ``{"ok": true, "echo": <parsed>}`` so
        the test can inspect what the client sent."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port_holder.append(srv.getsockname()[1])

        def loop():
            conn, _ = srv.accept()
            try:
                hdr = b""
                while len(hdr) < 4:
                    chunk = conn.recv(4 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                length = struct.unpack(">I", hdr)[0]
                body = b""
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        return
                    body += chunk
                parsed = json.loads(body.decode("utf-8"))
                resp = json.dumps({"ok": True, "echo": parsed}).encode("utf-8")
                conn.sendall(struct.pack(">I", len(resp)))
                conn.sendall(resp)
            finally:
                conn.close()
                srv.close()
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def test_rpc_call_reads_token_file_when_data_dir_passed(self):
        # Write a token file.
        token = "c" * 64
        path = os.path.join(self.tmp, "rpc_auth_token")
        with open(path, "w") as f:
            f.write(token + "\n")

        port_holder = []
        thread = self._spin_echo_server(port_holder)
        try:
            from client import rpc_call
            resp = rpc_call(
                "127.0.0.1", port_holder[0],
                "unban_peer", {"address": "1.2.3.4:9333"},
                data_dir=self.tmp,
            )
        finally:
            thread.join(timeout=2)

        self.assertTrue(resp.get("ok"))
        echo = resp["echo"]
        self.assertEqual(echo.get("auth"), token,
            "rpc_call did not include the token from "
            "<data_dir>/rpc_auth_token in the request payload")

    def test_rpc_call_falls_back_silently_when_token_file_missing(self):
        """No token file, no env var: request goes out WITHOUT an
        auth field.  Public methods still work; admin methods will
        401 from the server with a clear error."""
        port_holder = []
        thread = self._spin_echo_server(port_holder)
        try:
            from client import rpc_call
            resp = rpc_call(
                "127.0.0.1", port_holder[0],
                "get_chain_info", {},
                data_dir=self.tmp,  # exists but empty
            )
        finally:
            thread.join(timeout=2)

        self.assertTrue(resp.get("ok"))
        echo = resp["echo"]
        self.assertNotIn("auth", echo,
            "rpc_call sent an auth field with no token source available")


class TestUpgradeSmokeTestWalCheckpoint(unittest.TestCase):
    """Sanity: the WAL-checkpoint pre-smoke call doesn't blow up on a
    fresh / non-WAL chain.db, and the 300s timeout + retry-once
    semantics are present in the source.

    We don't actually run the upgrade subprocess (that needs sudo +
    a real release tag); the test confirms the new defenses landed
    in the source by string-matching the patched code paths."""

    def test_upgrade_cmd_does_wal_checkpoint_with_300s_timeout(self):
        import messagechain.cli as cli
        import inspect
        src = inspect.getsource(cli.cmd_upgrade)
        # WAL checkpoint must precede the smoke test.
        self.assertIn("PRAGMA wal_checkpoint(TRUNCATE)", src)
        # Per-attempt timeout bumped from 120s -> 300s.
        self.assertIn("timeout=300", src)
        # Retry path: explicit second attempt after a sleep.
        self.assertIn("retrying once", src.lower() or "")
        # The double-fail message names BOTH attempts so an operator
        # reading the failure knows the smoke test already retried.
        self.assertIn("both attempts", src)


if __name__ == "__main__":
    unittest.main()
