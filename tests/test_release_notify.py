"""
Tests for the operator-notification surface of the release manifest.

Three surfaces are covered:

1. Boot-time log (`server.log_release_status`) — logs a structured
   "UPDATE AVAILABLE" line at INFO/WARNING/ERROR levels depending on
   manifest presence and severity.  Pure function of
   `(blockchain.latest_release_manifest, current_version)`; no side
   effects beyond logging.

2. RPC (`get_latest_release`) — cheap read-only RPC that echoes the
   manifest + `current_node_version` + `update_available` flag.
   Serializes binary_hashes and nonce as lowercase hex, threshold +
   signer indices + severity_label populated.

3. CLI (`cmd_release_status`) — prints a human-readable block by
   calling the new RPC.  Tested against a stubbed RPC result.

This feature is pure notification — nothing is auto-downloaded,
nothing is verified against a local binary, nothing is consensus-
gated.  See CLAUDE.md "permanence scope is message payloads only"
and the release_announce.py docstring.
"""

from __future__ import annotations

import io
import logging
import unittest
from contextlib import redirect_stdout
from dataclasses import dataclass
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

from messagechain import __version__ as current_node_version
from messagechain import config


# ──────────────────────────────────────────────────────────────
# Tiny fake manifest — covers only the fields the notification
# surface reads.  Using a dataclass stub keeps the tests
# independent of the real tx's signature + threshold machinery,
# which is already covered by test_release_announce.py.
# ──────────────────────────────────────────────────────────────
@dataclass
class FakeManifest:
    version: str
    severity: int
    binary_hashes: Dict[str, bytes]
    min_activation_height: Optional[int]
    release_notes_uri: str
    nonce: bytes
    signer_indices: List[int]


def _manifest(
    *,
    version: str = "9.9.9",
    severity: int = 0,
    binary_hashes: Optional[Dict[str, bytes]] = None,
    min_activation_height: Optional[int] = None,
    release_notes_uri: str = "https://releases.messagechain.org/9.9.9",
    nonce: bytes = b"\xAB" * 16,
    signer_indices: Optional[List[int]] = None,
) -> FakeManifest:
    if binary_hashes is None:
        binary_hashes = {
            "linux-x86_64": b"\x11" * 32,
            "darwin-arm64": b"\x22" * 32,
        }
    if signer_indices is None:
        signer_indices = [0, 2, 4]
    return FakeManifest(
        version=version,
        severity=severity,
        binary_hashes=binary_hashes,
        min_activation_height=min_activation_height,
        release_notes_uri=release_notes_uri,
        nonce=nonce,
        signer_indices=signer_indices,
    )


class _StubChain:
    """Just enough blockchain surface for the notify helpers."""

    def __init__(self, manifest: Optional[FakeManifest] = None):
        self.latest_release_manifest = manifest


# ──────────────────────────────────────────────────────────────
# 1. Boot-log helper — server.log_release_status
# ──────────────────────────────────────────────────────────────
class TestLogReleaseStatus(unittest.TestCase):
    """`log_release_status(logger, blockchain, current_version)`.

    Contract:
    - no manifest → no log output
    - version matches current → single INFO "Running latest announced release ..."
    - version differs, severity 0 → WARNING line
    - version differs, severity >= 1 → ERROR line
    - message body includes manifest version, current version,
      severity label, signer count, release notes uri, and
      (if set) activation height
    """

    def _get_records(self, blockchain, current_version):
        """Invoke the helper and return (records, test_logger)."""
        from server import log_release_status

        lg = logging.getLogger("test_release_notify." + self.id())
        lg.setLevel(logging.DEBUG)
        lg.propagate = False
        # Ensure the logger has no leftover handlers across tests.
        lg.handlers = []
        with self.assertLogs(lg, level="DEBUG") as cm:
            log_release_status(lg, blockchain, current_version)
            # assertLogs requires >= 1 record; emit a sentinel we can filter.
            lg.debug("__sentinel__")
        return [r for r in cm.records if "__sentinel__" not in r.getMessage()]

    def test_no_manifest_silent(self):
        chain = _StubChain(manifest=None)
        records = self._get_records(chain, current_node_version)
        self.assertEqual(records, [],
                         f"expected no log records, got: "
                         f"{[r.getMessage() for r in records]}")

    def test_version_match_logs_info(self):
        chain = _StubChain(manifest=_manifest(version=current_node_version))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.INFO)
        msg = records[0].getMessage()
        self.assertIn("latest announced release", msg.lower())
        self.assertIn(current_node_version, msg)

    def test_severity_zero_mismatch_logs_warning(self):
        chain = _StubChain(manifest=_manifest(version="99.0.0", severity=0,
                                              signer_indices=[0, 1, 2]))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1, [r.getMessage() for r in records])
        self.assertEqual(records[0].levelno, logging.WARNING)
        msg = records[0].getMessage()
        self.assertIn("UPDATE AVAILABLE", msg)
        self.assertIn("v99.0.0", msg)
        self.assertIn(f"v{current_node_version}", msg)
        self.assertIn("normal", msg)
        self.assertIn("3", msg)  # three signers
        self.assertIn("https://releases.messagechain.org/", msg)

    def test_severity_one_mismatch_logs_error(self):
        chain = _StubChain(manifest=_manifest(version="99.0.0", severity=1,
                                              signer_indices=[0, 1, 2, 3]))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.ERROR)
        msg = records[0].getMessage()
        self.assertIn("UPDATE AVAILABLE", msg)
        self.assertIn("security", msg)
        self.assertIn("4", msg)  # signer count

    def test_severity_two_mismatch_logs_error(self):
        chain = _StubChain(manifest=_manifest(version="99.0.0", severity=2))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.ERROR)
        msg = records[0].getMessage()
        self.assertIn("emergency", msg)

    def test_min_activation_height_included_when_set(self):
        chain = _StubChain(manifest=_manifest(
            version="99.0.0", severity=0, min_activation_height=12345,
        ))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1)
        msg = records[0].getMessage()
        self.assertIn("12345", msg)
        # Activation height line should precede release notes URL.
        self.assertLess(msg.index("12345"), msg.index("Release notes"))

    def test_min_activation_height_omitted_when_none(self):
        chain = _StubChain(manifest=_manifest(
            version="99.0.0", severity=0, min_activation_height=None,
        ))
        records = self._get_records(chain, current_node_version)
        self.assertEqual(len(records), 1)
        msg = records[0].getMessage()
        # No 'activation' wording when None.
        self.assertNotIn("activation", msg.lower())

    # ── Semver-aware update detection ───────────────────────────
    def test_nine_to_ten_minor_bump_warns_update_available(self):
        """Regression for the lex-compare bug: node v0.9.0, manifest v0.10.0
        MUST surface as an update — under the old lex compare
        "0.10.0" < "0.9.0", so the helper would have said "running
        latest" and hidden a real update."""
        chain = _StubChain(manifest=_manifest(version="0.10.0", severity=0))
        records = self._get_records(chain, "0.9.0")
        self.assertEqual(len(records), 1, [r.getMessage() for r in records])
        self.assertEqual(records[0].levelno, logging.WARNING)
        msg = records[0].getMessage()
        self.assertIn("UPDATE AVAILABLE", msg)
        self.assertIn("v0.10.0", msg)
        self.assertIn("v0.9.0", msg)

    def test_node_ahead_of_manifest_logs_info(self):
        """Node v0.10.0 running, manifest announces v0.9.0 — this is a
        dev build newer than the last announced release.  Should NOT
        fire UPDATE AVAILABLE; should emit a friendly "ahead" info line."""
        chain = _StubChain(manifest=_manifest(version="0.9.0", severity=0))
        records = self._get_records(chain, "0.10.0")
        self.assertEqual(len(records), 1, [r.getMessage() for r in records])
        self.assertEqual(records[0].levelno, logging.INFO)
        msg = records[0].getMessage()
        self.assertNotIn("UPDATE AVAILABLE", msg)
        self.assertIn("ahead", msg.lower())
        self.assertIn("v0.10.0", msg)
        self.assertIn("v0.9.0", msg)

    def test_equal_versions_log_running_latest(self):
        """Semver-equal → still "running latest", same as before."""
        chain = _StubChain(manifest=_manifest(version="0.2.0", severity=0))
        records = self._get_records(chain, "0.2.0")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.INFO)
        self.assertIn("latest announced release", records[0].getMessage().lower())

    def test_unparseable_node_version_falls_back_to_strict_string(self):
        """If the node's own version string doesn't parse (e.g. a
        developer build tag), the helper must still surface a real
        update — fall back to the old string-inequality behavior.

        This is the safety net: we never want a parser edge case to
        silence an UPDATE AVAILABLE signal.
        """
        chain = _StubChain(manifest=_manifest(version="0.2.0", severity=0))
        records = self._get_records(chain, "weird-local-build")
        # Falls back: they aren't equal, so UPDATE AVAILABLE.
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.WARNING)
        self.assertIn("UPDATE AVAILABLE", records[0].getMessage())


# ──────────────────────────────────────────────────────────────
# 2. RPC handler — get_latest_release
# ──────────────────────────────────────────────────────────────
class TestGetLatestReleaseRPC(unittest.TestCase):
    """`Server._rpc_get_latest_release(params)` returns the canonical
    notification shape documented in the task spec.

    We build a minimal fake "server" with just `.blockchain` and call
    the method directly — no sockets, no rate limiter.
    """

    def setUp(self):
        # Isolate from global config drift between tests.
        self._orig_threshold = config.RELEASE_THRESHOLD
        config.RELEASE_THRESHOLD = 3

    def tearDown(self):
        config.RELEASE_THRESHOLD = self._orig_threshold

    def _call(self, manifest):
        from server import Server
        srv = Server.__new__(Server)
        srv.blockchain = _StubChain(manifest=manifest)
        return srv._rpc_get_latest_release({})

    def test_no_manifest(self):
        resp = self._call(None)
        self.assertTrue(resp["ok"])
        result = resp["result"]
        self.assertEqual(result["current_node_version"], current_node_version)
        self.assertIsNone(result["latest_manifest"])
        self.assertFalse(result["update_available"])

    def test_version_match_update_not_available(self):
        m = _manifest(version=current_node_version, severity=0)
        resp = self._call(m)
        self.assertTrue(resp["ok"])
        result = resp["result"]
        self.assertEqual(result["current_node_version"], current_node_version)
        self.assertIsNotNone(result["latest_manifest"])
        self.assertEqual(result["latest_manifest"]["version"], current_node_version)
        self.assertFalse(result["update_available"])

    def test_version_mismatch_update_available(self):
        m = _manifest(version="99.0.0", severity=0)
        resp = self._call(m)
        result = resp["result"]
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest_manifest"]["version"], "99.0.0")

    def test_severity_label_mapping(self):
        for sev, label in ((0, "normal"), (1, "security"), (2, "emergency")):
            m = _manifest(version="99.0.0", severity=sev)
            resp = self._call(m)
            lm = resp["result"]["latest_manifest"]
            self.assertEqual(lm["severity"], sev)
            self.assertEqual(lm["severity_label"], label)

    def test_binary_hashes_are_lowercase_hex(self):
        m = _manifest(
            version="99.0.0", severity=0,
            binary_hashes={"linux-x86_64": b"\xAB\xCD" + b"\x00" * 30},
        )
        resp = self._call(m)
        bh = resp["result"]["latest_manifest"]["binary_hashes"]
        hex_val = bh["linux-x86_64"]
        self.assertEqual(hex_val, hex_val.lower(),
                         f"binary hash hex must be lowercase: {hex_val}")
        self.assertEqual(hex_val,
                         ("\xab\xcd".encode("latin-1") + b"\x00" * 30).hex())

    def test_nonce_is_lowercase_hex(self):
        m = _manifest(version="99.0.0", severity=0, nonce=b"\xFE" * 16)
        resp = self._call(m)
        nh = resp["result"]["latest_manifest"]["nonce_hex"]
        self.assertEqual(nh, nh.lower())
        self.assertEqual(nh, (b"\xfe" * 16).hex())

    def test_signer_indices_num_signers_threshold(self):
        m = _manifest(version="99.0.0", severity=0, signer_indices=[0, 2, 4])
        resp = self._call(m)
        lm = resp["result"]["latest_manifest"]
        self.assertEqual(lm["signer_indices"], [0, 2, 4])
        self.assertEqual(lm["num_signers"], 3)
        self.assertEqual(lm["threshold"], config.RELEASE_THRESHOLD)

    def test_min_activation_height_passthrough(self):
        for value in (None, 42, 12345):
            m = _manifest(version="99.0.0", severity=0,
                          min_activation_height=value)
            resp = self._call(m)
            self.assertEqual(
                resp["result"]["latest_manifest"]["min_activation_height"],
                value,
            )

    # ── Semver-aware update_available flag ──────────────────────
    def _call_with_node_version(self, manifest, node_version):
        """Same as _call() but pin __version__ so we can exercise the
        update_available semantics without rebuilding the package."""
        from server import Server
        import messagechain
        srv = Server.__new__(Server)
        srv.blockchain = _StubChain(manifest=manifest)
        orig = messagechain.__version__
        try:
            messagechain.__version__ = node_version
            return srv._rpc_get_latest_release({})
        finally:
            messagechain.__version__ = orig

    def test_update_available_9_to_10_boundary(self):
        """Node v0.9.0, manifest v0.10.0 → update_available True.

        Regression: under the old `manifest.version != current_version`
        compare, this returned True only by luck — the inequality
        happened to hold.  Now we use the semver comparator, and this
        should stay True (and be True for the *right* reason).
        """
        m = _manifest(version="0.10.0", severity=0)
        resp = self._call_with_node_version(m, "0.9.0")
        self.assertTrue(resp["result"]["update_available"])

    def test_update_available_false_when_node_ahead(self):
        """Node v0.10.0, manifest v0.9.0 → update_available False.

        Under the old inequality compare this was True, which is a
        bug: the operator isn't missing an update, they're a dev
        build ahead of the last announced release.
        """
        m = _manifest(version="0.9.0", severity=0)
        resp = self._call_with_node_version(m, "0.10.0")
        self.assertFalse(resp["result"]["update_available"])

    def test_update_available_false_on_equal(self):
        m = _manifest(version="0.2.0", severity=0)
        resp = self._call_with_node_version(m, "0.2.0")
        self.assertFalse(resp["result"]["update_available"])

    def test_update_available_falls_back_when_unparseable(self):
        """Unparseable node version → fall back to string inequality
        so a real update signal is never silenced."""
        m = _manifest(version="0.2.0", severity=0)
        resp = self._call_with_node_version(m, "weird-local-build")
        self.assertTrue(resp["result"]["update_available"])


# ──────────────────────────────────────────────────────────────
# 3. CLI subcommand — release-status
# ──────────────────────────────────────────────────────────────
class TestCmdReleaseStatus(unittest.TestCase):
    """`cli.cmd_release_status(args)` prints a human-readable block
    fed from the RPC.  We stub the RPC call and capture stdout.
    """

    def _args(self):
        ns = MagicMock()
        ns.server = None
        return ns

    def _run(self, rpc_result):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            with patch("client.rpc_call",
                       return_value={"ok": True, "result": rpc_result}):
                with redirect_stdout(buf):
                    cli_mod.cmd_release_status(self._args())
        return buf.getvalue()

    def test_no_manifest_message(self):
        out = self._run({
            "current_node_version": "0.1.0",
            "latest_manifest": None,
            "update_available": False,
        })
        self.assertIn("No release manifest seen", out)
        self.assertIn("0.1.0", out)

    def test_update_available_layout(self):
        out = self._run({
            "current_node_version": "0.1.0",
            "latest_manifest": {
                "version": "0.2.0",
                "severity": 1,
                "severity_label": "security",
                "binary_hashes": {
                    "linux-x86_64": "ab" * 32,
                    "macos-arm64": "cd" * 32,
                    "windows-x86_64": "ef" * 32,
                },
                "min_activation_height": 12345,
                "release_notes_uri": "https://releases.messagechain.org/0.2.0",
                "signer_indices": [0, 2, 4],
                "num_signers": 3,
                "threshold": 5,
                "nonce_hex": "aa" * 16,
            },
            "update_available": True,
        })
        # Core lines
        self.assertIn("Node version:", out)
        self.assertIn("0.1.0", out)
        self.assertIn("Latest manifest:", out)
        self.assertIn("v0.2.0", out)
        self.assertIn("security", out)
        self.assertIn("Update available:", out)
        self.assertIn("YES", out)
        self.assertIn("Signers:", out)
        self.assertIn("3 of 5", out)
        self.assertIn("0, 2, 4", out)
        self.assertIn("Min activation:", out)
        self.assertIn("12345", out)
        self.assertIn("Binary hashes:", out)
        self.assertIn("linux-x86_64", out)
        self.assertIn("Release notes:", out)
        self.assertIn("https://releases.messagechain.org/0.2.0", out)

    def test_omits_activation_line_when_none(self):
        out = self._run({
            "current_node_version": "0.1.0",
            "latest_manifest": {
                "version": "0.1.0",
                "severity": 0,
                "severity_label": "normal",
                "binary_hashes": {"linux-x86_64": "ab" * 32},
                "min_activation_height": None,
                "release_notes_uri": "https://releases.messagechain.org/0.1.0",
                "signer_indices": [0, 1, 2],
                "num_signers": 3,
                "threshold": 3,
                "nonce_hex": "cd" * 16,
            },
            "update_available": False,
        })
        self.assertNotIn("Min activation:", out)
        self.assertIn("NO", out)  # update available flag

    def test_rpc_error_surfaces(self):
        """If the RPC fails, print the error and exit non-zero."""
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)):
            with patch("client.rpc_call",
                       return_value={"ok": False, "error": "boom"}):
                with redirect_stdout(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        cli_mod.cmd_release_status(self._args())
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("boom", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
