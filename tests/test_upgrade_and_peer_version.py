"""Tests for v1.2.0 operator-ergonomics release:

1. Peer version exchange — outgoing handshakes advertise
   ``messagechain.__version__`` and the inbound receive path stores
   it on ``peer.peer_version`` (falling back to ``"unknown"`` for
   peers running pre-1.2.0 that never sent the field).

2. ``messagechain upgrade`` subcommand — parser registration,
   preflight gates (git missing, non-root), target-version already
   at HEAD shortcut, and the rollback-on-health-check-failure path.

Tests are fully hermetic: no real systemctl, git, subprocess,
network, or filesystem outside a tempdir.  All heavy I/O is mocked.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

from messagechain import __version__ as CURRENT_VERSION
from messagechain.identity.identity import Entity
from messagechain.network.node import Node
from messagechain.network.protocol import MessageType, NetworkMessage


# ─────────────────────────────────────────────────────────────────────
# Part 1 — version constants and handshake plumbing
# ─────────────────────────────────────────────────────────────────────

class TestVersionConstants(unittest.TestCase):
    """The v1.2.0 bump must land in both the runtime constant and the
    distribution metadata.  A mismatch would mean `pip show` and
    `messagechain status` disagree."""

    def test_version_constant_bumped_past_1_0_0(self):
        import messagechain
        self.assertNotEqual(messagechain.__version__, "1.0.0")
        # Sanity: semver triple of three integers separated by dots.
        parts = messagechain.__version__.split(".")
        self.assertEqual(len(parts), 3)
        for p in parts:
            int(p)  # raises ValueError if not an integer

    def test_pyproject_version_matches(self):
        # Mirror of tests/test_release_hygiene.py but asserts the
        # literal value so a future revert of either side trips this.
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(repo_root, "pyproject.toml")
        try:
            import tomllib  # py311+
            with open(path, "rb") as f:
                data = tomllib.load(f)
            declared = data["project"]["version"]
        except ModuleNotFoundError:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            m = re.search(
                r"^\s*version\s*=\s*\"([^\"]+)\"\s*$",
                text, re.MULTILINE,
            )
            assert m is not None
            declared = m.group(1)
        self.assertEqual(declared, CURRENT_VERSION)


# ─────────────────────────────────────────────────────────────────────
# Part 1b — outbound handshake: node.py dial path advertises version
# ─────────────────────────────────────────────────────────────────────

class _FakePeer:
    """Minimal peer stand-in for _handle_message (mirrors the shape
    test_handshake_genesis_check.py uses)."""

    def __init__(self, addr: str):
        self.address = addr
        self.host, port = addr.split(":")
        self.port = int(port)
        self.is_connected = True
        self.writer = MagicMock()
        self.reader = MagicMock()
        self.handshake_complete = False
        self.last_seen = 0.0
        self.entity_id = ""
        self.connection_type = "full_relay"
        self.direction = "inbound"
        self.transport = "plain"
        self.peer_height = 0
        self.peer_version = ""

    def touch(self):
        self.last_seen = 1.0


def _handshake_msg(
    sender_id_hex: str,
    *,
    port: int = 9333,
    chain_height: int = 0,
    best_block_hash: str = "",
    cumulative_weight: int = 0,
    genesis_hash: str | None = "",
    version: str | None = "__MISSING__",
) -> NetworkMessage:
    payload: dict = {
        "port": port,
        "chain_height": chain_height,
        "best_block_hash": best_block_hash,
        "cumulative_weight": cumulative_weight,
        "genesis_hash": genesis_hash if genesis_hash is not None else "",
    }
    if version != "__MISSING__":
        payload["version"] = version
    return NetworkMessage(
        msg_type=MessageType.HANDSHAKE,
        sender_id=sender_id_hex,
        payload=payload,
    )


class TestInboundHandshakePopulatesPeerVersion(unittest.TestCase):
    """Cover the inbound receive side in messagechain/network/node.py.

    Peers running 1.2.0+ send "version" in the payload; older peers
    don't. Either way, the receiver stores something sensible on
    peer.peer_version (explicit version or "unknown").
    """

    def _make_node(self, port: int = 9999, *, seed: bytes = b"\x42" * 32) -> Node:
        ent = Entity.create(seed, tree_height=4)
        return Node(ent, port=port)

    def test_inbound_handshake_stores_peer_version(self):
        node = self._make_node(9200, seed=b"\x11" * 32)
        peer_entity = Entity.create(b"\x12" * 32, tree_height=4)
        peer = _FakePeer("10.0.0.10:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(
            peer_entity.entity_id_hex,
            version="1.1.0",
        )
        asyncio.run(node._handle_message(msg, peer))

        self.assertEqual(peer.peer_version, "1.1.0")

    def test_inbound_handshake_missing_version_maps_to_unknown(self):
        # Peer on a pre-1.2.0 binary: no "version" key in payload.
        node = self._make_node(9201, seed=b"\x13" * 32)
        peer_entity = Entity.create(b"\x14" * 32, tree_height=4)
        peer = _FakePeer("10.0.0.11:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(peer_entity.entity_id_hex)  # no version
        asyncio.run(node._handle_message(msg, peer))

        self.assertEqual(peer.peer_version, "unknown")

    def test_inbound_handshake_empty_version_maps_to_unknown(self):
        # Explicit empty string should also map to "unknown" — a peer
        # that advertises "" is as unhelpful as one that omits the key.
        node = self._make_node(9202, seed=b"\x15" * 32)
        peer_entity = Entity.create(b"\x16" * 32, tree_height=4)
        peer = _FakePeer("10.0.0.12:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(peer_entity.entity_id_hex, version="")
        asyncio.run(node._handle_message(msg, peer))

        self.assertEqual(peer.peer_version, "unknown")


class TestOutboundHandshakePayloadBuilders(unittest.TestCase):
    """The outbound handshake is built by a coroutine that also does
    socket I/O; rather than fake the transport, we lift the payload-
    dict literal out of the source and assert the "version" key is
    present. If the literal is ever rewritten to a builder function,
    this test should be rewritten to call the builder directly.

    The source-level check is cheap insurance: if a future refactor
    drops the version key from either send site, this fires loudly
    without requiring a live node handshake in the test.
    """

    def _read(self, rel_path: str) -> str:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, rel_path), "r", encoding="utf-8") as f:
            return f.read()

    def test_node_py_outbound_handshake_includes_version_key(self):
        src = self._read("messagechain/network/node.py")
        # Find the HANDSHAKE NetworkMessage block in node.py and check
        # it advertises version. Match on the specific payload dict
        # that precedes `sender_id=self.entity.entity_id_hex` (the
        # outbound dial-path handshake).
        m = re.search(
            r"msg_type=MessageType\.HANDSHAKE,\s*payload=\{(.*?)\},\s*"
            r"sender_id=self\.entity\.entity_id_hex",
            src, re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "could not locate outbound handshake payload in node.py — "
            "if the shape changed, update this test to match",
        )
        payload_block = m.group(1)
        self.assertIn('"version": __version__', payload_block)

    def test_server_py_outbound_handshake_includes_version_key(self):
        src = self._read("server.py")
        # server.py's outbound-dial handshake uses wallet_id as sender.
        m = re.search(
            r"msg_type=MessageType\.HANDSHAKE,\s*payload=\{(.*?)\},\s*"
            r"sender_id=self\.wallet_id\.hex\(\)",
            src, re.DOTALL,
        )
        self.assertIsNotNone(
            m,
            "could not locate outbound handshake payload in server.py",
        )
        payload_block = m.group(1)
        self.assertIn('"version": __version__', payload_block)


# ─────────────────────────────────────────────────────────────────────
# Part 2 — messagechain upgrade subcommand
# ─────────────────────────────────────────────────────────────────────

class TestUpgradeSubparser(unittest.TestCase):
    def test_upgrade_subparser_registered(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        # parse_args with `upgrade --tag vX.Y.Z` should not raise.
        args = parser.parse_args(["upgrade", "--tag", "v1.2.0-mainnet", "--yes"])
        self.assertEqual(args.command, "upgrade")
        self.assertEqual(args.tag, "v1.2.0-mainnet")
        self.assertTrue(args.yes)
        # Defaults should be set.
        self.assertEqual(args.install_dir, "/opt/messagechain")
        self.assertEqual(args.data_dir, "/var/lib/messagechain")
        self.assertEqual(args.service, "messagechain-validator")
        self.assertFalse(args.no_rollback)
        self.assertFalse(args.skip_migrate)


def _make_args(**overrides):
    """Build a minimal argparse.Namespace for cmd_upgrade tests."""
    import argparse
    ns = argparse.Namespace(
        command="upgrade",
        tag=None,
        install_dir="/opt/messagechain",
        data_dir="/var/lib/messagechain",
        service="messagechain-validator",
        repo="https://github.com/ben-arnao/MessageChain",
        service_user="messagechain:messagechain",
        no_rollback=False,
        skip_migrate=False,
        rpc_host="127.0.0.1",
        rpc_port=9334,
        yes=True,
        verbose=False,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


class TestUpgradePreflight(unittest.TestCase):
    def test_upgrade_fails_if_git_missing(self):
        from messagechain import cli as cli_mod
        args = _make_args()
        # which("git") returns None; which("systemctl") can return
        # something so the git branch is what trips the exit.
        def fake_which(name):
            return None if name == "git" else "/usr/bin/systemctl"
        with patch.object(cli_mod.shutil, "which", side_effect=fake_which) \
                if hasattr(cli_mod, "shutil") else patch("shutil.which", side_effect=fake_which):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_upgrade(args)
        self.assertNotEqual(cm.exception.code, 0)

    def test_upgrade_fails_if_not_root(self):
        # geteuid only exists on POSIX.  On Windows, cmd_upgrade skips
        # the root check entirely — which is correct because this
        # command is Linux-only in practice; skip the test accordingly.
        if not hasattr(os, "geteuid"):
            self.skipTest("os.geteuid not available on this platform")
        from messagechain import cli as cli_mod
        args = _make_args()
        with patch("shutil.which", return_value="/usr/bin/anything"), \
             patch.object(os, "geteuid", return_value=1000, create=True):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_upgrade(args)
        self.assertNotEqual(cm.exception.code, 0)

    def test_upgrade_no_op_when_at_target_tag(self):
        """If the resolved tag maps to the current running version,
        cmd_upgrade should print "already at X.Y.Z" and return without
        touching systemctl, git, or the filesystem."""
        from messagechain import cli as cli_mod

        # Pin geteuid to 0 (root) so preflight passes, then feed the
        # resolver the current version so the early-return fires.
        tag_for_current = f"v{CURRENT_VERSION}-mainnet"
        args = _make_args(tag=tag_for_current)

        fake_run = MagicMock()
        with patch("shutil.which", return_value="/usr/bin/anything"), \
             patch.object(os, "geteuid", return_value=0, create=True), \
             patch("subprocess.run", fake_run):
            # No SystemExit; returns normally.
            cli_mod.cmd_upgrade(args)

        # Crucially, subprocess.run must not have been called (no
        # systemctl stop, no git clone, no chown, nothing).
        fake_run.assert_not_called()


class TestUpgradeRollback(unittest.TestCase):
    """The centerpiece: on post-start health-check failure, cmd_upgrade
    must stop the service, remove the new install, move the backup
    back, and restart.  Mocks make the test hermetic — no real
    systemctl, no real git clone, no real filesystem mutation beyond
    a tempdir that never materializes.
    """

    def test_rollback_on_health_check_failure(self):
        from messagechain import cli as cli_mod

        args = _make_args(
            tag="v99.99.99-mainnet",  # never equals current version
            skip_migrate=True,         # keep the test focused
        )

        # Ordered list of subprocess.run calls so we can assert the
        # rollback sequence actually runs.
        calls: list[list[str]] = []

        def fake_run(cmd, *a, **kw):
            calls.append(list(cmd))
            # All subprocess calls "succeed" — we're testing the
            # rollback branch driven by health-check, not a
            # subprocess-failure branch.
            result = MagicMock()
            result.returncode = 0
            return result

        rmtree_calls: list[str] = []
        move_calls: list[tuple[str, str]] = []
        copy_calls: list[tuple[str, str]] = []

        def fake_rmtree(path, *a, **kw):
            rmtree_calls.append(path)

        def fake_move(src, dst):
            move_calls.append((src, dst))

        def fake_copytree(src, dst, *a, **kw):
            copy_calls.append((src, dst))

        # Health check: always fails (False) so the rollback branch fires.
        def fake_health(host, port, timeout_s=60):
            return False

        with patch("shutil.which", return_value="/usr/bin/anything"), \
             patch.object(os, "geteuid", return_value=0, create=True), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("shutil.rmtree", side_effect=fake_rmtree), \
             patch("shutil.move", side_effect=fake_move), \
             patch("shutil.copytree", side_effect=fake_copytree), \
             patch("os.path.exists", return_value=True), \
             patch.object(cli_mod, "_upgrade_verify_tag_signature"), \
             patch.object(cli_mod, "_upgrade_health_check", side_effect=fake_health):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_upgrade(args)

        self.assertNotEqual(cm.exception.code, 0)

        # --- Expected subprocess sequence ---
        # 1. systemctl stop (initial)
        # 2. systemctl reset-failed (best-effort)
        # 3. git clone
        # 4. chown
        # 5. systemctl start (post-install)
        # 6. systemctl stop (rollback)
        # 7. systemctl start (rollback)
        cmdlines = [" ".join(c) for c in calls]
        joined = "\n".join(cmdlines)
        self.assertIn("systemctl stop messagechain-validator", joined)
        self.assertIn("systemctl start messagechain-validator", joined)
        self.assertIn("git clone", joined)
        self.assertIn("chown -R messagechain:messagechain", joined)

        # At least two stop+start pairs: initial upgrade + rollback.
        stop_count = sum(
            1 for c in cmdlines if c.startswith("systemctl stop ")
        )
        start_count = sum(
            1 for c in cmdlines if c.startswith("systemctl start ")
        )
        self.assertGreaterEqual(stop_count, 2)
        self.assertGreaterEqual(start_count, 2)

        # --- Rollback filesystem sequence ---
        # shutil.move called twice: first to back up (install -> bak),
        # then to restore (bak -> install).
        self.assertGreaterEqual(len(move_calls), 2)
        self.assertEqual(move_calls[0][0], args.install_dir)  # backup
        # Restore: src is the backup dir, dst is the install dir.
        self.assertEqual(move_calls[-1][1], args.install_dir)
        # And rmtree was called on the failed install before restore.
        self.assertIn(args.install_dir, rmtree_calls)

    def test_clone_and_verify_run_before_service_stop(self):
        """Supply-chain gate ordering: ``git clone`` and the signature
        verify helper MUST both run BEFORE ``systemctl stop`` and
        ``shutil.move(install_dir -> backup_dir)``.

        Rationale: ``_upgrade_verify_tag_signature`` lazily imports
        ``messagechain.release_signers`` — if the install directory has
        already been moved to the backup path, that import resolves
        against a filesystem path that no longer exists and the
        upgrade aborts with the service stopped and no live install.
        The 1.5.x rollout to the 1.6.0 release hit this bug: validator-1
        needed a manual ``mv`` of the backup directory back to
        /opt/messagechain before it could restart.  Fixed by reordering
        so a failed clone or verify leaves the prior binary running
        and untouched.
        """
        from messagechain import cli as cli_mod

        args = _make_args(
            tag="v99.99.99-mainnet",
            skip_migrate=True,
        )

        events: list[str] = []

        def fake_run(cmd, *a, **kw):
            joined = " ".join(cmd)
            if "git clone" in joined:
                events.append("git_clone")
            elif joined.startswith("systemctl stop"):
                events.append("systemctl_stop")
            elif joined.startswith("systemctl start"):
                events.append("systemctl_start")
            elif joined.startswith("chown"):
                events.append("chown")
            result = MagicMock()
            result.returncode = 0
            return result

        def fake_move(src, dst):
            if src == args.install_dir:
                events.append("move_install_to_backup")
            else:
                events.append("move_other")

        def fake_verify(clone_dir, tag):
            events.append("verify_signature")

        def fake_health(host, port, timeout_s=60):
            # Pass so we exercise the happy-path ordering up to
            # completion rather than the rollback branch.
            return True

        with patch("shutil.which", return_value="/usr/bin/anything"), \
             patch.object(os, "geteuid", return_value=0, create=True), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("shutil.rmtree"), \
             patch("shutil.move", side_effect=fake_move), \
             patch("shutil.copytree"), \
             patch("os.path.exists", return_value=True), \
             patch.object(cli_mod, "_upgrade_verify_tag_signature",
                          side_effect=fake_verify), \
             patch.object(cli_mod, "_upgrade_health_check",
                          side_effect=fake_health):
            cli_mod.cmd_upgrade(args)

        # The critical invariants: clone and verify must BOTH land
        # before the service stop and before the backup move.
        clone_idx = events.index("git_clone")
        verify_idx = events.index("verify_signature")
        stop_idx = events.index("systemctl_stop")
        backup_idx = events.index("move_install_to_backup")
        self.assertLess(clone_idx, stop_idx,
                        f"git clone must precede systemctl stop; got {events}")
        self.assertLess(verify_idx, stop_idx,
                        f"verify must precede systemctl stop; got {events}")
        self.assertLess(clone_idx, backup_idx,
                        f"git clone must precede backup move; got {events}")
        self.assertLess(verify_idx, backup_idx,
                        f"verify must precede backup move; got {events}")
        # And verify runs on the clone that git clone produced, so
        # verify must follow the clone.
        self.assertLess(clone_idx, verify_idx,
                        f"verify must follow git clone; got {events}")

    def test_no_rollback_flag_leaves_new_code_in_place(self):
        """With --no-rollback, a failed health check must NOT move the
        backup back — operator recovers by hand using the printed
        command."""
        from messagechain import cli as cli_mod

        args = _make_args(
            tag="v99.99.99-mainnet",
            skip_migrate=True,
            no_rollback=True,
        )

        move_calls: list[tuple[str, str]] = []

        def fake_run(cmd, *a, **kw):
            r = MagicMock()
            r.returncode = 0
            return r

        def fake_health(host, port, timeout_s=60):
            return False

        with patch("shutil.which", return_value="/usr/bin/anything"), \
             patch.object(os, "geteuid", return_value=0, create=True), \
             patch("subprocess.run", side_effect=fake_run), \
             patch("shutil.rmtree"), \
             patch("shutil.move", side_effect=lambda s, d: move_calls.append((s, d))), \
             patch("shutil.copytree"), \
             patch("os.path.exists", return_value=True), \
             patch.object(cli_mod, "_upgrade_verify_tag_signature"), \
             patch.object(cli_mod, "_upgrade_health_check", side_effect=fake_health):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.cmd_upgrade(args)

        self.assertNotEqual(cm.exception.code, 0)
        # Exactly one move: the initial backup. The rollback-path
        # second move must not have happened.
        self.assertEqual(len(move_calls), 1)


class TestUpgradeTagHelpers(unittest.TestCase):
    def test_tag_to_version_strips_v_prefix(self):
        from messagechain.cli import _upgrade_tag_to_version
        self.assertEqual(_upgrade_tag_to_version("v1.2.0"), "1.2.0")
        self.assertEqual(_upgrade_tag_to_version("V1.2.0"), "1.2.0")

    def test_tag_to_version_strips_network_suffix(self):
        from messagechain.cli import _upgrade_tag_to_version
        self.assertEqual(_upgrade_tag_to_version("v1.2.0-mainnet"), "1.2.0")
        self.assertEqual(_upgrade_tag_to_version("v1.2.0-testnet"), "1.2.0")

    def test_tag_to_version_passthrough_for_plain_version(self):
        from messagechain.cli import _upgrade_tag_to_version
        self.assertEqual(_upgrade_tag_to_version("1.2.0"), "1.2.0")


class TestUpgradeTagResolutionFailure(unittest.TestCase):
    def test_resolver_raises_on_network_error(self):
        from messagechain.cli import _upgrade_resolve_latest_tag
        import urllib.error

        def _boom(*a, **kw):
            raise urllib.error.URLError("no route to host")

        with patch("urllib.request.urlopen", side_effect=_boom):
            with self.assertRaises(RuntimeError) as cm:
                _upgrade_resolve_latest_tag(
                    "https://github.com/ben-arnao/MessageChain",
                )
        self.assertIn("--tag", str(cm.exception))


class TestUpgradeTagResolutionPicksHighestSemver(unittest.TestCase):
    """The resolver uses the git-tags API (not releases API), because
    this repo publishes by pushing git tags rather than creating
    GitHub Release objects.  The tags API returns every pushed tag,
    but in *creation order*, not semver order -- so the resolver must
    sort vX.Y.Z-mainnet tags by (major, minor, patch) and pick the
    highest, skipping any tag that doesn't match the canonical
    pattern."""

    def _mock_urlopen_with(self, tags_payload):
        """Return a patcher that makes urlopen yield *tags_payload*
        JSON-encoded on first .read()."""
        import io
        import json

        body = json.dumps(tags_payload).encode("utf-8")

        class _Resp:
            def __init__(self, data):
                self._buf = io.BytesIO(data)

            def read(self):
                return self._buf.read()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return patch("urllib.request.urlopen", return_value=_Resp(body))

    def test_picks_highest_semver_not_creation_order(self):
        from messagechain.cli import _upgrade_resolve_latest_tag

        # Creation order puts 1.0.0 *last* (oldest) -- the releases
        # API would have returned 1.0.0 (the only one ever published
        # as a Release object). The tags-API + semver-sort path
        # must instead pick v1.2.1-mainnet.
        payload = [
            {"name": "v1.2.1-mainnet"},
            {"name": "v1.2.0-mainnet"},
            {"name": "v1.1.1-mainnet"},
            {"name": "v1.1.0-mainnet"},
            {"name": "v1.0.2-mainnet"},
            {"name": "v1.0.1-mainnet"},
            {"name": "v1.0.0-mainnet"},
        ]
        with self._mock_urlopen_with(payload):
            tag = _upgrade_resolve_latest_tag(
                "https://github.com/ben-arnao/MessageChain",
            )
        self.assertEqual(tag, "v1.2.1-mainnet")

    def test_ignores_non_mainnet_tags(self):
        from messagechain.cli import _upgrade_resolve_latest_tag

        payload = [
            {"name": "v2.0.0-testnet"},
            {"name": "v1.9.9-rc1"},
            {"name": "random-tag"},
            {"name": "v1.1.0-mainnet"},
            {"name": "v1.0.0-mainnet"},
        ]
        with self._mock_urlopen_with(payload):
            tag = _upgrade_resolve_latest_tag(
                "https://github.com/ben-arnao/MessageChain",
            )
        self.assertEqual(tag, "v1.1.0-mainnet")

    def test_sorts_semver_not_lexicographic(self):
        from messagechain.cli import _upgrade_resolve_latest_tag

        # Lexicographic would pick v1.9.0 over v1.10.0.  Semver sorting
        # must pick v1.10.0.
        payload = [
            {"name": "v1.9.0-mainnet"},
            {"name": "v1.10.0-mainnet"},
            {"name": "v1.2.0-mainnet"},
        ]
        with self._mock_urlopen_with(payload):
            tag = _upgrade_resolve_latest_tag(
                "https://github.com/ben-arnao/MessageChain",
            )
        self.assertEqual(tag, "v1.10.0-mainnet")

    def test_raises_if_no_mainnet_tags_found(self):
        from messagechain.cli import _upgrade_resolve_latest_tag

        payload = [
            {"name": "v1.0.0-testnet"},
            {"name": "nightly-2026-04-24"},
        ]
        with self._mock_urlopen_with(payload):
            with self.assertRaises(RuntimeError) as cm:
                _upgrade_resolve_latest_tag(
                    "https://github.com/ben-arnao/MessageChain",
                )
        self.assertIn("no canonical", str(cm.exception))


class TestUpgradeTagSignatureVerification(unittest.TestCase):
    """Supply-chain gate: ``_upgrade_verify_tag_signature`` must accept
    tags signed by pinned release signers and reject everything else
    (unsigned tags, unknown signers, missing tags).  Without this
    gate, ``messagechain upgrade`` would install any tag pushed to
    the repo as root — an attacker who compromised a maintainer's
    GitHub token could ship arbitrary code to every validator on
    next upgrade.
    """

    def test_unknown_signer_rejected(self):
        """git tag -v returns non-zero when the signer is not in the
        pinned allowed_signers file.  Simulate via a fake subprocess
        that returns exit 1 with a 'no principal matched' style error —
        exactly what git emits for a tag signed by a key outside the
        allowed set."""
        from messagechain.cli import _upgrade_verify_tag_signature
        from unittest.mock import patch, MagicMock

        def fake_run(cmd, *a, **kw):
            r = MagicMock()
            r.returncode = 1
            r.stderr = (
                "error: gpg.ssh.allowedSignersFile needs to be "
                "configured and exist for ssh signature verification\n"
                "no principal matched"
            )
            r.stdout = ""
            return r

        with patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as cm:
                _upgrade_verify_tag_signature("/tmp/fake", "v1.2.3-mainnet")
        self.assertIn("signature verification", str(cm.exception).lower())

    def test_unsigned_tag_rejected(self):
        """git tag -v returns non-zero with 'no signature found' on an
        unsigned tag.  The verifier must propagate this as a fatal
        RuntimeError."""
        from messagechain.cli import _upgrade_verify_tag_signature
        from unittest.mock import patch, MagicMock

        def fake_run(cmd, *a, **kw):
            r = MagicMock()
            r.returncode = 1
            r.stderr = "error: no signature found"
            r.stdout = ""
            return r

        with patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(RuntimeError) as cm:
                _upgrade_verify_tag_signature("/tmp/fake", "v1.2.3-mainnet")
        self.assertIn("no signature", str(cm.exception).lower())

    def test_authorized_signer_accepted(self):
        """A git tag -v run that exits 0 and emits a 'Good signature'
        line passes verification without raising."""
        from messagechain.cli import _upgrade_verify_tag_signature
        from unittest.mock import patch, MagicMock

        def fake_run(cmd, *a, **kw):
            r = MagicMock()
            r.returncode = 0
            r.stderr = (
                'Good "git" signature for arnaoben@gmail.com with '
                "ED25519 key SHA256:abcdef"
            )
            r.stdout = ""
            return r

        with patch("subprocess.run", side_effect=fake_run):
            # Must not raise.
            _upgrade_verify_tag_signature("/tmp/fake", "v1.2.3-mainnet")

    def test_verifier_pins_allowed_signers_via_c_flag(self):
        """The verifier MUST pass -c gpg.ssh.allowedSignersFile=<tmp>
        so the pinned set (not the host's global git config) decides
        which keys are trusted.  Otherwise an attacker who can edit
        the operator's ~/.gitconfig would bypass the gate."""
        from messagechain.cli import _upgrade_verify_tag_signature
        from unittest.mock import patch, MagicMock

        observed_cmds: list[list[str]] = []

        def fake_run(cmd, *a, **kw):
            observed_cmds.append(list(cmd))
            r = MagicMock()
            r.returncode = 0
            r.stderr = 'Good "git" signature for arnaoben@gmail.com'
            r.stdout = ""
            return r

        with patch("subprocess.run", side_effect=fake_run):
            _upgrade_verify_tag_signature("/tmp/fake", "v1.2.3-mainnet")

        self.assertEqual(len(observed_cmds), 1)
        cmd = observed_cmds[0]
        # -c gpg.ssh.allowedSignersFile=<path> is present.
        joined = " ".join(cmd)
        self.assertIn("gpg.ssh.allowedSignersFile=", joined)
        self.assertIn("gpg.format=ssh", joined)
        # tag -v is the terminal operation.
        self.assertIn("tag", cmd)
        self.assertIn("-v", cmd)

    def test_allowed_signers_pins_known_maintainer(self):
        """The pinned allowed-signers blob MUST contain the documented
        MessageChain release-signer pubkey — regression against
        accidental edits that would break the signature chain on every
        validator on next upgrade."""
        from messagechain.release_signers import ALLOWED_SIGNERS

        self.assertIn(b"arnaoben@gmail.com", ALLOWED_SIGNERS)
        self.assertIn(b'namespaces="git"', ALLOWED_SIGNERS)
        self.assertIn(b"ssh-ed25519", ALLOWED_SIGNERS)


if __name__ == "__main__":
    unittest.main()
