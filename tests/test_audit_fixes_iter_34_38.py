"""Regression tests for the iter 34-38 final-pass audit fixes.

Shipped in this batch:

1. needs_sync() guard on block production — prevents WOTS+ leaf-reuse
   after a stale-snapshot restore where our local chain.db is behind
   the real network.  If any known peer has higher height, we refuse
   to sign a block until IBD catches us up.  At N=0 peers we produce
   normally (bootstrap-phase single validator).

2. generate-key + verify-key CLI now prints the `mc1...` address
   alongside the raw entity_id hex, so users can share a
   typo-checked address without copying hex.

3. systemd unit adds MemoryDenyWriteExecute, PrivateIPC, RemoveIPC,
   ProcSubset=pid — standard hardening gaps flagged by
   `systemd-analyze security`.

4. Runbook docs switched from `python -m messagechain` to
   `messagechain` (the `pip install .` entry point works post-iter-32).
"""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent

# deploy/ and docs/ are gitignored per CLAUDE.md (operator/founder-local
# content).  These tests only run when those directories are present.
_DEPLOY_PRESENT = (ROOT / "deploy").is_dir()
_DOCS_PRESENT = (ROOT / "docs").is_dir()


class TestBlockProductionRefusesWhenPeersAhead(unittest.TestCase):
    """The leaf-reuse defence — if `needs_sync()` returns True, block
    production must return None / early-return instead of signing.

    Source pin (not a live test — exercising block production needs a
    full chain + mempool; this confirms the guard is in place where it
    matters)."""

    def test_server_try_produce_block_sync_guards_on_needs_sync(self):
        src = (ROOT / "server.py").read_text(encoding="utf-8")
        i = src.index("def _try_produce_block_sync")
        j = src.index("\n    def ", i + 1)
        body = src[i:j]
        self.assertIn("self.syncer.needs_sync()", body,
                      "server.py:_try_produce_block_sync must early-return "
                      "when needs_sync() is True — this prevents WOTS+ "
                      "leaf reuse after a stale-snapshot restore")

    def test_node_try_produce_block_guards_on_needs_sync(self):
        src = (ROOT / "messagechain" / "network" / "node.py").read_text(encoding="utf-8")
        i = src.index("async def _try_produce_block")
        # find next async def
        j = src.index("\n    async def ", i + 1)
        body = src[i:j]
        self.assertIn("self.syncer.needs_sync()", body,
                      "node.py:_try_produce_block must early-return "
                      "when needs_sync() is True")


class TestGenerateVerifyKeyPrintsAddress(unittest.TestCase):
    """Users running `messagechain generate-key` or `verify-key` should
    see the checksummed `mc1…` form alongside the raw entity_id — raw
    hex has no typo protection for share-to-receive workflows."""

    def test_generate_key_emits_address(self):
        src = (ROOT / "messagechain" / "cli.py").read_text(encoding="utf-8")
        i = src.index("def cmd_generate_key")
        j = src.index("\ndef ", i + 1)
        body = src[i:j]
        self.assertIn("encode_address(entity.entity_id)", body)
        self.assertIn("Address:", body)

    def test_verify_key_emits_address(self):
        src = (ROOT / "messagechain" / "cli.py").read_text(encoding="utf-8")
        i = src.index("def cmd_verify_key")
        j = src.index("\ndef ", i + 1)
        body = src[i:j]
        self.assertIn("encode_address(entity.entity_id)", body)
        self.assertIn("Address:", body)


class TestSystemdHardening(unittest.TestCase):
    """Production validator unit file must carry baseline hardening.
    Adding a new required directive here serves as a regression gate if
    the unit file is ever regenerated from a template.

    Runs against the PUBLIC shipped template
    (``examples/messagechain-validator.service.example``) so any PR
    that weakens the hardening surface fails CI immediately — the
    previous ``deploy/``-gated form skipped on every public CI run
    and the hardening contract was enforced only on the operator's
    local machine.
    """

    def test_unit_has_memory_deny_write_execute(self):
        unit = (
            ROOT / "examples" / "messagechain-validator.service.example"
        ).read_text(encoding="utf-8")
        required = [
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectKernelModules=true",
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "MemoryDenyWriteExecute=true",
            "PrivateIPC=true",
            "RemoveIPC=true",
            "ProcSubset=pid",
        ]
        missing = [d for d in required if d not in unit]
        self.assertEqual(
            missing, [],
            f"systemd unit missing hardening: {missing}",
        )


@unittest.skipUnless(_DOCS_PRESENT, "docs/ gitignored; operator-only test")
class TestRunbookDocsUseDirectCLI(unittest.TestCase):
    """After `pip install .` ships the `messagechain` entry point (iter
    32), runbooks should show `messagechain foo` not `python -m
    messagechain foo`.  Historical audit files (system-audit.md) keep
    the old form intentionally — we're pinning runbooks only."""

    def test_runbooks_no_python_m_form(self):
        for doc in ("backup-restore-runbook.md", "key-rotation-runbook.md"):
            content = (ROOT / "docs" / doc).read_text(encoding="utf-8")
            self.assertNotIn(
                "python -m messagechain", content,
                f"docs/{doc} still references `python -m messagechain` — "
                f"should be `messagechain` (direct entry point).",
            )


class TestDevnetFlagStaysInSyncWithNetworkName(unittest.TestCase):
    """config.py previously computed DEVNET once before config_local.py
    ran.  A config_local.py that flipped NETWORK_NAME to "devnet" would
    leave DEVNET=False — consumers checking `if DEVNET:` got the wrong
    answer.  Fix re-derives DEVNET after the local-override block,
    same pattern as PINNED_GENESIS_HASH."""

    def test_config_re_derives_devnet_after_local_override(self):
        src = (ROOT / "messagechain" / "config.py").read_text(encoding="utf-8")
        # Find the local-override load block
        i = src.index("# ─────────────────────────────────────────────────────────────────────\n# Local overrides")
        tail = src[i:]
        self.assertIn('if "DEVNET" not in', tail,
                      "config.py must re-derive DEVNET after config_local "
                      "loads, else a config_local NETWORK_NAME='devnet' "
                      "override leaves DEVNET False")
        self.assertIn('DEVNET = NETWORK_NAME == "devnet"', tail)


class TestStartupLogsTruncateEntityID(unittest.TestCase):
    """Full entity_id in startup logs is sensitive validator metadata.
    Truncate to 16 hex chars — correlation within a single node's logs
    still works, but journald aggregation doesn't leak the full id."""

    def test_server_wallet_log_truncates(self):
        src = (ROOT / "server.py").read_text(encoding="utf-8")
        # No "Wallet: " log that includes full .hex() (no slice)
        self.assertNotIn(
            'logger.info(f"Wallet: {self.wallet_id.hex() if self.wallet_id else \'NOT SET\'}")',
            src,
        )
        # And the truncated form is present
        self.assertIn("self.wallet_id.hex()[:16]", src)

    def test_node_entity_id_log_truncates(self):
        src = (ROOT / "messagechain" / "network" / "node.py").read_text(encoding="utf-8")
        self.assertNotIn(
            'logger.info(f"Entity ID: {self.entity.entity_id_hex}")',
            src,
        )
        self.assertIn("self.entity.entity_id_hex[:16]", src)


if __name__ == "__main__":
    unittest.main()
