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
    the unit file is ever regenerated from a template."""

    def test_unit_has_memory_deny_write_execute(self):
        unit = (ROOT / "deploy" / "systemd" / "messagechain-validator.service").read_text(encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
