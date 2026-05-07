"""Audit r34 #2 -- ``messagechain start --mine`` gates on the leaf-
index check before the daemon takes its first signing opportunity.

r33 #3 added ``_check_leaf_index`` to the doctor checklist.  The check
is correct -- it catches the keyfile-on-fresh-disk-without-cursor
restore disaster (chain watermark > 0, no leaf_index.json on disk →
next sign re-uses a burned leaf → 100%-slash equivocation evidence).
But the gate only fires when the operator runs ``messagechain
doctor`` first.

An operator who restores from paper backup and (a) starts the daemon
via ``systemctl start messagechain-validator`` directly, (b) follows
older runbook habits and skips ``doctor``, or (c) runs ``messagechain
start --mine`` straight, bypasses the gate.  They sign at the
already-burned leaf; the on-chain watermark catches the equivocation
on the first observed conflict; full stake loss on a documented
operator workflow.

The fix lifts the same ``_check_leaf_index`` call into ``cmd_start``
right after entity resolution -- BEFORE the daemon can take its first
signing turn.  Level=2 (RED) exits non-zero with the operator
remediation message.  Level=1 (WARN / inconclusive) prints the
warning and continues.  Level=0 (GREEN) is silent.

Operators who have manually verified their cursor situation and need
to bypass the gate can pass ``--accept-leaf-reuse-risk`` -- mirrors
the pattern used by ``--yes-nat`` for the reachability probe.

Soft-fix; no consensus rule change, no fork.  The CLI surface adds
exactly one flag to ``start``.
"""

from __future__ import annotations

import argparse
import inspect
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from messagechain.runtime.onboarding import CheckResult


class TestStartParserHasAcceptFlag(unittest.TestCase):
    """``start`` must expose ``--accept-leaf-reuse-risk`` so operators
    who have manually verified the cursor situation can bypass the
    gate without editing source."""

    def test_start_parser_includes_accept_leaf_reuse_risk(self):
        from messagechain.cli import build_parser
        parser = build_parser()
        # Locate the `start` subparser and assert the flag is present.
        # build_parser returns the top-level parser; subparsers live
        # under the registered "command" action.
        for action in parser._subparsers._actions:  # type: ignore[union-attr]
            if isinstance(action, argparse._SubParsersAction):
                start = action.choices.get("start")
                self.assertIsNotNone(start, "`start` subcommand missing")
                opts = {
                    o for a in start._actions
                    for o in (a.option_strings or [])
                }
                self.assertIn(
                    "--accept-leaf-reuse-risk", opts,
                    "`start` must expose --accept-leaf-reuse-risk for "
                    "operators bypassing the leaf-index gate after "
                    "manual verification",
                )
                return
        self.fail("subparsers action not found on top-level parser")


class TestStartMineCallsLeafIndexCheck(unittest.TestCase):
    """``cmd_start`` must invoke ``_check_leaf_index`` from
    ``messagechain.runtime.onboarding`` after entity resolution.

    Defensive structural test -- a future regression that drops the
    call silently re-opens the disaster path.  Verified by source
    inspection rather than mocked execution because ``cmd_start`` has
    a deep async / network boot sequence we don't want to exercise
    in a unit test.
    """

    def test_cmd_start_source_calls_leaf_index_check(self):
        from messagechain import cli as _cli
        src = inspect.getsource(_cli.cmd_start)
        # The function must reference _check_leaf_index either as a
        # bare name (after a `from ... import _check_leaf_index`) or
        # as `<module>._check_leaf_index`.  We accept both shapes.
        self.assertIn(
            "_check_leaf_index", src,
            "cmd_start must call onboarding._check_leaf_index after "
            "entity resolution -- without it, an operator who skips "
            "`doctor` and runs `start --mine` straight loses their "
            "stake on the first sign post-paper-restore",
        )


class TestStartMineExitsRedOnLeafIndexFailure(unittest.TestCase):
    """When the leaf-index check returns level=2 (RED), ``cmd_start``
    must print the diagnostic and exit non-zero -- before reaching
    the async `_run` block where the daemon would take its first
    signing turn."""

    def test_red_exits_non_zero(self):
        from messagechain import cli as _cli

        # Build a minimal args namespace for cmd_start.  Everything
        # cmd_start touches before the leaf-index gate must be set.
        args = argparse.Namespace(
            mine=True,
            data_dir="/tmp/mc-test-r34-leaf-index",
            keyfile=None,
            seed=None,
            port=9333,
            rpc_port=9334,
            rpc_bind="127.0.0.1",
            wallet=None,
            skip_reachability_probe=True,
            yes_nat=True,
            accept_leaf_reuse_risk=False,
        )

        # Fake entity object -- only `entity_id` / `entity_id_hex` /
        # `public_key` and `keypair` are touched on the path under
        # test.
        fake_entity = mock.MagicMock()
        fake_entity.entity_id = b"\x11" * 32
        fake_entity.entity_id_hex = "11" * 32
        fake_entity.public_key = b"\x22" * 32
        fake_entity.keypair = mock.MagicMock()

        red = CheckResult(
            2, "leaf-index", "MISSING but chaindb has signs",
            "chain watermark=42 -- next sign WILL re-use a burned leaf "
            "(100% slash).  Restore the leaf-index file from backup.",
        )

        # Mock everything cmd_start touches BEFORE and AT the leaf-
        # index gate.  The call must SystemExit before any of the
        # post-gate machinery runs.
        with mock.patch(
            "messagechain.cli._resolve_private_key",
            return_value=b"\x00" * 32,
        ), mock.patch(
            "server.Server",
        ) as fake_server_cls, mock.patch(
            "server._load_or_create_entity",
            return_value=fake_entity,
        ), mock.patch(
            "messagechain.runtime.onboarding._check_leaf_index",
            return_value=red,
        ):
            fake_server = fake_server_cls.return_value
            fake_server.blockchain.get_wots_leaves_used.return_value = 0
            fake_server.blockchain.get_authority_key.return_value = None
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
                _cli.cmd_start(args)
            self.assertNotEqual(
                cm.exception.code, 0,
                "RED leaf-index check must exit non-zero",
            )
            output = buf.getvalue()
            self.assertIn("leaf-index", output.lower())


class TestStartMineAcceptFlagBypasses(unittest.TestCase):
    """When ``--accept-leaf-reuse-risk`` is set, RED is downgraded to
    a warning and ``cmd_start`` continues past the gate."""

    def test_accept_flag_bypasses_red_exit(self):
        from messagechain import cli as _cli

        args = argparse.Namespace(
            mine=True,
            data_dir="/tmp/mc-test-r34-leaf-index-bypass",
            keyfile=None,
            seed=None,
            port=9333,
            rpc_port=9334,
            rpc_bind="127.0.0.1",
            wallet=None,
            skip_reachability_probe=True,
            yes_nat=True,
            accept_leaf_reuse_risk=True,
        )

        fake_entity = mock.MagicMock()
        fake_entity.entity_id = b"\x11" * 32
        fake_entity.entity_id_hex = "11" * 32
        fake_entity.public_key = b"\x22" * 32
        fake_entity.keypair = mock.MagicMock()

        red = CheckResult(
            2, "leaf-index", "MISSING but chaindb has signs",
            "chain watermark=42",
        )

        # Stub asyncio.run so cmd_start doesn't enter the async loop;
        # we only need to verify it reaches the post-gate code.
        with mock.patch(
            "messagechain.cli._resolve_private_key",
            return_value=b"\x00" * 32,
        ), mock.patch(
            "server.Server",
        ) as fake_server_cls, mock.patch(
            "server._load_or_create_entity",
            return_value=fake_entity,
        ), mock.patch(
            "messagechain.runtime.onboarding._check_leaf_index",
            return_value=red,
        ), mock.patch(
            # Consume the coroutine so it does not leak as an
            # un-awaited RuntimeWarning when the test's stack tears
            # down the mocked daemon's _run() body.
            "asyncio.run",
            side_effect=lambda coro, *a, **kw: coro.close(),
        ):
            fake_server = fake_server_cls.return_value
            fake_server.blockchain.get_wots_leaves_used.return_value = 0
            fake_server.blockchain.get_authority_key.return_value = None
            buf = io.StringIO()
            try:
                with redirect_stdout(buf):
                    _cli.cmd_start(args)
            except SystemExit as e:
                # If we got SystemExit it must NOT be the RED-exit
                # code.  cmd_start's no-mine branch exits cleanly;
                # in --accept mode the RED gate is downgraded to a
                # printed warning, so we should not exit here.
                self.fail(
                    f"--accept-leaf-reuse-risk did not bypass the "
                    f"leaf-index gate (exit code {e.code})"
                )
            output = buf.getvalue()
            # The override should print a clear warning so the
            # operator's choice is visible in logs.
            self.assertTrue(
                "leaf-index" in output.lower()
                or "leaf reuse" in output.lower(),
                "Accept-flag path must still print the leaf-index "
                "warning so the operator's bypass is logged",
            )


class TestStartMineGreenIsSilent(unittest.TestCase):
    """Level 0 (GREEN) -- the leaf-index gate must NOT print noise on
    healthy boots.  Operators see the gate output only when there's
    something to act on."""

    def test_green_is_silent(self):
        from messagechain import cli as _cli

        args = argparse.Namespace(
            mine=True,
            data_dir="/tmp/mc-test-r34-leaf-index-green",
            keyfile=None,
            seed=None,
            port=9333,
            rpc_port=9334,
            rpc_bind="127.0.0.1",
            wallet=None,
            skip_reachability_probe=True,
            yes_nat=True,
            accept_leaf_reuse_risk=False,
        )

        fake_entity = mock.MagicMock()
        fake_entity.entity_id = b"\x11" * 32
        fake_entity.entity_id_hex = "11" * 32
        fake_entity.public_key = b"\x22" * 32
        fake_entity.keypair = mock.MagicMock()

        green = CheckResult(0, "leaf-index", "cursor + chain in sync")

        with mock.patch(
            "messagechain.cli._resolve_private_key",
            return_value=b"\x00" * 32,
        ), mock.patch(
            "server.Server",
        ) as fake_server_cls, mock.patch(
            "server._load_or_create_entity",
            return_value=fake_entity,
        ), mock.patch(
            "messagechain.runtime.onboarding._check_leaf_index",
            return_value=green,
        ), mock.patch(
            # Consume the coroutine so it does not leak as an
            # un-awaited RuntimeWarning when the test's stack tears
            # down the mocked daemon's _run() body.
            "asyncio.run",
            side_effect=lambda coro, *a, **kw: coro.close(),
        ):
            fake_server = fake_server_cls.return_value
            fake_server.blockchain.get_wots_leaves_used.return_value = 0
            fake_server.blockchain.get_authority_key.return_value = None
            buf = io.StringIO()
            try:
                with redirect_stdout(buf):
                    _cli.cmd_start(args)
            except SystemExit:
                pass
            output = buf.getvalue()
            self.assertNotIn(
                "WILL re-use", output,
                "GREEN leaf-index check must not print the RED "
                "diagnostic message",
            )


if __name__ == "__main__":
    unittest.main()
