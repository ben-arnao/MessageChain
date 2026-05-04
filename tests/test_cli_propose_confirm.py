"""Confirm prompt + fee preview for governance CLI commands.

`messagechain propose` charges the largest single fee in the protocol
(GOVERNANCE_PROPOSAL_FEE = 10,000 tokens — ~33 faucet drips).  A typo
on the title or description is an irreversible burn with no recovery
path.  Pre-existing CLI auto-fee + auto-submit one-shot left no UX
room to catch the mistake.

This test file pins:
  * `propose` prints a fee preview AND requires interactive confirm
    ("type 'yes' to proceed"), honors `--yes` for scripts.
  * `vote` prints a fee preview but does NOT prompt (over-friction at
    the smaller GOVERNANCE_VOTE_FEE level).
  * `react` prints a fee preview but does NOT prompt (smaller fee).

Mirrors the pattern shipped in cmd_transfer (1.48.0).
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


_TEST_PRIVKEY = bytes(range(32))


def _propose_args(**overrides):
    base = dict(
        title="My proposal title",
        description="A detailed description of the proposal body.",
        fee=None,
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
        urgency="normal",
        yes=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _vote_args(**overrides):
    base = dict(
        proposal="ab" * 32,
        yes=True,    # vote YES (existing semantics on the vote subcmd)
        no=False,
        fee=None,
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
        urgency="normal",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _react_args(**overrides):
    base = dict(
        target="cd" * 32,
        choice="up",
        target_type="message",
        fee=None,
        server="127.0.0.1:9334",
        keyfile="/dev/null",
        data_dir=None,
        urgency="normal",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _make_entity():
    entity = MagicMock()
    entity.entity_id = b"\x01" * 32
    entity.entity_id_hex = "01" * 32
    entity.keypair = MagicMock()
    return entity


def _stub_rpc(extra=None):
    """Return (rpc_side, captured) where captured records all calls."""
    captured = []
    extras = extra or {}

    def rpc_side(host, port, method, params=None):
        captured.append((method, params))
        if method in extras:
            return extras[method]
        if method == "get_nonce":
            return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
        if method == "get_chain_info":
            return {"ok": True, "result": {"height": 1}}
        if method == "estimate_fee":
            return {"ok": True, "result": {"mempool_fee": 0}}
        if method == "submit_proposal":
            return {
                "ok": True,
                "result": {
                    "proposal_id": "ee" * 32,
                    "fee": 10_000,
                    "tx_hash": "ff" * 32,
                },
            }
        if method == "submit_vote":
            return {"ok": True, "result": {"tx_hash": "00" * 32}}
        if method == "submit_react":
            return {
                "ok": True,
                "result": {"tx_hash": "ab" * 32, "fee": 1},
            }
        return {"ok": True, "result": {}}

    return rpc_side, captured


def _drive_propose(args, *, stdin_text=None, extra_rpc=None):
    """Run cmd_propose with all RPCs + signing stubbed.

    Returns dict with stdout, exit_code, captured rpc methods, and
    whether create_proposal was called.
    """
    from messagechain import cli as cli_mod

    rpc_side, captured = _stub_rpc(extra_rpc)
    entity = _make_entity()

    fake_tx = MagicMock()
    fake_tx.serialize.return_value = {"type": "proposal"}
    create_called = []

    def fake_create_proposal(entity, title, description, fee, current_height=None):
        create_called.append({"fee": fee, "title": title})
        return fake_tx

    patches = [
        patch.object(cli_mod, "_resolve_private_key", return_value=_TEST_PRIVKEY),
        patch.object(cli_mod, "_resolve_signing_entity", return_value=entity),
        patch.object(cli_mod, "_parse_server", return_value=("127.0.0.1", 9334)),
        patch.object(cli_mod, "_bind_persistent_leaf_index"),
        patch("messagechain.governance.governance.create_proposal",
              side_effect=fake_create_proposal),
        patch("client.rpc_call", side_effect=rpc_side),
    ]

    if stdin_text is None:
        # No stdin -> input() raises EOFError under the simulated pipe.
        patches.append(
            patch("builtins.input", side_effect=EOFError("no stdin"))
        )
    else:
        # The .strip().lower() on the CLI side normalizes whitespace.
        patches.append(
            patch("builtins.input", return_value=stdin_text)
        )

    exit_code = None
    buf = io.StringIO()
    try:
        for p in patches:
            p.start()
        try:
            with redirect_stdout(buf):
                cli_mod.cmd_propose(args)
        finally:
            for p in reversed(patches):
                p.stop()
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0
    except EOFError:
        # If the prompt is missing (regression), input() will raise
        # straight through here; surface as a sentinel.
        exit_code = "EOF-leaked"

    return {
        "stdout": buf.getvalue(),
        "exit_code": exit_code,
        "rpc_methods": [m for (m, _p) in captured],
        "create_called": bool(create_called),
        "create_calls": create_called,
    }


def _drive_vote(args, *, extra_rpc=None):
    from messagechain import cli as cli_mod

    rpc_side, captured = _stub_rpc(extra_rpc)
    entity = _make_entity()

    fake_tx = MagicMock()
    fake_tx.serialize.return_value = {"type": "vote"}

    patches = [
        patch.object(cli_mod, "_resolve_private_key", return_value=_TEST_PRIVKEY),
        patch.object(cli_mod, "_resolve_signing_entity", return_value=entity),
        patch.object(cli_mod, "_parse_server", return_value=("127.0.0.1", 9334)),
        patch.object(cli_mod, "_bind_persistent_leaf_index"),
        patch("messagechain.governance.governance.create_vote",
              return_value=fake_tx),
        patch("client.rpc_call", side_effect=rpc_side),
        # Vote should not prompt; if it does, blow up loudly.
        patch("builtins.input",
              side_effect=AssertionError("vote should not prompt")),
    ]

    exit_code = None
    buf = io.StringIO()
    try:
        for p in patches:
            p.start()
        try:
            with redirect_stdout(buf):
                cli_mod.cmd_vote(args)
        finally:
            for p in reversed(patches):
                p.stop()
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0

    return {
        "stdout": buf.getvalue(),
        "exit_code": exit_code,
        "rpc_methods": [m for (m, _p) in captured],
    }


def _drive_react(args, *, extra_rpc=None):
    from messagechain import cli as cli_mod

    rpc_side, captured = _stub_rpc(extra_rpc)
    entity = _make_entity()

    fake_tx = MagicMock()
    fake_tx.serialize.return_value = {"type": "react"}

    patches = [
        patch.object(cli_mod, "_resolve_private_key", return_value=_TEST_PRIVKEY),
        patch.object(cli_mod, "_resolve_signing_entity", return_value=entity),
        patch.object(cli_mod, "_parse_server", return_value=("127.0.0.1", 9334)),
        patch.object(cli_mod, "_bind_persistent_leaf_index"),
        patch("messagechain.core.reaction.create_react_transaction",
              return_value=fake_tx),
        patch("client.rpc_call", side_effect=rpc_side),
        # React should not prompt; if it does, blow up loudly.
        patch("builtins.input",
              side_effect=AssertionError("react should not prompt")),
    ]

    exit_code = None
    buf = io.StringIO()
    try:
        for p in patches:
            p.start()
        try:
            with redirect_stdout(buf):
                cli_mod.cmd_react(args)
        finally:
            for p in reversed(patches):
                p.stop()
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0

    return {
        "stdout": buf.getvalue(),
        "exit_code": exit_code,
        "rpc_methods": [m for (m, _p) in captured],
    }


class TestProposeConfirmPrompt(unittest.TestCase):
    """propose without --yes requires interactive 'yes' confirmation."""

    def test_propose_without_yes_aborts_on_eof(self):
        """No stdin (EOF on input()) → abort with non-zero exit, no submit."""
        args = _propose_args(yes=False)
        r = _drive_propose(args, stdin_text=None)
        self.assertNotEqual(
            r["exit_code"], 0,
            f"expected non-zero exit on EOF; got {r['exit_code']!r}\n"
            f"stdout=\n{r['stdout']}"
        )
        self.assertNotEqual(
            r["exit_code"], "EOF-leaked",
            "EOFError leaked through cmd_propose -- the prompt is "
            "missing and input() ran without a try/except wrapper.",
        )
        self.assertNotIn("submit_proposal", r["rpc_methods"])
        self.assertFalse(
            r["create_called"],
            "create_proposal must NOT be called when confirmation is denied.",
        )

    def test_propose_without_yes_aborts_on_no(self):
        """Typing 'no' aborts with non-zero exit, no submit."""
        args = _propose_args(yes=False)
        r = _drive_propose(args, stdin_text="no")
        # Cancellation can either exit(0) with a clear cancel message or
        # exit non-zero -- both are acceptable as long as nothing was
        # submitted.  cmd_transfer's pattern uses exit(0) + a printed
        # cancel banner; we follow it here.
        self.assertNotIn("submit_proposal", r["rpc_methods"])
        self.assertFalse(
            r["create_called"],
            "create_proposal must NOT be called when user types 'no'.",
        )
        self.assertIn("cancel", r["stdout"].lower())

    def test_propose_with_yes_submits(self):
        """--yes skips the prompt and submits the proposal."""
        args = _propose_args(yes=True)
        r = _drive_propose(args, stdin_text=None)
        self.assertIn(
            "submit_proposal", r["rpc_methods"],
            f"expected submit_proposal RPC; got methods={r['rpc_methods']}\n"
            f"stdout=\n{r['stdout']}",
        )
        self.assertTrue(
            r["create_called"],
            "create_proposal must be called under --yes.",
        )

    def test_propose_with_typed_yes_submits(self):
        """Typing literal 'yes' at the prompt submits the proposal."""
        args = _propose_args(yes=False)
        r = _drive_propose(args, stdin_text="yes")
        self.assertIn("submit_proposal", r["rpc_methods"])
        self.assertTrue(r["create_called"])


class TestProposeFeePreview(unittest.TestCase):
    """propose prints the fee BEFORE asking to confirm or submitting."""

    def test_propose_fee_preview_visible(self):
        args = _propose_args(yes=True)  # --yes still prints preview
        r = _drive_propose(args, stdin_text=None)
        out = r["stdout"]
        self.assertIn("Fee:", out, f"no 'Fee:' line in stdout:\n{out}")
        # The figure should be human-readable: '10,000' (with thousands
        # separator) is what the spec calls for.
        self.assertTrue(
            "10,000" in out or "10000" in out,
            f"expected the proposal fee number in stdout; got:\n{out}",
        )

    def test_propose_fee_preview_before_submit(self):
        """The fee line must appear in stdout BEFORE any submit attempt.

        Implementation note: the fee preview should run as part of the
        confirmation banner, before the submit_proposal RPC is called.
        Easiest way to verify this: pipe 'no' so we abort BEFORE submit,
        and assert the fee line still printed.
        """
        args = _propose_args(yes=False)
        r = _drive_propose(args, stdin_text="no")
        self.assertIn("Fee:", r["stdout"])
        self.assertNotIn("submit_proposal", r["rpc_methods"])


class TestVoteFeePreview(unittest.TestCase):
    """vote prints fee preview but does NOT prompt."""

    def test_vote_fee_preview_visible(self):
        args = _vote_args()
        r = _drive_vote(args)
        self.assertEqual(
            r["exit_code"], None,
            f"vote should run cleanly without exit; got "
            f"exit={r['exit_code']!r}\nstdout=\n{r['stdout']}",
        )
        self.assertIn("Fee:", r["stdout"])
        self.assertIn("submit_vote", r["rpc_methods"])


class TestReactFeePreview(unittest.TestCase):
    """react prints fee preview but does NOT prompt."""

    def test_react_fee_preview_visible(self):
        args = _react_args()
        r = _drive_react(args)
        self.assertEqual(
            r["exit_code"], None,
            f"react should run cleanly without exit; got "
            f"exit={r['exit_code']!r}\nstdout=\n{r['stdout']}",
        )
        out = r["stdout"]
        # The "Fee:" line must show BEFORE the submit-result echo, but
        # since react also prints "Fee:" in the success banner today,
        # check that there are TWO 'Fee:' occurrences (preview + result)
        # OR the preview line appears with "tokens" and a "(reaction
        # fee)" qualifier.
        self.assertIn("Fee:", out)
        self.assertIn("submit_react", r["rpc_methods"])

    def test_react_fee_preview_before_submit(self):
        """Fee preview line must print BEFORE the RPC call that submits."""
        # Capture the order of stdout vs RPC calls by intercepting the
        # rpc submit_react and asserting the buffer already contains
        # 'Fee:' at that moment.
        from messagechain import cli as cli_mod

        captured_at_submit = {"stdout_snapshot": None}
        rpc_side, _captured = _stub_rpc()

        buf = io.StringIO()

        def rpc_with_snapshot(host, port, method, params=None):
            if method == "submit_react":
                captured_at_submit["stdout_snapshot"] = buf.getvalue()
            return rpc_side(host, port, method, params)

        entity = _make_entity()
        fake_tx = MagicMock()
        fake_tx.serialize.return_value = {"type": "react"}

        args = _react_args()
        with patch.object(cli_mod, "_resolve_private_key",
                          return_value=_TEST_PRIVKEY), \
             patch.object(cli_mod, "_resolve_signing_entity",
                          return_value=entity), \
             patch.object(cli_mod, "_parse_server",
                          return_value=("127.0.0.1", 9334)), \
             patch.object(cli_mod, "_bind_persistent_leaf_index"), \
             patch("messagechain.core.reaction.create_react_transaction",
                   return_value=fake_tx), \
             patch("client.rpc_call", side_effect=rpc_with_snapshot), \
             patch("builtins.input",
                   side_effect=AssertionError("react should not prompt")):
            with redirect_stdout(buf):
                cli_mod.cmd_react(args)

        snap = captured_at_submit["stdout_snapshot"]
        self.assertIsNotNone(
            snap,
            "submit_react was never called -- can't measure print order.",
        )
        self.assertIn(
            "Fee:", snap,
            "Fee: line must print BEFORE submit_react RPC.\n"
            f"stdout-at-submit:\n{snap}",
        )


class TestParserAcceptsProposeYes(unittest.TestCase):
    """The argparse layer accepts --yes and -y on `propose`."""

    def setUp(self):
        from messagechain import cli as cli_mod
        self.parser = cli_mod.build_parser()

    def test_propose_yes_long(self):
        args = self.parser.parse_args([
            "propose",
            "--title", "T",
            "--description", "D",
            "--yes",
        ])
        self.assertTrue(getattr(args, "yes", False))

    def test_propose_yes_short(self):
        args = self.parser.parse_args([
            "propose",
            "--title", "T",
            "--description", "D",
            "-y",
        ])
        self.assertTrue(getattr(args, "yes", False))

    def test_propose_default_no_yes(self):
        args = self.parser.parse_args([
            "propose",
            "--title", "T",
            "--description", "D",
        ])
        self.assertFalse(getattr(args, "yes", False))


if __name__ == "__main__":
    unittest.main()
