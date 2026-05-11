"""Audit r46 #3 — cmd_send_multi_submit must reuse cmd_send's signing-
pipeline abstractions.

Three coupled defects, all rooted in one missing abstraction: the
shared signing-pipeline ``cmd_send`` evolved (mnemonic / checksummed-
hex keyfile handling via ``_resolve_private_key``; first-spend
``include_pubkey`` probe via ``get_entity`` RPC) but
``cmd_send_multi_submit`` never adopted it.

  (a) Keyfile load is ``bytes.fromhex(hex_key)`` — rejects 24-word
      BIP-39 mnemonics and 72-char checksummed-hex, the only forms
      README's ``generate-key`` produces.  A dissident under pressure
      who pastes their recovery phrase or checksummed backup gets
      "keyfile must contain a 64-char hex private key" and falls
      back to ``cmd_send`` (the single-RPC submission path the
      censorship-resistance escape hatch exists to AVOID).

  (b) Skips the ``_should_include_pubkey`` probe — a fresh-key
      first-spend through ``send-multi`` lands as a tx without
      ``sender_pubkey``, and every endpoint rejects with "Unknown
      entity — must register first."  The most likely use case for
      ``send-multi`` (a fresh-key dissident's first controversial
      post) is silently broken, and the failure looks like
      validator-collusion censorship rather than missing pubkey-
      install.

  (c) ``--keyfile`` isn't listed in ``send-multi --help`` and isn't
      shown in the README example, so first-time users hit "--keyfile
      is required and must exist for multi-submit" with no guidance
      that they need to attach the GLOBAL --keyfile flag.

CLAUDE.md adversary at risk: validator collusion (#1 — primary).  The
chain's structural defense against its primary threat — ``send-multi``
as the user-side tool for the slashable-suppression rule — is
invisibly broken at the exact moment dissidents need it.

Abstraction fix: extract ``_should_include_pubkey(host, port, entity,
target_height)`` from ``cmd_send`` into a shared helper; route
``cmd_send_multi_submit`` through ``_resolve_private_key`` (the
existing helper used by 27 other signing commands).  Update the
send-multi parser description and the README example to surface
``--keyfile``.

After this fix the signing pipeline is unified: any future signing
command can adopt the same abstractions without rebuilding the
keyfile / pubkey-install logic, and ``cmd_send_multi_submit`` can't
silently drift back into hand-rolled keyfile handling.
"""

from __future__ import annotations

import unittest


class TestSendMultiKeyfileResolutionRoutesThroughHelper(unittest.TestCase):
    """(a) ``cmd_send_multi_submit`` must use ``_resolve_private_key``
    instead of hand-rolling ``bytes.fromhex(hex_key)``."""

    def _read_send_multi_source(self) -> str:
        import inspect
        from messagechain.cli import cmd_send_multi_submit
        return inspect.getsource(cmd_send_multi_submit)

    def test_cmd_send_multi_routes_through_resolve_private_key(self):
        """The hand-rolled keyfile block is replaced with a call to
        the shared ``_resolve_private_key`` helper."""
        src = self._read_send_multi_source()
        self.assertIn(
            "_resolve_private_key", src,
            "cmd_send_multi_submit must call _resolve_private_key to "
            "support every keyfile format (mnemonic / checksummed / "
            "raw hex) -- not just bare 64-char hex.",
        )

    def test_cmd_send_multi_no_longer_hand_rolls_bytes_fromhex(self):
        """The buggy ``bytes.fromhex(hex_key)`` pattern that rejected
        mnemonics and checksummed-hex must be gone from the body."""
        src = self._read_send_multi_source()
        self.assertNotIn(
            "bytes.fromhex(hex_key)", src,
            "cmd_send_multi_submit must NOT hand-roll keyfile parsing "
            "via bytes.fromhex -- the 64-char-hex-only constraint "
            "broke the README-recommended mnemonic / checksummed-hex "
            "formats.",
        )

    def test_cmd_send_multi_personal_wallet_gate(self):
        """``send-multi`` is a personal-wallet command (just like
        ``send``).  Must pass ``personal_wallet=True`` to
        ``_resolve_private_key`` so ``sudo messagechain send-multi``
        on a validator host doesn't auto-sign with the validator's
        identity (a fund-loss / identity-attribution footgun)."""
        src = self._read_send_multi_source()
        self.assertIn(
            "personal_wallet=True", src,
            "send-multi must use the same personal-wallet hard-gate "
            "cmd_send uses, so the validator hot-key isn't auto-picked.",
        )


class TestShouldIncludePubkeyHelper(unittest.TestCase):
    """(b) The first-spend pubkey-install probe is extracted into a
    shared helper, and both ``cmd_send`` and ``cmd_send_multi_submit``
    use it."""

    def test_helper_exists(self):
        """``_should_include_pubkey`` exists in ``messagechain.cli`` as
        the single chokepoint for the first-spend pubkey-install
        decision."""
        from messagechain import cli
        self.assertTrue(
            hasattr(cli, "_should_include_pubkey"),
            "cli._should_include_pubkey must exist as the shared "
            "helper for the first-spend pubkey-install probe.",
        )

    def test_helper_returns_false_pre_fork(self):
        """Pre-FIRST_SEND_PUBKEY_HEIGHT, v3 txs (with sender_pubkey)
        are rejected; the helper must return False so callers stay on
        v1/v2."""
        from messagechain import cli, config
        result = cli._should_include_pubkey(
            host="127.0.0.1", port=9334,
            entity_id_hex="0" * 64,
            target_height=config.FIRST_SEND_PUBKEY_HEIGHT - 1,
        )
        self.assertFalse(
            result,
            "Pre-fork the helper must return False unconditionally.",
        )

    def test_helper_returns_true_when_pubkey_not_registered(self):
        """Post-fork, if get_entity reports pubkey_registered=False
        (typical for a freshly-received-funds wallet), the helper
        must return True."""
        from messagechain import cli, config
        captured_rpc_args = []

        def fake_rpc(host, port, method, params):
            captured_rpc_args.append((method, params))
            return {
                "ok": True,
                "result": {"pubkey_registered": False},
            }

        # Patch rpc_call indirectly via the cli module's importer path.
        import client as _client
        orig = _client.rpc_call
        _client.rpc_call = fake_rpc
        try:
            result = cli._should_include_pubkey(
                host="127.0.0.1", port=9334,
                entity_id_hex="0" * 64,
                target_height=config.FIRST_SEND_PUBKEY_HEIGHT + 1,
            )
        finally:
            _client.rpc_call = orig
        self.assertTrue(
            result,
            "Helper must return True when chain reports pubkey not yet "
            "registered (first-spend case).",
        )
        self.assertEqual(
            captured_rpc_args[0][0], "get_entity",
            "Helper must probe via get_entity RPC.",
        )

    def test_helper_returns_false_when_pubkey_registered(self):
        """Post-fork, if get_entity reports pubkey already on chain,
        the helper must return False so subsequent sends stay on
        v1/v2."""
        from messagechain import cli, config

        def fake_rpc(host, port, method, params):
            return {
                "ok": True,
                "result": {"pubkey_registered": True},
            }

        import client as _client
        orig = _client.rpc_call
        _client.rpc_call = fake_rpc
        try:
            result = cli._should_include_pubkey(
                host="127.0.0.1", port=9334,
                entity_id_hex="0" * 64,
                target_height=config.FIRST_SEND_PUBKEY_HEIGHT + 1,
            )
        finally:
            _client.rpc_call = orig
        self.assertFalse(result)

    def test_cmd_send_uses_helper(self):
        """``cmd_send`` source must route through ``_should_include_
        pubkey`` -- the abstraction enforces that both call sites
        agree on the probe semantics."""
        import inspect
        from messagechain.cli import cmd_send
        src = inspect.getsource(cmd_send)
        self.assertIn(
            "_should_include_pubkey", src,
            "cmd_send must use _should_include_pubkey, not the inline "
            "probe -- otherwise send-multi will silently drift from "
            "the canonical first-spend behaviour.",
        )

    def test_cmd_send_multi_uses_helper(self):
        """``cmd_send_multi_submit`` source must also route through
        ``_should_include_pubkey`` and pass ``include_pubkey`` to
        ``create_transaction``."""
        import inspect
        from messagechain.cli import cmd_send_multi_submit
        src = inspect.getsource(cmd_send_multi_submit)
        self.assertIn(
            "_should_include_pubkey", src,
            "cmd_send_multi_submit must use _should_include_pubkey to "
            "support first-spend through the censorship-resistance "
            "fan-out path.",
        )
        self.assertIn(
            "include_pubkey=", src,
            "cmd_send_multi_submit must pass include_pubkey= to "
            "create_transaction so first-spend lands as v3.",
        )


class TestSendMultiParserAndReadmeSurface(unittest.TestCase):
    """(c) Discoverability: ``send-multi --help`` and the README
    example must surface ``--keyfile``."""

    def test_parser_description_mentions_keyfile(self):
        """The send-multi parser description must mention --keyfile
        so users running ``send-multi --help`` see the requirement
        without having to read the top-level parser docs."""
        import argparse
        from messagechain.cli import build_parser
        parser = build_parser()
        # Walk subparsers to find send-multi.
        subparser_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                subparser_action = action
                break
        self.assertIsNotNone(subparser_action)
        send_multi_parser = subparser_action.choices.get("send-multi")
        self.assertIsNotNone(send_multi_parser)
        desc = send_multi_parser.description or ""
        self.assertIn(
            "--keyfile", desc,
            "send-multi parser description must mention --keyfile so "
            "`send-multi --help` surfaces the requirement.",
        )

    def test_readme_send_multi_example_includes_keyfile(self):
        """Every README ``send-multi`` example block must show --keyfile
        so users following the example don't hit the 'keyfile required'
        error on their first attempt.  Checks every code-fence block
        that uses ``send-multi`` — both the worked example and the CLI
        reference table — to enforce consistency."""
        import os
        import re
        readme_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "README.md",
        )
        with open(readme_path, "r", encoding="utf-8") as f:
            readme = f.read()
        # Find every line that invokes `messagechain ... send-multi`.
        # Each one must show --keyfile on the same line so a user
        # copy-pasting any example sees the requirement.
        pattern = re.compile(r"^.*messagechain\s+.*\bsend-multi\b.*$",
                             re.MULTILINE)
        invocations = pattern.findall(readme)
        self.assertGreater(
            len(invocations), 0,
            "README must contain at least one send-multi example",
        )
        for line in invocations:
            self.assertIn(
                "--keyfile", line,
                f"send-multi example must include --keyfile: {line!r}",
            )


if __name__ == "__main__":
    unittest.main()
