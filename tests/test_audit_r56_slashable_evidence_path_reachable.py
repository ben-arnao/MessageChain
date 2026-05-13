"""Audit r56 #3 -- slashable-evidence escalation path reachable from the public surface.

The chain's HEADLINE differentiator is "suppression is slashable" --
a well-formed message paying the fee floor is permanent and can never
be deleted; any validator caught dropping it loses stake.  But the
chain provides that defense only through the escalation chain
``send -> receipt-bundle saved -> messagechain receipt <tx> ->
messagechain submit-evidence censorship --receipt <bundle>``.

Audit r56 surfaces three broken rungs in that chain:

  (a) ``cmd_send`` / ``cmd_transfer`` / ``cmd_react`` each print a
      submit-success footer with a different shape -- only cmd_send
      surfaces the share URL + permanence framing.  The receipt-bundle
      save logic is duplicated three times.  Future signing commands
      either copy the boilerplate (drift over time) or skip it (the
      r56 finding: 6+ commands ended with bare hex hashes).  The fix
      is one shared helper: ``_print_submit_success_footer``.

  (b) The web receipt page's NOT_FOUND branch tells visitors to "see
      the receipt CLI for slashable-evidence escalation" but does NOT
      print the actual ``messagechain submit-evidence ...`` command --
      while the CLI version DOES print it verbatim.  A user landing
      on a NOT_FOUND share-URL via a censorship suspicion has no
      copy-pasteable next step.

  (c) The README CLI reference omits both ``messagechain receipt
      <tx_hash>`` AND ``messagechain submit-evidence`` -- the middle
      and last rungs of the escalation chain.  A user who reads
      "suppression is slashable" in the README has no documented path
      from "I think my tx was suppressed" to "I filed slashable
      evidence."

CLAUDE.md anchor at risk: "Collective censorship-resistance" -- the
structural defense erodes from the operator-UX side even though the
consensus rule is correct.  All three rungs must be visible on the
public surface for the headline promise to be invokable.

Soft fixes -- no consensus rule change, no wire format, no fork.
"""

from __future__ import annotations

import io
import os
import pathlib
import re
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestPrintSubmitSuccessFooter(unittest.TestCase):
    """The new ``_print_submit_success_footer`` chokepoint absorbs the
    duplicated receipt-bundle save + share-URL + permanence-footer
    print pattern that cmd_send / cmd_transfer / cmd_react each
    inlined.  Future signing commands route through it by default."""

    def test_helper_exists_and_is_importable(self):
        from messagechain.cli import _print_submit_success_footer  # noqa: F401

    def test_helper_saves_receipt_when_present(self, tmp_dir=None):
        from messagechain.cli import _print_submit_success_footer

        tx_hash_hex = "ab" * 32
        receipt_hex = "11" * 32  # arbitrary placeholder bytes
        # Use a stub tx with the minimal shape _save_receipt_bundle
        # consumes: a serialize() method returning bytes.
        class _StubTx:
            def __init__(self):
                self.tx_hash = bytes.fromhex(tx_hash_hex)
            def serialize(self):
                # _save_receipt_bundle json-dumps this dict; mirror the
                # real Transaction.serialize() shape (dict) not bytes.
                return {"stub": True}
        # Override the receipts dir to a tmp location so the test
        # doesn't pollute ~/.messagechain.
        import tempfile
        tmp_dir = tempfile.mkdtemp(prefix="r56-receipts-")
        try:
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                _print_submit_success_footer(
                    tx_hash_hex=tx_hash_hex,
                    kind="message",
                    fee=1,
                    receipt_hex=receipt_hex,
                    tx=_StubTx(),
                    share_url=True,
                    receipts_dir=tmp_dir,
                )
            finally:
                sys.stdout = old_stdout
            out = buf.getvalue()
            # The bundle was saved on disk.
            bundle_path = os.path.join(tmp_dir, f"{tx_hash_hex}.json")
            self.assertTrue(
                os.path.exists(bundle_path),
                "receipt bundle was not written",
            )
            # The success footer mentions the bundle path.
            self.assertIn(tmp_dir, out)
            # Permanence framing is present.
            self.assertIn("Permanence", out)
            # Verify CLI is named.
            self.assertIn(f"messagechain receipt {tx_hash_hex}", out)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_helper_skips_save_when_no_receipt(self):
        from messagechain.cli import _print_submit_success_footer

        import tempfile
        tmp_dir = tempfile.mkdtemp(prefix="r56-receipts-")
        try:
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                _print_submit_success_footer(
                    tx_hash_hex="cc" * 32,
                    kind="message",
                    fee=1,
                    receipt_hex=None,
                    tx=None,
                    share_url=False,
                    receipts_dir=tmp_dir,
                )
            finally:
                sys.stdout = old_stdout
            # Directory should be empty -- nothing saved.
            self.assertEqual(os.listdir(tmp_dir), [])
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_helper_includes_share_url_only_for_message_kind(self):
        from messagechain.cli import _print_submit_success_footer

        import tempfile
        tmp_dir = tempfile.mkdtemp(prefix="r56-receipts-")
        try:
            tx_hash_hex = "dd" * 32
            # Message kind WITH share_url=True -> share URL printed.
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                _print_submit_success_footer(
                    tx_hash_hex=tx_hash_hex, kind="message", fee=1,
                    receipt_hex=None, tx=None,
                    share_url=True, receipts_dir=tmp_dir,
                )
            finally:
                sys.stdout = old_stdout
            out = buf.getvalue()
            self.assertIn(f"/r/{tx_hash_hex}", out)
            # Non-message kind defaults to no share URL.
            buf = io.StringIO()
            sys.stdout = buf
            try:
                _print_submit_success_footer(
                    tx_hash_hex=tx_hash_hex, kind="transfer", fee=1,
                    receipt_hex=None, tx=None,
                    share_url=False, receipts_dir=tmp_dir,
                )
            finally:
                sys.stdout = old_stdout
            out = buf.getvalue()
            self.assertNotIn(f"/r/{tx_hash_hex}", out)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestCmdSendCmdTransferCmdReactRouteThroughHelper(unittest.TestCase):
    """Structural pin: cmd_send / cmd_transfer / cmd_react each call
    ``_print_submit_success_footer`` instead of inlining the receipt-
    bundle save + permanence-footer print pattern.  Future signing
    commands inherit the property by routing through the helper."""

    def test_each_cmd_calls_helper(self):
        import inspect
        from messagechain import cli
        for fn_name in ("cmd_send", "cmd_transfer", "cmd_react"):
            fn = getattr(cli, fn_name)
            src = inspect.getsource(fn)
            self.assertIn(
                "_print_submit_success_footer",
                src,
                f"{fn_name} must route through the shared submit-success "
                f"footer helper -- the receipt-bundle save + permanence "
                f"footer print pattern is the slashable-evidence "
                f"escalation chain's first rung, and inlining it three "
                f"different ways is exactly the drift the r56 audit "
                f"finding called out.",
            )


class TestReceiptPageNotFoundPrintsCommand(unittest.TestCase):
    """The web receipt page's NOT_FOUND branch must surface the
    canonical ``messagechain submit-evidence censorship --receipt
    <path>`` command, mirroring the CLI's NOT_FOUND text.  A user who
    lands on a NOT_FOUND share-URL under censorship suspicion otherwise
    has no copy-pasteable next step."""

    def test_receipt_html_not_found_branch_names_the_command(self):
        path = REPO_ROOT / "messagechain" / "static" / "receipt.html"
        text = path.read_text(encoding="utf-8")
        # Must contain the literal CLI surface so a paste-into-terminal
        # works without translation.  The path placeholder varies but
        # the command name + flag must be present in the NOT_FOUND
        # narrative.
        self.assertIn("submit-evidence censorship", text)
        self.assertIn("--receipt", text)
        # And the receipt-CLI verifier (the middle rung) must be named
        # too, since the user typically wants to cross-check before
        # filing slashable evidence.
        self.assertIn("messagechain receipt", text)


class TestReadmeNamesEscalationCommands(unittest.TestCase):
    """README CLI reference must include both rungs of the slashable-
    evidence escalation chain.  Without them a user reading the
    headline promise ("suppression is slashable") has no documented
    path to invoke it."""

    def test_readme_cli_reference_includes_receipt_and_submit_evidence(self):
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r"messagechain receipt\b",
            "README CLI reference must name `messagechain receipt "
            "<tx_hash>` -- the middle rung of the slashable-evidence "
            "escalation chain.  Without it, a user who suspects "
            "suppression has no way to discover the verifier surface.",
        )
        self.assertRegex(
            text,
            r"messagechain submit-evidence\b",
            "README CLI reference must name `messagechain submit-"
            "evidence` -- the slashable-evidence pipeline's user "
            "entry point.  The whole 'collective censorship "
            "resistance' anchor is invokable only through this path.",
        )


if __name__ == "__main__":
    unittest.main()
