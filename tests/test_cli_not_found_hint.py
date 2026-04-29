"""The receipt-CLI's NOT_FOUND escalation hint must point at the LIVE
submit-evidence form, not the deprecated `--tx <hash>` stub.

Pre-fix the hint printed:

    messagechain submit-evidence --tx <tx_hash>

which the actual submit-evidence subcommand rejects as a deprecated
legacy invocation.  The user clicked through the funnel and hit a
dead end at the very command the chain just told them to run.

Post-fix the hint must point at the working form:

    messagechain submit-evidence censorship --receipt <bundle.json>

with the canonical bundle path under ~/.messagechain/receipts/<tx_hash>.json
since that's exactly what cmd_send now writes on success.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout


_FAKE_TX_HASH = "deadbeefcafef00d" + "0" * 48


class TestNotFoundHintPointsAtLiveEscalationForm(unittest.TestCase):
    """The NOT_FOUND printout drives users into the slashing pipeline.
    If the printed command doesn't actually run, the entire censorship
    defense funnel is dead at the user-facing tip.
    """

    def test_not_found_hint_uses_censorship_subcommand(self):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod._print_not_found_receipt(_FAKE_TX_HASH)
        out = buf.getvalue()

        # Live, working form must be present.
        self.assertIn("submit-evidence censorship", out,
            "NOT_FOUND hint must use the live `submit-evidence "
            "censorship` subcommand, not the deprecated `--tx` stub")
        self.assertIn("--receipt", out,
            "NOT_FOUND hint must name the --receipt <bundle.json> flag "
            "the live subcommand actually accepts")

    def test_not_found_hint_does_not_print_deprecated_tx_form(self):
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod._print_not_found_receipt(_FAKE_TX_HASH)
        out = buf.getvalue()

        # The literal deprecated string must NOT appear -- otherwise
        # users keep hitting the migration-error wall.
        self.assertNotIn(
            f"submit-evidence --tx {_FAKE_TX_HASH}",
            out,
            "NOT_FOUND hint must NOT print the deprecated "
            "`submit-evidence --tx <hash>` form -- that command is "
            "now a migration stub that refuses to submit anything",
        )

    def test_not_found_hint_points_at_canonical_bundle_path(self):
        """The hint should name the exact file cmd_send writes, so the
        user can paste the path verbatim without translation.
        """
        from messagechain import cli as cli_mod

        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod._print_not_found_receipt(_FAKE_TX_HASH)
        out = buf.getvalue()

        # Canonical default location used by cmd_send's bundle writer.
        # The path may render with either separator depending on
        # platform; check the substring under a normalized form.
        normalized = out.replace("\\", "/")
        self.assertIn(".messagechain/receipts/", normalized,
            "NOT_FOUND hint should name the canonical receipts dir "
            "(~/.messagechain/receipts/) where cmd_send saves bundles")
        self.assertIn(f"{_FAKE_TX_HASH}.json", out,
            "NOT_FOUND hint should reference the per-tx-hash bundle "
            "filename so the user can copy-paste the path")


if __name__ == "__main__":
    unittest.main()
