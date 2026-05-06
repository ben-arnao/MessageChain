"""``_print_pending_receipt`` must name the LIVE submit-evidence form.

Surfaced by audit r24 top-3 #3.  The PENDING-receipt branch of
``messagechain receipt <tx_hash>`` printed the deprecated
``messagechain submit-evidence --tx {tx_hash}`` form -- a stub that
prints a "use ``submit-evidence censorship --receipt
<bundle.json>`` instead" diagnostic and exits 0 without filing
anything on chain.  Every user hitting the exact moment censorship
anxiety peaks (queued tx, suspected validator collusion) was handed
a copy-paste command that pretended to succeed and never actually
filed evidence -- silently hollowing out the chain's headline
censorship-resistance differentiator.

The NOT_FOUND branch was migrated to the live form
(``submit-evidence censorship --receipt {bundle_path}``) in audit
r7 (cli.py:5996-6008).  PENDING was missed.

Fix mirrors the r7 NOT_FOUND fix exactly: the same bundle-path
construction (``_default_receipts_dir() + tx_hash + .json``) and
the same live-form invocation, so a user who copy-pastes the
suggestion lands at the canonical evidence path
``cmd_send`` writes on submit.

Anchored in CLAUDE.md "Censorship resistance is a *collective
decision* ... slashable evidence" -- the on-chain evidence path
must actually be reachable from the receipt UX.
"""

import io
import os
import unittest
from unittest import mock

from messagechain import cli


class _StubInfo:
    """Minimal rpc_call stub returning a fixed get_chain_info response."""

    def __init__(self, seconds_since_last_block: int = 30):
        self._ssl = seconds_since_last_block

    def __call__(self, host, port, method, params):
        if method == "get_chain_info":
            return {
                "ok": True,
                "result": {"seconds_since_last_block": self._ssl},
            }
        return {"ok": False, "error": "unexpected rpc"}


class TestPendingReceiptLiveForm(unittest.TestCase):
    """The PENDING-receipt printout MUST direct the user to the live
    ``submit-evidence censorship --receipt <bundle.json>`` form, not
    the deprecated ``--tx <hash>`` stub.
    """

    TX_HEX = "ab" * 32  # 64-hex tx_hash placeholder

    def _capture_pending_print(self) -> str:
        """Call ``_print_pending_receipt`` with stub RPC + stub stdout
        and return the captured stdout text."""
        result = {"current_height": 1000}
        captured = io.StringIO()
        with mock.patch("client.rpc_call", _StubInfo(30)), \
                mock.patch("sys.stdout", captured):
            rc = cli._print_pending_receipt(
                result, self.TX_HEX, "127.0.0.1", 9334,
            )
        self.assertEqual(rc, 0)
        return captured.getvalue()

    def test_pending_receipt_does_not_print_deprecated_dash_tx_form(self):
        # The bare ``--tx`` form is the deprecated stub.  Any
        # printout containing ``submit-evidence --tx`` (note: with a
        # space and a dash, not ``submit-evidence censorship``) is
        # the regression we're closing.
        out = self._capture_pending_print()
        self.assertNotIn(
            f"submit-evidence --tx {self.TX_HEX}",
            out,
            "PENDING printout must not name the deprecated "
            "``submit-evidence --tx <hash>`` stub form -- it prints "
            "a migration diagnostic and files nothing on chain.",
        )

    def test_pending_receipt_prints_live_censorship_receipt_form(self):
        # The live form is ``submit-evidence censorship --receipt
        # <bundle.json>`` -- the path that actually files an
        # on-chain CensorshipEvidenceTx.
        out = self._capture_pending_print()
        bundle_path = os.path.join(
            cli._default_receipts_dir(), f"{self.TX_HEX}.json",
        )
        # Match against the canonical bundle path so the test pins
        # the exact copy-paste contract the user gets.
        self.assertIn(
            f"submit-evidence censorship --receipt {bundle_path}",
            out,
            "PENDING printout must name the live ``submit-evidence "
            "censorship --receipt <bundle.json>`` form so the user "
            "can copy-paste it to file evidence.",
        )

    def test_pending_receipt_still_names_pending_status_and_tx_age(self):
        # Regression guard: the fix must not strip the wait-estimate
        # / status framing that anchors the user before the
        # escalation hint.  The PENDING line + "permanent and can
        # never be deleted" guarantee must remain.
        out = self._capture_pending_print()
        self.assertIn("PENDING", out)
        self.assertIn("can never be deleted", out)


if __name__ == "__main__":
    unittest.main()
