"""cmd_send happy-path must print a shareable receipt URL.

The receipt page at ``https://messagechain.org/r/<tx_hash_hex>`` is
the artifact a user points at when they need to share their post --
a journalist proving they reported a story at a specific time, a
dissident demonstrating "I said this and it can never be taken
down," an author building a body of work that anyone can verify on
the chain.  The page exists, renders cleanly with "Permanent · this
message is on-chain and can never be deleted" framing, and queries
``/v1/tx_status`` to confirm inclusion.  But pre-fix the only thing
``cmd_send`` told the user after a successful submit was the
``messagechain receipt <hash>`` CLI -- which is the right pointer
for verification but USELESS for sharing.  The value-prop of the
chain (permanence as a public artifact, not a private receipt) was
literally invisible to every user at the exact moment they had
just paid to create one.

This regression pin enforces:

  1. The success block names a fully-qualified URL on the public
     feed host with the literal tx_hash substituted.
  2. The base host is configurable via ``PUBLIC_FEED_URL`` so a
     testnet or alternative feed deployment overrides cleanly.
  3. The URL appears alongside the existing ``messagechain receipt``
     pointer -- this is additive, not a replacement (the CLI
     verifier is still the slashing-grounded path; the URL is the
     human-shareable artifact on top).
  4. The failure path stays clean (no URL emitted when no tx
     landed).
"""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


def _send_args(message: str, **overrides):
    base = dict(
        message=message,
        fee=None,
        server="127.0.0.1:9334",
        prev=None,
        keyfile="/dev/null",
        data_dir=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _run_cmd_send_with_submit_response(
    submit_response: dict, message: str = "hello world",
) -> str:
    """Drive cmd_send through to the print branch and capture stdout.

    Stubs every RPC the CLI hits on the happy path so the only thing
    actually executing is the post-submit print logic we're testing.
    """
    from messagechain import cli as cli_mod

    entity = MagicMock()
    entity.entity_id = b"\x01" * 32
    entity.entity_id_hex = "01" * 32
    entity.keypair = MagicMock()
    entity.keypair.advance_to_leaf = MagicMock()

    fake_tx = MagicMock()
    fake_tx.serialize.return_value = {"fake": "tx"}

    def rpc_side(host, port, method, params):
        if method == "get_nonce":
            return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
        if method == "reserve_leaf":
            return {"ok": True, "result": {"leaf": 0}}
        if method == "get_chain_info":
            return {"ok": True, "result": {"height": 432}}
        if method == "get_fee_estimate":
            return {"ok": True, "result": {"fee_estimate": 100}}
        if method == "get_entity":
            return {"ok": True, "result": {"pubkey_registered": True}}
        if method == "submit_transaction":
            return submit_response
        return {"ok": True, "result": {}}

    with patch.object(cli_mod, "_resolve_private_key",
                      return_value=b"\x02" * 32), \
         patch("messagechain.identity.identity.Entity.create",
               return_value=entity), \
         patch("messagechain.core.transaction.create_transaction",
               return_value=fake_tx), \
         patch("client.rpc_call", side_effect=rpc_side), \
         patch.object(cli_mod, "_parse_server",
                      return_value=("127.0.0.1", 9334)), \
         patch.object(cli_mod, "_reserve_leaf_via_rpc",
                      return_value=0):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                cli_mod.cmd_send(_send_args(message))
            except SystemExit:
                pass
    return buf.getvalue()


SUCCESS_TX_HASH = "deadbeefcafef00d" + "0" * 48


class TestCmdSendSuccessPrintsShareableUrl(unittest.TestCase):

    def test_success_prints_messagechain_org_receipt_url(self):
        """The success block must include a fully-qualified shareable
        URL on the public feed host with the literal tx_hash."""
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        expected_url = f"https://messagechain.org/r/{SUCCESS_TX_HASH}"
        self.assertIn(
            expected_url, out,
            "success path must print the shareable receipt URL with "
            "the literal tx_hash substituted; this is the artifact a "
            "user hands to anyone who needs to verify their post is "
            "on chain.",
        )

    def test_success_url_appears_alongside_cli_receipt_pointer(self):
        """Additive, not a replacement: the existing receipt CLI
        pointer must still appear AND the new URL must appear too."""
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        # CLI verifier (existing) must still be there.
        self.assertIn(f"messagechain receipt {SUCCESS_TX_HASH}", out)
        # And the shareable URL (new) must be there too.
        self.assertIn(
            f"https://messagechain.org/r/{SUCCESS_TX_HASH}", out,
        )


class TestCmdSendSuccessUrlIsConfigurable(unittest.TestCase):
    """A testnet / alternative feed deployment must be able to
    override the host without code change.  ``PUBLIC_FEED_URL`` in
    ``messagechain.config`` is the override knob."""

    def test_override_via_public_feed_url_config(self):
        from messagechain import cli as cli_mod
        # Patch the config constant the CLI reads to build the URL.
        with patch.object(
            cli_mod, "PUBLIC_FEED_URL", "https://testnet.example.org",
            create=True,
        ):
            out = _run_cmd_send_with_submit_response({
                "ok": True,
                "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
            })
        self.assertIn(
            f"https://testnet.example.org/r/{SUCCESS_TX_HASH}", out,
            "PUBLIC_FEED_URL override must cleanly redirect the share "
            "URL host so testnet / alternative deployments don't need "
            "to fork the CLI.",
        )
        # And the production host must NOT leak through the override.
        self.assertNotIn("messagechain.org", out)


class TestCmdSendFailurePathOmitsUrl(unittest.TestCase):
    """No URL emitted when there's no tx to share."""

    def test_failure_does_not_print_share_url(self):
        out = _run_cmd_send_with_submit_response({
            "ok": False,
            "error": "Unknown entity -- must register first",
        })
        self.assertNotIn("/r/", out,
            "failure path must NOT print a /r/ receipt URL -- the tx "
            "did not land, there's nothing to share")
        self.assertNotIn("messagechain.org/r/", out)


if __name__ == "__main__":
    unittest.main()
