"""cmd_send happy-path must name the permanence guarantee + point at
verification.

The send command is the highest-traffic UX surface in the project --
every "I just posted a message" hits this code path.  Pre-fix the
success block printed only "Message sent! / TX hash: / Fee:" and then
stopped, leaving the headline promise of the project ("your message
can never be deleted") completely invisible at the exact moment the
user just paid real tokens for it.

Round-6 audit fix.  These tests pin:
  1. Success path names "permanent" / "can never be deleted".
  2. Success path points at `messagechain receipt <tx_hash>` with
     the literal hash substituted (the verification surface).
  3. Success path names slashing-backed enforcement so the user
     understands why the permanence claim is binding, not marketing.
  4. Failure path stays clean -- we do NOT claim permanence on a
     failed submit; the existing error-and-bootstrap text is the
     dominant output there.
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
                # Failure path raises SystemExit -- that's fine, we
                # still want stdout for the assertions.
                pass
    return buf.getvalue()


SUCCESS_TX_HASH = "deadbeefcafef00d" + "0" * 48


class TestCmdSendSuccessPrintsPermanenceMessage(unittest.TestCase):
    """The headline promise of the project must appear at the exact
    moment the user just paid real tokens to invoke it.

    Either of two phrasings is acceptable -- the CLI elsewhere
    ("This message is permanent.  It can never be deleted.") uses
    both -- but at least one MUST land in the success block.
    """

    def test_cmd_send_success_prints_permanence_message(self):
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        self.assertTrue(
            ("permanent" in out.lower()
             or "can never be deleted" in out.lower()),
            f"success path must name the permanence guarantee in plain "
            f"language; got:\n{out}",
        )


class TestCmdSendSuccessPrintsVerifyCommandWithTxHash(unittest.TestCase):
    """The success block must point at `messagechain receipt <hash>`
    with the literal hash substituted, not a placeholder.

    The receipt CLI is the verification surface that names slashing-
    backed permanence -- a user who never discovers it never gets
    to confirm their tx is actually on-chain.
    """

    def test_cmd_send_success_prints_verify_command_with_tx_hash(self):
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        self.assertIn(f"messagechain receipt {SUCCESS_TX_HASH}", out,
            "success path must point at the receipt CLI with the actual "
            "tx hash substituted (not a literal '<tx_hash>' placeholder).")


class TestCmdSendSuccessPrintsSlashingFraming(unittest.TestCase):
    """Naming "permanent" without naming the enforcement mechanism is
    a marketing claim.  The existing receipt CLI grounds the promise
    in slashable evidence; the send success block must do the same.
    """

    def test_cmd_send_success_prints_slashing_framing(self):
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        lower = out.lower()
        self.assertTrue(
            ("slash" in lower or "lose stake" in lower),
            f"success path must name slashing-backed enforcement so the "
            f"permanence claim is grounded in protocol mechanics, not "
            f"marketing copy; got:\n{out}",
        )


class TestCmdSendSuccessPointsAtCrossCheckServer(unittest.TestCase):
    """The paranoid-user pivot we built for the receipt CLI is the
    --cross-check-server flag.  Surfacing it in the send success
    block is what makes "permanent under collusion" reachable from
    the moment the tx is submitted, without the user having to read
    the receipt-CLI docs separately.
    """

    def test_cmd_send_success_mentions_cross_check_server(self):
        out = _run_cmd_send_with_submit_response({
            "ok": True,
            "result": {"tx_hash": SUCCESS_TX_HASH, "fee": 223},
        })
        self.assertIn("--cross-check-server", out,
            "success path should suggest --cross-check-server so users "
            "with a paranoid threat model can verify against a second "
            "validator without re-reading the receipt CLI docs.")


class TestCmdSendFailurePathUnchanged(unittest.TestCase):
    """We do NOT claim permanence on a failed submit.  The error path
    must stay focused on the error + bootstrap hint; permanence
    framing belongs strictly to the success branch.
    """

    def test_cmd_send_failure_does_not_print_permanence_framing(self):
        out = _run_cmd_send_with_submit_response({
            "ok": False,
            "error": "Unknown entity -- must register first",
        })
        # The existing failure copy must still land.
        self.assertIn("Failed:", out)
        self.assertIn("receive-to-exist", out)
        # And the permanence framing must NOT.
        lower = out.lower()
        self.assertNotIn("can never be deleted", lower,
            "failure path must NOT claim permanence -- the tx didn't land")
        # "permanent" is also a substring of innocuous English; pin the
        # specific strings the success block uses so we catch any drift
        # without false-positive on the word "permanently".
        self.assertNotIn("this tx is now binding", lower,
            "failure path must NOT print the success-block headline")
        self.assertNotIn(
            f"messagechain receipt ", out,
            "failure path must NOT point at the receipt verify command -- "
            "there's no tx to verify",
        )


if __name__ == "__main__":
    unittest.main()
