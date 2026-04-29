"""cmd_send must persist the SubmissionReceipt bundle on success.

The slashing-backed permanence promise is the chain's headline claim,
but pre-fix the default `messagechain send` path read `tx_hash` and
`fee` from the RPC response and IGNORED the `receipt` field that the
server already returns at submit time.  Without the bundle on disk
the user has nothing to feed `submit-evidence censorship --receipt
<bundle.json>` later if their tx is censored.

The fix:

  1. cmd_send writes ~/.messagechain/receipts/<tx_hash>.json containing
     the validator's SubmissionReceipt + the original message_tx so the
     bundle is loadable by `_load_receipt_bundle` (the very same parser
     `submit-evidence censorship --receipt` uses) without further
     translation.
  2. cmd_send prints a "receipt saved: <path>" notice so the user can
     find the file later.
  3. The receipt-CLI not-found hint points at the LIVE escalation form
     (`submit-evidence censorship --receipt <path>`), not the deprecated
     `submit-evidence --tx <hash>` stub.

These tests pin the funnel end-to-end: the file the send path writes
must round-trip through the loader the submit-evidence path uses.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch


_FAKE_TX_HASH = "deadbeefcafef00d" + "0" * 48


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


_cached_sender = None
_cached_issuer = None
_cached_receipt_kp = None


def _build_real_message_tx_and_receipt():
    """Build a real MessageTransaction + matching SubmissionReceipt.

    The receipt's tx_hash MUST match the message_tx's tx_hash or the
    bundle loader will refuse the file -- exactly the round-trip the
    fix is supposed to guarantee.  Returns (tx, receipt_hex, tx_hash_hex)
    where receipt_hex is what the server returns in
    `result["receipt"]`.

    Entities + receipt-subtree keypair are cached at module level so
    successive tests in this file don't pay 4x the keygen cost.
    """
    from messagechain.identity.identity import Entity
    from messagechain.core.transaction import create_transaction
    from messagechain.crypto.keys import KeyPair
    from messagechain.network.submission_receipt import (
        ReceiptIssuer, SubmissionReceipt,
    )

    global _cached_sender, _cached_issuer, _cached_receipt_kp
    if _cached_sender is None:
        _cached_sender = Entity.create(
            b"send-saves-receipt-sender".ljust(32, b"\x00"),
        )
    if _cached_issuer is None:
        _cached_issuer = Entity.create(
            b"send-saves-receipt-issuer".ljust(32, b"\x00"),
        )
    if _cached_receipt_kp is None:
        _cached_receipt_kp = KeyPair.generate(
            seed=b"receipt-subtree-send-saves",
            height=4,
        )
    # Reset signing state so successive calls re-use leaves cleanly.
    _cached_sender.keypair._next_leaf = 0
    _cached_receipt_kp._next_leaf = 0

    tx = create_transaction(_cached_sender, "hello round-trip",
                            fee=300, nonce=0)
    issuer = ReceiptIssuer(
        _cached_issuer.entity_id, _cached_receipt_kp,
        height_fn=lambda: 432,
    )
    receipt = issuer.issue(tx.tx_hash)
    return tx, receipt.to_bytes().hex(), tx.tx_hash.hex()


def _run_cmd_send_with_response(
    submit_response: dict,
    *,
    tmp_home: str,
    real_tx=None,
):
    """Drive cmd_send to its post-submit branch with HOME redirected.

    The redirect lets the test point cmd_send's `~/.messagechain` at a
    pytest-managed tmpdir and inspect the resulting file directly.
    Stubs every RPC the CLI hits on the happy path so the only thing
    actually executing is the post-submit logic we care about.
    """
    from messagechain import cli as cli_mod

    entity = MagicMock()
    entity.entity_id = b"\x01" * 32
    entity.entity_id_hex = "01" * 32
    entity.keypair = MagicMock()
    entity.keypair.advance_to_leaf = MagicMock()

    if real_tx is not None:
        tx_for_create = real_tx
    else:
        tx_for_create = MagicMock()
        tx_for_create.serialize.return_value = {"fake": "tx"}
        tx_for_create.tx_hash = bytes.fromhex(_FAKE_TX_HASH)

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

    # Redirect HOME so the receipt write hits the tmpdir, not the real
    # operator's filesystem.  Both env vars matter: USERPROFILE on
    # Windows, HOME on POSIX -- os.path.expanduser consults whichever
    # is appropriate for the platform.
    env_overrides = {"HOME": tmp_home, "USERPROFILE": tmp_home}
    with patch.dict(os.environ, env_overrides), \
         patch.object(cli_mod, "_resolve_private_key",
                      return_value=b"\x02" * 32), \
         patch("messagechain.identity.identity.Entity.create",
               return_value=entity), \
         patch("messagechain.core.transaction.create_transaction",
               return_value=tx_for_create), \
         patch("client.rpc_call", side_effect=rpc_side), \
         patch.object(cli_mod, "_parse_server",
                      return_value=("127.0.0.1", 9334)), \
         patch.object(cli_mod, "_reserve_leaf_via_rpc",
                      return_value=0):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                cli_mod.cmd_send(_send_args("hello world"))
            except SystemExit:
                pass
    return buf.getvalue()


class TestCmdSendWritesReceiptBundle(unittest.TestCase):
    """The default send path must persist the SubmissionReceipt bundle.

    Pin the canonical default location ~/.messagechain/receipts/
    <tx_hash>.json so the user can paste the path straight into
    `submit-evidence censorship --receipt <path>` later.
    """

    def test_send_writes_bundle_to_canonical_path_on_success(self):
        with tempfile.TemporaryDirectory() as tmp_home:
            tx, receipt_hex, tx_hash_hex = (
                _build_real_message_tx_and_receipt()
            )
            response = {
                "ok": True,
                "result": {
                    "tx_hash": tx_hash_hex,
                    "fee": 223,
                    "receipt": receipt_hex,
                },
            }
            out = _run_cmd_send_with_response(
                response, tmp_home=tmp_home, real_tx=tx,
            )

            expected_dir = os.path.join(
                tmp_home, ".messagechain", "receipts",
            )
            expected_path = os.path.join(
                expected_dir, f"{tx_hash_hex}.json",
            )
            self.assertTrue(
                os.path.exists(expected_path),
                f"cmd_send must write the receipt bundle to "
                f"{expected_path!r} on success; got files: "
                f"{os.listdir(expected_dir) if os.path.isdir(expected_dir) else 'NO DIR'}",
            )
            # Path must be surfaced in stdout so the user can find it.
            self.assertIn("receipt", out.lower())
            self.assertIn(expected_path.replace("\\", "/").split("/")[-1],
                          out.replace("\\", "/"))


class TestSavedBundleLoadsViaSubmitEvidenceParser(unittest.TestCase):
    """End-to-end round-trip: the file cmd_send writes MUST be loadable
    by the same parser `submit-evidence censorship --receipt` uses.

    The bug being closed is precisely that the funnel was broken at
    the disk-handoff boundary -- pin the round-trip so any future
    schema drift on either side fails loud.
    """

    def test_saved_bundle_is_loadable_by_load_receipt_bundle(self):
        from messagechain.cli import _load_receipt_bundle

        with tempfile.TemporaryDirectory() as tmp_home:
            tx, receipt_hex, tx_hash_hex = (
                _build_real_message_tx_and_receipt()
            )
            response = {
                "ok": True,
                "result": {
                    "tx_hash": tx_hash_hex,
                    "fee": 223,
                    "receipt": receipt_hex,
                },
            }
            _run_cmd_send_with_response(
                response, tmp_home=tmp_home, real_tx=tx,
            )

            bundle_path = os.path.join(
                tmp_home, ".messagechain", "receipts",
                f"{tx_hash_hex}.json",
            )
            # Sanity: file exists and is valid JSON before the loader
            # runs, so a loader failure can't be confused with a
            # missing-file failure.
            with open(bundle_path, "r", encoding="utf-8") as f:
                parsed = json.load(f)
            self.assertIn("receipt", parsed)
            self.assertIn("message_tx", parsed)

            # The actual round-trip the funnel depends on.
            loaded_receipt, loaded_tx = _load_receipt_bundle(bundle_path)
            self.assertEqual(loaded_receipt.tx_hash, tx.tx_hash)
            self.assertEqual(loaded_tx.tx_hash, tx.tx_hash)


class TestReceiptSaveIsIdempotent(unittest.TestCase):
    """Two sends with the same tx_hash must not crash on the second
    write.  mkdir -p semantics + overwrite-allowed.
    """

    def test_second_send_with_same_tx_hash_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp_home:
            tx, receipt_hex, tx_hash_hex = (
                _build_real_message_tx_and_receipt()
            )
            response = {
                "ok": True,
                "result": {
                    "tx_hash": tx_hash_hex,
                    "fee": 223,
                    "receipt": receipt_hex,
                },
            }
            _run_cmd_send_with_response(
                response, tmp_home=tmp_home, real_tx=tx,
            )
            # Second invocation -- the receipts dir already exists, the
            # file already exists.  Must not raise.
            _run_cmd_send_with_response(
                response, tmp_home=tmp_home, real_tx=tx,
            )
            bundle_path = os.path.join(
                tmp_home, ".messagechain", "receipts",
                f"{tx_hash_hex}.json",
            )
            self.assertTrue(os.path.exists(bundle_path))


class TestNoReceiptFieldNoFile(unittest.TestCase):
    """If the server returns no `receipt` field (older validator, or
    receipt-budget exhaustion), cmd_send must not crash and must not
    write a half-bundle file.
    """

    def test_no_receipt_field_skips_write_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_home:
            response = {
                "ok": True,
                "result": {"tx_hash": _FAKE_TX_HASH, "fee": 223},
            }
            out = _run_cmd_send_with_response(
                response, tmp_home=tmp_home,
            )
            receipts_dir = os.path.join(
                tmp_home, ".messagechain", "receipts",
            )
            # No file written -- either the dir doesn't exist or it's
            # empty.  Both are fine; we just need "no half-bundle".
            if os.path.isdir(receipts_dir):
                self.assertEqual(
                    [n for n in os.listdir(receipts_dir)
                     if n.endswith(".json")],
                    [],
                    "no-receipt path must not leave a stray bundle",
                )
            # And the success print must still have happened.
            self.assertIn("Message sent", out)


if __name__ == "__main__":
    unittest.main()
