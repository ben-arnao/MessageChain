"""Audit r45 #3 — ``cmd_transfer`` and ``cmd_react`` must save the
server-returned SubmissionReceipt to disk, mirroring ``cmd_send`` and
``cmd_send_multi_submit``.

Pre-fix only ``cmd_send`` and ``cmd_send_multi_submit`` persisted
``result["receipt"]`` to ``~/.messagechain/receipts/<tx_hash>.json``
in the bundle shape ``submit-evidence censorship --receipt <path>``
consumes.  ``cmd_transfer`` and ``cmd_react`` -- the only OTHER
user-facing signed-tx commands whose server admit path actually
issues a receipt (see ``Server._rpc_submit_transfer`` and
``Server._rpc_submit_react`` -- both surface ``payload["receipt"]``
when the validator issued one) -- silently dropped it.

Without the on-disk bundle, the user has no artifact to file as
``CensorshipEvidenceTx`` if the transfer / react is later silently
dropped by a coerced validator.  The CLAUDE.md collective-
censorship-resistance anchor reads "a tx that is well-formed, pays
at least the per-byte floor, and fits the byte budget cannot be
suppressed by anything weaker than a full validator-set majority
actively colluding *and* willing to absorb the slashing risk."  The
slashable evidence path is the structural defense; saving the
receipt the moment the server returns it is the user-facing surface
that makes it accessible.

Other signed-tx commands (``cmd_stake``, ``cmd_unstake``,
``cmd_propose``, ``cmd_vote``, ``cmd_rotate_key``,
``cmd_emergency_revoke``) are NOT in scope here -- their server
admit paths do NOT issue receipts today (the server-side
``submit_transaction_to_mempool`` plumbing exists only for message
/ transfer / react), so there is nothing for the CLI to save until
the server side is extended.  That is a separate, larger structural
change.

CLAUDE.md anchor at risk:
  * Collective censorship resistance (validator-collusion threat
    model is primary) -- the slashable-evidence path is the
    structural defense, and the user-facing surface to reach it
    must work for every tx kind the server issues receipts for, not
    just messages.
  * Dual-purpose-token / "mainstream-asset quality bar" -- transfer
    is a first-class tx type held to mainstream-asset standards; the
    censorship-evidence promise must apply to transfers just like to
    messages.

Fix: route both commands' success path through the same
``_save_receipt_bundle`` helper that ``cmd_send`` uses, with
``tx_kind="transfer"`` / ``tx_kind="react"`` respectively.  Best-
effort write -- a disk failure logs a warning but does not fail the
command (the tx is already on the wire).

Surfaced by audit r45 UX axis #3 / value-prop axis.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch


def _write_keyfile(raw_seed: bytes) -> tuple[str, str]:
    from messagechain.identity.key_encoding import encode_private_key
    d = tempfile.mkdtemp()
    p = os.path.join(d, "key.txt")
    with open(p, "w", encoding="ascii") as f:
        f.write(encode_private_key(raw_seed))
    return d, p


def _make_recipient_address() -> tuple[bytes, str]:
    from messagechain.identity.address import encode_address
    raw = b"\x42" * 32
    return raw, encode_address(raw)


def _fake_receipt_hex(tx_hash_hex: str) -> str:
    """A receipt-shaped hex blob that survives a JSON round-trip.

    The CLI just persists whatever string the server returned (the
    on-disk bundle's ``"receipt"`` field).  No structural validation
    happens at save time, so a sentinel hex is fine for testing the
    save-path behaviour.  Real receipt verification is exercised by
    ``submit-evidence censorship``'s own test suite.
    """
    return "ab" * 8 + tx_hash_hex[:16]


class _BaseSavePathTest(unittest.TestCase):
    """Shared setup: keyfile, recipient address, isolated receipts dir."""

    def setUp(self):
        seed = b"alice-r45-receipt-hoist".ljust(32, b"\x00")
        self._key_dir, self.key_path = _write_keyfile(seed)
        self._recipient_raw, self._recipient_addr = _make_recipient_address()
        # Isolated receipts dir, swapped in via _default_receipts_dir
        # monkey-patch so neither test pollutes the real ~/.messagechain.
        self._receipts_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._key_dir, ignore_errors=True)
        shutil.rmtree(self._receipts_dir, ignore_errors=True)


class TestCmdTransferSavesReceiptBundle(_BaseSavePathTest):
    """``cmd_transfer`` must persist ``result["receipt"]`` to disk in
    the same bundle shape ``submit-evidence censorship --receipt`` reads.
    """

    def _args(self, **overrides):
        base = dict(
            to=self._recipient_addr,
            amount=10,
            fee=None,
            keyfile=self.key_path,
            data_dir=None,
            server="127.0.0.1:9334",
            yes=True,
            urgency="normal",
            allow_raw_hex_address=False,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def _build_fake_rpc(self):
        """RPC mock: existing recipient + valid receipt-hex on submit."""
        def fake_rpc_call(host, port, method, params):
            if method == "estimate_fee":
                return {"ok": True, "result": {
                    "min_fee": 1, "mempool_fee": 0, "recipient_is_new": False,
                }}
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "reserve_leaf":
                return {"ok": False}
            if method == "get_key_status":
                return {"ok": True, "result": {"public_key": "aa" * 32}}
            if method == "get_chain_info":
                from messagechain.config import UNIFIED_FEE_FLOOR_HEIGHT
                return {"ok": True,
                        "result": {"height": UNIFIED_FEE_FLOOR_HEIGHT + 1000}}
            if method == "submit_transfer":
                from messagechain.core.transfer import TransferTransaction
                tx = TransferTransaction.deserialize(params["transaction"])
                tx_hash_hex = tx.tx_hash.hex()
                return {"ok": True, "result": {
                    "tx_hash": tx_hash_hex,
                    "amount": tx.amount,
                    "fee": tx.fee,
                    "receipt": _fake_receipt_hex(tx_hash_hex),
                }}
            return {"ok": True, "result": {}}
        return fake_rpc_call

    def test_transfer_with_server_receipt_writes_bundle_to_disk(self):
        """Server returns ``receipt`` -> CLI writes the JSON bundle."""
        from messagechain import cli as mod

        receipts_dir = self._receipts_dir
        with patch("client.rpc_call", self._build_fake_rpc()), \
             patch.object(mod, "_default_receipts_dir",
                          return_value=receipts_dir):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_transfer(self._args())

        files = os.listdir(receipts_dir)
        bundles = [f for f in files if f.endswith(".json")]
        self.assertEqual(
            len(bundles), 1,
            f"cmd_transfer must save exactly one receipt bundle on "
            f"success; got files={files}\noutput:\n{buf.getvalue()}",
        )
        bundle_path = os.path.join(receipts_dir, bundles[0])

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertIn("receipt", bundle, "bundle must carry the receipt")
        self.assertIn("message_tx", bundle, "bundle must carry the tx")
        self.assertEqual(
            bundle.get("tx_kind"), "transfer",
            "bundle must mark tx_kind='transfer' so "
            "_load_receipt_bundle deserialises against TransferTransaction",
        )
        # Filename pins the tx_hash so a downstream operator can find
        # the bundle by hash directly.
        self.assertTrue(
            bundles[0].endswith(".json"),
            f"bundle filename {bundles[0]!r} must end in .json",
        )

    def test_transfer_bundle_carries_transfer_tx_kind_and_serialized_tx(self):
        """The saved bundle must be structurally consumable by the
        ``submit-evidence censorship --receipt`` path: it carries the
        ``tx_kind`` discriminator (so ``_load_receipt_bundle`` picks
        the right deserialiser) AND the original ``message_tx`` blob
        (so the evidence covers the actual rejected tx).  A real
        receipt-hex round-trip through ``_load_receipt_bundle`` is
        exercised end-to-end by the send-multi receipt-bundle suite
        with real WOTS+ signatures; here we pin the shape only.
        """
        from messagechain import cli as mod

        receipts_dir = self._receipts_dir
        with patch("client.rpc_call", self._build_fake_rpc()), \
             patch.object(mod, "_default_receipts_dir",
                          return_value=receipts_dir):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_transfer(self._args())

        bundles = [f for f in os.listdir(receipts_dir) if f.endswith(".json")]
        bundle_path = os.path.join(receipts_dir, bundles[0])
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertEqual(bundle["tx_kind"], "transfer")
        # message_tx is the serialised TransferTransaction -- must
        # round-trip through TransferTransaction.deserialize so the
        # downstream slashing-evidence path can recompute tx_hash.
        from messagechain.core.transfer import TransferTransaction
        round_tripped = TransferTransaction.deserialize(bundle["message_tx"])
        self.assertEqual(round_tripped.tx_hash.hex(),
                         bundle_path.rsplit(os.sep, 1)[-1][:64])

    def test_transfer_without_server_receipt_no_bundle_written(self):
        """If the server didn't issue a receipt (e.g. the receipt
        subtree was full, opt-out flag, etc.), the CLI must not
        write a bundle nor crash.  Pre-fix this case was implicit;
        re-pin it now that we route through ``_save_receipt_bundle``.
        """
        from messagechain import cli as mod

        def fake_rpc_call(host, port, method, params):
            if method == "estimate_fee":
                return {"ok": True, "result": {
                    "min_fee": 1, "mempool_fee": 0, "recipient_is_new": False,
                }}
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "reserve_leaf":
                return {"ok": False}
            if method == "get_key_status":
                return {"ok": True, "result": {"public_key": "aa" * 32}}
            if method == "get_chain_info":
                from messagechain.config import UNIFIED_FEE_FLOOR_HEIGHT
                return {"ok": True,
                        "result": {"height": UNIFIED_FEE_FLOOR_HEIGHT + 1000}}
            if method == "submit_transfer":
                from messagechain.core.transfer import TransferTransaction
                tx = TransferTransaction.deserialize(params["transaction"])
                # No 'receipt' key -- mirrors the server's behaviour
                # when no SubmissionReceipt was issued.
                return {"ok": True, "result": {
                    "tx_hash": tx.tx_hash.hex(),
                    "amount": tx.amount,
                    "fee": tx.fee,
                }}
            return {"ok": True, "result": {}}

        receipts_dir = self._receipts_dir
        with patch("client.rpc_call", fake_rpc_call), \
             patch.object(mod, "_default_receipts_dir",
                          return_value=receipts_dir):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_transfer(self._args())

        bundles = [f for f in os.listdir(receipts_dir) if f.endswith(".json")]
        self.assertEqual(
            len(bundles), 0,
            "no receipt returned by server -> no bundle written; "
            f"got files={bundles}",
        )


class TestCmdReactSavesReceiptBundle(_BaseSavePathTest):
    """``cmd_react`` mirror: server-issued receipt must be persisted."""

    def _args(self, **overrides):
        # cmd_react needs target_type + target + choice (parser uses
        # nargs='?').  Use a 64-hex target that isn't self.
        base = dict(
            target_type="message",
            target="11" * 32,
            choice="up",
            fee=None,
            keyfile=self.key_path,
            data_dir=None,
            server="127.0.0.1:9334",
            urgency="normal",
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def _build_fake_rpc(self):
        def fake_rpc_call(host, port, method, params):
            if method == "estimate_fee":
                return {"ok": True, "result": {
                    "min_fee": 1, "mempool_fee": 0,
                }}
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "reserve_leaf":
                return {"ok": False}
            if method == "get_chain_info":
                from messagechain.config import TIER_18_HEIGHT
                return {"ok": True,
                        "result": {"height": TIER_18_HEIGHT + 1000}}
            if method == "submit_react":
                from messagechain.core.reaction import ReactTransaction
                tx = ReactTransaction.deserialize(params["transaction"])
                tx_hash_hex = tx.tx_hash.hex()
                return {"ok": True, "result": {
                    "tx_hash": tx_hash_hex,
                    "fee": tx.fee,
                    "receipt": _fake_receipt_hex(tx_hash_hex),
                }}
            return {"ok": True, "result": {}}
        return fake_rpc_call

    def test_react_with_server_receipt_writes_bundle_to_disk(self):
        from messagechain import cli as mod

        receipts_dir = self._receipts_dir
        with patch("client.rpc_call", self._build_fake_rpc()), \
             patch.object(mod, "_default_receipts_dir",
                          return_value=receipts_dir):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_react(self._args())

        bundles = [f for f in os.listdir(receipts_dir) if f.endswith(".json")]
        self.assertEqual(
            len(bundles), 1,
            f"cmd_react must save exactly one receipt bundle on "
            f"success; got files={bundles}\noutput:\n{buf.getvalue()}",
        )
        bundle_path = os.path.join(receipts_dir, bundles[0])

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertIn("receipt", bundle)
        self.assertIn("message_tx", bundle)
        self.assertEqual(
            bundle.get("tx_kind"), "react",
            "bundle must mark tx_kind='react'",
        )

    def test_react_bundle_carries_react_tx_kind_and_serialized_tx(self):
        """Mirror of the cmd_transfer pin -- bundle must carry
        ``tx_kind="react"`` and a ReactTransaction-shaped
        ``message_tx`` blob.
        """
        from messagechain import cli as mod

        receipts_dir = self._receipts_dir
        with patch("client.rpc_call", self._build_fake_rpc()), \
             patch.object(mod, "_default_receipts_dir",
                          return_value=receipts_dir):
            buf = StringIO()
            with redirect_stdout(buf):
                mod.cmd_react(self._args())

        bundles = [f for f in os.listdir(receipts_dir) if f.endswith(".json")]
        bundle_path = os.path.join(receipts_dir, bundles[0])
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        self.assertEqual(bundle["tx_kind"], "react")
        from messagechain.core.reaction import ReactTransaction
        round_tripped = ReactTransaction.deserialize(bundle["message_tx"])
        self.assertEqual(round_tripped.tx_hash.hex(),
                         bundle_path.rsplit(os.sep, 1)[-1][:64])


class TestReceiptSaveHelperCoversAllReceiptIssuingCommands(unittest.TestCase):
    """Structural pin: every CLI command whose RPC handler surfaces
    ``payload["receipt"]`` (today: cmd_send, cmd_send_multi_submit,
    cmd_transfer, cmd_react) must invoke ``_save_receipt_bundle`` in
    its success path.  This is the audit r45 #3 anti-regression
    guard against a future signed-tx command that adds a receipt-
    issuing server path but forgets to save the bundle in the CLI.
    """

    def test_cmd_transfer_calls_save_receipt_bundle(self):
        from messagechain import cli as mod
        src = open(mod.__file__, encoding="utf-8").read()
        # Slice cmd_transfer's body and check the helper appears.
        start = src.index("def cmd_transfer(")
        # Function body ends at the next top-level def.
        end = src.index("\ndef ", start + 1)
        body = src[start:end]
        self.assertIn(
            "_save_receipt_bundle", body,
            "cmd_transfer must route its success-path receipt save "
            "through _save_receipt_bundle so submit-evidence "
            "censorship --receipt can consume the bundle directly.",
        )

    def test_cmd_react_calls_save_receipt_bundle(self):
        from messagechain import cli as mod
        src = open(mod.__file__, encoding="utf-8").read()
        start = src.index("def cmd_react(")
        end = src.index("\ndef ", start + 1)
        body = src[start:end]
        self.assertIn(
            "_save_receipt_bundle", body,
            "cmd_react must route its success-path receipt save "
            "through _save_receipt_bundle.",
        )


if __name__ == "__main__":
    unittest.main()
