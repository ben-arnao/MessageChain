"""``send-multi`` must write JSON receipt bundles, not raw ``.bin`` blobs.

``send-multi`` is the censorship-resistance escape hatch (only CLI
path that defends against single-validator collusion / single-RPC-node
suppression).  Pre-fix the success path wrote ``<tx>_<issuer>.bin``
files containing raw ``receipt.to_bytes()`` -- a format the
``submit-evidence censorship --receipt <path>`` CLI cannot consume:
``_load_receipt_bundle`` requires a JSON object with ``receipt`` AND
``message_tx`` keys and raises ``ValueError("receipt bundle missing
'message_tx' field")`` on a raw .bin.

Net effect: a dissident reaches for ``send-multi`` (the only path
that defends against validator collusion), the censoring node drops
their tx, they try ``submit-evidence`` to file slashable evidence --
and the CLI rejects their own receipts with a "missing message_tx"
error.  The structural defense at the protocol level exists; the
user-facing path to invoke it is broken.

This file pins the round-trip:

  1. The success path writes JSON files (not ``.bin``).
  2. The file contents are accepted by ``_load_receipt_bundle``
     without translation.
  3. The loaded (receipt, tx) pair carries the same tx_hash the
     submission saw.

Surfaced by audit r44 #2 — censorship-defense escape hatch
escalation path.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch


def _write_keyfile(content_hex: str) -> tuple[str, str]:
    d = tempfile.mkdtemp()
    p = os.path.join(d, "key.txt")
    with open(p, "w", encoding="ascii") as f:
        f.write(content_hex)
    return d, p


def _make_fake_receipt(tx_hash: bytes, issuer_id: bytes):
    """Construct a real SubmissionReceipt with placeholder fields.

    The ``_compute_hash`` path doesn't depend on the signature blob
    (the signature signs the same hash; ``_signable_data`` excludes
    it), so a placeholder Signature is round-trip-safe for the
    bundle-shape tests here.  We do NOT exercise verify_receipt --
    that's the slashing path's concern, and is covered elsewhere.
    """
    from messagechain.network.submission_receipt import SubmissionReceipt
    from messagechain.crypto.keys import Signature, WOTS_KEY_CHAINS

    # Round-trip-safe placeholder: WOTS_KEY_CHAINS chains of zero bytes
    # so ``Signature.from_bytes(sig.to_bytes())`` succeeds.  The receipt
    # path doesn't verify the signature here -- ``_load_receipt_bundle``
    # only structurally decodes the bytes; signature verification is
    # the slashing path's concern.
    sig = Signature(
        wots_signature=[b"\x00" * 32] * WOTS_KEY_CHAINS,
        leaf_index=0,
        auth_path=[],
        wots_public_key=b"\x00" * 32,
        wots_public_seed=b"\x00" * 32,
    )
    return SubmissionReceipt(
        tx_hash=tx_hash,
        commit_height=42,
        issuer_id=issuer_id,
        issuer_root_public_key=b"\xcd" * 32,
        signature=sig,
    )


def _fake_submit_result_with_receipts(tx, *, issuer_ids):
    """SubmitClient.submit return shape with one receipt per issuer."""
    from unittest.mock import MagicMock
    r = MagicMock()
    r.tx_hash = tx.tx_hash
    r.successes = len(issuer_ids)
    r.receipts = [_make_fake_receipt(tx.tx_hash, iid) for iid in issuer_ids]
    r.rejections = []
    r.elapsed_ms = 7
    return r


class TestSendMultiWritesJsonBundles(unittest.TestCase):
    """The receipts the success path writes must be ingestible by
    ``submit-evidence censorship --receipt <path>`` without
    translation -- i.e. JSON bundles, not raw .bin blobs."""

    def setUp(self):
        # Post-audit-r46: cmd_send_multi_submit routes keyfile through
        # `_resolve_private_key`, which expects the checksummed-hex or
        # mnemonic form (what `generate-key` produces), not raw 64-char
        # hex.  Encode via the canonical helper for parity with real
        # user keyfiles.
        from messagechain.identity.key_encoding import encode_private_key
        priv = b"alice-r44-bundles".ljust(32, b"\x00")
        self._key_dir, self.key_path = _write_keyfile(encode_private_key(priv))
        self._receipts_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._key_dir, ignore_errors=True)
        shutil.rmtree(self._receipts_dir, ignore_errors=True)

    def _args(self):
        return argparse.Namespace(
            message="dissident post",
            fee=5000,
            endpoints=[
                "127.0.0.1:8443",
                "127.0.0.1:8444",
                "127.0.0.1:8445",
            ],
            insecure=True,
            keyfile=self.key_path,
            receipts_dir=self._receipts_dir,
            min_successes=1,
            per_endpoint_timeout_s=1.0,
            no_receipts=False,
            nonce=0,
            leaf_index=0,
            server="127.0.0.1:9334",
            data_dir=None,
            urgency="normal",
        )

    def _run_with_fake_receipts(self):
        """Common setup: drive cmd_send_multi_submit with a SubmitClient
        that returns one receipt per endpoint, and stub the chain RPCs."""
        from messagechain import cli as mod

        def fake_rpc_call(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 100}}
            return {"ok": True, "result": {}}

        issuer_ids = [b"\xa1" * 32, b"\xa2" * 32, b"\xa3" * 32]

        class _FakeClient:
            def __init__(self, **kw):
                self.min_successes = kw.get("min_successes", 1)

            def submit(self, tx):
                return _fake_submit_result_with_receipts(
                    tx, issuer_ids=issuer_ids,
                )

        with patch("client.rpc_call", fake_rpc_call), \
             patch("messagechain.network.submit_client.SubmitClient",
                   _FakeClient):
            buf = StringIO()
            with redirect_stdout(buf):
                rc = mod.cmd_send_multi_submit(self._args())
        return rc, issuer_ids, buf.getvalue()

    def test_success_path_writes_json_files_not_bin(self):
        """The receipts directory must contain JSON files after a
        successful multi-submit.  Pre-fix it contained ``.bin``."""
        rc, _issuers, out = self._run_with_fake_receipts()
        self.assertEqual(rc, 0, out)

        files = os.listdir(self._receipts_dir)
        # Filter the ``.tmp`` files the atomic write helper may leave
        # in a crash window (none in tests, but harmless to ignore).
        files = [f for f in files if not f.endswith(".tmp")]
        self.assertTrue(files, "expected at least one receipt bundle on disk")

        # All bundle files must end in ``.json`` -- the format
        # ``submit-evidence --receipt`` consumes.
        for f in files:
            self.assertTrue(
                f.endswith(".json"),
                f"receipt bundle {f!r} is not a JSON file -- "
                f"`submit-evidence` will reject it on load",
            )
        # And no .bin remnants.
        for f in files:
            self.assertFalse(
                f.endswith(".bin"),
                f"pre-fix .bin format leaked: {f!r}",
            )

    def test_bundles_are_keyed_per_issuer(self):
        """N validators each issue their own receipt for the same tx;
        the on-disk layout must preserve all N receipts, not collapse
        them under a single tx_hash.json that overwrites itself."""
        rc, issuer_ids, out = self._run_with_fake_receipts()
        self.assertEqual(rc, 0, out)

        files = [
            f for f in os.listdir(self._receipts_dir)
            if not f.endswith(".tmp")
        ]
        # One bundle per issuer.
        self.assertEqual(
            len(files), len(issuer_ids),
            f"expected {len(issuer_ids)} receipt files (one per validator); "
            f"got {len(files)}: {files!r}",
        )

    def test_bundles_round_trip_through_load_receipt_bundle(self):
        """Each written bundle must be ingestible by
        ``_load_receipt_bundle`` -- the exact loader
        ``submit-evidence censorship --receipt`` runs."""
        from messagechain.cli import _load_receipt_bundle

        rc, _issuers, out = self._run_with_fake_receipts()
        self.assertEqual(rc, 0, out)

        files = [
            os.path.join(self._receipts_dir, f)
            for f in os.listdir(self._receipts_dir)
            if f.endswith(".json")
        ]
        self.assertTrue(files, "no JSON bundles to round-trip")

        for path in files:
            # Must NOT raise.  Pre-fix the .bin format triggered
            # "receipt bundle missing `message_tx` field".
            receipt, tx = _load_receipt_bundle(path)
            # Sanity: the loaded receipt's tx_hash matches the tx's.
            self.assertEqual(receipt.tx_hash, tx.tx_hash)


if __name__ == "__main__":
    unittest.main()
