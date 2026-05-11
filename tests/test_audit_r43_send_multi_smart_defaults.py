"""``send-multi`` must auto-resolve fee, nonce, and leaf-watermark.

``send-multi`` is the censorship-resistance escape hatch — the ONLY
CLI path that defends a single user against validator collusion or
single-RPC-node suppression.  Pre-fix it required the user to
hand-supply ``--fee`` (``required=True``), defaulted ``--nonce`` to
0 (silently wrong on any non-fresh account), and used ``--nonce`` as
the WOTS+ ``--leaf-index`` floor with no reconciliation against the
chain's actual watermark.  A dissident reaching for this command
under pressure was exactly the population that would set
``--nonce 0`` from muscle memory and either bounce off a "nonce too
low" rejection or, on a fresh-machine + previously-used keyfile
combination, burn a WOTS+ leaf the chain has already seen — which
is grounds for equivocation slashing.

The fix mirrors ``cmd_send``: ``send-multi`` now accepts an optional
``--server`` for chain-state queries (parity with every other
tx-submitting command), auto-resolves ``--fee`` via the shared
``auto_fee`` helper when omitted, auto-resolves ``--nonce`` via the
``get_nonce`` RPC, and uses the ``leaf_watermark`` returned by the
same RPC as the floor passed to ``_bind_persistent_leaf_index``.
The on-disk cursor + chain watermark together close the cross-
machine leaf-reuse window the agent flagged.

These tests pin the surface — no real network, no real validators;
just argparse + rpc_call + auto_fee mocked.  The CLI-end behaviour
that "the right thing happens with zero flags beyond message +
endpoints" is what matters.

Surfaced by audit r43 UX axis #1.
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


_TEST_FEE = 7777


def _write_keyfile(content_hex: str) -> tuple[str, str]:
    d = tempfile.mkdtemp()
    p = os.path.join(d, "key.txt")
    with open(p, "w", encoding="ascii") as f:
        f.write(content_hex)
    return d, p


def _fake_submit_result(tx, successes=3):
    """Stand-in for SubmitClient.submit's return shape."""
    from unittest.mock import MagicMock
    r = MagicMock()
    r.tx_hash = tx.tx_hash
    r.successes = successes
    r.receipts = []
    r.rejections = []
    r.elapsed_ms = 12
    return r


class TestSendMultiParserAcceptsOmittedFee(unittest.TestCase):
    """``--fee`` is now optional — parser must accept the command
    without it (and downstream auto-fee picks a value)."""

    def test_parser_accepts_send_multi_without_fee(self):
        from messagechain.cli import build_parser

        parser = build_parser()
        # The parse_args call must not raise SystemExit on missing --fee.
        args = parser.parse_args([
            "send-multi", "hello",
            "--endpoint", "127.0.0.1:8443",
            "--endpoint", "127.0.0.1:8444",
            "--endpoint", "127.0.0.1:8445",
        ])
        self.assertIsNone(args.fee)


class TestSendMultiAutoResolvesNonceAndLeaf(unittest.TestCase):
    """When ``--nonce`` and ``--leaf-index`` are omitted, send-multi
    must query ``get_nonce`` via ``--server`` and use the chain's
    watermark — parity with ``cmd_send``."""

    def setUp(self):
        # Stable per-test scratch.  Post-audit-r46, cmd_send_multi_submit
        # routes through `_resolve_private_key` which only accepts
        # mnemonic / checksummed-hex (the formats `generate-key`
        # actually produces) -- raw 64-char hex without --data-dir is
        # rejected.  Encode via the canonical helper so the test reflects
        # what a real user's keyfile contains.
        from messagechain.identity.key_encoding import encode_private_key
        priv = b"alice-r43-send-multi".ljust(32, b"\x00")
        self._key_dir, self.key_path = _write_keyfile(encode_private_key(priv))
        self._receipts_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self._key_dir, ignore_errors=True)
        shutil.rmtree(self._receipts_dir, ignore_errors=True)

    def _args(self, **overrides):
        base = dict(
            message="dissident post",
            fee=None,
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
            no_receipts=True,
            nonce=None,
            leaf_index=None,
            server="127.0.0.1:9334",
            data_dir=None,
            urgency="normal",
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_auto_nonce_and_leaf_from_get_nonce_rpc(self):
        """When --nonce is omitted, query get_nonce and use the
        returned nonce + leaf_watermark for signing."""
        from messagechain import cli as mod

        rpc_calls = []

        def fake_rpc_call(host, port, method, params):
            rpc_calls.append((method, params))
            if method == "get_nonce":
                # Chain says alice is at nonce 5, leaf 8 -- a
                # divergent leaf_watermark > nonce is exactly the
                # case --leaf-index=nonce would have miscovered.
                # Both stay inside the conftest's tree_height=4
                # (num_leaves=16) so advance_to_leaf doesn't bail.
                return {"ok": True, "result": {"nonce": 5, "leaf_watermark": 8}}
            if method == "estimate_fee":
                return {"ok": True, "result": {"mempool_fee": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 100}}
            return {"ok": True, "result": {}}

        captured_tx = {}

        class _FakeClient:
            def __init__(self, *, endpoints, min_successes,
                         per_endpoint_timeout_s, request_receipts):
                self.endpoints = endpoints
                self.min_successes = min_successes

            def submit(self, tx):
                captured_tx["tx"] = tx
                return _fake_submit_result(tx, successes=3)

        with patch("client.rpc_call", fake_rpc_call), \
             patch("messagechain.network.submit_client.SubmitClient",
                   _FakeClient):
            buf = StringIO()
            with redirect_stdout(buf):
                # Explicit --fee here so this test isolates the
                # nonce/leaf path; the auto-fee path is covered by
                # test_auto_fee_resolves_when_fee_omitted below.
                rc = mod.cmd_send_multi_submit(self._args(fee=5000))
        self.assertEqual(rc, 0, buf.getvalue())

        # 1. The signing entity's tx must carry the AUTO-resolved
        #    nonce, not the default 0.
        self.assertIn("tx", captured_tx)
        self.assertEqual(captured_tx["tx"].nonce, 5)
        # 2. The tx's signature must use the chain's leaf_watermark
        #    (not nonce-as-fallback).  The signature.leaf_index field
        #    is the WOTS+ leaf actually consumed.
        self.assertEqual(captured_tx["tx"].signature.leaf_index, 8)
        # 3. get_nonce must have been called against the --server.
        methods = [m for (m, _) in rpc_calls]
        self.assertIn("get_nonce", methods)

    def test_auto_fee_resolves_when_fee_omitted(self):
        """When --fee is omitted, auto_fee must drive the picked fee
        through the existing helper (same path as cmd_send)."""
        from messagechain import cli as mod

        def fake_rpc_call(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "estimate_fee":
                return {"ok": True, "result": {"mempool_fee": 123}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 100}}
            return {"ok": True, "result": {}}

        captured_tx = {}

        class _FakeClient:
            def __init__(self, **kw):
                self.min_successes = kw.get("min_successes", 1)
            def submit(self, tx):
                captured_tx["tx"] = tx
                return _fake_submit_result(tx, successes=3)

        # Patch auto_fee to a sentinel value so the test pins the
        # call chain (auto_fee was called -> its return wins).
        with patch("client.rpc_call", fake_rpc_call), \
             patch("messagechain.network.submit_client.SubmitClient",
                   _FakeClient), \
             patch("messagechain.economics.auto_fee.auto_fee",
                   return_value=9999):
            buf = StringIO()
            with redirect_stdout(buf):
                rc = mod.cmd_send_multi_submit(self._args())
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(captured_tx["tx"].fee, 9999)

    def test_explicit_fee_overrides_auto_pick(self):
        """The override path must still work — a user who passes
        --fee 5000 must get fee=5000 regardless of auto-pick."""
        from messagechain import cli as mod

        def fake_rpc_call(host, port, method, params):
            if method == "get_nonce":
                return {"ok": True, "result": {"nonce": 0, "leaf_watermark": 0}}
            if method == "get_chain_info":
                return {"ok": True, "result": {"height": 100}}
            return {"ok": True, "result": {}}

        captured_tx = {}

        class _FakeClient:
            def __init__(self, **kw):
                self.min_successes = kw.get("min_successes", 1)
            def submit(self, tx):
                captured_tx["tx"] = tx
                return _fake_submit_result(tx, successes=3)

        with patch("client.rpc_call", fake_rpc_call), \
             patch("messagechain.network.submit_client.SubmitClient",
                   _FakeClient):
            buf = StringIO()
            with redirect_stdout(buf):
                rc = mod.cmd_send_multi_submit(self._args(fee=5000))
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(captured_tx["tx"].fee, 5000)


class TestReadmeMentionsSendMulti(unittest.TestCase):
    """README must point users to the censorship-resistance escape
    hatch — without a doc mention, the protocol's structural
    defense against validator collusion has no usable surface."""

    def test_readme_mentions_send_multi(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        readme = os.path.join(repo_root, "README.md")
        with open(readme, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn(
            "send-multi", src,
            "README must reference the multi-validator submission CLI; "
            "without it, the censorship-resistance defense is invisible "
            "to users reaching the project from the README.",
        )


if __name__ == "__main__":
    unittest.main()
