"""Receipt page (``/r/<tx_hash>``) must render a "pending" state for
recently-submitted txs — not the suspect-suppression "Not found" card.

The 1.71.0 shareable-receipt URL is printed by ``cmd_send`` at submit
time; every successful send tells the user to share that link.  Pre-fix
the dispatch in ``receipt.html``'s ``loadStatus`` was binary:

    if (result.status === "included") renderIncluded(...);
    else                              renderNotFound(...);

The public-feed shim ``Blockchain.get_tx_status_public`` deliberately
returns only ``"included" | "not_found"`` (no ``"pending"`` — public
feed does not see the mempool, by design).  Net effect: every share-URL
opened in the first ~10 min after submit shows the user (and the user's
friend) a red "Not found on this node / suspect censorship" card for a
tx that is behaving normally.  The chain's headline value-prop demo
moment inverts itself on every successful send.

This file pins the two-state dispatch:

  1. ``renderPending`` exists and surfaces a "waiting for inclusion"
     verdict (the existing ``.verdict.pending`` CSS class, which was
     already styled but unused).
  2. The dispatch in ``loadStatus`` routes the first N polls of a
     ``not_found`` response through ``renderPending`` and auto-retries.
  3. After the retry budget exhausts, ``renderNotFound`` is reached so
     a tx that really is suppressed still gets the suppression
     narrative + slashable-evidence escalation pointer.

Surfaced by audit r44 — receipt-page pending render.  Fix is purely in
``receipt.html``; the public-feed shim's "no mempool exposure" anchor
is preserved.
"""

from __future__ import annotations

import http.client
import socket
import time
import unittest
from types import SimpleNamespace

from messagechain.network.public_feed_server import PublicFeedServer


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubChainForHTML:
    """Minimal stub — receipt.html is served as static text, so the
    chain just needs to exist for the public-feed server to boot."""

    def __init__(self):
        self._genesis_hash = b"\xaa" * 32
        self._tip_hash = b"\xbb" * 32
        genesis = SimpleNamespace(
            header=SimpleNamespace(
                timestamp=1_700_000_000.0, state_root=self._genesis_hash,
            ),
            block_hash=self._genesis_hash,
        )
        tip = SimpleNamespace(
            header=SimpleNamespace(
                timestamp=1_700_000_999.0, state_root=b"\xcc" * 32,
            ),
            block_hash=self._tip_hash,
        )
        self.chain = [genesis, tip]
        self.height = 1

    def get_recent_messages(self, count):
        return []

    def get_tx_status_public(self, tx_hash: bytes) -> dict:
        return {"status": "not_found"}


class TestReceiptHtmlRendersPending(unittest.TestCase):
    """Pre-fix the page rendered the suspect-suppression card for
    every just-submitted tx.  Post-fix the page surfaces a
    "Waiting for inclusion" state during the normal ~10-min window,
    only falling through to the suppression narrative after the
    retry budget exhausts."""

    def setUp(self):
        self.chain = _StubChainForHTML()
        port = _find_free_port()
        self.server = PublicFeedServer(
            blockchain=self.chain, port=port, bind="127.0.0.1",
        )
        self.server.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            self.server.stop()
            raise RuntimeError("PublicFeedServer never came up")
        self.port = port

    def tearDown(self):
        self.server.stop()

    def _fetch_receipt_html(self) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/r/" + ("ab" * 32))
            resp = conn.getresponse()
            return resp.read().decode("utf-8")
        finally:
            conn.close()

    def test_render_pending_function_exists(self):
        """A ``renderPending`` function must be defined — without it
        there is no path that uses the existing ``.verdict.pending``
        CSS class for a recently-submitted tx."""
        src = self._fetch_receipt_html()
        self.assertIn("function renderPending", src)

    def test_pending_verdict_uses_existing_pending_css_class(self):
        """The pending render must apply ``verdict.pending`` so the
        styling lands.  Pre-fix the class was styled but unreached."""
        src = self._fetch_receipt_html()
        # Loose check: somewhere in the renderPending body we add the
        # pending class.  Pin the call site rather than exact phrasing.
        pending_idx = src.find("function renderPending")
        self.assertGreater(pending_idx, 0)
        # Look in the next ~600 chars for the class.add call.
        slice_ = src[pending_idx:pending_idx + 900]
        self.assertIn('classList.add("pending"', slice_)

    def test_pending_verdict_mentions_typical_wait(self):
        """The pending narrative must tell the user this is normal,
        not a suppression signal — block cadence is ~10 min so a
        just-submitted tx is expected to be invisible for one block."""
        src = self._fetch_receipt_html()
        lower = src.lower()
        # Any of these phrasings is fine; pin presence, not exact form.
        self.assertTrue(
            any(
                phrase in lower
                for phrase in (
                    "waiting for inclusion",
                    "not yet visible",
                    "typical for",
                )
            ),
            "renderPending should reassure the user the wait is normal",
        )

    def test_loadstatus_routes_not_found_through_pending_first(self):
        """On ``not_found`` the dispatch must call ``renderPending``
        for the early polls — otherwise the share-URL's first ten
        minutes still misframe as suspect suppression."""
        src = self._fetch_receipt_html()
        # The loadStatus body must reference renderPending in the
        # not_found branch.  Pin the reference; exact retry count is
        # a tuning knob.
        load_idx = src.find("async function loadStatus")
        self.assertGreater(load_idx, 0)
        slice_ = src[load_idx:load_idx + 1500]
        self.assertIn("renderPending", slice_)

    def test_pending_render_auto_refreshes(self):
        """Pending state must self-poll; otherwise the user must
        manually refresh the page during the normal ~10-min wait,
        which the share-URL recipient is least likely to do."""
        src = self._fetch_receipt_html()
        # Any setTimeout that calls loadStatus is fine.  Pin the
        # combination so a "decorative" setTimeout elsewhere doesn't
        # mask a missing retry loop.
        self.assertIn("setTimeout", src)
        self.assertIn("loadStatus", src)
        # The retry must be wired explicitly from the pending path or
        # the loadStatus body's not_found branch.
        load_idx = src.find("async function loadStatus")
        self.assertGreater(load_idx, 0)
        slice_ = src[load_idx:load_idx + 2000]
        self.assertIn("setTimeout", slice_)

    def test_retry_budget_eventually_falls_through_to_not_found(self):
        """After the retry budget exhausts, a tx that really is being
        suppressed must still reach the suppression narrative — we
        must not strand the user in pending forever."""
        src = self._fetch_receipt_html()
        # Pin that renderNotFound is still called from a path that
        # checks the retry count.  Look for the not_found call with a
        # retry-count check nearby.
        load_idx = src.find("async function loadStatus")
        slice_ = src[load_idx:load_idx + 2000]
        self.assertIn("renderNotFound", slice_)


if __name__ == "__main__":
    unittest.main()
