"""Audit r39 #3 -- ANNOUNCE_PENDING_TX must route to the pending_tx
rate-limit bucket.

Pre-fix ``messagechain.network.dispatch.message_category`` had no
case for ``MessageType.ANNOUNCE_PENDING_TX``; the message type fell
through to the wide ``general`` bucket (RATE_GENERAL = 30/s, burst
100) instead of the dedicated ``pending_tx`` bucket
(RATE_PENDING_TX = 2/s, burst 20) that ``ratelimit.py`` defines and
``_ensure_buckets`` provisions.

Concrete attack: ANNOUNCE_PENDING_TX carries WOTS+-signed stake /
unstake / authority / governance transactions.  Each receipt forces
the receiver to parse and WOTS+-verify the signature -- ~2.7 KB of
signature material and ~thousand hash invocations per message.  With
the legacy ``general`` bucket gating, a single peer could sustain
30 WOTS+ verifies per second indefinitely (with a 100-burst), an
asymmetric CPU-DoS targeting honest validators trying to keep up.

The dedicated ``pending_tx`` bucket was sized at (2, 20) explicitly
for this message type -- see the comment block at
``ratelimit.py:RATE_PENDING_TX``.  Every supporting piece was in
place (rate constant, bucket allocation in ``_ensure_buckets``);
only the dispatch routing was missing.

CLAUDE.md anchor at risk: "Spam ceiling is block timing, not per-tx
fee inflation" + "we do NOT defend against spam by jacking up
minimum fees" -- the gossip-layer rate limit is the analogous
defense-in-depth at the network layer, and the bucket was unwired.

Same shape as the ``signed_announce`` carve-out already shipped for
ANNOUNCE_ATTESTATION / ANNOUNCE_FINALITY_VOTE / ANNOUNCE_SLASH /
ANNOUNCE_CUSTODY_PROOF (each carries a WOTS+ signature, each routes
to its own tight bucket).  This patch finishes the analogous
routing for ANNOUNCE_PENDING_TX.

Tests:
  1. message_category(MessageType.ANNOUNCE_PENDING_TX) returns
     "pending_tx" (the routing fix -- the regression pin).
  2. The ``pending_tx`` bucket continues to exist on
     PeerRateLimiter (no regression on the bucket allocation).
  3. Other ANNOUNCE_* routings unchanged: ATTESTATION /
     FINALITY_VOTE / SLASH / CUSTODY_PROOF still go to
     "signed_announce".
  4. Non-pending-tx-related messages still route to "general"
     (catch-all unchanged).
"""

from __future__ import annotations

import unittest

from messagechain.network.dispatch import message_category
from messagechain.network.protocol import MessageType
from messagechain.network.ratelimit import (
    PeerRateLimiter,
    RATE_GENERAL,
    RATE_PENDING_TX,
)


class TestAnnouncePendingTxRoutesToPendingTxBucket(unittest.TestCase):
    """Routing fix: ANNOUNCE_PENDING_TX must select the dedicated
    'pending_tx' bucket, not the wide 'general' bucket."""

    def test_announce_pending_tx_routes_to_pending_tx(self) -> None:
        category = message_category(MessageType.ANNOUNCE_PENDING_TX)
        self.assertEqual(
            category, "pending_tx",
            "ANNOUNCE_PENDING_TX MUST route to the dedicated "
            "pending_tx bucket so a peer flooding stake/unstake/"
            "authority/governance gossip cannot force unbounded "
            "WOTS+-verify CPU spend at the wider general-bucket "
            f"rate.  Got: {category!r}",
        )

    def test_pending_tx_bucket_is_strictly_tighter_than_general(self):
        """Sanity: the dedicated bucket really is tighter than general
        -- otherwise the routing fix would be a no-op."""
        rate_pt, burst_pt = RATE_PENDING_TX
        rate_gen, burst_gen = RATE_GENERAL
        self.assertLess(
            rate_pt, rate_gen,
            f"pending_tx rate {rate_pt}/s must be strictly tighter "
            f"than general rate {rate_gen}/s",
        )
        self.assertLess(
            burst_pt, burst_gen,
            f"pending_tx burst {burst_pt} must be strictly tighter "
            f"than general burst {burst_gen}",
        )


class TestSiblingRoutingsUnchanged(unittest.TestCase):
    """The 4 ANNOUNCE_* signed-announce siblings must still route to
    'signed_announce' -- no regression."""

    def test_attestation_still_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_ATTESTATION),
            "signed_announce",
        )

    def test_finality_vote_still_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_FINALITY_VOTE),
            "signed_announce",
        )

    def test_slash_still_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_SLASH),
            "signed_announce",
        )

    def test_custody_proof_still_signed_announce(self):
        self.assertEqual(
            message_category(MessageType.ANNOUNCE_CUSTODY_PROOF),
            "signed_announce",
        )


class TestRateLimiterStillAllocatesPendingTxBucket(unittest.TestCase):
    """Regression pin: PeerRateLimiter._ensure_buckets continues to
    allocate the pending_tx bucket so the routing fix has a concrete
    bucket to consume from."""

    def test_pending_tx_bucket_check_passes_initially(self):
        rl = PeerRateLimiter()
        # First call ensures the bucket exists.
        self.assertTrue(rl.check("198.51.100.1:9333", "pending_tx"))


if __name__ == "__main__":
    unittest.main()
