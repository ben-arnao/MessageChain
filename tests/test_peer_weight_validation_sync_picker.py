"""Sync-target picker must filter on the validated-weight flag too.

Audit finding: ``ChainSyncer._maybe_validate_peer_weight`` flips
``PeerSyncInfo.peer_weight_evidence_validated`` only after the peer
has delivered headers whose computed cumulative weight matches their
handshake claim within ±5% (see ``test_peer_weight_verification.py``).
The recent fix (commit ``bb7af14``) consults that flag inside
``Node._minority_fork_likely`` — but ``ChainSyncer.get_best_sync_peer``
still ranks candidates by the *unverified* handshake fields, so a
sybil cluster that wins the picker can still force IBD bandwidth burn
until ``SYNC_STALE_TIMEOUT`` punts them.

Fix shipped here (Option B — graceful fallback): the picker prefers
peers whose flag is True; if no validated peer is available it falls
back to the unvalidated path BUT logs an explicit
"syncing against unvalidated peer X — bandwidth/eclipse risk"
warning so the operator/log audit can see the fallback was hit.
``needs_sync`` stays as it is (bootstrap path needs to work); the
verified-vs-unverified split happens in the picker, which is the
choke point.
"""

import logging
import unittest
from unittest.mock import MagicMock

from messagechain.network.sync import (
    ChainSyncer,
    PeerSyncInfo,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _make_syncer(*, our_height: int = 0):
    """Build a ChainSyncer with a blockchain mock and offense capture."""
    bc = MagicMock()
    bc.height = our_height
    bc.get_latest_block.return_value = None
    bc.has_block.return_value = False
    bc.supply = MagicMock()
    bc.supply.staked = {}
    bc.fork_choice = MagicMock()
    bc.fork_choice.get_best_tip.return_value = None
    syncer = ChainSyncer(
        blockchain=bc,
        get_peer_writer=lambda _a: None,
        on_peer_offense=lambda *_a, **_kw: None,
    )
    return syncer


def _add_peer(
    syncer: ChainSyncer,
    addr: str,
    *,
    height: int,
    weight: int,
    validated: bool,
):
    """Inject a PeerSyncInfo with a controllable validated flag."""
    info = PeerSyncInfo(
        peer_address=addr,
        chain_height=height,
        best_block_hash="",
        cumulative_weight=weight,
    )
    info.peer_weight_evidence_validated = validated
    syncer.peer_heights[addr] = info


# --------------------------------------------------------------------------
# get_best_sync_peer — validated-flag preference + graceful fallback
# --------------------------------------------------------------------------


class TestGetBestSyncPeerValidatedFlag(unittest.TestCase):

    def test_get_best_sync_peer_prefers_validated_peer_over_unvalidated(self):
        """Two peers above our tip; one validated, one not — pick validated."""
        syncer = _make_syncer(our_height=10)
        _add_peer(syncer, "honest", height=20, weight=10_000, validated=True)
        _add_peer(syncer, "liar", height=25, weight=20_000, validated=False)
        self.assertEqual(syncer.get_best_sync_peer(), "honest")

    def test_get_best_sync_peer_filters_unvalidated_when_validated_available(self):
        """3 peers above our tip; validated one wins regardless of unvalidated
        peers' (potentially inflated) chain_height/weight claims."""
        syncer = _make_syncer(our_height=10)
        _add_peer(syncer, "liar1", height=999, weight=99_000_000, validated=False)
        _add_peer(syncer, "honest", height=15, weight=10_000, validated=True)
        _add_peer(syncer, "liar2", height=500, weight=50_000_000, validated=False)
        self.assertEqual(syncer.get_best_sync_peer(), "honest")

    def test_get_best_sync_peer_falls_back_to_unvalidated_when_none_validated(
        self,
    ):
        """Fresh-IBD scenario: no validated peers at all.

        Option B (graceful fallback): the picker still returns *some* peer so
        bootstrap can make progress, but the call MUST emit a warning that
        the operator/audit log can see.  This preserves liveness on a
        brand-new node while making the eclipse/bandwidth risk visible.
        """
        syncer = _make_syncer(our_height=0)
        _add_peer(syncer, "p1", height=10, weight=10_000, validated=False)
        _add_peer(syncer, "p2", height=20, weight=20_000, validated=False)

        with self.assertLogs(
            "messagechain.network.sync", level=logging.WARNING,
        ) as captured:
            picked = syncer.get_best_sync_peer()

        # Some peer is returned (bootstrap liveness)
        self.assertIn(picked, {"p1", "p2"})
        # Tallest unvalidated peer wins on fallback
        self.assertEqual(picked, "p2")
        # Warning about unvalidated fallback is logged
        self.assertTrue(
            any(
                "unvalidated" in rec.getMessage().lower()
                and picked in rec.getMessage()
                for rec in captured.records
            ),
            f"expected unvalidated-fallback warning naming {picked}; "
            f"got {[r.getMessage() for r in captured.records]}",
        )

    def test_get_best_sync_peer_returns_none_when_no_peers(self):
        """Empty peer set — returns None as today."""
        syncer = _make_syncer(our_height=10)
        self.assertIsNone(syncer.get_best_sync_peer())

    def test_lying_unvalidated_peer_does_not_outrank_honest_validated_peer(self):
        """The headline regression: sybil claims 4× weight + 100 blocks ahead
        but is unvalidated; honest validated peer claims 1× weight + 1 block
        ahead — honest wins."""
        syncer = _make_syncer(our_height=100)
        _add_peer(
            syncer, "honest",
            height=101, weight=10_000_000, validated=True,
        )
        _add_peer(
            syncer, "sybil",
            height=200, weight=40_000_000, validated=False,
        )
        self.assertEqual(syncer.get_best_sync_peer(), "honest")

    def test_get_best_sync_peer_returns_none_when_validated_peer_not_ahead(
        self,
    ):
        """Validated peer is at-or-below our tip — picker returns None
        regardless of any unvalidated peers ahead.  This preserves the
        existing 'don't sync from a peer who isn't ahead of us' invariant
        and avoids being tricked into syncing from an unvalidated peer
        just because the only validated peer is at-or-below us."""
        syncer = _make_syncer(our_height=100)
        _add_peer(syncer, "validated_short", height=99, weight=10_000,
                  validated=True)
        _add_peer(syncer, "unvalidated_tall", height=200, weight=40_000_000,
                  validated=False)
        # Validated peer is not ahead → no validated candidate; fallback
        # would otherwise pick unvalidated_tall, but the explicit
        # validated-not-ahead case should NOT fall back: the existence of
        # a validated peer at-or-below us is good evidence WE are at the
        # tip, not behind.  Returning None here matches the round-6
        # philosophy: prefer a stuck-but-safe sync state over chasing
        # an attacker chain.
        self.assertIsNone(syncer.get_best_sync_peer())


# --------------------------------------------------------------------------
# needs_sync — bootstrap path still works
# --------------------------------------------------------------------------


class TestNeedsSyncBootstrap(unittest.TestCase):

    def test_needs_sync_still_returns_true_in_bootstrap(self):
        """Fresh-IBD with only un-validated peers reporting higher chain
        heights — needs_sync must still return True so bootstrap can trigger
        start_sync, which in turn calls get_best_sync_peer (where the
        verified/unverified split happens)."""
        syncer = _make_syncer(our_height=0)
        _add_peer(syncer, "p1", height=10, weight=10_000, validated=False)
        _add_peer(syncer, "p2", height=20, weight=20_000, validated=False)
        self.assertTrue(syncer.needs_sync())

    def test_needs_sync_false_when_all_peers_at_or_below_us(self):
        """Sanity: regardless of validated flag, needs_sync stays False
        when no peer claims a height above ours.  Pre-existing semantics."""
        syncer = _make_syncer(our_height=100)
        _add_peer(syncer, "p1", height=100, weight=10_000, validated=True)
        _add_peer(syncer, "p2", height=99, weight=20_000, validated=False)
        self.assertFalse(syncer.needs_sync())


# --------------------------------------------------------------------------
# Regression: round-6 minority-fork filter intact
# --------------------------------------------------------------------------


class TestMinorityForkFilterStillIntact(unittest.TestCase):
    """Belt-and-braces regression: after the picker change, the
    _minority_fork_likely flag-filter must still reject unverified peers
    exactly as before.  This duplicates one assertion from
    test_peer_weight_verification.py to make the dependency explicit
    in this PR's test set."""

    def test_minority_fork_filter_still_intact(self):
        from messagechain.network.node import Node

        class _Stub:
            def __init__(self, our_height, our_weight):
                self.blockchain = MagicMock()
                self.blockchain.height = our_height
                self._w = our_weight
                self.syncer = MagicMock()
                self.syncer.peer_heights = {}

            def _current_cumulative_weight(self):
                return self._w

        node = _Stub(our_height=100, our_weight=1_000_000)
        for addr, w in [
            ("liar1", 4_000_000),
            ("liar2", 4_000_000),
            ("liar3", 4_000_000),
        ]:
            info = PeerSyncInfo(
                peer_address=addr, chain_height=100,
                best_block_hash="", cumulative_weight=w,
            )
            info.peer_weight_evidence_validated = False
            node.syncer.peer_heights[addr] = info

        # Round-6 invariant: unverified majority must NOT trip the fork
        # detector.  If a future picker change accidentally re-flips the
        # round-6 fix, this test fires.
        self.assertFalse(Node._minority_fork_likely(node))


if __name__ == "__main__":
    unittest.main()
