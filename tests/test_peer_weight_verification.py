"""Peer-claimed cumulative_weight must be verified against headers
the peer actually delivers, before letting the claim drive sync
decisions.

Audit finding: ``Node._minority_fork_likely`` consults
``syncer.peer_heights[*].cumulative_weight``, which is sourced from
the peer's handshake and only sanity-capped (``_accept_peer_weight``)
— never *verified*.  A sybil cluster filling >=2 outbound slots can
lie about ``cumulative_weight`` up to the cap; with 2+ such peers at
``chain_height == our_height`` reporting inflated weights, the
strict-majority test in ``_minority_fork_likely`` trips and schedules
``start_sync`` against attacker peers.  Cryptographic gates downstream
prevent chain corruption — the cost is liveness (IBD bandwidth burned
on round-trips against attacker chains).  Eclipse-amplifier on
small/young networks.

Fix: ``PeerSyncInfo`` carries a ``peer_weight_evidence_validated``
flag (default ``False``).  ``_minority_fork_likely`` filters its
candidate set to peers whose flag is ``True`` BEFORE running the
strict-majority test.  The flag is set ONLY after the peer has
successfully delivered headers whose computed cumulative weight
matches their handshake claim within tolerance (±5%, see rationale
in ``ChainSyncer._maybe_validate_peer_weight``).

Tolerance bounds rationale: the verification compares
``our_weight + sum(stake_weight(hdr) for hdr in delivered)`` against
the peer's claim.  ``compute_block_stake_weight`` uses live
``supply.staked`` rather than the per-block stake snapshot the peer
saw when they computed their claim, so small drift is expected on
healthy chains; ±5% absorbs that drift while still catching the
audit's 4× over-claim attack with margin to spare.
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from messagechain.network.sync import (
    ChainSyncer,
    PeerSyncInfo,
    SyncState,
    HEADERS_BATCH_SIZE,
)


# --------------------------------------------------------------------------
# Helpers shared by the suite
# --------------------------------------------------------------------------


class _NodeStub:
    """Minimal Node-shaped object for the unbound _minority_fork_likely call.

    Mirrors ``tests/test_node_minority_fork_detection.py`` so the two
    suites stay in lockstep on the fixture shape.
    """

    def __init__(self, our_height: int, our_weight: int):
        self.blockchain = MagicMock()
        self.blockchain.height = our_height
        self._our_weight = our_weight
        self.syncer = MagicMock()
        self.syncer.peer_heights = {}

    def _current_cumulative_weight(self) -> int:
        return self._our_weight

    def add_peer(
        self,
        addr: str,
        height: int,
        weight: int,
        validated: bool = False,
    ):
        info = PeerSyncInfo(
            peer_address=addr,
            chain_height=height,
            best_block_hash="",
            cumulative_weight=weight,
        )
        info.peer_weight_evidence_validated = validated
        self.syncer.peer_heights[addr] = info


def _detect(node) -> bool:
    """Bind _minority_fork_likely from the real Node class to the stub."""
    from messagechain.network.node import Node
    return Node._minority_fork_likely(node)


def _make_syncer(state: SyncState, *, our_height: int = 0,
                 staked: dict | None = None):
    """Build a ChainSyncer with a blockchain mock and offense capture list."""
    bc = MagicMock()
    bc.height = our_height
    bc.get_latest_block.return_value = None
    bc.has_block.return_value = False
    # supply.staked is consulted by the verification hook to compute
    # delivered-header weight contributions.  Empty dict + the
    # ``max(1, …)`` floor in compute_block_stake_weight means each
    # header contributes weight=1 by default.
    bc.supply = MagicMock()
    bc.supply.staked = staked if staked is not None else {}
    # fork_choice.get_best_tip is consulted via _current_cumulative_weight
    # in the live runtime; the syncer-level hook reads
    # blockchain.fork_choice.get_best_tip directly to be runtime-agnostic.
    bc.fork_choice = MagicMock()
    bc.fork_choice.get_best_tip.return_value = None
    offenses: list[tuple[str, int, str]] = []
    syncer = ChainSyncer(
        blockchain=bc,
        get_peer_writer=lambda _a: None,
        on_peer_offense=lambda addr, pts, reason: offenses.append(
            (addr, pts, reason)
        ),
    )
    syncer.state = state
    return syncer, offenses


def _make_header(block_number: int, prev_hash_hex: str, *,
                 proposer_id_hex: str | None = None) -> dict:
    """Build a minimal-but-valid header dict for handle_headers_response."""
    bh = f"{block_number:064x}"
    if proposer_id_hex is None:
        # Default to a deterministic 32-byte hex string so tests can
        # populate stakes for it explicitly.
        proposer_id_hex = "11" * 32
    return {
        "block_number": block_number,
        "prev_hash": prev_hash_hex,
        "block_hash": bh,
        "proposer_id": proposer_id_hex,
    }


# --------------------------------------------------------------------------
# 1) _minority_fork_likely must ignore unverified peers
# --------------------------------------------------------------------------


class TestMinorityForkLikelyGate(unittest.TestCase):

    def test_minority_fork_likely_ignores_unverified_peers(self):
        """3 peers all claim higher weight, none verified → returns False.

        This is the core regression: pre-fix, any 2 peers with
        unverified inflated weights would trip the heuristic and
        schedule a wasted start_sync.
        """
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000, validated=False)
        node.add_peer("p2", height=100, weight=2_500_000, validated=False)
        node.add_peer("p3", height=100, weight=3_000_000, validated=False)
        self.assertFalse(_detect(node))

    def test_minority_fork_likely_trips_with_verified_majority(self):
        """3 peers, 2 with verified higher weight → strict majority → True."""
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000, validated=True)
        node.add_peer("p2", height=100, weight=2_500_000, validated=True)
        node.add_peer("p3", height=100, weight=3_000_000, validated=False)
        self.assertTrue(_detect(node))

    def test_minority_fork_likely_unverified_peers_excluded_from_total(self):
        """Verification gate strips unverified peers from BOTH numerator and
        denominator. 1 verified heavy-weight peer alone is below the >=2
        corroborator floor, so we still don't trip — which is correct: one
        peer is insufficient evidence even if their claim is verified."""
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("p1", height=100, weight=2_000_000, validated=True)
        node.add_peer("p2", height=100, weight=2_500_000, validated=False)
        node.add_peer("p3", height=100, weight=3_000_000, validated=False)
        # Only p1 counts → < 2 corroborators → False.
        self.assertFalse(_detect(node))


# --------------------------------------------------------------------------
# 2) Header-batch validation hook flips the flag iff the peer's claim
#    is consistent with what they actually delivered.
# --------------------------------------------------------------------------


class TestHeaderBatchWeightValidation(unittest.TestCase):

    def _seed_peer_claim(self, syncer, peer_addr: str,
                         *, height: int, claimed_weight: int):
        """Simulate the handshake side of the bookkeeping."""
        syncer.update_peer_height(
            peer_addr, height, "", cumulative_weight=claimed_weight,
        )

    def test_header_batch_validation_sets_flag_on_consistent_peer(self):
        """Peer claims weight ~ matching what their headers compute to.

        With ``supply.staked`` empty, each header contributes weight=1
        (the bootstrap floor in ``compute_block_stake_weight``). A peer
        delivering N headers and claiming cumulative_weight=N is
        consistent → flag set to True.
        """
        peer = "1.2.3.4:9333"
        # Our height is 0, target tip will be at height N.
        n = 10
        syncer, offenses = _make_syncer(
            SyncState.SYNCING_HEADERS, our_height=0,
        )
        # Peer claims they're at height n with cumulative_weight=n
        # (matches per-header weight=1 floor).
        self._seed_peer_claim(syncer, peer, height=n, claimed_weight=n)
        syncer._sync_target_height = n
        syncer._current_sync_peer = peer

        # Build a header chain h_1..h_n linked by prev_hash.
        prev = "00" * 32
        headers = []
        for i in range(1, n + 1):
            hdr = _make_header(i, prev)
            headers.append(hdr)
            prev = hdr["block_hash"]

        # Final batch (len < HEADERS_BATCH_SIZE) so the syncer flips
        # state past the headers phase and runs the verification hook.
        asyncio.run(syncer.handle_headers_response(headers, peer))

        info = syncer.peer_heights[peer]
        self.assertTrue(
            getattr(info, "peer_weight_evidence_validated", False),
            f"flag should be True after consistent delivery (offenses={offenses})",
        )

    def test_header_batch_validation_rejects_lying_peer(self):
        """Peer claims 4× the weight they actually deliver → flag stays False."""
        peer = "5.6.7.8:9333"
        n = 10
        syncer, offenses = _make_syncer(
            SyncState.SYNCING_HEADERS, our_height=0,
        )
        # Claim is 4× the honest baseline of n=10.
        self._seed_peer_claim(syncer, peer, height=n, claimed_weight=4 * n)
        syncer._sync_target_height = n
        syncer._current_sync_peer = peer

        prev = "00" * 32
        headers = []
        for i in range(1, n + 1):
            hdr = _make_header(i, prev)
            headers.append(hdr)
            prev = hdr["block_hash"]

        asyncio.run(syncer.handle_headers_response(headers, peer))

        info = syncer.peer_heights[peer]
        self.assertFalse(
            getattr(info, "peer_weight_evidence_validated", True),
            "flag must remain False after over-claim is detected",
        )

    def test_header_batch_validation_within_tolerance_band(self):
        """Within ±5% of the claim is fine — small drift accepted.

        Per-header floor weight=1 × 100 headers = 100 delivered.
        Claim of 104 (4% high) sits inside the ±5% band → flag set.
        """
        peer = "9.9.9.9:9333"
        n = 100
        syncer, offenses = _make_syncer(
            SyncState.SYNCING_HEADERS, our_height=0,
        )
        self._seed_peer_claim(syncer, peer, height=n, claimed_weight=104)
        syncer._sync_target_height = n
        syncer._current_sync_peer = peer

        # Build a partial-batch (< HEADERS_BATCH_SIZE) so the verification
        # hook runs at end-of-headers transition.
        self.assertLess(n, HEADERS_BATCH_SIZE * 2)
        prev = "00" * 32
        headers = []
        for i in range(1, n + 1):
            hdr = _make_header(i, prev)
            headers.append(hdr)
            prev = hdr["block_hash"]

        asyncio.run(syncer.handle_headers_response(headers, peer))

        info = syncer.peer_heights[peer]
        self.assertTrue(
            getattr(info, "peer_weight_evidence_validated", False),
            f"4% drift must fall inside the ±5% tolerance (offenses={offenses})",
        )


# --------------------------------------------------------------------------
# 3) Headline regression: lying peers must NOT amplify DoS.
# --------------------------------------------------------------------------


class TestLyingPeerDosAmplification(unittest.TestCase):

    def test_lying_peer_does_not_amplify_dos(self):
        """3 sybil peers handshake with inflated weights at our height —
        none have delivered verifying headers — _minority_fork_likely
        must NOT trip → no start_sync gets queued from the heuristic.
        """
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        # Cap-bounded but unverified — pre-fix this trips the heuristic.
        node.add_peer("liar1", height=100, weight=4_000_000, validated=False)
        node.add_peer("liar2", height=100, weight=4_000_000, validated=False)
        node.add_peer("liar3", height=100, weight=4_000_000, validated=False)

        self.assertFalse(
            _detect(node),
            "minority-fork heuristic must not trip on unverified weight claims",
        )


# --------------------------------------------------------------------------
# 4) Honest path still works end-to-end.
# --------------------------------------------------------------------------


class TestNormalRecoveryPathStillWorks(unittest.TestCase):

    def test_normal_recovery_path_still_works(self):
        """Honest peer delivers consistent headers → flag flips → with
        a 2nd verified peer the heuristic correctly trips at our same
        height (the canonical minority-fork recovery contract).
        """
        # Step 1: honest peer delivers consistent headers — flag flips.
        peer = "10.0.0.1:9333"
        n = 12
        syncer, _offenses = _make_syncer(
            SyncState.SYNCING_HEADERS, our_height=0,
        )
        syncer.update_peer_height(peer, n, "", cumulative_weight=n)
        syncer._sync_target_height = n
        syncer._current_sync_peer = peer

        prev = "00" * 32
        headers = []
        for i in range(1, n + 1):
            hdr = _make_header(i, prev)
            headers.append(hdr)
            prev = hdr["block_hash"]
        asyncio.run(syncer.handle_headers_response(headers, peer))

        self.assertTrue(
            syncer.peer_heights[peer].peer_weight_evidence_validated,
            "honest peer's flag should be True after consistent delivery",
        )

        # Step 2: at our height, with two verified higher-weight peers,
        # _minority_fork_likely should trip — recovery contract intact.
        node = _NodeStub(our_height=100, our_weight=1_000_000)
        node.add_peer("h1", height=100, weight=2_000_000, validated=True)
        node.add_peer("h2", height=100, weight=2_500_000, validated=True)
        self.assertTrue(_detect(node))


if __name__ == "__main__":
    unittest.main()
