"""Tests for the ``ChainSyncer`` fork-resolution path (1.51.0).

Background -- 2026-05-03 incident: after the ban auto-clear restored
P2P peering between validator-1 and validator-2 (both having minted
~5 independent blocks during the partition), v1's IBD got stuck in a
tight retry loop:

    Starting IBD: our height=1354, target=1359, peer=v2
    Header chain broken at block #1354
    [10s later, identical retry]
    ...

The original IBD code in ``ChainSyncer.handle_headers_response`` only
handles the linear "peer's chain extends ours" case.  When the peer's
first header doesn't extend the local tip, it logs "Header chain
broken" and aborts -- with no fallback to walk back, find the common
ancestor, and feed the divergent chain through ``add_block``'s
existing fork-storage + ``_reorganize`` machinery.  The result was a
permanent stall on the recovering node despite the peer having a
strictly heavier chain.

The 1.51.0 fix adds ``_start_fork_resolution`` /
``_handle_fork_resolution_response`` paths that:

  * Probe back from the divergence point in doubling lookback windows.
  * Walk the response to find the LAST height whose hash matches our
    local chain (= common ancestor) and the FIRST height that diverges
    (= start of the competing chain).
  * Continue forward until headers covering up to the peer's claimed
    tip are collected.
  * Hand the competing-chain block hashes to ``_request_next_blocks``;
    each block downloaded is applied via ``add_block``, which stores
    fork blocks via the existing fork-choice path and triggers
    ``_reorganize`` automatically when the fork outweighs canonical.

These tests exercise the syncer's fork-resolution methods directly
with a stubbed blockchain so the behaviour can be pinned without
spinning up a full two-validator network at every assertion.
"""

from __future__ import annotations

import asyncio
import unittest
from dataclasses import dataclass, field
from unittest.mock import MagicMock

from messagechain.network.sync import (
    ChainSyncer,
    FORK_LOOKBACK_INITIAL,
    FORK_LOOKBACK_CAP,
    FORK_RESOLUTION_MAX_RETRIES,
    HEADERS_BATCH_SIZE,
    SyncState,
    PeerSyncInfo,
)


# ─── Stubs ───────────────────────────────────────────────────────────


@dataclass
class StubBlock:
    block_number: int
    block_hash: bytes


@dataclass
class StubBlockchain:
    """Minimum surface ``ChainSyncer`` reads from.  Hash convention:
    canonical block at height H gets ``b"L" + H.to_bytes(31, 'big')``;
    competing fork blocks (per the peer) get ``b"P" + H.to_bytes(...)``.
    Common ancestor exists on both."""
    height: int
    common_ancestor_height: int
    sent_messages: list = field(default_factory=list)

    def _hash_for(self, height: int, side: str) -> bytes:
        # side="L" for our local chain, "P" for the peer's competing chain.
        # Below the common ancestor, both sides match.
        if height <= self.common_ancestor_height:
            side = "L"
        return side.encode() + height.to_bytes(31, "big")

    def get_block(self, height: int):
        if height < 0 or height > self.height:
            return None
        return StubBlock(
            block_number=height,
            block_hash=self._hash_for(height, "L"),
        )

    def get_latest_block(self):
        return self.get_block(self.height)

    def has_block(self, block_hash: bytes) -> bool:
        # Linear scan over our local chain.  Fast enough for tests.
        for h in range(self.height + 1):
            if self.get_block(h).block_hash == block_hash:
                return True
        return False

    def add_block(self, block):
        # Stub: just record + claim success.  Real Blockchain.add_block
        # routes to the fork-storage + _reorganize path; this stub
        # collects which competing blocks were applied so the test can
        # assert the sync code FED them in.
        self.sent_messages.append(("add_block", block))
        return True, "stub"


def _peer_header(height: int, common_ancestor_height: int):
    """Header dict matching the wire shape ``ChainSyncer`` consumes."""
    if height <= common_ancestor_height:
        side = "L"
    else:
        side = "P"
    block_hash = (side.encode() + height.to_bytes(31, "big")).hex()
    if height == 0:
        prev_hash = ("\x00" * 32).encode().hex()
    else:
        prev_side = (
            "L" if height - 1 <= common_ancestor_height else "P"
        )
        prev_hash = (
            prev_side.encode() + (height - 1).to_bytes(31, "big")
        ).hex()
    return {
        "block_number": height,
        "block_hash": block_hash,
        "prev_hash": prev_hash,
    }


# ─── Tests ───────────────────────────────────────────────────────────


class TestForkResolutionWalkBack(unittest.IsolatedAsyncioTestCase):
    """Exercise ``_start_fork_resolution`` and
    ``_handle_fork_resolution_response`` end-to-end with a stubbed
    blockchain + peer.  The test fixture mirrors the 2026-05-03 prod
    state: local at height 1354, peer at 1359, common ancestor at
    1346 (8 blocks of local divergence + 13 blocks of peer divergence,
    or in tests a smaller version of the same shape)."""

    def setUp(self):
        # Smaller version of prod scenario: local at 20, peer at 25,
        # common ancestor at 15.  All numbers chosen so lookback=16
        # (the initial probe) covers the divergence.
        self.local_height = 20
        self.peer_height = 25
        self.common_ancestor_height = 15
        self.peer_addr = "10.0.0.99:9333"

        self.blockchain = StubBlockchain(
            height=self.local_height,
            common_ancestor_height=self.common_ancestor_height,
        )
        # Mock writer so _send_request_headers doesn't blow up.
        self.writer_calls = []

        async def _async_write(_writer, msg):
            # Capture the (start_height, count) the syncer requested so
            # the test can assert the walk-back probe was correct.
            self.writer_calls.append(msg.payload)

        # Patch write_message in the sync module.
        import messagechain.network.sync as sync_mod
        self._orig_write_message = sync_mod.write_message
        sync_mod.write_message = _async_write
        self.addCleanup(
            lambda: setattr(sync_mod, "write_message", self._orig_write_message),
        )

        def _get_writer(_addr):
            return (MagicMock(), MagicMock())

        self.syncer = ChainSyncer(
            blockchain=self.blockchain,
            get_peer_writer=_get_writer,
        )
        # Tell the syncer about the peer with a HIGHER cumulative weight
        # than our own.  Without this, _peer_outweighs_local refuses to
        # start fork resolution (no point chasing a lighter chain).
        self.syncer.peer_heights[self.peer_addr] = PeerSyncInfo(
            peer_address=self.peer_addr,
            chain_height=self.peer_height,
            best_block_hash=("P".encode() + self.peer_height.to_bytes(31, "big")).hex(),
            cumulative_weight=10**12,  # well above our local weight
        )
        # Stub _our_cumulative_weight to a small number so the gate
        # passes without spinning up the real consensus stack.
        self.syncer._our_cumulative_weight = lambda: 0

    async def test_initial_probe_uses_initial_lookback(self):
        """First fork-resolution probe must walk back FORK_LOOKBACK_INITIAL
        below the divergence point."""
        # Simulate the trigger: handle_headers_response detected a
        # divergence at block 16 (one past the common ancestor at 15).
        await self.syncer._start_fork_resolution(self.peer_addr, 16)

        self.assertTrue(self.syncer._fork_resolution_active)
        self.assertEqual(self.syncer._fork_resolution_lookback, FORK_LOOKBACK_INITIAL)
        self.assertEqual(self.syncer._fork_resolution_retries, 0)
        self.assertEqual(len(self.writer_calls), 1)
        # Probe should start at max(0, 16 - 16 - 1) = 0 in this fixture.
        self.assertEqual(self.writer_calls[0]["start_height"], 0)
        # Count must include lookback + headroom.
        self.assertGreaterEqual(
            self.writer_calls[0]["count"],
            FORK_LOOKBACK_INITIAL,
        )

    async def test_response_locates_common_ancestor(self):
        """When the response shows headers matching local up through the
        ancestor and diverging after, the syncer must:
          * recognize the ancestor
          * extract competing-chain headers
          * either fetch more competing headers OR transition to block
            download (depending on whether the peer's tip was reached)."""
        await self.syncer._start_fork_resolution(self.peer_addr, 16)
        # Simulate v2's response: headers from height 0 through 25.
        # 0..15 match our local hashes (common up to ancestor at 15).
        # 16..25 are the peer's divergent chain.
        response = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(0, 26)
        ]
        # Confirm fork-resolution is active so handle_headers_response
        # routes through the fork path.
        self.syncer.state = SyncState.SYNCING_HEADERS
        await self.syncer.handle_headers_response(response, self.peer_addr)

        # Competing headers should be exactly heights 16..25 (10 blocks).
        competing = self.syncer._fork_resolution_competing_headers
        self.assertEqual(
            [h["block_number"] for h in competing],
            list(range(16, 26)),
            "fork resolution must extract heights AFTER the common "
            "ancestor as the competing chain",
        )
        # Since competing chain reaches peer's tip (25), syncer must
        # have transitioned to SYNCING_BLOCKS.
        self.assertEqual(self.syncer.state, SyncState.SYNCING_BLOCKS)
        # blocks_needed must be the competing block hashes.
        self.assertEqual(
            len(self.syncer.blocks_needed), len(competing),
            "every competing header must be queued for block download",
        )

    async def test_lookback_doubles_when_too_shallow(self):
        """If the entire probe response matches our local chain, the
        divergence is later than the lookback covered.  The syncer
        must double the lookback and re-probe, not abort."""
        # Construct a fixture where divergence is at height 50 but
        # local + peer agree through 49.  Lookback=16 from 50 is 34;
        # probe returns heights 33..49 -- ALL match local.
        self.local_height = 60
        self.common_ancestor_height = 49
        self.peer_height = 65
        self.blockchain.height = self.local_height
        self.blockchain.common_ancestor_height = self.common_ancestor_height

        await self.syncer._start_fork_resolution(self.peer_addr, 50)
        # Probe should have requested headers starting at
        # max(0, 50 - 16 - 1) = 33.
        first_probe = self.writer_calls[0]
        self.assertEqual(first_probe["start_height"], 33)

        # Response: ALL headers in range match local (33..49).
        # Note: the response stops at the common_ancestor_height because
        # the stub fixture's "P" hashes only kick in past it -- but the
        # peer in the real protocol returns its own chain, which is
        # local up through the ancestor.  For this test we feed back
        # heights 33..49, all matching local.
        response = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(33, 50)
        ]
        self.syncer.state = SyncState.SYNCING_HEADERS
        await self.syncer.handle_headers_response(response, self.peer_addr)

        # Lookback must have doubled.
        self.assertEqual(
            self.syncer._fork_resolution_lookback,
            FORK_LOOKBACK_INITIAL * 2,
            "shallow probe must double the lookback for the next round",
        )
        # Retry counter must have incremented.
        self.assertEqual(self.syncer._fork_resolution_retries, 1)
        # A second probe must have been issued (start lower).
        self.assertEqual(len(self.writer_calls), 2)

    async def test_max_retries_bounds_unbounded_probing(self):
        """A peer that keeps returning matching headers (e.g. lying or
        on an actually-identical chain) cannot pin the syncer in an
        infinite walk-back loop.  After FORK_RESOLUTION_MAX_RETRIES,
        the syncer abandons + resets."""
        # Force the max-retry guard by manually setting retries to
        # the cap minus one and triggering one more call.
        self.syncer._fork_resolution_active = True
        self.syncer._fork_resolution_peer = self.peer_addr
        self.syncer._fork_resolution_lookback = FORK_LOOKBACK_INITIAL
        self.syncer._fork_resolution_retries = FORK_RESOLUTION_MAX_RETRIES

        await self.syncer._start_fork_resolution(self.peer_addr, 100)
        # The retry counter incremented past the cap on entry; the
        # method must have abandoned + reset rather than sending another
        # probe.
        self.assertFalse(self.syncer._fork_resolution_active)
        self.assertEqual(self.syncer.state, SyncState.IDLE)


class TestForkResolutionContinuation(unittest.IsolatedAsyncioTestCase):
    """Once the common ancestor is located, subsequent forward-fetch
    responses must be treated as competing-chain extensions, NOT as
    fresh ancestor probes.

    Regression: the first 1.51.0 deploy on validator-1 found the
    ancestor at height 1333 and collected competing headers up to
    1360, then asked v2 for headers from 1361.  v2 returned an empty
    response (it was at height 1361, so anything above its tip is
    empty).  The original implementation treated that as "lookback
    too shallow" and retried with a deeper probe -- which kept
    finding the same ancestor at 1333 and re-collecting the same
    competing headers, doubling the buffer on every iteration until
    FORK_RESOLUTION_MAX_RETRIES exhausted.

    The fix routes responses through different sub-handlers based on
    whether ``competing_headers`` is already populated:
      - empty: initial probe path (walk back, doubling)
      - non-empty: continuation path (extend or done)
    """

    def setUp(self):
        self.local_height = 20
        self.peer_height = 30
        self.common_ancestor_height = 15
        self.peer_addr = "10.0.0.99:9333"

        self.blockchain = StubBlockchain(
            height=self.local_height,
            common_ancestor_height=self.common_ancestor_height,
        )
        self.writer_calls = []

        async def _async_write(_writer, msg):
            self.writer_calls.append(msg.payload)

        import messagechain.network.sync as sync_mod
        self._orig_write_message = sync_mod.write_message
        sync_mod.write_message = _async_write
        self.addCleanup(
            lambda: setattr(sync_mod, "write_message", self._orig_write_message),
        )

        self.syncer = ChainSyncer(
            blockchain=self.blockchain,
            get_peer_writer=lambda _a: (MagicMock(), MagicMock()),
        )
        self.syncer.peer_heights[self.peer_addr] = PeerSyncInfo(
            peer_address=self.peer_addr,
            chain_height=self.peer_height,
            best_block_hash=("P".encode() + self.peer_height.to_bytes(31, "big")).hex(),
            cumulative_weight=10**12,
        )
        self.syncer._our_cumulative_weight = lambda: 0

    async def test_continuation_empty_response_means_done_not_retry(self):
        """An empty continuation response = peer's tip reached.  The
        syncer must transition to block download, NOT loop back into
        the initial-probe retry path (which is the prod bug)."""
        # Pre-populate state as if initial probe already found ancestor
        # and collected up to height 25 (5 short of peer's tip 30).
        self.syncer._fork_resolution_active = True
        self.syncer._fork_resolution_peer = self.peer_addr
        self.syncer._fork_resolution_lookback = FORK_LOOKBACK_INITIAL
        self.syncer._fork_resolution_competing_headers = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(16, 26)
        ]
        self.syncer.state = SyncState.SYNCING_HEADERS
        retries_before = self.syncer._fork_resolution_retries

        # Empty response (peer has nothing past its current tip).
        await self.syncer.handle_headers_response([], self.peer_addr)

        # MUST NOT have incremented retry counter (would mean it
        # routed through the initial-probe path).
        self.assertEqual(
            self.syncer._fork_resolution_retries, retries_before,
            "empty continuation response must NOT trigger lookback "
            "doubling -- it means peer's tip reached",
        )
        # MUST have transitioned to block download.
        self.assertEqual(self.syncer.state, SyncState.SYNCING_BLOCKS)
        self.assertEqual(
            len(self.syncer.blocks_needed),
            len(self.syncer._fork_resolution_competing_headers),
        )

    async def test_continuation_extends_competing_chain(self):
        """A non-empty continuation response that properly chains from
        the last collected header must be appended to the competing
        chain.  After this we either continue forward or transition
        depending on peer's tip."""
        self.syncer._fork_resolution_active = True
        self.syncer._fork_resolution_peer = self.peer_addr
        self.syncer._fork_resolution_lookback = FORK_LOOKBACK_INITIAL
        # Started with competing 16..25.
        self.syncer._fork_resolution_competing_headers = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(16, 26)
        ]
        self.syncer.state = SyncState.SYNCING_HEADERS

        # Response: continuation 26..30 (covers up to peer's tip).
        response = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(26, 31)
        ]
        await self.syncer.handle_headers_response(response, self.peer_addr)

        # All 15 headers (16..30) collected.
        self.assertEqual(
            len(self.syncer._fork_resolution_competing_headers), 15,
        )
        # Peer's tip reached -> SYNCING_BLOCKS.
        self.assertEqual(self.syncer.state, SyncState.SYNCING_BLOCKS)

    async def test_continuation_with_gap_is_rejected(self):
        """A continuation response whose first header doesn't directly
        follow the last collected one is malformed; abort cleanly
        rather than splicing a hole into the competing chain."""
        self.syncer._fork_resolution_active = True
        self.syncer._fork_resolution_peer = self.peer_addr
        self.syncer._fork_resolution_lookback = FORK_LOOKBACK_INITIAL
        # Last collected ends at height 25.
        self.syncer._fork_resolution_competing_headers = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(16, 26)
        ]
        self.syncer.state = SyncState.SYNCING_HEADERS

        # Bogus response: skips height 26, returns 27 first.
        response = [
            _peer_header(h, self.common_ancestor_height)
            for h in range(27, 31)
        ]
        offenses_recorded = []
        self.syncer._on_peer_offense = (
            lambda addr, points, reason:
                offenses_recorded.append((addr, points, reason))
        )

        await self.syncer.handle_headers_response(response, self.peer_addr)

        # Resolution aborted, peer recorded an offense.
        self.assertFalse(self.syncer._fork_resolution_active)
        self.assertEqual(self.syncer.state, SyncState.IDLE)
        self.assertTrue(any(
            "continuation_gap" in r[2] for r in offenses_recorded
        ))


class TestPeerOutweighsLocalGate(unittest.TestCase):
    """The fork-resolution trigger must only fire when the peer's
    claimed weight exceeds ours.  Otherwise a sybil could redirect us
    onto a divergent-but-lighter chain and burn our bandwidth."""

    def _make_syncer(self, our_weight: int, peer_weight: int):
        bc = StubBlockchain(height=10, common_ancestor_height=5)
        syncer = ChainSyncer(blockchain=bc, get_peer_writer=lambda _a: None)
        syncer._our_cumulative_weight = lambda: our_weight
        syncer.peer_heights["10.0.0.99:9333"] = PeerSyncInfo(
            peer_address="10.0.0.99:9333",
            chain_height=20,
            cumulative_weight=peer_weight,
        )
        return syncer

    def test_heavier_peer_passes_gate(self):
        syncer = self._make_syncer(our_weight=100, peer_weight=200)
        self.assertTrue(syncer._peer_outweighs_local("10.0.0.99:9333"))

    def test_equal_peer_does_not_pass_gate(self):
        """Equal weight = no work to do; either we agree on the chain
        already, or fork-choice tiebreak handles it elsewhere."""
        syncer = self._make_syncer(our_weight=100, peer_weight=100)
        self.assertFalse(syncer._peer_outweighs_local("10.0.0.99:9333"))

    def test_lighter_peer_does_not_pass_gate(self):
        syncer = self._make_syncer(our_weight=200, peer_weight=100)
        self.assertFalse(syncer._peer_outweighs_local("10.0.0.99:9333"))

    def test_unknown_peer_does_not_pass_gate(self):
        bc = StubBlockchain(height=10, common_ancestor_height=5)
        syncer = ChainSyncer(blockchain=bc, get_peer_writer=lambda _a: None)
        self.assertFalse(syncer._peer_outweighs_local("10.0.0.99:9333"))


class TestForkResolutionResetState(unittest.TestCase):
    """``_reset_fork_resolution`` must clear EVERY fork-resolution
    field.  A leak (e.g. forgetting to reset competing_headers) would
    cause the next sync round to apply stale headers."""

    def test_reset_clears_all_fields(self):
        bc = StubBlockchain(height=10, common_ancestor_height=5)
        syncer = ChainSyncer(blockchain=bc, get_peer_writer=lambda _a: None)
        syncer._fork_resolution_active = True
        syncer._fork_resolution_peer = "10.0.0.99:9333"
        syncer._fork_resolution_lookback = 256
        syncer._fork_resolution_retries = 3
        syncer._fork_resolution_competing_headers = [{"x": "y"}]

        syncer._reset_fork_resolution()
        self.assertFalse(syncer._fork_resolution_active)
        self.assertEqual(syncer._fork_resolution_peer, "")
        self.assertEqual(syncer._fork_resolution_lookback, 0)
        self.assertEqual(syncer._fork_resolution_retries, 0)
        self.assertEqual(syncer._fork_resolution_competing_headers, [])


if __name__ == "__main__":
    unittest.main()
