"""
Initial Block Download (IBD) and chain synchronization for MessageChain.

Inspired by Bitcoin's headers-first sync strategy:
1. Connect to peers and compare chain heights
2. Download block headers first (lightweight, fast to validate structure)
3. Validate header chain (prev_hash linkage, block numbers)
4. Download full blocks in batches for validated headers
5. Apply blocks to local chain

This allows new nodes to catch up to the network efficiently without
trusting any single peer for the full chain.

Sync states:
- IDLE: fully synced, processing new blocks normally
- SYNCING_HEADERS: downloading and validating headers
- SYNCING_BLOCKS: downloading full blocks for validated headers
- COMPLETE: sync finished, transitioning back to IDLE
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import messagechain.config
from messagechain.config import MIN_CUMULATIVE_STAKE_WEIGHT
from messagechain.consensus.checkpoint import WeakSubjectivityCheckpoint
from messagechain.validation import MAX_SANE_BLOCK_HEIGHT, parse_hex
from messagechain.core.block import Block, BlockHeader
from messagechain.network.ban import (
    OFFENSE_CHECKPOINT_VIOLATION,
    OFFENSE_INVALID_HEADERS,
    OFFENSE_PROTOCOL_VIOLATION,
)
from messagechain.network.protocol import (
    MessageType, NetworkMessage, write_message,
)

logger = logging.getLogger(__name__)

# Sync parameters
HEADERS_BATCH_SIZE = 100  # headers per request
BLOCKS_BATCH_SIZE = 10  # full blocks per request
SYNC_TIMEOUT = 30  # seconds to wait for a response
MAX_SYNC_PEERS = 3  # max peers to sync from simultaneously
SYNC_STALE_TIMEOUT = 60  # restart sync if stuck for this long


class SyncState(Enum):
    IDLE = "idle"
    SYNCING_HEADERS = "syncing_headers"
    SYNCING_BLOCKS = "syncing_blocks"
    COMPLETE = "complete"


@dataclass
class PeerSyncInfo:
    """Track what we know about a peer's chain."""
    peer_address: str
    chain_height: int
    best_block_hash: str = ""
    last_response_time: float = 0.0
    cumulative_weight: int = 0


class ChainSyncer:
    """
    Manages IBD and ongoing chain synchronization.

    Headers-first approach:
    1. Ask peers for their chain height
    2. Request headers starting from our tip
    3. Validate header chain structure
    4. Request full blocks for validated headers
    5. Apply blocks to local blockchain
    """

    def __init__(
        self,
        blockchain,
        get_peer_writer,
        trusted_checkpoints: list[WeakSubjectivityCheckpoint] | None = None,
        on_peer_offense: Callable[[str, int, str], None] | None = None,
    ):
        """
        Args:
            blockchain: The Blockchain instance to sync
            get_peer_writer: callable(address) -> (writer, peer) to get peer connection
            trusted_checkpoints: Optional list of weak-subjectivity checkpoints.
                During IBD, any header at a checkpoint's block_number whose hash
                does not match is rejected and the peer is penalized. This is the
                primary long-range-attack defense for PoS.
            on_peer_offense: Optional callback invoked as
                `on_peer_offense(peer_address, offense_points, reason)` when a
                sync-time misbehavior is detected (checkpoint mismatch, stall).
        """
        self.blockchain = blockchain
        self.get_peer_writer = get_peer_writer
        # Index checkpoints by block_number for O(1) lookup during header processing
        self._checkpoints: dict[int, WeakSubjectivityCheckpoint] = {
            cp.block_number: cp for cp in (trusted_checkpoints or [])
        }
        self._on_peer_offense = on_peer_offense or (lambda _a, _p, _r: None)
        self.state = SyncState.IDLE
        self.peer_heights: dict[str, PeerSyncInfo] = {}

        # Headers we've validated but don't have full blocks for
        self.pending_headers: list[dict] = []
        # Block hashes we need to download
        self.blocks_needed: list[bytes] = []
        # Blocks downloaded but not yet applied
        self.downloaded_blocks: dict[int, Block] = {}

        self._sync_start_time = 0.0
        self._last_progress_time = 0.0
        self._sync_target_height = 0
        self._current_sync_peer: str = ""
        # Parallel block download bookkeeping: peer -> list of block_hashes
        # currently in flight from that peer. Used to reassign on stall and
        # to enforce per-peer inflight caps.
        self._inflight_by_peer: dict[str, list[bytes]] = {}

    def _parse_block_hashes(self, headers: list[dict]) -> list[bytes]:
        """Safely parse block hashes from header dicts, skipping invalid ones."""
        result = []
        for h in headers:
            bh = parse_hex(h.get("block_hash", ""))
            if bh is not None:
                result.append(bh)
        return result

    def _check_headers_limit(self) -> bool:
        """Check if pending headers have reached the limit.

        Returns True if at or above the limit (no more should be stored).
        Prevents OOM from header spam attacks during IBD.
        """
        return len(self.pending_headers) >= messagechain.config.MAX_PENDING_HEADERS

    @property
    def is_syncing(self) -> bool:
        return self.state in (SyncState.SYNCING_HEADERS, SyncState.SYNCING_BLOCKS)

    @property
    def sync_progress(self) -> float:
        """Return sync progress as 0.0 to 1.0."""
        if not self.is_syncing:
            return 1.0
        if self._sync_target_height <= 0:
            return 0.0
        return min(1.0, self.blockchain.height / self._sync_target_height)

    def update_peer_height(self, peer_address: str, height: int, best_hash: str = "",
                           cumulative_weight: int = 0):
        """Update our knowledge of a peer's chain height and weight.

        Rejects negative or absurdly high block heights to prevent
        peers from manipulating sync decisions.
        """
        # Clamp to valid range
        if height < 0:
            height = 0
        if height > MAX_SANE_BLOCK_HEIGHT:
            logger.warning(f"Peer {peer_address} reported absurd height {height}, clamping")
            height = MAX_SANE_BLOCK_HEIGHT

        self.peer_heights[peer_address] = PeerSyncInfo(
            peer_address=peer_address,
            chain_height=height,
            best_block_hash=best_hash,
            last_response_time=time.time(),
            cumulative_weight=cumulative_weight,
        )

    def needs_sync(self) -> bool:
        """Check if we're behind any peers."""
        our_height = self.blockchain.height
        for info in self.peer_heights.values():
            if info.chain_height > our_height:
                return True
        return False

    def get_best_sync_peer(self) -> str | None:
        """Find the peer with the tallest chain to sync from.

        Rejects peers whose cumulative stake weight is below the minimum
        threshold (nMinimumChainWork equivalent). This prevents a new node
        from being tricked into syncing a fabricated chain.
        """
        if not self.peer_heights:
            return None
        # Filter peers above minimum chain weight
        eligible = [
            p for p in self.peer_heights.values()
            if p.cumulative_weight >= MIN_CUMULATIVE_STAKE_WEIGHT
        ]
        if not eligible:
            return None
        best = max(eligible, key=lambda p: p.chain_height)
        if best.chain_height <= self.blockchain.height:
            return None
        return best.peer_address

    async def start_sync(self) -> bool:
        """Begin sync process if we're behind."""
        if self.is_syncing:
            return False

        peer_addr = self.get_best_sync_peer()
        if peer_addr is None:
            return False

        target_height = self.peer_heights[peer_addr].chain_height
        our_height = self.blockchain.height

        logger.info(
            f"Starting IBD: our height={our_height}, "
            f"target={target_height}, peer={peer_addr}"
        )

        self.state = SyncState.SYNCING_HEADERS
        self._sync_start_time = time.time()
        self._last_progress_time = time.time()
        self._sync_target_height = target_height
        self._current_sync_peer = peer_addr
        self.pending_headers = []
        self.blocks_needed = []
        self.downloaded_blocks = {}

        # Request headers starting from our tip
        await self._request_headers(peer_addr, our_height)
        return True

    async def _request_headers(self, peer_addr: str, start_height: int):
        """Request a batch of headers from a peer."""
        result = self.get_peer_writer(peer_addr)
        if result is None:
            logger.warning(f"Cannot request headers — peer {peer_addr} not connected")
            self.state = SyncState.IDLE
            return

        writer, _ = result
        msg = NetworkMessage(
            msg_type=MessageType.REQUEST_HEADERS,
            payload={
                "start_height": start_height,
                "count": HEADERS_BATCH_SIZE,
            },
        )
        try:
            await write_message(writer, msg)
            logger.debug(f"Requested headers {start_height}..{start_height + HEADERS_BATCH_SIZE}")
        except Exception as e:
            logger.warning(f"Failed to request headers from {peer_addr}: {e}")
            self.state = SyncState.IDLE

    async def handle_headers_response(self, headers_data: list[dict], peer_addr: str):
        """Process a batch of headers received from a peer."""
        if self.state != SyncState.SYNCING_HEADERS:
            return

        self._last_progress_time = time.time()

        # Reject oversized batches — prevents memory-exhaustion DoS.
        max_allowed = HEADERS_BATCH_SIZE * 2
        if len(headers_data) > max_allowed:
            logger.warning(
                f"Peer {peer_addr} sent {len(headers_data)} headers "
                f"(limit {max_allowed}) — truncating"
            )
            headers_data = headers_data[:max_allowed]

        if not headers_data:
            # No more headers — switch to block download
            logger.info(f"Headers sync complete. {len(self.pending_headers)} headers to fetch blocks for.")
            if self.pending_headers:
                self.state = SyncState.SYNCING_BLOCKS
                self.blocks_needed = self._parse_block_hashes(self.pending_headers)
                await self._request_next_blocks(peer_addr)
            else:
                self.state = SyncState.COMPLETE
            return

        # Validate header chain structure
        valid_headers = []
        expected_prev = (
            self.pending_headers[-1]["block_hash"]
            if self.pending_headers
            else (self.blockchain.get_latest_block().block_hash.hex()
                  if self.blockchain.get_latest_block() else "00" * 32)
        )

        checkpoint_violation = False
        for hdr in headers_data:
            if hdr["prev_hash"] != expected_prev:
                logger.warning(f"Header chain broken at block #{hdr['block_number']}")
                break
            bh = parse_hex(hdr.get("block_hash", ""))
            if bh is None:
                logger.warning("Invalid block_hash hex in header from peer")
                break
            # Validate block_number is sane BEFORE other checks
            bn = hdr.get("block_number", 0)
            if not isinstance(bn, int) or bn < 0 or bn > MAX_SANE_BLOCK_HEIGHT:
                logger.warning(f"Invalid block_number {bn} in header from peer")
                break
            # Weak-subjectivity checkpoint gate: reject the whole batch if
            # a header lands on a checkpoint height with the wrong hash.
            # This is the primary long-range-attack defense for PoS.
            cp = self._checkpoints.get(bn)
            if cp is not None and bh != cp.block_hash:
                logger.warning(
                    f"Peer {peer_addr} served header at checkpoint height {bn} "
                    f"with wrong hash {bh.hex()[:16]} (expected {cp.block_hash.hex()[:16]}) "
                    f"— rejecting batch and penalizing peer"
                )
                self._on_peer_offense(
                    peer_addr, OFFENSE_CHECKPOINT_VIOLATION,
                    f"checkpoint_mismatch:block={bn}",
                )
                checkpoint_violation = True
                valid_headers = []  # discard everything we collected from this peer
                break
            if self.blockchain.has_block(bh):
                # Already have this block, skip
                expected_prev = hdr["block_hash"]
                continue
            valid_headers.append(hdr)
            expected_prev = hdr["block_hash"]

        if checkpoint_violation:
            # Abort the sync round entirely — do not extend pending_headers,
            # do not request more headers from this peer.
            self.state = SyncState.IDLE
            return

        # Enforce header spam limit before extending
        max_pending = messagechain.config.MAX_PENDING_HEADERS
        remaining_capacity = max_pending - len(self.pending_headers)
        if remaining_capacity <= 0:
            logger.warning(
                f"Pending headers at limit ({max_pending}), "
                f"dropping {len(valid_headers)} new headers from {peer_addr}"
            )
            valid_headers = []
        elif len(valid_headers) > remaining_capacity:
            logger.warning(
                f"Truncating headers batch from {len(valid_headers)} to {remaining_capacity} "
                f"(limit: {max_pending})"
            )
            valid_headers = valid_headers[:remaining_capacity]

        self.pending_headers.extend(valid_headers)

        # Request more headers if we got a full batch
        if len(headers_data) >= HEADERS_BATCH_SIZE:
            next_start = headers_data[-1]["block_number"] + 1
            if next_start > MAX_SANE_BLOCK_HEIGHT:
                self.state = SyncState.COMPLETE
                return
            await self._request_headers(peer_addr, next_start)
        else:
            # Got partial batch — all headers received
            if self.pending_headers:
                logger.info(f"All headers received ({len(self.pending_headers)} new). Downloading blocks...")
                self.state = SyncState.SYNCING_BLOCKS
                self.blocks_needed = self._parse_block_hashes(self.pending_headers)
                await self._request_next_blocks(peer_addr)
            else:
                self.state = SyncState.COMPLETE

    def _eligible_sync_peers(self) -> list[str]:
        """Return sync-eligible peer addresses ordered by claimed weight."""
        eligible = [
            p for p in self.peer_heights.values()
            if p.cumulative_weight >= MIN_CUMULATIVE_STAKE_WEIGHT
        ]
        eligible.sort(key=lambda p: p.chain_height, reverse=True)
        return [p.peer_address for p in eligible]

    async def _request_next_blocks(self, peer_addr: str):
        """Single-peer request — kept for headers fallback + tests.

        The main block-download path uses _request_next_blocks_parallel,
        which fans out across multiple peers. This method is still used
        for the very first block request kicked off by start_sync, and
        for single-peer topologies where only one peer is eligible.
        """
        if not self.blocks_needed:
            self.state = SyncState.COMPLETE
            return

        # If we have more than one eligible peer, prefer the parallel path
        if len(self._eligible_sync_peers()) > 1:
            await self._request_next_blocks_parallel()
            return

        batch = [
            h for h in self.blocks_needed[:BLOCKS_BATCH_SIZE]
            if h not in self._inflight_hashes()
        ]
        if not batch:
            return

        result = self.get_peer_writer(peer_addr)
        if result is None:
            logger.warning(f"Cannot request blocks — peer {peer_addr} not connected")
            self.state = SyncState.IDLE
            return

        writer, _ = result
        msg = NetworkMessage(
            msg_type=MessageType.REQUEST_BLOCKS_BATCH,
            payload={
                "block_hashes": [h.hex() for h in batch],
            },
        )
        try:
            await write_message(writer, msg)
            self._inflight_by_peer.setdefault(peer_addr, []).extend(batch)
            logger.debug(f"Requested {len(batch)} blocks from {peer_addr}")
        except Exception as e:
            logger.warning(f"Failed to request blocks from {peer_addr}: {e}")
            self.state = SyncState.IDLE

    def _inflight_hashes(self) -> set[bytes]:
        """Set of block hashes currently in flight across all peers."""
        return {
            h for hashes in self._inflight_by_peer.values() for h in hashes
        }

    async def _request_next_blocks_parallel(self):
        """Fan out REQUEST_BLOCKS_BATCH across multiple eligible peers.

        One slow/malicious peer in a single-peer IBD dominates our entire
        sync window — they can accept REQUEST_BLOCKS_BATCH and delay the
        response for SYNC_STALE_TIMEOUT, burning a whole stall cycle per
        batch. Splitting the work across up to MAX_SYNC_PEERS peers caps
        the per-peer damage at ~1/N of our bandwidth.

        Disjoint-slice assignment: each in-flight block hash is recorded
        in _inflight_by_peer so we never ask two peers for the same block.
        On stall (see check_sync_stale), the stalling peer's inflight
        slice is released back to the free pool and reassigned.
        """
        if not self.blocks_needed:
            self.state = SyncState.COMPLETE
            return

        eligible = self._eligible_sync_peers()
        if not eligible:
            self.state = SyncState.IDLE
            return

        # Skip hashes already requested from some peer
        inflight = self._inflight_hashes()
        free_hashes = [h for h in self.blocks_needed if h not in inflight]
        if not free_hashes:
            return

        # Slice across at most MAX_SYNC_PEERS peers, BLOCKS_BATCH_SIZE each
        peers_to_use = eligible[:MAX_SYNC_PEERS]
        slices: list[list[bytes]] = []
        i = 0
        for _ in peers_to_use:
            if i >= len(free_hashes):
                break
            slices.append(free_hashes[i : i + BLOCKS_BATCH_SIZE])
            i += BLOCKS_BATCH_SIZE

        for peer_addr, batch in zip(peers_to_use, slices):
            if not batch:
                continue
            result = self.get_peer_writer(peer_addr)
            if result is None:
                logger.debug(
                    f"Skipping unreachable sync peer {peer_addr} in parallel fan-out"
                )
                continue
            writer, _ = result
            msg = NetworkMessage(
                msg_type=MessageType.REQUEST_BLOCKS_BATCH,
                payload={"block_hashes": [h.hex() for h in batch]},
            )
            try:
                await write_message(writer, msg)
                self._inflight_by_peer.setdefault(peer_addr, []).extend(batch)
                logger.debug(
                    f"Parallel sync: requested {len(batch)} blocks from {peer_addr}"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to request blocks from {peer_addr} in parallel fan-out: {e}"
                )
                continue

    async def handle_blocks_response(self, blocks_data: list[dict], peer_addr: str):
        """Process a batch of full blocks received from a peer."""
        if self.state != SyncState.SYNCING_BLOCKS:
            return

        self._last_progress_time = time.time()

        # Reject oversized batches — prevents memory-exhaustion DoS.
        max_allowed = BLOCKS_BATCH_SIZE * 2
        if len(blocks_data) > max_allowed:
            logger.warning(
                f"Peer {peer_addr} sent {len(blocks_data)} blocks "
                f"(limit {max_allowed}) — truncating"
            )
            blocks_data = blocks_data[:max_allowed]

        for block_data in blocks_data:
            try:
                block = Block.deserialize(block_data)
                block_hash = block.block_hash

                # Remove from needed list
                if block_hash in self.blocks_needed:
                    self.blocks_needed.remove(block_hash)

                # Clear from any peer's inflight record
                for inflight in self._inflight_by_peer.values():
                    if block_hash in inflight:
                        inflight.remove(block_hash)

                # Apply block to chain
                success, reason = self.blockchain.add_block(block)
                if success:
                    logger.debug(f"Synced block #{block.header.block_number}")
                else:
                    logger.warning(
                        f"Failed to apply synced block #{block.header.block_number}: {reason}"
                    )
            except Exception as e:
                logger.warning(f"Failed to deserialize synced block: {e}")

        # Drop empty inflight buckets
        self._inflight_by_peer = {
            p: hs for p, hs in self._inflight_by_peer.items() if hs
        }

        # Request more blocks — parallel path pulls from all eligible peers
        if self.blocks_needed:
            if len(self._eligible_sync_peers()) > 1:
                await self._request_next_blocks_parallel()
            else:
                await self._request_next_blocks(peer_addr)
        else:
            elapsed = time.time() - self._sync_start_time
            logger.info(
                f"IBD complete! Synced to height {self.blockchain.height} "
                f"in {elapsed:.1f}s"
            )
            self.state = SyncState.COMPLETE
            self.pending_headers = []
            self._inflight_by_peer.clear()

    async def check_sync_stale(self):
        """Check if sync has stalled and restart if needed.

        A stalling peer — one that accepts our REQUEST_HEADERS/REQUEST_BLOCKS
        but never responds — is penalized with a misbehavior offense so that
        a repeated offender eventually gets banned. Without this, an attacker
        can repeatedly stall our IBD without consequence.
        """
        if not self.is_syncing:
            return

        if time.time() - self._last_progress_time > SYNC_STALE_TIMEOUT:
            logger.warning(
                f"Sync stalled for {SYNC_STALE_TIMEOUT}s — penalizing in-flight peers"
            )
            # Penalize every peer that still has inflight blocks — they
            # accepted REQUEST_BLOCKS_BATCH and didn't deliver. Also drop
            # them from the candidate set and release their inflight
            # slices so the next fan-out reassigns the work.
            stalling_peers = list(self._inflight_by_peer.keys())
            if not stalling_peers and self._current_sync_peer:
                stalling_peers = [self._current_sync_peer]
            for stale_peer in stalling_peers:
                self._on_peer_offense(
                    stale_peer, OFFENSE_PROTOCOL_VIOLATION, "sync_stall",
                )
                self.peer_heights.pop(stale_peer, None)
                self._inflight_by_peer.pop(stale_peer, None)
            self.state = SyncState.IDLE
            self.pending_headers = []
            self.blocks_needed = []
            self.downloaded_blocks = {}
            self._inflight_by_peer.clear()

            # Try to restart with a different peer
            await self.start_sync()

    def get_sync_status(self) -> dict:
        """Return current sync status for monitoring."""
        return {
            "state": self.state.value,
            "progress": f"{self.sync_progress:.1%}",
            "our_height": self.blockchain.height,
            "target_height": self._sync_target_height,
            "pending_headers": len(self.pending_headers),
            "blocks_needed": len(self.blocks_needed),
            "sync_peer": self._current_sync_peer,
            "known_peers": len(self.peer_heights),
        }
