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

from messagechain.core.block import Block, BlockHeader
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

    def __init__(self, blockchain, get_peer_writer):
        """
        Args:
            blockchain: The Blockchain instance to sync
            get_peer_writer: callable(address) -> (writer, peer) to get peer connection
        """
        self.blockchain = blockchain
        self.get_peer_writer = get_peer_writer
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

    def update_peer_height(self, peer_address: str, height: int, best_hash: str = ""):
        """Update our knowledge of a peer's chain height."""
        self.peer_heights[peer_address] = PeerSyncInfo(
            peer_address=peer_address,
            chain_height=height,
            best_block_hash=best_hash,
            last_response_time=time.time(),
        )

    def needs_sync(self) -> bool:
        """Check if we're behind any peers."""
        our_height = self.blockchain.height
        for info in self.peer_heights.values():
            if info.chain_height > our_height:
                return True
        return False

    def get_best_sync_peer(self) -> str | None:
        """Find the peer with the tallest chain to sync from."""
        if not self.peer_heights:
            return None
        best = max(self.peer_heights.values(), key=lambda p: p.chain_height)
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

        if not headers_data:
            # No more headers — switch to block download
            logger.info(f"Headers sync complete. {len(self.pending_headers)} headers to fetch blocks for.")
            if self.pending_headers:
                self.state = SyncState.SYNCING_BLOCKS
                self.blocks_needed = [
                    bytes.fromhex(h["block_hash"]) for h in self.pending_headers
                ]
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

        for hdr in headers_data:
            if hdr["prev_hash"] != expected_prev:
                logger.warning(f"Header chain broken at block #{hdr['block_number']}")
                break
            if self.blockchain.has_block(bytes.fromhex(hdr["block_hash"])):
                # Already have this block, skip
                expected_prev = hdr["block_hash"]
                continue
            valid_headers.append(hdr)
            expected_prev = hdr["block_hash"]

        self.pending_headers.extend(valid_headers)

        # Request more headers if we got a full batch
        if len(headers_data) >= HEADERS_BATCH_SIZE:
            next_start = headers_data[-1]["block_number"] + 1
            await self._request_headers(peer_addr, next_start)
        else:
            # Got partial batch — all headers received
            if self.pending_headers:
                logger.info(f"All headers received ({len(self.pending_headers)} new). Downloading blocks...")
                self.state = SyncState.SYNCING_BLOCKS
                self.blocks_needed = [
                    bytes.fromhex(h["block_hash"]) for h in self.pending_headers
                ]
                await self._request_next_blocks(peer_addr)
            else:
                self.state = SyncState.COMPLETE

    async def _request_next_blocks(self, peer_addr: str):
        """Request the next batch of full blocks."""
        if not self.blocks_needed:
            self.state = SyncState.COMPLETE
            return

        # Take next batch
        batch = self.blocks_needed[:BLOCKS_BATCH_SIZE]

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
            logger.debug(f"Requested {len(batch)} blocks")
        except Exception as e:
            logger.warning(f"Failed to request blocks from {peer_addr}: {e}")
            self.state = SyncState.IDLE

    async def handle_blocks_response(self, blocks_data: list[dict], peer_addr: str):
        """Process a batch of full blocks received from a peer."""
        if self.state != SyncState.SYNCING_BLOCKS:
            return

        self._last_progress_time = time.time()

        for block_data in blocks_data:
            try:
                block = Block.deserialize(block_data)
                block_hash = block.block_hash

                # Remove from needed list
                if block_hash in self.blocks_needed:
                    self.blocks_needed.remove(block_hash)

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

        # Request more blocks if needed
        if self.blocks_needed:
            await self._request_next_blocks(peer_addr)
        else:
            elapsed = time.time() - self._sync_start_time
            logger.info(
                f"IBD complete! Synced to height {self.blockchain.height} "
                f"in {elapsed:.1f}s"
            )
            self.state = SyncState.COMPLETE
            self.pending_headers = []

    async def check_sync_stale(self):
        """Check if sync has stalled and restart if needed."""
        if not self.is_syncing:
            return

        if time.time() - self._last_progress_time > SYNC_STALE_TIMEOUT:
            logger.warning(
                f"Sync stalled for {SYNC_STALE_TIMEOUT}s — resetting"
            )
            self.state = SyncState.IDLE
            self.pending_headers = []
            self.blocks_needed = []
            self.downloaded_blocks = {}

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
