"""
Multi-criteria peer eviction protection (Bitcoin Core-inspired).

When connection slots are full and a new inbound peer connects,
we must choose which existing peer to disconnect. An attacker
trying to eclipse a node must outperform honest peers on ALL
criteria simultaneously, which is extremely difficult.

Protected peer categories (not evictable):
1. Lowest ping latency (fast peers are hard to fake)
2. Longest connection time (loyal peers)
3. Most novel block deliveries (useful peers)
4. Most novel transaction deliveries (useful peers)

After removing protected peers, the remaining peer with the
worst combined score is selected for eviction.
"""

import time
from dataclasses import dataclass, field


# How many peers to protect in each category
PROTECT_BY_PING = 4
PROTECT_BY_CONNECT_TIME = 4
PROTECT_BY_NOVEL_BLOCKS = 4
PROTECT_BY_NOVEL_TXS = 4
# Minimum peers before any eviction is considered
MIN_PEERS_FOR_EVICTION = 8


@dataclass
class PeerMetrics:
    """Tracked metrics for eviction decisions."""
    connect_time: float = 0.0
    ping_ms: float = float("inf")
    novel_blocks: int = 0
    novel_txs: int = 0
    last_block_time: float = 0.0
    last_tx_time: float = 0.0
    network_group: str = ""  # e.g. "192.168.1" for IPv4


class PeerEvictionProtector:
    """Selects eviction candidates using multi-criteria protection.

    Peers excelling in any single criterion are protected, forcing
    an attacker to outperform honest peers across ALL dimensions.
    """

    def __init__(self):
        self.peers: dict[str, PeerMetrics] = {}

    def register_peer(self, peer_addr: str, connect_time: float | None = None,
                      network_group: str = ""):
        """Register a new peer for eviction tracking."""
        self.peers[peer_addr] = PeerMetrics(
            connect_time=connect_time or time.time(),
            network_group=network_group or self._extract_group(peer_addr),
        )

    def remove_peer(self, peer_addr: str):
        """Remove a disconnected peer."""
        self.peers.pop(peer_addr, None)

    def update_ping(self, peer_addr: str, latency_ms: float):
        """Update a peer's ping latency."""
        if peer_addr in self.peers:
            self.peers[peer_addr].ping_ms = latency_ms

    def record_novel_block(self, peer_addr: str):
        """Record that a peer delivered a novel block."""
        if peer_addr in self.peers:
            self.peers[peer_addr].novel_blocks += 1
            self.peers[peer_addr].last_block_time = time.time()

    def record_novel_tx(self, peer_addr: str):
        """Record that a peer delivered a novel transaction."""
        if peer_addr in self.peers:
            self.peers[peer_addr].novel_txs += 1
            self.peers[peer_addr].last_tx_time = time.time()

    def select_eviction_candidate(self) -> str | None:
        """Select the best candidate for eviction, or None.

        Returns None if there aren't enough peers to justify eviction.
        Protected peers (best in any criterion) are never selected.
        """
        if len(self.peers) < MIN_PEERS_FOR_EVICTION:
            return None

        candidates = set(self.peers.keys())

        # Protect best-ping peers
        by_ping = sorted(candidates, key=lambda p: self.peers[p].ping_ms)
        for p in by_ping[:PROTECT_BY_PING]:
            candidates.discard(p)

        if not candidates:
            return None

        # Protect longest-connected peers
        by_connect = sorted(candidates, key=lambda p: self.peers[p].connect_time)
        for p in by_connect[:PROTECT_BY_CONNECT_TIME]:
            candidates.discard(p)

        if not candidates:
            return None

        # Protect best block-delivering peers
        by_blocks = sorted(candidates, key=lambda p: self.peers[p].novel_blocks, reverse=True)
        for p in by_blocks[:PROTECT_BY_NOVEL_BLOCKS]:
            candidates.discard(p)

        if not candidates:
            return None

        # Protect best tx-delivering peers
        by_txs = sorted(candidates, key=lambda p: self.peers[p].novel_txs, reverse=True)
        for p in by_txs[:PROTECT_BY_NOVEL_TXS]:
            candidates.discard(p)

        if not candidates:
            return None

        # From remaining candidates, evict the most recently connected
        # (least proven) peer
        return max(candidates, key=lambda p: self.peers[p].connect_time)

    def _extract_group(self, peer_addr: str) -> str:
        """Extract network group from address (first 3 octets for IPv4)."""
        host = peer_addr.rsplit(":", 1)[0] if ":" in peer_addr else peer_addr
        parts = host.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3])
        return host
