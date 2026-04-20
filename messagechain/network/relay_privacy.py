"""
Transaction relay timing privacy.

Adds Poisson-distributed random delays before relaying transactions
to peers, preventing surveillance nodes from determining which node
originated a transaction by observing first-seen timing.

Also tracks which transactions have been announced to which peers —
a node should not serve GETDATA for a transaction it hasn't yet
announced via INV to the requesting peer.
"""

import math
import secrets
from collections import defaultdict

import messagechain.config


class TxRelayScheduler:
    """Schedule transaction relay with random delays for privacy.

    Each relay to each peer gets an independent random delay drawn
    from an exponential distribution (Poisson process inter-arrivals).
    """

    def __init__(self, mean_delay: float | None = None):
        self._mean = mean_delay or messagechain.config.TX_RELAY_DELAY_MEAN
        # peer_addr -> set of tx_hashes that have been announced to that peer
        self._announced: dict[str, set[bytes]] = defaultdict(set)

    def compute_delay(self) -> float:
        """Compute a random relay delay (exponential distribution).

        Returns delay in seconds. The mean is configurable via
        TX_RELAY_DELAY_MEAN (default 2.0 seconds).

        Uses `secrets` rather than the standard `random` module: relay delays
        are a privacy feature, and predictable delays would let a surveillance
        peer correlate timings to identify transaction origins. Inverse-CDF
        sampling against a cryptographically-random uniform [0,1) gives us the
        same exponential distribution as `random.expovariate` without the
        deterministic-PRNG weakness.
        """
        # Draw u uniformly from (0, 1] using 53 bits of crypto randomness.
        # Avoid u == 0 so -log(u) stays finite.
        raw = secrets.randbits(53) + 1  # in [1, 2^53]
        u = raw / (1 << 53)              # in (0, 1]
        return -self._mean * math.log(u)

    def mark_announced(self, peer_addr: str, tx_hash: bytes):
        """Record that we announced a tx to a peer via INV."""
        self._announced[peer_addr].add(tx_hash)

    def can_serve_tx(self, peer_addr: str, tx_hash: bytes) -> bool:
        """Check if we can serve GETDATA for this tx to this peer.

        Returns False if we haven't announced this tx to the peer yet.
        Prevents information leaks from premature GETDATA responses.
        """
        return tx_hash in self._announced.get(peer_addr, set())

    def remove_peer(self, peer_addr: str):
        """Clean up state when a peer disconnects."""
        self._announced.pop(peer_addr, None)

    def remove_tx(self, tx_hash: bytes):
        """Remove a confirmed tx from all peer announcement sets."""
        for peer_set in self._announced.values():
            peer_set.discard(tx_hash)
