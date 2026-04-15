"""
Per-peer rate limiting with token bucket algorithm.

Each peer gets independent rate limiters for different message categories:
- Transactions: moderate rate (prevents tx spam flooding)
- Block requests: lower rate (prevents resource exhaustion)
- General messages: higher rate (handshakes, height checks, etc.)

Uses a token bucket: tokens refill at a steady rate, each message
consumes one token. When the bucket is empty, messages are rejected.
"""

import time
from dataclasses import dataclass, field

# Rate limit profiles (tokens_per_second, max_burst)
RATE_TX = (10, 50)          # 10 tx/sec, burst up to 50
RATE_BLOCK_REQ = (2, 10)    # 2 block requests/sec, burst up to 10
RATE_HEADERS_REQ = (2, 10)  # 2 header requests/sec, burst up to 10
RATE_GENERAL = (30, 100)    # 30 msg/sec, burst up to 100
# ADDR / PEER_LIST — matches Bitcoin Core's ~0.1/s average with a
# small burst allowance. Strict because an attacker who can flood
# address gossip can dominate our addrman and set up eclipse attacks.
RATE_ADDR = (0.1, 10)       # 0.1 msg/sec, burst up to 10
# Response messages (RESPONSE_HEADERS, RESPONSE_BLOCKS_BATCH) — a peer
# sending unsolicited responses can exhaust CPU via deserialization.
RATE_RESPONSE = (5, 20)     # 5 responses/sec, burst up to 20
# Non-message-tx gossip (ANNOUNCE_PENDING_TX carrying stake / unstake /
# authority / governance txs).  In legitimate use these are rare (a
# validator rotating a key, a user setting a cold-key binding, a
# governance vote) — so the rate is tight.  Each one carries a WOTS+
# signature to verify, so a flood is disproportionately expensive to
# process.  2/sec with a burst of 20 accommodates normal bursty usage
# while making a spam flood economically visible in peer scoring.
RATE_PENDING_TX = (2, 20)


@dataclass
class TokenBucket:
    """Token bucket rate limiter."""
    rate: float          # tokens added per second
    max_tokens: float    # maximum bucket capacity
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.time)

    def __post_init__(self):
        self.tokens = self.max_tokens  # start full

    def consume(self, count: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed, False if rate-limited."""
        self._refill()
        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
        self.last_refill = now


class PeerRateLimiter:
    """Per-peer rate limiting across message categories."""

    def __init__(self):
        self._buckets: dict[str, dict[str, TokenBucket]] = {}

    def _get_ip(self, address: str) -> str:
        """Extract IP, handling both IPv4 and IPv6 bracket notation."""
        if address.startswith("["):
            bracket_end = address.find("]")
            if bracket_end != -1:
                return address[1:bracket_end]
        return address.rsplit(":", 1)[0] if ":" in address else address

    def _ensure_buckets(self, ip: str):
        if ip not in self._buckets:
            self._buckets[ip] = {
                "tx": TokenBucket(rate=RATE_TX[0], max_tokens=RATE_TX[1]),
                "block_req": TokenBucket(rate=RATE_BLOCK_REQ[0], max_tokens=RATE_BLOCK_REQ[1]),
                "headers_req": TokenBucket(rate=RATE_HEADERS_REQ[0], max_tokens=RATE_HEADERS_REQ[1]),
                "general": TokenBucket(rate=RATE_GENERAL[0], max_tokens=RATE_GENERAL[1]),
                "addr": TokenBucket(rate=RATE_ADDR[0], max_tokens=RATE_ADDR[1]),
                "response": TokenBucket(rate=RATE_RESPONSE[0], max_tokens=RATE_RESPONSE[1]),
                "pending_tx": TokenBucket(
                    rate=RATE_PENDING_TX[0], max_tokens=RATE_PENDING_TX[1],
                ),
            }

    def check(self, address: str, category: str) -> bool:
        """Check if a message from this peer is within rate limits.

        Returns True if allowed, False if rate-limited.

        Categories: 'tx', 'block_req', 'headers_req', 'general'
        """
        ip = self._get_ip(address)
        self._ensure_buckets(ip)
        bucket = self._buckets[ip].get(category)
        if bucket is None:
            return True  # unknown category, allow
        return bucket.consume()

    def remove_peer(self, address: str):
        """Clean up rate limit state when a peer disconnects."""
        ip = self._get_ip(address)
        self._buckets.pop(ip, None)

    def cleanup_stale(self, max_age: float = 600):
        """Remove buckets for peers that haven't been seen recently."""
        now = time.time()
        to_remove = []
        for ip, buckets in self._buckets.items():
            # Check if all buckets are fully refilled (peer inactive)
            all_full = all(
                (now - b.last_refill) > max_age
                for b in buckets.values()
            )
            if all_full:
                to_remove.append(ip)
        for ip in to_remove:
            del self._buckets[ip]


class RPCRateLimiter:
    """Simple sliding-window rate limiter for RPC connections.

    Tracks request timestamps per IP and rejects requests that exceed
    the configured rate within the window.
    """

    MAX_TRACKED_IPS = 1000

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def check(self, ip: str) -> bool:
        """Check if a request from this IP is allowed. Returns True if allowed."""
        now = time.time()
        cutoff = now - self.window_seconds

        if ip not in self._requests:
            # M12: Cap tracked IPs to prevent unbounded memory growth
            if len(self._requests) >= self.MAX_TRACKED_IPS:
                self.cleanup_stale(max_age=60)
                # If still over limit after cleanup, evict oldest
                if len(self._requests) >= self.MAX_TRACKED_IPS:
                    oldest_ip = min(self._requests, key=lambda k: self._requests[k][-1] if self._requests[k] else 0)
                    del self._requests[oldest_ip]
            self._requests[ip] = []

        # Prune expired entries
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]

        if len(self._requests[ip]) >= self.max_requests:
            return False

        self._requests[ip].append(now)
        return True

    def cleanup_stale(self, max_age: float = 600):
        """Remove tracking for IPs that haven't made requests recently."""
        now = time.time()
        to_remove = [
            ip for ip, times in self._requests.items()
            if not times or (now - times[-1]) > max_age
        ]
        for ip in to_remove:
            del self._requests[ip]
