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
from messagechain.config import (
    MEMPOOL_REQUEST_RATE_PER_SEC, MEMPOOL_REQUEST_BURST,
)

# Rate limit profiles (tokens_per_second, max_burst)
RATE_TX = (10, 50)          # 10 tx/sec, burst up to 50
RATE_BLOCK_REQ = (2, 10)    # 2 block requests/sec, burst up to 10
RATE_HEADERS_REQ = (2, 10)  # 2 header requests/sec, burst up to 10
RATE_GENERAL = (30, 100)    # 30 msg/sec, burst up to 100
# Active mempool-replication request traffic (REQUEST_MEMPOOL_TX).  A
# peer legitimately has at most MEMPOOL_DIGEST_MAX_HASHES holes to fill
# per digest interval, and digests fire every MEMPOOL_SYNC_INTERVAL_SEC,
# so 10/s with a 50-burst comfortably supports honest catch-up without
# opening a DoS vector on the responder (each request costs a mempool
# lookup and one ANNOUNCE_TX send).
RATE_MEMPOOL_REQ = (MEMPOOL_REQUEST_RATE_PER_SEC, MEMPOOL_REQUEST_BURST)
# Digest arrivals themselves are separately throttled (see Node._handle
# path and MEMPOOL_DIGEST_MIN_INTERVAL_SEC) but we still want a token-
# bucket guard so a peer that somehow squeaks past the interval gate
# can't saturate the dispatcher.  Tight: essentially one digest per
# MEMPOOL_SYNC_INTERVAL_SEC, with a small burst to tolerate startup.
RATE_MEMPOOL_DIGEST = (0.2, 5)
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
# Signed-announce gossip (ANNOUNCE_ATTESTATION, ANNOUNCE_FINALITY_VOTE,
# ANNOUNCE_SLASH, ANNOUNCE_CUSTODY_PROOF).  Each one triggers a WOTS+-
# class signature parse and verify — ~2.7 kB of signature material and
# ~thousand hash invocations per message.  Under the old `general`
# bucket (30/s, burst 100) a single peer could force 30 WOTS+ verifies
# per second indefinitely; that is a real CPU DoS vector.  Tight bucket
# here: legitimate gossip of a finality vote / slash / custody proof is
# measured in events per epoch, not per second, so 2/sec with a burst
# of 20 covers normal validator-rotation spikes while making a flood
# economically visible in ban-score accounting.
RATE_SIGNED_ANNOUNCE = (2, 20)


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
                "signed_announce": TokenBucket(
                    rate=RATE_SIGNED_ANNOUNCE[0],
                    max_tokens=RATE_SIGNED_ANNOUNCE[1],
                ),
                "mempool_req": TokenBucket(
                    rate=RATE_MEMPOOL_REQ[0], max_tokens=RATE_MEMPOOL_REQ[1],
                ),
                "mempool_digest": TokenBucket(
                    rate=RATE_MEMPOOL_DIGEST[0],
                    max_tokens=RATE_MEMPOOL_DIGEST[1],
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

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0,
                 max_per_minute: int | None = None):
        # Back-compat: tests use max_per_minute; keep window as 60s in that case.
        if max_per_minute is not None:
            max_requests = max_per_minute
            window_seconds = 60.0
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def check(self, ip: str, cost: int = 1) -> bool:
        """Check if a request from this IP is allowed. Returns True if allowed.

        `cost` charges a weighted amount against the budget — expensive
        methods (submit_transaction, stake, etc. = WOTS+ verify) should
        pay more tokens than cheap ones (get_chain_info = dict lookup).
        Default 1 preserves the existing 1-token-per-call semantics for
        callers that haven't been migrated yet.

        IPv6 addresses are aggregated to /64 before bucketing so a cloud
        attacker can't rotate within their allocation to bypass limits.
        """
        from messagechain.network.ban import _normalize_ip_for_bucket
        ip = _normalize_ip_for_bucket(ip)
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

        if len(self._requests[ip]) + cost > self.max_requests:
            return False

        # Charge `cost` tokens by inserting `cost` timestamps.  Each
        # participating token decays from the window independently, so
        # a cost=10 submit burns 10 of the next 300 tokens and frees
        # them over the next 60s window.
        for _ in range(cost):
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
