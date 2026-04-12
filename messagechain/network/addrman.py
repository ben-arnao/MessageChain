"""
Address manager with Sybil/eclipse attack resistance.

Inspired by Bitcoin Core's addrman: uses a two-table design (new/tried)
with cryptographic bucketing to prevent a single attacker from dominating
a node's peer address book.

Key defenses:
- Source-based bucketing: addresses from the same source go in the same buckets
- Per-source limits: a single source can't add unlimited addresses
- Network group isolation: bucketing by /16 prefix prevents AS-level attacks
- Tried table: only addresses we've successfully connected to
- Cryptographic bucket selection: secret key makes bucketing unpredictable
"""

import hashlib
import os
import time
from dataclasses import dataclass, field
from messagechain.config import (
    HASH_ALGO,
    ADDRMAN_NEW_BUCKET_COUNT,
    ADDRMAN_TRIED_BUCKET_COUNT,
    ADDRMAN_BUCKET_SIZE,
    ADDRMAN_MAX_PER_SOURCE,
    ADDRMAN_HORIZON_DAYS,
)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _network_group(ip: str) -> str:
    """Extract network group from an IP address.

    IPv4: groups by /16 (first two octets).
    IPv6: groups by /48 (first three hextets).
    This prevents a single AS from dominating the address tables.
    """
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}"
    # IPv6: strip brackets and group by /48 (first 3 hextets)
    v6 = ip.strip("[]")
    hextets = v6.split(":")
    if len(hextets) >= 3:
        return ":".join(hextets[:3])
    return v6


@dataclass
class AddrEntry:
    """A single address entry in the manager."""
    ip: str
    port: int
    source_ip: str  # who told us about this address
    timestamp: float = field(default_factory=time.time)
    last_success: float = 0.0
    last_attempt: float = 0.0
    attempts: int = 0
    in_tried: bool = False

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    def is_terrible(self) -> bool:
        """Check if this address should be discarded (BTC-style)."""
        now = time.time()
        # Too old and never connected
        if self.last_success == 0 and now - self.timestamp > ADDRMAN_HORIZON_DAYS * 86400:
            return True
        # Too many failed attempts
        if self.attempts >= 10:
            return True
        # Future-dated (clock skew attack)
        if self.timestamp > now + 600:
            return True
        return False


class AddressManager:
    """Two-table address manager with Sybil resistance.

    New table: addresses we've heard about but haven't connected to.
    Tried table: addresses we've successfully connected to.

    Bucket selection is keyed with a random secret to prevent
    an attacker from predicting which bucket an address will land in.
    """

    def __init__(self, secret_key: bytes | None = None):
        self._secret_key = secret_key or os.urandom(32)
        # Tables: bucket_index -> dict of (ip:port -> AddrEntry)
        self._new_table: list[dict[str, AddrEntry]] = [
            {} for _ in range(ADDRMAN_NEW_BUCKET_COUNT)
        ]
        self._tried_table: list[dict[str, AddrEntry]] = [
            {} for _ in range(ADDRMAN_TRIED_BUCKET_COUNT)
        ]
        # Track per-source counts
        self._source_counts: dict[str, int] = {}
        # All known addresses for dedup
        self._all_addrs: dict[str, AddrEntry] = {}

    def _new_bucket(self, ip: str, source_ip: str) -> int:
        """Compute new-table bucket for an address given its source."""
        group = _network_group(ip)
        source_group = _network_group(source_ip)
        data = self._secret_key + group.encode() + source_group.encode()
        h = int.from_bytes(_hash(data)[:4], "big")
        return h % ADDRMAN_NEW_BUCKET_COUNT

    def _tried_bucket(self, ip: str) -> int:
        """Compute tried-table bucket for an address."""
        group = _network_group(ip)
        data = self._secret_key + group.encode() + b"tried"
        h = int.from_bytes(_hash(data)[:4], "big")
        return h % ADDRMAN_TRIED_BUCKET_COUNT

    def add_address(self, ip: str, port: int, source_ip: str) -> bool:
        """Add a new address learned from a peer.

        Returns True if the address was added, False if rejected.
        """
        addr_key = f"{ip}:{port}"

        # Already known
        if addr_key in self._all_addrs:
            # Update timestamp
            self._all_addrs[addr_key].timestamp = time.time()
            return False

        # Per-source limit
        source_group = _network_group(source_ip)
        count = self._source_counts.get(source_group, 0)
        if count >= ADDRMAN_MAX_PER_SOURCE:
            return False

        entry = AddrEntry(ip=ip, port=port, source_ip=source_ip)

        # Compute bucket
        bucket_idx = self._new_bucket(ip, source_ip)
        bucket = self._new_table[bucket_idx]

        # Bucket full — evict terrible entry or reject
        if len(bucket) >= ADDRMAN_BUCKET_SIZE:
            evicted = False
            for key, existing in list(bucket.items()):
                if existing.is_terrible():
                    del bucket[key]
                    if key in self._all_addrs:
                        del self._all_addrs[key]
                    evicted = True
                    break
            if not evicted:
                return False  # bucket full, no terrible entries

        bucket[addr_key] = entry
        self._all_addrs[addr_key] = entry
        self._source_counts[source_group] = count + 1
        return True

    def mark_good(self, ip: str, port: int):
        """Mark an address as successfully connected — move to tried table."""
        addr_key = f"{ip}:{port}"
        entry = self._all_addrs.get(addr_key)
        if entry is None:
            return

        entry.last_success = time.time()
        entry.attempts = 0

        if entry.in_tried:
            return  # already in tried

        # Remove from new table
        for bucket in self._new_table:
            if addr_key in bucket:
                del bucket[addr_key]
                break

        # Add to tried table
        bucket_idx = self._tried_bucket(ip)
        bucket = self._tried_table[bucket_idx]

        if len(bucket) >= ADDRMAN_BUCKET_SIZE:
            # Evict oldest entry in bucket
            oldest_key = min(bucket, key=lambda k: bucket[k].last_success)
            old_entry = bucket.pop(oldest_key)
            old_entry.in_tried = False
            # Move evicted back to new table
            new_bucket_idx = self._new_bucket(old_entry.ip, old_entry.source_ip)
            self._new_table[new_bucket_idx][oldest_key] = old_entry

        bucket[addr_key] = entry
        entry.in_tried = True

    def mark_attempt(self, ip: str, port: int):
        """Record a connection attempt."""
        addr_key = f"{ip}:{port}"
        entry = self._all_addrs.get(addr_key)
        if entry:
            entry.last_attempt = time.time()
            entry.attempts += 1

    def select_addresses(self, count: int) -> list[tuple[str, int]]:
        """Select addresses for connection, preferring tried and diverse groups.

        Returns list of (ip, port) tuples.
        """
        results = []
        seen_groups = set()

        # First try from tried table (known-good peers)
        for bucket in self._tried_table:
            for entry in bucket.values():
                group = _network_group(entry.ip)
                if group not in seen_groups and not entry.is_terrible():
                    results.append((entry.ip, entry.port))
                    seen_groups.add(group)
                    if len(results) >= count:
                        return results

        # Fill from new table
        for bucket in self._new_table:
            for entry in bucket.values():
                group = _network_group(entry.ip)
                if group not in seen_groups and not entry.is_terrible():
                    results.append((entry.ip, entry.port))
                    seen_groups.add(group)
                    if len(results) >= count:
                        return results

        return results

    def count_new(self) -> int:
        """Count entries in the new table."""
        return sum(len(b) for b in self._new_table)

    def count_tried(self) -> int:
        """Count entries in the tried table."""
        return sum(len(b) for b in self._tried_table)

    def remove_address(self, ip: str, port: int):
        """Remove an address from all tables."""
        addr_key = f"{ip}:{port}"
        if addr_key in self._all_addrs:
            entry = self._all_addrs.pop(addr_key)
            source_group = _network_group(entry.source_ip)
            self._source_counts[source_group] = max(
                0, self._source_counts.get(source_group, 0) - 1
            )
        for bucket in self._new_table:
            bucket.pop(addr_key, None)
        for bucket in self._tried_table:
            bucket.pop(addr_key, None)

    def cleanup_terrible(self) -> int:
        """Remove terrible addresses from new table. Returns count removed."""
        removed = 0
        for bucket in self._new_table:
            terrible = [k for k, v in bucket.items() if v.is_terrible()]
            for k in terrible:
                del bucket[k]
                if k in self._all_addrs:
                    del self._all_addrs[k]
                removed += 1
        return removed
