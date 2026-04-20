"""Anti-eclipse peer selection: enforce subnet diversity in outbound connections.

Eclipse attack: an attacker surrounds a node with their own peers,
controlling its entire network view.  All censorship defenses (forced
inclusion, mempool replication, multi-path submission) assume at least
one honest peer.  Eclipse breaks that assumption.

Defense: when choosing outbound peers, prefer candidates whose /16
subnet (IPv4) or /48 prefix (IPv6) is NOT already represented in the
current outbound set.  An attacker needs IPs across many distinct
subnets to eclipse a node — expensive and hard to acquire.

Private/localhost IPs bypass diversity checks entirely so test
environments using 127.x.x.x or 10.x.x.x peers work without friction.

This is a PREFERENCE, not a hard block.  If no diverse candidates
exist, we connect to whatever's available (some peers > no peers).
"""

import ipaddress
import os

# ── Config constants ─────────────────────────────────────────────────

MAX_PEERS_PER_SUBNET = 2       # max outbound peers from same /16 (IPv4) or /48 (IPv6)
MIN_DIVERSE_SUBNETS = 3        # warn (don't halt) if fewer distinct subnets than this


def _is_private_or_loopback(ip_str: str) -> bool:
    """Return True if the IP is in a private/loopback/link-local range
    that should bypass diversity checks (test environments).

    Specifically bypasses:
      - 127.0.0.0/8 (loopback)
      - 10.0.0.0/8 (RFC 1918 private)
      - 172.16.0.0/12 (RFC 1918 private)
      - 192.168.0.0/16 (RFC 1918 private)
      - ::1 (IPv6 loopback)
      - fe80::/10 (IPv6 link-local)
      - fc00::/7 (IPv6 unique-local / private)

    Does NOT bypass documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24, 2001:db8::/32) — those are used in tests as stand-ins
    for real public IPs and SHOULD be subject to diversity checks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        return (
            ip.is_loopback  # 127.0.0.0/8
            or ip in ipaddress.IPv4Network("10.0.0.0/8")
            or ip in ipaddress.IPv4Network("172.16.0.0/12")
            or ip in ipaddress.IPv4Network("192.168.0.0/16")
        )

    # IPv6
    return (
        ip.is_loopback       # ::1
        or ip.is_link_local  # fe80::/10
        or ip in ipaddress.IPv6Network("fc00::/7")  # unique-local
    )


def get_subnet(ip_str: str) -> str:
    """Extract the subnet prefix used for diversity bucketing.

    IPv4: /16 prefix (first two octets, e.g. "203.0").
    IPv6: /48 prefix (first three groups, e.g. "2001:0db8:85a3").
    IPv4-mapped IPv6 (::ffff:a.b.c.d): treated as IPv4, returns "a.b".

    Returns a string key suitable for equality comparison.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Fallback: treat as opaque string (shouldn't happen with valid IPs)
        return ip_str

    if isinstance(ip, ipaddress.IPv4Address):
        octets = str(ip).split(".")
        return f"{octets[0]}.{octets[1]}"

    # IPv6
    assert isinstance(ip, ipaddress.IPv6Address)

    # Handle IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
    mapped = ip.ipv4_mapped
    if mapped is not None:
        octets = str(mapped).split(".")
        return f"{octets[0]}.{octets[1]}"

    # Full IPv6: use /48 prefix = first 3 groups of the exploded form
    # Exploded form is always 8 groups of 4 hex digits separated by ':'
    groups = ip.exploded.split(":")
    return f"{groups[0]}:{groups[1]}:{groups[2]}"


def is_subnet_saturated(
    candidate_ip: str,
    current_outbound: list[tuple[str, int]],
) -> bool:
    """Return True if connecting to candidate_ip would exceed
    MAX_PEERS_PER_SUBNET for its /16 (or /48 for IPv6).

    Private/localhost IPs always return False (bypass for test envs).
    """
    if _is_private_or_loopback(candidate_ip):
        return False

    candidate_subnet = get_subnet(candidate_ip)
    count = 0
    for ip, _port in current_outbound:
        if _is_private_or_loopback(ip):
            continue
        if get_subnet(ip) == candidate_subnet:
            count += 1
    return count >= MAX_PEERS_PER_SUBNET


def diversity_score(outbound: list[tuple[str, int]]) -> float:
    """Score the diversity of a set of outbound peers.

    Returns a float from 0.0 to 1.0:
      1.0 = every peer is in a distinct subnet (or set is empty/single).
      0.0 would require all peers sharing one subnet (approaches 1/N).

    Formula: unique_subnets / total_peers.
    """
    if len(outbound) <= 1:
        return 1.0
    subnets = set(get_subnet(ip) for ip, _port in outbound)
    return len(subnets) / len(outbound)


class PeerSelector:
    """Selects outbound peers with subnet diversity preference.

    Usage:
        selector = PeerSelector()
        peer = selector.select_outbound_peer(candidates, current_outbound)
    """

    def select_outbound_peer(
        self,
        candidates: list[tuple[str, int]],
        current_outbound: list[tuple[str, int]],
    ) -> tuple[str, int] | None:
        """Pick the best candidate to connect to, preferring subnet diversity.

        Priority:
          1. Candidates whose /16 is NOT already in current_outbound.
          2. Candidates whose /16 is present but not saturated.
          3. Candidates from saturated /16s (better than no peer).

        Within each tier, pick randomly (using os.urandom for
        unpredictability — same rationale as eviction.py).

        Returns (host, port) or None if candidates is empty.
        """
        if not candidates:
            return None

        # Count subnets in current outbound set.  Private/loopback peers
        # still contribute to the subnet count for diversity *preference*
        # scoring (so a selector with one 10.1.x.x peer still prefers a
        # 10.2.x.x candidate over another 10.1.x.x one).  Private IPs only
        # bypass the hard saturation cap, not the soft diversity preference.
        current_subnets: dict[str, int] = {}
        for ip, _port in current_outbound:
            subnet = get_subnet(ip)
            current_subnets[subnet] = current_subnets.get(subnet, 0) + 1

        # Bucket candidates into tiers
        tier_new_subnet: list[tuple[str, int]] = []       # subnet not seen at all
        tier_unsaturated: list[tuple[str, int]] = []       # subnet seen but < max
        tier_saturated: list[tuple[str, int]] = []         # subnet at max

        for candidate in candidates:
            ip, _port = candidate
            subnet = get_subnet(ip)
            count = current_subnets.get(subnet, 0)
            if count == 0:
                tier_new_subnet.append(candidate)
            elif count < MAX_PEERS_PER_SUBNET or _is_private_or_loopback(ip):
                # Private IPs never hit the saturated tier — they always
                # remain at least unsaturated (bypass the hard cap).
                tier_unsaturated.append(candidate)
            else:
                tier_saturated.append(candidate)

        # Pick from the best non-empty tier
        for tier in (tier_new_subnet, tier_unsaturated, tier_saturated):
            if tier:
                idx = int.from_bytes(os.urandom(4), "big") % len(tier)
                return tier[idx]

        return None

    def check_diversity(
        self,
        current_outbound: list[tuple[str, int]],
    ) -> tuple[bool, str]:
        """Check whether the current outbound set meets minimum diversity.

        Returns (ok, warning_message).  ok=True means we have at least
        MIN_DIVERSE_SUBNETS distinct /16s (or the set is all-private,
        which is assumed to be a test environment).

        This is advisory only — the node should log the warning but
        NOT halt operation.
        """
        if not current_outbound:
            # No peers at all — warn
            return False, "No outbound peers; subnet diversity check cannot pass"

        # If all peers are private/localhost, assume test environment — OK
        public_peers = [
            (ip, port) for ip, port in current_outbound
            if not _is_private_or_loopback(ip)
        ]
        if not public_peers:
            return True, ""

        subnets = set(get_subnet(ip) for ip, _port in public_peers)
        if len(subnets) >= MIN_DIVERSE_SUBNETS:
            return True, ""

        return False, (
            f"Low subnet diversity: {len(subnets)} distinct /16 subnets "
            f"in outbound set (minimum recommended: {MIN_DIVERSE_SUBNETS}). "
            f"Eclipse attack risk is elevated."
        )
