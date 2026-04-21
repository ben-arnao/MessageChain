"""
Peer misbehavior scoring and banning system (BTC-inspired).

Every peer starts with a score of 0. Misbehavior increments the score.
When a peer exceeds BAN_THRESHOLD, they are banned for BAN_DURATION seconds.
Banned peers are refused connections and their messages are dropped.

Score assignments follow Bitcoin Core's logic:
- Invalid block/tx:    100 (instant ban)
- Invalid headers:      50
- Unrequested data:     20
- Protocol violation:   10
- Minor infractions:     1-5
"""

import time
import logging
import ipaddress
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _normalize_ip_for_bucket(ip_str: str) -> str:
    """Normalize an IP string to the ban/rate-limit bucket key.

    IPv4 -> canonical dotted-quad ("1.2.3.4").
    IPv6 -> /64 network prefix ("2001:db8::/64") because a /64 is the
    standard end-site allocation; rotating within it is free for any
    IPv6-enabled adversary and defeats per-address bucketing.
    Non-IP strings pass through unchanged so 'unknown' etc. still work.
    """
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except (ValueError, AttributeError):
        return ip_str
    if isinstance(addr, ipaddress.IPv4Address):
        return str(addr)
    # IPv6: mask to /64.
    net = ipaddress.ip_network(f"{addr}/64", strict=False)
    return str(net)

# Thresholds
BAN_THRESHOLD = 100       # score at which a peer gets banned
BAN_DURATION = 86400      # 24 hours in seconds
DECAY_INTERVAL = 3600     # score decays by 1 every hour of good behavior
MAX_TRACKED_PEERS = 5000  # limit memory usage for tracking
# Non-decaying cumulative offense ceiling. A patient attacker who offends
# just under BAN_THRESHOLD and waits for decay to reset the score can
# otherwise misbehave indefinitely. This "lifetime" counter never decays,
# so once a peer crosses it they are banned regardless of recent behavior.
# Set to 2x ban threshold — harmless peers with occasional one-off glitches
# still get forgiveness, but sustained gaming is caught.
LIFETIME_BAN_MULTIPLIER = 2

# Offense severities (same scale as Bitcoin Core)
OFFENSE_INVALID_BLOCK = 100       # instant ban
OFFENSE_INVALID_TX = 100          # instant ban
# Serving a header at a known weak-subjectivity checkpoint height with a
# different hash is unambiguous history-forging. There is no honest
# reason to do this once, so there is no reason to tolerate it once.
# Matches Bitcoin Core's instant-disconnect policy for checkpoint lies.
OFFENSE_CHECKPOINT_VIOLATION = 100
OFFENSE_INVALID_HEADERS = 50
OFFENSE_UNREQUESTED_DATA = 20
OFFENSE_PROTOCOL_VIOLATION = 10
OFFENSE_RATE_LIMIT = 5
OFFENSE_MINOR = 1


@dataclass
class PeerScore:
    score: int = 0
    # Lifetime cumulative offense points — NEVER decays. Closes the
    # decay-gaming attack where a peer offends just under BAN_THRESHOLD,
    # waits for hourly decay, and repeats indefinitely.
    lifetime_score: int = 0
    banned_until: float = 0.0
    last_decay: float = field(default_factory=time.time)
    offenses: list = field(default_factory=list)  # [(timestamp, reason, points)]

    @property
    def is_banned(self) -> bool:
        if self.banned_until == 0:
            return False
        if time.time() >= self.banned_until:
            # Ban expired, reset current score but KEEP lifetime_score —
            # a peer that was banned once should not get a clean slate.
            self.banned_until = 0.0
            self.score = 0
            self.offenses.clear()
            return False
        return True


class PeerBanManager:
    """Tracks misbehavior scores and bans for all peers.

    Peers are identified by their IP address (not port), so reconnecting
    on a different port doesn't dodge a ban.
    """

    def __init__(self, ban_threshold: int = BAN_THRESHOLD,
                 ban_duration: int = BAN_DURATION):
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self._scores: dict[str, PeerScore] = {}  # ip -> PeerScore

    def _get_ip(self, address: str) -> str:
        """Extract a bucket key from 'host:port' for ban accounting.

        IPv4 bucket is the full /32 address (flooding at scale requires
        real v4 allocations, which are scarce).  IPv6 bucket is the
        /64 prefix because a /64 is the standard end-site allocation
        and a cloud attacker trivially rotates addresses within it —
        keying on /128 gives every rotation a fresh ban score, defeating
        the defense for any IPv6-enabled adversary.  Matches Bitcoin
        Core's 2021-era netgroup bucketing.
        """
        raw = address
        if address.startswith("["):
            bracket_end = address.find("]")
            if bracket_end != -1:
                raw = address[1:bracket_end]
        elif ":" in address:
            # IPv4:port — count colons to distinguish from bare IPv6.
            if address.count(":") == 1:
                raw = address.rsplit(":", 1)[0]
            # else: bare IPv6 literal without brackets, leave as-is.
        return _normalize_ip_for_bucket(raw)

    def _get_score(self, ip: str) -> PeerScore:
        if ip not in self._scores:
            if len(self._scores) >= MAX_TRACKED_PEERS:
                # Evict oldest non-banned entry
                self._evict_oldest()
            self._scores[ip] = PeerScore()
        return self._scores[ip]

    def _evict_oldest(self):
        """Remove the oldest non-banned peer to free memory."""
        oldest_ip = None
        oldest_time = float("inf")
        for ip, ps in self._scores.items():
            if not ps.is_banned and ps.last_decay < oldest_time:
                oldest_time = ps.last_decay
                oldest_ip = ip
        if oldest_ip:
            del self._scores[oldest_ip]

    def is_banned(self, address: str) -> bool:
        """Check if a peer is currently banned."""
        ip = self._get_ip(address)
        ps = self._scores.get(ip)
        if ps is None:
            return False
        return ps.is_banned

    def record_offense(self, address: str, points: int, reason: str) -> bool:
        """Record a misbehavior offense. Returns True if peer is now banned."""
        ip = self._get_ip(address)
        ps = self._get_score(ip)

        if ps.is_banned:
            return True  # already banned

        # Apply score decay based on time since last offense
        now = time.time()
        elapsed_hours = (now - ps.last_decay) / DECAY_INTERVAL
        if elapsed_hours >= 1:
            decay = int(elapsed_hours)
            ps.score = max(0, ps.score - decay)
            ps.last_decay = now

        ps.score += points
        ps.lifetime_score += points
        ps.offenses.append((now, reason, points))

        # Trim offense history to last 50
        if len(ps.offenses) > 50:
            ps.offenses = ps.offenses[-50:]

        logger.info(
            f"Peer {ip} offense: {reason} "
            f"(+{points}, current={ps.score}, lifetime={ps.lifetime_score})"
        )

        lifetime_ceiling = self.ban_threshold * LIFETIME_BAN_MULTIPLIER
        if ps.score >= self.ban_threshold or ps.lifetime_score >= lifetime_ceiling:
            ps.banned_until = now + self.ban_duration
            logger.warning(
                f"Peer {ip} BANNED for {self.ban_duration}s "
                f"(score={ps.score}, lifetime={ps.lifetime_score}, reason={reason})"
            )
            return True

        return False

    def manual_ban(self, address: str, duration: int | None = None, reason: str = "manual"):
        """Manually ban a peer."""
        ip = self._get_ip(address)
        ps = self._get_score(ip)
        ps.score = self.ban_threshold
        ps.banned_until = time.time() + (duration or self.ban_duration)
        ps.offenses.append((time.time(), reason, self.ban_threshold))
        logger.warning(f"Peer {ip} manually banned: {reason}")

    def manual_unban(self, address: str):
        """Manually unban a peer.

        Resets lifetime_score too, so an operator-granted second chance
        is a genuine clean slate (unlike automatic ban expiry).
        """
        ip = self._get_ip(address)
        if ip in self._scores:
            self._scores[ip].score = 0
            self._scores[ip].lifetime_score = 0
            self._scores[ip].banned_until = 0.0
            self._scores[ip].offenses.clear()
            logger.info(f"Peer {ip} manually unbanned")

    def get_score(self, address: str) -> int:
        """Get a peer's current misbehavior score."""
        ip = self._get_ip(address)
        ps = self._scores.get(ip)
        return ps.score if ps else 0

    def get_banned_peers(self) -> list[dict]:
        """Get list of currently banned peers."""
        now = time.time()
        banned = []
        for ip, ps in self._scores.items():
            if ps.is_banned:
                banned.append({
                    "ip": ip,
                    "score": ps.score,
                    "banned_until": ps.banned_until,
                    "remaining_seconds": int(ps.banned_until - now),
                    "last_offense": ps.offenses[-1][1] if ps.offenses else "",
                })
        return banned

    def cleanup_expired(self):
        """Remove expired ban entries and zero-score peers."""
        to_remove = []
        for ip, ps in self._scores.items():
            if not ps.is_banned and ps.score == 0 and not ps.offenses:
                to_remove.append(ip)
        for ip in to_remove:
            del self._scores[ip]
