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

import json
import os
import tempfile
import time
import logging
import ipaddress
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Debounce interval for disk saves.  Every record_offense() could
# otherwise trigger a syscall-heavy atomic write; for a noisy peer
# hammering us with OFFENSE_RATE_LIMIT events that becomes a hot loop.
# Transition events (becoming banned / becoming unbanned) bypass the
# debounce so the critical durability point is never delayed.
_BAN_SAVE_DEBOUNCE_SEC = 2.0


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

# Thresholds - authoritative definitions live in messagechain.config.
# Importing via the config module so config_local.py overrides actually
# take effect (iter 5 audit found these were previously redefined here,
# silently breaking any operator's attempt to tune ban policy).
from messagechain.config import (
    BAN_THRESHOLD, BAN_DURATION, DECAY_INTERVAL, MAX_TRACKED_PEERS,
)
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
    # Wall-clock time of first offense — persisted so we can tell
    # "long-running misbehaver" apart from "freshly tracked peer"
    # across restarts.  Not used for decisions today but cheap to keep
    # and avoids a schema-migration story if we need it later.
    first_seen: float = field(default_factory=time.time)
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
                 ban_duration: int = BAN_DURATION,
                 persistence_path: str | None = None):
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self._scores: dict[str, PeerScore] = {}  # ip -> PeerScore
        # Persistence: when a path is configured, ban state is serialized
        # to disk so bans survive node restarts.  Default None preserves
        # old behavior for tests and in-memory fixtures.  A peer banned
        # moments before an OOM kill or maintenance reboot previously
        # reconnected fresh — now they stay banned.
        self._persistence_path: str | None = persistence_path
        self._last_save_time: float = 0.0
        if persistence_path is not None:
            self._load()

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
            # Ban transition = critical durability point; force-save
            # so a crash between "decided to ban" and "next debounced
            # save" cannot lose the ban.
            self._maybe_save(force=True)
            return True

        # Non-ban offense: debounced save so a flood of low-weight
        # offenses doesn't turn into a syscall hot loop.
        self._maybe_save()
        return False

    def manual_ban(self, address: str, duration: int | None = None, reason: str = "manual"):
        """Manually ban a peer."""
        ip = self._get_ip(address)
        ps = self._get_score(ip)
        ps.score = self.ban_threshold
        ps.banned_until = time.time() + (duration or self.ban_duration)
        ps.offenses.append((time.time(), reason, self.ban_threshold))
        logger.warning(f"Peer {ip} manually banned: {reason}")
        # Operator-issued bans bypass debounce — they're rare and
        # high-intent, and an operator expects durability.
        self._maybe_save(force=True)

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
            # Operator unban is a transition — force-save so a crash
            # doesn't leave the peer banned after intentional pardon.
            self._maybe_save(force=True)

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

    # ─── Persistence ───────────────────────────────────────────────
    # Ban state lives on disk so a peer banned just before a restart
    # (OOM kill, maintenance reboot) stays banned on boot.  Otherwise
    # a patient attacker waits for the next restart window and returns
    # with a clean slate.  Schema:
    #   { "<ip>": {
    #         "score": int,
    #         "lifetime_score": int,
    #         "first_seen": float,
    #         "banned_until": float-or-null,
    #     }, ... }
    # Ephemeral fields (last_decay, offenses history) are NOT persisted
    # — they're diagnostic, large, and can't be trusted across a
    # restart boundary anyway.  On load, last_decay resets to "now" so
    # decay math still works.

    def save(self, force: bool = False) -> None:
        """Persist ban state to disk (public alias for tests / shutdown)."""
        self._maybe_save(force=force)

    def _maybe_save(self, force: bool = False) -> None:
        """Debounced atomic save of ban state.

        Force-save bypasses the debounce — used on ban/unban transitions
        so a crash between "decided to ban" and the next debounce tick
        can't lose the ban.
        """
        if self._persistence_path is None:
            return
        now = time.time()
        if not force and (now - self._last_save_time) < _BAN_SAVE_DEBOUNCE_SEC:
            return
        self._last_save_time = now
        self._write_to_disk()

    def _serialize(self) -> dict:
        """Convert _scores to the on-disk JSON-friendly shape."""
        out: dict[str, dict] = {}
        for ip, ps in self._scores.items():
            out[ip] = {
                "score": int(ps.score),
                "lifetime_score": int(ps.lifetime_score),
                "first_seen": float(ps.first_seen),
                # banned_until == 0 means "not banned" — store as null
                # so the on-disk file is self-describing for humans.
                "banned_until": (
                    float(ps.banned_until) if ps.banned_until else None
                ),
            }
        return out

    def _write_to_disk(self) -> None:
        """Atomic tmp-file + fsync + rename.  Matches AnchorStore pattern."""
        path = self._persistence_path
        if path is None:
            return
        try:
            payload = json.dumps(self._serialize())
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize ban state for {path}: {e}")
            return
        parent = os.path.dirname(path) or "."
        tmp_fd = None
        tmp_path = None
        try:
            os.makedirs(parent, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=os.path.basename(path) + ".",
                suffix=".tmp",
                dir=parent,
            )
            with os.fdopen(tmp_fd, "w") as f:
                tmp_fd = None  # fdopen took ownership
                f.write(payload)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync not supported on every FS (e.g. some tmpfs);
                    # non-fatal — the rename is still atomic.
                    pass
            os.replace(tmp_path, path)
            tmp_path = None  # successfully renamed
        except OSError as e:
            logger.warning(f"Failed to save ban state to {path}: {e}")
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception as e:
            logger.warning(f"Unexpected error saving ban state to {path}: {e}")
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _load(self) -> None:
        """Load ban state from disk.  Safe against missing / corrupt files.

        Any parse error logs a WARNING and leaves _scores empty — we'd
        rather forget a few bans than crash on boot.  Entries whose
        ban has already expired are dropped silently; they carry no
        enforcement value but would otherwise clutter the in-memory map.
        """
        path = self._persistence_path
        if path is None or not os.path.exists(path):
            return
        try:
            with open(path, "r") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.warning(
                f"Ban state file at {path} is unreadable ({e}); "
                f"starting with empty ban table"
            )
            return
        if not isinstance(raw, dict):
            logger.warning(
                f"Ban state file at {path} is malformed (not a dict); "
                f"starting with empty ban table"
            )
            return
        now = time.time()
        for ip, entry in raw.items():
            if not isinstance(ip, str) or not isinstance(entry, dict):
                continue
            try:
                score = int(entry.get("score", 0))
                lifetime_score = int(entry.get("lifetime_score", 0))
                first_seen = float(entry.get("first_seen", now))
                bu_raw = entry.get("banned_until")
                banned_until = float(bu_raw) if bu_raw else 0.0
            except (TypeError, ValueError):
                # A single bad row is not a reason to discard the
                # whole file — silently skip it and keep going.
                continue
            # Drop entries whose ban already expired before we loaded.
            # They carry no enforcement weight and would waste space
            # until cleanup_expired() ran.
            if banned_until and banned_until <= now:
                continue
            self._scores[ip] = PeerScore(
                score=score,
                lifetime_score=lifetime_score,
                banned_until=banned_until,
                # last_decay resets to "now" on load — we have no
                # trustworthy record of when the last on-disk decay
                # tick happened, and resetting avoids a stale timestamp
                # causing an instant over-decay.
                last_decay=now,
                first_seen=first_seen,
                offenses=[],
            )
