"""Cold-start funding faucet for the public feed server.

Purpose: close the receive-to-exist cold-start gap.  Pre-Tier-11,
MessageChain rejected first messages from any wallet whose pubkey
wasn't on chain yet; Tier 11 (FIRST_SEND_PUBKEY_HEIGHT) added v3
sender_pubkey reveal so the receive-to-exist install also covers
messaging.  But the FIRST hop -- getting any tokens at all to the
fresh wallet -- still requires somebody to send them tokens, and
without a public allocation path the chain stays effectively
read-only for the general public.

This module implements an operator-funded drip faucet that closes
that hop:

  * Operator-controlled wallet (separate from the validator hot key)
    funded out-of-band with a one-time transfer from a token holder.
  * `POST /faucet` accepts `{"address", "challenge_seed", "nonce"}`
    and sends a fixed `FAUCET_DRIP` transfer to the address after
    verifying the proof-of-work nonce against the issued challenge.
  * `GET /faucet/challenge?address=<hex>` issues a fresh challenge
    bound to the address.  The client (browser WebWorker) finds a
    nonce such that sha256(seed || nonce || address) has FAUCET_POW_BITS
    leading zero bits; tuned for ~5s on a desktop browser, ~15s on
    mobile.  PoW makes bulk Sybil farming uneconomical without
    requiring a third-party CAPTCHA -- staying inside the project's
    no-external-deps stance and keeping Tor / privacy users
    first-class (they pay CPU, not credentials).
  * IP rate-limit (per-/24 cooldown) is kept as defense-in-depth,
    but treated as the cheap first filter rather than the actual
    gate -- VPNs and CGNAT make per-IP throttling noisy.  PoW does
    the real work; IP limits stop noise.
  * Per-address one-shot: a given address can claim once per
    process lifetime regardless of IP / PoW.
  * Per-day aggregate cap: FAUCET_DAILY_CAP drips total per UTC day,
    cap on operator's daily exposure.

State is in-memory and intentionally non-durable.  A restart resets
the per-address claim list, per-IP cooldowns, and outstanding
challenges; the daily cap counter is reconstructed from scratch.
This keeps the surface small for v1; persistent state moves to
Phase 2 once we see real abuse patterns worth defending against.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("messagechain.faucet")


# Proof-of-work difficulty in leading zero bits of sha256(seed || nonce
# || address).  At ~1M sha256/s in browser JS, 22 bits requires ~4M
# tries on average = ~4 seconds desktop / ~12s mobile.  Honest users
# pay CPU, not credentials -- privacy/Tor users stay first-class.
# Each unique address requires an independent PoW: bulk farming N
# addresses costs N * average_solve_time, so daily-cap drains take
# real wall-clock time even with parallel hardware.
FAUCET_POW_BITS = 22

# Outstanding challenge TTL.  Long enough that a slow mobile device
# can solve, short enough that we don't accumulate millions of
# unsolved challenges in memory.  10 minutes covers the 99th
# percentile mobile solver.
FAUCET_CHALLENGE_TTL_SEC = 600

# Cap on outstanding challenges to bound memory.  Eviction policy
# is FIFO-by-expiry (oldest first) when the cap is hit.  4096
# pending challenges at ~96 bytes each = ~400 KB worst case.
FAUCET_MAX_PENDING_CHALLENGES = 4096


# Per-drip token amount.  Sized for ~3-4 short messages at the live
# LINEAR fee floor (BASE_TX_FEE=10 + FEE_PER_STORED_BYTE=1 * stored).
# Big enough that the user can experiment, small enough that abuse
# costs the operator only modest amounts before the daily cap fires.
FAUCET_DRIP = 1000

# Maximum drips per UTC day across all sources.  Hard ceiling on the
# operator's daily exposure.  At FAUCET_DRIP=1000 + transfer fee ~=
# 200, a fully drained day costs ~120,000 tokens.  The faucet wallet
# should be funded for ~2-3x this so a sustained-cap week does not
# dry it out before refill.
FAUCET_DAILY_CAP = 50

# Per-/24 IP cooldown.  24 hours.  /24 chosen instead of full /32 so
# a residential NAT does not give one user 256 drips by cycling
# devices on the same network -- still cheap to defeat with a /16
# IP pool but raises the bar for casual abuse.
FAUCET_IP_COOLDOWN_SEC = 86_400


def _ip_cidr_24(ip: str) -> str:
    """Return the /24 prefix of an IPv4 address as a string.

    Falls back to the original string for IPv6 (the /24 concept does
    not transfer cleanly), so each unique IPv6 address is tracked
    individually.  Acceptable for v1: IPv6-only abusers are rare
    enough that per-IP cooldown is sufficient defense.
    """
    if "." not in ip:
        return ip  # IPv6 or unparseable -- track per full address
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return ".".join(parts[:3]) + ".0/24"


def _utc_day(ts: float) -> int:
    """UTC day number for the given Unix timestamp.

    Dividing by 86400 gives a stable bucket that rolls over at
    UTC midnight, which matches what an operator would expect when
    looking at the daily cap counter.
    """
    return int(ts // 86_400)


@dataclass
class FaucetDripResult:
    ok: bool
    error: str = ""
    tx_hash: str = ""
    amount: int = 0
    remaining_today: int = 0


@dataclass
class FaucetChallenge:
    """A PoW challenge bound to a specific recipient address.

    `seed` is 16 random bytes generated by os.urandom and serves as
    the unique identifier (also the dedup key in _pending_challenges).
    `address` binds the PoW to a specific recipient -- finding a nonce
    for one address does not transfer to another, so an attacker
    cannot pre-mine a nonce pool and burn it across many requests.
    `expires_at` is the Unix timestamp after which the challenge is
    rejected (FAUCET_CHALLENGE_TTL_SEC from issuance).
    `difficulty` is the required leading-zero-bit count of
    sha256(seed || nonce_be_8 || address).
    """
    seed: bytes
    address: bytes
    expires_at: float
    difficulty: int


def _verify_pow(
    seed: bytes, nonce: int, address: bytes, difficulty: int,
) -> bool:
    """Return True iff sha256(seed || nonce_be_8 || address) has
    `difficulty` leading zero bits.

    Nonce is encoded as 8-byte big-endian so the client and server
    agree on the canonical bytes.  The hash function is SHA-256 to
    keep the browser implementation tiny (SubtleCrypto is async and
    awkward inside a tight loop; we use a JS sha256 fallback instead,
    so server-side stays sha256 too for symmetry).
    """
    if difficulty <= 0 or difficulty > 256:
        return False
    if nonce < 0 or nonce > 0xFFFFFFFFFFFFFFFF:
        return False
    digest = hashlib.sha256(
        seed + nonce.to_bytes(8, "big") + address,
    ).digest()
    # Count leading zero bits.  Walk byte-by-byte; in the typical
    # difficulty=22 case the loop exits within 3 bytes.
    zero_bits = 0
    for byte in digest:
        if byte == 0:
            zero_bits += 8
            continue
        # Count the leading zeros within this byte.
        for shift in range(7, -1, -1):
            if byte & (1 << shift):
                return zero_bits >= difficulty
            zero_bits += 1
        return zero_bits >= difficulty
    return zero_bits >= difficulty


@dataclass
class FaucetState:
    """In-memory rate-limit + drip-builder state.

    Thread-safe: every public method takes `_lock` for the duration
    of its read-modify-write.  All decisions are made under the
    lock; the actual transfer-tx build + submit happens inside the
    same critical section so a concurrent request cannot squeeze
    past the cap between the check and the commit.

    `submit_callback`:  function(tx_dict) -> (ok: bool, reason: str)
        Called with the serialized TransferTransaction dict.  The
        caller wires this to the validator's local _rpc_submit_transfer
        equivalent; we deliberately do NOT do an outbound RPC roundtrip
        because the faucet runs in the validator process.

    `build_tx_callback`:  function(recipient_bytes) -> tx_dict
        Returns a signed transfer-tx dict ready to submit.  Encapsulates
        the wallet (entity + keypair), nonce/leaf management, and fee
        selection.  Kept as a callback so the FaucetState object is
        wallet-agnostic and trivially testable with a mock.
    """

    submit_callback: Callable[[dict], tuple[bool, str]]
    build_tx_callback: Callable[[bytes], dict]
    drip_amount: int = FAUCET_DRIP
    daily_cap: int = FAUCET_DAILY_CAP
    ip_cooldown_sec: int = FAUCET_IP_COOLDOWN_SEC
    pow_difficulty: int = FAUCET_POW_BITS
    challenge_ttl_sec: int = FAUCET_CHALLENGE_TTL_SEC

    _lock: threading.Lock = field(default_factory=threading.Lock)
    _ip_last_drip: dict[str, float] = field(default_factory=dict)
    _addresses_claimed: set[bytes] = field(default_factory=set)
    # Outstanding PoW challenges keyed by seed (16-byte random).
    # Bounded by FAUCET_MAX_PENDING_CHALLENGES; oldest-by-expiry
    # evicted when full.
    _pending_challenges: dict[bytes, "FaucetChallenge"] = field(default_factory=dict)
    _day: int = 0
    _drips_today: int = 0

    def issue_challenge(self, address_hex: str) -> tuple[bool, str, dict]:
        """Mint a fresh PoW challenge for the given recipient address.

        Returns (ok, error, payload) where payload is a JSON-friendly
        dict the HTTP layer relays to the client.  Cleans up expired
        challenges as a side effect to bound memory.

        No rate limit on issuance: an attacker who spams /challenge
        gets back challenges they cannot use without solving the PoW
        anyway.  The per-address one-shot still applies at try_drip
        time, so a malicious requester cannot drain by hoarding
        challenges for an already-claimed address.
        """
        try:
            address = bytes.fromhex(address_hex.strip())
        except (ValueError, AttributeError):
            return False, "address must be 64 hex characters (entity_id)", {}
        if len(address) != 32:
            return False, (
                f"address must be 32 bytes (got {len(address)})"
            ), {}

        with self._lock:
            self._evict_expired_challenges_locked(time.time())

            # Refuse to issue more challenges than we can hold without
            # evicting old ones FIFO.  Eviction policy: drop the
            # oldest-by-expiry first to keep the working set fresh.
            if len(self._pending_challenges) >= FAUCET_MAX_PENDING_CHALLENGES:
                # Find and drop the soonest-to-expire entry.
                oldest_seed = min(
                    self._pending_challenges,
                    key=lambda s: self._pending_challenges[s].expires_at,
                )
                del self._pending_challenges[oldest_seed]

            seed = os.urandom(16)
            now = time.time()
            challenge = FaucetChallenge(
                seed=seed,
                address=address,
                expires_at=now + self.challenge_ttl_sec,
                difficulty=self.pow_difficulty,
            )
            self._pending_challenges[seed] = challenge

        return True, "", {
            "seed": seed.hex(),
            "address": address.hex(),
            "difficulty": self.pow_difficulty,
            "expires_at": challenge.expires_at,
            "ttl_sec": self.challenge_ttl_sec,
        }

    def _evict_expired_challenges_locked(self, now: float) -> int:
        """Drop expired challenges.  Caller MUST hold _lock.

        Returns number of entries dropped.  O(N) over the dict; runs
        on every challenge issuance + every drip attempt, both of
        which are already heavyweight ops, so the linear scan is
        free in practice.
        """
        stale = [
            seed for seed, ch in self._pending_challenges.items()
            if ch.expires_at <= now
        ]
        for seed in stale:
            del self._pending_challenges[seed]
        return len(stale)

    def _reset_day_if_rolled_locked(self, now: float) -> None:
        """Roll the daily counter at UTC midnight.

        Caller MUST hold `_lock`.  Cheap: integer compare per call.
        """
        today = _utc_day(now)
        if today != self._day:
            self._day = today
            self._drips_today = 0

    def remaining_today(self) -> int:
        with self._lock:
            self._reset_day_if_rolled_locked(time.time())
            return max(0, self.daily_cap - self._drips_today)

    def try_drip(
        self,
        client_ip: str,
        recipient_hex: str,
        challenge_seed_hex: str = "",
        nonce: int | None = None,
    ) -> FaucetDripResult:
        """Attempt one drip.  Returns a result object with the outcome.

        Order of checks (most-likely-fail first to keep failures cheap):
          1. recipient_hex is a valid 64-char hex entity_id.
          2. challenge_seed + nonce are present and valid PoW for this
             address (the actual abuse gate).
          3. address has not already claimed (one-shot per process).
          4. /24 IP has not drip'd in the last 24 hours (defense-in-depth).
          5. daily cap not yet exhausted (operator's exposure ceiling).
          6. submit_callback succeeds.

        On success: state is committed (challenge consumed, IP cooldown
        set, address added to claimed set, daily counter incremented)
        BEFORE the function returns, so a concurrent request cannot
        double-spend the same slot.
        """
        # Address sanity outside the lock -- pure CPU work.
        try:
            recipient_bytes = bytes.fromhex(recipient_hex.strip())
        except (ValueError, AttributeError):
            return FaucetDripResult(
                ok=False,
                error="address must be 64 hex characters (entity_id)",
            )
        if len(recipient_bytes) != 32:
            return FaucetDripResult(
                ok=False,
                error=f"address must be 32 bytes (got {len(recipient_bytes)})",
            )

        # Parse + validate the PoW solution outside the lock; the only
        # state read is the challenge dict, and we re-fetch under the
        # lock before consuming.
        try:
            challenge_seed = bytes.fromhex(challenge_seed_hex.strip())
        except (ValueError, AttributeError):
            return FaucetDripResult(
                ok=False,
                error="challenge_seed must be hex",
            )
        if len(challenge_seed) != 16:
            return FaucetDripResult(
                ok=False,
                error="challenge_seed must be 16 bytes",
            )
        if nonce is None or not isinstance(nonce, int):
            return FaucetDripResult(
                ok=False,
                error="nonce required (integer PoW solution)",
            )

        cidr = _ip_cidr_24(client_ip)

        with self._lock:
            now = time.time()
            self._reset_day_if_rolled_locked(now)
            self._evict_expired_challenges_locked(now)

            # PoW gate -- the actual abuse defense.  Missing/expired
            # challenge or wrong nonce both fail here BEFORE we touch
            # any other rate-limit state, so a malformed POST does not
            # consume the per-IP cooldown slot or the daily cap.
            challenge = self._pending_challenges.get(challenge_seed)
            if challenge is None:
                return FaucetDripResult(
                    ok=False,
                    error=(
                        "challenge unknown or expired -- request a fresh "
                        "one via GET /faucet/challenge"
                    ),
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )
            if challenge.address != recipient_bytes:
                return FaucetDripResult(
                    ok=False,
                    error=(
                        "challenge was issued for a different address -- "
                        "request a new challenge bound to this address"
                    ),
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )
            if not _verify_pow(
                challenge.seed, nonce, challenge.address,
                challenge.difficulty,
            ):
                return FaucetDripResult(
                    ok=False,
                    error=(
                        f"nonce does not satisfy proof-of-work "
                        f"(need {challenge.difficulty} leading zero bits)"
                    ),
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )
            # Consume the challenge atomically so a stolen pair cannot
            # be replayed even if it satisfies the PoW.  Drop it from
            # the pending set BEFORE checking the other rate limits so
            # a per-address-claimed rejection still burns the challenge
            # (the requester needs to do new PoW for the next attempt).
            del self._pending_challenges[challenge_seed]

            if recipient_bytes in self._addresses_claimed:
                return FaucetDripResult(
                    ok=False,
                    error=(
                        "this address has already received a drip from "
                        "this faucet (one per address)"
                    ),
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )

            last = self._ip_last_drip.get(cidr)
            if last is not None and now - last < self.ip_cooldown_sec:
                wait_h = (self.ip_cooldown_sec - (now - last)) / 3600.0
                return FaucetDripResult(
                    ok=False,
                    error=(
                        f"this network ({cidr}) already received a drip "
                        f"in the last 24h; try again in {wait_h:.1f}h"
                    ),
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )

            if self._drips_today >= self.daily_cap:
                return FaucetDripResult(
                    ok=False,
                    error=(
                        f"daily faucet cap ({self.daily_cap} drips) "
                        "reached; resets at 00:00 UTC"
                    ),
                    remaining_today=0,
                )

            # Build + submit INSIDE the lock so a concurrent request
            # cannot race the cap counter between check and commit.
            try:
                tx_dict = self.build_tx_callback(recipient_bytes)
            except Exception as e:
                logger.exception("faucet build_tx failed")
                return FaucetDripResult(
                    ok=False,
                    error=f"faucet wallet build failed: {e}",
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )

            ok, reason = self.submit_callback(tx_dict)
            if not ok:
                logger.warning("faucet submit rejected: %s", reason)
                return FaucetDripResult(
                    ok=False,
                    error=f"chain rejected drip tx: {reason}",
                    remaining_today=max(0, self.daily_cap - self._drips_today),
                )

            # Success path: commit state.
            self._ip_last_drip[cidr] = now
            self._addresses_claimed.add(recipient_bytes)
            self._drips_today += 1
            tx_hash = tx_dict.get("tx_hash", "")
            logger.info(
                "faucet drip: %s -> %s amount=%d (today=%d/%d)",
                cidr, recipient_hex[:16], self.drip_amount,
                self._drips_today, self.daily_cap,
            )
            return FaucetDripResult(
                ok=True,
                tx_hash=tx_hash,
                amount=self.drip_amount,
                remaining_today=max(0, self.daily_cap - self._drips_today),
            )
