"""Cold-start funding faucet for the public feed server.

Purpose: close the receive-to-exist cold-start gap.  MessageChain
requires a wallet to have on-chain balance before its first send
(the chain rejects "Unknown entity -- must register first" otherwise),
which means a fresh user with a freshly-generated keyfile cannot
post anything until somebody sends them tokens.  Without an
allocation path the chain is read-only for the public.

This module implements a Phase-1 operator-funded drip faucet:

  * Operator-controlled wallet (separate from the validator hot key)
    funded out-of-band with a one-time transfer from a token holder.
  * `/faucet` POST endpoint on the public feed server takes
    `{"address": "<entity_id_hex>"}` and sends a fixed `FAUCET_DRIP`
    transfer to it.
  * Three rate-limit layers, in order:
      - per-/24 IP cooldown (one drip per 24h per CIDR)
      - per-address one-time (an address can claim once, ever, while
        the process lives -- in-memory, lost on restart)
      - per-day aggregate cap (FAUCET_DAILY_CAP drips/day across
        all sources)
  * No CAPTCHA dependency -- adding a third-party captcha would
    violate the project's no-external-deps principle.  The
    rate-limit triple is good enough for a single-validator-set
    bootstrap chain; if Sybil drains exceed the daily cap for a
    sustained week, revisit.

State is in-memory and intentionally non-durable.  A restart resets
the per-address claim list and the per-IP cooldowns; the daily cap
counter is reconstructed from scratch.  This keeps the surface
small for v1; persistent state moves to Phase 2 once we see real
abuse patterns worth defending against.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("messagechain.faucet")


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

    _lock: threading.Lock = field(default_factory=threading.Lock)
    _ip_last_drip: dict[str, float] = field(default_factory=dict)
    _addresses_claimed: set[bytes] = field(default_factory=set)
    _day: int = 0
    _drips_today: int = 0

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
    ) -> FaucetDripResult:
        """Attempt one drip.  Returns a result object with the outcome.

        Order of checks (most-likely-fail first to keep failures cheap):
          1. recipient_hex is a valid 64-char hex entity_id.
          2. address has not already claimed (one-shot per process).
          3. /24 IP has not drip'd in the last 24 hours.
          4. daily cap not yet exhausted.
          5. submit_callback succeeds.

        On success: state is committed (IP cooldown set, address
        added to claimed set, daily counter incremented) BEFORE the
        function returns, so a concurrent request cannot double-spend
        the same slot.
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

        cidr = _ip_cidr_24(client_ip)

        with self._lock:
            now = time.time()
            self._reset_day_if_rolled_locked(now)

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
