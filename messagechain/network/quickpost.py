"""Server-assisted "quick try it" message-send flow for the public feed.

Purpose: lower the friction of "post my first message" from a
multi-step CLI walkthrough (install, generate-key, faucet, wait, send)
to a single browser click.  The visitor types a message, the server
generates an ephemeral keypair on their behalf, faucets it, queues
the message for submission once the drip confirms, and streams the
private key back as a downloadable keyfile.

This is explicitly a "try it" path, not a real-wallet path.  The
private key was generated on the server and briefly held in server
memory — a curious visitor gets a real on-chain message in seconds,
but the README (and the UI disclaimer) tells them to generate offline
for any account they intend to keep.

Architecture:

  * `QuickpostState` runs alongside `FaucetState` in the validator
    process.  It holds its own PoW challenge dict so /quickpost
    challenges do not collide with /faucet challenges, and shares
    rate-limit budget with the faucet by routing drips through
    `FaucetState.drip_for_quickpost` (same per-/24 cooldown, same
    window cap).
  * PoW is bound to `sha256(message_utf8)` rather than a recipient
    address, since the address does not exist at challenge time
    (the keypair is generated server-side AFTER PoW verification).
    The challenge seed itself is the one-shot anti-replay gate —
    server-issued, tracked in _pending_challenges, consumed atomically
    on the drip path.
  * After a successful drip, the message tx cannot be submitted yet:
    the fresh entity has zero on-chain balance until the drip is
    included in a block, and the chain rejects message txs from
    entities with no balance.  The watcher thread polls the chain
    every 30s; once the drip lands and the entity has nonzero
    balance, it builds + signs + submits the queued message tx.
  * Job state is in-memory and intentionally non-durable.  A
    server restart loses the pending-message queue, but the visitor
    has the keyfile in their downloads folder — they can post the
    message manually via the CLI if they care.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from messagechain.network.faucet import (
    FAUCET_CHALLENGE_TTL_SEC,
    FAUCET_MAX_PENDING_CHALLENGES,
    FAUCET_POW_BITS,
    FaucetChallenge,
    FaucetDripResult,
    FaucetState,
    _verify_pow,
)

logger = logging.getLogger("messagechain.quickpost")


# Tree height for the ephemeral demo wallet.  Sized for "this is a
# try-it path, not a real wallet": h=4 = 16 leaves means keygen is
# sub-second on any hardware, the user gets enough leaves to play
# with a few sends if they want, and a serious user is told to
# regenerate offline at the standard wallet height anyway.
QUICKPOST_TREE_HEIGHT = 4

# Max pending message-send jobs awaiting drip confirmation.  Each job
# holds an Entity (with WOTS+ keypair, ~few KB at h=4) plus a string
# message.  64 jobs at ~10 KB = ~640 KB worst case.  Bounded so a
# burst at the rate-limit edge cannot grow the queue unboundedly.
QUICKPOST_MAX_PENDING_JOBS = 64

# How long the watcher waits between polls of pending jobs.  Block
# cadence is ~10 minutes in production and ~30s in prototype, so a
# 30s poll wakes up at most once per block on prod and a few times
# per block on prototype — cheap regardless.
QUICKPOST_WATCHER_POLL_SEC = 30

# Drop a queued job after this many seconds without a successful
# drip-confirmation.  Twelve hours is conservative: the drip should
# confirm within one block (~10 min on prod), so anything still
# pending after 12h is almost certainly a stuck node or a dropped
# drip tx the operator should investigate.  Leaving the job in the
# queue forever would slowly leak memory across restarts of the
# validator; the user has the keyfile and can repost manually.
QUICKPOST_JOB_MAX_AGE_SEC = 12 * 3600


@dataclass
class QuickpostChallenge:
    """A PoW challenge for the /quickpost flow.

    Mirrors `FaucetChallenge` but with no `address` field — the
    challenge is bound to the message hash via the verification
    formula sha256(seed || nonce_be_8 || sha256(message)) instead.
    """
    seed: bytes
    expires_at: float
    difficulty: int


@dataclass
class QuickpostResult:
    ok: bool
    error: str = ""
    entity_id_hex: str = ""
    private_key_hex: str = ""
    drip_tx_hash: str = ""
    remaining_window: int = 0


@dataclass
class _QuickpostJob:
    entity: Any  # messagechain.identity.identity.Entity
    message: str
    drip_tx_hash: str
    enqueued_at: float
    last_attempt_at: float = 0.0
    attempts: int = 0


@dataclass
class QuickpostState:
    """Server-assisted "try it" message-send flow.

    Drips are routed through ``faucet.drip_for_quickpost`` so the
    operator-facing per-window cap is the SAME budget the /faucet
    endpoint enforces — a quickpost consumes one drip slot.

    `keygen_callback`:  function() -> (entity, private_key_bytes)
        Generates a fresh ephemeral keypair at QUICKPOST_TREE_HEIGHT.
        Kept as a callback so this module stays decoupled from the
        Entity/keypair-cache plumbing.

    `submit_message_callback`:  function(entity, message) -> tx_hash_hex
        Builds + signs + submits the queued message tx.  Raises on
        failure; the watcher will retry on the next poll.

    `is_drip_confirmed`:  function(entity_id) -> bool
        Returns True iff the drip recipient has nonzero on-chain
        balance (i.e. the drip tx has been included in a finalized
        block).  Drives the watcher's "is this job ready to send"
        check.
    """

    faucet: FaucetState
    keygen_callback: Callable[[], tuple[Any, bytes]]
    submit_message_callback: Callable[[Any, str], str]
    is_drip_confirmed: Callable[[bytes], bool]

    pow_difficulty: int = FAUCET_POW_BITS
    challenge_ttl_sec: int = FAUCET_CHALLENGE_TTL_SEC
    max_message_bytes: int = 1024
    poll_interval_sec: int = QUICKPOST_WATCHER_POLL_SEC
    job_max_age_sec: int = QUICKPOST_JOB_MAX_AGE_SEC

    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pending_challenges: dict[bytes, QuickpostChallenge] = field(default_factory=dict)
    _pending_jobs: list[_QuickpostJob] = field(default_factory=list)
    _watcher_thread: Optional[threading.Thread] = None
    _watcher_stop: threading.Event = field(default_factory=threading.Event)

    # ---- Challenge issuance --------------------------------------

    def issue_challenge(self) -> tuple[bool, str, dict]:
        """Mint a fresh PoW challenge.

        Unlike the faucet challenge, no address binding — the user
        does not have an entity yet (the keypair is generated by the
        server AFTER PoW verification).  The seed alone is the
        anti-replay gate: server-issued, one-shot, consumed on /quickpost.
        """
        with self._lock:
            self._evict_expired_challenges_locked(time.time())
            if len(self._pending_challenges) >= FAUCET_MAX_PENDING_CHALLENGES:
                oldest_seed = min(
                    self._pending_challenges,
                    key=lambda s: self._pending_challenges[s].expires_at,
                )
                del self._pending_challenges[oldest_seed]
            seed = os.urandom(16)
            now = time.time()
            challenge = QuickpostChallenge(
                seed=seed,
                expires_at=now + self.challenge_ttl_sec,
                difficulty=self.pow_difficulty,
            )
            self._pending_challenges[seed] = challenge
        return True, "", {
            "seed": seed.hex(),
            "difficulty": self.pow_difficulty,
            "expires_at": challenge.expires_at,
            "ttl_sec": self.challenge_ttl_sec,
        }

    def _evict_expired_challenges_locked(self, now: float) -> int:
        stale = [
            seed for seed, ch in self._pending_challenges.items()
            if ch.expires_at <= now
        ]
        for seed in stale:
            del self._pending_challenges[seed]
        return len(stale)

    # ---- Quickpost submission ------------------------------------

    def try_quickpost(
        self,
        client_ip: str,
        message: str,
        challenge_seed_hex: str = "",
        nonce: int | None = None,
    ) -> QuickpostResult:
        """Generate a fresh wallet, drip it, and queue the message tx.

        On success, returns the private key + entity id + drip tx hash
        immediately; the message itself is queued and submitted by the
        watcher thread once the drip lands.  The HTTP boundary streams
        the keyfile back to the client so the visitor walks away with
        a real wallet AND a real on-chain message that arrives a few
        minutes later.

        On any failure path before the drip is consumed, no rate-limit
        slot is burned (the PoW gate runs first; the IP cooldown +
        window cap are inside the drip path).  On success the slot is
        committed atomically before the function returns.
        """
        if not isinstance(message, str):
            return QuickpostResult(ok=False, error="message must be a string")
        if not message.strip():
            return QuickpostResult(ok=False, error="message must not be empty")
        try:
            msg_bytes = message.encode("utf-8")
        except UnicodeEncodeError:
            return QuickpostResult(
                ok=False, error="message must be valid UTF-8",
            )
        if len(msg_bytes) > self.max_message_bytes:
            return QuickpostResult(
                ok=False,
                error=(
                    f"message is {len(msg_bytes)} bytes UTF-8 "
                    f"(max {self.max_message_bytes})"
                ),
            )

        try:
            challenge_seed = bytes.fromhex(challenge_seed_hex.strip())
        except (ValueError, AttributeError):
            return QuickpostResult(ok=False, error="challenge_seed must be hex")
        if len(challenge_seed) != 16:
            return QuickpostResult(
                ok=False, error="challenge_seed must be 16 bytes",
            )
        if nonce is None or not isinstance(nonce, int):
            return QuickpostResult(
                ok=False, error="nonce required (integer PoW solution)",
            )

        message_hash = hashlib.sha256(msg_bytes).digest()

        with self._lock:
            self._evict_expired_challenges_locked(time.time())
            challenge = self._pending_challenges.get(challenge_seed)
            if challenge is None:
                return QuickpostResult(
                    ok=False,
                    error=(
                        "challenge unknown or expired -- request a fresh "
                        "one via GET /quickpost/challenge"
                    ),
                )
            if not _verify_pow(
                challenge.seed, nonce, message_hash, challenge.difficulty,
            ):
                return QuickpostResult(
                    ok=False,
                    error=(
                        f"nonce does not satisfy proof-of-work "
                        f"(need {challenge.difficulty} leading zero bits "
                        f"on sha256(seed || nonce || sha256(message)))"
                    ),
                )
            # Consume the challenge atomically so a stolen pair cannot
            # be replayed even if the drip path rejects (full queue,
            # cap exhausted, etc.) — the requester does fresh PoW for
            # the next attempt.
            del self._pending_challenges[challenge_seed]

            if len(self._pending_jobs) >= QUICKPOST_MAX_PENDING_JOBS:
                return QuickpostResult(
                    ok=False,
                    error=(
                        "too many pending quickposts awaiting drip "
                        "confirmation; try again in a few minutes"
                    ),
                )

        # Generate the ephemeral wallet OUTSIDE the lock — keygen at
        # QUICKPOST_TREE_HEIGHT is sub-second but still beats holding
        # the lock across CPU-bound work.
        try:
            entity, private_key = self.keygen_callback()
        except Exception as e:
            logger.exception("quickpost keygen failed")
            return QuickpostResult(
                ok=False, error=f"keygen failed: {e}",
            )

        # Drip via the faucet's shared rate-limit + tx-build path.
        # If this fails (cap reached, IP cooldown, chain rejection),
        # the keypair is discarded and the caller learns why.
        drip_result = self.faucet.drip_for_quickpost(
            client_ip, entity.entity_id,
        )
        if not drip_result.ok:
            return QuickpostResult(
                ok=False,
                error=drip_result.error,
                remaining_window=drip_result.remaining_window,
            )

        # Queue the message for submission once the drip confirms.
        with self._lock:
            self._pending_jobs.append(_QuickpostJob(
                entity=entity,
                message=message,
                drip_tx_hash=drip_result.tx_hash,
                enqueued_at=time.time(),
            ))
        logger.info(
            "quickpost queued: entity=%s drip_tx=%s "
            "(%d jobs pending)",
            entity.entity_id.hex()[:16],
            drip_result.tx_hash[:16] if drip_result.tx_hash else "(none)",
            len(self._pending_jobs),
        )

        return QuickpostResult(
            ok=True,
            entity_id_hex=entity.entity_id.hex(),
            private_key_hex=private_key.hex(),
            drip_tx_hash=drip_result.tx_hash,
            remaining_window=drip_result.remaining_window,
        )

    # ---- Watcher -------------------------------------------------

    def start_watcher(self) -> None:
        """Spawn the background thread that submits queued messages.

        Idempotent: safe to call multiple times; only the first call
        starts a thread.
        """
        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            return
        self._watcher_stop.clear()
        self._watcher_thread = threading.Thread(
            target=self._watcher_loop,
            name="mc-quickpost-watcher",
            daemon=True,
        )
        self._watcher_thread.start()

    def stop_watcher(self, timeout: float = 5.0) -> None:
        self._watcher_stop.set()
        if self._watcher_thread is not None:
            self._watcher_thread.join(timeout=timeout)
            self._watcher_thread = None

    def _watcher_loop(self) -> None:
        while not self._watcher_stop.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("quickpost watcher tick failed")
            self._watcher_stop.wait(self.poll_interval_sec)

    def _tick(self) -> None:
        """One pass: try to submit any job whose drip has confirmed.

        Drops jobs older than `job_max_age_sec`.  Jobs that fail
        submission stay in the queue and retry on the next tick —
        a transient mempool reject (e.g. concurrent nonce churn) gets
        another shot rather than being silently dropped.
        """
        now = time.time()
        with self._lock:
            jobs = list(self._pending_jobs)

        for job in jobs:
            if now - job.enqueued_at > self.job_max_age_sec:
                logger.warning(
                    "quickpost dropping stale job: entity=%s "
                    "age=%.0fs drip=%s",
                    job.entity.entity_id.hex()[:16],
                    now - job.enqueued_at,
                    job.drip_tx_hash[:16] if job.drip_tx_hash else "(none)",
                )
                self._remove_job(job)
                continue

            try:
                confirmed = self.is_drip_confirmed(job.entity.entity_id)
            except Exception:
                logger.exception("quickpost is_drip_confirmed failed")
                continue
            if not confirmed:
                continue

            job.last_attempt_at = now
            job.attempts += 1
            try:
                tx_hash = self.submit_message_callback(job.entity, job.message)
            except Exception as e:
                logger.warning(
                    "quickpost message-submit attempt %d failed for entity=%s: %s",
                    job.attempts, job.entity.entity_id.hex()[:16], e,
                )
                continue

            logger.info(
                "quickpost message submitted: entity=%s tx=%s",
                job.entity.entity_id.hex()[:16],
                tx_hash[:16] if tx_hash else "(none)",
            )
            self._remove_job(job)

    def _remove_job(self, job: _QuickpostJob) -> None:
        with self._lock:
            try:
                self._pending_jobs.remove(job)
            except ValueError:
                pass

    def pending_job_count(self) -> int:
        with self._lock:
            return len(self._pending_jobs)
