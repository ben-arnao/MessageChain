"""
Fork-emergency detector — automatic detection of unintentional hard
forks via supermajority finality-vote signal.

Existing fork-choice picks the heavier branch automatically up to
MAX_REORG_DEPTH = 100. That covers shallow contention. The remaining
hole is the nightmare scenario for a small mainnet:

  A consensus bug or transient partition causes a minority of
  validators to accept a block the rest reject. The minority extends
  its bad branch past the reorg-depth bound. Heavier-chain logic on
  the minority node now refuses to follow the (correct) heavier
  branch back, and there is no automatic escape hatch — the operator
  must intervene by hand.

The supermajority signal exists already: every FinalityVote a
validator casts commits 2/3 of stake to a specific block hash at a
specific height. This detector observes those votes (already gossiped
network-wide and signature-verified) and asks one question:

  "Is there a height H at which 2/3+ of stake has signed a block
   hash my chain doesn't recognize?"

If yes, this node is on the wrong side of a fork. The detector
records the emergency. What happens next is policy:

  * Validators auto-halt block proposal + finality voting. This is
    safe-by-construction — a paused validator cannot make the fork
    worse, and never auto-flips to the supermajority chain (an
    autoflip on a quorum-signal bug would weaponize the bug into a
    network-wide chain abandonment).

  * Full nodes default to log-only. Operators may opt in to
    auto-rewind to the last common ancestor with the supermajority
    chain via FORK_EMERGENCY_AUTO_RECOVERY = True (see config). A
    full node has nothing to slash and no consensus role, so an
    incorrect rewind costs only resync time.

What the detector deliberately does NOT do:

  * Trust unverified peer claims. Every vote fed in must already be
    signature-verified by the caller — gossip ingest does this once,
    so detector input is free.

  * Decide WHICH chain is correct. It only flags "supermajority
    signed a hash you don't have." The 2/3 threshold matches
    FINALITY_THRESHOLD so the signal IS the same one consensus
    already trusts to finalize.

  * Auto-act on its own. Action lives at integration sites
    (validator loop, optional full-node recovery), so a single
    test-only test shim cannot accidentally rewind production.

Storage and bounds:
  * Per-(height, hash) accumulators are bounded by
    FORK_EMERGENCY_MAX_TRACKED_HEIGHTS to cap memory under a
    pathological vote flood. LRU eviction by height — the most
    recently-seen height wins.
  * One vote per signer per (height, hash) is counted (idempotent).
  * A single signer voting for two different hashes at the same
    height is the equivocation that
    FinalityCheckpoints.add_vote already auto-slashes; the
    detector mirrors that: only the first hash seen for that
    (signer, height) accumulates stake. The second is ignored
    because the equivocator's stake is about to be burned anyway.
"""

import logging
import time
from dataclasses import dataclass, field

from messagechain.config import (
    FINALITY_THRESHOLD_DENOMINATOR,
    FINALITY_THRESHOLD_NUMERATOR,
)
from messagechain.consensus.finality import FinalityVote

logger = logging.getLogger(__name__)


# Cap how many distinct target heights the detector will track at
# once. A pathological flood of votes for distinct heights cannot
# grow memory without bound — the LRU eviction below keeps the
# most recently observed heights and drops the oldest. Sized so a
# 100-validator network signing every FINALITY_INTERVAL = 100 blocks
# can keep ~30 days of vote history (8640 blocks / 100 = 86 heights)
# with headroom for spam.
FORK_EMERGENCY_MAX_TRACKED_HEIGHTS = 1024


@dataclass
class ForkEmergency:
    """Frozen description of a detected fork emergency.

    Created when 2/3+ of stake-at-height has signed a block hash
    that disagrees with this node's chain at the same height (or
    that this node has no block for).

    Fields:
        height:           target_block_number where the disagreement
                          was detected.
        supermajority_hash: the block hash that 2/3+ of stake signed.
        local_hash:       what this node has at `height`, or None if
                          this node has no block at that height yet.
        attested_stake:   sum of signers' stake that signed
                          supermajority_hash. Always >= 2/3 of
                          total_stake_at_height by construction.
        total_stake:      total stake at `height` (denominator).
        detected_at:      wall-clock unix timestamp of detection.
                          Informational; do not gate consensus on it.
    """
    height: int
    supermajority_hash: bytes
    local_hash: bytes | None
    attested_stake: int
    total_stake: int
    detected_at: float = field(default_factory=time.time)

    def short(self) -> str:
        local = self.local_hash.hex()[:16] if self.local_hash else "<missing>"
        return (
            f"ForkEmergency(height={self.height}, "
            f"supermajority={self.supermajority_hash.hex()[:16]}, "
            f"local={local}, "
            f"stake={self.attested_stake}/{self.total_stake})"
        )


class ForkEmergencyDetector:
    """Stateful observer of FinalityVotes that flags supermajority forks.

    Wire it to two ingestion points:
      1. Gossip ingest in the network handler (after sig verify)
      2. Block-apply path when a block carries finality votes

    Both feed the same `observe_vote` API. The detector itself does
    no signature verification — callers MUST verify first.
    """

    def __init__(
        self,
        threshold_num: int = FINALITY_THRESHOLD_NUMERATOR,
        threshold_den: int = FINALITY_THRESHOLD_DENOMINATOR,
        max_tracked_heights: int = FORK_EMERGENCY_MAX_TRACKED_HEIGHTS,
    ):
        self._threshold_num = threshold_num
        self._threshold_den = threshold_den
        self._max_tracked = max_tracked_heights

        # height -> { hash -> { signer_id -> stake } }
        # Inner stake is the signer's stake at THIS vote's observation;
        # we keep the first-observed value to stay deterministic under
        # late-arriving stake-table mutations.
        self._stake_by_height_hash: dict[
            int, dict[bytes, dict[bytes, int]]
        ] = {}
        # Track which (signer, height) we've already counted, so
        # equivocators (same signer, same height, different hash) only
        # get credited for their first observed vote — the second is
        # the slashable double-vote and contributes nothing.
        self._signer_height_seen: dict[tuple[bytes, int], bytes] = {}
        # Insertion order of heights for LRU eviction.
        self._height_order: list[int] = []

        # Currently-active emergencies, keyed by height. Cleared
        # explicitly via `clear_emergency` after recovery.
        self._emergencies: dict[int, ForkEmergency] = {}

    # ── observation ───────────────────────────────────────────────

    def observe_vote(
        self,
        vote: FinalityVote,
        signer_stake: int,
        total_stake_at_target: int,
        local_hash_at_height: bytes | None,
    ) -> ForkEmergency | None:
        """Record a verified finality vote.

        Args:
            vote: signature-verified FinalityVote (caller verified).
            signer_stake: signer's stake at vote.target_block_number.
                <= 0 contributes nothing — a stake-less validator has
                no voting weight, same rule the FinalityCheckpoints
                aggregator enforces.
            total_stake_at_target: total stake at the target height
                (denominator for the 2/3 check).
            local_hash_at_height: the block hash THIS NODE has at
                vote.target_block_number, or None if this node has
                no block there yet.

        Returns the freshly-detected ForkEmergency if THIS call was
        what crossed the threshold AND the supermajority hash
        disagrees with `local_hash_at_height`. Returns None for any
        other outcome (below threshold, agrees with local, already
        flagged, equivocation skipped).
        """
        if signer_stake <= 0:
            return None
        if total_stake_at_target <= 0:
            return None

        height = vote.target_block_number
        sh = vote.target_block_hash
        sid = vote.signer_entity_id

        # Equivocation: a signer voting twice at the same height for
        # different hashes only contributes their first hash. Mirrors
        # FinalityCheckpoints.add_vote — the second vote is the
        # slashable one and gets handled by the normal finality path.
        prev_hash = self._signer_height_seen.get((sid, height))
        if prev_hash is not None and prev_hash != sh:
            return None

        # LRU bookkeeping: insertion-order list, dedup on touch.
        if height not in self._stake_by_height_hash:
            self._height_order.append(height)
            self._stake_by_height_hash[height] = {}
            # Evict oldest heights if we're over the cap. Drop
            # emergencies for evicted heights too — if we no longer
            # have the supporting votes in memory we should not act
            # on a stale flag.
            while len(self._height_order) > self._max_tracked:
                evict_h = self._height_order.pop(0)
                self._stake_by_height_hash.pop(evict_h, None)
                self._emergencies.pop(evict_h, None)
                # Drop signer-height keys for the evicted height.
                stale = [
                    k for k in self._signer_height_seen
                    if k[1] == evict_h
                ]
                for k in stale:
                    self._signer_height_seen.pop(k, None)

        per_hash = self._stake_by_height_hash[height]
        signers = per_hash.setdefault(sh, {})

        # Idempotent: same (signer, height, hash) seen before is a no-op.
        if sid in signers:
            return None

        signers[sid] = signer_stake
        self._signer_height_seen[(sid, height)] = sh

        accumulated = sum(signers.values())
        meets_threshold = (
            accumulated * self._threshold_den
            >= total_stake_at_target * self._threshold_num
        )
        if not meets_threshold:
            return None

        # Threshold met. Two cases:
        #   * supermajority hash matches local → no emergency. This is
        #     the common path: 2/3 of stake confirms what we already
        #     have. We deliberately do NOT clear an existing emergency
        #     here — once a supermajority disagreement is recorded,
        #     only explicit `clear_emergency` removes it. The fact
        #     that a different supermajority then agreed at a
        #     LATER height does not retroactively fix an earlier
        #     conflict.
        #   * supermajority hash differs from local → emergency.
        if local_hash_at_height is not None and local_hash_at_height == sh:
            return None

        # Don't re-flag the same (height, hash) if we already have it.
        existing = self._emergencies.get(height)
        if existing is not None and existing.supermajority_hash == sh:
            return None

        emergency = ForkEmergency(
            height=height,
            supermajority_hash=sh,
            local_hash=local_hash_at_height,
            attested_stake=accumulated,
            total_stake=total_stake_at_target,
        )
        self._emergencies[height] = emergency
        logger.error(
            "FORK EMERGENCY DETECTED: %s — supermajority of stake has "
            "committed to a block this node does not have. Validators "
            "should halt block production; full nodes may auto-rewind "
            "if FORK_EMERGENCY_AUTO_RECOVERY is enabled.",
            emergency.short(),
        )
        return emergency

    # ── inspection ────────────────────────────────────────────────

    def is_in_emergency(self) -> bool:
        return bool(self._emergencies)

    def current_emergencies(self) -> list[ForkEmergency]:
        """All currently-active emergencies, oldest height first."""
        return [self._emergencies[h] for h in sorted(self._emergencies)]

    def lowest_emergency(self) -> ForkEmergency | None:
        """The earliest unresolved fork emergency.

        Recovery should target this height first — once we reorg past
        it, any later emergencies that depended on the same divergent
        ancestry will resolve as a side effect.
        """
        if not self._emergencies:
            return None
        return self._emergencies[min(self._emergencies)]

    def attested_stake(self, height: int, block_hash: bytes) -> int:
        """Sum of signers' stake that voted for (height, block_hash)."""
        per_hash = self._stake_by_height_hash.get(height)
        if not per_hash:
            return 0
        signers = per_hash.get(block_hash)
        if not signers:
            return 0
        return sum(signers.values())

    # ── recovery hooks ────────────────────────────────────────────

    def clear_emergency(self, height: int) -> bool:
        """Mark the emergency at `height` as resolved.

        Caller is responsible for actually reorganizing onto the
        supermajority chain BEFORE clearing. Returns True iff there
        was an emergency at that height to clear.
        """
        return self._emergencies.pop(height, None) is not None

    def clear_all(self) -> int:
        """Clear every active emergency. Returns the count cleared.

        Use after a recovery pass that brings the local chain onto
        the supermajority branch at every flagged height.
        """
        n = len(self._emergencies)
        self._emergencies.clear()
        return n

    def recheck_after_chain_advance(
        self,
        local_hash_lookup,
    ) -> int:
        """Auto-clear emergencies the local chain has caught up to.

        After a reorg or fresh sync the local block at a previously
        flagged height may now match the supermajority hash. This
        helper walks active emergencies and clears those that no
        longer disagree with the local chain.

        ``local_hash_lookup(height) -> bytes | None`` returns the
        local block hash at that height, or None if the height is
        beyond the chain tip.

        Returns the number of emergencies cleared. Safe to call on
        every block accept — cheap, bounded by the cap on tracked
        heights.
        """
        cleared = 0
        for height in list(self._emergencies):
            emergency = self._emergencies[height]
            local_hash = local_hash_lookup(height)
            if local_hash is not None and local_hash == emergency.supermajority_hash:
                self._emergencies.pop(height, None)
                cleared += 1
                logger.info(
                    "Fork emergency at height %d resolved: local chain "
                    "now matches supermajority hash %s",
                    height,
                    emergency.supermajority_hash.hex()[:16],
                )
        return cleared
