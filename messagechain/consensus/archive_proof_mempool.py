"""
Mempool for CustodyProofs awaiting inclusion in a challenge block.

Mirrors the shape of the existing finality_pool / slash_pool on
messagechain.core.mempool.Mempool but lives in its own module because
custody proofs have their own eviction rule (submission window) that
doesn't match the tx TTL behavior of the main mempool.

A proof is bound for a specific **challenge block** — the block height
at which the challenge fires.  The node learns that binding at ingress
time: the submitter tells the node which challenge they are responding
to (via `challenge_block_number`), and the node validates that:

    * `challenge_block_number` is actually a challenge height
      (is_archive_challenge_block);
    * the proof's target_block_hash matches the block the chain picked
      for that challenge (via compute_challenge against the challenge
      block's **parent** hash — known at submission time);
    * the submission window for that challenge is still open.

The check-once-at-ingress design keeps validation cost bounded — a flood
of spammy proofs hits only the dedupe + signature-free verify path, not
the full challenge-resolution pipeline in the proposer's hot loop.

Invariants:
  * Dedupe by (challenge_block_number, prover_id) — one slot per prover
    per challenge.
  * FCFS within a challenge: proofs are yielded in arrival order.
  * Evict on expiry: once the submission window for a challenge has
    closed, its proofs are dropped on the next eviction call.
  * Size cap: bounded entries.  Overflow evicts the oldest entry in
    insertion order — matches mempool.slash_pool_max_size pattern.

Unsigned proofs in v1 (see archive_challenge.py module docstring for the
front-run tradeoff); the mempool therefore stores whatever it is handed
after the ingress helper's shape/freshness checks succeed.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable

from messagechain.config import (
    ARCHIVE_PROOFS_PER_CHALLENGE,
    is_archive_challenge_block,
)
from messagechain.consensus.archive_challenge import (
    CustodyProof,
    is_within_submission_window,
)


__all__ = ["ArchiveProofMempool"]


# Size cap.  Proofs are a few hundred bytes each; even at 10k entries
# the pool costs a couple of MB.  Bounded against a flood while leaving
# headroom for chains with many active archive operators.
_DEFAULT_MAX_PROOFS = 10_000


@dataclass
class _PoolEntry:
    """Per-proof bookkeeping: the proof + its target challenge + arrival time.

    `challenge_block_number` is the block height whose challenge this
    proof is answering — carried in the pool entry rather than on the
    CustodyProof itself because the block-embedded proof does not (and
    should not) carry a self-referential field that the proposer could
    lie about.  The challenge binding is re-checked in validate_block
    against the chain's known challenge schedule.

    `arrival_seq` drives FCFS ordering and the overflow-eviction choice.
    Losing it on restart is acceptable: the worst case is the new
    arrival-seq starts from zero after restart, but the expiration
    window still applies — no eligible proof outlasts its window.
    """
    proof: CustodyProof
    challenge_block_number: int
    arrival_seq: int


class ArchiveProofMempool:
    """Pool of custody proofs pending inclusion."""

    def __init__(self, max_proofs: int = _DEFAULT_MAX_PROOFS):
        # OrderedDict preserves insertion order — our FCFS invariant.
        # Key is (challenge_block_number, prover_id); value is _PoolEntry.
        self._entries: "OrderedDict[tuple[int, bytes], _PoolEntry]" = OrderedDict()
        self.max_proofs = max_proofs
        self._seq = 0

    # ---- mutation -------------------------------------------------------

    def add_proof(
        self,
        proof: CustodyProof,
        *,
        challenge_block_number: int,
    ) -> bool:
        """Add a proof bound for `challenge_block_number`.

        Returns True if the proof was newly accepted.  False on
        duplicate (same challenge + prover_id).  Overflow evicts the
        oldest entry in insertion order — the earliest-arrived proof is
        closest to expiring anyway, so it is the least valuable
        replacement candidate.

        Cheap caller-side sanity: rejects non-challenge heights early
        so the pool can never hold an eternally-unreachable entry.
        """
        if not is_archive_challenge_block(challenge_block_number):
            return False
        key = (challenge_block_number, bytes(proof.prover_id))
        if key in self._entries:
            return False
        if len(self._entries) >= self.max_proofs:
            self._entries.popitem(last=False)
        self._seq += 1
        self._entries[key] = _PoolEntry(
            proof=proof,
            challenge_block_number=challenge_block_number,
            arrival_seq=self._seq,
        )
        return True

    def remove_proofs(self, keys: Iterable[tuple[int, bytes]]) -> int:
        """Drop proofs by (challenge_block_number, prover_id).  Returns count."""
        n = 0
        for key in keys:
            if self._entries.pop(key, None) is not None:
                n += 1
        return n

    def evict_expired(self, current_block_number: int) -> int:
        """Drop every proof whose submission window has closed.

        Called periodically (on new-block arrival or a cleanup tick).
        Idempotent for windows still open at this height.  Returns
        the number evicted.
        """
        dead: list[tuple[int, bytes]] = []
        for key, entry in self._entries.items():
            if not is_within_submission_window(
                entry.challenge_block_number, current_block_number,
            ):
                dead.append(key)
        for k in dead:
            self._entries.pop(k, None)
        return len(dead)

    # ---- query ----------------------------------------------------------

    def proofs_for_challenge(
        self, challenge_block_number: int,
    ) -> list[CustodyProof]:
        """Every proof for `challenge_block_number`, in FCFS arrival order.

        Returns a newly-allocated list; mutating it does not affect
        the pool.  The proposer reads from here when it is ready to
        pack a challenge block; the validator uses the same order when
        it cross-checks membership.
        """
        entries = [
            e for e in self._entries.values()
            if e.challenge_block_number == challenge_block_number
        ]
        entries.sort(key=lambda e: e.arrival_seq)
        return [e.proof for e in entries]

    def top_for_challenge(
        self,
        challenge_block_number: int,
        cap: int = ARCHIVE_PROOFS_PER_CHALLENGE,
    ) -> list[CustodyProof]:
        """First `cap` FCFS proofs for a specific challenge.

        Legacy FCFS helper — kept for backward compat with callers
        that haven't switched to `select_for_inclusion`.  Live-chain
        proposers SHOULD use select_for_inclusion with the parent
        block's randao_mix as seed to get the iter-3g fairness
        guarantee.
        """
        return self.proofs_for_challenge(challenge_block_number)[:cap]

    def select_for_inclusion(
        self,
        challenge_block_number: int,
        *,
        cap: int = ARCHIVE_PROOFS_PER_CHALLENGE,
        selection_seed: "bytes | None" = None,
    ) -> list[CustodyProof]:
        """Select up to `cap` proofs for inclusion in a challenge block
        via a DETERMINISTIC UNIFORM SHUFFLE keyed by `selection_seed`.

        Iteration 3g: replaces FCFS-at-proposer-side with a fair
        shuffle so a single proposer cannot systematically prefer
        their own cartel's proofs over outsiders in the mempool.
        Pairs with the 3e payout-side shuffle — the whole pipeline
        is randomness-driven end-to-end.

        Seed should be parent block's `randao_mix` (consensus-
        deterministic, tamper-resistant, available to all nodes).
        When `selection_seed` is None this function degrades to the
        legacy FCFS order — retained for test helpers and startup
        paths that run before any parent-block randao exists.
        """
        proofs = self.proofs_for_challenge(challenge_block_number)
        if not proofs or cap <= 0:
            return []
        if selection_seed is None:
            return proofs[:cap]

        # Deterministic shuffle via seed-keyed sort over prover_id.
        # Same primitive as apply_archive_rewards (iter 3e); every
        # node reproduces the same ordering from the same seed.
        import hashlib as _hashlib
        from messagechain.config import HASH_ALGO as _HASH_ALGO

        def _shuffle_key(p: CustodyProof) -> bytes:
            return _hashlib.new(
                _HASH_ALGO, bytes(selection_seed) + p.prover_id,
            ).digest()

        shuffled = sorted(proofs, key=_shuffle_key)
        return shuffled[:cap]

    def __contains__(self, key: tuple[int, bytes]) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)
