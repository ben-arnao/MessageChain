"""Escrow ledger for bootstrap-era attester rewards.

During bootstrap, attester-committee rewards land in escrow instead of
going straight to the validator's spendable balance.  Escrow entries
mature after `escrow_blocks_for_progress(progress)` blocks and are
slashable during that window.  At progress=1.0 the escrow window
collapses to zero and rewards credit balance immediately — normal
post-bootstrap behavior.

The ledger is a pure data structure.  Blockchain.__apply_block_state
drives the unlock cadence (popping matured entries) and records new
entries when rewards are earned.  Slashing (stage 4) will call
`slash_all(entity_id)` to burn the accumulated escrow.

State-root note: this ledger is in-memory; its contents are
deterministic from chain replay, so every honest node reconstructs
the same state.  The balance changes that ARE committed to state_root
(maturity-driven credits, slash-driven burns) flow through
SupplyTracker.balances — which IS in state_root.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EscrowEntry:
    """A single attester reward earned at `earned_at`, unlocks at `unlock_at`.

    Kept as a plain dataclass — no hidden fields, no serialized-state
    surprises.  Lets downstream code persist / replay the ledger cheaply
    if we ever need to (current design reconstructs from chain history).
    """
    entity_id: bytes
    amount: int
    earned_at: int
    unlock_at: int


class EscrowLedger:
    """Per-validator accumulation of attester rewards awaiting maturity.

    Public API:
      * add(entity_id, amount, earned_at, unlock_at) — credit escrow
      * pop_matured(current_block) → list of (entity, amount) now liquid
      * slash_all(entity_id) → total amount burned from this entity's
        escrow (stake is handled separately by SupplyTracker.slash_validator)
      * total_escrowed(entity_id) — current escrow balance for queries
      * total_supply_escrowed() — sum across all entities, for integrity checks

    Implementation: simple list of entries.  Linear in entries for
    pop_matured / slash_all; fine at our scale (a few thousand entries
    at peak, during the first ~90 days of bootstrap).  If this becomes
    a hot path we can switch to a sorted-by-unlock-at index later.
    """

    def __init__(self) -> None:
        self._entries: list[EscrowEntry] = []

    def add(
        self, *,
        entity_id: bytes,
        amount: int,
        earned_at: int,
        unlock_at: int,
    ) -> None:
        if amount <= 0:
            raise ValueError(f"escrow amount must be positive, got {amount}")
        if unlock_at < earned_at:
            raise ValueError(
                f"unlock_at ({unlock_at}) cannot precede earned_at ({earned_at})"
            )
        self._entries.append(EscrowEntry(
            entity_id=entity_id,
            amount=amount,
            earned_at=earned_at,
            unlock_at=unlock_at,
        ))

    def pop_matured(self, current_block: int) -> list[tuple[bytes, int]]:
        """Remove entries whose unlock_at <= current_block; return them.

        Aggregates per-entity so the caller credits each balance once
        per maturity pass (not once per entry).  Matters because an
        active validator can accumulate hundreds of entries in a single
        committee tenure.
        """
        still_held: list[EscrowEntry] = []
        matured_by_eid: dict[bytes, int] = {}
        for entry in self._entries:
            if entry.unlock_at <= current_block:
                matured_by_eid[entry.entity_id] = (
                    matured_by_eid.get(entry.entity_id, 0) + entry.amount
                )
            else:
                still_held.append(entry)
        self._entries = still_held
        return list(matured_by_eid.items())

    def slash_all(self, entity_id: bytes, slash_pct: int = 100) -> int:
        """Burn `slash_pct` of every escrow entry for this entity.
        Returns total burned.

        Pre-Tier 19 (default slash_pct=100): every entry for this entity
        is removed entirely — full escrow wipe matching the legacy
        equivocation policy.

        Tier 19+ (slash_pct=SOFT_SLASH_PCT, typically 5): each entry's
        amount is scaled by (1 - slash_pct/100) in place; entries that
        round to zero are dropped, others retain their original
        `unlock_at` so the escrow maturity schedule the offender
        accumulated is not extended by the slash.
        """
        if not 0 < slash_pct <= 100:
            raise ValueError(
                f"slash_pct must be in (0, 100], got {slash_pct}"
            )
        total_burned = 0
        still_held: list[EscrowEntry] = []
        for entry in self._entries:
            if entry.entity_id != entity_id:
                still_held.append(entry)
                continue
            if slash_pct == 100:
                total_burned += entry.amount
                continue
            burn = entry.amount * slash_pct // 100
            total_burned += burn
            remaining = entry.amount - burn
            if remaining > 0:
                still_held.append(EscrowEntry(
                    entity_id=entry.entity_id,
                    amount=remaining,
                    earned_at=entry.earned_at,
                    unlock_at=entry.unlock_at,
                ))
        self._entries = still_held
        return total_burned

    def total_escrowed(self, entity_id: bytes) -> int:
        return sum(
            e.amount for e in self._entries if e.entity_id == entity_id
        )

    def total_supply_escrowed(self) -> int:
        return sum(e.amount for e in self._entries)

    def entries_for(self, entity_id: bytes) -> list[EscrowEntry]:
        """Read-only snapshot of entries for one entity (diagnostics)."""
        return [e for e in self._entries if e.entity_id == entity_id]
