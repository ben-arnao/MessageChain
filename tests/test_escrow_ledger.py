"""Escrow ledger: slashable attester rewards, unlock on maturity.

During bootstrap, attester-committee rewards are held in escrow for
`escrow_blocks_for_progress(progress)` blocks before unlocking to
spendable balance.  The escrow window is the slashing window: if the
validator is found to have misbehaved during that time, their
accumulated escrow is forfeit.

This module is pure data — no chain hooks, no state-root coupling.
The blockchain wraps it to drive the unlock-on-apply cadence.
"""

import unittest

from messagechain.economics.escrow import EscrowLedger, EscrowEntry


def _eid(n: int) -> bytes:
    return bytes([n]) + b"\x00" * 31


class TestEscrowLedgerAdd(unittest.TestCase):
    """Adding entries to the ledger."""

    def test_empty_ledger_total_is_zero(self):
        ledger = EscrowLedger()
        self.assertEqual(ledger.total_escrowed(_eid(1)), 0)
        self.assertEqual(ledger.total_supply_escrowed(), 0)

    def test_add_single_entry(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=110)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 5)

    def test_add_multiple_entries_same_entity(self):
        """A validator earns over many blocks; all entries accumulate."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=1, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(1), amount=1, earned_at=101, unlock_at=201)
        ledger.add(entity_id=_eid(1), amount=1, earned_at=102, unlock_at=202)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 3)

    def test_different_entities_are_independent(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(2), amount=7, earned_at=100, unlock_at=200)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 5)
        self.assertEqual(ledger.total_escrowed(_eid(2)), 7)
        self.assertEqual(ledger.total_supply_escrowed(), 12)

    def test_rejects_nonpositive_amount(self):
        """Zero or negative amounts are a caller bug; fail loudly."""
        ledger = EscrowLedger()
        with self.assertRaises(ValueError):
            ledger.add(entity_id=_eid(1), amount=0, earned_at=100, unlock_at=110)
        with self.assertRaises(ValueError):
            ledger.add(entity_id=_eid(1), amount=-5, earned_at=100, unlock_at=110)

    def test_rejects_unlock_before_earn(self):
        """Unlock cannot precede the earning block."""
        ledger = EscrowLedger()
        with self.assertRaises(ValueError):
            ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=50)


class TestEscrowMaturity(unittest.TestCase):
    """Matured entries are returned for the caller to credit to balance."""

    def test_no_matured_entries_before_unlock(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        matured = ledger.pop_matured(current_block=150)
        self.assertEqual(matured, [])
        # Still escrowed after the query.
        self.assertEqual(ledger.total_escrowed(_eid(1)), 5)

    def test_matured_at_unlock_block_inclusive(self):
        """An entry with unlock_at=200 matures at block 200."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        matured = ledger.pop_matured(current_block=200)
        self.assertEqual(matured, [(_eid(1), 5)])
        # Gone from ledger after popping.
        self.assertEqual(ledger.total_escrowed(_eid(1)), 0)

    def test_partial_maturity_across_entries(self):
        """Entries mature independently by their own unlock_at."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=1, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(1), amount=1, earned_at=101, unlock_at=250)
        ledger.add(entity_id=_eid(1), amount=1, earned_at=102, unlock_at=300)
        matured = ledger.pop_matured(current_block=250)
        # First two should mature, third (unlock_at=300) stays.
        self.assertEqual(sum(a for _, a in matured), 2)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 1)

    def test_matured_aggregates_per_entity(self):
        """Multiple matured entries for the same entity are summed in the output."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=3, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(1), amount=4, earned_at=110, unlock_at=200)
        matured = ledger.pop_matured(current_block=200)
        # One (entity, total_amount) entry, not two.
        self.assertEqual(len(matured), 1)
        self.assertEqual(matured[0], (_eid(1), 7))

    def test_idempotent_after_pop(self):
        """Calling pop_matured twice returns nothing new."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        ledger.pop_matured(current_block=250)
        matured = ledger.pop_matured(current_block=250)
        self.assertEqual(matured, [])


class TestEscrowSlashing(unittest.TestCase):
    """Slashing burns escrow entries.

    The slash operation returns the actual amount slashed so callers
    can log it, reduce total supply, etc.  If an entity has less
    escrowed than the slash amount, only what exists is slashed
    (caller must still slash their staked balance separately — stake
    lives in SupplyTracker, not here).
    """

    def test_slash_full_escrow(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        slashed = ledger.slash_all(_eid(1))
        self.assertEqual(slashed, 5)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 0)

    def test_slash_removes_all_entries(self):
        """slash_all burns every entry for the entity, any age."""
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=1, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(1), amount=2, earned_at=150, unlock_at=250)
        ledger.add(entity_id=_eid(1), amount=3, earned_at=175, unlock_at=275)
        slashed = ledger.slash_all(_eid(1))
        self.assertEqual(slashed, 6)
        self.assertEqual(ledger.total_escrowed(_eid(1)), 0)

    def test_slash_nonexistent_entity_is_zero(self):
        """Slashing a validator who has no escrow is a no-op returning 0."""
        ledger = EscrowLedger()
        self.assertEqual(ledger.slash_all(_eid(99)), 0)

    def test_slash_does_not_affect_others(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        ledger.add(entity_id=_eid(2), amount=7, earned_at=100, unlock_at=200)
        ledger.slash_all(_eid(1))
        self.assertEqual(ledger.total_escrowed(_eid(2)), 7)


class TestEscrowAfterMaturityInteraction(unittest.TestCase):
    """Matured entries are no longer slashable (they've left escrow)."""

    def test_slash_after_maturity_is_noop(self):
        ledger = EscrowLedger()
        ledger.add(entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200)
        ledger.pop_matured(current_block=250)  # matured, moved out
        slashed = ledger.slash_all(_eid(1))
        self.assertEqual(slashed, 0)


class TestEscrowEntrySerialization(unittest.TestCase):
    """EscrowEntry is a plain data class — no hidden fields, no
    surprise behavior.  Ensures we can checkpoint / restore escrow
    state from chain replay in later stages.
    """

    def test_entry_is_simple_data(self):
        entry = EscrowEntry(
            entity_id=_eid(1), amount=5, earned_at=100, unlock_at=200,
        )
        self.assertEqual(entry.entity_id, _eid(1))
        self.assertEqual(entry.amount, 5)
        self.assertEqual(entry.earned_at, 100)
        self.assertEqual(entry.unlock_at, 200)


if __name__ == "__main__":
    unittest.main()
