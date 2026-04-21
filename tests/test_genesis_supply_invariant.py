"""Genesis-supply invariant: total_supply == sum(balances) at genesis.

The bug being fixed: GENESIS_SUPPLY was set to 1_000_000_000 while the
default mainnet allocation table only distributes 140_000_000
(TREASURY_ALLOCATION + _MAINNET_FOUNDER_TOTAL).  The 860M gap was
phantom — unowned, unspendable, yet counted in the "% of supply"
denominator for every fee-model, governance, and analytics
calculation.

The fix rebases GENESIS_SUPPLY to 140_000_000 so that, at genesis,

    chain.supply.total_supply == sum(chain.supply.balances.values())
                              == sum(chain.supply.staked.values())
                              == _MAINNET_FOUNDER_TOTAL + TREASURY_ALLOCATION

holds by construction.  A one-shot migration in chaindb.py rebases
existing persisted mainnet state by subtracting 860M from the stored
total_supply (detected by the anomaly total_supply==1B at genesis).

These tests encode that invariant so the fix cannot regress.
"""

import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    GENESIS_SUPPLY,
    TREASURY_ALLOCATION,
    _MAINNET_FOUNDER_TOTAL,
)


class TestGenesisSupplyConstant(unittest.TestCase):
    """GENESIS_SUPPLY must equal the sum of every genesis allocation."""

    def test_genesis_supply_matches_mainnet_allocation_total(self):
        """GENESIS_SUPPLY must equal the sum of canonical mainnet
        allocations.  Any phantom gap between GENESIS_SUPPLY and the
        sum of actual allocations inflates every '% of supply'
        calculation and is the bug this suite protects against.
        """
        self.assertEqual(
            GENESIS_SUPPLY,
            _MAINNET_FOUNDER_TOTAL + TREASURY_ALLOCATION,
            "GENESIS_SUPPLY must equal the sum of canonical mainnet "
            "allocations (founder 100M + treasury 40M = 140M); any "
            "gap is phantom unowned supply",
        )

    def test_genesis_supply_is_140m(self):
        """Pin the numeric value so a silent regression is caught."""
        self.assertEqual(GENESIS_SUPPLY, 140_000_000)


class TestFreshSupplyTrackerInvariant(unittest.TestCase):
    """A freshly-constructed SupplyTracker must start with a clean
    invariant: total_supply == GENESIS_SUPPLY AND no phantom tokens."""

    def test_fresh_tracker_total_supply_equals_genesis_supply(self):
        tracker = SupplyTracker()
        self.assertEqual(tracker.total_supply, GENESIS_SUPPLY)

    def test_fresh_tracker_has_no_balances(self):
        """Before any allocation, balances is empty — so
        sum(balances) == 0, and an allocation loop must bring it up
        to GENESIS_SUPPLY without leaving a phantom gap."""
        tracker = SupplyTracker()
        self.assertEqual(sum(tracker.balances.values()), 0)


class TestGenesisAllocationInvariant(unittest.TestCase):
    """After applying the canonical mainnet allocation, the invariant
    total_supply == sum(balances) + sum(staked) must hold."""

    def test_full_mainnet_allocation_sums_to_total_supply(self):
        """Simulate the mainnet genesis allocation directly on a
        SupplyTracker and assert the invariant.  This is the single
        load-bearing check: the sum of EVERY genesis allocation
        (treasury + founder, liquid + staked) must equal total_supply
        exactly.  A nonzero gap is the phantom-supply bug.
        """
        from messagechain.config import (
            TREASURY_ENTITY_ID,
            _MAINNET_FOUNDER_LIQUID,
            _MAINNET_FOUNDER_STAKE,
        )

        tracker = SupplyTracker()
        founder_id = b"\x01" * 32

        # Mirrors _apply_mainnet_genesis_state: founder gets full
        # 100M liquid, then 95M of it moves into stake.
        tracker.balances[founder_id] = _MAINNET_FOUNDER_LIQUID + _MAINNET_FOUNDER_STAKE
        tracker.balances[TREASURY_ENTITY_ID] = TREASURY_ALLOCATION
        ok = tracker.stake(founder_id, _MAINNET_FOUNDER_STAKE)
        self.assertTrue(ok)

        owned_total = (
            sum(tracker.balances.values()) + sum(tracker.staked.values())
        )
        self.assertEqual(
            owned_total, tracker.total_supply,
            "Post-genesis invariant broken: sum(balances)+sum(staked) "
            "!= total_supply. The gap is phantom unowned supply.",
        )

    def test_no_phantom_tokens_at_genesis(self):
        """Direct re-statement of the phantom-supply bug: there must
        be exactly zero tokens that are counted in total_supply but
        owned by nobody."""
        from messagechain.config import (
            TREASURY_ENTITY_ID,
            _MAINNET_FOUNDER_LIQUID,
            _MAINNET_FOUNDER_STAKE,
        )

        tracker = SupplyTracker()
        founder_id = b"\x01" * 32
        tracker.balances[founder_id] = _MAINNET_FOUNDER_LIQUID + _MAINNET_FOUNDER_STAKE
        tracker.balances[TREASURY_ENTITY_ID] = TREASURY_ALLOCATION
        tracker.stake(founder_id, _MAINNET_FOUNDER_STAKE)

        owned_total = (
            sum(tracker.balances.values()) + sum(tracker.staked.values())
        )
        phantom = tracker.total_supply - owned_total
        self.assertEqual(
            phantom, 0,
            f"Phantom supply detected: {phantom} tokens exist in "
            f"total_supply but are owned by no entity",
        )


class TestChainDbPhantomSupplyMigration(unittest.TestCase):
    """Existing mainnet state on disk has total_supply == 1B (the old
    value) persisted via chaindb.py's supply_meta table.  A one-shot
    migration must detect the anomaly and rebase to the corrected
    value on startup."""

    def _fresh_chaindb(self):
        """Return (db, tmpdir) for an isolated sqlite chaindb."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB

        tmpdir = tempfile.mkdtemp(prefix="mc_supply_invariant_")
        db_path = os.path.join(tmpdir, "chain.sqlite")
        db = ChainDB(db_path)
        return db, tmpdir, db_path

    def test_migration_detects_and_rebases_old_1b_value(self):
        """If total_supply == 1_000_000_000 is persisted (legacy
        mainnet state), the migration must rebase it to
        1_000_000_000 - 860_000_000 = 140_000_000 on open."""
        import shutil
        from messagechain.storage.chaindb import ChainDB
        db, tmpdir, db_path = self._fresh_chaindb()
        try:
            # Simulate legacy persisted state: total_supply == 1B.
            db.set_supply_meta("total_supply", 1_000_000_000)
            db.close()

            # Reopen — the migration must detect the anomaly and
            # rebase.  The hook is a method on ChainDB that the
            # fix will add (or an automatic step in __init__).
            db2 = ChainDB(db_path)
            db2.migrate_phantom_supply_if_needed()
            rebased = db2.get_supply_meta("total_supply")
            db2.close()

            self.assertEqual(
                rebased, 140_000_000,
                "Migration must rebase legacy total_supply=1B to 140M "
                "so the invariant total_supply == sum(balances) holds",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_migration_is_idempotent(self):
        """Running the migration twice must be a no-op the second
        time — it detects the already-rebased value and leaves it."""
        import shutil
        from messagechain.storage.chaindb import ChainDB
        db, tmpdir, db_path = self._fresh_chaindb()
        try:
            db.set_supply_meta("total_supply", 1_000_000_000)
            db.migrate_phantom_supply_if_needed()
            first_rebase = db.get_supply_meta("total_supply")
            db.migrate_phantom_supply_if_needed()
            second_rebase = db.get_supply_meta("total_supply")
            db.close()
            self.assertEqual(first_rebase, 140_000_000)
            self.assertEqual(second_rebase, 140_000_000)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_migration_leaves_fresh_chain_alone(self):
        """On a fresh chain (no anomalous 1B value), the migration
        must be a no-op — don't touch a correctly-initialized
        total_supply."""
        import shutil
        from messagechain.storage.chaindb import ChainDB
        db, tmpdir, db_path = self._fresh_chaindb()
        try:
            # Fresh init writes total_supply = GENESIS_SUPPLY (140M
            # after the fix).  Migration must see this and do nothing.
            initial = db.get_supply_meta("total_supply")
            db.migrate_phantom_supply_if_needed()
            after = db.get_supply_meta("total_supply")
            db.close()
            self.assertEqual(initial, after)
            self.assertEqual(after, 140_000_000)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
