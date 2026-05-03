"""Tests for the SUPPLY_RECONCILIATION_HEIGHT hard fork (1.50.0).

Background -- 2026-05-03 incident: mainnet's prior phantom-supply
migration (chaindb.migrate_phantom_supply_if_needed) assumed
``GENESIS_SUPPLY`` (140M) equalled the actual on-chain allocation
total.  It didn't -- mainnet allocations only ever summed to ~88.5M.
After the 33M treasury rebase burn, ``total_supply`` = 107M while
actual buckets only ever held ~55.5M, leaving a permanent ~47.5M
phantom that 1.49.0's per-block supply-conservation invariant
correctly began flagging.

Repair: at ``SUPPLY_RECONCILIATION_HEIGHT``, every node re-computes
``total_supply`` from the same sum the conservation invariant uses
(non_treasury_balances + treasury + staked + pending_unstakes +
archive_reward_pool + lottery_prize_pool) and persists it.  Post-
rebase, the conservation invariant passes by construction.

These tests pin:

  * The rebase fires exactly once, at exactly the activation height.
  * Pre- and post-activation heights are no-ops.
  * The rebase deterministically equals the conservation sum
    (so the invariant passes on the same block).
  * The rebase is reorg-safe: rolling back the activation block
    un-flips the applied flag so the canonical replay re-fires.
  * The rebase is idempotent across process restarts: a node that
    starts up with total_supply already matching the conservation
    sum sees a no-op.
  * The rebase does NOT change ``state_root``: it only mutates the
    supply-level scalar, not any per-entity SMT leaf.  Sim/apply
    parity is preserved (no "Invalid state_root" rejection on the
    activation block itself).
"""

from __future__ import annotations

import unittest
from unittest import mock

from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _fresh_chain_with_phantom_supply(phantom_amount: int) -> Blockchain:
    """Build a tiny chain whose ``total_supply`` exceeds the
    conservation sum by EXACTLY ``phantom_amount``.  Reproduces the
    prod state: total_supply tracks N more tokens than any bucket
    actually holds.

    initialize_genesis sets total_supply = GENESIS_SUPPLY (140M) but
    only allocates GENESIS_ALLOCATION (10K) to balances by default,
    so the helper has to credit the difference to a synthetic sink
    AND then re-introduce a clean ``phantom_amount`` gap on top -- a
    direct ``total_supply = actual + phantom_amount`` assignment is
    the cleanest way to land exactly the gap the test wants.
    """
    ent = Entity.create(b"recon_test_genesis".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(ent)

    # Reset total_supply to "actual sum + phantom_amount" so the
    # conservation gap is EXACTLY phantom_amount regardless of what
    # initialize_genesis baked in.
    _expected_pre, actual_pre, _bd = chain.check_supply_conservation()
    chain.supply.total_supply = actual_pre + phantom_amount
    return chain


class TestSupplyReconciliationFiresAtActivation(unittest.TestCase):
    """At ``SUPPLY_RECONCILIATION_HEIGHT``, the rebase brings
    ``total_supply`` into agreement with the conservation sum."""

    def test_rebase_at_activation_clears_phantom(self):
        chain = _fresh_chain_with_phantom_supply(47_494_983)
        expected_pre, actual_pre, _bd = chain.check_supply_conservation()
        self.assertEqual(
            expected_pre - actual_pre, 47_494_983,
            "test setup must produce the exact prod-shaped phantom",
        )

        # Patch the activation height to match the next block we will
        # process (the helper has to call _apply_supply_reconciliation
        # at that block).  The actual constant in config is high (5000)
        # for runway; the test exercises the same code path at a
        # smaller height.
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)

        expected_post, actual_post, _bd_post = chain.check_supply_conservation()
        self.assertEqual(
            expected_post, actual_post,
            "post-rebase, conservation must pass by construction",
        )
        self.assertTrue(
            chain.supply.supply_reconciliation_applied,
            "applied flag must flip True so a re-apply at the same "
            "height is a no-op",
        )

    def test_pre_activation_height_is_noop(self):
        chain = _fresh_chain_with_phantom_supply(1_000)
        expected_pre, _actual_pre, _bd = chain.check_supply_conservation()

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 100,
        ):
            chain._apply_supply_reconciliation(50)

        # No rebase, supply tracker unchanged, flag unchanged.
        self.assertEqual(chain.supply.total_supply, expected_pre)
        self.assertFalse(chain.supply.supply_reconciliation_applied)

    def test_post_activation_height_is_noop(self):
        """A height past activation that the chain reaches without
        ever crossing activation (e.g. devnet config edits) must not
        retroactively rebase.  The check is gated on EQUALITY with the
        activation height, not >=."""
        chain = _fresh_chain_with_phantom_supply(1_000)
        expected_pre, _actual_pre, _bd = chain.check_supply_conservation()

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 100,
        ):
            chain._apply_supply_reconciliation(101)
            chain._apply_supply_reconciliation(500)
            chain._apply_supply_reconciliation(10_000)

        self.assertEqual(chain.supply.total_supply, expected_pre)
        self.assertFalse(chain.supply.supply_reconciliation_applied)

    def test_rebase_is_idempotent_at_same_height(self):
        """An adjacent re-apply at the same height (e.g., a reorg that
        rolls back and replays the same block, OR a buggy caller that
        invokes the helper twice) must not double-burn / double-rebase
        the supply.  The flag is the guard."""
        chain = _fresh_chain_with_phantom_supply(123_456)
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)
        post_first = chain.supply.total_supply

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)  # second call, same height
        post_second = chain.supply.total_supply
        self.assertEqual(
            post_first, post_second,
            "second invocation at the same height must be a no-op "
            "guarded by supply_reconciliation_applied",
        )

    def test_no_phantom_no_rebase_but_flag_still_set(self):
        """A chain whose total_supply already matches the conservation
        sum at activation has no phantom to clear -- the rebase is a
        no-op on values, but the flag MUST still flip True so future
        re-applies (e.g. reorg replay) are also no-ops rather than
        re-running the (meaningless) rebase loop."""
        ent = Entity.create(b"recon_clean_chain".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        # Force a clean state by aligning total_supply to the actual sum.
        _expected, actual, _bd = chain.check_supply_conservation()
        chain.supply.total_supply = actual

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)

        self.assertEqual(chain.supply.total_supply, actual)
        self.assertTrue(chain.supply.supply_reconciliation_applied)


class TestSupplyReconciliationReorgSafety(unittest.TestCase):
    """The applied flag is snapshotted with the supply state.  A reorg
    that undoes the activation block must un-flip the flag so the
    canonical replay re-fires the rebase deterministically."""

    def test_flag_round_trips_through_supply_snapshot(self):
        """The snapshot dict captured by ``_snapshot_memory_state`` (or
        the equivalent supply snapshot path used by the reorg machinery)
        must include ``supply_reconciliation_applied``, and the restore
        path must read it back.  Otherwise a reorg leaves the flag
        stuck at True and the replay silently skips the rebase, leaving
        the canonical-chain node with total_supply != conservation sum.
        """
        ent = Entity.create(b"recon_reorg_t1".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)

        # Take a snapshot before the rebase -- captures flag=False.
        snap_before = chain._snapshot_memory_state()

        # Fire the rebase.
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)
        self.assertTrue(chain.supply.supply_reconciliation_applied)

        # Roll back via the snapshot (mirrors the reorg path).
        chain._restore_memory_snapshot(snap_before)
        self.assertFalse(
            chain.supply.supply_reconciliation_applied,
            "reorg-rollback must un-flip the applied flag so the "
            "canonical replay re-fires the rebase deterministically",
        )


class TestSupplyReconciliationDoesNotChangeStateRoot(unittest.TestCase):
    """The rebase mutates ``self.supply.total_supply`` (a supply-level
    scalar persisted in supply_meta), NOT any per-entity SMT leaf.
    State_root is computed from per-entity leaves only.  So the rebase
    must NOT change state_root -- otherwise the activation block's
    sim/apply parity breaks and every node rejects it as "Invalid
    state_root."
    """

    def test_rebase_leaves_state_root_unchanged(self):
        ent = Entity.create(b"recon_state_root_t1".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        chain.supply.total_supply += 999_999  # synthetic phantom

        root_before = chain.compute_current_state_root()

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation(1)

        root_after = chain.compute_current_state_root()
        self.assertEqual(
            root_before, root_after,
            "supply reconciliation must not touch any per-entity SMT "
            "leaf -- if it does, the activation block's sim/apply "
            "diverges and the chain wedges with an Invalid state_root "
            "rejection",
        )


if __name__ == "__main__":
    unittest.main()
