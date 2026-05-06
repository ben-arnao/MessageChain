"""Recovery from the 1.50.0 supply-reconciliation bug that wedged
mainnet at block 1709 on 2026-05-06.

Root cause -- ``Blockchain._apply_supply_reconciliation`` at
``SUPPLY_RECONCILIATION_HEIGHT`` rebased ``total_supply`` to match the
bucket-sum invariant (sum of balances + staked + pending_unstakes +
treasury + scalar pools) but did NOT bump ``total_burned`` by the same
delta.  This left the SCALAR invariant -- ``total_supply ==
GENESIS_SUPPLY + total_minted - total_burned`` -- broken by exactly the
rebase delta.

The scalar invariant fires at the end of every
``_apply_block_state``.  At the activation block itself
(``SUPPLY_RECONCILIATION_HEIGHT``) the check runs BEFORE the
reconciliation (the rebase is called from ``_append_block`` after
``_apply_block_state`` returns), so it passes.  The very NEXT block
trips the check with a ``ChainIntegrityError`` and the chain wedges.

On mainnet:

  * ``SUPPLY_RECONCILIATION_HEIGHT = 1708``
  * ``_apply_supply_reconciliation`` rebased ``total_supply``
    ``107,007,690 -> 59,512,707`` (delta ``-47,494,983``)
  * Block 1708 applied cleanly (the scalar check fires before the
    rebase).
  * Block 1709 apply tripped ``Supply invariant broken at height
    1709: total_supply=59,512,721 vs genesis=140,000,000 +
    minted=47,177 - burned=33,039,473`` -- a ``-47,494,983`` gap in
    the scalar invariant.
  * Both validators wedged at height 1709 indefinitely.

Fix -- a one-shot at ``SUPPLY_RECONCILIATION_FIX_HEIGHT`` that bumps
``total_burned`` by the gap (or ``total_minted`` if the gap is
negative -- defensive, not expected on the realized mainnet trajectory)
to restore the scalar invariant.  Runs at the START of
``_apply_block_state`` (alongside other one-shot activation hooks) so
the rest of the apply path -- including the end-of-apply scalar check
-- sees the corrected state.

These tests pin:

  * The fix fires exactly once, at exactly the activation height.
  * Pre- and post-activation heights are no-ops.
  * After the fix, the SCALAR invariant ``total_supply == GENESIS +
    total_minted - total_burned`` holds.
  * After the fix, the BUCKET conservation invariant
    (``check_supply_conservation``) still holds (the fix only mutates
    the scalar; bucket sums are unchanged).
  * If the scalar invariant is already balanced at the fix height,
    the fix is a no-op (the realized mainnet incident shape AND the
    devnet shape that never crossed the reconciliation height should
    both be safe).
  * The fix is idempotent: a re-apply at the same height is a no-op.
  * The flag is reorg-safe: an in-memory snapshot round-trip
    preserves it.
"""

from __future__ import annotations

import unittest
from unittest import mock

from messagechain.config import (
    GENESIS_SUPPLY,
    SUPPLY_RECONCILIATION_FIX_HEIGHT,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


_MAINNET_SCALAR_GAP = 47_494_983


def _chain_with_broken_scalar(gap: int) -> Blockchain:
    """Build a tiny chain whose scalar invariant ``total_supply ==
    GENESIS + minted - burned`` is broken by exactly ``gap`` tokens.

    Reproduces the prod state: ``total_supply`` was rebased DOWN by
    the SUPPLY_RECONCILIATION_HEIGHT logic but ``total_burned`` was
    NOT bumped to match.  Direct scalar mutation is the cleanest path
    -- the bucket-sum invariant is allowed to be broken too in this
    helper because the fix itself doesn't touch bucket sums.
    """
    ent = Entity.create(b"recon_fix_genesis".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(ent)
    # Mirror the prod incident: SUPPLY_RECONCILIATION rebased
    # total_supply DOWN without bumping total_burned.  Subtract from
    # total_supply directly so the scalar invariant breaks by exactly
    # the requested gap.
    chain.supply.total_supply -= gap
    return chain


class TestSupplyReconciliationFixFiresAtActivation(unittest.TestCase):
    """At ``SUPPLY_RECONCILIATION_FIX_HEIGHT`` the fix bumps
    ``total_burned`` to restore the scalar invariant."""

    def test_fix_at_activation_restores_scalar_invariant(self):
        chain = _chain_with_broken_scalar(_MAINNET_SCALAR_GAP)

        # Pre-fix scalar invariant is broken by exactly the gap.
        pre_total_supply = chain.supply.total_supply
        pre_total_minted = chain.supply.total_minted
        pre_total_burned = chain.supply.total_burned
        pre_expected = (
            GENESIS_SUPPLY + pre_total_minted - pre_total_burned
        )
        self.assertEqual(
            pre_expected - pre_total_supply, _MAINNET_SCALAR_GAP,
            "test setup must produce the exact prod-shaped scalar gap",
        )

        # Patch the activation height to a small one so the fixture
        # chain (which has only the genesis block applied so far) can
        # reach it.
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation_fix(1)

        # Post-fix scalar invariant must hold.
        post_expected = (
            GENESIS_SUPPLY
            + chain.supply.total_minted
            - chain.supply.total_burned
        )
        self.assertEqual(
            chain.supply.total_supply, post_expected,
            f"After SUPPLY_RECONCILIATION_FIX, the scalar invariant "
            f"total_supply == GENESIS + total_minted - total_burned "
            f"must hold.  Got total_supply="
            f"{chain.supply.total_supply} vs "
            f"GENESIS+minted-burned={post_expected}.",
        )
        # The gap was filled by bumping total_burned (positive gap).
        self.assertEqual(
            chain.supply.total_burned,
            pre_total_burned + _MAINNET_SCALAR_GAP,
            "positive gap must be closed by bumping total_burned (the "
            "tokens left circulation via the rebase, the bookkeeping "
            "should reflect that as a burn)",
        )
        # total_supply / total_minted must be untouched.
        self.assertEqual(chain.supply.total_supply, pre_total_supply)
        self.assertEqual(chain.supply.total_minted, pre_total_minted)
        # Flag set so a re-apply is a no-op.
        self.assertTrue(chain.supply.supply_reconciliation_fix_applied)

    def test_pre_activation_height_is_noop(self):
        chain = _chain_with_broken_scalar(1_000)
        pre_burned = chain.supply.total_burned

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 100,
        ):
            chain._apply_supply_reconciliation_fix(50)

        # No fix, supply unchanged, flag unchanged.
        self.assertEqual(chain.supply.total_burned, pre_burned)
        self.assertFalse(chain.supply.supply_reconciliation_fix_applied)

    def test_post_activation_height_is_noop(self):
        """Strict equality on the activation height -- a chain that
        somehow skipped the activation block does NOT get a
        retroactive fix at any later height."""
        chain = _chain_with_broken_scalar(1_000)
        pre_burned = chain.supply.total_burned

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 100,
        ):
            chain._apply_supply_reconciliation_fix(101)
            chain._apply_supply_reconciliation_fix(500)
            chain._apply_supply_reconciliation_fix(10_000)

        self.assertEqual(chain.supply.total_burned, pre_burned)
        self.assertFalse(chain.supply.supply_reconciliation_fix_applied)


class TestSupplyReconciliationFixIdempotent(unittest.TestCase):
    """The fix is once-and-only-once.  A re-apply at the same height
    (e.g. an adjacent reorg replay) does not double-bump."""

    def test_double_apply_at_same_height_is_noop(self):
        chain = _chain_with_broken_scalar(_MAINNET_SCALAR_GAP)
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation_fix(1)
            burned_after_first = chain.supply.total_burned
            chain._apply_supply_reconciliation_fix(1)
        self.assertEqual(
            chain.supply.total_burned, burned_after_first,
            "second apply at the same height must be a no-op",
        )

    def test_already_balanced_chain_is_noop(self):
        """If the scalar invariant is already balanced at the fix
        height (e.g. devnet that never crossed the reconciliation
        height), the fix is a clean no-op -- not a spurious bump."""
        ent = Entity.create(b"recon_fix_balanced".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        # Sanity check: the post-genesis state has the scalar
        # invariant satisfied.
        self.assertEqual(
            chain.supply.total_supply,
            (
                GENESIS_SUPPLY
                + chain.supply.total_minted
                - chain.supply.total_burned
            ),
            "post-genesis scalar invariant must hold",
        )
        pre_burned = chain.supply.total_burned
        pre_minted = chain.supply.total_minted

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation_fix(1)

        # No bump applied, but flag still flips so a future re-apply
        # at the same height is also a no-op.
        self.assertEqual(chain.supply.total_burned, pre_burned)
        self.assertEqual(chain.supply.total_minted, pre_minted)
        self.assertTrue(chain.supply.supply_reconciliation_fix_applied)


class TestSupplyReconciliationFixDoesNotBreakBucketInvariant(unittest.TestCase):
    """The fix only mutates the scalar; bucket sums are
    untouched.  ``check_supply_conservation`` must pass post-fix iff
    it passed pre-fix."""

    def test_bucket_invariant_unchanged_by_fix(self):
        chain = _chain_with_broken_scalar(_MAINNET_SCALAR_GAP)

        # The fixture sets total_supply DOWN without touching buckets,
        # which means the bucket invariant is also broken pre-fix
        # (buckets sum to GENESIS, scalar is GENESIS - gap).
        # That's the actual prod shape -- both invariants were broken.
        # The point of THIS test is that the fix changes the scalar's
        # delta vs buckets by ZERO: it bumps total_burned, which is
        # NOT in the bucket sum.
        pre_expected, pre_actual, _bd_pre = (
            chain.check_supply_conservation()
        )
        pre_delta = pre_actual - pre_expected

        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation_fix(1)

        post_expected, post_actual, _bd_post = (
            chain.check_supply_conservation()
        )
        post_delta = post_actual - post_expected

        self.assertEqual(
            pre_delta, post_delta,
            f"the fix must not change the bucket-vs-scalar delta "
            f"(pre={pre_delta}, post={post_delta}); only "
            f"total_burned moves",
        )


class TestSupplyReconciliationFixFlagSnapshotRoundTrip(unittest.TestCase):
    """Reorg safety: an in-memory snapshot of supply state must
    round-trip the new fix-applied flag so a rolled-back fix block
    correctly un-flips it."""

    def test_flag_round_trips_through_supply_snapshot(self):
        chain = _chain_with_broken_scalar(_MAINNET_SCALAR_GAP)
        with mock.patch(
            "messagechain.config.SUPPLY_RECONCILIATION_FIX_HEIGHT", 1,
        ):
            chain._apply_supply_reconciliation_fix(1)

        self.assertTrue(chain.supply.supply_reconciliation_fix_applied)

        # Snapshot, mutate, restore -- the flag must come back True.
        snap = chain._snapshot_memory_state()
        chain.supply.supply_reconciliation_fix_applied = False
        chain._restore_memory_snapshot(snap)
        self.assertTrue(
            chain.supply.supply_reconciliation_fix_applied,
            "snapshot/restore must round-trip the fix-applied flag",
        )


class TestSupplyReconciliationFixActivationHeightIsValid(unittest.TestCase):
    """The activation height shipped in config must satisfy the
    invariants every other tier height does."""

    def test_activation_height_is_positive(self):
        self.assertGreater(SUPPLY_RECONCILIATION_FIX_HEIGHT, 0)

    def test_activation_height_at_or_after_supply_reconciliation(self):
        """The fix only makes sense at or after the original
        reconciliation height -- the broken-scalar state is a
        consequence of the original reconciliation having fired."""
        from messagechain.config import SUPPLY_RECONCILIATION_HEIGHT
        self.assertGreaterEqual(
            SUPPLY_RECONCILIATION_FIX_HEIGHT,
            SUPPLY_RECONCILIATION_HEIGHT,
        )


if __name__ == "__main__":
    unittest.main()
