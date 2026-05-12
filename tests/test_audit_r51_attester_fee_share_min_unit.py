"""Audit r51 #3 -- Tier 73: ``attester_share`` rounds to ZERO at
``base_fee=1`` (the steady-state when ``MARKET_FEE_FLOOR=1`` is
binding, which dominates quiet periods on a low-volume chain).

The Tier 4 fee-share redirect was supposed to send
``ATTESTER_FEE_SHARE_BPS/10_000 = 50%`` of every fee burn to the
per-block attester pool.  Integer arithmetic eats the redirect when
``base_fee < 2``:

    >>> base_fee = 1
    >>> attester_share = base_fee * 5000 // 10_000
    >>> attester_share
    0

All 100% of the fee burns; attesters get nothing from the fee
channel.  CLAUDE.md pillar at risk: "Perpetual security via fees,
not issuance" -- validators are supposed to live on fee redirects
in the long run, but in the regime the chain spends most of its
time in (low utilization, floor-binding), the redirect is silently
zero.  Under-payment: 100% of the fee-funded attester share lost
during steady state.

Same shape applies at ``base_fee`` in {2, 3} -- floor-divide still
collapses to 1.  At ``base_fee >= 2`` we accept the existing
rounding (the floor at 1 is what matters for the "is the channel
on or off" question); at ``base_fee == 1`` we want the redirect
to be ``1`` so attesters receive a non-zero share of every fee.

Fix (consensus-visible math change, gated by a new tier):

    if effective_height >= ATTESTER_FEE_MIN_UNIT_HEIGHT and base_fee > 0:
        attester_share = max(1, base_fee * ATTESTER_FEE_SHARE_BPS // 10_000)
    elif effective_height >= ATTESTER_FEE_FUNDING_HEIGHT:
        attester_share = base_fee * ATTESTER_FEE_SHARE_BPS // 10_000  # legacy

Pre-fork is byte-identical to today (every historical replay path
matches).  Post-fork the redirect channel is guaranteed non-zero
whenever a fee burns, even when the floor binds.

The fix is a one-line clamp at a single call site (the
``pay_fee_with_burn`` chokepoint); same shape is applicable to any
future ``bps // 10_000`` split that could round to zero under a
realistic minimum value (the wider abstraction calls out a shared
``_split_bps(amount, bps, denom=10_000, min_unit=1)`` helper, but
this round scopes the rule to the fee-share site where the audit
demonstrated the user-visible economic harm).
"""

from __future__ import annotations

import unittest


class TestTier73HeightConstant(unittest.TestCase):
    def test_attester_fee_min_unit_height_is_above_tier_72(self):
        from messagechain.config import (
            ATTESTER_FEE_MIN_UNIT_HEIGHT,
            POLL_HEIGHT,
            EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT,
        )
        self.assertGreater(
            ATTESTER_FEE_MIN_UNIT_HEIGHT, POLL_HEIGHT,
            "Tier 73 (ATTESTER_FEE_MIN_UNIT_HEIGHT) must strictly "
            "follow Tier 72 (POLL_HEIGHT) to keep activation ordering "
            "monotone.",
        )
        self.assertGreater(
            ATTESTER_FEE_MIN_UNIT_HEIGHT, EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT,
            "Tier 73 must also follow Tier 71 -- the cohort must clear "
            "the highest already-scheduled height on the protocol-level "
            "registry so a fresh operator's cold-start replay sees the "
            "tiers in the cut order.",
        )


class _SupplyHarness:
    """Wrap a SupplyTracker pinned to a specific block_height so the
    height-gate inside ``pay_fee_with_burn`` is unambiguous."""

    def __init__(self, block_height: int):
        from messagechain.economics.inflation import SupplyTracker
        self.supply = SupplyTracker()
        # Funds for one fee payment.
        self.supply.balances[b"\x01" * 32] = 10_000
        self.supply._current_block_height = block_height
        self.proposer = b"\x02" * 32

    def pay(self, fee: int, base_fee: int) -> bool:
        return self.supply.pay_fee_with_burn(
            from_id=b"\x01" * 32,
            to_proposer_id=self.proposer,
            fee=fee,
            base_fee=base_fee,
        )


class TestPreForkPreservedAtBaseFeeOne(unittest.TestCase):
    """Regression: below the Tier 73 activation height, ``base_fee=1``
    continues to produce ``attester_share=0`` byte-for-byte with the
    pre-fork legacy code path so historical replay matches.
    """

    def test_legacy_base_fee_1_yields_attester_share_zero(self):
        from messagechain.config import (
            ATTESTER_FEE_FUNDING_HEIGHT,
            ATTESTER_FEE_MIN_UNIT_HEIGHT,
        )
        # Pick any height in the post-Tier-4 / pre-Tier-73 window.
        h = (ATTESTER_FEE_FUNDING_HEIGHT + ATTESTER_FEE_MIN_UNIT_HEIGHT) // 2
        harness = _SupplyHarness(block_height=h)
        ok = harness.pay(fee=1, base_fee=1)
        self.assertTrue(ok)
        self.assertEqual(
            harness.supply.attester_fee_pool_this_block, 0,
            "Pre-Tier-73: base_fee=1 must continue to floor-divide "
            "to attester_share=0 (legacy behaviour).  Changing this "
            "below the activation height would break historical "
            "replay.",
        )


class TestPostForkBaseFeeOneRedirectsOneUnit(unittest.TestCase):
    """At/after Tier 73 activation, ``base_fee=1`` must produce
    ``attester_share=1`` so the fee channel that funds long-horizon
    validator security is never silently dead at the floor.
    """

    def test_post_fork_base_fee_1_attester_share_is_1(self):
        from messagechain.config import ATTESTER_FEE_MIN_UNIT_HEIGHT
        harness = _SupplyHarness(block_height=ATTESTER_FEE_MIN_UNIT_HEIGHT)
        starting_supply = harness.supply.total_supply

        ok = harness.pay(fee=1, base_fee=1)

        self.assertTrue(ok)
        self.assertEqual(
            harness.supply.attester_fee_pool_this_block, 1,
            "Post-Tier-73: base_fee=1 MUST produce attester_share=1 "
            "(not 0).  The whole point of the fee redirect is to "
            "fund attesters; floor-divide can't be allowed to round "
            "the redirect off at the steady-state base_fee.",
        )
        # The 1 token that goes to attesters does NOT burn — supply
        # must drop by exactly base_fee - attester_share = 0 in this
        # specific case.  (Yes, base_fee=1 with attester_share=1 means
        # nothing burns this round; the share stays in circulation
        # for the per-block attester pool, which mint_block_reward
        # credits to committee members.)
        self.assertEqual(
            harness.supply.total_supply - starting_supply, 0,
            "actual_burn = base_fee - attester_share must remain "
            "non-negative; at base_fee=1 / attester_share=1 the burn "
            "is 0 and supply is unchanged.",
        )

    def test_post_fork_base_fee_2_unchanged(self):
        """Above ``base_fee=1`` the floor-divide already gives a
        non-zero answer, so the ``max(1, ...)`` clamp is a no-op.
        Pin this to lock the abstraction: the clamp only kicks in
        where the redirect would otherwise round to 0."""
        from messagechain.config import ATTESTER_FEE_MIN_UNIT_HEIGHT
        harness = _SupplyHarness(block_height=ATTESTER_FEE_MIN_UNIT_HEIGHT)
        ok = harness.pay(fee=2, base_fee=2)
        self.assertTrue(ok)
        # 2 * 5000 // 10_000 = 1
        self.assertEqual(
            harness.supply.attester_fee_pool_this_block, 1,
            "Post-Tier-73: base_fee=2 yields the same attester_share "
            "as the legacy formula (the clamp is a no-op above "
            "base_fee=1).",
        )

    def test_post_fork_base_fee_1000_unchanged(self):
        """The clamp only matters at the floor; at typical base_fees
        the redirect is unchanged."""
        from messagechain.config import ATTESTER_FEE_MIN_UNIT_HEIGHT
        harness = _SupplyHarness(block_height=ATTESTER_FEE_MIN_UNIT_HEIGHT)
        ok = harness.pay(fee=1_000, base_fee=1_000)
        self.assertTrue(ok)
        self.assertEqual(
            harness.supply.attester_fee_pool_this_block, 500,
            "Post-Tier-73: base_fee=1000 yields attester_share=500 "
            "(50%), unchanged from legacy.",
        )

    def test_post_fork_base_fee_zero_attester_share_zero(self):
        """When ``base_fee == 0`` (an off-chain audit / unusual test
        path), the redirect stays at zero — the ``max(1, ...)`` clamp
        is gated on ``base_fee > 0`` so we don't manufacture
        attester-pool credit from thin air."""
        from messagechain.config import ATTESTER_FEE_MIN_UNIT_HEIGHT
        harness = _SupplyHarness(block_height=ATTESTER_FEE_MIN_UNIT_HEIGHT)
        ok = harness.pay(fee=0, base_fee=0)
        self.assertTrue(ok)
        self.assertEqual(
            harness.supply.attester_fee_pool_this_block, 0,
            "Post-Tier-73: base_fee=0 must keep attester_share=0 "
            "(no fee, no redirect).",
        )


class TestActualBurnNonNegative(unittest.TestCase):
    """Sanity: ``actual_burn = base_fee - attester_share`` must remain
    non-negative at every (base_fee, post-fork) combination.  The
    ``max(1, ...)`` clamp must not exceed ``base_fee``.
    """

    def test_actual_burn_non_negative_across_floor_band(self):
        from messagechain.config import ATTESTER_FEE_MIN_UNIT_HEIGHT
        for base_fee in (1, 2, 3, 4, 5, 10, 100, 10_000):
            harness = _SupplyHarness(block_height=ATTESTER_FEE_MIN_UNIT_HEIGHT)
            starting_supply = harness.supply.total_supply
            harness.pay(fee=base_fee, base_fee=base_fee)
            supply_delta = harness.supply.total_supply - starting_supply
            self.assertLessEqual(
                supply_delta, 0,
                f"actual_burn must be >= 0 at base_fee={base_fee} "
                f"post-Tier-73 (got supply delta {supply_delta}).",
            )
            self.assertLessEqual(
                harness.supply.attester_fee_pool_this_block, base_fee,
                f"attester_share must never exceed base_fee — "
                f"got pool={harness.supply.attester_fee_pool_this_block} "
                f"with base_fee={base_fee}.",
            )


if __name__ == "__main__":
    unittest.main()
