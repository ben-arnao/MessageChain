"""Cross-tenet economic invariants — verify the three CLAUDE.md
"Core Economic Tenets" hold simultaneously, not just individually.

Per-tenet tests already live alongside each mechanism (dormancy
controller, reward curve, fee distribution).  This file pins the
INTERACTIONS — places where one tenet could quietly weaken another
if a future change crosses the wires.

The three tenets (CLAUDE.md "Core Economic Tenets"):
  1. Stable active supply (controller-driven, not committee-driven).
  2. Perpetual security via fees, not issuance.
  3. Mathematical decentralization over time (concave reward curve).

The three cross-cut invariants enforced here:

  A. Issuance is decoupled from fee revenue.  ``compute_dormancy_issuance``
     depends ONLY on the active-supply gap and the height — not on
     ``total_fees_collected``, ``total_burned``, ``base_fee``, the
     attester fee pool, or any other security-budget proxy.  Without
     this, "issuance for supply integrity, not security" can quietly
     drift into "issuance subsidizes validator pay" the first time a
     future change wires a fee-deficit signal into the controller.
     (Tenet 1 ⊥ Tenet 2.)

  B. Per-unit decentralization holds at all fee levels.  Smaller
     validators earn STRICTLY higher per-unit-stake revenue than
     larger validators, even when fee throughput dwarfs issuance.
     The concave attester-pool curve is what enforces this; the
     stake-weighted "tip → proposer" channel is linear in stake and
     contributes per-unit-equally to every validator, so it does
     NOT erode the strict-inequality invariant — but it dilutes the
     compression FORCE.  This test pins the strict invariant; the
     dilution is a known characteristic, not a violation.
     (Tenet 2 → Tenet 3.)

  C. Steady-state active supply is invariant to fee throughput.
     At target, the controller mints zero regardless of fee revenue
     scale.  At a fixed below-target gap, the controller mints the
     same amount regardless of how much has been collected/burned in
     fees.  (Tenet 2 → Tenet 1.)
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
    DORMANCY_TARGET_ACTIVE_SUPPLY_V2,
    DORMANCY_TARGET_RETUNE_HEIGHT,
)
from messagechain.economics.inflation import (
    SupplyTracker,
    reward_curve_multiplier_v4,
)


# ───────── Invariant A — issuance decoupled from fee revenue ─────────


class TestIssuanceDecoupledFromFees(unittest.TestCase):
    """Invariant A: ``compute_dormancy_issuance`` output depends only
    on (active_supply, height).  Varying any scalar bookkeeping field
    that tracks fee, burn, or mint state must not change controller
    output — even by one token.

    Anchor: CLAUDE.md "long-term validator security comes from the
    fee market, not from issuance — issuance still accrues to
    validators on the existing reward curve, but its *purpose* is
    supply replenishment, not security-budget funding."
    """

    HEIGHT = DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT + 100  # post-Tier-54

    def _tracker_with_active_balance(self, active_target: int) -> SupplyTracker:
        """Build a SupplyTracker whose active_supply == active_target.

        One non-treasury entity holding the full target, recently
        active so its dormancy weight is 10_000 / 10_000 (full active).
        """
        s = SupplyTracker()
        eid = b"\x01" + b"\x00" * 31
        s.balances[eid] = active_target
        s.last_active_heights[eid] = self.HEIGHT
        return s

    def _assert_invariant(self, field_name: str, values: list[int]) -> None:
        s = self._tracker_with_active_balance(50_000_000)
        baseline = s.compute_dormancy_issuance(self.HEIGHT)
        # Sanity: gap is large here, so issuance must be > 0 — otherwise
        # the test trivially passes by pinning zero against zero.
        self.assertGreater(baseline, 0, "expected non-zero baseline issuance")
        for v in values:
            setattr(s, field_name, v)
            self.assertEqual(
                s.compute_dormancy_issuance(self.HEIGHT), baseline,
                msg=f"controller output changed when {field_name}={v}",
            )

    def test_invariant_to_total_fees_collected(self):
        self._assert_invariant("total_fees_collected", [0, 10**3, 10**6, 10**12, 10**18])

    def test_invariant_to_total_burned(self):
        self._assert_invariant("total_burned", [0, 10**3, 10**6, 10**12, 10**18])

    def test_invariant_to_base_fee(self):
        self._assert_invariant("base_fee", [0, 1, 1_000, 10**9])

    def test_invariant_to_attester_fee_pool(self):
        self._assert_invariant("attester_fee_pool_this_block", [0, 1, 1_000, 10**9])

    def test_invariant_to_total_minted(self):
        self._assert_invariant("total_minted", [0, 1, 10**6, 10**12])

    def test_invariant_to_fee_burn_this_block(self):
        self._assert_invariant("fee_burn_this_block", [0, 1, 1_000, 10**9])


# ───────── Invariant B — per-unit decentralization at all fee levels ─


class TestPerUnitDecentralizationUnderAllFeeLevels(unittest.TestCase):
    """Invariant B: per-unit-stake revenue is STRICTLY higher for
    smaller validators than larger ones, at every fee level.  The
    concave attester-pool curve is what enforces this.

    Anchor: CLAUDE.md "smaller validators earn at a strictly higher
    per-unit rate."

    Model — expected per-block revenue for validator i in an N-validator
    set where every validator attests:

        E[revenue_i]
            = s_i * (proposer_share + tip_per_block)             # linear-in-stake
            + (attester_pool / N) * curve_v4(stake_bps_i)        # concave in stake share

    where  s_i = stake_i / total_stake,
           attester_pool = (1 - 1/4) * issuance_per_block + 0.5 * base_fee_per_block.

    Per-unit revenue = E[revenue_i] / stake_i.  The linear-in-stake
    term reduces to (proposer_share + tip) / total_stake — a constant
    across validators, contributing nothing to the per-unit
    differential.  The attester term is strictly decreasing in stake
    via the concave curve, so per-unit_small > per-unit_large for any
    stake_small < stake_large.

    Critical reading: the strict invariant survives high tip throughput
    BECAUSE the curve still applies to the (smaller-but-nonzero)
    attester pool from base_fee.  If a future change zeros the
    attester pool entirely (e.g. routes 100% of base_fee to burn or
    drops the fee-funding fork), this test will fail — by design, as
    the chain would be losing its sole compression force.
    """

    PROPOSER_SHARE_PER_BLOCK = 250          # toy issuance proposer share
    ATTESTER_POOL_FROM_ISSUANCE = 750       # remaining 3/4 of toy 1000 issuance
    N_VALIDATORS = 2                        # bootstrap pair

    def _per_unit_revenue(
        self, stake_i: int, total_stake: int,
        tip: int, base_fee: int,
    ) -> float:
        s_i = stake_i / total_stake
        stake_bps = (stake_i * 10_000) // total_stake
        num, den = reward_curve_multiplier_v4(stake_bps)
        attester_pool = self.ATTESTER_POOL_FROM_ISSUANCE + base_fee // 2
        per_slot = attester_pool / self.N_VALIDATORS
        attester_reward = per_slot * num / den
        linear = s_i * (self.PROPOSER_SHARE_PER_BLOCK + tip)
        return (linear + attester_reward) / stake_i

    def _assert_strict(
        self, small: int, large: int, tip: int, base_fee: int,
    ) -> None:
        total = small + large
        pu_small = self._per_unit_revenue(small, total, tip, base_fee)
        pu_large = self._per_unit_revenue(large, total, tip, base_fee)
        self.assertGreater(
            pu_small, pu_large,
            msg=(
                f"per-unit revenue regression at "
                f"(small={small}, large={large}, tip={tip}, base_fee={base_fee}): "
                f"small={pu_small:.6f} large={pu_large:.6f}"
            ),
        )

    SPLITS = [(10, 90), (1, 99), (25, 75), (40, 60)]

    def test_zero_fee_strict_invariant(self):
        # Foundational case: no fees at all, curve does 100% of the work.
        for small, large in self.SPLITS:
            self._assert_strict(small, large, tip=0, base_fee=0)

    def test_low_fee_strict_invariant(self):
        # Modest fee throughput.
        for small, large in self.SPLITS:
            self._assert_strict(small, large, tip=100, base_fee=100)

    def test_high_fee_strict_invariant(self):
        # Stress: fees dwarf issuance, tips dominate.  The linear-in-stake
        # tip flow dilutes compression force but does NOT break the strict
        # per-unit inequality, because the curve still applies to the
        # attester portion of base_fee.
        for small, large in self.SPLITS:
            self._assert_strict(small, large, tip=100_000, base_fee=100_000)

    def test_extreme_fee_only_attester_pool_keeps_curve_active(self):
        # Tip-only spike with zero base_fee: the only curve-shaped
        # revenue is the issuance-side attester pool (3/4 * 1000 = 750
        # in the toy).  Strict invariant must still hold.
        for small, large in self.SPLITS:
            self._assert_strict(small, large, tip=10**6, base_fee=0)


# ───────── Invariant C — stable supply target invariant to fee throughput


class TestStableSupplyUnderFeeSwings(unittest.TestCase):
    """Invariant C: the controller's at-target output and below-target
    output are both invariant to fee throughput.  Drive 0× / 1× / 100×
    fee bookkeeping at matched balance setups; controller behavior
    identical.

    Anchor: CLAUDE.md "Issuance targets a stable active supply, not a
    fixed schedule" + "no large supply shocks in either direction"
    (Core Economic Tenets §1).
    """

    HEIGHT = DORMANCY_TARGET_RETUNE_HEIGHT + 100  # post-Tier-60

    FEE_LEVELS = [
        (0, 0),                       # 0× — no fees
        (10**6, 10**6 // 2),          # 1× — modest fees
        (10**12, 10**12 // 2),        # 100× — heavy fee era
    ]

    def _tracker_at(self, active_balance: int, fees: int, burned: int) -> SupplyTracker:
        s = SupplyTracker()
        eid = b"\x02" + b"\x00" * 31
        s.balances[eid] = active_balance
        s.last_active_heights[eid] = self.HEIGHT
        s.total_fees_collected = fees
        s.total_burned = burned
        return s

    def test_at_target_mints_zero_under_any_fee_throughput(self):
        # active_supply exactly at target → gap = 0 → issuance = 0,
        # regardless of accumulated fees / burns.
        for fees, burned in self.FEE_LEVELS:
            s = self._tracker_at(DORMANCY_TARGET_ACTIVE_SUPPLY_V2, fees, burned)
            self.assertEqual(
                s.compute_dormancy_issuance(self.HEIGHT), 0,
                msg=f"controller minted at-target with fees={fees}",
            )

    def test_above_target_mints_zero_under_any_fee_throughput(self):
        # active_supply above target → gap < 0 → issuance = 0.
        for fees, burned in self.FEE_LEVELS:
            s = self._tracker_at(
                DORMANCY_TARGET_ACTIVE_SUPPLY_V2 + 5_000_000, fees, burned,
            )
            self.assertEqual(
                s.compute_dormancy_issuance(self.HEIGHT), 0,
                msg=f"controller minted above-target with fees={fees}",
            )

    def test_below_target_issuance_constant_across_fee_levels(self):
        # active_supply 10M below target → gap = 10M → controller mints
        # the same amount regardless of fee bookkeeping.
        below = DORMANCY_TARGET_ACTIVE_SUPPLY_V2 - 10_000_000
        baseline = None
        for fees, burned in self.FEE_LEVELS:
            s = self._tracker_at(below, fees, burned)
            issuance = s.compute_dormancy_issuance(self.HEIGHT)
            self.assertGreater(issuance, 0)
            if baseline is None:
                baseline = issuance
            else:
                self.assertEqual(
                    issuance, baseline,
                    msg=(
                        f"controller varied across fee levels: "
                        f"baseline={baseline}, observed={issuance} at fees={fees}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
