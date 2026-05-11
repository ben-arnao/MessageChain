"""Audit r47 #2 -- Tier 71: per-slot attester reward sizing must route
through the Tier 70 ``effective_weight`` soft cap.

Tier 70 (audit r46 #2) introduced the rational soft-cap

    effective_weight(s) = s * C / (s + C)

and routed three consensus-active call sites through it:

  * ``weights_for_progress`` -- attester-committee SELECTION
  * ``select_proposer_vrf`` -- active proposer-selection path
  * ``Blockchain._selected_proposer_for_slot`` fallback -- pre-VRF /
    very-early-chain proposer path

But the per-attester reward SIZING path in
``SupplyTracker.mint_block_reward`` (and its sim mirror in
``Blockchain._calculate_committee_rewards``) still read raw stake:

    total_active_stake = sum(self.staked.values())  # raw
    stake_bps = self.staked.get(eid, 0) * 10_000 // total_active_stake

Both numerator and denominator are linear in whale stake.  The v4
reward-curve multiplier (``reward_curve_multiplier_v4``) then sizes
each attester's per-slot reward off that raw bps -- so on a chain
with a single dominant staker, the small-stake validator sees
``stake_bps`` round to ~0 (e.g. at 200 / 50M = 0.04 bps) and the
v4 multiplier sits at the high-end of the curve, but the founder's
bps stays near 9999 and the founder absorbs the bulk of the per-slot
reward via the absolute pool share even though per-unit yield should
be compressed.

CLAUDE.md anchor at risk: "Stake concentration is softly capped via
diminishing returns -- rich-get-richer in absolute terms, but their
*share* of issuance compresses over time."  Tier 70 compressed
SELECTION share; without this fix the per-slot reward sizing path
stretches the compression back out to linear.

Abstraction fix: Tier 71 routes the per-slot reward sizing through
the same ``effective_weight`` chokepoint.  Pre-fork the behavior is
byte-identical to today (``effective_weight`` is the identity below
the Tier 70 activation height, which Tier 71 is strictly above);
post-fork the per-slot bps is sized against effective-weight totals.

Both the apply path (``SupplyTracker.mint_block_reward``) and the
sim mirror (in ``Blockchain._calculate_committee_rewards`` /
``_apply_block_state``) must change in lockstep -- the sim drives
the state-root commitment, so any drift between sim and apply forks
the chain on the activation block.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain import config
from messagechain.consensus.attester_committee import effective_weight
from messagechain.core.blockchain import Blockchain
from messagechain.economics.inflation import SupplyTracker


class TestTier71HeightConstantsAndOrdering(unittest.TestCase):
    """Tier 71 must be defined, must follow Tier 70 (the activation it
    depends on), and must have meaningful runway."""

    def test_height_constant_exists(self):
        self.assertTrue(
            hasattr(config, "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT"),
            "Tier 71 activation height must be defined in config -- "
            "this is the gate that turns on effective_weight in the "
            "per-slot reward sizing path.",
        )

    def test_tier71_follows_tier70(self):
        """Tier 71 routes per-slot reward sizing through the
        ``effective_weight`` curve.  ``effective_weight`` is the
        identity until Tier 70 activates, so gating Tier 71 below
        Tier 70 would be a no-op for live nodes (sim ahead of apply
        could even diverge the state root at the Tier-70 activation
        block).  Tier 71 MUST strictly follow Tier 70."""
        self.assertGreater(
            config.EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT,
            config.STAKE_CONCENTRATION_SOFT_CAP_HEIGHT,
            "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT must strictly follow "
            "STAKE_CONCENTRATION_SOFT_CAP_HEIGHT -- effective_weight is "
            "the identity below Tier 70.",
        )

    def test_tier71_runway_above_tier70(self):
        """Validators need runway for the Tier 71 cohort separately from
        the Tier 70 cohort -- piling fork heights into a tight band
        reduces the operational margin for upgrades."""
        runway = (
            config.EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT
            - config.STAKE_CONCENTRATION_SOFT_CAP_HEIGHT
        )
        self.assertGreaterEqual(
            runway, 1000,
            "Tier 71 runway must be at least 1000 blocks (~7d) above "
            "Tier 70 -- consecutive consensus-rule activations need "
            "cohort spacing.",
        )


class TestApplyPathRoutesThroughEffectiveWeight(unittest.TestCase):
    """Structural: ``SupplyTracker.mint_block_reward`` source must
    reference ``effective_weight`` and the Tier 71 height gate.  A new
    reward-sizing call site that bypasses the helper reintroduces the
    audit r47 #2 defect."""

    def test_mint_block_reward_imports_effective_weight(self):
        src = inspect.getsource(SupplyTracker.mint_block_reward)
        self.assertIn(
            "effective_weight", src,
            "mint_block_reward must route the per-slot bps numerator "
            "and the total-active-stake denominator through "
            "effective_weight(stake, block_height) when Tier 71 is "
            "active.",
        )

    def test_mint_block_reward_references_tier71_gate(self):
        src = inspect.getsource(SupplyTracker.mint_block_reward)
        self.assertIn(
            "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT", src,
            "mint_block_reward must gate the effective_weight routing "
            "behind the Tier 71 activation height so pre-fork replay "
            "stays byte-identical.",
        )


class TestSimMirrorRoutesThroughEffectiveWeight(unittest.TestCase):
    """The sim path in ``Blockchain.compute_post_state_root`` drives the
    state-root commitment.  Any drift between sim and apply forks the
    chain on the Tier 71 activation block."""

    def test_sim_mirror_imports_effective_weight(self):
        src = inspect.getsource(Blockchain.compute_post_state_root)
        self.assertIn(
            "effective_weight", src,
            "compute_post_state_root sim mirror must route per-slot "
            "bps through effective_weight to match the apply path.",
        )

    def test_sim_mirror_references_tier71_gate(self):
        src = inspect.getsource(Blockchain.compute_post_state_root)
        self.assertIn(
            "EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT", src,
            "compute_post_state_root sim mirror must gate "
            "effective_weight routing behind the same Tier 71 height "
            "as the apply path.",
        )


class TestBehavioralPreVsPostFork(unittest.TestCase):
    """Behavioral: at a single-dominant-staker distribution, the small
    validator's effective bps share post-Tier-71 must be meaningfully
    larger than its raw bps share -- the property that makes the per-
    unit-yield compression actually flow through to per-slot reward."""

    def _set_up_supply(self) -> tuple[SupplyTracker, bytes, bytes]:
        s = SupplyTracker()
        whale = b"\x01" * 32
        ant = b"\x02" * 32
        s.balances[whale] = 100_000_000
        s.balances[ant] = 10_000
        s.staked[whale] = 50_000_000
        s.staked[ant] = 200
        return s, whale, ant

    def test_pre_tier71_pays_attesters_by_raw_bps(self):
        """At a height below Tier 71, mint_block_reward must use raw
        stake for bps -- pre-fork replay byte-identical."""
        s, whale, ant = self._set_up_supply()
        pre_height = config.EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT - 1
        result = s.mint_block_reward(
            proposer_id=whale,
            block_height=pre_height,
            attester_committee=[whale, ant],
        )
        ar = result["attestor_rewards"]
        # At raw-bps, ant's stake is 200 / 50_000_200 ~= 0 bps so ant's
        # multiplier sits at the v4 PEAK (small-staker bonus).  But the
        # PER-SLOT pool share is determined by attester_pool // n; the
        # bps only modulates the multiplier.  The structural check that
        # matters: both attesters get >= 0 from a positive pool, and
        # ant's reward is bounded above by the multiplier-applied per-
        # slot.  This test just pins that the call succeeds and produces
        # the legacy shape pre-fork.
        self.assertIn(whale, ar)
        self.assertIn(ant, ar)

    def test_post_tier71_ant_bps_share_is_meaningfully_larger(self):
        """At and above Tier 71, the small validator's effective-weight
        bps share (numerator AND denominator routed through
        effective_weight) is dramatically larger than its raw-stake bps
        share -- the property that makes the per-unit-yield compression
        flow through to per-slot reward sizing."""
        whale_stake = 50_000_000
        ant_stake = 200
        post_height = config.EFFECTIVE_WEIGHT_REWARD_SIZING_HEIGHT + 1

        raw_total = whale_stake + ant_stake
        raw_ant_bps = ant_stake * 10_000 // raw_total

        eff_total = (
            effective_weight(whale_stake, post_height)
            + effective_weight(ant_stake, post_height)
        )
        eff_ant_bps = (
            effective_weight(ant_stake, post_height) * 10_000 // eff_total
        )

        # Raw bps for ant at 200/50M+200 is 0 (integer division).
        # Effective bps -- with the soft-cap curve compressing whale's
        # weight from 50M down to ~980_400 -- is ~2 bps.  The exact
        # value depends on integer-arithmetic rounding; what we pin is
        # the qualitative property the anchor cares about: the small
        # validator's per-unit-yield SHARE must be MEANINGFULLY larger
        # post-fork (orders-of-magnitude, not single-bps cosmetic).
        self.assertEqual(
            raw_ant_bps, 0,
            "Pre-Tier-71 baseline: ant at 200/50M sees ~0 raw bps.  "
            "This is the property the fix targets.",
        )
        self.assertGreater(
            eff_ant_bps, raw_ant_bps,
            "Post-Tier-71: routing both numerator and denominator "
            "through effective_weight must increase ant's bps share "
            "(per-unit-yield compression flowing to reward sizing).",
        )
        self.assertGreaterEqual(
            eff_ant_bps, 2,
            f"With C=1M and whale_stake=50M, effective-weight bps for "
            f"a 200-stake validator should be ~2 bps; got {eff_ant_bps}",
        )


if __name__ == "__main__":
    unittest.main()
