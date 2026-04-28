"""Tier 35 — dynamic attester committee at floor era.

Background
----------
Tier 4 (`ATTESTER_REWARD_SPLIT_HEIGHT`) decoupled committee size from
reward budget: the committee is now sized to a fixed
`ATTESTER_COMMITTEE_TARGET_SIZE = 128` post-activation, and
`mint_block_reward` divides `attester_pool` pro-rata across the full
committee with integer-division remainder burning.  That fixed the
"only 3 paid forever at floor" structural failure of the legacy
truncate path, but it traded one decentralization failure for another:
when `attester_pool < committee_size`, integer division rounds to 0,
the entire pool burns, and EVERY committee member earns 0 from
issuance.

The CLAUDE.md "validator profitability over decades" anchor says the
network must remain economically viable for honest operators forever.
Once halvings drive `BLOCK_REWARD` to `BLOCK_REWARD_FLOOR=4`, the
proposer takes 1 token (PROPOSER_SHARE = 1/4) and `attester_pool = 3`
— a 128-slot committee receives `3 // 128 == 0` tokens per slot.
Every attester's issuance income is permanently zero from year ~8
onward.  The Tier 20 reward-curve multiplier (1.25× mid-tier) on
`per_slot_reward = 0` is still 0 — the entire mid-tier compression
band that's supposed to close the gap on whales is inert at floor era.

Even at genesis (`BLOCK_REWARD = 16`, `attester_pool = 12`) only the
first 12 sorted-by-stake committee slots get 1 token each; the
remaining 116 burn — a ~90% leak of the attester pool's intended
budget across the entire pre-floor regime.

Tier 35 fixes both with a dynamic-committee rule: when
`attester_pool < ATTESTER_COMMITTEE_TARGET_SIZE`, shrink the committee
to `min(target, attester_pool)` so every paid slot gets ≥1 token.
The remaining stake-set still attests for finality liveness; they
just don't draw issuance for THIS block.  Stake-weighted committee
selection rotates them through paid blocks at their stake-weighted
frequency — same selection rule, just a shorter paid prefix.

This file:
  * Pins the pre-Tier-35 zero-per-slot floor-era behavior so hard-fork
    rollback is byte-identical for any height strictly below activation.
  * Locks in the post-Tier-35 dynamic-shrink math at floor era and
    healthy regime.
  * Verifies the reward-curve multiplier reactivates because the base
    is non-zero post-fork.
  * Verifies pre-fork blocks reproduce byte-identical per-attester
    payout distributions vs legacy code.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import (
    ATTESTER_REWARD_PER_SLOT,
)
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    PROPOSER_REWARD_NUMERATOR,
    PROPOSER_REWARD_DENOMINATOR,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_COMMITTEE_TARGET_SIZE,
    ATTESTER_DYNAMIC_COMMITTEE_HEIGHT,
    TREASURY_ENTITY_ID,
)


# Heights for activation tests.  Pre-Tier-35 = ATTESTER_REWARD_SPLIT_
# HEIGHT (the post-Tier-4 regime that exhibits the zero-per-slot bug).
# Post-Tier-35 = ATTESTER_DYNAMIC_COMMITTEE_HEIGHT.
PRE_TIER35_HEIGHT = max(
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_DYNAMIC_COMMITTEE_HEIGHT - 1,
)
POST_TIER35_HEIGHT = ATTESTER_DYNAMIC_COMMITTEE_HEIGHT


def _make_committee(n: int) -> list[bytes]:
    """Deterministic list of n distinct 32-byte entity IDs.

    Skips 0x70 ("p" — reserved for the test proposer) so the committee
    never accidentally contains the proposer.  At n=128 the helper
    yields IDs in [0x10, 0x91] minus the 0x70 byte.
    """
    out: list[bytes] = []
    i = 0
    while len(out) < n:
        b = i + 0x10
        if b != 0x70:  # avoid colliding with proposer ID b"p" * 32
            out.append(bytes([b]) * 32)
        i += 1
    return out


def _freeze_reward_at_floor():
    """Freeze block reward at BLOCK_REWARD_FLOOR for floor-era tests."""
    return patch.object(
        SupplyTracker,
        "calculate_block_reward",
        lambda self, height: BLOCK_REWARD_FLOOR,
    )


class TestPreTier35FloorEraZeroPerSlotPersists(unittest.TestCase):
    """Pre-Tier-35: floor-era 128-member committee yields per_slot=0,
    full attester_pool burns.  This is the regression Tier 35 targets;
    locked in for the pre-activation window so the old behavior remains
    byte-replayable."""

    def test_floor_era_full_committee_zero_per_slot(self):
        """Floor era (`reward=4`, `proposer_share=1`, `pool=3`) with a
        128-member committee: per_slot = 3 // 128 = 0.  Every attester
        earns 0; full 3-token pool burns."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(ATTESTER_COMMITTEE_TARGET_SIZE)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=PRE_TIER35_HEIGHT,
                attester_committee=committee,
            )

        # Floor era: reward=4, proposer_share=1, attester_pool=3.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)
        self.assertEqual(result["total_attestor_reward"], 0)
        self.assertEqual(result["burned"], 3)


class TestPostTier35DynamicShrinkAtFloor(unittest.TestCase):
    """Post-Tier-35: caller shrinks committee_size to
    `min(target, attester_pool)` BEFORE selecting; mint_block_reward
    receives a smaller list, divides exactly, every paid slot earns
    >= 1 token, no burn."""

    def test_floor_era_shrink_to_pool_size_pays_every_slot(self):
        """Floor era: caller passes a 3-member committee (= attester_
        pool size); per_slot = 3 // 3 = 1.  All three earn 1 token.
        No burn — the whole pool delivers."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(3)  # caller already shrunk
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=POST_TIER35_HEIGHT,
                attester_committee=committee,
            )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        self.assertEqual(result["total_attestor_reward"], 3)
        self.assertEqual(result["burned"], 0)

    def test_floor_era_zero_pool_no_committee_no_burn(self):
        """Edge: at attester_pool == 0, no payout, no burn from issuance.
        (Reachable only if rewards become 0; defensive — current floor
        keeps reward >= 4 forever.)  Post-Tier-35 behavior is identical
        to pre-Tier-35 for this corner — empty-committee branch fires."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        # No attesters whatsoever — empty committee branch.
        for eid in [proposer, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=POST_TIER35_HEIGHT,
                attester_committee=[],
            )

        self.assertEqual(result["total_attestor_reward"], 0)
        self.assertEqual(result["burned"], 0)
        # Proposer absorbed full reward (no committee path).
        self.assertEqual(result["proposer_reward"], BLOCK_REWARD_FLOOR)


class TestPostTier35HealthyRegimeShrinks116BurnSlots(unittest.TestCase):
    """At genesis (BLOCK_REWARD=16, attester_pool=12), a 128-slot
    committee under Tier 4 wastes 116 zero-paid slots.  Post-Tier-35
    the caller shrinks to a 12-slot committee that fully consumes the
    pool — same per-slot payout as pre-fork's first-12, but no leaked
    burn beyond it."""

    def test_genesis_pool_12_dynamic_shrink_no_burn(self):
        """Post-Tier-35 caller passes a 12-member committee (= attester_
        pool=12).  per_slot = 12 // 12 = 1; every member earns 1; no
        burn."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(12)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_TIER35_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        self.assertEqual(result["total_attestor_reward"], 12)
        self.assertEqual(result["burned"], 0)

    def test_pre_fork_genesis_pool_12_with_128_committee_burns_116(self):
        """Pre-Tier-35 reference: 128-member committee at genesis pool=12
        produces per_slot = 12 // 128 = 0.  Whole pool of 12 burns.
        This is the upper-bound waste figure that Tier 35 eliminates."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(ATTESTER_COMMITTEE_TARGET_SIZE)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_TIER35_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)
        # Whole pool burns under pre-Tier-35 rule (no committee shrink).
        self.assertEqual(result["burned"], 12)


class TestPostTier35RewardCurveReactivates(unittest.TestCase):
    """The Tier 20 reward-curve multiplier (small=0.8×, mid=1.25×,
    large=1.0×) operates on per_slot_reward.  Pre-Tier-35 at floor
    era, per_slot is 0 so every multiplier output is 0 — the mid-tier
    compression band that's supposed to close the gap on whales is
    inert.  Post-Tier-35 the dynamic shrink produces a non-zero
    per_slot, so the curve actually multiplies a number that matters.

    Note on integer rounding at the edge: at per_slot=1, mid×1.25
    rounds to int(1.25) = 1 — the same integer as the large band's
    1×1=1.  The compression doesn't show as a per-block delta at this
    extreme rounding floor; what DOES show is that the COMMITTEE
    selection (`select_attester_committee` at the caller) uses
    stake-weighted blending, so mid-tier validators are picked into
    the paid set MORE OFTEN per unit stake than large stakers.  Cross
    enough blocks and the relative-rate compression manifests as
    higher annualized issuance per token staked for mid-tier vs
    large.  Pre-Tier-35 that mechanism was strictly inert at floor
    (rate × 0 = 0); post-Tier-35 it's at least 1 per paid slot.
    """

    def test_floor_era_committee_member_earns_nonzero_post_fork(self):
        """Floor era post-Tier-35: a committee member with non-trivial
        stake earns at least 1 token.  Pre-Tier-35 they earn 0.  This
        is the binary reactivation of the curve mechanism — the curve
        operates on >= 1 instead of exactly 0."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(3)
        # Give every committee member non-trivial stake so the curve
        # has a defined stake_bps to evaluate.  Distribute stake
        # evenly so each member sits at the same band — proves
        # baseline reactivation, not curve placement.
        for eid in committee:
            supply.staked[eid] = 1_000_000
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=POST_TIER35_HEIGHT,
                attester_committee=committee,
            )

        for eid in committee:
            # Every paid committee member earns at least the minimum.
            # Pre-Tier-35 this would be 0.
            self.assertGreaterEqual(supply.balances[eid], 1)
        self.assertGreater(result["total_attestor_reward"], 0)


class TestPreTier35ByteIdenticalReplay(unittest.TestCase):
    """Pre-Tier-35 blocks must replay byte-for-byte identically to
    legacy Tier 4 behavior.  Any divergence here breaks reorg-replay
    determinism: a node restarting from a snapshot before activation
    must produce the same per-attester payout list as it did when it
    originally applied the block."""

    def test_pre_fork_floor_era_identical_to_legacy(self):
        """Floor era at PRE_TIER35_HEIGHT: the ENTIRE 128-member
        committee receives 0 (per_slot = 3 // 128 = 0); 3-token pool
        burns.  This is the exact legacy Tier 4 behavior — Tier 35
        must not change it pre-activation."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(ATTESTER_COMMITTEE_TARGET_SIZE)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=PRE_TIER35_HEIGHT,
                attester_committee=committee,
            )

        # All 128 committee members get exactly 0 — pre-Tier-35 legacy.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)
        self.assertEqual(result["total_attestor_reward"], 0)
        # Whole 3-token attester_pool burns.
        self.assertEqual(result["burned"], 3)

    def test_pre_fork_genesis_pool_remainder_burn_unchanged(self):
        """Genesis-era pre-Tier-35: pool=12, committee=5, per_slot =
        12//5 = 2.  Total paid = 10, remainder 2 burns.  Identical to
        legacy split-fork behavior (existing test in
        test_attester_reward_split.py asserts the same)."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(5)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_TIER35_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 2)
        self.assertEqual(result["total_attestor_reward"], 10)
        self.assertEqual(result["burned"], 2)


class TestSelectAttesterCommitteeRespectsShrink(unittest.TestCase):
    """`select_attester_committee` already returns at most
    `committee_size` candidates (sorted), and the existing branch in
    that function naturally handles `committee_size < len(candidates)`
    by taking a stake-weighted sample.  Tier 35 leans on this existing
    behavior — the only change is at the CALLER, computing a smaller
    `committee_size`.  Verify that passing `committee_size = pool`
    produces a committee of EXACTLY pool members when there are more
    candidates than pool, with selection weighting honored."""

    def test_shrink_to_pool_yields_pool_members(self):
        """20 candidates, committee_size=3: returns exactly 3, drawn
        from the candidate set per the stake-weighted blend."""
        from messagechain.consensus.attester_committee import (
            select_attester_committee,
        )
        candidates = [(_make_committee(20)[i], 1_000) for i in range(20)]
        seeds: frozenset[bytes] = frozenset()
        committee = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=seeds,
            bootstrap_progress=1.0,
            randomness=b"\x42" * 32,
            committee_size=3,
        )
        self.assertEqual(len(committee), 3)
        # Each member must be one of the candidates.
        candidate_ids = {eid for eid, _ in candidates}
        for eid in committee:
            self.assertIn(eid, candidate_ids)

    def test_shrink_to_zero_yields_empty_committee(self):
        """committee_size=0 (pool=0 edge) yields empty list."""
        from messagechain.consensus.attester_committee import (
            select_attester_committee,
        )
        candidates = [(_make_committee(5)[i], 1_000) for i in range(5)]
        committee = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            bootstrap_progress=1.0,
            randomness=b"\x42" * 32,
            committee_size=0,
        )
        self.assertEqual(committee, [])


class TestCallerSiteCommitteeSizeDerivation(unittest.TestCase):
    """The dynamic-shrink decision is made at the caller (sim and apply
    paths in `Blockchain.add_block` / `_apply_block_state`) — they
    compute `committee_size = min(target, attester_pool)` post-Tier-35
    and pass it to `select_attester_committee`.  This file pins the
    purely arithmetic part of the rule so a refactor of the caller
    sites can re-verify against it."""

    def test_committee_size_formula_floor(self):
        """At BLOCK_REWARD_FLOOR=4: pool = 3.  Dynamic size = min(128, 3) = 3."""
        proposer_share = (
            BLOCK_REWARD_FLOOR
            * PROPOSER_REWARD_NUMERATOR
            // PROPOSER_REWARD_DENOMINATOR
        )
        pool = BLOCK_REWARD_FLOOR - proposer_share
        self.assertEqual(pool, 3)
        dynamic_size = min(ATTESTER_COMMITTEE_TARGET_SIZE, pool)
        self.assertEqual(dynamic_size, 3)

    def test_committee_size_formula_genesis(self):
        """At BLOCK_REWARD=16: pool = 12.  Dynamic size = min(128, 12) = 12."""
        proposer_share = (
            BLOCK_REWARD
            * PROPOSER_REWARD_NUMERATOR
            // PROPOSER_REWARD_DENOMINATOR
        )
        pool = BLOCK_REWARD - proposer_share
        self.assertEqual(pool, 12)
        dynamic_size = min(ATTESTER_COMMITTEE_TARGET_SIZE, pool)
        self.assertEqual(dynamic_size, 12)

    def test_committee_size_formula_above_target(self):
        """If pool ever exceeds target (it doesn't with current
        constants, but defend the formula): size clamps to target."""
        pool = ATTESTER_COMMITTEE_TARGET_SIZE * 4  # arbitrary large pool
        dynamic_size = min(ATTESTER_COMMITTEE_TARGET_SIZE, pool)
        self.assertEqual(dynamic_size, ATTESTER_COMMITTEE_TARGET_SIZE)

    def test_committee_size_formula_zero_pool(self):
        """Pool=0 (theoretical — current floor keeps reward >= 4):
        size = 0 → caller should skip selection / yield empty
        committee, matching today's empty-committee branch in
        mint_block_reward.  The min() formula naturally produces 0."""
        pool = 0
        dynamic_size = min(ATTESTER_COMMITTEE_TARGET_SIZE, pool)
        self.assertEqual(dynamic_size, 0)


if __name__ == "__main__":
    unittest.main()
