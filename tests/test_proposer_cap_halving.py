"""Tests for the halvings-aware proposer reward cap (Tier 19).

Background
----------
Pre-Tier-19, ``PROPOSER_REWARD_CAP`` is computed once at module load:

    PROPOSER_REWARD_CAP = BLOCK_REWARD * 1 / 4 = 4 tokens

This is fine while ``BLOCK_REWARD`` stays at its initial value (16),
but the halving schedule drives the actual minted reward down to
``BLOCK_REWARD_FLOOR=4`` over time.  At the floor era a single
validator who proposes AND attests can earn proposer_share(1) +
attester_pool(3) = 4 tokens — exactly the cap, so no clawback ever
fires.  The mechanism is permanently non-binding once the chain
reaches the floor.

At ``PROPOSER_CAP_HALVING_HEIGHT`` (Tier 19) the cap becomes a
function of the actual issued reward at this height: ``effective_cap
= reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR``.
That keeps the cap at exactly 1/4 of the issued reward across all
eras, including post-halving and post-floor.

Tests below pin down:
1. Pre-fork behavior is byte-for-byte unchanged (cap == 4 regardless
   of halvings — the bug we're shipping the fork to fix).
2. Post-fork behavior tracks halvings: at reward=8 the cap is 2,
   at reward=4 the cap is 1.
3. The proposer-cap clawback fires correctly at the new cap.
4. Conservation (sum of deltas + burned == reward) holds at every
   halving era.
5. The bootstrap path (effective_cap = reward) is unaffected.
"""

import unittest
from unittest.mock import patch

from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    HALVING_INTERVAL,
    PROPOSER_REWARD_CAP,
    PROPOSER_CAP_HALVING_HEIGHT,
    TREASURY_ENTITY_ID,
)


def _height_at_reward(reward: int) -> int:
    """Return a post-fork height that mints ``reward`` tokens/block.

    The halving schedule is reward = BLOCK_REWARD >> halvings, floored
    at BLOCK_REWARD_FLOOR.  Pick the smallest height whose halvings
    count produces the target reward, then offset it past
    PROPOSER_CAP_HALVING_HEIGHT so the new cap rule activates.
    """
    if reward == BLOCK_REWARD:
        target_halvings = 0
    elif reward >= BLOCK_REWARD_FLOOR:
        # reward = BLOCK_REWARD >> n  →  n = log2(BLOCK_REWARD / reward)
        target_halvings = (BLOCK_REWARD).bit_length() - reward.bit_length()
    else:
        raise ValueError(f"reward={reward} below floor")
    base = target_halvings * HALVING_INTERVAL
    return max(base, PROPOSER_CAP_HALVING_HEIGHT)


class TestPreForkUnchanged(unittest.TestCase):
    """At heights below the fork, cap == PROPOSER_REWARD_CAP exactly."""

    def test_pre_fork_cap_is_frozen_constant(self):
        """Block at height 0: cap is the import-time constant (4)."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32

        result = supply.mint_block_reward(
            proposer,
            block_height=0,
            attester_committee=[proposer, other],
        )

        # Default constants: share=4, cap=4.  Proposer in committee
        # triggers the slot clawback path.  Net proposer = 4.
        self.assertEqual(supply.balances[proposer], PROPOSER_REWARD_CAP)
        self.assertEqual(supply.balances[other], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[other]
            + result["burned"],
            BLOCK_REWARD,
        )

    def test_pre_fork_cap_unchanged_one_block_before_activation(self):
        """At PROPOSER_CAP_HALVING_HEIGHT - 1, cap is still the legacy
        constant.  Even if halvings somehow already drove reward down
        (forced via patched HALVING_INTERVAL=1), the pre-fork branch
        does NOT recompute the cap from current reward.
        """
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32

        height = PROPOSER_CAP_HALVING_HEIGHT - 1
        # Force reward=4 even at this height by patching halvings.
        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            1,
        ):
            # Sanity: calculate_block_reward returns the floor here.
            self.assertEqual(supply.calculate_block_reward(height), BLOCK_REWARD_FLOOR)
            result = supply.mint_block_reward(
                proposer,
                block_height=height,
                attester_committee=[proposer, other],
            )

        # Pre-fork: cap is the frozen constant (4), not a function of
        # the actual reward (4).  At reward=4 / cap=4 / share=1, the
        # proposer can earn share(1) + slot(reward//committee=4//2=2)
        # = 3 < 4, so no cap fires.  Proposer keeps everything.
        # Note: per_slot_reward = attester_pool // committee_size
        #     = (4 - 1) // 2 = 1.
        # Proposer total = share(1) + slot(1) = 2 < cap(4) → no cap.
        self.assertEqual(supply.balances[proposer], 1 + 1)


class TestPostForkHalvingAware(unittest.TestCase):
    """At heights >= fork, cap = reward * 1/4."""

    def test_at_first_halving_cap_is_2(self):
        """BLOCK_REWARD=16 → 8 (one halving): cap should be 2."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32

        # Force one halving by patching HALVING_INTERVAL so we don't
        # need to advance the chain to block 210k+.
        height = PROPOSER_CAP_HALVING_HEIGHT
        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            height,
        ):
            self.assertEqual(supply.calculate_block_reward(height), 8)
            result = supply.mint_block_reward(
                proposer,
                block_height=height,
                attester_committee=[proposer, other],
            )

        # Reward=8, share=8//4=2, attester_pool=6, per_slot=6//2=3.
        # proposer_total = share(2) + slot(3) = 5 > new_cap(2).
        # Clawback: subtract 3 from proposer's balance, share alone=2 ==
        # new_cap, no further trim.  Net proposer = 2.
        self.assertEqual(result["total_reward"], 8)
        self.assertEqual(supply.balances[proposer], 2)
        self.assertEqual(supply.balances[other], 3)
        # Conservation: 2 + 3 + burned == 8 → burned == 3.
        self.assertEqual(result["burned"], 3)

    def test_at_floor_era_cap_is_1(self):
        """At reward=BLOCK_REWARD_FLOOR=4, post-fork cap = 1.

        This is the failure mode the fork is designed to fix.  Without
        the fork the cap stays at 4 and a mega-staker on a single-slot
        committee captures the whole block.
        """
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32

        height = PROPOSER_CAP_HALVING_HEIGHT
        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            1,
        ):
            self.assertEqual(supply.calculate_block_reward(height), 4)
            result = supply.mint_block_reward(
                proposer,
                block_height=height,
                attester_committee=[proposer, other],
            )

        # Reward=4, share=4//4=1, attester_pool=3, per_slot=3//2=1.
        # proposer_total = 1 + 1 = 2 > new_cap(1).
        # Clawback: subtract 1 from proposer balance.  share(1) == cap(1),
        # no further trim.  Net proposer = 1, other = 1, burned = 2.
        self.assertEqual(result["total_reward"], 4)
        self.assertEqual(supply.balances[proposer], 1)
        self.assertEqual(supply.balances[other], 1)
        self.assertEqual(result["burned"], 2)

    def test_no_committee_unaffected_post_fork(self):
        """No-committee path bypasses cap logic — proposer gets full
        reward post-fork too.  Same legacy behavior."""
        supply = SupplyTracker()
        proposer = b"p" * 32

        height = PROPOSER_CAP_HALVING_HEIGHT
        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            1,
        ):
            result = supply.mint_block_reward(proposer, block_height=height)

        self.assertEqual(result["total_reward"], 4)
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(result["burned"], 0)

    def test_bootstrap_unaffected_post_fork(self):
        """Bootstrap mode: effective_cap = reward, NOT the new
        halvings-aware cap.  The bootstrap branch is orthogonal."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        other = b"a" * 32

        height = PROPOSER_CAP_HALVING_HEIGHT
        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            1,
        ):
            result = supply.mint_block_reward(
                proposer,
                block_height=height,
                attester_committee=[proposer, other],
                bootstrap=True,
            )

        # Bootstrap: cap = reward (4).  proposer_total = 1 + 1 = 2 ≤ 4,
        # no clawback.  Proposer keeps share(1) + slot(1) = 2.
        self.assertEqual(supply.balances[proposer], 2)
        self.assertEqual(supply.balances[other], 1)


class TestConservationAcrossEras(unittest.TestCase):
    """Conservation invariant must hold at every halving era."""

    def _conservation_check(self, *, reward_target):
        supply = SupplyTracker()
        proposer = b"p" * 32
        others = [bytes([i]) * 32 for i in range(1, 5)]
        for eid in [proposer, *others, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        height = PROPOSER_CAP_HALVING_HEIGHT
        # Pick HALVING_INTERVAL so the chosen height yields reward_target.
        if reward_target == BLOCK_REWARD:
            patched_interval = max(height + 1, 1)
        elif reward_target == BLOCK_REWARD // 2:
            patched_interval = height
        else:
            patched_interval = 1  # forces floor

        balances_before = {eid: 0 for eid in [proposer, *others, TREASURY_ENTITY_ID]}
        supply_before = supply.total_supply

        with patch(
            "messagechain.economics.inflation.HALVING_INTERVAL",
            patched_interval,
        ):
            self.assertEqual(
                supply.calculate_block_reward(height), reward_target,
            )
            result = supply.mint_block_reward(
                proposer,
                block_height=height,
                attester_committee=[proposer, others[0], others[1]],
            )

        reward = result["total_reward"]
        burned = result["burned"]
        delta_sum = sum(
            supply.balances.get(eid, 0) - balances_before[eid]
            for eid in [proposer, *others, TREASURY_ENTITY_ID]
        )
        self.assertEqual(
            delta_sum + burned, reward,
            f"conservation violated at reward={reward_target}",
        )
        self.assertEqual(supply.total_supply, supply_before + reward - burned)
        # Treasury never auto-credited.
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_conservation_at_initial_reward(self):
        self._conservation_check(reward_target=BLOCK_REWARD)

    def test_conservation_after_one_halving(self):
        self._conservation_check(reward_target=BLOCK_REWARD // 2)

    def test_conservation_at_floor(self):
        self._conservation_check(reward_target=BLOCK_REWARD_FLOOR)


if __name__ == "__main__":
    unittest.main()
