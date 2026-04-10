"""Tests for per-validator reward capping.

Reward capping limits how much any single validator can earn from block
rewards per block. This breaks the compounding loop where large stakers
earn proportionally more, accumulate more stake, and dominate further.

Excess rewards go to the treasury for community use.
"""

import unittest
from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    BLOCK_REWARD, PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
    TREASURY_ENTITY_ID, PROPOSER_REWARD_CAP,
)


class TestRewardCap(unittest.TestCase):
    """Proposer reward is capped per block."""

    def setUp(self):
        self.supply = SupplyTracker()
        self.proposer = b"p" * 32
        self.supply.balances[self.proposer] = 0

    def test_small_reward_not_capped(self):
        """Rewards below the cap are paid in full."""
        result = self.supply.mint_block_reward(self.proposer, block_height=0)
        # Full reward with no attestors = 16 tokens
        # If 16 <= cap, proposer should get full reward
        if BLOCK_REWARD <= PROPOSER_REWARD_CAP:
            self.assertEqual(result["proposer_reward"], BLOCK_REWARD)

    def test_proposer_share_capped_with_attestors(self):
        """When proposer's share exceeds cap, excess goes to treasury."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        # Give proposer a huge attestor stake to earn most of the attestor pool too
        # Use a scenario where proposer is also an attestor with large stake
        attestor_stakes = {proposer: 10_000, b"a" * 32: 1}
        supply.balances[b"a" * 32] = 0

        result = supply.mint_block_reward(proposer, block_height=0, attestor_stakes=attestor_stakes)

        # Proposer earns: proposer_share + their attestor pro-rata share
        # Both combined should not exceed cap
        total_proposer_earned = result["proposer_reward"] + result["attestor_rewards"].get(proposer, 0)
        self.assertLessEqual(total_proposer_earned, PROPOSER_REWARD_CAP)

    def test_excess_goes_to_treasury(self):
        """Capped excess is redirected to treasury."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        treasury_before = supply.balances.get(TREASURY_ENTITY_ID, 0)

        # No attestors — proposer would get full reward (16 tokens)
        # If cap < 16, excess should go to treasury
        result = supply.mint_block_reward(proposer, block_height=0)

        if BLOCK_REWARD > PROPOSER_REWARD_CAP:
            treasury_after = supply.balances.get(TREASURY_ENTITY_ID, 0)
            self.assertGreater(treasury_after, treasury_before)
            self.assertEqual(result["proposer_reward"], PROPOSER_REWARD_CAP)
            self.assertEqual(result["treasury_excess"], BLOCK_REWARD - PROPOSER_REWARD_CAP)

    def test_cap_does_not_affect_attestor_rewards(self):
        """Non-proposer attestors are not subject to the proposer cap."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        att1 = b"a" * 32
        att2 = b"b" * 32
        supply.balances[proposer] = 0
        supply.balances[att1] = 0
        supply.balances[att2] = 0

        attestor_stakes = {att1: 500, att2: 500}
        result = supply.mint_block_reward(proposer, block_height=0, attestor_stakes=attestor_stakes)

        # Attestors split 3/4 of reward equally
        attestor_pool = BLOCK_REWARD - (BLOCK_REWARD * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR)
        expected_each = attestor_pool // 2

        # Attestor rewards should not be reduced by the cap
        self.assertEqual(result["attestor_rewards"][att1], expected_each)

    def test_reward_cap_config_exists(self):
        """PROPOSER_REWARD_CAP is defined and reasonable."""
        self.assertGreater(PROPOSER_REWARD_CAP, 0)
        self.assertLessEqual(PROPOSER_REWARD_CAP, BLOCK_REWARD)

    def test_total_minted_unchanged_by_cap(self):
        """Capping doesn't reduce total minted — tokens still enter supply."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        supply_before = supply.total_supply

        supply.mint_block_reward(proposer, block_height=0)

        # Total supply should increase by full block reward regardless of cap
        self.assertEqual(supply.total_supply, supply_before + BLOCK_REWARD)


if __name__ == "__main__":
    unittest.main()
