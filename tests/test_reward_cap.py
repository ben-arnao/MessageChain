"""Tests for per-validator reward capping.

Reward capping limits how much any single validator can earn from block
rewards per block. This breaks the compounding loop where large stakers
earn proportionally more, accumulate more stake, and dominate further.

Excess rewards go to the treasury for community use.

Reward distribution is now committee-based (see
messagechain/consensus/attester_committee.py): each committee slot pays
ATTESTER_REWARD_PER_SLOT = 1 token, and the proposer's combined earnings
(proposer share + slot if they're on the committee) still respect
PROPOSER_REWARD_CAP.
"""

import unittest
from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
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
        if BLOCK_REWARD <= PROPOSER_REWARD_CAP:
            self.assertEqual(result["proposer_reward"], BLOCK_REWARD)

    def test_proposer_share_capped_when_also_in_committee(self):
        """Proposer-share + committee-slot combined respects the cap."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        att = b"a" * 32
        supply.balances[proposer] = 0
        supply.balances[att] = 0
        supply.balances[TREASURY_ENTITY_ID] = 0

        # Proposer is on the committee AND is the proposer.
        result = supply.mint_block_reward(
            proposer, block_height=0, attester_committee=[proposer, att],
        )
        total_proposer_earned = (
            result["proposer_reward"]
            + result["attestor_rewards"].get(proposer, 0)
        )
        self.assertLessEqual(total_proposer_earned, PROPOSER_REWARD_CAP)

    def test_excess_goes_to_treasury_no_committee(self):
        """Capped excess when there's no committee (pure proposer path)."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0
        treasury_before = supply.balances.get(TREASURY_ENTITY_ID, 0)

        result = supply.mint_block_reward(proposer, block_height=0)

        if BLOCK_REWARD > PROPOSER_REWARD_CAP:
            treasury_after = supply.balances.get(TREASURY_ENTITY_ID, 0)
            self.assertGreater(treasury_after, treasury_before)
            self.assertEqual(result["proposer_reward"], PROPOSER_REWARD_CAP)
            self.assertEqual(
                result["treasury_excess"], BLOCK_REWARD - PROPOSER_REWARD_CAP,
            )

    def test_cap_does_not_affect_committee_members(self):
        """Non-proposer committee members always get their 1-token slot."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        att1 = b"a" * 32
        att2 = b"b" * 32
        supply.balances[proposer] = 0
        supply.balances[att1] = 0
        supply.balances[att2] = 0

        # Two non-proposer committee members.
        result = supply.mint_block_reward(
            proposer, block_height=0, attester_committee=[att1, att2],
        )
        # Each non-proposer slot pays the flat ATTESTER_REWARD_PER_SLOT.
        # No stake-weighted pro-rata; cap does not apply.
        self.assertEqual(result["attestor_rewards"][att1], ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(result["attestor_rewards"][att2], ATTESTER_REWARD_PER_SLOT)

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

        self.assertEqual(supply.total_supply, supply_before + BLOCK_REWARD)


if __name__ == "__main__":
    unittest.main()
