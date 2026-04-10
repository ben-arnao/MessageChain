"""Tests for inflationary token economics."""

import unittest
from messagechain.economics.inflation import SupplyTracker
from messagechain.config import GENESIS_SUPPLY, BLOCK_REWARD, HALVING_INTERVAL, MIN_FEE


class TestInflation(unittest.TestCase):
    def setUp(self):
        self.tracker = SupplyTracker()
        self.entity_id = b"\x01" * 32
        self.proposer_id = b"\x02" * 32
        self.tracker.balances[self.entity_id] = 10000
        self.tracker.balances[self.proposer_id] = 0

    def test_initial_state(self):
        self.assertEqual(self.tracker.total_supply, GENESIS_SUPPLY)
        self.assertEqual(self.tracker.total_minted, 0)

    def test_block_reward_minting(self):
        reward = self.tracker.mint_block_reward(self.proposer_id, block_height=1)
        self.assertEqual(reward, BLOCK_REWARD)
        self.assertEqual(self.tracker.total_supply, GENESIS_SUPPLY + BLOCK_REWARD)
        self.assertEqual(self.tracker.get_balance(self.proposer_id), BLOCK_REWARD)

    def test_supply_increases_over_blocks(self):
        """Supply should increase with each block (inflation)."""
        for i in range(10):
            self.tracker.mint_block_reward(self.proposer_id, block_height=i)
        self.assertGreater(self.tracker.total_supply, GENESIS_SUPPLY)

    def test_halving_reduces_reward(self):
        reward_early = self.tracker.calculate_block_reward(0)
        reward_after_halving = self.tracker.calculate_block_reward(HALVING_INTERVAL)
        self.assertEqual(reward_early, 16)
        self.assertEqual(reward_after_halving, 8)

    def test_four_meaningful_halvings(self):
        """BLOCK_REWARD=16 gives 4 meaningful halvings: 16 -> 8 -> 4 -> 2 -> 1 (floor)."""
        self.assertEqual(self.tracker.calculate_block_reward(0), 16)
        self.assertEqual(self.tracker.calculate_block_reward(HALVING_INTERVAL), 8)
        self.assertEqual(self.tracker.calculate_block_reward(HALVING_INTERVAL * 2), 4)
        self.assertEqual(self.tracker.calculate_block_reward(HALVING_INTERVAL * 3), 2)
        self.assertEqual(self.tracker.calculate_block_reward(HALVING_INTERVAL * 4), 1)
        self.assertEqual(self.tracker.calculate_block_reward(HALVING_INTERVAL * 5), 1)

    def test_reward_never_reaches_zero(self):
        """Even after many halvings, reward stays at least 1."""
        reward = self.tracker.calculate_block_reward(HALVING_INTERVAL * 100)
        self.assertGreaterEqual(reward, 1)

    def test_fee_payment(self):
        self.assertTrue(self.tracker.pay_fee(self.entity_id, self.proposer_id, 100))
        self.assertEqual(self.tracker.get_balance(self.entity_id), 9900)
        self.assertEqual(self.tracker.get_balance(self.proposer_id), 100)
        self.assertEqual(self.tracker.total_fees_collected, 100)

    def test_fee_below_minimum_rejected(self):
        self.assertFalse(self.tracker.pay_fee(self.entity_id, self.proposer_id, 0))

    def test_fee_exceeding_balance_rejected(self):
        self.assertFalse(self.tracker.pay_fee(self.entity_id, self.proposer_id, 999999))

    def test_staking(self):
        self.assertTrue(self.tracker.stake(self.entity_id, 500))
        self.assertEqual(self.tracker.get_balance(self.entity_id), 9500)
        self.assertEqual(self.tracker.get_staked(self.entity_id), 500)

    def test_transfer(self):
        other = b"\x03" * 32
        self.tracker.balances[other] = 0
        self.assertTrue(self.tracker.transfer(self.entity_id, other, 100))
        self.assertEqual(self.tracker.get_balance(other), 100)

    def test_supply_stats(self):
        stats = self.tracker.get_supply_stats(current_block_height=5)
        self.assertIn("total_supply", stats)
        self.assertIn("inflation_pct", stats)
        self.assertIn("current_block_reward", stats)
        self.assertIn("next_halving_block", stats)


if __name__ == "__main__":
    unittest.main()
