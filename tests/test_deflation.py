"""Tests for deflationary token economics."""

import unittest
from messagechain.economics.deflation import SupplyTracker
from messagechain.config import GENESIS_SUPPLY, BURN_RATE, MIN_BURN


class TestDeflation(unittest.TestCase):
    def setUp(self):
        self.tracker = SupplyTracker()
        self.entity_id = b"\x01" * 32
        self.tracker.initialize_balance(self.entity_id, 10000)

    def test_initial_state(self):
        self.assertEqual(self.tracker.total_supply, GENESIS_SUPPLY)
        self.assertEqual(self.tracker.total_burned, 0)

    def test_burn_cost_proportional_to_supply(self):
        cost = self.tracker.calculate_burn_cost()
        expected = max(MIN_BURN, int(GENESIS_SUPPLY * BURN_RATE))
        self.assertEqual(cost, expected)

    def test_burn_decreases_supply(self):
        cost = self.tracker.calculate_burn_cost()
        self.tracker.execute_burn(self.entity_id, cost)
        self.assertEqual(self.tracker.total_supply, GENESIS_SUPPLY - cost)
        self.assertEqual(self.tracker.total_burned, cost)

    def test_supply_strictly_decreasing(self):
        """Each burn reduces total supply."""
        prev_supply = self.tracker.total_supply
        for _ in range(10):
            cost = self.tracker.calculate_burn_cost()
            self.tracker.execute_burn(self.entity_id, cost)
            self.assertLess(self.tracker.total_supply, prev_supply)
            prev_supply = self.tracker.total_supply

    def test_burn_cost_decreases_over_time(self):
        """As supply shrinks, absolute burn cost decreases."""
        costs = []
        for _ in range(100):
            cost = self.tracker.calculate_burn_cost()
            costs.append(cost)
            self.tracker.execute_burn(self.entity_id, cost)
        # Cost should be non-increasing
        for i in range(1, len(costs)):
            self.assertLessEqual(costs[i], costs[i - 1])

    def test_insufficient_balance(self):
        poor_entity = b"\x02" * 32
        self.tracker.initialize_balance(poor_entity, 0)
        self.assertFalse(self.tracker.can_afford(poor_entity))

    def test_staking(self):
        self.assertTrue(self.tracker.stake(self.entity_id, 500))
        self.assertEqual(self.tracker.get_balance(self.entity_id), 9500)
        self.assertEqual(self.tracker.get_staked(self.entity_id), 500)

    def test_transfer(self):
        other = b"\x03" * 32
        self.tracker.initialize_balance(other, 0)
        self.assertTrue(self.tracker.transfer(self.entity_id, other, 100))
        self.assertEqual(self.tracker.get_balance(other), 100)

    def test_supply_stats(self):
        stats = self.tracker.get_supply_stats()
        self.assertIn("total_supply", stats)
        self.assertIn("deflation_pct", stats)
        self.assertIn("projected_supply_after_1000_msgs", stats)


if __name__ == "__main__":
    unittest.main()
