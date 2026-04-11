"""Tests for the unbonding period mechanism.

Validates that unstaking locks tokens for UNBONDING_PERIOD blocks before
they become spendable, and that pending unstakes can still be slashed.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.inflation import SupplyTracker
from messagechain.config import UNBONDING_PERIOD, VALIDATOR_MIN_STAKE
from tests import register_entity_for_test


class TestUnbondingPeriod(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.consensus = ProofOfStake()

    def test_unstake_goes_to_pending(self):
        """Unstaking should not return tokens immediately."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, 500)
        self.assertEqual(supply.get_staked(self.alice.entity_id), 500)

        result = supply.unstake(self.alice.entity_id, 200, current_block=10)
        self.assertTrue(result)
        # Staked amount decreases
        self.assertEqual(supply.get_staked(self.alice.entity_id), 300)
        # But balance does NOT increase yet
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9500)
        # Tokens are in pending
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), 200)

    def test_pending_unstake_releases_after_period(self):
        """Pending tokens become spendable after UNBONDING_PERIOD blocks."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, 500)
        supply.unstake(self.alice.entity_id, 200, current_block=10)

        # Not released yet at block 10 + UNBONDING_PERIOD - 1
        supply.process_pending_unstakes(10 + UNBONDING_PERIOD - 1)
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9500)

        # Released at block 10 + UNBONDING_PERIOD
        supply.process_pending_unstakes(10 + UNBONDING_PERIOD)
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9700)
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), 0)

    def test_pending_unstake_slashable(self):
        """Pending unstakes can still be slashed."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, 500)
        supply.unstake(self.alice.entity_id, 500, current_block=10)

        # Alice has 0 staked, 500 pending — slash should burn pending too
        slashed, reward = supply.slash_validator(self.alice.entity_id, self.bob.entity_id)
        self.assertGreater(slashed, 0)
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), 0)

    def test_multiple_unstakes_tracked_separately(self):
        """Multiple unstake requests at different blocks release at different times."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, 500)

        supply.unstake(self.alice.entity_id, 100, current_block=10)
        supply.unstake(self.alice.entity_id, 100, current_block=20)

        # First batch releases at 10 + UNBONDING_PERIOD
        supply.process_pending_unstakes(10 + UNBONDING_PERIOD)
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9600)  # 9500 + 100

        # Second batch releases at 20 + UNBONDING_PERIOD
        supply.process_pending_unstakes(20 + UNBONDING_PERIOD)
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9700)  # 9600 + 100


class TestUnbondingInBlockchain(unittest.TestCase):
    """Test that unbonding integrates correctly with block processing."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.consensus = ProofOfStake()

    def _make_block(self, proposer, txs):
        prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = self.chain.compute_post_state_root(txs, proposer.entity_id, block_height)
        return self.consensus.create_block(proposer, txs, prev, state_root=state_root)

    def test_unstake_tokens_locked_during_unbonding(self):
        """After unstaking, tokens are locked and cannot be spent until unbonding completes."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, 1000)
        supply.unstake(self.alice.entity_id, 1000, current_block=self.chain.height)

        # Alice's spendable balance should NOT include the unstaked amount
        self.assertEqual(supply.get_balance(self.alice.entity_id), 9000)


if __name__ == "__main__":
    unittest.main()
