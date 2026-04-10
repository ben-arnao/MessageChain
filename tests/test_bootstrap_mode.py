"""Tests for bootstrap mode safety.

Bootstrap mode (permissive block production when no validators exist)
must be a one-way door: once validators stake, it cannot be re-entered.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.config import VALIDATOR_MIN_STAKE, MIN_TOTAL_STAKE
from tests import register_entity_for_test


class TestBootstrapMode(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key")
        self.bob = Entity.create(b"bob-private-key")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.consensus = ProofOfStake()

    def test_bootstrap_permissive_initially(self):
        """With no validators, attestation validation is permissive."""
        self.assertEqual(self.consensus.validator_count, 0)
        self.assertTrue(self.consensus.is_bootstrap_mode)

    def test_bootstrap_ends_after_staking(self):
        """Once validators stake, bootstrap mode is permanently off."""
        self.consensus.register_validator(self.alice.entity_id, VALIDATOR_MIN_STAKE)
        self.assertFalse(self.consensus.is_bootstrap_mode)

    def test_bootstrap_cannot_reenter(self):
        """Removing all validators does NOT re-enable bootstrap mode."""
        self.consensus.register_validator(self.alice.entity_id, VALIDATOR_MIN_STAKE)
        self.assertFalse(self.consensus.is_bootstrap_mode)

        # Remove all validators
        self.consensus.remove_validator(self.alice.entity_id)
        self.assertEqual(self.consensus.validator_count, 0)

        # Bootstrap mode should still be OFF
        self.assertFalse(self.consensus.is_bootstrap_mode)

    def test_unstake_blocked_below_minimum(self):
        """Cannot unstake if it would drop total stake below MIN_TOTAL_STAKE."""
        supply = self.chain.supply
        # Stake enough to be above minimum
        supply.stake(self.alice.entity_id, 2000)
        self.consensus.register_validator(self.alice.entity_id, 2000)
        self.consensus._bootstrap_ended = True

        # Try to unstake most of it — should be blocked if below min
        # (depends on MIN_TOTAL_STAKE config value)
        total_after = 2000 - 1500  # 500 remaining
        if total_after < MIN_TOTAL_STAKE:
            result = supply.unstake(
                self.alice.entity_id, 1500,
                current_block=1,
                total_staked_after_check=total_after,
                min_total_stake=MIN_TOTAL_STAKE,
                bootstrap_ended=True,
            )
            self.assertFalse(result)

    def test_min_total_stake_config(self):
        """MIN_TOTAL_STAKE is defined and reasonable."""
        self.assertGreater(MIN_TOTAL_STAKE, 0)
        self.assertGreaterEqual(MIN_TOTAL_STAKE, VALIDATOR_MIN_STAKE)


if __name__ == "__main__":
    unittest.main()
