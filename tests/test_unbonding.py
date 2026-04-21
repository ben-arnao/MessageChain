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
from messagechain.config import (
    UNBONDING_PERIOD,
    UNBONDING_PERIOD_EXTENSION_HEIGHT,
    VALIDATOR_MIN_STAKE,
    VALIDATOR_MIN_STAKE_POST_RAISE,
)

# Pick a synthetic block height safely past the unbonding-period
# extension fork so ``supply.unstake(current_block=...)`` uses the
# post-extension period and the release_block arithmetic matches the
# module-level ``UNBONDING_PERIOD`` imported above.  Pre-activation
# unstakes release at the legacy 1008-block maturity regardless of
# what ``UNBONDING_PERIOD`` evaluates to — see
# ``tests/test_unbonding_evidence_invariant.py`` for that path.
_POST_FORK = UNBONDING_PERIOD_EXTENSION_HEIGHT + 10
# After the MIN_STAKE_RAISE hard fork, partial unstakes must leave
# the validator at 0 or >= VALIDATOR_MIN_STAKE_POST_RAISE.  Scale
# the test amounts up so the partial-unstake path exercised below
# remains valid (stake 50_000, unstake 20_000 leaves 30_000 — well
# above the 10_000 post-raise floor).  The unbonding-period mechanic
# under test is orthogonal to the min-stake floor; we size amounts
# to keep both constraints satisfied.
_STAKE = VALIDATOR_MIN_STAKE_POST_RAISE * 5   # 50_000
_UNSTAKE_PARTIAL = VALIDATOR_MIN_STAKE_POST_RAISE * 2  # 20_000
_BAL = 100_000
from tests import register_entity_for_test


class TestUnbondingPeriod(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = _BAL
        self.chain.supply.balances[self.bob.entity_id] = _BAL
        self.consensus = ProofOfStake()

    def test_unstake_goes_to_pending(self):
        """Unstaking should not return tokens immediately."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, _STAKE)
        self.assertEqual(supply.get_staked(self.alice.entity_id), _STAKE)

        result = supply.unstake(self.alice.entity_id, _UNSTAKE_PARTIAL, current_block=_POST_FORK)
        self.assertTrue(result)
        # Staked amount decreases
        self.assertEqual(supply.get_staked(self.alice.entity_id), _STAKE - _UNSTAKE_PARTIAL)
        # But balance does NOT increase yet
        self.assertEqual(supply.get_balance(self.alice.entity_id), _BAL - _STAKE)
        # Tokens are in pending
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), _UNSTAKE_PARTIAL)

    def test_pending_unstake_releases_after_period(self):
        """Pending tokens become spendable after UNBONDING_PERIOD blocks."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, _STAKE)
        supply.unstake(self.alice.entity_id, _UNSTAKE_PARTIAL, current_block=_POST_FORK)

        # Not released yet at block _POST_FORK + UNBONDING_PERIOD - 1
        supply.process_pending_unstakes(_POST_FORK + UNBONDING_PERIOD - 1)
        self.assertEqual(supply.get_balance(self.alice.entity_id), _BAL - _STAKE)

        # Released at block _POST_FORK + UNBONDING_PERIOD
        supply.process_pending_unstakes(_POST_FORK + UNBONDING_PERIOD)
        self.assertEqual(
            supply.get_balance(self.alice.entity_id),
            _BAL - _STAKE + _UNSTAKE_PARTIAL,
        )
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), 0)

    def test_pending_unstake_slashable(self):
        """Pending unstakes can still be slashed."""
        supply = self.chain.supply
        supply.stake(self.alice.entity_id, _STAKE)
        # Full exit (_STAKE -> 0) is always permitted, unaffected by fork.
        supply.unstake(self.alice.entity_id, _STAKE, current_block=_POST_FORK)

        # Alice has 0 staked, _STAKE pending — slash should burn pending too
        slashed, reward = supply.slash_validator(self.alice.entity_id, self.bob.entity_id)
        self.assertGreater(slashed, 0)
        self.assertEqual(supply.get_pending_unstake(self.alice.entity_id), 0)

    def test_multiple_unstakes_tracked_separately(self):
        """Multiple unstake requests at different blocks release at different times."""
        supply = self.chain.supply
        # Stake 3x floor so two sequential partial unstakes of one-floor
        # each still leave the validator above-floor after the first.
        big_stake = VALIDATOR_MIN_STAKE_POST_RAISE * 6  # 60_000
        chunk = VALIDATOR_MIN_STAKE_POST_RAISE * 2      # 20_000
        supply.stake(self.alice.entity_id, big_stake)

        supply.unstake(self.alice.entity_id, chunk, current_block=_POST_FORK)
        supply.unstake(self.alice.entity_id, chunk, current_block=_POST_FORK + 10)

        # First batch releases at _POST_FORK + UNBONDING_PERIOD
        supply.process_pending_unstakes(_POST_FORK + UNBONDING_PERIOD)
        self.assertEqual(
            supply.get_balance(self.alice.entity_id),
            _BAL - big_stake + chunk,
        )

        # Second batch releases at _POST_FORK + 10 + UNBONDING_PERIOD
        supply.process_pending_unstakes(_POST_FORK + 10 + UNBONDING_PERIOD)
        self.assertEqual(
            supply.get_balance(self.alice.entity_id),
            _BAL - big_stake + 2 * chunk,
        )


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
