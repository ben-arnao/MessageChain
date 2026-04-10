"""Tests for graduated minimum stake and sqrt stake weighting.

Graduated stake: minimum stake requirement starts low and increases
with block height, making early network participation accessible
while hardening security as the network matures.

Sqrt stake weighting: proposer selection uses sqrt(stake) instead of
raw stake, giving diminishing returns to large stakers and preventing
plutocratic concentration of block production.
"""

import math
import unittest
from collections import Counter

from messagechain.config import HASH_ALGO
from messagechain.consensus.pos import ProofOfStake, graduated_min_stake


class TestGraduatedMinStake(unittest.TestCase):
    """Minimum stake scales with block height."""

    def test_early_blocks_low_minimum(self):
        """Blocks 0–50,000 require only 1 token to stake."""
        self.assertEqual(graduated_min_stake(0), 1)
        self.assertEqual(graduated_min_stake(1), 1)
        self.assertEqual(graduated_min_stake(25_000), 1)
        self.assertEqual(graduated_min_stake(49_999), 1)

    def test_mid_blocks_medium_minimum(self):
        """Blocks 50,000–199,999 require 10 tokens."""
        self.assertEqual(graduated_min_stake(50_000), 10)
        self.assertEqual(graduated_min_stake(100_000), 10)
        self.assertEqual(graduated_min_stake(199_999), 10)

    def test_late_blocks_full_minimum(self):
        """Blocks 200,000+ require 100 tokens."""
        self.assertEqual(graduated_min_stake(200_000), 100)
        self.assertEqual(graduated_min_stake(1_000_000), 100)

    def test_register_validator_respects_block_height(self):
        """register_validator uses graduated minimum at given block height."""
        pos = ProofOfStake()

        # At block 0, 1 token is enough
        self.assertTrue(pos.register_validator(b"a" * 32, 1, block_height=0))

        # At block 200,000, 1 token is NOT enough
        pos2 = ProofOfStake()
        self.assertFalse(pos2.register_validator(b"b" * 32, 1, block_height=200_000))

        # At block 200,000, 100 tokens IS enough
        self.assertTrue(pos2.register_validator(b"b" * 32, 100, block_height=200_000))

    def test_sync_consensus_respects_block_height(self):
        """sync_consensus_stakes should use graduated minimum."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        from tests import register_entity_for_test

        alice = Entity.create(b"alice-grad-test")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        # Give alice a small stake (5 tokens) in the supply tracker
        chain.supply.staked[alice.entity_id] = 5

        # At early block height, 5 tokens should qualify
        pos = ProofOfStake()
        chain.sync_consensus_stakes(pos, block_height=0)
        self.assertIn(alice.entity_id, pos.stakes)

        # At late block height, 5 tokens should NOT qualify
        pos2 = ProofOfStake()
        chain.sync_consensus_stakes(pos2, block_height=200_000)
        self.assertNotIn(alice.entity_id, pos2.stakes)


class TestSqrtStakeWeighting(unittest.TestCase):
    """Proposer selection uses sqrt(stake) for diminishing returns."""

    def test_sqrt_weighting_reduces_whale_dominance(self):
        """A validator with 100x more stake should NOT get 100x more blocks."""
        pos = ProofOfStake()
        small = b"s" * 32
        whale = b"w" * 32
        pos.register_validator(small, 100, block_height=0)
        pos.register_validator(whale, 10_000, block_height=0)

        # With raw stake, whale would get ~99% of selections.
        # With sqrt, whale has sqrt(10000)/sqrt(100) = 100/10 = 10x weight,
        # so whale should get ~10/11 ≈ 91% — still dominant but less extreme.
        # Run many selections and check the ratio.
        counts = Counter()
        for i in range(10_000):
            seed = i.to_bytes(32, "big")
            proposer = pos.select_proposer(seed)
            counts[proposer] += 1

        whale_ratio = counts[whale] / 10_000
        small_ratio = counts[small] / 10_000

        # Whale should get roughly 10x more than small (sqrt ratio)
        # Allow wide tolerance for randomness: whale 80-97%, small 3-20%
        self.assertGreater(small_ratio, 0.03, "Small staker should get >3% of blocks")
        self.assertLess(small_ratio, 0.20, "Small staker should get <20% of blocks")
        self.assertGreater(whale_ratio, 0.80, "Whale should get >80% of blocks")

    def test_equal_stakes_equal_chance(self):
        """Validators with equal stake should have roughly equal selection."""
        pos = ProofOfStake()
        a = b"a" * 32
        b_id = b"b" * 32
        pos.register_validator(a, 100, block_height=0)
        pos.register_validator(b_id, 100, block_height=0)

        counts = Counter()
        for i in range(10_000):
            seed = i.to_bytes(32, "big")
            proposer = pos.select_proposer(seed)
            counts[proposer] += 1

        # Each should get roughly 50% (allow 40-60% for randomness)
        a_ratio = counts[a] / 10_000
        self.assertGreater(a_ratio, 0.40)
        self.assertLess(a_ratio, 0.60)

    def test_sqrt_total_stake(self):
        """total_effective_stake should be sum of sqrt(stake) values."""
        pos = ProofOfStake()
        pos.register_validator(b"a" * 32, 100, block_height=0)
        pos.register_validator(b"b" * 32, 400, block_height=0)

        # sqrt(100) + sqrt(400) = 10 + 20 = 30
        self.assertEqual(pos.total_effective_stake, 30)


if __name__ == "__main__":
    unittest.main()
