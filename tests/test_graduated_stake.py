"""Tests for flat minimum stake.

Minimum stake is 100 tokens at all block heights — no graduated tiers.
"""

import unittest

from messagechain.consensus.pos import ProofOfStake
from messagechain.config import VALIDATOR_MIN_STAKE


class TestFlatMinStake(unittest.TestCase):
    """Minimum stake is 100 at every block height."""

    def test_min_stake_is_100(self):
        self.assertEqual(VALIDATOR_MIN_STAKE, 100)

    def test_register_validator_rejects_below_100(self):
        """At any block height, staking < 100 tokens is rejected."""
        pos = ProofOfStake()
        self.assertFalse(pos.register_validator(b"a" * 32, 99, block_height=0))
        self.assertFalse(pos.register_validator(b"b" * 32, 99, block_height=50_000))
        self.assertFalse(pos.register_validator(b"c" * 32, 99, block_height=200_000))

    def test_register_validator_accepts_100(self):
        """100 tokens is enough from block 0 onward."""
        pos = ProofOfStake()
        self.assertTrue(pos.register_validator(b"a" * 32, 100, block_height=0))
        self.assertTrue(pos.register_validator(b"b" * 32, 100, block_height=200_000))

    def test_sync_consensus_respects_flat_minimum(self):
        """sync_consensus_stakes uses the flat 100-token minimum."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"alice-grad-test".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)

        # Give alice a small stake (5 tokens) in the supply tracker
        chain.supply.staked[alice.entity_id] = 5

        # At any block height, 5 tokens should NOT qualify (min is 100)
        pos = ProofOfStake()
        chain.sync_consensus_stakes(pos, block_height=0)
        self.assertNotIn(alice.entity_id, pos.stakes)

        # 100 tokens should qualify
        chain.supply.staked[alice.entity_id] = 100
        pos2 = ProofOfStake()
        chain.sync_consensus_stakes(pos2, block_height=0)
        self.assertIn(alice.entity_id, pos2.stakes)


if __name__ == "__main__":
    unittest.main()
