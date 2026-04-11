"""Tests for graduated minimum stake.

Minimum stake requirement starts low and increases with block height,
making early network participation accessible while hardening sybil
resistance as the network matures.
"""

import unittest

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

        alice = Entity.create(b"alice-grad-test".ljust(32, b"\x00"))
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


if __name__ == "__main__":
    unittest.main()
