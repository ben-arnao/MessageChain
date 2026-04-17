"""Tests for single-seed bootstrap and flat 100-token minimum stake.

Change 1: build_launch_allocation requires exactly 1 seed (not 3).
Change 2: Flat VALIDATOR_MIN_STAKE = 100 at all block heights (no tiers).
"""

import unittest

from messagechain.config import VALIDATOR_MIN_STAKE
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.bootstrap import (
    build_launch_allocation,
    RECOMMENDED_STAKE_PER_SEED,
    RECOMMENDED_GENESIS_PER_SEED,
    RECOMMENDED_FEE_BUFFER,
)


class TestSingleSeedAllocation(unittest.TestCase):
    """build_launch_allocation requires exactly 1 seed entity."""

    def test_one_seed_succeeds(self):
        """Exactly 1 seed is the required shape."""
        eid = b"\x01" * 32
        allocation = build_launch_allocation([eid])
        self.assertIn(eid, allocation)

    def test_three_seeds_raises(self):
        """3 seeds is now rejected — the old shape."""
        eids = [bytes([i]) * 32 for i in range(1, 4)]
        with self.assertRaises(ValueError):
            build_launch_allocation(eids)

    def test_two_seeds_raises(self):
        eids = [bytes([i]) * 32 for i in range(1, 3)]
        with self.assertRaises(ValueError):
            build_launch_allocation(eids)

    def test_recommended_stake_is_99m(self):
        """Single seed stakes 99M instead of 3 x 33M."""
        self.assertEqual(RECOMMENDED_STAKE_PER_SEED, 99_000_000)

    def test_recommended_genesis_includes_fee_buffer(self):
        """Genesis allocation = stake + fee buffer.

        The fee buffer sizing lives in bootstrap.py and must cover a few
        surcharge-bearing ops now that NEW_ACCOUNT_FEE applies to
        brand-new payout-address sweeps.  Assert only the invariant
        (genesis == stake + buffer) here so the numeric value can move
        without invalidating this test.
        """
        self.assertEqual(
            RECOMMENDED_GENESIS_PER_SEED,
            RECOMMENDED_STAKE_PER_SEED + RECOMMENDED_FEE_BUFFER,
        )


class TestFlatMinStake(unittest.TestCase):
    """Minimum stake is flat 100 tokens at all block heights."""

    def test_min_stake_constant_is_100(self):
        self.assertEqual(VALIDATOR_MIN_STAKE, 100)

    def test_no_graduated_stake_tiers(self):
        """GRADUATED_STAKE_TIERS should no longer exist in config."""
        import messagechain.config as cfg
        self.assertFalse(hasattr(cfg, 'GRADUATED_STAKE_TIERS'),
                         "GRADUATED_STAKE_TIERS should be removed")

    def test_register_below_100_fails_at_height_0(self):
        """Even at block height 0, staking < 100 fails."""
        pos = ProofOfStake()
        self.assertFalse(pos.register_validator(b"a" * 32, 99, block_height=0))

    def test_register_at_100_succeeds_at_height_0(self):
        """100 tokens is enough from block 0."""
        pos = ProofOfStake()
        self.assertTrue(pos.register_validator(b"a" * 32, 100, block_height=0))

    def test_register_below_100_fails_at_any_height(self):
        """Flat stake means the same minimum at all heights."""
        pos = ProofOfStake()
        for height in [0, 1, 49_999, 50_000, 199_999, 200_000, 1_000_000]:
            self.assertFalse(
                pos.register_validator(bytes([height % 256]) * 32, 99, block_height=height),
                f"Should reject 99 tokens at height {height}",
            )

    def test_no_graduated_min_stake_function(self):
        """graduated_min_stake should no longer be importable from pos."""
        from messagechain.consensus import pos
        self.assertFalse(hasattr(pos, 'graduated_min_stake'),
                         "graduated_min_stake function should be removed")


if __name__ == "__main__":
    unittest.main()
