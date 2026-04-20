"""RECOMMENDED_FEE_BUFFER must cover NEW_ACCOUNT_FEE surcharges.

With NEW_ACCOUNT_FEE in place, a bootstrap seed's fee buffer must be
large enough to sweep to a brand-new payout address at least once
(MIN_FEE + NEW_ACCOUNT_FEE), and realistically several times to cover
initial ops (authority-key tx, first few transfers to pre-announce a
payout path, etc.).
"""

import unittest

from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE
from messagechain.core.bootstrap import (
    RECOMMENDED_FEE_BUFFER,
    RECOMMENDED_STAKE_PER_SEED,
    RECOMMENDED_GENESIS_PER_SEED,
)


class TestBootstrapFeeBuffer(unittest.TestCase):
    def test_buffer_covers_single_new_account_transfer(self):
        """A single sweep to a brand-new address costs MIN_FEE +
        NEW_ACCOUNT_FEE = 1100.  Buffer must cover at least this."""
        self.assertGreaterEqual(
            RECOMMENDED_FEE_BUFFER, MIN_FEE + NEW_ACCOUNT_FEE,
        )

    def test_buffer_covers_several_surcharge_ops(self):
        """Buffer must realistically cover a few surcharge-bearing ops
        so a seed can make the authority-key tx AND fund a payout
        address AND re-try without going broke."""
        self.assertGreaterEqual(
            RECOMMENDED_FEE_BUFFER,
            (MIN_FEE + NEW_ACCOUNT_FEE) * 3,
        )

    def test_genesis_per_seed_covers_stake_plus_buffer(self):
        """The genesis allocation for a seed must cover stake + buffer."""
        self.assertGreaterEqual(
            RECOMMENDED_GENESIS_PER_SEED,
            RECOMMENDED_STAKE_PER_SEED + RECOMMENDED_FEE_BUFFER,
        )


if __name__ == "__main__":
    unittest.main()
