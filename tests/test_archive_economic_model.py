"""Economic validation of the archive-custody incentive.

Iteration 3d (Tier S #10): verify that the full-history-retention
incentive is actually load-bearing at plausible year-1, year-10,
year-50, and year-100 parameters.  The whole duty-withhold-pool
edifice from 3b-3c relies on two inequalities holding for a rational
validator contemplating whether to prune:

    (A) per-epoch withhold cost >> per-epoch storage savings from
        pruning (i.e., losing block rewards hurts more than saving
        disk).

    (B) archive-reward pool per-payout >> storage cost for a full-
        history non-validator archivist (so the open-bounty path has
        economic reason to exist beyond altruism).

This module encodes the model explicitly in code so every constant is
documented, every assumption is visible, and any future config tweak
that breaks the inequalities surfaces as a test failure.  The model
is deliberately conservative: numbers err toward making the incentive
look WEAKER than reality (higher storage cost, lower token value,
ignoring Moore's-law gains in $/GB) so if it passes here it's
genuinely strong.

These tests are NOT production validators — they're a running
sanity check.  A future governance proposal that retunes any of
ARCHIVE_REWARD, ARCHIVE_WITHHOLD_TIERS, ARCHIVE_BURN_REDIRECT_PCT,
or BLOCK_REWARD_FLOOR must keep these assertions passing or surface
a deliberate, documented design tradeoff.
"""

from __future__ import annotations

import math
import unittest

from messagechain.config import (
    ARCHIVE_BURN_REDIRECT_PCT,
    ARCHIVE_CHALLENGE_INTERVAL,
    ARCHIVE_PROOFS_PER_CHALLENGE,
    ARCHIVE_REWARD,
    ARCHIVE_WITHHOLD_TIERS,
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    HALVING_INTERVAL,
)


# ---------------------------------------------------------------------------
# Model parameters — deliberately conservative
# ---------------------------------------------------------------------------
# Block cadence: BLOCK_TIME_TARGET = 600s → ~52,560 blocks/year.
BLOCKS_PER_YEAR = 52_560

# Average on-chain block size.  Real blocks currently run ~4-20 KB;
# at maximum-full-block scale we'd see ~100 KB.  Using 100 KB is
# pessimistic (larger storage burden → higher cost to retain).
BYTES_PER_BLOCK_AVG = 100_000

# Storage cost per gigabyte per year.  $0.02/GB-yr is a home-server-
# overprovisioned rate (modern HDDs at ~$15/TB, 5-year amortization,
# power, redundancy).  Cloud archival ($0.001/GB-mo = $0.012/GB-yr) is
# cheaper, and historical storage cost halves every 18-24 months, so
# treating this as constant is the pessimistic path.
STORAGE_COST_DOLLARS_PER_GB_YEAR = 0.02

# Assumed token price.  Worst-case: $0.10/token at year 100.  Best-
# case would be $1+ indefinitely with fee-driven value capture.
# Using $0.10 throughout stresses the withhold inequality.
TOKEN_PRICE_USD = 0.10

# Validator set size.  20-100 is the realistic bootstrap-to-mature
# range.  Lower N = each validator proposes more blocks per year =
# bigger withhold pool → more-punishing.  Using N=100 is the worst
# case for the withhold inequality (each validator proposes fewer
# blocks, so their potential annual withhold is smaller).
VALIDATOR_COUNT_MATURE = 100

# Challenge epochs per year.
EPOCHS_PER_YEAR = BLOCKS_PER_YEAR // ARCHIVE_CHALLENGE_INTERVAL


# ---------------------------------------------------------------------------
# Model functions
# ---------------------------------------------------------------------------


def chain_bytes_at_year(year: int) -> int:
    """Total bytes stored on-chain at the end of year N.  Linear in
    block count (no Moore's-law-style cost-per-byte assumption)."""
    return year * BLOCKS_PER_YEAR * BYTES_PER_BLOCK_AVG


def annual_storage_cost_usd(year: int) -> float:
    """What a full-history archivist pays per year in storage at the
    END of year N (all N years of history retained)."""
    gb = chain_bytes_at_year(year) / (1024 ** 3)
    return gb * STORAGE_COST_DOLLARS_PER_GB_YEAR


def block_reward_at_year(year: int) -> int:
    """Halvings-adjusted block reward in tokens at year N's midpoint.
    Floors at BLOCK_REWARD_FLOOR."""
    block_height = year * BLOCKS_PER_YEAR
    halvings = block_height // HALVING_INTERVAL
    reward = max(BLOCK_REWARD >> halvings, BLOCK_REWARD_FLOOR)
    return reward


def annual_withhold_usd_full_tier(
    year: int, validator_count: int,
) -> float:
    """Per-validator annual withhold at 100% tier = they lose EVERY
    block reward they would have earned this year.  Uses the post-
    halving BLOCK_REWARD and assumes proposer-cap isn't the binding
    constraint (which is only true for mega-stakers — average case
    loses the full pro-rata share)."""
    reward_per_block = block_reward_at_year(year)
    blocks_per_validator_per_year = BLOCKS_PER_YEAR // validator_count
    tokens = reward_per_block * blocks_per_validator_per_year
    full_withhold_pct = ARCHIVE_WITHHOLD_TIERS[-1]  # 100
    withheld_tokens = tokens * full_withhold_pct // 100
    return withheld_tokens * TOKEN_PRICE_USD


def annual_archive_reward_usd_for_fcfs_winner(year: int) -> float:
    """A non-validator full-history archivist who wins 1 FCFS slot per
    epoch earns ARCHIVE_REWARD tokens per epoch × EPOCHS_PER_YEAR.
    This is the economic return to non-validator archivists — the
    'why hold if you're not staked' question.  NOT scaled by chain
    size in current code; this is the constant-reward reality."""
    tokens = ARCHIVE_REWARD * EPOCHS_PER_YEAR
    return tokens * TOKEN_PRICE_USD


# ---------------------------------------------------------------------------
# Inequality (A): withhold > storage savings at every horizon
# ---------------------------------------------------------------------------


class TestWithholdDominatesStorageSavings(unittest.TestCase):
    """A rational validator considering pruning compares:
        savings = annual_storage_cost (if they prune)
        losses  = annual_withhold (if they get caught and hit 100%)
    For the duty mechanism to actually deter pruning, losses must
    exceed savings by a meaningful margin at every chain age.
    """

    def _check(self, year: int, margin: float):
        savings = annual_storage_cost_usd(year)
        losses = annual_withhold_usd_full_tier(
            year, VALIDATOR_COUNT_MATURE,
        )
        self.assertGreater(
            losses, savings * margin,
            f"year {year}: withhold ${losses:.2f} must exceed "
            f"storage savings ${savings:.2f} by {margin}x; "
            f"got ratio {losses / max(savings, 0.001):.2f}x",
        )

    def test_year_1(self):
        """Bootstrap era: withhold must dominate by >100x."""
        self._check(year=1, margin=100)

    def test_year_10(self):
        """Mid-term: withhold must dominate by >10x."""
        self._check(year=10, margin=10)

    def test_year_50(self):
        """Long-term: withhold must dominate by >2x."""
        self._check(year=50, margin=2)

    def test_year_100(self):
        """1000-year-horizon headline: at year 100 under conservative
        assumptions, withhold must still exceed storage savings.  The
        margin can be narrow (>1x) but must exist.  This is the
        strictest test of whether the current parameters age well.
        """
        self._check(year=100, margin=1)


# ---------------------------------------------------------------------------
# Inequality (B): non-validator archive reward covers storage cost
# ---------------------------------------------------------------------------


class TestArchiveRewardCoversStorage(unittest.TestCase):
    """A non-validator archivist who wins 1 FCFS slot per epoch
    earns ARCHIVE_REWARD tokens/epoch.  If that's less than their
    annual storage cost, they have no economic reason to archive.
    """

    def _check(self, year: int, margin: float):
        earnings = annual_archive_reward_usd_for_fcfs_winner(year)
        cost = annual_storage_cost_usd(year)
        self.assertGreater(
            earnings, cost * margin,
            f"year {year}: FCFS-winner earnings ${earnings:.2f} must "
            f"exceed storage cost ${cost:.2f} by {margin}x; "
            f"got ratio {earnings / max(cost, 0.001):.2f}x",
        )

    def test_year_1(self):
        self._check(year=1, margin=100)

    def test_year_10(self):
        self._check(year=10, margin=10)

    def test_year_50(self):
        """At year 50 the fixed reward may start feeling tight
        against growing storage cost.  Require a small margin only.
        """
        self._check(year=50, margin=2)

    def test_year_100_flags_scaling_need(self):
        """At year 100 under the MOST CONSERVATIVE assumptions (no
        Moore's-law cost reduction, $0.10/token), a non-validator
        FCFS archivist's annual earnings should still beat storage
        cost by SOME margin.  If this test tightens close to 1.0x or
        fails, that's the signal to ship reward scaling (#1 on the
        tier list).
        """
        earnings = annual_archive_reward_usd_for_fcfs_winner(100)
        cost = annual_storage_cost_usd(100)
        ratio = earnings / max(cost, 0.001)
        self.assertGreater(
            ratio, 1.0,
            f"YEAR 100 ECONOMIC ALARM: FCFS earnings ${earnings:.2f} "
            f"only {ratio:.2f}x storage cost ${cost:.2f}.  Reward "
            f"scaling (iter 3d-ii) needed to prevent archivist "
            f"dropout at long horizons.",
        )


# ---------------------------------------------------------------------------
# Pool funding sanity
# ---------------------------------------------------------------------------


class TestPoolCanFundPayouts(unittest.TestCase):
    """The pool is funded by ARCHIVE_BURN_REDIRECT_PCT% of fee-burn.
    Per-epoch payouts are capped at ARCHIVE_PROOFS_PER_CHALLENGE ×
    ARCHIVE_REWARD.  For the pool to not run dry during normal
    activity, fee-burn per epoch × redirect-pct must cover at least
    a fraction of the per-epoch cap.
    """

    def test_redirect_pct_is_nonzero(self):
        """If the redirect was accidentally zeroed the pool would
        never fund from burn — catch that regression."""
        self.assertGreater(ARCHIVE_BURN_REDIRECT_PCT, 0)

    def test_per_epoch_payout_cap_is_meaningful(self):
        """The max payout per epoch should be enough that a single
        validator being paid for a single epoch feels meaningful
        relative to block rewards."""
        per_epoch_cap_tokens = (
            ARCHIVE_PROOFS_PER_CHALLENGE * ARCHIVE_REWARD
        )
        # Compare against block reward at floor × interval (what
        # validators earn just from proposing during one epoch).
        block_reward_per_epoch = (
            BLOCK_REWARD_FLOOR * ARCHIVE_CHALLENGE_INTERVAL
        )
        self.assertGreater(
            per_epoch_cap_tokens, block_reward_per_epoch,
            f"archive pool per-epoch cap ({per_epoch_cap_tokens} tokens) "
            f"is smaller than one epoch's block-reward mint "
            f"({block_reward_per_epoch}).  Rewards may feel "
            f"insignificant to archivists.",
        )


# ---------------------------------------------------------------------------
# Year-horizon sanity
# ---------------------------------------------------------------------------


class TestModelSanity(unittest.TestCase):
    """Meta-tests that catch ridiculous numbers — if BLOCKS_PER_YEAR
    or BYTES_PER_BLOCK_AVG drift wildly, the whole model breaks
    silently.  These assert the pieces are plausible."""

    def test_year_1_chain_is_gigabytes_not_petabytes(self):
        gb = chain_bytes_at_year(1) / (1024 ** 3)
        self.assertGreater(gb, 0.5)     # at least 0.5 GB in year 1
        self.assertLess(gb, 50)          # less than 50 GB in year 1

    def test_year_100_chain_is_bounded(self):
        gb = chain_bytes_at_year(100) / (1024 ** 3)
        # Year 100 should be hundreds of GB, not exabytes.  If this
        # fires, BYTES_PER_BLOCK_AVG or BLOCKS_PER_YEAR drifted.
        self.assertLess(gb, 100_000)

    def test_block_reward_floors_eventually(self):
        """BLOCK_REWARD halves until it hits the floor.  Year 100
        should definitely be at floor."""
        self.assertEqual(block_reward_at_year(100), BLOCK_REWARD_FLOOR)


if __name__ == "__main__":
    unittest.main()
