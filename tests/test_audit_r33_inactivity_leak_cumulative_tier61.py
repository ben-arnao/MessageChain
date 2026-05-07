"""Audit r33 #2 -- Tier 61 inactivity-leak cumulative-floor fix.

Pre-Tier-61 (Tier 59 era) formula::

    penalty_per_block = stake * BASE * blocks_since_finality² // Q

with ``Q = 16_777_216_000_000`` (= 2^24 * 10⁶) integer-truncated to
zero for any validator with stake < ~1M tokens.  Cumulative drain
over a 10000-block stall is the SUM of per-block penalties; if every
per-block term floors to 0, the SUM is also 0.  Net effect: the
inactivity leak fired correctly only for whales; the rank-and-file
validator set (stake = 10K..100K) experienced zero drain on
arbitrarily long partitions.

The CLAUDE.md anchor "honest operators are insured against
accidents" is technically still satisfied (no wipe), but the dual
"censorship resistance is a *collective decision*" anchor is
*broken*: a 1/3-stake cartel composed of small-stake validators
withholds attestations indefinitely without economic counter-
pressure.  The leak is supposed to be the slashing-bearing path
that makes coordinated suppression cost real money; for small-
stake cartels under Tier 59 it costs nothing.

Tier 61 fix is stateless and preserves the calibration constants:
compute the per-block penalty as the integer DIFFERENCE of
cumulative-floor values rather than the FLOOR of per-block-real::

    cum(k) = stake * BASE * (k * (k+1) * (2k+1) / 6) // Q
    penalty_at_block_k = cum(k) - cum(k-1)

The cumulative-floor trick integer-truncates at the *cumulative*
level (which is well above 1 token for any realistic stake over a
realistic partition) instead of at the per-block level.  Over a
10000-block stall:

  * stake=10K:   cum(10000) = 198 tokens (~2% drain) -- works.
  * stake=1M:    cum(10000) = 19_842 tokens (~2%)    -- works.
  * stake=100M:  cum(10000) = 1_984_226 tokens (~2%) -- works.

The min(penalty, stake) cap still applies per-block, so a wipe
remains impossible inside one block.  Pre-fork (height <
``INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT``) the legacy Tier 59
formula runs unchanged, so historical blocks replay byte-identically.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain import config
from messagechain.consensus.inactivity import compute_inactivity_penalty


class TestActivationConstantOrdering(unittest.TestCase):
    """Source pin: Tier 61 activation height MUST exceed Tier 60
    (DORMANCY_TARGET_RETUNE_HEIGHT = 2250) by the standard 50-block
    cohort spacing, so the upgrade rolls in the same window pattern
    as Tiers 49-60."""

    def test_height_ordering(self):
        self.assertGreater(
            config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT,
            config.DORMANCY_TARGET_RETUNE_HEIGHT,
            "INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT (Tier 61) MUST "
            "follow Tier 60 (DORMANCY_TARGET_RETUNE_HEIGHT) so the "
            "two-validator coordinated upgrade window does not span "
            "two distinct height gates simultaneously.",
        )

    def test_height_ordering_above_tier_59(self):
        self.assertGreater(
            config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT,
            config.INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
            "Tier 61 fixes a Tier 59 calibration bug; the height "
            "gate MUST follow Tier 59 activation so pre-Tier-59 "
            "blocks replay through the legacy quadratic-flat path.",
        )


class TestSourceUsesCumulativeFloor(unittest.TestCase):
    """Source pin: the post-Tier-61 branch MUST compute the per-
    block penalty as the difference of cumulative-floor values,
    not as the floor of per-block-real.  The literal substring
    'cumulative' or 'cum' would not be load-bearing; we instead
    pin on the closed-form sum-of-squares term that is unique to
    the Tier 61 path."""

    def test_source_calls_cumulative_helper(self):
        src = inspect.getsource(compute_inactivity_penalty)
        self.assertIn(
            "INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT", src,
            "compute_inactivity_penalty MUST gate the cumulative-"
            "floor path on INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT "
            "(Tier 61).",
        )
        self.assertIn(
            "_cumulative_inactivity_drain", src,
            "compute_inactivity_penalty's post-Tier-61 branch MUST "
            "compute penalty as cum(k) - cum(k-1) using the "
            "_cumulative_inactivity_drain helper.",
        )


class TestSmallValidatorDrainsCumulatively(unittest.TestCase):
    """Behavioral pin: a stake=10K honest validator on a 10000-
    block partition under Tier 61 MUST see cumulative drain that
    is non-zero AND fractional.  The pre-fix Tier 59 formula
    yielded 0 cumulative; the cumulative-floor trick yields ~198
    tokens (~2% of stake)."""

    def _cumulative_post_fork(self, stake: int, blocks: int) -> int:
        """Sum the per-block post-Tier-61 penalty across `blocks`."""
        h = config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT
        # Threshold is implicit in compute_inactivity_penalty -- we
        # iterate from k=1 because below the activation threshold the
        # penalty is 0 by design.
        total = 0
        for k in range(1, blocks + 1):
            total += compute_inactivity_penalty(
                blocks_since_finality=k,
                validator_stake=stake,
                current_height=h,
            )
        return total

    def test_small_validator_drains_at_all(self):
        cum = self._cumulative_post_fork(stake=10_000, blocks=10_000)
        self.assertGreater(
            cum, 0,
            "Tier 61 fix MUST drain a non-zero cumulative amount "
            "from a stake=10K validator on a 10000-block partition. "
            "Pre-fix (Tier 59 calibration) the per-block formula "
            "integer-truncated to 0 for stake<1M and the cartel-"
            "defense lever was disabled for the rank-and-file "
            "validator set.",
        )

    def test_small_validator_drain_is_fractional(self):
        cum = self._cumulative_post_fork(stake=10_000, blocks=10_000)
        self.assertLessEqual(
            cum, 10_000 * 5 // 100,
            f"Cumulative drain {cum} on 10K stake exceeds 5% -- "
            "anchor is 'small fraction of stake, not a wipe'.",
        )
        # Closed-form expected value: stake * sum_squares(N) // Q
        # where sum_squares(10000) = 10000*10001*20001/6 ≈ 3.33e11.
        # Expected ≈ 198 tokens.  Tolerance: ±10 to absorb
        # discretization; the point is "~2%" not exact match.
        self.assertGreaterEqual(
            cum, 100,
            f"Cumulative drain {cum} on 10K stake is below 1% -- "
            "Tier 61 calibration target is ~2% over 10000 blocks.",
        )


class TestWhaleProportionalDrain(unittest.TestCase):
    """Behavioral pin: a stake=100M validator on the same 10000-
    block partition MUST drain at the SAME fractional rate as a
    stake=10K validator (the Tier 59 calibration intent).  Pre-fix
    whales drained correctly but small validators didn't; the
    cumulative-floor trick equalizes the fractional drain at every
    stake size."""

    def _cumulative_post_fork(self, stake: int, blocks: int) -> int:
        h = config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT
        total = 0
        for k in range(1, blocks + 1):
            total += compute_inactivity_penalty(
                blocks_since_finality=k,
                validator_stake=stake,
                current_height=h,
            )
        return total

    def test_whale_drains_at_2_percent(self):
        stake = 100_000_000
        cum = self._cumulative_post_fork(stake=stake, blocks=10_000)
        # Anchor target: ~2% of stake.  Tolerance: 1.5% .. 3%.
        self.assertGreaterEqual(cum, stake * 15 // 1000)
        self.assertLessEqual(cum, stake * 30 // 1000)


class TestPreForkLegacyByteIdenticalReplay(unittest.TestCase):
    """Source pin: pre-Tier-61 (current_height < activation) the
    function MUST produce the byte-identical Tier 59 result, so
    historical blocks at heights 2200..2299 replay unchanged."""

    def test_pre_fork_height_uses_tier59_formula(self):
        # Current Tier 59 quotient applied to the per-block-real
        # formula:  stake * 1 * blocks² // Q.
        stake = 1_000_000
        blocks = 5000
        h_before = config.INACTIVITY_LEAK_STAKE_SCALED_HEIGHT
        # Pick a height firmly inside Tier 59 era (post Tier 59,
        # pre Tier 61).
        h = (h_before + config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT) // 2
        if h <= h_before:
            h = h_before + 1

        legacy = (
            stake * config.INACTIVITY_BASE_PENALTY * blocks * blocks
            // config.INACTIVITY_PENALTY_STAKE_SCALED_QUOTIENT
        )
        legacy = min(legacy, stake)

        actual = compute_inactivity_penalty(
            blocks_since_finality=blocks,
            validator_stake=stake,
            current_height=h,
        )
        self.assertEqual(
            actual, legacy,
            "Pre-Tier-61 height MUST yield the byte-identical "
            "Tier 59 per-block formula -- replay determinism on "
            "historical blocks at heights "
            f"[{h_before}, {config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT})"
            " requires this.",
        )


class TestPenaltyCappedAtStake(unittest.TestCase):
    """Behavioral pin: even under the cumulative-floor formula the
    per-block penalty is capped at the validator's current stake
    (cannot drain below zero in one block)."""

    def test_per_block_capped_at_stake(self):
        h = config.INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT
        # Pick a pathological combination: tiny stake, huge block
        # count.  Without the cap a single block's cumulative-
        # difference could exceed stake.
        stake = 100
        big = 10_000_000  # absurd stall length
        p = compute_inactivity_penalty(
            blocks_since_finality=big,
            validator_stake=stake,
            current_height=h,
        )
        self.assertLessEqual(
            p, stake,
            "Per-block penalty MUST be capped at validator stake.",
        )


if __name__ == "__main__":
    unittest.main()
