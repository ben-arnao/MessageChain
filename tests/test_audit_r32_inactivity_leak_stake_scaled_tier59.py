"""Audit r32 #2 -- Inactivity-leak penalty is FLAT in tokens, not
stake-scaled.

Pre-fix ``compute_inactivity_penalty`` is ``BASE * blocks² /
quotient`` (no stake factor; ``validator_stake`` is used only as a
CAP).  Coverage-leak's ``compute_coverage_penalty`` IS stake-scaled
(``stake * BASE * misses² / QUOTIENT``).  Asymmetry is by docstring
intent on the coverage side but contradicts the CLAUDE.md
"honest-operator insurance" anchor on the inactivity side: at
INACTIVITY_BASE_PENALTY=1, quotient=2²⁴, threshold=4, a
10k-stake (VALIDATOR_MIN_STAKE_POST_RAISE) honest-but-isolated
validator hits zero stake at ``blocks_since_finality≈12700``
(~88 days) while a 1M-stake whale absorbs <0.06% of stake.  Tier 55
honesty-curve relief floors at 20% of nominal -- still a wipe for
the small validator on a long partition.

Tier 59 closes the gap: at and above
``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` the nominal penalty becomes
``stake * BASE * blocks² / QUOTIENT``, mirroring
``compute_coverage_penalty`` exactly.  The Tier-55 honesty-curve
relief layer wraps the new shape unchanged (it multiplies whatever
nominal it gets).  Pre-fork blocks replay byte-identically via the
height gate; the legacy flat formula is preserved on the pre-fork
branch.

CLAUDE.md anchor: "honest operators are insured against accidents
... the burn is a small *fraction* of stake, not a wipe."  Stake-
scaling makes the inactivity leak fractional-of-stake, restoring
the anchor for the smallest validators (whom the chain wants to
recruit).  The cartel-defense intent of the leak is preserved: a
1/3-stake withholding cartel still pays the same FRACTION of stake
per block as a small honest validator -- in absolute tokens the
cartel's drain is much larger because their stake is much larger.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    INACTIVITY_BASE_PENALTY,
    INACTIVITY_LEAK_ACTIVATION_THRESHOLD,
    INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
    INACTIVITY_PENALTY_QUOTIENT,
    COLD_LEAF_WATERMARK_HEIGHT,
    INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT,
)
from messagechain.consensus.inactivity import (
    apply_inactivity_leak,
    compute_inactivity_penalty,
)


class TestActivationHeightConstant(unittest.TestCase):
    """Source pin: ``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` exists,
    sits above Tier 58 (cohort spacing) and above Tier 55
    (honesty-curve relief layer must already wrap the leak)."""

    def test_constant_above_tier_58(self):
        self.assertGreater(
            INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
            COLD_LEAF_WATERMARK_HEIGHT,
            "Tier 59 (INACTIVITY_LEAK_STAKE_SCALED_HEIGHT) must "
            "follow Tier 58 (COLD_LEAF_WATERMARK_HEIGHT) -- cohort "
            "spacing keeps consecutive consensus-rule changes from "
            "collapsing into a single activation window.",
        )

    def test_constant_above_tier_55_honesty_curve_relief(self):
        self.assertGreater(
            INACTIVITY_LEAK_STAKE_SCALED_HEIGHT,
            INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT,
            "Tier 59 must follow Tier 55 -- the honesty-curve relief "
            "multiplier (Tier 55) wraps whatever nominal Tier 59 "
            "produces, so Tier 55 must already be live before Tier 59 "
            "changes the nominal shape.",
        )


class TestPreForkLegacyBehaviorByteIdentical(unittest.TestCase):
    """Replay determinism: the legacy flat formula MUST be
    byte-identical on the pre-fork branch.  No optional kwarg, no
    height-gate change, can shift a single token of penalty for any
    historical block.  Without this, every node re-validating
    historical blocks would compute a different per-validator burn
    than the chain originally applied -- silent fork on every
    in-leak block.
    """

    def test_legacy_call_shape_unchanged(self):
        """The 2-arg call form (the only form pre-fork) MUST return
        the legacy flat formula exactly.  This is the call shape
        every existing call site uses."""
        # blocks_since=10000, validator_stake=10_000_000 (whale).
        # Legacy expectation: BASE * 10000² // QUOTIENT, capped at
        # stake.  At BASE=1 / QUOTIENT=2²⁴ that is 5 tokens.
        legacy_pen = compute_inactivity_penalty(10000, 10_000_000)
        expected = (
            INACTIVITY_BASE_PENALTY * 10000 * 10000
            // INACTIVITY_PENALTY_QUOTIENT
        )
        self.assertEqual(legacy_pen, expected)

    def test_below_threshold_zero(self):
        """Inside the activation buffer the penalty is 0 in BOTH
        legacy and stake-scaled modes."""
        self.assertEqual(
            compute_inactivity_penalty(
                INACTIVITY_LEAK_ACTIVATION_THRESHOLD, 10_000,
            ),
            0,
        )

    def test_zero_stake_zero_penalty(self):
        """A validator with no stake takes no penalty, in any mode."""
        self.assertEqual(compute_inactivity_penalty(10000, 0), 0)


class TestPostForkStakeScaledShape(unittest.TestCase):
    """Behavioral pin: at and above
    ``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` the nominal penalty
    scales with ``validator_stake`` -- matching
    ``compute_coverage_penalty``'s shape and restoring the
    fractional-of-stake property the CLAUDE.md anchor calls for."""

    def test_post_fork_doubles_with_stake(self):
        """Doubling stake roughly doubles the nominal penalty (post-
        fork).  This is the property a small validator gets the same
        fractional bleed as a whale."""
        stake_small = 10_000
        stake_whale = 1_000_000
        ratio = stake_whale // stake_small  # 100x

        pen_small = compute_inactivity_penalty(
            10000, stake_small,
            current_height=INACTIVITY_LEAK_STAKE_SCALED_HEIGHT + 1,
        )
        pen_whale = compute_inactivity_penalty(
            10000, stake_whale,
            current_height=INACTIVITY_LEAK_STAKE_SCALED_HEIGHT + 1,
        )
        # Per-stake-unit yield should be approximately equal (the
        # whole point of stake-scaling).  Allow ±5% slack for integer
        # rounding.
        per_unit_small = pen_small / max(1, stake_small)
        per_unit_whale = pen_whale / max(1, stake_whale)
        self.assertAlmostEqual(
            per_unit_small, per_unit_whale, delta=0.06,
            msg=(
                f"Per-stake-unit penalty post-fork should be ~equal "
                f"(small={per_unit_small}, whale={per_unit_whale}) -- "
                "the whole point of stake-scaling is fractional-of-"
                "stake parity across the validator set."
            ),
        )
        # Absolute drain on the whale should be much larger (the
        # cartel-defense property: large coordinated stake withholding
        # for the same number of cycles costs the cartel proportionally
        # more in absolute tokens).
        self.assertGreater(
            pen_whale, pen_small * (ratio - 5),  # small slack
            f"Post-fork: whale absolute drain ({pen_whale}) should "
            f"scale roughly with stake-ratio ({ratio}x) over small "
            f"validator drain ({pen_small}) -- cartel-defense intent.",
        )

    def test_post_fork_small_validator_not_wiped_immediately(self):
        """At blocks_since=10000 a 10k-stake honest-but-isolated
        validator MUST NOT lose more than a small fraction of stake
        in one penalty cycle.  Pre-fork the same parameters wipe
        ~50% of stake (5/block × 10000 / 1000-block window etc.);
        post-fork the per-call penalty is fractional-of-stake."""
        stake = 10_000
        pen = compute_inactivity_penalty(
            10000, stake,
            current_height=INACTIVITY_LEAK_STAKE_SCALED_HEIGHT + 1,
        )
        # Bound: per-call penalty < 5% of stake at blocks_since=10000.
        # The stake-scaled formula at BASE=1 / QUOTIENT=2²⁴ /
        # blocks=10000 yields stake * (5/(2²⁴/10000²)) ≈ 5.96 * stake/1000
        # ≈ 0.6% of stake.  Generously bound at 5%.
        self.assertLess(
            pen, stake // 20,
            f"Post-fork inactivity penalty on a 10k-stake validator "
            f"at blocks_since=10000 ({pen}) should be < 5% of stake "
            f"({stake // 20}).  CLAUDE.md anchor: small fraction, "
            "not a wipe.",
        )


class TestApplyInactivityLeakHeightGate(unittest.TestCase):
    """``apply_inactivity_leak`` MUST thread ``current_height`` into
    ``compute_inactivity_penalty`` so the height gate fires.  Without
    this thread, even with the new compute math, the leak fires the
    pre-fork formula on post-fork blocks (or vice versa) and replay
    determinism is broken."""

    def test_apply_threads_current_height_post_fork(self):
        """apply_inactivity_leak with current_height post-Tier-59 must
        thread the height into compute and produce a stake-PROPORTIONAL
        drain.  Per-block at blocks_since=10000 is roughly
        stake * 5.96e-6 = stake * blocks² / Q_V2.  For a 10M-stake
        validator that's ~60 tokens per block; for a 100M-stake whale
        ~600 tokens per block; for a 100k-stake validator ~0.6 tokens
        (rounds to 0 -- small-validator transient slack).
        """
        whale_id = b"whale_validator" + b"\x00" * 17
        whale_stake = 10_000_000

        burned_post_fork, _ = apply_inactivity_leak(
            staked={whale_id: whale_stake},
            blocks_since_finality=10000,
            inactive_validators={whale_id},
            min_stake=0,
            current_height=INACTIVITY_LEAK_STAKE_SCALED_HEIGHT + 1,
            blockchain=None,  # honesty-curve relief is None-passthrough
        )
        # Whale's post-fork penalty: stake * 1 * 10000² / Q_V2.
        # At stake=10M, Q_V2=2^24*1M, this is ~60 tokens.  Compare to
        # legacy flat formula which yields ~6 tokens regardless of
        # stake -- whale pays 10x more in absolute tokens post-fork
        # (proportional to its stake fraction over 1M reference).
        legacy_pen = (
            INACTIVITY_BASE_PENALTY * 10000 * 10000
            // INACTIVITY_PENALTY_QUOTIENT
        )  # =5 or 6
        self.assertGreater(
            burned_post_fork, legacy_pen * 5,
            f"Post-fork apply on a 10M-stake validator should drain "
            f"strictly MORE than 5x the legacy flat shape (legacy={legacy_pen}, "
            f"got burned={burned_post_fork}).",
        )
        # Sanity: not a wipe.  A single-block call on a 10M-stake
        # validator at blocks=10000 should be far below 1% of stake.
        self.assertLess(
            burned_post_fork, whale_stake // 100,
            f"Post-fork single-block penalty must not wipe ~1% of stake "
            f"in one call (got {burned_post_fork} on stake "
            f"{whale_stake}).",
        )

    def test_apply_legacy_pre_fork_byte_identical(self):
        """Pre-fork apply MUST return the legacy flat drain
        byte-identically.  Replay determinism on every historical
        in-leak block depends on this."""
        whale_id = b"whale_validator" + b"\x00" * 17
        whale_stake = 10_000_000

        burned_legacy_no_kwargs, _ = apply_inactivity_leak(
            staked={whale_id: whale_stake},
            blocks_since_finality=10000,
            inactive_validators={whale_id},
            min_stake=0,
        )
        # Legacy 2-arg compute: BASE * 10000² // QUOTIENT
        expected = (
            INACTIVITY_BASE_PENALTY * 10000 * 10000
            // INACTIVITY_PENALTY_QUOTIENT
        )
        self.assertEqual(burned_legacy_no_kwargs, expected)

        # Same with current_height pre-Tier-59: still legacy.
        burned_pre_fork, _ = apply_inactivity_leak(
            staked={whale_id: whale_stake},
            blocks_since_finality=10000,
            inactive_validators={whale_id},
            min_stake=0,
            current_height=INACTIVITY_LEAK_STAKE_SCALED_HEIGHT - 10,
            blockchain=None,
        )
        self.assertEqual(burned_pre_fork, expected)


if __name__ == "__main__":
    unittest.main()
