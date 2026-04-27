"""LOTTERY_BOUNTY raise hard fork: 100 -> 5,000.

Background
----------
The bootstrap lottery mints a reputation-weighted bounty every
LOTTERY_INTERVAL blocks.  Legacy sizing (100 tokens) at 140M supply
distributed ~73K tokens (~0.05% of supply) across the 2-year bootstrap
window — too small to materially diversify non-founder holdings.
Raising to 5,000 tokens distributes ~1.83M (~1.3% of supply),
restoring the intended bootstrap-era dispersion.

Activation-gated at LOTTERY_BOUNTY_RAISE_HEIGHT.  The existing
`(1 - bootstrap_progress)` fade mechanic must still work with the new
base value so the bounty collapses to 0 at progress=1.0 under both
regimes.
"""

from __future__ import annotations

import unittest

import messagechain.config as config
from messagechain.consensus.reputation_lottery import (
    lottery_bounty_for_progress,
)


class TestLotteryBountyRaiseConstants(unittest.TestCase):
    """Constants + helper function + activation gate."""

    def test_legacy_constant_unchanged(self):
        self.assertEqual(config.LOTTERY_BOUNTY, 100)

    def test_post_raise_constant_exists(self):
        self.assertTrue(hasattr(config, "LOTTERY_BOUNTY_POST_RAISE"))
        self.assertEqual(config.LOTTERY_BOUNTY_POST_RAISE, 5_000)

    def test_activation_height_canonical(self):
        self.assertTrue(hasattr(config, "LOTTERY_BOUNTY_RAISE_HEIGHT"))
        # Compressed in 1.11.0 from 62_000 to 1100; fast-forwarded to 702 in 1.26.0.
        self.assertEqual(config.LOTTERY_BOUNTY_RAISE_HEIGHT, 702)

    def test_helper_exists(self):
        self.assertTrue(hasattr(config, "get_lottery_bounty"))

    def test_pre_activation_returns_legacy(self):
        self.assertEqual(
            config.get_lottery_bounty(config.LOTTERY_BOUNTY_RAISE_HEIGHT - 1),
            100,
        )
        self.assertEqual(config.get_lottery_bounty(0), 100)

    def test_at_activation_returns_new(self):
        self.assertEqual(
            config.get_lottery_bounty(config.LOTTERY_BOUNTY_RAISE_HEIGHT),
            5_000,
        )

    def test_post_activation_returns_new(self):
        self.assertEqual(
            config.get_lottery_bounty(
                config.LOTTERY_BOUNTY_RAISE_HEIGHT + 10_000,
            ),
            5_000,
        )


class TestFadePreservedUnderBothRegimes(unittest.TestCase):
    """Progress-fade still collapses the bounty to 0 at progress=1.0."""

    def test_pre_activation_full_bounty_at_genesis(self):
        self.assertEqual(
            lottery_bounty_for_progress(0.0, full_bounty=config.LOTTERY_BOUNTY),
            config.LOTTERY_BOUNTY,
        )

    def test_pre_activation_zero_at_progress_one(self):
        self.assertEqual(
            lottery_bounty_for_progress(1.0, full_bounty=config.LOTTERY_BOUNTY),
            0,
        )

    def test_post_activation_full_bounty_at_genesis(self):
        self.assertEqual(
            lottery_bounty_for_progress(
                0.0, full_bounty=config.LOTTERY_BOUNTY_POST_RAISE,
            ),
            config.LOTTERY_BOUNTY_POST_RAISE,
        )

    def test_post_activation_zero_at_progress_one(self):
        """The new (larger) base bounty must still fade to 0 at p=1."""
        self.assertEqual(
            lottery_bounty_for_progress(
                1.0, full_bounty=config.LOTTERY_BOUNTY_POST_RAISE,
            ),
            0,
        )

    def test_pre_activation_bounty_bounded_by_legacy(self):
        """At any progress in [0, 1], payout <= legacy_bounty * (1 - p)."""
        for p_tenth in range(11):
            p = p_tenth / 10.0
            payout = lottery_bounty_for_progress(
                p, full_bounty=config.LOTTERY_BOUNTY,
            )
            ceiling = int(config.LOTTERY_BOUNTY * (1.0 - p))
            self.assertLessEqual(payout, ceiling)

    def test_post_activation_bounty_bounded_by_new_base(self):
        """At any progress in [0, 1], payout <= new_bounty * (1 - p)."""
        for p_tenth in range(11):
            p = p_tenth / 10.0
            payout = lottery_bounty_for_progress(
                p, full_bounty=config.LOTTERY_BOUNTY_POST_RAISE,
            )
            ceiling = int(config.LOTTERY_BOUNTY_POST_RAISE * (1.0 - p))
            self.assertLessEqual(payout, ceiling)


class TestBootstrapEnvelope(unittest.TestCase):
    """Upper-bound check on total lottery mint over the bootstrap window.

    With a triangle fade from full_bounty at p=0 to 0 at p=1 and one firing
    every LOTTERY_INTERVAL blocks, total mint is bounded by:
        (BOOTSTRAP_END_HEIGHT / LOTTERY_INTERVAL) * full_bounty / 2
    Pre-raise: ~365 intervals * 100 / 2 ~= 18K.
    Post-raise: ~365 intervals * 5000 / 2 ~= 900K.
    (Numbers are order-of-magnitude sanity; we pin only the ratio
    invariant here so constant tweaks don't invalidate the test.)
    """

    def _envelope(self, full_bounty: int) -> int:
        from messagechain.consensus.bootstrap_gradient import (
            BOOTSTRAP_END_HEIGHT,
        )
        total = 0
        intervals = BOOTSTRAP_END_HEIGHT // config.LOTTERY_INTERVAL
        for k in range(intervals + 1):
            p = (k * config.LOTTERY_INTERVAL) / BOOTSTRAP_END_HEIGHT
            if p > 1.0:
                p = 1.0
            total += lottery_bounty_for_progress(p, full_bounty=full_bounty)
        return total

    def test_envelope_scales_with_base_bounty(self):
        """Raising the base by 50x raises the envelope by ~50x."""
        legacy_env = self._envelope(config.LOTTERY_BOUNTY)
        raised_env = self._envelope(config.LOTTERY_BOUNTY_POST_RAISE)
        ratio = raised_env / max(legacy_env, 1)
        self.assertAlmostEqual(
            ratio,
            config.LOTTERY_BOUNTY_POST_RAISE / config.LOTTERY_BOUNTY,
            delta=1.0,
        )


class TestGetLotteryBountyCallSite(unittest.TestCase):
    """The call-site that reads LOTTERY_BOUNTY must switch through the helper.

    Spot-check: whether `get_lottery_bounty(h)` composed with
    `lottery_bounty_for_progress` produces the expected faded value at
    each regime.
    """

    def test_pre_activation_firing_payout_bounded_by_legacy(self):
        """At any progress, faded payout is <= legacy * (1 - p)."""
        h = config.LOTTERY_BOUNTY_RAISE_HEIGHT - 1
        full = config.get_lottery_bounty(h)
        self.assertEqual(full, 100)
        for p_tenth in range(11):
            p = p_tenth / 10.0
            payout = lottery_bounty_for_progress(p, full_bounty=full)
            self.assertLessEqual(payout, int(100 * (1.0 - p)))

    def test_post_activation_firing_payout_bounded_by_new_base(self):
        h = config.LOTTERY_BOUNTY_RAISE_HEIGHT + 1
        full = config.get_lottery_bounty(h)
        self.assertEqual(full, 5_000)
        for p_tenth in range(11):
            p = p_tenth / 10.0
            payout = lottery_bounty_for_progress(p, full_bounty=full)
            self.assertLessEqual(payout, int(5_000 * (1.0 - p)))


if __name__ == "__main__":
    unittest.main()
