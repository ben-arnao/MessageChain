"""Slash-evasion window: UNBONDING_PERIOD must cover the evidence window.

Finding: pre-fix, ``UNBONDING_PERIOD = 1_008`` blocks (~7 days) was
SHORTER than ``EVIDENCE_EXPIRY_BLOCKS = 2_016`` (~14 days).  A
validator could equivocate at block H, queue an unstake at H+1, let
the 7-day unbond period mature, withdraw the tokens, and be
judgment-proof when slow censorship/double-sign evidence landed at
H+2000 — well inside the 14-day evidence window but past the 7-day
unbond window.  The ``max(UNBONDING_PERIOD, ATTESTER_ESCROW_BLOCKS)``
TTL in ``validate_slash_transaction`` doesn't help: it still admits
evidence, but ``supply.get_pending_unstake()`` returns 0 because the
queue already drained.

Fix (hard-forked at ``UNBONDING_PERIOD_EXTENSION_HEIGHT``):
    UNBONDING_PERIOD = EVIDENCE_EXPIRY_BLOCKS
                       + EVIDENCE_MATURITY_BLOCKS
                       + 144   # 1-day clock-skew / future-window margin

Pre-activation: the legacy 1008-block period applies so in-flight
unstakes don't retroactively extend and existing consensus state
stays deterministic.  Post-activation: newly initiated unstakes use
the new period.  In-flight unstakes initiated pre-activation keep
their original maturity (release_block stored at unstake time, never
mutated).
"""

import unittest

from messagechain.config import (
    UNBONDING_PERIOD,
    UNBONDING_PERIOD_LEGACY,
    UNBONDING_PERIOD_POST_EXTENSION,
    UNBONDING_PERIOD_EXTENSION_HEIGHT,
    get_unbonding_period,
)
from messagechain.economics.inflation import SupplyTracker


class TestUnbondingEvidenceInvariant(unittest.TestCase):
    """Static invariant: post-activation unbonding covers the evidence window."""

    def test_post_extension_covers_evidence_plus_maturity(self):
        """The defining slash-evasion invariant.

        Uses the config-import-time evidence constants (2016, 16) rather
        than re-reading ``messagechain.config.*`` — other test modules
        monkey-patch those globals at import time and the mutations can
        persist across the discover run.  The invariant we care about
        is the one baked in at config load.
        """
        original_evidence_expiry = 2_016
        original_evidence_maturity = 16
        self.assertGreaterEqual(
            UNBONDING_PERIOD_POST_EXTENSION,
            original_evidence_expiry + original_evidence_maturity,
            "Post-extension unbonding period MUST cover evidence expiry "
            "+ maturity delay, or a validator can outrun slashing evidence "
            "by unstaking.",
        )

    def test_post_extension_value_matches_formula(self):
        """Explicit: +144 block (1-day) margin absorbs clock skew.

        Uses the original (config-import-time) evidence constants rather
        than re-reading ``messagechain.config.*`` live, because other
        test modules (``test_censorship_evidence``,
        ``test_feature_composition``) monkey-patch those globals at
        their own import time and the mutations can bleed across the
        unittest discover run.  The invariant we care about is the one
        baked in at config load, which is exactly what
        ``UNBONDING_PERIOD_POST_EXTENSION`` captured.
        """
        # 2016 + 16 + 144 = 2176
        self.assertEqual(UNBONDING_PERIOD_POST_EXTENSION, 2_016 + 16 + 144)
        self.assertEqual(UNBONDING_PERIOD_POST_EXTENSION, 2_176)

    def test_post_extension_is_strictly_longer_than_legacy(self):
        """The fix extends the window; it never shortens."""
        self.assertGreater(UNBONDING_PERIOD_POST_EXTENSION, UNBONDING_PERIOD_LEGACY)

    def test_module_level_alias_is_post_extension_value(self):
        """``UNBONDING_PERIOD`` (the module-level name pinned for code and
        tests that don't thread block height) tracks the post-activation
        value so callers that read the bare constant see the safe one."""
        self.assertEqual(UNBONDING_PERIOD, UNBONDING_PERIOD_POST_EXTENSION)

    def test_legacy_matches_historical_7_day_window(self):
        """Regression anchor: the pre-activation period is exactly 1008."""
        self.assertEqual(UNBONDING_PERIOD_LEGACY, 1_008)


class TestGetUnbondingPeriodActivationGate(unittest.TestCase):
    """Hard-fork gate: selects legacy vs post-extension by block height."""

    def test_pre_activation_returns_legacy(self):
        self.assertEqual(
            get_unbonding_period(UNBONDING_PERIOD_EXTENSION_HEIGHT - 1),
            UNBONDING_PERIOD_LEGACY,
        )

    def test_at_activation_returns_post_extension(self):
        self.assertEqual(
            get_unbonding_period(UNBONDING_PERIOD_EXTENSION_HEIGHT),
            UNBONDING_PERIOD_POST_EXTENSION,
        )

    def test_post_activation_returns_post_extension(self):
        self.assertEqual(
            get_unbonding_period(UNBONDING_PERIOD_EXTENSION_HEIGHT + 10_000),
            UNBONDING_PERIOD_POST_EXTENSION,
        )

    def test_genesis_height_uses_legacy(self):
        """Height 0 is pre-activation so historical replay keeps the
        same release_block arithmetic it had when the block applied."""
        self.assertEqual(get_unbonding_period(0), UNBONDING_PERIOD_LEGACY)


class TestUnstakeUsesActivationGate(unittest.TestCase):
    """``SupplyTracker.unstake()`` applies the gated period at call time."""

    def _supply_with_stake(self, vid: bytes, amount: int) -> SupplyTracker:
        supply = SupplyTracker()
        supply.balances[vid] = amount * 2
        self.assertTrue(supply.stake(vid, amount))
        return supply

    def test_unstake_pre_activation_uses_legacy_period(self):
        vid = b"v" * 32
        supply = self._supply_with_stake(vid, 1_000)
        pre_h = UNBONDING_PERIOD_EXTENSION_HEIGHT - 10
        self.assertTrue(supply.unstake(vid, 1_000, current_block=pre_h))
        # Release one block before legacy maturity: tokens still pending.
        supply.process_pending_unstakes(pre_h + UNBONDING_PERIOD_LEGACY - 1)
        self.assertEqual(supply.get_pending_unstake(vid), 1_000)
        # Exactly at legacy maturity: tokens release.
        supply.process_pending_unstakes(pre_h + UNBONDING_PERIOD_LEGACY)
        self.assertEqual(supply.get_pending_unstake(vid), 0)

    def test_unstake_post_activation_uses_extended_period(self):
        vid = b"v" * 32
        supply = self._supply_with_stake(vid, 1_000)
        h = UNBONDING_PERIOD_EXTENSION_HEIGHT + 5
        self.assertTrue(supply.unstake(vid, 1_000, current_block=h))
        # Legacy maturity must NOT release tokens anymore.
        supply.process_pending_unstakes(h + UNBONDING_PERIOD_LEGACY + 10)
        self.assertEqual(
            supply.get_pending_unstake(vid), 1_000,
            "Post-activation unstake released at legacy maturity — the "
            "extension gate is not wired into supply.unstake().",
        )
        # Extended maturity releases.
        supply.process_pending_unstakes(h + UNBONDING_PERIOD_POST_EXTENSION)
        self.assertEqual(supply.get_pending_unstake(vid), 0)

    def test_in_flight_unstake_from_pre_activation_keeps_legacy_maturity(self):
        """Unstake queued pre-activation must not be retroactively extended
        when the chain crosses the activation height.  The release_block
        was baked in at unstake time; crossing the fork does not rewrite
        pending queue entries."""
        vid = b"v" * 32
        supply = self._supply_with_stake(vid, 1_000)
        pre_h = UNBONDING_PERIOD_EXTENSION_HEIGHT - 5
        self.assertTrue(supply.unstake(vid, 1_000, current_block=pre_h))
        # Fast-forward past activation AND past the legacy maturity.  The
        # originally scheduled release_block = pre_h + 1008 is still valid.
        release_at = pre_h + UNBONDING_PERIOD_LEGACY
        supply.process_pending_unstakes(release_at)
        self.assertEqual(
            supply.get_pending_unstake(vid), 0,
            "Pre-activation unstake did NOT release at its originally "
            "scheduled maturity — the fix must not mutate queue entries "
            "retroactively.",
        )


class TestEquivocationDuringUnstakeScenario(unittest.TestCase):
    """End-to-end: validator equivocates at H, unstakes at H+1, evidence
    lands at H+2000 — the stake MUST still be slashable.

    This is the attack the fix is designed to close.  Pre-fix: by
    H+1+1008 ≈ H+1009 the pending queue has drained and
    ``get_pending_unstake()`` returns 0, so the slash lands on empty
    state.  Post-fix: by H+1+2176 > H+2000 the queue still holds the
    offender's tokens, so ``slash_validator`` burns them.
    """

    def test_equivocator_cannot_outrun_slash_evidence(self):
        vid = b"v" * 32
        supply = SupplyTracker()
        supply.balances[vid] = 10_000
        self.assertTrue(supply.stake(vid, 1_000))

        # Offender unstakes one block after the offense.  Both happen at
        # post-activation heights.
        H = UNBONDING_PERIOD_EXTENSION_HEIGHT + 100  # offense height
        unstake_h = H + 1
        self.assertTrue(supply.unstake(vid, 1_000, current_block=unstake_h))
        self.assertEqual(supply.get_staked(vid), 0)
        self.assertEqual(supply.get_pending_unstake(vid), 1_000)

        # Slow evidence arrives at H+2000, inside EVIDENCE_EXPIRY_BLOCKS
        # (2016) but WAY past the old 1008-block unbond window.
        evidence_at = H + 2_000
        # Advance queue maturation to the evidence-submission height.
        # Pre-fix: this call would release all 1_000 tokens.
        supply.process_pending_unstakes(evidence_at)

        self.assertEqual(
            supply.get_pending_unstake(vid), 1_000,
            "The offender's pending unstake drained before the evidence "
            "landed — the unbonding period is still shorter than the "
            "evidence window.  Slash-evasion window is OPEN.",
        )
        # And of course the slash itself captures it.
        slashed, _ = supply.slash_validator(vid, b"f" * 32)
        self.assertEqual(slashed, 1_000)
        self.assertEqual(supply.get_pending_unstake(vid), 0)


if __name__ == "__main__":
    unittest.main()
