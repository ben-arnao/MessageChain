"""Regression for audit r53 #3.

Same defect class as the Tier 73 / Tier 74 ``_split_bps`` fixes on the
REWARD side, but on the PUNISHMENT side: ``slash_validator``,
``burn_slash_proportional``, and ``EscrowLedger.slash_all`` all compute
the slash amount as ``basis * slash_pct // 100``.  At the anchored
``SOFT_SLASH_PCT = 5`` (Tier 20 honest-operator-insurance level), any
basis under 20 tokens rounds the slash to zero -- the offender keeps
their full stake / pending / escrow entry and the punishment is
silently a no-op.

The anchored "Honest-operators are insured" CLAUDE.md anchor wants
*small fractional* burns on transient hiccups, not *zero* burns: a
0% slash means the rule didn't bite even for clearly-malicious
offenders whose basis happens to be small (e.g. an escrow entry below
20 tokens at the steady-state low-issuance regime the dormancy
controller is anchored to produce).  Without the clamp, the reward
side rounds up to a non-zero minimum (Tier 73/74) while the
punishment side silently rounds DOWN to zero -- the two anchors are
in deliberate symmetry only after this Tier-75 fix.

Activation height ``SLASH_MIN_UNIT_HEIGHT`` (Tier 75) sits 2000
blocks above Tier 74 (10500), matching the Tier 70->71->73->74
cohort cadence -- a punishment-shape change deserves its own
operator-runway cohort.

Property tested:
  * Pre-fork ``slash_validator`` rounds to zero at small basis
    (byte-identical to legacy).
  * Post-fork ``slash_validator`` clamps to min-unit=1 token at the
    same small basis -- offender's stake is debited by 1 token, not
    silently spared.
  * Pre-fork ``burn_slash_proportional`` rounds to zero at small basis.
  * Post-fork ``burn_slash_proportional`` clamps to 1 token.
  * Pre-fork ``EscrowLedger.slash_all`` keeps the offender's small
    entry intact (burn=0, entry survives at remaining=amount).
  * Post-fork ``EscrowLedger.slash_all`` burns at least 1 token from
    a small entry.
  * Supply conservation: the clamp never exceeds the input basis.
"""

from __future__ import annotations

import unittest

from messagechain.config import SLASH_MIN_UNIT_HEIGHT
from messagechain.economics.escrow import EscrowEntry, EscrowLedger
from messagechain.economics.inflation import SupplyTracker


SMALL_STAKE = 10  # 5% of 10 = 0 under integer floor; clamp is the fix.
SLASH_PCT_SOFT = 5  # The Tier 20 anchored honest-operator-insurance pct.


class TestSlashValidatorMinUnit(unittest.TestCase):
    """``SupplyTracker.slash_validator`` must round small slashes UP to
    1 token post-fork, not silently to 0."""

    def _make_supply_with_small_stake(self):
        s = SupplyTracker()
        offender = b"\x11" * 32
        finder = b"\x22" * 32
        s.staked[offender] = SMALL_STAKE
        s.balances[offender] = 0
        s.balances[finder] = 0
        s.total_supply = SMALL_STAKE
        return s, offender, finder

    def test_legacy_pre_fork_rounds_small_slash_to_zero(self):
        s, offender, finder = self._make_supply_with_small_stake()
        slashed, finder_reward = s.slash_validator(
            offender, finder, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT - 1,
        )
        # Byte-identical legacy: 10 * 5 // 100 = 0.
        self.assertEqual(slashed, 0)
        self.assertEqual(s.staked[offender], SMALL_STAKE,
                         "pre-fork must preserve the legacy no-op shape")

    def test_post_fork_clamps_small_slash_to_min_unit(self):
        s, offender, finder = self._make_supply_with_small_stake()
        slashed, finder_reward = s.slash_validator(
            offender, finder, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT,
        )
        # Post-fork: clamp burns at least 1 token from the offender.
        self.assertGreaterEqual(slashed, 1)
        self.assertLess(
            s.staked[offender], SMALL_STAKE,
            "post-fork: offender stake must shrink by the clamp",
        )

    def test_post_fork_supply_conservation(self):
        """The clamp must never exceed the bucket -- a basis of 1
        token at 5% slash should burn at most 1 token, never 2."""
        s = SupplyTracker()
        offender = b"\x33" * 32
        finder = b"\x44" * 32
        s.staked[offender] = 1
        s.balances[offender] = 0
        s.balances[finder] = 0
        s.total_supply = 1
        slashed, _ = s.slash_validator(
            offender, finder, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT,
        )
        # 1 token at 5% with min_unit=1 -> burn 1 (the whole bucket).
        # Must never exceed the bucket amount.
        self.assertEqual(slashed, 1)
        self.assertEqual(s.staked[offender], 0)


class TestBurnSlashProportionalMinUnit(unittest.TestCase):
    """``SupplyTracker.burn_slash_proportional`` is the censorship /
    inclusion-list-violation / non-response / bogus-rejection slash
    path -- same defect-class, same clamp."""

    def _make_supply_with_small_stake(self):
        s = SupplyTracker()
        offender = b"\x55" * 32
        s.staked[offender] = SMALL_STAKE
        s.balances[offender] = 0
        s.total_supply = SMALL_STAKE
        return s, offender

    def test_legacy_pre_fork_rounds_small_slash_to_zero(self):
        s, offender = self._make_supply_with_small_stake()
        burned = s.burn_slash_proportional(
            offender, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT - 1,
        )
        self.assertEqual(burned, 0)
        self.assertEqual(s.staked[offender], SMALL_STAKE)

    def test_post_fork_clamps_small_slash_to_min_unit(self):
        s, offender = self._make_supply_with_small_stake()
        burned = s.burn_slash_proportional(
            offender, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT,
        )
        self.assertGreaterEqual(burned, 1)
        self.assertLess(s.staked[offender], SMALL_STAKE)


class TestEscrowLedgerSlashAllMinUnit(unittest.TestCase):
    """``EscrowLedger.slash_all`` is the per-attester-batch slash path
    -- attester rewards mature into escrow as small entries, so any
    entry under 20 tokens silently escapes the 5% soft slash pre-fork."""

    def _make_escrow_with_small_entry(self):
        ledger = EscrowLedger()
        offender = b"\x66" * 32
        ledger.add(
            entity_id=offender, amount=SMALL_STAKE,
            earned_at=0, unlock_at=100,
        )
        return ledger, offender

    def test_legacy_pre_fork_keeps_small_entry_intact(self):
        ledger, offender = self._make_escrow_with_small_entry()
        burned = ledger.slash_all(
            offender, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT - 1,
        )
        # 10 * 5 // 100 = 0; entry survives at amount=10.
        self.assertEqual(burned, 0)
        entries = [e for e in ledger.entries_for(offender)]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].amount, SMALL_STAKE)

    def test_post_fork_clamps_small_entry_burn_to_min_unit(self):
        ledger, offender = self._make_escrow_with_small_entry()
        burned = ledger.slash_all(
            offender, slash_pct=SLASH_PCT_SOFT,
            block_height=SLASH_MIN_UNIT_HEIGHT,
        )
        self.assertGreaterEqual(burned, 1)
        entries = [e for e in ledger.entries_for(offender)]
        # Entry remains (since slash_pct < 100) but with amount reduced.
        self.assertEqual(len(entries), 1)
        self.assertLess(entries[0].amount, SMALL_STAKE)


class TestActivationHeightOrdering(unittest.TestCase):
    """``SLASH_MIN_UNIT_HEIGHT`` (Tier 75) must strictly follow Tier 74
    (``PROPOSER_SHARE_MIN_UNIT_HEIGHT``) so the cohort spacing matches
    the Tier 70->71->73->74 runway pattern."""

    def test_slash_min_unit_height_follows_tier_74(self):
        from messagechain.config import (
            PROPOSER_SHARE_MIN_UNIT_HEIGHT,
            SLASH_MIN_UNIT_HEIGHT,
        )
        self.assertGreater(
            SLASH_MIN_UNIT_HEIGHT, PROPOSER_SHARE_MIN_UNIT_HEIGHT,
            "Tier 75 must activate strictly after Tier 74 so operators "
            "absorb each validator-economics retune in its own upgrade "
            "cycle",
        )


if __name__ == "__main__":
    unittest.main()
