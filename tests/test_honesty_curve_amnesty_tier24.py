"""Tier 24: perfect-record amnesty for AMBIGUOUS evidence.

CLAUDE.md anchor (user-stated wording, 2026-04-27): "users with long
history/veteran + high good behavior rate + good behavior volume have
LOW CHANCE of getting penalized and/or get lower-severity penalty."
Tier 23 implemented "lower-severity"; Tier 24 closes "low chance":

  * AMBIGUOUS (restart-shape) evidence
  * AND offender's track_record >= AMNESTY_TRACK_THRESHOLD
  * AND offender has zero priors

  → severity = 0 → slash skipped entirely.

The amnesty is single-shot: the apply path bumps slash_offense_counts
even on a 0-severity outcome, so the next AMBIGUOUS incident sees
prior=1 and no longer qualifies (fall back to standard small severity).

UNAMBIGUOUS evidence is NEVER amnestied — the deliberate-Byzantine
bar stands regardless of tenure.

Pre-Tier-24: amnesty does not apply (legacy small-severity path
returns at least HONESTY_CURVE_MIN_PCT = 1).
"""

import unittest
from unittest.mock import patch

from messagechain.config import (
    HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    HONESTY_CURVE_MIN_PCT,
    HONESTY_CURVE_RATE_HEIGHT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    slashing_severity,
)


PRE = HONESTY_CURVE_RATE_HEIGHT - 1
POST = HONESTY_CURVE_RATE_HEIGHT


class _ChainStub:
    def __init__(self, height: int = POST):
        self._height = height
        self.proposer_sig_counts: dict[bytes, int] = {}
        self.reputation: dict[bytes, int] = {}
        self.slash_offense_counts: dict[bytes, int] = {}

    @property
    def height(self) -> int:
        return self._height


class TestAmnestyConfig(unittest.TestCase):
    def test_amnesty_threshold_above_relief_threshold(self):
        # The amnesty band is a STRICTER bar than the relief band —
        # full pass requires more good standing than just a small
        # severity.
        self.assertGreater(
            HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD,
            HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
        )


class TestAmnestyApplies(unittest.TestCase):
    """Severity == 0 only when ALL three conditions hold."""

    def setUp(self):
        self.eid = b"v" * 32
        self.chain = _ChainStub(height=POST)

    def _set_track(self, weighted_sum: int):
        # weighted_sum = 4 * blocks + 1 * atts.  Allocate to
        # reputation only so block_weight isn't confused.
        self.chain.proposer_sig_counts[self.eid] = 0
        self.chain.reputation[self.eid] = weighted_sum

    def test_long_tenured_zero_priors_ambiguous_returns_zero(self):
        self._set_track(HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD)
        self.chain.slash_offense_counts[self.eid] = 0
        sev = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertEqual(sev, 0)

    def test_long_tenured_one_prior_falls_back_to_standard(self):
        # Prior == 1 disqualifies amnesty.  Falls back to standard
        # AMBIGUOUS path which returns at least MIN_PCT.
        self._set_track(HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD)
        self.chain.slash_offense_counts[self.eid] = 1
        sev = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertGreaterEqual(sev, HONESTY_CURVE_MIN_PCT)

    def test_short_tenure_zero_priors_does_not_amnesty(self):
        # Track below AMNESTY_THRESHOLD → no amnesty even with zero
        # priors.  The bar is "perfect record AND high tenure", not
        # just "perfect record".
        self._set_track(HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD - 1)
        self.chain.slash_offense_counts[self.eid] = 0
        sev = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertGreater(sev, 0)

    def test_unambiguous_never_amnestied(self):
        # Even a perfect-record validator gets full UNAMBIGUOUS_FIRST_
        # PCT slash on a deliberate double-state-root.  Amnesty does
        # NOT cover the deliberate-Byzantine band.
        self._set_track(HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD * 100)
        self.chain.slash_offense_counts[self.eid] = 0
        sev = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        # Long tenure + first UNAMBIGUOUS → UNAMBIGUOUS_FIRST_PCT band
        # (50%), not 0.
        self.assertGreaterEqual(sev, 50)

    def test_pre_activation_no_amnesty(self):
        # Below HONESTY_CURVE_RATE_HEIGHT, the amnesty branch is
        # skipped — historical replay byte-identical to pre-Tier-24.
        chain = _ChainStub(height=PRE)
        chain.proposer_sig_counts[self.eid] = 0
        chain.reputation[self.eid] = HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD * 10
        chain.slash_offense_counts[self.eid] = 0
        sev = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        # Pre-fork: no amnesty, returns standard small severity.
        self.assertGreaterEqual(sev, HONESTY_CURVE_MIN_PCT)


class TestAmnestyOneShot(unittest.TestCase):
    """The amnesty applies only once — second offense doesn't qualify."""

    def setUp(self):
        self.eid = b"v" * 32
        self.chain = _ChainStub(height=POST)
        self.chain.proposer_sig_counts[self.eid] = 0
        self.chain.reputation[self.eid] = (
            HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD * 10
        )

    def test_zero_priors_amnestied_one_prior_not(self):
        # First incident: prior=0, amnesty applies → severity 0.
        self.chain.slash_offense_counts[self.eid] = 0
        sev0 = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertEqual(sev0, 0)

        # The apply-path would now bump prior to 1.  Simulate that.
        self.chain.slash_offense_counts[self.eid] = 1
        sev1 = slashing_severity(
            self.eid,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        # Second incident: amnesty disabled by prior=1, falls back to
        # standard AMBIGUOUS severity.
        self.assertGreater(sev1, 0)


if __name__ == "__main__":
    unittest.main()
