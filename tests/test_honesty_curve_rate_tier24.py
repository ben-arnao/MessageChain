"""Tier 24: rate factor on the honesty curve.

Tier 23 introduced honest-history relief based on track_record (a
volume measure: weighted sum of good blocks + good attestations).
Tier 24 closes the rate gap — the relief now reads good-vs-bad
rate by subtracting `BAD_PENALTY_WEIGHT × prior_offenses` from the
raw track_record before relief is computed.

Tests pin:
  * Pre-activation byte-for-byte identity with Tier 23
  * Post-activation: priors erode track_record proportionally
  * Long-tenured + clean record → unchanged relief (max relief)
  * Long-tenured + many priors → eroded relief → higher severity
  * Track_record clamped to ≥ 0 (heavy priors can't go negative)
  * Rate factor combines with existing escalation multiplier
"""

import unittest
from unittest.mock import patch

from messagechain.config import (
    HONESTY_CURVE_HEIGHT,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_BAD_PENALTY_WEIGHT,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    HONESTY_CURVE_BLOCK_WEIGHT,
    HONESTY_CURVE_ATTEST_WEIGHT,
    HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    _track_record,
    slashing_severity,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


# Heights for the two regimes.  Use direct chain-height assignments
# so the test exercises the activation gate without spinning the
# chain forward thousands of blocks.
PRE = HONESTY_CURVE_RATE_HEIGHT - 1
POST = HONESTY_CURVE_RATE_HEIGHT


class _ChainStub:
    """Minimal blockchain-shaped object for pure-function tests."""
    def __init__(self, height: int):
        self._height = height
        self.proposer_sig_counts: dict[bytes, int] = {}
        self.reputation: dict[bytes, int] = {}
        self.slash_offense_counts: dict[bytes, int] = {}

    @property
    def height(self) -> int:
        return self._height


class TestTier24Activation(unittest.TestCase):
    """Activation height ordering and runway."""

    def test_rate_height_above_curve_height(self):
        # Tier 24 must follow Tier 23 — config asserts enforce this at
        # module import; a runtime test makes the invariant visible.
        self.assertGreater(HONESTY_CURVE_RATE_HEIGHT, HONESTY_CURVE_HEIGHT)

    def test_bad_penalty_weight_positive(self):
        self.assertGreater(HONESTY_CURVE_BAD_PENALTY_WEIGHT, 0)


class TestTrackRecordPreActivation(unittest.TestCase):
    """Pre-activation: track_record matches Tier 23 formula byte-for-byte."""

    def test_clean_validator_track_record_unchanged(self):
        chain = _ChainStub(height=PRE)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 50
        chain.reputation[eid] = 100
        track = _track_record(chain, eid)
        # Tier 23 formula: 4*50 + 1*100 = 300
        self.assertEqual(
            track,
            HONESTY_CURVE_BLOCK_WEIGHT * 50 + HONESTY_CURVE_ATTEST_WEIGHT * 100,
        )

    def test_priors_do_not_affect_track_record_pre_activation(self):
        chain = _ChainStub(height=PRE)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 50
        chain.reputation[eid] = 100
        chain.slash_offense_counts[eid] = 5  # would erode under Tier 24
        track = _track_record(chain, eid)
        # Pre-activation: priors silently ignored — full Tier 23 sum.
        self.assertEqual(track, 4 * 50 + 100)


class TestTrackRecordPostActivation(unittest.TestCase):
    """Post-activation: priors erode track_record."""

    def test_clean_validator_track_record_unchanged_by_rate_factor(self):
        # Validator with no priors: track_record same as Tier 23.
        chain = _ChainStub(height=POST)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 50
        chain.reputation[eid] = 100
        track = _track_record(chain, eid)
        self.assertEqual(track, 4 * 50 + 100)

    def test_priors_erode_track_record(self):
        chain = _ChainStub(height=POST)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 50    # = 200 weighted
        chain.reputation[eid] = 100            # = 100 weighted
        chain.slash_offense_counts[eid] = 1
        track = _track_record(chain, eid)
        # Raw = 300; after one prior of weight 100: 300 - 100 = 200.
        self.assertEqual(track, 200)

    def test_heavy_priors_clamp_to_zero(self):
        # If priors × penalty exceeds raw track_record, the rate-
        # adjusted value clamps at 0 — never goes negative.
        chain = _ChainStub(height=POST)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 10  # = 40 weighted
        chain.reputation[eid] = 20           # = 20 weighted
        chain.slash_offense_counts[eid] = 5  # = 500 penalty
        track = _track_record(chain, eid)
        # Raw = 60, penalty = 500, clamped to 0.
        self.assertEqual(track, 0)

    def test_priors_proportional_erosion(self):
        # Each additional prior erodes by exactly BAD_PENALTY_WEIGHT.
        chain = _ChainStub(height=POST)
        eid = b"v" * 32
        chain.proposer_sig_counts[eid] = 1000  # huge head-room
        chain.reputation[eid] = 0
        # = 4000 raw track_record
        chain.slash_offense_counts[eid] = 0
        t0 = _track_record(chain, eid)
        chain.slash_offense_counts[eid] = 1
        t1 = _track_record(chain, eid)
        chain.slash_offense_counts[eid] = 5
        t5 = _track_record(chain, eid)
        self.assertEqual(t0 - t1, HONESTY_CURVE_BAD_PENALTY_WEIGHT)
        self.assertEqual(t0 - t5, 5 * HONESTY_CURVE_BAD_PENALTY_WEIGHT)


class TestSlashingSeverityRateAware(unittest.TestCase):
    """slashing_severity reads the Tier-24 rate-adjusted track."""

    def setUp(self):
        self.alice = Entity.create(b"rate-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"rate-bob".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.bob)
        register_entity_for_test(self.chain, self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 1_000)
        # Long-tenured + perfect.  Track = 4*1000 + 5000 = 9000 (very
        # high) → maximum relief at threshold/9000 ≈ FLOOR.
        self.chain.proposer_sig_counts[self.alice.entity_id] = 1_000
        self.chain.reputation[self.alice.entity_id] = 5_000

    def _force_height(self, h: int):
        """Override the chain height for severity calls.  Slashing
        severity reads `blockchain.height`, which is a property — patch
        it via a lambda so we can flip between PRE/POST without
        actually advancing the chain."""
        return patch.object(
            Blockchain, "height", new=property(lambda _: h),
        )

    def test_long_tenured_clean_validator_keeps_relief_post_tier_24(self):
        # No priors → Tier 24 rate factor is a no-op → relief
        # unchanged from Tier 23.  Severity for an AMBIGUOUS first
        # offense is at the relief floor.
        self.chain.slash_offense_counts[self.alice.entity_id] = 0
        with self._force_height(POST):
            sev = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
        # AMBIGUOUS base × relief × escalation, all clamped to MIN_PCT.
        # With prior=0 and a huge clean track, severity is at the
        # floor: max(MIN_PCT, base * floor_multiplier).
        self.assertLessEqual(sev, HONESTY_CURVE_AMBIGUOUS_BASE_PCT)

    def test_long_tenured_dirty_validator_loses_relief_post_tier_24(self):
        # Same long-tenure good actions, but with priors — Tier 24
        # erodes track_record → relief shrinks → severity climbs.
        self.chain.slash_offense_counts[self.alice.entity_id] = 0
        with self._force_height(POST):
            sev_clean = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
        self.chain.slash_offense_counts[self.alice.entity_id] = 50
        # 50 priors × 100 penalty = 5000 erosion.  Raw = 9000 → 4000
        # post-erosion (still ≥ threshold=100, so relief still
        # applies but at less-aggressive ratio).
        with self._force_height(POST):
            sev_dirty = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
        # Repeat-offender escalation (1 + 2*50 = 101x) ALSO inflates
        # severity, so we just assert dirty > clean — both directions
        # of the curve push the same way.
        self.assertGreater(sev_dirty, sev_clean)

    def test_pre_activation_priors_only_via_escalation(self):
        # Pre-Tier-24, priors enter ONLY through escalation, not
        # through track_record erosion.  Track_record stays high so
        # relief stays at floor.  Compare to post-activation: same
        # priors should produce a STRICTLY higher severity
        # post-activation (rate factor adds another lever).
        self.chain.slash_offense_counts[self.alice.entity_id] = 10
        with self._force_height(PRE):
            sev_pre = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
        with self._force_height(POST):
            sev_post = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
        # Post severity ≥ pre severity — Tier 24 is monotonic in the
        # bad-behavior direction (never softer than Tier 23 for the
        # same priors).  Strict > preferred but allow equality at the
        # 100% ceiling clamp.
        self.assertGreaterEqual(sev_post, sev_pre)

    def test_unambiguous_path_unaffected_by_rate_factor(self):
        # The UNAMBIGUOUS-with-prior path is 100% regardless — Tier 24's
        # rate factor only tunes the AMBIGUOUS relief, so the
        # deliberate-Byzantine-on-repeat decision is unchanged.
        self.chain.slash_offense_counts[self.alice.entity_id] = 1
        with self._force_height(POST):
            sev = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.UNAMBIGUOUS,
                self.chain,
            )
        self.assertEqual(sev, 100)


if __name__ == "__main__":
    unittest.main()
