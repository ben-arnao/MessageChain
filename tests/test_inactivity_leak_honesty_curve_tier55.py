"""
Tier 55 — inactivity & coverage leaks consult the honesty curve.

Audit r30 #2 — `compute_inactivity_penalty` and `compute_coverage_penalty`
were pure functions of `(blocks_since_finality, validator_stake)` and
`(consecutive_misses, attester_stake)` respectively.  Neither consulted
`slashing_severity`, `_track_record`, or `_prior_offenses` — the entire
Tier-23/24/51 honesty-curve machinery that every other slashing path
uses.

Worst case: a fork-emergency auto-halt (network/node.py correctly halts
attestation/finality voting on the minority side -- the right thing)
puts honest, long-tenured validators into the leak-eligible set the
moment finality stalls past INACTIVITY_LEAK_ACTIVATION_THRESHOLD.  The
validator is doing exactly what the protocol asks; the chain bleeds
their stake quadratically as punishment, identical to a withholding
cartel's bleed.

CLAUDE.md anchor at risk: "long-tenured, high-volume, high-honesty
operators get fractional penalties at worst" -- the inactivity leak
silently exempted itself from this anchor.

Tier 55 routes both penalty paths through a `honest_history_relief_
multiplier_bps` helper that mirrors the AMBIGUOUS-path relief in
slashing_severity:

  * Validator with prior offenses: NO relief (10000 bps = full
    nominal penalty).  Repeat offenders pay full price.
  * Validator with track_record < HONEST_TRACK_THRESHOLD:
    NO relief.  Fresh validators carry less benefit-of-the-doubt.
  * Long-tenured high-honesty validator with no priors: relief
    multiplier = max(FLOOR_NUM/FLOOR_DEN, THRESHOLD/track) ⇒
    capped at 1/5 = 2000 bps = 20% of nominal penalty.

Pre-fork (current_height < INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT):
byte-identical legacy bleed -- pre-Tier-55 blocks replay as before.
"""

import unittest
from unittest.mock import MagicMock

from messagechain import config


class _Base(unittest.TestCase):
    def setUp(self):
        # Save originals; tests may monkey-patch height-gates and curve
        # constants and we restore on teardown.
        self._saved = {}
        for name in (
            "INACTIVITY_LEAK_ACTIVATION_THRESHOLD",
            "INACTIVITY_PENALTY_QUOTIENT",
            "INACTIVITY_BASE_PENALTY",
            "COVERAGE_LEAK_BASE_PENALTY",
            "COVERAGE_LEAK_QUOTIENT",
            "COVERAGE_LEAK_ACTIVATION_MISSES",
            "HONESTY_CURVE_HONEST_TRACK_THRESHOLD",
            "HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM",
            "HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN",
        ):
            self._saved[name] = getattr(config, name)

    def tearDown(self):
        for name, val in self._saved.items():
            setattr(config, name, val)

    def _bc(self, *, track_blocks=0, track_atts=0, priors=0, height=10_000):
        """Build a stripped-down Blockchain mock the honesty-curve
        helpers will consume.  Mirrors the shape used in
        ``test_honesty_curve_*`` tests."""
        bc = MagicMock()
        bc.proposer_sig_counts = {b"V": track_blocks}
        bc.reputation = {b"V": track_atts}
        bc.slash_offense_counts = {b"V": priors}
        bc.height = height
        return bc


class TestActivationHeightConstant(_Base):
    """Tier 55 activation height must exist and follow Tier 54
    (DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT)."""

    def test_constant_present_and_above_tier_54(self):
        self.assertTrue(
            hasattr(config, "INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT"),
            "INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT must be defined; "
            "Tier 55 hard-fork gate.",
        )
        self.assertGreater(
            config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT,
            config.DORMANCY_CONTROLLER_K_DEN_RETUNE_HEIGHT,
            "Tier 55 must follow Tier 54 -- operators upgrade through "
            "Tier 54 before this consensus-rule change binds.",
        )


class TestReliefMultiplierShape(_Base):
    """`honest_history_relief_multiplier_bps` -- the new helper that
    grades inactivity / coverage leak per validator."""

    def test_no_priors_no_track_full_penalty(self):
        from messagechain.consensus.honesty_curve import (
            honest_history_relief_multiplier_bps,
        )
        bc = self._bc(track_blocks=0, track_atts=0, priors=0)
        # Fresh validator -- no relief.
        self.assertEqual(
            honest_history_relief_multiplier_bps(bc, b"V"),
            10_000,
            "Fresh validator with no track record must pay full "
            "nominal penalty.",
        )

    def test_priors_disable_relief(self):
        from messagechain.consensus.honesty_curve import (
            honest_history_relief_multiplier_bps,
        )
        # High track record, but with priors: no relief.
        bc = self._bc(
            track_blocks=10_000, track_atts=10_000, priors=1,
        )
        self.assertEqual(
            honest_history_relief_multiplier_bps(bc, b"V"),
            10_000,
            "Repeat offenders must pay full nominal penalty -- no "
            "track-record relief for prior >= 1.",
        )

    def test_long_tenured_no_priors_capped_at_floor(self):
        from messagechain.consensus.honesty_curve import (
            honest_history_relief_multiplier_bps,
        )
        # track way past HONEST_TRACK_THRESHOLD; floor binds.
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=0,
        )
        bps = honest_history_relief_multiplier_bps(bc, b"V")
        # Floor is FLOOR_NUM/FLOOR_DEN = 1/5 = 2000 bps.
        expected = (
            config.HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
            * 10_000
            // config.HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
        )
        self.assertEqual(bps, expected)
        self.assertLessEqual(
            bps, 2_500,
            "Long-tenured high-honesty operator must see substantial "
            "relief (no more than ~25% of nominal at the floor).",
        )

    def test_under_threshold_no_relief(self):
        from messagechain.consensus.honesty_curve import (
            honest_history_relief_multiplier_bps,
        )
        # track_record below HONEST_TRACK_THRESHOLD -> no relief.
        # _track_record weights blocks > attestations, so a few of
        # each may still cross threshold; pick numbers safely below.
        bc = self._bc(track_blocks=0, track_atts=10, priors=0)
        self.assertEqual(
            honest_history_relief_multiplier_bps(bc, b"V"),
            10_000,
            "Under-threshold validator pays full nominal penalty.",
        )


class TestInactivityLeakHonestyGated(_Base):
    """`apply_inactivity_leak` consults the honesty curve only at/above
    INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT.  Pre-fork: byte-identical to
    legacy."""

    def setUp(self):
        super().setUp()
        # Inactivity leak fires when blocks_since_finality >
        # INACTIVITY_LEAK_ACTIVATION_THRESHOLD.  Pick generous params
        # so the per-validator penalty is unambiguously > 0.
        self.STALL = 10_000  # well past activation, big quadratic
        config.INACTIVITY_BASE_PENALTY = 1
        config.INACTIVITY_PENALTY_QUOTIENT = 1  # huge per-block penalty
        config.INACTIVITY_LEAK_ACTIVATION_THRESHOLD = 4

    def test_pre_fork_no_relief(self):
        """Below INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT, the long-tenured
        high-honesty validator is bled identically to the cartel.
        Compares against the legacy compute_inactivity_penalty output
        (which caps at min(penalty, stake)) to avoid hard-coding the
        saturation level."""
        from messagechain.consensus.inactivity import (
            apply_inactivity_leak, compute_inactivity_penalty,
        )

        starting_stake = 1_000_000_000
        nominal = compute_inactivity_penalty(self.STALL, starting_stake)
        self.assertGreater(nominal, 0)

        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=0,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT - 1,
        )
        burned, _ = apply_inactivity_leak(
            staked,
            blocks_since_finality=self.STALL,
            inactive_validators={b"V"},
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        self.assertEqual(burned, nominal)

    def test_post_fork_long_tenured_relief_applied(self):
        """At/above the activation height, a long-tenured high-honesty
        validator pays a fraction of nominal -- the relief floor."""
        from messagechain.consensus.inactivity import (
            apply_inactivity_leak,
            compute_inactivity_penalty,
        )

        # Use a smaller quadratic so we can observe scaling vs cap.
        config.INACTIVITY_PENALTY_QUOTIENT = 1_000_000
        starting_stake = 1_000_000
        nominal = compute_inactivity_penalty(self.STALL, starting_stake)
        self.assertGreater(nominal, 0, "test setup: nominal must be > 0")

        # Long-tenured high-honesty validator -> relief multiplier of
        # FLOOR_NUM/FLOOR_DEN = 1/5 = 2000 bps.
        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=0,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT + 1,
        )
        burned, _ = apply_inactivity_leak(
            staked,
            blocks_since_finality=self.STALL,
            inactive_validators={b"V"},
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        expected_relief_bps = (
            config.HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
            * 10_000
            // config.HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
        )
        expected_burn = nominal * expected_relief_bps // 10_000
        self.assertEqual(
            burned, expected_burn,
            "Long-tenured validator must pay only relief-multiplied "
            f"penalty: {expected_burn}, got {burned}.",
        )
        self.assertLess(
            burned, nominal,
            "Post-fork long-tenured operator MUST pay strictly less "
            "than the pre-fork nominal -- that's the whole anchor.",
        )

    def test_post_fork_fresh_validator_full_penalty(self):
        """Fresh validator: post-fork, pays full nominal (no relief)."""
        from messagechain.consensus.inactivity import (
            apply_inactivity_leak,
            compute_inactivity_penalty,
        )
        config.INACTIVITY_PENALTY_QUOTIENT = 1_000_000
        starting_stake = 1_000_000
        nominal = compute_inactivity_penalty(self.STALL, starting_stake)

        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=0, track_atts=0, priors=0,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT + 1,
        )
        burned, _ = apply_inactivity_leak(
            staked,
            blocks_since_finality=self.STALL,
            inactive_validators={b"V"},
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        self.assertEqual(burned, nominal)

    def test_post_fork_priors_no_relief(self):
        """Validator with prior offenses: no relief even with high
        track record.  Repeat offenders pay full nominal."""
        from messagechain.consensus.inactivity import (
            apply_inactivity_leak,
            compute_inactivity_penalty,
        )
        config.INACTIVITY_PENALTY_QUOTIENT = 1_000_000
        starting_stake = 1_000_000
        nominal = compute_inactivity_penalty(self.STALL, starting_stake)

        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=1,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT + 1,
        )
        burned, _ = apply_inactivity_leak(
            staked,
            blocks_since_finality=self.STALL,
            inactive_validators={b"V"},
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        self.assertEqual(
            burned, nominal,
            "Repeat-offender validator must pay full nominal post-fork.",
        )


class TestCoverageLeakHonestyGated(_Base):
    """Same shape applies to apply_coverage_leak: post-fork, long-
    tenured high-honesty operators pay fractional, repeat offenders
    and fresh validators pay full."""

    def test_post_fork_long_tenured_relief(self):
        from messagechain.consensus.inactivity import (
            apply_coverage_leak,
            compute_coverage_penalty,
        )
        # Build a fake inclusion list with one tx the validator missed.
        inc_list = MagicMock()
        entry = MagicMock()
        entry.tx_hash = b"\x01" * 32
        inc_list.entries = [entry]
        # No reports from V at all -- treated as full miss.
        inc_list.quorum_attestation = []

        config.COVERAGE_LEAK_QUOTIENT = 1
        config.COVERAGE_LEAK_ACTIVATION_MISSES = 0

        starting_stake = 1_000_000
        # Pre-charge counter so a single call escalates above threshold.
        misses_counter = {b"V": 5}
        nominal_consec = misses_counter[b"V"] + 1  # bumped this cycle
        nominal = compute_coverage_penalty(starting_stake, nominal_consec)
        self.assertGreater(nominal, 0)

        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=0,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT + 1,
        )
        burned, _ = apply_coverage_leak(
            staked,
            misses_counter,
            active_attesters={b"V"},
            inclusion_list=inc_list,
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        expected_relief_bps = (
            config.HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
            * 10_000
            // config.HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
        )
        expected_burn = nominal * expected_relief_bps // 10_000
        self.assertEqual(burned, expected_burn)
        self.assertLess(burned, nominal)

    def test_pre_fork_no_relief(self):
        from messagechain.consensus.inactivity import (
            apply_coverage_leak,
            compute_coverage_penalty,
        )
        inc_list = MagicMock()
        entry = MagicMock()
        entry.tx_hash = b"\x01" * 32
        inc_list.entries = [entry]
        inc_list.quorum_attestation = []

        config.COVERAGE_LEAK_QUOTIENT = 1
        config.COVERAGE_LEAK_ACTIVATION_MISSES = 0

        starting_stake = 1_000_000
        misses_counter = {b"V": 5}
        nominal_consec = misses_counter[b"V"] + 1
        nominal = compute_coverage_penalty(starting_stake, nominal_consec)

        staked = {b"V": starting_stake}
        bc = self._bc(
            track_blocks=100_000, track_atts=100_000, priors=0,
            height=config.INACTIVITY_LEAK_HONESTY_CURVE_HEIGHT - 1,
        )
        burned, _ = apply_coverage_leak(
            staked,
            misses_counter,
            active_attesters={b"V"},
            inclusion_list=inc_list,
            min_stake=0,
            current_height=bc.height,
            blockchain=bc,
        )
        self.assertEqual(
            burned, nominal,
            "Pre-fork: byte-identical to legacy, no relief applied.",
        )


class TestBackCompatLegacyCallSignature(_Base):
    """Pre-fork callers (and tests) should keep working without passing
    current_height/blockchain -- the new args MUST default to None and
    the legacy bleed must be byte-identical to before."""

    def test_apply_inactivity_leak_legacy_call_unchanged(self):
        from messagechain.consensus.inactivity import (
            apply_inactivity_leak, compute_inactivity_penalty,
        )

        config.INACTIVITY_BASE_PENALTY = 1
        config.INACTIVITY_PENALTY_QUOTIENT = 1
        config.INACTIVITY_LEAK_ACTIVATION_THRESHOLD = 4

        starting_stake = 1_000_000_000
        nominal = compute_inactivity_penalty(10_000, starting_stake)
        staked = {b"V": starting_stake}
        # Legacy 4-arg call (no current_height, no blockchain).
        burned, _ = apply_inactivity_leak(
            staked,
            blocks_since_finality=10_000,
            inactive_validators={b"V"},
            min_stake=0,
        )
        self.assertEqual(burned, nominal)

    def test_apply_coverage_leak_legacy_call_unchanged(self):
        from messagechain.consensus.inactivity import apply_coverage_leak

        config.COVERAGE_LEAK_QUOTIENT = 1
        config.COVERAGE_LEAK_ACTIVATION_MISSES = 0

        inc_list = MagicMock()
        entry = MagicMock()
        entry.tx_hash = b"\x01" * 32
        inc_list.entries = [entry]
        inc_list.quorum_attestation = []

        staked = {b"V": 1_000_000}
        misses_counter = {b"V": 5}
        # Legacy call (no current_height, no blockchain).
        burned, _ = apply_coverage_leak(
            staked,
            misses_counter,
            active_attesters={b"V"},
            inclusion_list=inc_list,
            min_stake=0,
        )
        self.assertGreater(
            burned, 0,
            "Legacy call shape must still produce a burn -- "
            "back-compat for pre-fork callers and existing tests.",
        )


if __name__ == "__main__":
    unittest.main()
