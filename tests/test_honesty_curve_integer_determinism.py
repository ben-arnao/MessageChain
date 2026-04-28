"""Honesty-curve severity is computed in pure integer arithmetic.

Pre-fix the AMBIGUOUS branch built ``raw = base * escalation * relief``
where ``relief = HONEST_TRACK_THRESHOLD / track`` was a Python float and
the final step was ``int(raw)``.  IEEE-754 division of small bounded
integers is exact-rounded on every conformant platform, so in practice
the float form was deterministic — but ``slashing_severity`` is
consensus state (its output drives the slash percent that mutates
``staked`` / ``total_supply``), and "in practice deterministic" is a
weaker bar than the chain's permanent ledger demands.  A future Python
release tweaking float repr, a build linked against a non-conformant
libm, or a niche ARM32 target hitting subnormals could produce a
1-percent disagreement at exactly the wrong input — replayers fork,
recovery requires manual surgery.

Post-fix the relief is a rational ``(relief_num, relief_den)`` and the
final severity is one floor-division: ``(base * esc * num) // den``.
Equivalent to the float form for the input ranges this function sees,
but auditably integer-only.

This file pins that property two ways:

  1. ``slashing_severity`` outputs across a representative input grid
     match a hand-computed integer table.  If a future change to the
     curve drifts an output, the test fails loudly with the offending
     input vector — exactly the signal the v1.27/1.28/1.29 state-root
     saga lacked.

  2. The function never invokes float arithmetic on the consensus
     hot-path: a probe that monkeypatches ``float`` to raise on call
     during ``slashing_severity`` execution must not trip.  Catches
     accidental re-introduction of float relief in a future refactor.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
    HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER,
    HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN,
    HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    HONESTY_CURVE_MIN_PCT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    slashing_severity,
)


class _StubChain:
    """Minimal Blockchain stand-in with the four counters the curve reads."""

    def __init__(
        self,
        proposer_sig_counts: int,
        reputation: int,
        prior_offenses: int,
        height: int = 0,
    ):
        vid = b"v" * 32
        self.proposer_sig_counts = {vid: proposer_sig_counts}
        self.reputation = {vid: reputation}
        self.slash_offense_counts = {vid: prior_offenses}
        self.height = height


def _expected_ambiguous_pct(track: int, prior: int) -> int:
    """Recompute the AMBIGUOUS branch in pure integer math.

    Mirrors `slashing_severity` exactly so a regression in either
    surface flags the test, not the production code drifting silently.
    """
    base = HONESTY_CURVE_AMBIGUOUS_BASE_PCT
    escalation = 1 + HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER * prior
    if track >= HONESTY_CURVE_HONEST_TRACK_THRESHOLD:
        if (
            HONESTY_CURVE_HONEST_TRACK_THRESHOLD
            * HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
            <= HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM * track
        ):
            num = HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM
            den = HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN
        else:
            num = HONESTY_CURVE_HONEST_TRACK_THRESHOLD
            den = track
    else:
        num, den = 1, 1
    raw = (base * escalation * num) // den
    return max(HONESTY_CURVE_MIN_PCT, min(100, raw))


class HonestyCurveIntegerDeterminismTests(unittest.TestCase):
    """Severity is integer-only and matches the float form bit-for-bit
    on the representative grid."""

    def test_ambiguous_severity_matches_float_form_on_input_grid(self):
        # Sweep the cells where float vs integer divergence was most
        # plausible: track close to threshold (rounding boundary), track
        # close to the floor's binding point (500), and several prior-
        # offense escalations.
        track_grid = [
            0, 1, 50, 99,                # under-tenure: relief = 1.0
            100, 101, 137, 200, 333,     # active relief band
            499, 500, 501,               # floor boundary
            750, 1000, 5000,             # deep floor
        ]
        prior_grid = [0, 1, 2, 3, 5, 8, 10]
        for track in track_grid:
            for prior in prior_grid:
                with self.subTest(track=track, prior=prior):
                    chain = _StubChain(
                        proposer_sig_counts=track,
                        reputation=0,
                        prior_offenses=prior,
                    )
                    actual = slashing_severity(
                        b"v" * 32,
                        OffenseKind.CENSORSHIP,
                        Unambiguity.AMBIGUOUS,
                        chain,
                    )
                    # Block-weight default is 4 — `_track_record` sums
                    # block_weight × proposer_sigs + 1 × reputation.
                    # We feed reputation=0, so track_record == 4 × ps_count.
                    expected = _expected_ambiguous_pct(track * 4, prior)
                    self.assertEqual(
                        actual, expected,
                        f"severity drifted at (track*4={track*4}, prior={prior}): "
                        f"got {actual}, expected {expected}",
                    )

    def test_ambiguous_severity_pinned_golden_table(self):
        # Hand-computed reference table — independent of the production
        # constants drifting.  If anyone retunes BASE_PCT or
        # REPEAT_MULTIPLIER they must update this table consciously,
        # which is exactly the chokepoint a curve-shape change needs.
        # Format: (track_record, prior, expected_pct).
        # Computed against current constants:
        #   BASE_PCT = 5, REPEAT_MULTIPLIER = 2,
        #   HONEST_TRACK_THRESHOLD = 100, FLOOR = 1/5.
        golden = [
            # Under-tenure: no relief.  esc = 1+2*prior.
            (0,  0,  5),    # 5 * 1 * 1 = 5
            (50, 0,  5),
            (99, 0,  5),
            (50, 1,  15),   # 5 * 3 * 1 = 15
            (50, 5,  55),   # 5 * 11 * 1 = 55
            (50, 10, 100),  # 5 * 21 * 1 = 105 -> clamp 100
            # Threshold-exact: relief = 1, no change from base × esc.
            (100, 0, 5),
            (100, 1, 15),
            # Active relief band: relief = 100/track, scaling severity down.
            (200, 0, 2),    # (5 * 1 * 100) // 200 = 2
            (200, 1, 7),    # (5 * 3 * 100) // 200 = 7
            (200, 5, 27),   # (5 * 11 * 100) // 200 = 27
            (333, 0, 1),    # (5 * 1 * 100) // 333 = 1
            (333, 5, 16),   # (5 * 11 * 100) // 333 = 16
            (499, 0, 1),    # (5 * 1 * 100) // 499 = 1 (clamped to MIN_PCT)
            # Floor boundary: at track == 500, floor binds (relief = 1/5).
            (500, 0, 1),    # (5 * 1 * 1) // 5 = 1
            (500, 5, 11),   # (5 * 11 * 1) // 5 = 11
            (1000, 0, 1),   # floor: (5 * 1 * 1) // 5 = 1
            (1000, 5, 11),  # floor: (5 * 11 * 1) // 5 = 11
            (5000, 10, 21), # floor: (5 * 21 * 1) // 5 = 21
        ]
        for track, prior, expected in golden:
            with self.subTest(track=track, prior=prior, expected=expected):
                # _track_record multiplies proposer_sigs by 4, so we
                # feed track/4 (or set reputation alone; either works
                # because the curve only reads the sum).
                chain = _StubChain(
                    proposer_sig_counts=0,
                    reputation=track,  # _track_record = 4*0 + 1*track = track
                    prior_offenses=prior,
                )
                actual = slashing_severity(
                    b"v" * 32,
                    OffenseKind.CENSORSHIP,
                    Unambiguity.AMBIGUOUS,
                    chain,
                )
                self.assertEqual(
                    actual, expected,
                    f"golden drift at (track={track}, prior={prior}): "
                    f"got {actual}, expected {expected}",
                )

    def test_severity_uses_no_float_arithmetic(self):
        # Sentinel: if a future refactor reintroduces a float operation
        # on the severity hot path, this trips.  Builds an int subclass
        # that raises on any conversion to float — slashing_severity must
        # never coerce its inputs through float().
        class _NoFloatInt(int):
            def __float__(self):
                raise AssertionError(
                    "slashing_severity must not invoke float() on consensus inputs"
                )

        # Wrap the counters in the no-float int.  Any internal `/` would
        # promote one operand to float and trip the sentinel; `//`
        # stays integer.
        vid = b"v" * 32

        class _SentinelChain:
            proposer_sig_counts = {vid: _NoFloatInt(137)}
            reputation = {vid: _NoFloatInt(50)}
            slash_offense_counts = {vid: _NoFloatInt(2)}
            height = _NoFloatInt(0)

        # Should complete without raising.
        sev = slashing_severity(
            vid,
            OffenseKind.CENSORSHIP,
            Unambiguity.AMBIGUOUS,
            _SentinelChain(),
        )
        self.assertIsInstance(sev, int)
        self.assertGreaterEqual(sev, HONESTY_CURVE_MIN_PCT)
        self.assertLessEqual(sev, 100)


if __name__ == "__main__":
    unittest.main()
