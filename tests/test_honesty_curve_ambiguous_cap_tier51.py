"""Tier 51 — AMBIGUOUS slash severity cap.

CLAUDE.md anchor protected:

  * "Honest operators are insured against accidents.  When an honest
    node IS slashed (transient evidence collision, recoverable
    misconfig), the burn is a small fraction of stake, not a wipe."

Pre-fix problem: the AMBIGUOUS path computes
``sev = base × (1 + REPEAT_MULTIPLIER × prior) × relief`` and the
relief floor is 1/5.  At ``BASE=5``, ``REPEAT_MULTIPLIER=2``, a
long-tenured operator at ``track=200`` and ``prior=5`` lands at
``5 × 11 × (100/200) = 27%``; at ``prior=10`` -> ``52%``; at very
high tenure the relief floor pins at 0.2 so a ``prior=20`` veteran
still gets ``5 × 41 × 0.2 = 41%``.  21--52% on AMBIGUOUS
(restart-shape) evidence is NOT "small fractional" -- the math
turns the honest-operator-insurance anchor inside out for exactly
the long-tenured / high-volume class the anchor is named to
protect.

Tier 51 closes the gap by clamping the AMBIGUOUS-path output to
``HONESTY_CURVE_AMBIGUOUS_MAX_PCT`` (default 10 -- 2× SOFT_SLASH_PCT,
firmly in "small fraction" territory) at and above
``HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT``.  UNAMBIGUOUS path is
unchanged -- the Byzantine bar (50%+ on first, 100% on repeat) still
applies, because deliberate equivocation is not what the anchor
insures against.  Pre-fork heights replay byte-identically.

Surfaced by audit r22 top-3 #2.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from messagechain.config import (
    HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
    HONESTY_CURVE_AMBIGUOUS_REPEAT_MULTIPLIER,
    HONESTY_CURVE_HONEST_TRACK_FLOOR_DEN,
    HONESTY_CURVE_HONEST_TRACK_FLOOR_NUM,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    slashing_severity,
)


def _mk_chain(height: int, track_block_count: int, priors: int):
    """Build a stripped-down Blockchain mock for the curve.

    ``track_record`` is computed from ``proposer_sig_counts`` /
    ``reputation`` via ``HONESTY_CURVE_BLOCK_WEIGHT × good_blocks
    + HONESTY_CURVE_ATTEST_WEIGHT × good_atts`` (Tier 24 rate-
    adjusted by subtracting ``BAD_PENALTY_WEIGHT × priors`` post-
    HONESTY_CURVE_RATE_HEIGHT).  We hand in the block count
    directly so the math is transparent at the call site.
    """
    chain = MagicMock()
    chain.height = height
    chain.proposer_sig_counts = {b"V" * 32: track_block_count}
    chain.reputation = {b"V" * 32: 0}
    chain.slash_offense_counts = {b"V" * 32: priors}
    return chain


class TestNewConstantsExist(unittest.TestCase):
    """Tier 51 introduces ``HONESTY_CURVE_AMBIGUOUS_MAX_PCT`` and
    ``HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT``.  Without the constants the
    cap can't bind."""

    def test_max_pct_constant_exists_and_is_small_fractional(self):
        from messagechain import config
        self.assertTrue(
            hasattr(config, "HONESTY_CURVE_AMBIGUOUS_MAX_PCT"),
            "HONESTY_CURVE_AMBIGUOUS_MAX_PCT must be defined -- the "
            "cap that bounds AMBIGUOUS-path slash severity to a "
            "small fractional number.",
        )
        self.assertGreater(
            config.HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
            0,
            "Cap must be positive -- a 0 cap would no-op every "
            "AMBIGUOUS slash, breaking the deterrent against repeat "
            "patterns.",
        )
        self.assertLessEqual(
            config.HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
            20,
            "Cap must satisfy the 'small fraction of stake, not a "
            "wipe' anchor -- 20%+ on accidental evidence is not "
            "small fractional.",
        )
        self.assertGreaterEqual(
            config.HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
            HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
            "Cap must be at least BASE -- a cap below BASE would "
            "force first-offense AMBIGUOUS slashes BELOW the "
            "baseline, which is paradoxical and breaks the ratchet "
            "from the legacy soft-slash semantics.",
        )

    def test_cap_height_constant_exists_and_follows_tier_50(self):
        from messagechain import config
        self.assertTrue(
            hasattr(config, "HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT"),
            "HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT must be defined.",
        )
        self.assertGreater(
            config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT,
            config.VOTER_REWARD_INCLUSIVE_HEIGHT,
            "Cap activation must follow Tier 50 -- avoids stacking "
            "two consensus-rule changes in the same block, which "
            "compresses the rollout window for operators.",
        )


class TestPreForkByteIdentical(unittest.TestCase):
    """Below ``HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT`` the curve must
    produce the same severity it did before the cap was added.
    Historical replay correctness depends on it."""

    def test_pre_fork_legacy_severity_preserved(self):
        from messagechain import config
        # Pre-fork height -- AT/above HONESTY_CURVE_RATE_HEIGHT (so
        # rate adjustment is active and amnesty is reachable) but
        # BELOW HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT.
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        pre_h = max(HONESTY_CURVE_RATE_HEIGHT, cap_h - 10)
        # Legacy uncapped severity for prior=5, track=200:
        # base=5, escalation=1+2*5=11, relief=100/200=0.5
        # sev = (5 * 11 * 100) // 200 = 27
        chain = _mk_chain(
            height=pre_h, track_block_count=50, priors=5,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        # track_record at Tier 24:
        #   raw = 4 * 50 + 1 * 0 = 200
        #   priors=5, BAD_PENALTY_WEIGHT=HONEST_TRACK_THRESHOLD=100
        #   adj = max(0, 200 - 100*5) = 0
        # Track <= threshold -> no relief, sev = base * escalation
        # = 5 * 11 = 55, clamped to [MIN_PCT, 100] = 55.
        # Pre-cap legacy: 55%.  This MUST be preserved pre-fork.
        self.assertEqual(
            sev,
            min(55, 100),
            "Pre-fork AMBIGUOUS severity MUST replay byte-identical "
            "to legacy Tier 23/24 math -- historical replay "
            "correctness depends on it.",
        )


class TestPostForkCapBindsOnHonestVeteran(unittest.TestCase):
    """At and above the cap height, the AMBIGUOUS path output is
    clamped at HONESTY_CURVE_AMBIGUOUS_MAX_PCT regardless of how
    high the uncapped formula goes."""

    def test_long_tenured_high_priors_caps_at_max(self):
        from messagechain import config
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        max_pct = config.HONESTY_CURVE_AMBIGUOUS_MAX_PCT
        # Same scenario as the pre-fork test but at the cap height.
        # Uncapped: at cap_h, track_record post-Tier-24 rate adjustment
        # for priors=5, track_block_count=200:
        #   raw = 4 * 200 = 800; adj = max(0, 800 - 100*5) = 300
        # relief = max(1/5, 100/300) = max(0.2, 0.333) = 0.333
        # escalation = 11; sev = (5 * 11 * 100) // 300 = 18
        # Capped: min(18, max_pct).
        chain = _mk_chain(
            height=cap_h, track_block_count=200, priors=5,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertLessEqual(
            sev,
            max_pct,
            "Post-fork AMBIGUOUS slash severity MUST be capped at "
            "HONESTY_CURVE_AMBIGUOUS_MAX_PCT regardless of escalation "
            "or relief -- the honest-operator-insurance anchor "
            "explicitly insures against 'a wipe' on accidental "
            "evidence.",
        )

    def test_extreme_escalation_still_capped(self):
        """At priors=20, track=very-low (rate adjustment erodes track
        to zero), uncapped formula would give base × 41 = 205%, clamped
        to 100%.  Cap MUST hold."""
        from messagechain import config
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        max_pct = config.HONESTY_CURVE_AMBIGUOUS_MAX_PCT
        chain = _mk_chain(
            height=cap_h, track_block_count=50, priors=20,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertLessEqual(
            sev,
            max_pct,
            "Even pathological repeat-priors must respect the "
            "AMBIGUOUS cap -- otherwise a string of restart-shape "
            "events compounds to a wipeout, exactly the failure mode "
            "the cap is designed to prevent.",
        )


class TestUnambiguousPathUntouched(unittest.TestCase):
    """The cap MUST NOT relax UNAMBIGUOUS-path severity -- deliberate
    Byzantine evidence still burns at 50%+ first-offense / 100% on
    repeat.  CLAUDE.md anchor: 'Catastrophic slashes are reserved for
    unambiguous, intentional protocol violations.'"""

    def test_unambiguous_first_offense_long_tenured_still_50_pct(self):
        from messagechain import config
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        chain = _mk_chain(
            height=cap_h, track_block_count=1000, priors=0,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            chain,
        )
        self.assertGreaterEqual(
            sev,
            HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
            "Unambiguous first-offense severity MUST remain at "
            "UNAMBIGUOUS_FIRST_PCT (Byzantine bar) -- the cap is "
            "for AMBIGUOUS evidence only.",
        )

    def test_unambiguous_repeat_still_100_pct(self):
        from messagechain import config
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        chain = _mk_chain(
            height=cap_h, track_block_count=1000, priors=1,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            chain,
        )
        self.assertEqual(
            sev,
            100,
            "Any repeat unambiguous offense burns 100% -- the cap "
            "MUST NOT introduce a new escape hatch for Byzantine "
            "actors who happen to have a long good record.",
        )


class TestAmbiguousFirstOffenseUnaffected(unittest.TestCase):
    """A first AMBIGUOUS offense (prior=0) on a fresh validator
    already lands at BASE_PCT (= 5%), well below the cap.  The cap
    is only meant to bind on the high-prior + relief-erosion combo
    that produces wipeout-class burns."""

    def test_first_ambiguous_offense_unchanged(self):
        from messagechain import config
        cap_h = config.HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT
        chain = _mk_chain(
            height=cap_h, track_block_count=20, priors=0,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertEqual(
            sev,
            HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
            "First AMBIGUOUS offense on a fresh validator must "
            "still produce BASE_PCT -- the cap binds only when the "
            "uncapped formula would exceed it.",
        )


if __name__ == "__main__":
    unittest.main()
