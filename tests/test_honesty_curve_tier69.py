"""Tier 69 — Honesty-curve leniency refinement.

Three coupled tweaks that push the curve further toward the CLAUDE.md
"honest operators are insured against accidents" anchor without
weakening the deliberate-Byzantine bar:

  1. ``slash_offense_counts`` decay.  Every
     ``HONESTY_CURVE_DECAY_PERIOD_BLOCKS`` post-activation, every
     positive prior decrements by 1.  A single ancient slip no longer
     permanently disqualifies a validator from amnesty / honest-
     history relief.

  2. Restart-drift window widening (120s → 600s).  Honest restart
     cycles under heavy mempool / disk load can take longer than the
     legacy 120s budget; the wider window admits those into AMBIGUOUS.

  3. AMBIGUOUS-path cap tightening (10% → 3%).  Compounded restart-
     shape events should be an operational nuisance, not a multi-
     month rebuild.

Pre-Tier-69 heights replay byte-identically.  UNAMBIGUOUS path is
unchanged in all three knobs — the deliberate-Byzantine bar (50%+
first / 100% repeat) is anchored explicitly in CLAUDE.md and is not
the target of this fork.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from messagechain.config import (
    HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
    HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT,
    HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
    HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
    HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
    HONESTY_CURVE_MIN_PCT,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_RESTART_DRIFT_SECS,
    HONESTY_CURVE_RESTART_DRIFT_SECS_TIER69,
    HONESTY_CURVE_TIER69_HEIGHT,
    HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    classify_block_evidence,
    slashing_severity,
)


def _mk_chain(height: int, track_block_count: int = 0, priors: int = 0):
    """Stripped-down Blockchain mock for severity-curve tests."""
    chain = MagicMock()
    chain.height = height
    chain.proposer_sig_counts = {b"V" * 32: track_block_count}
    chain.reputation = {b"V" * 32: 0}
    chain.slash_offense_counts = {b"V" * 32: priors}
    return chain


def _mk_header(
    proposer_id: bytes = b"P" * 32,
    block_number: int = 100,
    prev_hash: bytes = b"\xaa" * 32,
    state_root: bytes = b"\xbb" * 32,
    merkle_root: bytes = b"\xcc" * 32,
    timestamp: float = 1_700_000_000.0,
    state_root_checkpoint: bytes = b"\x00" * 32,
):
    """Stripped-down BlockHeader mock for classifier tests."""
    h = MagicMock()
    h.proposer_id = proposer_id
    h.block_number = block_number
    h.prev_hash = prev_hash
    h.state_root = state_root
    h.merkle_root = merkle_root
    h.timestamp = timestamp
    h.state_root_checkpoint = state_root_checkpoint
    return h


# ─────────────────────────────────────────────────────────────────────
# Constants exist and have the expected shape
# ─────────────────────────────────────────────────────────────────────


class TestTier69ConstantsExist(unittest.TestCase):
    """Pin the new constants — without them the fork can't activate."""

    def test_activation_height_follows_tier_68(self):
        from messagechain import config
        self.assertGreater(
            config.HONESTY_CURVE_TIER69_HEIGHT,
            config.WITNESS_ACK_ISSUER_BINDING_HEIGHT,
            "Tier 69 activation must follow Tier 68 — consensus-rule "
            "activations need cohort spacing for the validator-upgrade "
            "window",
        )

    def test_decay_period_is_positive(self):
        self.assertGreater(
            HONESTY_CURVE_DECAY_PERIOD_BLOCKS, 0,
            "Decay period must be positive — a 0 period would decay "
            "every block, immediately erasing every prior and "
            "neutering the repeat-offense curve",
        )

    def test_drift_window_widens_not_narrows(self):
        self.assertGreater(
            HONESTY_CURVE_RESTART_DRIFT_SECS_TIER69,
            HONESTY_CURVE_RESTART_DRIFT_SECS,
            "Tier 69 drift window must widen the AMBIGUOUS classifier "
            "— the fork is a one-way leniency move",
        )

    def test_ambiguous_cap_tightens_not_loosens(self):
        self.assertLess(
            HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
            HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
            "Tier 69 AMBIGUOUS cap must tighten the previous cap — "
            "the fork is a one-way leniency move",
        )

    def test_ambiguous_cap_at_least_min_pct(self):
        self.assertGreaterEqual(
            HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
            HONESTY_CURVE_MIN_PCT,
            "Cap below MIN_PCT would be unreachable — the universal "
            "slash floor would clamp severity above the cap and the "
            "cap would be dead code",
        )


# ─────────────────────────────────────────────────────────────────────
# Change #1 — AMBIGUOUS-path cap tightening (10% → 3%)
# ─────────────────────────────────────────────────────────────────────


class TestPreTier69AmbiguousCapPreserved(unittest.TestCase):
    """Pre-Tier-69 the legacy 10% cap (Tier 51) still binds. Byte-
    identical historical replay is non-negotiable."""

    def test_pre_fork_cap_is_legacy_10pct(self):
        """At a height in [Tier 51, Tier 69), a pathological repeat-
        offender on AMBIGUOUS evidence caps at the legacy 10%, not 3%."""
        # Pick a height past Tier 51 but well below Tier 69.
        pre_h = max(
            HONESTY_CURVE_AMBIGUOUS_CAP_HEIGHT,
            HONESTY_CURVE_RATE_HEIGHT,
        )
        self.assertLess(
            pre_h, HONESTY_CURVE_TIER69_HEIGHT,
            "Test height must be pre-Tier-69 for this test to be "
            "meaningful",
        )
        chain = _mk_chain(
            height=pre_h, track_block_count=50, priors=20,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertEqual(
            sev, HONESTY_CURVE_AMBIGUOUS_MAX_PCT,
            f"Pre-Tier-69 AMBIGUOUS slash MUST cap at the legacy "
            f"{HONESTY_CURVE_AMBIGUOUS_MAX_PCT}% — historical replay "
            f"correctness depends on it.  Got {sev}.",
        )


class TestPostTier69AmbiguousCapTightened(unittest.TestCase):
    """At and above Tier 69, the AMBIGUOUS-path output caps at 3%."""

    def test_post_fork_cap_is_3pct(self):
        chain = _mk_chain(
            height=HONESTY_CURVE_TIER69_HEIGHT,
            track_block_count=50, priors=20,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertLessEqual(
            sev, HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
            f"Post-Tier-69 AMBIGUOUS slash MUST cap at "
            f"{HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69}% — the tighter "
            f"cap is the anchored 'small fraction, not a wipe' "
            f"property the honest-operator-insurance anchor calls for.",
        )
        # And it should actually bind, not just be <=.
        self.assertEqual(
            sev, HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
            f"At priors=20 + low track, the uncapped formula far "
            f"exceeds {HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69}; the "
            f"cap must bind exactly at the tighter value.",
        )

    def test_unambiguous_path_untouched(self):
        """The tightened cap MUST NOT relax UNAMBIGUOUS severity —
        deliberate Byzantine evidence still burns at 50%+ first /
        100% repeat."""
        chain = _mk_chain(
            height=HONESTY_CURVE_TIER69_HEIGHT,
            track_block_count=1000, priors=0,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            chain,
        )
        self.assertGreaterEqual(
            sev, HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
            "Tier 69 cap MUST be AMBIGUOUS-only — deliberate evidence "
            "still hits the UNAMBIGUOUS_FIRST_PCT floor.",
        )

    def test_unambiguous_repeat_still_100_pct(self):
        chain = _mk_chain(
            height=HONESTY_CURVE_TIER69_HEIGHT,
            track_block_count=1000, priors=1,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            chain,
        )
        self.assertEqual(
            sev, 100,
            "Any UNAMBIGUOUS repeat MUST still burn 100% — the "
            "tightened AMBIGUOUS cap does NOT introduce a Byzantine "
            "escape hatch.",
        )

    def test_first_ambiguous_offense_below_cap_unchanged(self):
        """A first AMBIGUOUS offense already lands at BASE (5%) on a
        fresh validator — that's HIGHER than the new 3% cap, so the
        cap binds even on first offense.  Verify the cap is enforced
        uniformly (not skipped for first-offenders)."""
        chain = _mk_chain(
            height=HONESTY_CURVE_TIER69_HEIGHT,
            track_block_count=20, priors=0,
        )
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertLessEqual(
            sev, HONESTY_CURVE_AMBIGUOUS_MAX_PCT_TIER69,
            "Tier 69 cap MUST bind uniformly, including on first "
            "AMBIGUOUS offenses — small-fractional means small for "
            "EVERY offense on the AMBIGUOUS path.",
        )


# ─────────────────────────────────────────────────────────────────────
# Change #2 — Restart-drift window widening (120s → 600s)
# ─────────────────────────────────────────────────────────────────────


class TestDriftWindowPreTier69(unittest.TestCase):
    """Pre-Tier-69 the 120s window still applies.  Headers with drift
    in (120s, 600s] classify as UNAMBIGUOUS pre-fork."""

    def test_drift_120s_or_less_is_ambiguous_pre_fork(self):
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_120.0, merkle_root=b"\xdd" * 32)
        # current_height=0 -> pre-fork classifier path.
        self.assertEqual(
            classify_block_evidence(h_a, h_b, current_height=0),
            Unambiguity.AMBIGUOUS,
            "120s drift is exactly the legacy boundary — must be "
            "AMBIGUOUS pre-fork.",
        )

    def test_drift_200s_unambiguous_pre_fork(self):
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_200.0, merkle_root=b"\xdd" * 32)
        self.assertEqual(
            classify_block_evidence(h_a, h_b, current_height=0),
            Unambiguity.UNAMBIGUOUS,
            "Pre-Tier-69 200s drift must be UNAMBIGUOUS — historical "
            "replay correctness depends on the 120s window.",
        )

    def test_drift_200s_unambiguous_at_tier69_minus_one(self):
        """Crispening the activation boundary: one block BEFORE Tier
        69 must still use the 120s window."""
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_200.0, merkle_root=b"\xdd" * 32)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT - 1,
            ),
            Unambiguity.UNAMBIGUOUS,
            "One block before Tier 69 activation, the legacy 120s "
            "window must still bind.",
        )


class TestDriftWindowPostTier69(unittest.TestCase):
    """At/after Tier 69 the 600s window applies.  Headers with drift
    in (120s, 600s] now classify as AMBIGUOUS."""

    def test_drift_200s_ambiguous_post_fork(self):
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_200.0, merkle_root=b"\xdd" * 32)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT,
            ),
            Unambiguity.AMBIGUOUS,
            "Post-Tier-69 200s drift (well inside the 600s window) "
            "must be AMBIGUOUS — heavy-load restart cycles routinely "
            "exceed 120s and must not be misclassified as deliberate.",
        )

    def test_drift_at_extended_boundary_ambiguous(self):
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_600.0, merkle_root=b"\xdd" * 32)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT,
            ),
            Unambiguity.AMBIGUOUS,
            "600s drift is exactly the new boundary — must be "
            "AMBIGUOUS post-fork.",
        )

    def test_drift_beyond_extended_window_unambiguous(self):
        h_a = _mk_header(timestamp=1_700_000_000.0)
        h_b = _mk_header(timestamp=1_700_000_700.0, merkle_root=b"\xdd" * 32)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT,
            ),
            Unambiguity.UNAMBIGUOUS,
            "Drift beyond the new 600s window must STILL be "
            "UNAMBIGUOUS — Tier 69 widens but does not eliminate the "
            "deliberate-Byzantine bar.",
        )

    def test_different_state_root_still_unambiguous(self):
        """Even at the wider drift, two headers with different
        state_root are deliberate fork-choice — never AMBIGUOUS."""
        h_a = _mk_header(state_root=b"\x11" * 32, timestamp=1_700_000_000.0)
        h_b = _mk_header(state_root=b"\x22" * 32, timestamp=1_700_000_100.0)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT,
            ),
            Unambiguity.UNAMBIGUOUS,
            "Different state_root is intentional fork-choice — Tier 69 "
            "wider drift window MUST NOT relax this invariant.",
        )

    def test_different_prev_hash_still_unambiguous(self):
        h_a = _mk_header(prev_hash=b"\x11" * 32, timestamp=1_700_000_000.0)
        h_b = _mk_header(prev_hash=b"\x22" * 32, timestamp=1_700_000_100.0)
        self.assertEqual(
            classify_block_evidence(
                h_a, h_b, current_height=HONESTY_CURVE_TIER69_HEIGHT,
            ),
            Unambiguity.UNAMBIGUOUS,
            "Different prev_hash is intentional parent-choice — Tier 69 "
            "wider drift window MUST NOT relax this invariant.",
        )


# ─────────────────────────────────────────────────────────────────────
# Change #3 — slash_offense_counts decay
# ─────────────────────────────────────────────────────────────────────


class TestDecaySweepHelper(unittest.TestCase):
    """``_apply_slash_offense_decay`` is the consensus chokepoint for
    the decay logic.  Tests use ``Blockchain.__new__`` to construct
    a minimal instance and exercise the helper directly."""

    def _make_chain(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain.__new__(Blockchain)
        chain.slash_offense_counts = {}
        chain.db = None  # No chaindb mirror in test
        return chain

    def test_no_op_pre_activation(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 3, b"B" * 32: 1}
        # Pre-Tier-69 height — even at a multiple of DECAY_PERIOD.
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT - 1,
        )
        self.assertEqual(
            chain.slash_offense_counts,
            {b"A" * 32: 3, b"B" * 32: 1},
            "Decay sweep MUST be no-op pre-activation — byte-identical "
            "historical replay.",
        )

    def test_no_op_at_activation_height(self):
        """The activation block itself does NOT decay.  Decay starts
        DECAY_PERIOD blocks later."""
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 3}
        chain._apply_slash_offense_decay(HONESTY_CURVE_TIER69_HEIGHT)
        self.assertEqual(
            chain.slash_offense_counts, {b"A" * 32: 3},
            "Activation block must NOT decay — the first decay event "
            "fires DECAY_PERIOD blocks past activation.",
        )

    def test_no_op_at_non_period_heights(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 3}
        # Mid-period — not a decay boundary.
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT + 1,
        )
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT
            + HONESTY_CURVE_DECAY_PERIOD_BLOCKS // 2,
        )
        self.assertEqual(
            chain.slash_offense_counts, {b"A" * 32: 3},
            "Decay sweep MUST fire only at period boundaries, not "
            "every block — the curve is supposed to take a real "
            "amount of clean operation to recover.",
        )

    def test_fires_at_first_period_boundary(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 3, b"B" * 32: 1}
        # First decay event: exactly DECAY_PERIOD past activation.
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT
            + HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
        )
        self.assertEqual(
            chain.slash_offense_counts,
            {b"A" * 32: 2, b"B" * 32: 0},
            "First decay sweep at activation+DECAY_PERIOD must "
            "decrement every positive entry by 1 — honest-operator "
            "recovery path.",
        )

    def test_zero_clamp_no_underflow(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 0}
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT
            + HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
        )
        self.assertEqual(
            chain.slash_offense_counts, {b"A" * 32: 0},
            "Decay on a clean validator (priors=0) MUST be a no-op — "
            "the clamp at 0 prevents underflow and avoids spurious "
            "chaindb writes.",
        )

    def test_repeated_sweeps_recover_high_priors(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 4}
        # Three full periods elapse, sweep fires each boundary.
        for k in range(1, 5):
            chain._apply_slash_offense_decay(
                HONESTY_CURVE_TIER69_HEIGHT
                + k * HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
            )
        self.assertEqual(
            chain.slash_offense_counts, {b"A" * 32: 0},
            "Four clean periods MUST fully recover a 4-prior validator "
            "— recovery rate is 1 prior per DECAY_PERIOD_BLOCKS.",
        )

    def test_repeated_sweeps_keep_clamping(self):
        chain = self._make_chain()
        chain.slash_offense_counts = {b"A" * 32: 1}
        # Two periods of clean operation: 1 → 0, then stays at 0.
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT
            + HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
        )
        chain._apply_slash_offense_decay(
            HONESTY_CURVE_TIER69_HEIGHT
            + 2 * HONESTY_CURVE_DECAY_PERIOD_BLOCKS,
        )
        self.assertEqual(
            chain.slash_offense_counts, {b"A" * 32: 0},
        )


class TestBumpClampAtZero(unittest.TestCase):
    """``_bump_slash_offense_count`` must clamp at 0 to support
    negative-delta calls from the decay sweep without underflow."""

    def test_positive_delta_increments(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain.__new__(Blockchain)
        chain.slash_offense_counts = {b"V" * 32: 2}
        chain.db = None
        result = chain._bump_slash_offense_count(b"V" * 32, delta=1)
        self.assertEqual(result, 3)
        self.assertEqual(chain.slash_offense_counts[b"V" * 32], 3)

    def test_negative_delta_decrements(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain.__new__(Blockchain)
        chain.slash_offense_counts = {b"V" * 32: 2}
        chain.db = None
        result = chain._bump_slash_offense_count(b"V" * 32, delta=-1)
        self.assertEqual(result, 1)

    def test_negative_delta_clamps_at_zero(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain.__new__(Blockchain)
        chain.slash_offense_counts = {b"V" * 32: 0}
        chain.db = None
        result = chain._bump_slash_offense_count(b"V" * 32, delta=-1)
        self.assertEqual(
            result, 0,
            "Negative delta on a 0 entry MUST clamp at 0 — without "
            "the clamp, the decay sweep would write negative priors "
            "and corrupt the chaindb table.",
        )
        self.assertEqual(chain.slash_offense_counts[b"V" * 32], 0)


class TestDecayInteractsCorrectlyWithSeverity(unittest.TestCase):
    """The whole point of the decay: a long-tenured validator who got
    slashed once must be able to return to amnesty / full-relief
    eligibility over time.  Severity uses the post-decay priors."""

    def test_post_decay_validator_is_amnesty_eligible(self):
        from messagechain.config import HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD
        # Long-tenured, one ancient slip — Tier 24 says amnesty only
        # applies when prior=0 AND track >= AMNESTY_THRESHOLD.
        # Without decay, prior=1 forever and amnesty is unreachable.
        # With decay, prior recovers to 0 after one period.
        chain = MagicMock()
        chain.height = (
            HONESTY_CURVE_TIER69_HEIGHT
            + HONESTY_CURVE_DECAY_PERIOD_BLOCKS
        )
        # Track far above amnesty threshold.
        chain.proposer_sig_counts = {
            b"V" * 32: HONESTY_CURVE_AMNESTY_TRACK_THRESHOLD * 4
        }
        chain.reputation = {b"V" * 32: 0}
        # Simulating "post-decay-sweep" state: validator's one slip
        # has decayed from 1 to 0.
        chain.slash_offense_counts = {b"V" * 32: 0}
        sev = slashing_severity(
            b"V" * 32,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            chain,
        )
        self.assertEqual(
            sev, 0,
            "A long-tenured validator whose single old slip has "
            "decayed must once again be amnesty-eligible (0% slash) "
            "on a restart-shape evidence — that's the whole point of "
            "the decay.",
        )


# ─────────────────────────────────────────────────────────────────────
# Pre-Tier-69 parity (catch-all regression guard)
# ─────────────────────────────────────────────────────────────────────


class TestPreForkSeverityByteIdentical(unittest.TestCase):
    """A sanity grid: for several (priors, track) combos at a height
    JUST BELOW Tier 69, severity must equal what the legacy code
    would produce.  Catches accidental drift in any of the three
    new code paths (decay, drift, cap)."""

    def test_grid_pre_fork_unchanged(self):
        # One block before Tier 69 activation.
        pre_h = HONESTY_CURVE_TIER69_HEIGHT - 1
        # (priors, track_block_count, expected_severity_pre_Tier69)
        # Calculations:
        #   raw_track = 4 * track_block_count
        #   adj_track = max(0, raw_track - 100 * priors)
        #   base=5, escalation=1 + 2*priors
        #   relief = max(1/5, 100/adj_track) if adj_track>=100 else 1
        #   sev_uncapped = (5 * escalation * relief_num) // relief_den
        #   Tier 51 cap = min(sev_uncapped, 10)
        cases = [
            # priors=0, track=20 -> adj=80, no relief, sev = 5*1 = 5
            #   cap binds at min(5, 10) = 5
            (0, 20, 5),
            # priors=5, track=200 -> adj = max(0, 800-500)=300
            #   relief = max(1/5, 100/300) = 1/3
            #   sev = (5 * 11 * 100) // 300 = 18, capped to 10
            (5, 200, HONESTY_CURVE_AMBIGUOUS_MAX_PCT),
            # priors=20, track=50 -> adj = max(0, 200-2000)=0
            #   relief = 1, sev = 5 * 41 = 205, capped to 10
            (20, 50, HONESTY_CURVE_AMBIGUOUS_MAX_PCT),
        ]
        for priors, track, expected in cases:
            chain = _mk_chain(
                height=pre_h, track_block_count=track, priors=priors,
            )
            sev = slashing_severity(
                b"V" * 32,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                chain,
            )
            self.assertEqual(
                sev, expected,
                f"Pre-Tier-69 (priors={priors}, track={track}) MUST "
                f"return legacy severity {expected}; got {sev}.  "
                "Historical replay correctness violated.",
            )


if __name__ == "__main__":
    unittest.main()
