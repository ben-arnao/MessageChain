"""Tier 30: honest-operator insurance for soft-slash paths.

CLAUDE.md anchors "honest operators are insured against accidents" —
catastrophic burns are reserved for unambiguous, intentional protocol
violations.  Two soft-slash paths violated the anchor:

  * `_apply_censorship_slash` burned flat CENSORSHIP_SLASH_BPS (10%)
    without consulting the honesty curve, so a long-tenured validator
    who happened to omit one tx during honest mempool churn paid the
    same as a deliberate censoring proposer.
  * `process_inclusion_list_violation` classified first offenses as
    UNAMBIGUOUS, producing a 50%/100% slash on a single missed
    include.  An IL violation CAN be honest mempool divergence — only
    a repeat pattern justifies UNAMBIGUOUS.

Tier 30 routes both paths through `slashing_severity` with
`Unambiguity.AMBIGUOUS` on first offense; subsequent offenses (read
off slash_offense_counts, persisted from Tier 24) escalate.  Pre-
activation: byte-identical to legacy behavior.

Tests pin:
  * Pre-activation (height < HONESTY_CURVE_INSURANCE_HEIGHT): legacy
    flat-10% censorship slash; UNAMBIGUOUS first-offense IL violation
    (= UNAMBIGUOUS_FIRST_PCT for tenured, 100% for fresh).
  * Post-activation: long-tenured validator first censorship slash
    receives AMBIGUOUS-band penalty (small, often single-digit %),
    NOT 10%.
  * Post-activation: long-tenured validator first IL violation
    receives AMBIGUOUS-band penalty, NOT UNAMBIGUOUS_FIRST_PCT.
  * Post-activation: a SECOND offense on the same validator escalates
    correctly (per existing curve mechanics).
"""

from __future__ import annotations

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    CENSORSHIP_SLASH_BPS,
    HONESTY_CURVE_AMBIGUOUS_BASE_PCT,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    HONESTY_CURVE_INSURANCE_HEIGHT,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
    INCLUSION_LIST_WAIT_BLOCKS,
    MIN_FEE,
)
from messagechain.consensus.censorship_evidence import compute_slash_amount
from messagechain.consensus.inclusion_list import (
    InclusionListViolationEvidenceTx,
    aggregate_inclusion_list,
    build_attester_mempool_report,
    process_inclusion_list_violation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


PRE = HONESTY_CURVE_INSURANCE_HEIGHT - 1
POST = HONESTY_CURVE_INSURANCE_HEIGHT


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"t30") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    return {v.entity_id: per for v in validators}


def _sign_violation_evidence(
    submitter, inclusion_list, omitted_tx_hash,
    accused_proposer_id, accused_height, fee=MIN_FEE,
):
    placeholder = Signature([], 0, [], b"", b"")
    tx = InclusionListViolationEvidenceTx(
        inclusion_list=inclusion_list,
        omitted_tx_hash=omitted_tx_hash,
        accused_proposer_id=accused_proposer_id,
        accused_height=accused_height,
        submitter_id=submitter.entity_id,
        timestamp=int(time.time()),
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


def _force_chain_height(chain, h):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


def _make_chain():
    """Single-validator chain with stake + balance pre-loaded.  The
    "accused" entity is the one we'll slash."""
    validators = _make_validators(8, tag=b"t30")
    submitter = validators[0]
    accused = validators[1]
    chain = Blockchain()
    chain.initialize_genesis(submitter)
    for v in validators[1:]:
        register_entity_for_test(chain, v)
    for v in validators:
        chain.supply.balances[v.entity_id] = 10_000_000
        chain.supply.staked[v.entity_id] = 1_000_000
    return chain, submitter, accused, validators[2:]


class TestCensorshipSlashHonestyCurve(unittest.TestCase):
    """_apply_censorship_slash must route through slashing_severity
    post-Tier-30, treating first offenses as AMBIGUOUS."""

    def _matured(self, offender_id, staked_at_admission):
        """Build a stub matured CensorshipEvidence the apply path
        consumes.  We only need the offender_id, evidence_hash, and
        staked_at_admission — the rest of _apply_censorship_slash
        doesn't read other fields."""
        from types import SimpleNamespace
        return SimpleNamespace(
            offender_id=offender_id,
            staked_at_admission=staked_at_admission,
            evidence_hash=_h(b"matured-" + offender_id),
        )

    def test_pre_activation_flat_10pct_unchanged(self):
        """Below HONESTY_CURVE_INSURANCE_HEIGHT: byte-identical to
        legacy flat 10% censorship slash."""
        chain, _submitter, accused, _atts = _make_chain()
        # Long track record so the AMBIGUOUS curve would compress; if
        # the curve were active the slash would be tiny, but pre-
        # activation we expect the flat 10%.
        chain.proposer_sig_counts[accused.entity_id] = 1_000
        chain.reputation[accused.entity_id] = 5_000

        stake_before = chain.supply.staked[accused.entity_id]
        with _force_chain_height(chain, PRE):
            chain._apply_censorship_slash(
                self._matured(accused.entity_id, stake_before),
            )
        stake_after = chain.supply.staked[accused.entity_id]
        self.assertEqual(
            stake_before - stake_after,
            compute_slash_amount(stake_before),
            "Pre-Tier-30 must keep flat CENSORSHIP_SLASH_BPS (10%)",
        )

    def test_post_activation_long_tenured_first_offense_uses_curve(self):
        """At/above HONESTY_CURVE_INSURANCE_HEIGHT, a long-tenured
        validator's first censorship offense must NOT be a flat 10%
        burn — it must route through the curve, producing the
        AMBIGUOUS_BASE_PCT band's small fractional penalty."""
        chain, _submitter, accused, _atts = _make_chain()
        # Strong track record + zero priors → AMBIGUOUS path produces
        # the smallest possible slash via the relief mechanism.
        chain.proposer_sig_counts[accused.entity_id] = 1_000
        chain.reputation[accused.entity_id] = 5_000

        stake_before = chain.supply.staked[accused.entity_id]
        flat_legacy = compute_slash_amount(stake_before)  # 10% baseline
        with _force_chain_height(chain, POST):
            chain._apply_censorship_slash(
                self._matured(accused.entity_id, stake_before),
            )
        stake_after = chain.supply.staked[accused.entity_id]
        actual_burn = stake_before - stake_after
        self.assertLess(
            actual_burn, flat_legacy,
            "Post-Tier-30: long-tenured first offense must burn LESS "
            "than the legacy 10%.  Pre-fix it stays at 10% because "
            "_apply_censorship_slash bypasses the curve.  A perfect-"
            "record validator may even hit the Tier 24 amnesty path "
            "(0%); that's the anchored insurance behavior.",
        )

    def test_post_activation_repeat_offense_escalates(self):
        """Repeat censorship offenses still bite — the curve's
        repeat-multiplier escalation path stays active."""
        chain, _submitter, accused, _atts = _make_chain()
        # Modest track record — clearing HONEST_TRACK_THRESHOLD (=100
        # default) but well below AMNESTY_TRACK_THRESHOLD (=1000).
        # That way the first offense gets relief but is still > 0,
        # leaving headroom for the second offense to escalate
        # observably.
        chain.proposer_sig_counts[accused.entity_id] = 30
        chain.reputation[accused.entity_id] = 50

        # First offense (post-Tier-30).
        stake_before_1 = chain.supply.staked[accused.entity_id]
        with _force_chain_height(chain, POST):
            chain._apply_censorship_slash(
                self._matured(accused.entity_id, stake_before_1),
            )
        stake_after_1 = chain.supply.staked[accused.entity_id]
        burn_1 = stake_before_1 - stake_after_1

        # Second offense — different evidence_hash so the dedupe set
        # doesn't reject it.  The repeat-multiplier should produce a
        # LARGER (or at least not smaller) fractional burn than the
        # first.  Compute the percentage relative to the stake at
        # admission so the comparison is fair against monotonically
        # decreasing absolute stake.
        stake_before_2 = chain.supply.staked[accused.entity_id]
        from types import SimpleNamespace
        m2 = SimpleNamespace(
            offender_id=accused.entity_id,
            staked_at_admission=stake_before_2,
            evidence_hash=_h(b"second-offense-" + accused.entity_id),
        )
        with _force_chain_height(chain, POST):
            chain._apply_censorship_slash(m2)
        stake_after_2 = chain.supply.staked[accused.entity_id]
        burn_2 = stake_before_2 - stake_after_2

        pct_1 = burn_1 * 100 / max(1, stake_before_1)
        pct_2 = burn_2 * 100 / max(1, stake_before_2)
        self.assertGreaterEqual(
            pct_2, pct_1,
            "Tier 30 escalation: a second offense must burn at least "
            "as large a fraction of stake as the first.",
        )


class TestInclusionListViolationFirstOffenseIsAmbiguous(unittest.TestCase):
    """process_inclusion_list_violation must classify first offenses
    as AMBIGUOUS post-Tier-30 (relying on slash_offense_counts to
    distinguish first from repeat)."""

    def _build_setup(self):
        """8-validator chain with a quorum-backed inclusion list ready
        to slash the accused."""
        chain, submitter, accused, attesters = _make_chain()
        return chain, submitter, accused, attesters

    def _build_list(self, attesters, stakes_dict, target_tx, publish_height):
        # Reset attester leaves so build_attester_mempool_report doesn't
        # crash on stale signing state across tests.
        for a in attesters:
            a.keypair._next_leaf = 0
        target_h = publish_height - 1
        report_h = target_h - INCLUSION_LIST_WAIT_BLOCKS
        reports = [
            build_attester_mempool_report(
                a, report_height=report_h, tx_hashes=[target_tx],
            )
            for a in attesters
        ]
        return aggregate_inclusion_list(
            reports=reports, stakes=stakes_dict,
            publish_height=publish_height,
        )

    def test_pre_tier30_first_offense_unambiguous_full_burn_for_short_tenure(self):
        """Pre-Tier-30 path: a fresh validator first IL violation is
        UNAMBIGUOUS → full burn.  Pinned so we know the legacy
        behavior is preserved before activation."""
        chain, submitter, accused, attesters = self._build_setup()
        # No track record on the accused.
        target_tx = _h(b"pre-fresh-burn")
        publish_height = 11
        stakes = _stakes([submitter, accused, *attesters])
        lst = self._build_list(attesters, stakes, target_tx, publish_height)
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        stake_before = chain.supply.staked[accused.entity_id]
        # Use a height between Tier 24 and Tier 30: curve is active
        # but insurance reclassification is not yet active.
        between_height = HONESTY_CURVE_RATE_HEIGHT
        with _force_chain_height(chain, between_height):
            result = process_inclusion_list_violation(
                etx, chain, current_height=between_height,
            )
        self.assertTrue(result.slashed)
        # Fresh validator + UNAMBIGUOUS = 100%.
        self.assertEqual(result.slash_amount, stake_before)

    def test_post_tier30_long_tenured_first_offense_is_ambiguous(self):
        """Post-Tier-30: long-tenured validator's first IL violation
        is classified AMBIGUOUS — the slash falls in the AMBIGUOUS
        band, NOT UNAMBIGUOUS_FIRST_PCT (50%) or 100%.

        Specifically: with a strong track record and zero priors, the
        sev_pct should be at most a few percent (the AMBIGUOUS_BASE_PCT
        baseline modulated by relief), NEVER ≥ UNAMBIGUOUS_FIRST_PCT.
        """
        chain, submitter, accused, attesters = self._build_setup()
        chain.proposer_sig_counts[accused.entity_id] = 1_000
        chain.reputation[accused.entity_id] = 5_000

        target_tx = _h(b"post-tenured-first")
        publish_height = 11
        stakes = _stakes([submitter, accused, *attesters])
        lst = self._build_list(attesters, stakes, target_tx, publish_height)
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        stake_before = chain.supply.staked[accused.entity_id]
        with _force_chain_height(chain, POST):
            result = process_inclusion_list_violation(
                etx, chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        # Pct should be FAR below UNAMBIGUOUS_FIRST_PCT.  Pre-fix it
        # equals UNAMBIGUOUS_FIRST_PCT (50%) for tenured first
        # offenders.  Post-fix the AMBIGUOUS band yields
        # AMBIGUOUS_BASE_PCT (5%) modulated by relief — so the actual
        # slash is well under UNAMBIGUOUS_FIRST_PCT.
        actual_pct = result.slash_amount * 100 / max(1, stake_before)
        self.assertLess(
            actual_pct, HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
            "Post-Tier-30 long-tenured first offense must be classified "
            "AMBIGUOUS — slash_pct must be strictly below "
            "UNAMBIGUOUS_FIRST_PCT.  Pre-fix (UNAMBIGUOUS classification) "
            f"this is exactly {HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT}.",
        )

    def test_post_tier30_repeat_offense_unambiguous_full_burn(self):
        """Post-Tier-30: a SECOND offense (slash_offense_counts ≥ 1)
        re-classifies as UNAMBIGUOUS → repeat-pattern burn.  This is
        the rule that lets a deliberate censoring proposer NOT escape
        consequences just because the first offense is treated
        leniently."""
        chain, submitter, accused, attesters = self._build_setup()
        chain.proposer_sig_counts[accused.entity_id] = 1_000
        chain.reputation[accused.entity_id] = 5_000

        # Pre-bump the slash counter — simulate a prior offense without
        # threading the full evidence-tx flow twice.
        chain.slash_offense_counts[accused.entity_id] = 1

        target_tx = _h(b"post-repeat-burn")
        publish_height = 11
        stakes = _stakes([submitter, accused, *attesters])
        lst = self._build_list(attesters, stakes, target_tx, publish_height)
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        stake_before = chain.supply.staked[accused.entity_id]
        with _force_chain_height(chain, POST):
            result = process_inclusion_list_violation(
                etx, chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        # Repeat unambiguous → 100% of remaining stake.
        self.assertEqual(result.slash_amount, stake_before)


if __name__ == "__main__":
    unittest.main()
