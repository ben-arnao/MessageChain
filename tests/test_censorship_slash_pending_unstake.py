"""Censorship + IL-violation slash basis includes pending_unstakes.

CLAUDE.md "validator collusion" anchor: the protocol's primary defense
against the headline adversary requires that a colluding/coerced
validator who censors a tx cannot evade the resulting slash by
immediately unstaking — the EVIDENCE_MATURITY_BLOCKS window (~16
blocks ~ 2.7h) is FAR shorter than UNBONDING_PERIOD (>14 days).  Pre-
fix, both `_apply_censorship_slash` and `process_inclusion_list_
violation` computed the slash on `staked` only, capped at the post-
unstake remainder — letting ≥ 90% of the would-be slashed stake ride
out the unbonding queue and release on schedule.

The fix mirrors the canonical pattern at
`validate_slash_transaction` (slashable = staked + pending_unstakes)
and the existing equivocation slash in `slash_validator()` (drain
proportionally from BOTH buckets).  Hard-fork gated on
``CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT`` so historical replay is
byte-identical pre-fork.

Tests pin:
  * Pre-fork: legacy staked-only basis; pending_unstakes UNTOUCHED.
  * Post-fork (censorship): slash percentage applied to (staked +
    pending) basis, drained proportionally from BOTH buckets.
  * Post-fork (censorship): the unstake-then-censor evasion fails —
    even with most stake migrated to pending, the slash bites the
    proportional share of pending.
  * Post-fork (IL violation): same shape — both buckets drained.
  * Tier 30 honesty-curve routing remains intact (the percentage is
    what slashing_severity returns; only the BASIS changes).
"""

from __future__ import annotations

import hashlib
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import (
    CENSORSHIP_SLASH_BPS,
    CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT,
    HASH_ALGO,
    HONESTY_CURVE_INSURANCE_HEIGHT,
    HONESTY_CURVE_RATE_HEIGHT,
    INCLUSION_LIST_WAIT_BLOCKS,
    MIN_FEE,
)
from messagechain.consensus.censorship_evidence import compute_slash_amount
from messagechain.consensus.inclusion_list import (
    InclusionListViolationEvidenceTx,
    aggregate_inclusion_list,
    build_attester_mempool_report,
    compute_violation_slash_amount,
    process_inclusion_list_violation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


PRE = CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT - 1
POST = CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"pu") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    return {v.entity_id: per for v in validators}


def _force_chain_height(chain, h):
    return patch.object(
        Blockchain, "height", new=property(lambda _: h),
    )


def _make_chain():
    """Single-validator chain with stake + balance pre-loaded."""
    validators = _make_validators(8, tag=b"pu")
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


def _matured(offender_id, staked_at_admission, tag=b""):
    return SimpleNamespace(
        offender_id=offender_id,
        staked_at_admission=staked_at_admission,
        evidence_hash=_h(b"matured-" + tag + offender_id),
    )


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


def _build_inclusion_list(attesters, stakes_dict, target_tx, publish_height):
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


# ─────────────────────────────────────────────────────────────────
# Activation height ordering
# ─────────────────────────────────────────────────────────────────

class TestActivationOrdering(unittest.TestCase):
    """The new fork height must follow Tier 30 (1.33.0)."""

    def test_height_above_tier30(self):
        self.assertGreater(
            CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT,
            HONESTY_CURVE_INSURANCE_HEIGHT,
            "CENSORSHIP_SLASH_PENDING_UNSTAKE_HEIGHT must follow Tier 30 "
            "(HONESTY_CURVE_INSURANCE_HEIGHT) so the curve routing "
            "introduced in 1.33.0 is the basis the new fork extends.",
        )


# ─────────────────────────────────────────────────────────────────
# Censorship slash — pre-fork legacy preserved
# ─────────────────────────────────────────────────────────────────

class TestCensorshipPreForkLegacy(unittest.TestCase):
    """Below the new fork height, behavior must be byte-identical to
    the legacy staked-only slash, including pending_unstakes left
    untouched."""

    def test_pre_fork_pending_unstakes_untouched(self):
        chain, _submitter, accused, _atts = _make_chain()
        # Park HALF the stake in pending_unstakes — simulates the
        # censorship-then-unstake evasion we're fixing.
        chain.supply.staked[accused.entity_id] = 500_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (500_000, 99_999),
        ]
        # Use the Tier-30-aware activation slot but BEFORE the new
        # pending fork, so the curve is still active.  Picking the
        # legacy "between" tier 30 and pending fork height keeps the
        # honesty-curve sev_pct in play.
        between = HONESTY_CURVE_INSURANCE_HEIGHT
        # Long track record so the curve would compress severity if
        # pending were included (proves the legacy path used staked
        # only).
        chain.proposer_sig_counts[accused.entity_id] = 1_000
        chain.reputation[accused.entity_id] = 5_000
        # Use the admission-time stake = current staked (post-unstake).
        # Pre-fix: slash = sev_pct × staked, capped at staked.
        stake_before = chain.supply.staked[accused.entity_id]
        pending_before = sum(
            amt for amt, _ in chain.supply.pending_unstakes[accused.entity_id]
        )
        with _force_chain_height(chain, between):
            chain._apply_censorship_slash(
                _matured(accused.entity_id, stake_before, b"pre-fork"),
            )
        pending_after = sum(
            amt for amt, _ in chain.supply.pending_unstakes.get(
                accused.entity_id, [],
            )
        )
        self.assertEqual(
            pending_after, pending_before,
            "Pre-fork: pending_unstakes MUST be untouched — legacy "
            "staked-only basis preserved for replay determinism.",
        )


# ─────────────────────────────────────────────────────────────────
# Censorship slash — post-fork: pending included
# ─────────────────────────────────────────────────────────────────

class TestCensorshipPostFork(unittest.TestCase):

    def test_post_fork_drains_both_buckets_proportionally(self):
        """Post-fork: censorship slash applies sev_pct against
        (staked + pending) basis and drains BOTH buckets in
        proportion to their balance."""
        chain, _submitter, accused, _atts = _make_chain()
        # 30% staked, 70% pending — the unstake-evasion shape.
        chain.supply.staked[accused.entity_id] = 300_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (700_000, 99_999),
        ]
        # No track record — honesty curve returns 100% on UNAMBIGUOUS,
        # but censorship is AMBIGUOUS and falls into the small base
        # band.  To get a deterministic answer regardless of curve
        # tuning, force the offender into the "fresh validator" bucket
        # which leaves curve relief off and applies just the base pct.
        # We don't pin a specific number; we pin the SHAPE: both
        # buckets drained, total = sev_pct × (staked + pending).

        admission_basis = 300_000 + 700_000  # = 1_000_000

        staked_before = chain.supply.staked[accused.entity_id]
        pending_before = sum(
            amt for amt, _ in chain.supply.pending_unstakes[accused.entity_id]
        )
        total_supply_before = chain.supply.total_supply

        with _force_chain_height(chain, POST):
            chain._apply_censorship_slash(
                _matured(accused.entity_id, admission_basis, b"post-fork"),
            )

        staked_after = chain.supply.staked.get(accused.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in chain.supply.pending_unstakes.get(
                accused.entity_id, [],
            )
        )
        burn_total = (staked_before + pending_before) - (
            staked_after + pending_after
        )

        # Burn must come from BOTH buckets, not just staked.
        self.assertLess(
            staked_after, staked_before,
            "Staked must be reduced.",
        )
        self.assertLess(
            pending_after, pending_before,
            "Pending must ALSO be reduced — the censor-then-unstake "
            "evasion is what this fix closes.",
        )
        self.assertGreater(burn_total, 0)
        # total_supply shrinks by exactly the burned amount.
        self.assertEqual(
            total_supply_before - chain.supply.total_supply,
            burn_total,
            "total_supply must shrink by exactly the slashed amount.",
        )
        # Proportional drain: stake_burn/staked_before ~=
        # pending_burn/pending_before.  With integer math we allow
        # ±1 rounding per bucket.
        stake_burn = staked_before - staked_after
        pending_burn = pending_before - pending_after
        # Tighter check: stake_burn × pending_before == pending_burn × staked_before
        # under exact rational arithmetic; integer-truncation may shave
        # a unit off either side.
        cross_a = stake_burn * pending_before
        cross_b = pending_burn * staked_before
        self.assertLessEqual(
            abs(cross_a - cross_b),
            max(staked_before, pending_before),
            "Drain must be proportional across staked + pending.",
        )

    def test_post_fork_unstake_then_censor_evasion_fails(self):
        """The headline scenario: a validator censors, then unstakes
        90% of their stake before evidence matures.  Pre-fix the
        slash hits only the 10% that remained in `staked` (capped at
        staked), letting ~90% ride out the unbonding wait.  Post-fix
        the slash hits the (staked + pending) basis as if the unstake
        hadn't happened — so the realized loss approximates the full
        intended slash."""
        chain, _submitter, accused, _atts = _make_chain()
        admission_basis = 1_000_000
        # Pre-bump slash counter so the AMBIGUOUS curve's repeat-
        # multiplier escalates sev_pct above the post-unstake staked
        # cap (otherwise first-offense AMBIGUOUS at ~5% × 1M = 50K is
        # below the 100K cap and the evasion-vs-no-evasion gap is
        # hidden).  Tier 30 keeps censorship classified as AMBIGUOUS,
        # so the curve drives sev_pct via prior offenses; the threat
        # model anchored in CLAUDE.md is exactly a colluding proposer
        # with priors who continues to violate.
        chain.slash_offense_counts[accused.entity_id] = 1
        # Offender unstaked 90% before evidence matures.
        chain.supply.staked[accused.entity_id] = 100_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (900_000, 99_999),
        ]

        # Compute the curve's sev_pct independently so the assertion
        # asserts an exact post-fix burn, not a fuzzy bound.
        from messagechain.consensus.honesty_curve import (
            OffenseKind, Unambiguity, slashing_severity,
        )
        with _force_chain_height(chain, POST):
            expected_sev = slashing_severity(
                accused.entity_id, OffenseKind.CENSORSHIP,
                Unambiguity.AMBIGUOUS, chain,
            )
            chain._apply_censorship_slash(
                _matured(accused.entity_id, admission_basis, b"evasion"),
            )

        staked_after = chain.supply.staked.get(accused.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in chain.supply.pending_unstakes.get(
                accused.entity_id, [],
            )
        )
        total_realized = (100_000 + 900_000) - (staked_after + pending_after)
        expected_burn = expected_sev * admission_basis // 100

        # Pre-fix the slash is capped at staked = 100_000.  Post-fix
        # the slash basis is (staked + pending) = admission, so the
        # realized burn equals sev_pct × admission_basis.  Sanity-check
        # the test setup: expected_burn must straddle the pre-fix cap
        # to make the gap observable.
        self.assertGreater(
            expected_burn, 100_000,
            "Test setup invariant: curve must produce a sev_pct large "
            "enough that sev × admission_basis > the post-unstake "
            "staked cap (100K).  Otherwise this test does not actually "
            "exercise the evasion fix.",
        )
        self.assertGreater(
            total_realized, 100_000,
            "Post-fix: total realized slash MUST exceed the staked "
            "balance at apply time — the whole point is that "
            "pending_unstakes is in the basis.  Pre-fix this assertion "
            "fails because the slash is capped at the post-unstake "
            "staked amount.",
        )
        # Strong invariant: post-fix burn equals sev_pct × admission.
        self.assertEqual(
            total_realized, expected_burn,
            "Post-fix burn must equal sev_pct × admission_basis "
            "exactly — both buckets drained against the full basis, "
            "not just the post-unstake remainder.",
        )


# ─────────────────────────────────────────────────────────────────
# IL-violation slash — pre-fork legacy preserved
# ─────────────────────────────────────────────────────────────────

class TestILViolationPreForkLegacy(unittest.TestCase):

    def test_pre_fork_pending_unstakes_untouched(self):
        chain, submitter, accused, attesters = _make_chain()
        chain.supply.staked[accused.entity_id] = 500_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (500_000, 99_999),
        ]
        target_tx = _h(b"il-pre-fork")
        publish_height = 11
        stakes = _stakes([submitter, accused, *attesters])
        lst = _build_inclusion_list(attesters, stakes, target_tx, publish_height)
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        # Use a height between Tier 30 and pending fork — Tier 30
        # curve active, pending fork NOT active.
        between = HONESTY_CURVE_INSURANCE_HEIGHT
        pending_before = sum(
            amt for amt, _ in chain.supply.pending_unstakes[accused.entity_id]
        )
        with _force_chain_height(chain, between):
            result = process_inclusion_list_violation(
                etx, chain, current_height=between,
            )
        self.assertTrue(result.slashed)
        pending_after = sum(
            amt for amt, _ in chain.supply.pending_unstakes.get(
                accused.entity_id, [],
            )
        )
        self.assertEqual(
            pending_after, pending_before,
            "Pre-fork: IL-violation must leave pending_unstakes "
            "untouched (legacy replay determinism).",
        )


# ─────────────────────────────────────────────────────────────────
# IL-violation slash — post-fork: pending included
# ─────────────────────────────────────────────────────────────────

class TestILViolationPostFork(unittest.TestCase):

    def test_post_fork_drains_both_buckets(self):
        chain, submitter, accused, attesters = _make_chain()
        # Pre-bump slash counter so the curve treats this as a repeat
        # offense (UNAMBIGUOUS path, 100% sev).  Mirrors the censorship
        # evasion test — the realistic threat is a colluding proposer
        # with priors who continues to violate; we need the spread to
        # be large enough that "evasion-vs-no-evasion" is observable.
        chain.slash_offense_counts[accused.entity_id] = 1
        chain.supply.staked[accused.entity_id] = 100_000
        chain.supply.pending_unstakes[accused.entity_id] = [
            (900_000, 99_999),
        ]
        target_tx = _h(b"il-post-fork-evasion")
        publish_height = 11
        stakes = _stakes([submitter, accused, *attesters])
        lst = _build_inclusion_list(attesters, stakes, target_tx, publish_height)
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        staked_before = chain.supply.staked[accused.entity_id]
        pending_before = sum(
            amt for amt, _ in chain.supply.pending_unstakes[accused.entity_id]
        )
        with _force_chain_height(chain, POST):
            result = process_inclusion_list_violation(
                etx, chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        staked_after = chain.supply.staked.get(accused.entity_id, 0)
        pending_after = sum(
            amt for amt, _ in chain.supply.pending_unstakes.get(
                accused.entity_id, [],
            )
        )
        # Both must be drained.
        self.assertLess(
            staked_after, staked_before,
            "Post-fork IL violation must reduce staked.",
        )
        self.assertLess(
            pending_after, pending_before,
            "Post-fork IL violation must reduce pending_unstakes — "
            "the censor-then-unstake evasion analog.",
        )
        # Total slash must exceed the pre-fix cap (staked at apply).
        total_realized = (
            staked_before + pending_before
        ) - (staked_after + pending_after)
        self.assertGreater(
            total_realized, staked_before,
            "Post-fork: realized IL-violation slash must exceed the "
            "post-unstake staked balance — pending must contribute.",
        )
        # result.slash_amount should equal the total burn from BOTH
        # buckets so block-apply receipts/state-root code sees the
        # right magnitude.
        self.assertEqual(
            result.slash_amount, total_realized,
            "Returned slash_amount must equal the sum of the burn "
            "across both buckets.",
        )


if __name__ == "__main__":
    unittest.main()
