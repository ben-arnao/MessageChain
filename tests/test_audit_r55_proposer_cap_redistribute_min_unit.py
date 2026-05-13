"""Audit r55 #2 -- Tier 77 ``_split_bps`` clamp on the proposer-cap
redistribute pro-rata.

Tier 53 (audit ~r43) made the proposer-cap clawback REDISTRIBUTE the
trimmed tokens pro-rata among non-proposer attesters with positive
credit, instead of burning them.  The intent under the CLAUDE.md
anchor "issuance still accrues to validators ... its purpose is supply
replenishment" was to keep the dormancy-controller's gap-closing
function at 100% efficiency rather than the legacy ~50%.

The per-attester math:

    bonus = trim_from_att * existing // other_total

is a raw integer-floor divide -- the same shape Tier 73 (r51 #3),
Tier 74 (r52 #3), and Tier 75 (r53 #3) introduced ``_split_bps`` to
fix on the proposer-share / per-block-cap / attester-fee / slash
sides.  The audit r52 #3 CHANGELOG explicitly named the wider
abstraction:

    "the wider abstraction calls for a shared ``_split_bps`` helper
     to catch every future ``bps // den`` site that could round to
     zero under a realistic minimum."

This site is the next instance of that defect class.

The bite: with N >= 2 non-proposer attesters and a small
``trim_from_att`` (the dormancy-controller's steady-state regime is
*exactly* the small-issuance regime, by design), every per-attester
``bonus`` rounds to 0 and the entire trim flows to ``burned`` instead
of being redistributed.  Tier 53's anti-burn intent silently inverts
back to the pre-Tier-53 burn-everything behavior in the regime Tier
47+ is anchored to produce.

Tier 77 (this commit) lands one change:
  * ``PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT`` -- new activation
    height gating the redistribute loop's per-attester ``bonus``
    through ``_split_bps(trim_from_att, existing, other_total,
    min_unit=1, gate=cap_min_unit_active)``.  Pre-fork
    (``gate=False``) byte-identical to legacy at every input.  Post-
    fork (``gate=True``) the per-attester bonus clamps to 1 whenever
    the floor-divide would round to 0, and a `remaining` clamp
    inside the loop prevents the stack of min-unit clamps from
    over-distributing past ``trim_from_att`` (supply conservation).

Co-cohort with Tier 76 (FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT =
14500) at 2000-block runway: 16500.

This module pins:
  1. ``_split_bps`` is the helper the production site routes through
     in BOTH gate regimes (legacy + min-unit-active).
  2. Pre-fork the redistribute math is byte-identical to legacy --
     historical-block replay preserved.
  3. Post-fork small ``trim_from_att`` distributes at least 1 token
     to the first eligible attester instead of silently burning all
     of it.
  4. Supply conservation holds in both regimes:
        sum(bonus_i) + remainder == trim_from_att
     ``_split_bps`` itself never exceeds its ``amount`` arg, and the
     `remaining` clamp prevents two consecutive min-unit clamps from
     stacking past ``trim_from_att``.
  5. Sole-proposer-attester still burns (no ``other_credit`` to
     distribute to) -- preserves the cap's anti-disproportionate
     intent without inventing a tie-breaker on who "deserves" the
     trim when nobody else attested.
  6. Height-ordering assertion: Tier 77 strictly follows Tier 76.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from messagechain.config import (
    BLOCK_REWARD,
    PROPOSER_CAP_HALVING_HEIGHT,
    DORMANCY_CONTROLLER_HEIGHT,
    TREASURY_ENTITY_ID,
)
from messagechain.economics import inflation as inflation_module
from messagechain.economics.inflation import SupplyTracker


# Same test height as the Tier 53 sibling test (post-Tier-21 cap formula,
# pre-dormancy-controller so reward is the stable BLOCK_REWARD = 16).
_TEST_HEIGHT = DORMANCY_CONTROLLER_HEIGHT - 5  # = 1705
assert _TEST_HEIGHT > PROPOSER_CAP_HALVING_HEIGHT


def _patch_min_unit_height(active: bool):
    """Patch the activation height so _TEST_HEIGHT is below (legacy =
    inactive) or at-or-above (active) the gate.

    Mirrors the test_proposer_cap_redistribute_tier53 pattern.  We also
    patch PROPOSER_CAP_REDISTRIBUTE_HEIGHT to active so the redistribute
    path itself is exercised -- the min-unit clamp can only fire when
    the redistribute path is active in the first place.
    """
    new_height = _TEST_HEIGHT if active else _TEST_HEIGHT + 1
    return patch.multiple(
        inflation_module,
        PROPOSER_CAP_REDISTRIBUTE_HEIGHT=_TEST_HEIGHT,
        PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT=new_height,
    )


class TestHeightOrdering(unittest.TestCase):
    """The Tier 77 height must strictly follow Tier 76 -- consecutive
    issuance-discipline retunes deserve their own operator cohort."""

    def test_tier77_strictly_follows_tier76(self):
        from messagechain.config import (
            PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT,
            FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT,
        )
        self.assertGreater(
            PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT,
            FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT,
            "Tier 77 (PROPOSER_CAP_REDISTRIBUTE_MIN_UNIT_HEIGHT) must "
            "strictly follow Tier 76 -- each issuance-discipline "
            "retune deserves its own operator cohort.",
        )


class TestPreTier77RedistributeIsByteIdenticalLegacy(unittest.TestCase):
    """Pre-fork the redistribute pro-rata must match the legacy floor-
    divide exactly -- historical-block replay across the activation
    height depends on this."""

    def test_pre_tier77_small_trim_many_attesters_silently_burns(self):
        """5-attester committee at _TEST_HEIGHT.  attester_pool = 12,
        per_slot = 12 // 5 = 2 each (slot remainder = 2 burns from the
        pre-existing attester_pool drain).  proposer_share = 4,
        proposer_slot = 2 -> proposer_total = 6 > cap = 4 -> overage =
        2, trim_from_att = min(2, 2) = 2.  other_credit = {a, b, c, d:
        2 each}, other_total = 8.  Pre-fork bonus_each = 2 * 2 // 8 =
        0.  Every per-attester bonus rounds to 0 -> distributed = 0,
        remainder = 2, 2 tokens BURN.

        This is the defect-class shape: in the dormancy-controller's
        steady-state regime, the redistribute path silently inverts to
        burn-everything for any small trim across 2+ attesters.
        """
        with _patch_min_unit_height(active=False):
            supply = SupplyTracker()
            proposer = b"p" * 32
            a, b, c, d = b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32
            for k in (proposer, a, b, c, d):
                supply.balances[k] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, a, b, c, d],
            )

        # Defect verified: all redistribute trim burned.  Conservation
        # invariant still holds because the burn accounts for the
        # rounded-away tokens.
        # proposer net = 4 (proposer_share, slot fully clawed back)
        # a, b, c, d net = 2 each (their per-slot share, no redistribute
        # bonus added)
        # burned = 2 (redistribute trim, rounded to zero distribution)
        #        + 2 (per-slot remainder from 12//5) = 4
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(supply.balances[a], 2)
        self.assertEqual(supply.balances[b], 2)
        self.assertEqual(supply.balances[c], 2)
        self.assertEqual(supply.balances[d], 2)
        # Conservation: 4 + 2*4 + 4 = 16 == BLOCK_REWARD.
        self.assertEqual(
            (
                supply.balances[proposer]
                + supply.balances[a] + supply.balances[b]
                + supply.balances[c] + supply.balances[d]
                + result["burned"]
            ),
            BLOCK_REWARD,
        )
        # The defect-class signature: 2 tokens of trim that should have
        # gone to attesters are silently burned.
        self.assertEqual(result["burned"], 4)


class TestPostTier77RedistributeClampsToMinUnit(unittest.TestCase):
    """Post-fork the small-trim path clamps at least 1 token to the
    first eligible attester per loop iteration; the per-iteration
    `remaining` clamp keeps the total ≤ trim_from_att."""

    def test_post_tier77_small_trim_many_attesters_distributes(self):
        with _patch_min_unit_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            a, b, c, d = b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32
            for k in (proposer, a, b, c, d):
                supply.balances[k] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, a, b, c, d],
            )

        # Same scenario as the pre-fork test, but now:
        #   trim_from_att = 2 distributes 1 token to TWO of the four
        #   non-proposer attesters (the first two in dict-iteration
        #   order on the per-block other_credit map).  The remaining 2
        #   attesters get nothing more than their bare per-slot share.
        # Net effect: trim's 2 tokens are PAID instead of burned.
        # proposer net = 4 (proposer_share, slot fully clawed back)
        # two of {a, b, c, d} get per-slot 2 + bonus 1 = 3
        # two of {a, b, c, d} get per-slot 2 + bonus 0 = 2
        # burned = 0 (from redistribute) + 2 (per-slot remainder) = 2
        attester_totals = [
            supply.balances[a], supply.balances[b],
            supply.balances[c], supply.balances[d],
        ]
        self.assertEqual(supply.balances[proposer], 4)
        # Two attesters got a 1-token bonus from the clamp; two did
        # not.  The exact identity depends on dict-iteration order
        # (cpython 3.7+ preserves insertion order, so a, b are the
        # winners here -- but the test pins the COUNT, not the IDs).
        self.assertEqual(sum(1 for v in attester_totals if v == 3), 2)
        self.assertEqual(sum(1 for v in attester_totals if v == 2), 2)
        # Burn dropped from 4 to 2: redistribute trim no longer burns.
        # The per-slot remainder (2 tokens from 12 // 5 = 2 r 2) still
        # burns -- that is a pre-existing drain unrelated to Tier 77.
        self.assertEqual(result["burned"], 2)
        # Conservation: 4 + (3+3+2+2) + 2 = 16.
        self.assertEqual(
            (
                supply.balances[proposer]
                + supply.balances[a] + supply.balances[b]
                + supply.balances[c] + supply.balances[d]
                + result["burned"]
            ),
            BLOCK_REWARD,
        )

    def test_post_tier77_supply_conservation_at_pathological_trim(self):
        """trim_from_att = 1 across many attesters: pre-fork ALL of it
        burns (every bonus rounds to 0).  Post-fork the first eligible
        attester gets the single token; the per-iteration ``remaining``
        clamp prevents subsequent iterations from over-distributing.

        Conservation invariant: distributed + remainder == trim_from_att
        in BOTH regimes.  This test pins the post-fork case at the
        smallest non-zero trim.

        Trim_from_att = 1 isn't reachable via the standard
        mint_block_reward at _TEST_HEIGHT (the cap math doesn't
        produce overage=1 there), so test the loop directly via a
        small synthetic call to the helper.  This is the unit-test
        analogue of the integration test above.
        """
        from messagechain.economics.inflation import _split_bps

        # 5 non-proposer attesters each with credit 10 (other_total
        # = 50).  trim_from_att = 1 across them.
        trim = 1
        others = [10, 10, 10, 10, 10]
        other_total = sum(others)

        # Pre-fork: every bonus rounds to 0.
        legacy_bonuses = [
            _split_bps(trim, e, other_total, min_unit=1, gate=False)
            for e in others
        ]
        self.assertEqual(legacy_bonuses, [0, 0, 0, 0, 0])
        legacy_distributed = sum(legacy_bonuses)
        legacy_remainder = trim - legacy_distributed
        self.assertEqual(legacy_distributed, 0)
        self.assertEqual(legacy_remainder, 1)  # all burns

        # Post-fork: the first iteration's clamp captures the lone
        # token; the production code's `remaining = trim - distributed`
        # short-circuit then breaks out of the loop so no further
        # iteration over-distributes.  Simulate that flow:
        distributed = 0
        post_bonuses = []
        for e in others:
            remaining = trim - distributed
            if remaining <= 0:
                break
            b = _split_bps(trim, e, other_total, min_unit=1, gate=True)
            b = min(b, remaining)
            post_bonuses.append(b)
            distributed += b
        self.assertEqual(distributed, 1)
        self.assertEqual(trim - distributed, 0)  # no burn
        # Exactly one bonus equals 1; the loop terminates after.
        self.assertEqual(post_bonuses, [1])


class TestPostTier77SoleProposerAttesterStillBurns(unittest.TestCase):
    """Sole-proposer-attester edge case: when the only attester IS the
    proposer, no other_credit exists -- the trim falls back to burn.
    The min-unit clamp only triggers when there's a non-proposer
    attester to distribute to."""

    def test_post_tier77_sole_proposer_attester_still_burns(self):
        with _patch_min_unit_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            supply.balances[proposer] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer],
            )

        # proposer is the only attester -> attester_pool (12) all goes
        # to them initially.  proposer_total = 4 + 12 = 16 > cap = 4
        # -> overage = 12, trim = 12.  No other attester to receive
        # the redistribute -> burn 12 (same as Tier 53's sole-proposer
        # fallback; Tier 77's min-unit clamp is orthogonal to this).
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(result["burned"], 12)


class TestPostTier77LargeTrimByteIdenticalToTier53(unittest.TestCase):
    """When the legacy redistribute math already distributes the full
    trim with no rounding loss, post-Tier-77 must be byte-identical to
    Tier 53.  The min-unit clamp must NOT change behavior in the regime
    the legacy already handles correctly -- it only closes the small-
    trim round-to-zero gap.

    Standard 2-attester committee: pre-fork bonus = 6 * 6 // 6 = 6
    (clean divide, no rounding).  Post-fork same path -- ``_split_bps``
    with ``gate=True`` returns the legacy floor whenever it would not
    round to zero."""

    def test_post_tier77_two_attester_no_op_at_clean_divide(self):
        with _patch_min_unit_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            other = b"o" * 32
            supply.balances[proposer] = 0
            supply.balances[other] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, other],
            )

        # Mirror of test_post_tier53_two_attester_committee_redistributes_to_other.
        # Post-fork at-clean-divide is byte-identical.
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(supply.balances[other], 12)
        self.assertEqual(result["burned"], 0)


if __name__ == "__main__":
    unittest.main()
