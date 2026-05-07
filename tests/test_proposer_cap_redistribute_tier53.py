"""Tier 53 -- proposer-cap clawback redistributes (no longer burns).

CLAUDE.md anchor: stake-concentration soft cap is anchored as
compression of *share* via diminishing returns, NOT punitive burn of
validator earnings.  "Issuance still accrues to validators on the
existing reward curve, but its purpose is supply replenishment, not
security-budget funding."

Pre-Tier-53 the proposer-cap clawback in
``SupplyTracker.mint_block_reward`` BURNED the trim.  Post-Tier-47
(dormancy controller, height 1710) the absolute number got large --
on today's 2-validator mainnet each validator both proposes and
attests on the other's blocks, the cap binds every block, and
~50% of every dormancy-controller refill incinerates back to
``total_burned`` instead of accruing to validators.  The dormancy
controller's gap-closing function lands at 50% efficiency.

Post-Tier-53 the trim is REDISTRIBUTED pro-rata among non-proposer
attesters with positive credit.  Anti-disproportionate-capture
intent preserved (proposer net stays at effective_cap); total
issuance accrues to validators.  Falls back to burn when no non-
proposer attester has positive credit (so the cap's intent is
preserved without inventing a tie-breaker on who "deserves" the
trim).

This module pins:

  1. Pre-Tier-53 the burn behavior is unchanged (legacy replay).
  2. Post-Tier-53 a 2-attester committee (proposer + one other)
     redistributes the proposer's slot to the other attester --
     other attester ends up with their slot + the proposer's slot,
     total issuance accrues to the validator set, no burn from the
     cap clawback (per-slot rounding remainder still burns, by
     design -- that's the pre-existing attester_pool drain logic).
  3. Post-Tier-53 with sole proposer-attester (1-attester committee
     where the only attester IS the proposer), the trim still BURNS
     -- no other attester to give it to.
  4. Total-issuance invariant holds in every case:
     proposer_net + sum(other_attesters_net) + burned == reward.

Tests pin behavior at a height where ``effective_cap == proposer_share``
(post-Tier-21 typical case) so the math is predictable.  Tier 53's
activation height is overridden in-test via ``patch.multiple`` so the
behavioral split can be tested at the same reward regime.
"""

import unittest
from unittest.mock import patch

from messagechain.config import (
    BLOCK_REWARD,
    PROPOSER_REWARD_CAP,
    PROPOSER_CAP_HALVING_HEIGHT,
    DORMANCY_CONTROLLER_HEIGHT,
    TREASURY_ENTITY_ID,
)
from messagechain.economics import inflation as inflation_module
from messagechain.economics.inflation import SupplyTracker


# Pick a height that's post-Tier-21 (cap formula = reward * 1/4) and
# pre-dormancy-controller (so reward is the stable BLOCK_REWARD = 16
# rather than the controller's variable mint).  Both pre- and post-
# Tier-53 tests run at this height; the redistribute/burn split is
# driven by patching ``PROPOSER_CAP_REDISTRIBUTE_HEIGHT`` to be just
# above (legacy) or just at-or-below (active) this height.
_TEST_HEIGHT = DORMANCY_CONTROLLER_HEIGHT - 5  # = 1705
assert _TEST_HEIGHT > PROPOSER_CAP_HALVING_HEIGHT


def _patch_redistribute_height(active: bool):
    """Patch the activation height so the test's _TEST_HEIGHT is below
    (legacy = inactive) or at-or-above (active) the gate."""
    new_height = _TEST_HEIGHT if active else _TEST_HEIGHT + 1
    return patch.object(
        inflation_module, "PROPOSER_CAP_REDISTRIBUTE_HEIGHT", new_height,
    )


class TestProposerCapPreTier53Legacy(unittest.TestCase):
    """Pre-Tier-53 the burn behavior must be byte-identical to before."""

    def test_pre_tier53_two_attester_committee_burns_proposer_slot(self):
        with _patch_redistribute_height(active=False):
            supply = SupplyTracker()
            proposer = b"p" * 32
            other = b"a" * 32
            supply.balances[proposer] = 0
            supply.balances[other] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, other],
            )

        # post-Tier-21 cap formula: effective_cap = 16 * 1/4 = 4
        # proposer_share = 4; attester_pool = 12; per_slot in
        # 2-attester committee = 12 // 2 = 6 each (no per-slot
        # remainder -- 12 is exactly divisible).
        # proposer_total = 4 + 6 = 10 > 4 -> overage = 6
        # Legacy: trim_from_att = 6, burn it all.
        # proposer net = proposer_share = 4
        # other net = 6 (untouched)
        # burned = 6 (trim only -- per-slot remainder is 0)
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(supply.balances[other], 6)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)
        self.assertEqual(result["burned"], 6)
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[other]
            + result["burned"],
            BLOCK_REWARD,
            "Conservation: proposer + other + burned == reward",
        )


class TestProposerCapPostTier53Redistribute(unittest.TestCase):
    """Post-Tier-53 the trim redistributes; total issuance accrues to
    validators."""

    def test_post_tier53_two_attester_committee_redistributes_to_other(self):
        with _patch_redistribute_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            other = b"a" * 32
            supply.balances[proposer] = 0
            supply.balances[other] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, other],
            )

        # Same math as pre-fork case, but: trim of 6 redistributes to
        # `other` (the only non-proposer attester with positive credit).
        # other_credit = {other: 6}, other_total = 6.
        # bonus to other = 6 * 6 // 6 = 6.  No remainder, no burn.
        # proposer net = 4 (proposer_share, slot fully clawed back)
        # other net = 6 (their slot) + 6 (proposer's redistributed slot) = 12
        # burned from cap clawback = 0
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(supply.balances[other], 12)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(
            supply.balances[proposer]
            + supply.balances[other]
            + result["burned"],
            BLOCK_REWARD,
            "Conservation: proposer + other + burned == reward",
        )

    def test_post_tier53_three_attester_committee_pro_rata(self):
        """3-attester committee: proposer + 2 others.  Each non-
        proposer attester slot is 12 // 3 = 4.  Proposer slot is
        also 4 -> proposer_total = 4 + 4 = 8 > cap=4 -> overage = 4.
        Trim of 4 redistributes pro-rata across 2 others (each with
        credit 4): each gets 4 * 4 // 8 = 2 bonus.  No remainder.
        """
        with _patch_redistribute_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            a, b = b"a" * 32, b"b" * 32
            for k in (proposer, a, b):
                supply.balances[k] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer, a, b],
            )

        proposer_net = supply.balances[proposer]
        a_net = supply.balances[a]
        b_net = supply.balances[b]
        self.assertLessEqual(
            proposer_net, 4,
            "Proposer net retention must not exceed effective_cap (4)",
        )
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)
        self.assertEqual(
            proposer_net + a_net + b_net + result["burned"],
            BLOCK_REWARD,
            "Conservation: proposer + others + burned == reward",
        )
        # The two non-proposer attesters get equal redistribution
        # (their pre-trim credit was equal), so they end up equal.
        self.assertEqual(a_net, b_net)
        # And each got more than their bare per-slot share (4),
        # because they absorbed half of the proposer's clawed-back
        # slot.
        self.assertGreater(a_net, 4)

    def test_post_tier53_sole_proposer_attester_falls_back_to_burn(self):
        """1-attester committee where the only attester IS the proposer.
        No other attester has positive credit, so the trim falls back
        to BURN -- preserves the cap's anti-disproportionate intent
        without inventing a tie-breaker on who "deserves" the
        redistribution.
        """
        with _patch_redistribute_height(active=True):
            supply = SupplyTracker()
            proposer = b"p" * 32
            supply.balances[proposer] = 0
            supply.balances[TREASURY_ENTITY_ID] = 0

            result = supply.mint_block_reward(
                proposer,
                block_height=_TEST_HEIGHT,
                attester_committee=[proposer],
            )

        # proposer is the only attester -> the entire attester pool
        # (12) goes to them initially.  proposer_total = 4 + 12 = 16 >
        # cap=4 -> overage = 12, trim = 12.  No other attester to
        # redistribute to -> burn 12.
        # proposer net = 4 (proposer_share); burned = 12.
        self.assertEqual(supply.balances[proposer], 4)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)
        self.assertEqual(result["burned"], 12)
        self.assertEqual(
            supply.balances[proposer] + result["burned"],
            BLOCK_REWARD,
        )


if __name__ == "__main__":
    unittest.main()
