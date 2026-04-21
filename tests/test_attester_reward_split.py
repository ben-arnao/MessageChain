"""Tests for the pro-rata attester reward split hard fork.

Background
----------
Pre-activation (`block_height < ATTESTER_REWARD_SPLIT_HEIGHT`), the
`mint_block_reward` function capped the PAID committee at
`attester_pool // ATTESTER_REWARD_PER_SLOT` slots — each slot earned
exactly 1 token, and any committee members beyond that index were
truncated to 0 reward.  Combined with the halving schedule (BLOCK_REWARD
16 → 8 → 4 floor) and the 1/4 proposer share, this meant:

  * Genesis era (BLOCK_REWARD=16): attester_pool = 12 → 12 paid slots.
  * After 1st halving (BLOCK_REWARD=8): attester_pool = 6 → 6 paid slots.
  * Floor (BLOCK_REWARD=4): attester_pool = 3 → **3 paid slots forever**.

A permanent 3-attester committee is a structural decentralization
failure.  The fix decouples committee size from reward budget: the
committee attests whether or not reward budget exists, and the pool is
split pro-rata across the full committee.  Integer-division remainder
burns.  If the committee is larger than the pool, per-slot reward
rounds to zero and the entire pool burns — participants still get
finality-weight credit, the reward is a bonus not a gate on
participation.

This file:
  * Pins the pre-activation legacy behavior so hard-fork rollback is
    byte-identical for any height strictly below the activation gate.
  * Locks in the post-activation pro-rata math and its corner cases.
  * Verifies that the proposer-cap logic still applies correctly
    post-activation (trim happens after pro-rata, not before).

Design note on the low-pool corner case
---------------------------------------
When `len(committee) > attester_pool`, two defensible strategies exist:

  (A) Pure pro-rata integer division: per_slot = pool // N. If that
      rounds to zero, everyone gets 0 reward and the whole pool burns.
  (B) Sort the committee and pay the first `pool` members 1 token each,
      burn the rest.

We pick (A) because:
  * It matches the semantic promise of the hard fork — reward is a
    *bonus*, not a gate.  A committee member who attested still gets
    finality-weight credit regardless of whether the per-slot reward
    rounds to 1 or 0.
  * It avoids re-introducing the "first N winners" asymmetry that
    approach (B) bakes back in — the whole point of decoupling is
    that committee membership, not slot index, determines reward
    eligibility.
  * Fee tips are the real long-horizon validator income; reward-pool
    dust is a rounding detail, not the incentive load-bearing piece.

The practical impact is confined to the narrow band where
`len(committee) > attester_pool` — at `BLOCK_REWARD_FLOOR=4` with
`attester_pool=3`, any committee of 4+ triggers the 0-per-slot case.
That's acceptable: the committee still attests for finality, and the
3-token pool burns as mild extra deflation.
"""

import unittest
from unittest.mock import patch

from messagechain.economics import inflation as inflation_module
from messagechain.economics.inflation import SupplyTracker
from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    HALVING_INTERVAL,
    PROPOSER_REWARD_CAP,
    PROPOSER_REWARD_NUMERATOR,
    PROPOSER_REWARD_DENOMINATOR,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    TREASURY_ENTITY_ID,
)


# Canonical heights for activation tests.  Pre-activation uses
# `ATTESTER_REWARD_SPLIT_HEIGHT - 1`; post-activation uses the
# activation height itself (inclusive fork gate).  Pinning these to
# the config constant keeps the tests correct if operators adjust the
# mainnet fork height later.
PRE_ACTIVATION_HEIGHT = max(0, ATTESTER_REWARD_SPLIT_HEIGHT - 1)
POST_ACTIVATION_HEIGHT = ATTESTER_REWARD_SPLIT_HEIGHT


def _make_committee(n: int) -> list[bytes]:
    """Deterministic list of `n` distinct 32-byte entity IDs (not 0x01 or 0x02 — those
    are reserved for the proposer in most tests below)."""
    return [bytes([i + 0x10]) * 32 for i in range(n)]


def _freeze_reward_at_floor():
    """Patch `calculate_block_reward` to return BLOCK_REWARD_FLOOR regardless
    of height.  Lets a test exercise the floor-era math without running
    `HALVING_INTERVAL * many` heights."""
    return patch.object(
        SupplyTracker, "calculate_block_reward",
        lambda self, height: BLOCK_REWARD_FLOOR,
    )


class TestPreActivationBehaviorUnchanged(unittest.TestCase):
    """Pre-activation height: legacy truncate-at-max_slots behavior preserved.

    This is the hard-fork rollback invariant — if the activation never
    fires (e.g. operator rolls back the deployment), byte-identical
    reward distribution must still be computable from the same inputs.
    """

    def test_pre_activation_20_member_committee_only_12_paid(self):
        """Year 0: attester_pool=12, committee of 20 → first 12 paid 1 each,
        rest truncated to 0.  Byte-identical to the legacy code path."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(20)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        # attester_pool = 12 (= BLOCK_REWARD * 3/4); 12 slots paid.
        attester_pool = BLOCK_REWARD - (
            BLOCK_REWARD * PROPOSER_REWARD_NUMERATOR
            // PROPOSER_REWARD_DENOMINATOR
        )
        self.assertEqual(attester_pool, 12)
        paid_members = [eid for eid in committee if supply.balances[eid] > 0]
        unpaid_members = [eid for eid in committee if supply.balances[eid] == 0]
        self.assertEqual(len(paid_members), 12)
        self.assertEqual(len(unpaid_members), 8)
        for eid in paid_members:
            self.assertEqual(supply.balances[eid], ATTESTER_REWARD_PER_SLOT)
        # No burn: 12 slots paid fully from 12-token pool.
        self.assertEqual(result["burned"], 0)

    def test_pre_activation_at_floor_only_3_paid(self):
        """BLOCK_REWARD floor: attester_pool=3 (pre-activation), committee
        of 10 → only first 3 paid 1 each, remaining 7 get zero.  This is
        exactly the regression the fix targets — locked in for the
        pre-activation window so the old behavior can be audited."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(10)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            supply.mint_block_reward(
                proposer,
                block_height=PRE_ACTIVATION_HEIGHT,
                attester_committee=committee,
            )

        # At floor: reward=4, proposer_share=1, attester_pool=3.
        paid_members = [eid for eid in committee if supply.balances[eid] > 0]
        self.assertEqual(len(paid_members), 3)

    def test_pre_activation_no_committee_still_burns_nothing(self):
        """No-committee codepath is unaffected by the fork: proposer
        absorbs the full reward, no burn."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        supply.balances[proposer] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
        )

        self.assertEqual(result["proposer_reward"], BLOCK_REWARD)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(supply.balances[proposer], BLOCK_REWARD)


class TestPostActivationEvenSplit(unittest.TestCase):
    """Post-activation: attester_pool splits pro-rata across full committee."""

    def test_post_activation_exact_fit_no_burn(self):
        """N=12, attester_pool=12 (BLOCK_REWARD=16): each gets 1 token, 0
        burned.  This matches what pre-activation produced — the happy
        path where pool // N == 1."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(12)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        self.assertEqual(result["total_attestor_reward"], 12)
        # Per-slot divides evenly → 0 burn from the attester pool.
        # Treasury untouched.
        self.assertEqual(result["burned"], 0)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_post_activation_large_committee_per_slot_zero_pool_burns(self):
        """N=20, attester_pool=12: per_slot = 12 // 20 = 0, everyone
        gets 0, 12 burns.  This is the low-pool corner case — the
        committee still attested, reward is a bonus not a gate."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(20)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)
        self.assertEqual(result["total_attestor_reward"], 0)
        # Whole attester_pool (12) burns.
        self.assertEqual(result["burned"], 12)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_post_activation_remainder_burns(self):
        """N=5, attester_pool=12: per_slot = 12 // 5 = 2, total paid = 10,
        remainder = 2 burns."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(5)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 2)
        self.assertEqual(result["total_attestor_reward"], 10)
        # 12 - 10 = 2 remainder burns.
        self.assertEqual(result["burned"], 2)
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_post_activation_floor_era_committee_12(self):
        """BLOCK_REWARD_FLOOR era: reward=4, attester_pool=3.  Post-fork
        a 12-member committee each gets 3 // 12 = 0, pool of 3 burns.

        Pre-fork comparison: same inputs would have paid 3 members 1
        token and truncated the other 9.  Post-fork, all 12 get equal
        (zero) treatment.  The decentralization invariant — committee
        size decoupled from pool — is preserved."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(12)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=POST_ACTIVATION_HEIGHT,
                attester_committee=committee,
            )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)
        # Full attester_pool (3) burns.
        self.assertEqual(result["burned"], 3)
        self.assertEqual(result["total_attestor_reward"], 0)

    def test_post_activation_floor_era_small_committee(self):
        """Floor era with N=3 committee: per_slot = 3 // 3 = 1, everyone
        gets 1, nothing burns.  Back-of-envelope: even at floor, small
        committees retain per-slot income."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(3)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        with _freeze_reward_at_floor():
            result = supply.mint_block_reward(
                proposer,
                block_height=POST_ACTIVATION_HEIGHT,
                attester_committee=committee,
            )

        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        self.assertEqual(result["burned"], 0)
        self.assertEqual(result["total_attestor_reward"], 3)


class TestPostActivationProposerCap(unittest.TestCase):
    """Proposer cap still applies post-activation."""

    def test_proposer_on_committee_capped_after_split(self):
        """Proposer sits on a 4-member committee; per_slot reward = 12//4 = 3.
        Proposer earns proposer_share=4 + slot=3 = 7 > cap(4).  After
        clawback the proposer slot zeros out; proposer_share alone
        (4) equals cap, no further trim."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        others = _make_committee(3)
        committee = [proposer, *others]
        for eid in [proposer, *others, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        # per_slot = 12 // 4 = 3; proposer_share = 4 = cap.
        # Proposer's slot is clawed back (7 > 4), share stays 4.
        self.assertEqual(supply.balances[proposer], PROPOSER_REWARD_CAP)
        for eid in others:
            self.assertEqual(supply.balances[eid], 3)
        # Conservation: 4 + 3*3 + burned == BLOCK_REWARD=16.
        self.assertEqual(
            supply.balances[proposer]
            + sum(supply.balances[o] for o in others)
            + result["burned"],
            BLOCK_REWARD,
        )
        # Treasury untouched.
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_proposer_clawback_burn_tracked(self):
        """Proposer slot clawback tokens flow into the burn total, not
        the treasury."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        others = _make_committee(3)
        committee = [proposer, *others]
        for eid in [proposer, *others, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        initial_burned = supply.total_burned
        result = supply.mint_block_reward(
            proposer,
            block_height=POST_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        # Burned = proposer clawback (3 tokens from proposer's slot).
        # No pool remainder (12 // 4 = 3, 4*3 = 12, remainder=0).
        # But proposer's own slot was clawed: burned = 3.
        self.assertEqual(result["burned"], 3)
        self.assertEqual(supply.total_burned, initial_burned + 3)


class TestConservationOfSupply(unittest.TestCase):
    """Supply invariant: minted - burned == sum of balance deltas."""

    def _run_conservation(self, *, height, committee_size, proposer_in_committee):
        supply = SupplyTracker()
        proposer = b"p" * 32
        others = _make_committee(committee_size - (1 if proposer_in_committee else 0))
        committee = ([proposer] if proposer_in_committee else []) + others
        for eid in [proposer, *others, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        supply_before = supply.total_supply

        result = supply.mint_block_reward(
            proposer,
            block_height=height,
            attester_committee=committee,
        )

        reward = result["total_reward"]
        burned = result["burned"]
        delta_sum = sum(
            supply.balances.get(eid, 0)
            for eid in [proposer, *others, TREASURY_ENTITY_ID]
        )
        self.assertEqual(delta_sum + burned, reward)
        self.assertEqual(supply.total_supply, supply_before + reward - burned)
        # Treasury still never receives reward-pipeline funds.
        self.assertEqual(supply.balances[TREASURY_ENTITY_ID], 0)

    def test_conservation_pre_activation(self):
        self._run_conservation(
            height=PRE_ACTIVATION_HEIGHT,
            committee_size=5,
            proposer_in_committee=False,
        )

    def test_conservation_pre_activation_proposer_included(self):
        self._run_conservation(
            height=PRE_ACTIVATION_HEIGHT,
            committee_size=5,
            proposer_in_committee=True,
        )

    def test_conservation_post_activation_exact_fit(self):
        self._run_conservation(
            height=POST_ACTIVATION_HEIGHT,
            committee_size=12,
            proposer_in_committee=False,
        )

    def test_conservation_post_activation_remainder(self):
        self._run_conservation(
            height=POST_ACTIVATION_HEIGHT,
            committee_size=5,
            proposer_in_committee=False,
        )

    def test_conservation_post_activation_low_pool(self):
        self._run_conservation(
            height=POST_ACTIVATION_HEIGHT,
            committee_size=20,
            proposer_in_committee=False,
        )

    def test_conservation_post_activation_proposer_on_committee(self):
        self._run_conservation(
            height=POST_ACTIVATION_HEIGHT,
            committee_size=4,
            proposer_in_committee=True,
        )


class TestActivationBoundary(unittest.TestCase):
    """The fork gate is inclusive at ATTESTER_REWARD_SPLIT_HEIGHT."""

    def test_height_one_below_activation_uses_legacy_truncate(self):
        """At height ATTESTER_REWARD_SPLIT_HEIGHT - 1: legacy behavior."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(20)
        for eid in [proposer, *committee]:
            supply.balances[eid] = 0

        supply.mint_block_reward(
            proposer,
            block_height=ATTESTER_REWARD_SPLIT_HEIGHT - 1,
            attester_committee=committee,
        )

        # Legacy: first 12 paid, rest 0.
        paid = [eid for eid in committee if supply.balances[eid] > 0]
        self.assertEqual(len(paid), 12)

    def test_height_at_activation_uses_pro_rata(self):
        """At height ATTESTER_REWARD_SPLIT_HEIGHT: new pro-rata behavior."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(20)
        for eid in [proposer, *committee]:
            supply.balances[eid] = 0

        supply.mint_block_reward(
            proposer,
            block_height=ATTESTER_REWARD_SPLIT_HEIGHT,
            attester_committee=committee,
        )

        # Pro-rata: per_slot = 12//20 = 0, all zero.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 0)


if __name__ == "__main__":
    unittest.main()
