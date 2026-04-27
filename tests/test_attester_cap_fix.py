"""Tests for the attester-reward cap formula fix (hard fork).

Background
----------
The original cap (ATTESTER_REWARD_CAP_HEIGHT = 60_000) was

    cap = attester_pool_this_block * PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS
          * FINALITY_INTERVAL // 10_000

`attester_pool_this_block` includes the fee-funded component, which
varies wildly per block.  A high-fee block in the first slot of an
epoch would let entities on that committee bank huge rewards under
a temporarily-large cap; a low-fee block would lower the cap later
in the same epoch.  Result: path-dependent.

Fix (ATTESTER_CAP_FIX_HEIGHT, 70_000): cap uses the issuance-only
component, not the fee-funded portion:

    cap = (reward - proposer_share) * PER_VALIDATOR... * FINALITY_INTERVAL
          // 10_000

At BLOCK_REWARD=16, proposer_share=4, issuance pool = 12, cap =
12 * 100 * 100 / 10_000 = 12 tokens/entity/epoch.  At floor era
(reward=4): cap = 3 * 100 * 100 / 10_000 = 3.  Stable, predictable,
path-independent.

Pre-activation (block_height < ATTESTER_CAP_FIX_HEIGHT): keep the
old (broken, fee-dependent) formula byte-for-byte.
"""

import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    ATTESTER_REWARD_CAP_HEIGHT,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_FEE_FUNDING_HEIGHT,
    ATTESTER_CAP_FIX_HEIGHT,
    BLOCK_REWARD,
    FINALITY_INTERVAL,
    GENESIS_SUPPLY,
    PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH,
    PROPOSER_REWARD_NUMERATOR,
    PROPOSER_REWARD_DENOMINATOR,
    TREASURY_ENTITY_ID,
)


# Heights straddling the fix activation.
PRE_FIX_HEIGHT = ATTESTER_CAP_FIX_HEIGHT - 1       # old (broken) formula
POST_FIX_HEIGHT = ATTESTER_CAP_FIX_HEIGHT          # new (issuance-only) formula


def _post_fix_epoch_start() -> int:
    """Return the first epoch start at-or-after POST_FIX_HEIGHT.

    Pre-1.26.0 the canonical fork heights were placed on epoch
    boundaries (e.g. 2300), so `(POST_FIX // INTERVAL) * INTERVAL`
    coincided with POST_FIX itself.  After the 1.26.0 fork sweep the
    activation heights cluster at 700-720 and may not land on an
    epoch boundary; round UP so the helper still returns a height
    where FIX is unambiguously active across the whole epoch.
    """
    return ((POST_FIX_HEIGHT - 1) // FINALITY_INTERVAL + 1) * FINALITY_INTERVAL


def _make_committee(n: int) -> list[bytes]:
    out: list[bytes] = []
    i = 0
    while len(out) < n:
        b = (i + 0x10) & 0xFF
        if b == 0x70:
            i += 1
            continue
        out.append(bytes([b]) * 32)
        i += 1
    return out


def _issuance_attester_pool(reward=BLOCK_REWARD):
    """The cap-relevant pool = reward - proposer_share."""
    proposer_share = (
        reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
    )
    return reward - proposer_share


class TestPreFixPreservesOldFormula(unittest.TestCase):
    """Pre-fix heights use the old fee-dependent formula.  Confirmed
    by setting a large fee accumulator and verifying the cap scales
    with the fee-funded pool (indicating the old formula fires)."""

    def test_pre_fix_cap_tracks_fee_pool(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        supply.attester_fee_pool_this_block = 500

        # Use a pre-fix height where the cap HAS activated
        # (ATTESTER_REWARD_CAP_HEIGHT <= height < ATTESTER_CAP_FIX_HEIGHT).
        # attester_pool = 12 (issuance) + 500 (fee) = 512.
        # OLD cap_per_entity = 512 * 100 * 100 / 10_000 = 512.
        # Pre-seed tracker with 511 so only 1 token credits.
        epoch_start = (
            (PRE_FIX_HEIGHT // FINALITY_INTERVAL) * FINALITY_INTERVAL
        )
        supply.attester_epoch_earnings_start = epoch_start
        supply.attester_epoch_earnings = {eid: 511 for eid in committee}

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_FIX_HEIGHT,
            attester_committee=committee,
        )
        # Each entity should get exactly 1 token under old formula
        # (cap = 512, earned = 511, available = 1).
        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)


class TestPostFixIssuanceOnlyCap(unittest.TestCase):
    """Post-fix cap is computed from issuance-only portion."""

    def test_post_fix_cap_value(self):
        """With BLOCK_REWARD=16, issuance_attester_pool=12, cap=
        12 * 100 * 100 / 10_000 = 12 tokens/entity/epoch."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        # Large fee pool — would inflate old cap to 512+
        supply.attester_fee_pool_this_block = 500

        # Pre-seed tracker to 11 (cap-1).  Mint at the first block of
        # the post-fix epoch so the tracker's epoch_start matches
        # mint's epoch (the in-place tracker would otherwise reset on
        # epoch boundary and the pre-seed would be discarded).
        epoch_start = _post_fix_epoch_start()
        supply.attester_epoch_earnings_start = epoch_start
        supply.attester_epoch_earnings = {eid: 11 for eid in committee}

        supply.mint_block_reward(
            proposer,
            block_height=epoch_start,
            attester_committee=committee,
        )
        # cap_per_entity = 12; earned = 11; available = 1; credit = 1.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)

    def test_post_fix_cap_is_fee_independent(self):
        """Identical cap values regardless of fee accumulator —
        path-independence property."""
        expected_cap = (
            _issuance_attester_pool(BLOCK_REWARD)
            * PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH
            * FINALITY_INTERVAL
            // 10_000
        )
        self.assertEqual(expected_cap, 12)

        for fee_pool in [0, 100, 500, 5000, 50_000]:
            supply = SupplyTracker()
            proposer = b"p" * 32
            committee = _make_committee(128)
            for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
                supply.balances[eid] = 0
            supply.attester_fee_pool_this_block = fee_pool
            # Pre-seed at cap so the NEXT credit is cap-bound.  Mint
            # at the first block of the post-fix epoch so the tracker
            # doesn't reset across an epoch boundary.
            epoch_start = _post_fix_epoch_start()
            supply.attester_epoch_earnings_start = epoch_start
            supply.attester_epoch_earnings = {
                eid: expected_cap for eid in committee
            }

            supply.mint_block_reward(
                proposer,
                block_height=epoch_start,
                attester_committee=committee,
            )
            # Tracker pinned at cap regardless of fee_pool.
            for eid in committee:
                self.assertEqual(
                    supply.attester_epoch_earnings[eid], expected_cap,
                )


class TestPathIndependence(unittest.TestCase):
    """The central property: same entity earnings regardless of the
    order of high-fee and low-fee blocks within an epoch."""

    def _run_epoch(self, fee_sequence):
        """Simulate one block per element in fee_sequence, return the
        final per-entity earnings of the committee."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        epoch_start = _post_fix_epoch_start()
        for i, fee_pool in enumerate(fee_sequence):
            supply.attester_fee_pool_this_block = fee_pool
            supply.mint_block_reward(
                proposer,
                block_height=epoch_start + i,
                attester_committee=committee,
            )
        return {eid: supply.balances[eid] for eid in committee}

    def test_high_then_low_equals_low_then_high(self):
        """Two epochs with identical fee multisets but different
        orderings must produce identical per-entity earnings."""
        # Sequence A: high-fee first, then lows.
        seq_a = [5000, 0, 0, 0, 0]
        # Sequence B: lows first, high-fee last.
        seq_b = [0, 0, 0, 0, 5000]
        earnings_a = self._run_epoch(seq_a)
        earnings_b = self._run_epoch(seq_b)
        self.assertEqual(earnings_a, earnings_b)

    def test_shuffled_order_same_result(self):
        """An arbitrary permutation of the same fee sequence gives
        the same result."""
        import random
        fees = [100, 500, 2000, 50, 3000, 0, 10_000]
        rng = random.Random(42)
        shuffled = list(fees)
        rng.shuffle(shuffled)
        earnings_a = self._run_epoch(fees)
        earnings_b = self._run_epoch(shuffled)
        self.assertEqual(earnings_a, earnings_b)


class TestActivationBoundary(unittest.TestCase):
    """The fix fires at exactly ATTESTER_CAP_FIX_HEIGHT."""

    def test_one_below_fix_uses_old_formula(self):
        """At PRE_FIX_HEIGHT with a large fee pool, the old formula's
        cap is large enough to admit per_slot_reward."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        supply.attester_fee_pool_this_block = 500

        # pool = 512, per_slot = 4, old cap = 512 — each entity earns 4.
        supply.mint_block_reward(
            proposer,
            block_height=PRE_FIX_HEIGHT,
            attester_committee=committee,
        )
        for eid in committee:
            self.assertEqual(supply.balances[eid], 4)

    def test_at_fix_uses_new_formula(self):
        """At POST_FIX_HEIGHT, the cap is the ISSUANCE-ONLY value = 12.
        With pool = 512 and per_slot = 4, each entity can earn 4 per
        block (4 < 12), so one block's earnings equal per_slot.  But
        after three blocks at per_slot=4, earnings hit 12 and the cap
        clamps subsequent credits to zero."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        epoch_start = _post_fix_epoch_start()
        # Mint 3 blocks each with per_slot=4.  After each, earnings
        # increment by 4 → 4, 8, 12.
        for offset in range(3):
            supply.attester_fee_pool_this_block = 500
            supply.mint_block_reward(
                proposer,
                block_height=epoch_start + offset,
                attester_committee=committee,
            )
        for eid in committee:
            self.assertEqual(supply.attester_epoch_earnings[eid], 12)
            self.assertEqual(supply.balances[eid], 12)

        # Fourth block — cap hit; no more credits to attester balances.
        pre_balances = {eid: supply.balances[eid] for eid in committee}
        supply.attester_fee_pool_this_block = 500
        supply.mint_block_reward(
            proposer,
            block_height=epoch_start + 3,
            attester_committee=committee,
        )
        for eid in committee:
            self.assertEqual(supply.balances[eid], pre_balances[eid])


class TestSupplyInvariant(unittest.TestCase):
    """The chain-level supply invariant must hold across fix
    activation."""

    def test_invariant_across_fix(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        base = (
            (ATTESTER_CAP_FIX_HEIGHT // FINALITY_INTERVAL) * FINALITY_INTERVAL
        )
        for offset in range(-FINALITY_INTERVAL, FINALITY_INTERVAL * 2):
            supply.attester_fee_pool_this_block = 500
            supply.mint_block_reward(
                proposer,
                block_height=base + offset,
                attester_committee=committee,
            )
            self.assertEqual(
                supply.total_supply,
                GENESIS_SUPPLY + supply.total_minted - supply.total_burned,
            )


if __name__ == "__main__":
    unittest.main()
