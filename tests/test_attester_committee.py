"""Attester committee selection.

Today every validator who attests a block shares the 12-token attestor
pool pro-rata by stake.  This concentrates all rewards in high-stake
validators and gives a newcomer with 1 token effectively zero income —
a non-starter for bootstrap where we want honest newcomers to earn
their first stake from nothing.

This module replaces that with a fixed-slot committee:

  * Up to K attesters are selected per block (K = attester_pool_tokens,
    so each slot pays exactly 1 token).
  * Selection weights interpolate between uniform (bootstrap) and
    stake-weighted (mature PoS) based on `bootstrap_progress`.
  * During early bootstrap (progress < 0.5) seeds are excluded from
    committee selection, so the founder doesn't compete with newcomers
    for the attester pool.
  * Unfilled slots (fewer attesters than K) — excess tokens go to the
    treasury, same pattern as PROPOSER_REWARD_CAP.

The selection is deterministic given a seed (the block hash), so
every node in the network agrees on the same committee for any given
block.  No consensus protocol change — this is purely a reward-layer
mechanism on top of the existing attestation flow.
"""

import unittest

from messagechain.consensus.attester_committee import (
    ATTESTER_REWARD_PER_SLOT,
    SEED_EXCLUSION_CROSSOVER,
    seed_weight_multiplier,
    select_attester_committee,
    weights_for_progress,
)


def _eid(n: int) -> bytes:
    """Build a deterministic test entity_id."""
    return bytes([n]) + b"\x00" * 31


class TestSelectionWeights(unittest.TestCase):
    """weights_for_progress interpolates linearly from uniform to stake-weighted."""

    def test_pure_uniform_at_progress_zero(self):
        """At bootstrap_progress = 0, every attester weighted equally.

        Stake differences are ignored entirely.  A 1-token attester
        has the same selection probability as a 1M-token attester.
        """
        stakes = [1, 100, 10_000, 1_000_000]
        w = weights_for_progress(stakes, bootstrap_progress=0.0)
        self.assertEqual(len(set(w)), 1)  # all equal

    def test_pure_stake_weighted_at_progress_one(self):
        """At bootstrap_progress = 1, weights equal stakes.

        Matches the pre-committee "normal PoS" regime — large stakers
        dominate selection.
        """
        stakes = [1, 100, 10_000, 1_000_000]
        w = weights_for_progress(stakes, bootstrap_progress=1.0)
        # Weights must be proportional to stakes.  Ratios equal.
        for i in range(len(stakes)):
            self.assertEqual(w[i] * stakes[0], w[0] * stakes[i])

    def test_midway_is_blend(self):
        """At progress = 0.5, weights are the linear midpoint of uniform and stake.

        Keeps the gradient smooth — no sudden regime shifts for any
        downstream consumer.
        """
        stakes = [1, 1000]
        w = weights_for_progress(stakes, bootstrap_progress=0.5)
        # At p=0.5: w_i = 0.5 * (1/n) + 0.5 * (stake_i / total_stake)
        # Relative weights should NOT be equal (some stake influence)
        # AND NOT proportional to stake alone (some uniform influence).
        self.assertNotEqual(w[0], w[1])
        self.assertLess(w[1] / max(w[0], 1e-9), 1000)  # not pure-stake ratio


class TestCommitteeSelection(unittest.TestCase):
    """select_attester_committee picks up to K attesters for one block."""

    def test_picks_at_most_committee_size(self):
        """Never returns more than the committee_size cap."""
        candidates = [(_eid(i), 100) for i in range(20)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x01" * 32,
            committee_size=12,
        )
        self.assertLessEqual(len(picked), 12)

    def test_picks_all_when_fewer_than_committee(self):
        """If N < K, all N candidates are selected (no slot left unfilled for no reason)."""
        candidates = [(_eid(i), 100) for i in range(5)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x02" * 32,
            committee_size=12,
        )
        self.assertEqual(len(picked), 5)
        self.assertEqual(set(picked), {_eid(i) for i in range(5)})

    def test_no_duplicates(self):
        """A single entity is selected at most once per block."""
        candidates = [(_eid(i), 100) for i in range(30)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x03" * 32,
            committee_size=12,
        )
        self.assertEqual(len(picked), len(set(picked)))

    def test_deterministic_given_randomness(self):
        """Same inputs → same committee.  Required for consensus agreement."""
        candidates = [(_eid(i), 100 * (i + 1)) for i in range(20)]
        seed = b"\x05" * 32
        a = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.3, randomness=seed, committee_size=12,
        )
        b = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.3, randomness=seed, committee_size=12,
        )
        self.assertEqual(a, b)

    def test_different_randomness_different_committee(self):
        """With enough candidates, different block hashes yield different committees."""
        candidates = [(_eid(i), 100) for i in range(30)]
        a = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x01" * 32, committee_size=12,
        )
        b = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x02" * 32, committee_size=12,
        )
        # They should differ (not proof of randomness, but smoke test).
        self.assertNotEqual(set(a), set(b))


class TestSeedExclusion(unittest.TestCase):
    """Seeds are excluded from the attester committee early in bootstrap.

    Rationale: seeds already dominate proposer rewards (stake-weighted).
    Reserving the attester pool for newcomers during early bootstrap
    accelerates external stake accumulation without requiring any
    founder action.  The exclusion is a SMOOTH RAMP: fully excluded at
    progress=0, linearly rejoining until fully included at
    progress >= SEED_EXCLUSION_CROSSOVER (0.5).  Replaces a binary cliff
    that caused a user-observable earnings discontinuity at the
    crossover.
    """

    def test_seeds_fully_excluded_at_genesis(self):
        """With progress = 0, seeds never appear in the committee."""
        seeds = frozenset({_eid(0), _eid(1), _eid(2)})
        candidates = [(_eid(i), 100) for i in range(10)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=seeds,
            bootstrap_progress=0.0, randomness=b"\x10" * 32,
            committee_size=12,
        )
        self.assertTrue(seeds.isdisjoint(set(picked)))

    def test_seeds_fully_included_at_or_above_crossover(self):
        """At progress >= 0.5, seeds eligible alongside everyone else."""
        seeds = frozenset({_eid(0), _eid(1), _eid(2)})
        # Only seeds are candidates — if excluded, committee is empty.
        candidates = [(_eid(i), 100) for i in range(3)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=seeds,
            bootstrap_progress=0.5, randomness=b"\x11" * 32,
            committee_size=12,
        )
        self.assertEqual(len(picked), 3)  # all seeds selected

    def test_exclusion_is_smooth_not_cliff(self):
        """At progress = 0.25 (halfway to crossover), seeds have
        roughly half the weight of newcomers with equal stake.  Across
        many independent slot randomness values, newcomers should be
        selected noticeably more often than seeds."""
        seeds = frozenset({_eid(0)})
        # 1 seed + 1 newcomer, equal stake.  Without tilt they'd be
        # 50/50; with tilt=0.5 the seed's weight is halved → newcomer
        # should win ~2/3 of slots.
        candidates = [(_eid(0), 100), (_eid(1), 100)]
        newcomer_wins = 0
        trials = 200
        for i in range(trials):
            picked = select_attester_committee(
                candidates=candidates, seed_entity_ids=seeds,
                bootstrap_progress=0.25,
                randomness=i.to_bytes(32, "big"),
                committee_size=1,
            )
            if picked == [_eid(1)]:
                newcomer_wins += 1
        # Expected ≈ 2/3 (seed tilt=0.5, newcomer tilt=1.0).  Allow
        # a wide band for sampling noise at N=200.
        self.assertGreater(newcomer_wins, trials * 0.55)
        self.assertLess(newcomer_wins, trials * 0.80)

    def test_full_exclusion_with_mixed_pool_at_genesis(self):
        """At progress=0 with seeds + newcomers: only newcomers picked."""
        seeds = frozenset({_eid(0), _eid(1)})
        candidates = (
            [(_eid(0), 1_000_000), (_eid(1), 1_000_000)]  # two seeds
            + [(_eid(i), 10) for i in range(2, 8)]         # six newcomers
        )
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=seeds,
            bootstrap_progress=0.0, randomness=b"\x12" * 32,
            committee_size=12,
        )
        # All six newcomers selected, zero seeds.
        self.assertEqual(set(picked), {_eid(i) for i in range(2, 8)})


class TestSeedWeightMultiplier(unittest.TestCase):
    """The smooth-ramp multiplier is a simple linear function of progress."""

    def test_zero_at_genesis(self):
        self.assertEqual(seed_weight_multiplier(0.0), 0.0)

    def test_one_at_and_above_crossover(self):
        self.assertEqual(seed_weight_multiplier(0.5), 1.0)
        self.assertEqual(seed_weight_multiplier(0.75), 1.0)
        self.assertEqual(seed_weight_multiplier(1.0), 1.0)

    def test_halfway_between_is_half(self):
        self.assertAlmostEqual(seed_weight_multiplier(0.25), 0.5)

    def test_crossover_constant_is_half(self):
        self.assertEqual(SEED_EXCLUSION_CROSSOVER, 0.5)

    def test_reward_per_slot_is_integer_positive(self):
        self.assertIsInstance(ATTESTER_REWARD_PER_SLOT, int)
        self.assertGreater(ATTESTER_REWARD_PER_SLOT, 0)


if __name__ == "__main__":
    unittest.main()
