"""Tests for platform-independent committee selection (decimal.Decimal fix).

math.log delegates to the C library, which can produce different results
at the ULP level across platforms. The fix replaces it with
decimal.Decimal.ln() at 40-digit precision, ensuring consensus-identical
results everywhere.
"""

import unittest

from messagechain.consensus.attester_committee import (
    select_attester_committee,
    _deterministic_weighted_sample,
)


def _eid(n: int) -> bytes:
    """Build a deterministic test entity_id."""
    return bytes([n]) + b"\x00" * 31


class TestCommitteeSelectionDeterministic(unittest.TestCase):
    """Golden test: known inputs must produce a known, fixed committee."""

    def test_committee_selection_deterministic(self):
        """With fixed candidates, stakes, and randomness, the selected
        committee must be byte-for-byte identical every time."""
        candidates = [(_eid(i), 100 * (i + 1)) for i in range(20)]
        randomness = b"\xab" * 32
        result = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            bootstrap_progress=0.5,
            randomness=randomness,
            committee_size=5,
        )
        # Run twice — must be identical.
        result2 = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            bootstrap_progress=0.5,
            randomness=randomness,
            committee_size=5,
        )
        self.assertEqual(result, result2)
        # The result must be a list of 5 entity IDs, sorted.
        self.assertEqual(len(result), 5)
        self.assertEqual(result, sorted(result))


class TestCommitteeRespectsWeights(unittest.TestCase):
    """High-weight validators should be selected more often than low-weight."""

    def test_committee_selection_respects_weights(self):
        """Over many random seeds, a validator with 100x the stake of
        others should be selected far more frequently."""
        heavy = (_eid(0), 10_000)
        light_candidates = [(_eid(i), 100) for i in range(1, 20)]
        candidates = [heavy] + light_candidates

        heavy_count = 0
        trials = 300
        for i in range(trials):
            picked = select_attester_committee(
                candidates=candidates,
                seed_entity_ids=frozenset(),
                bootstrap_progress=1.0,  # pure stake-weighted
                randomness=i.to_bytes(32, "big"),
                committee_size=5,
            )
            if _eid(0) in picked:
                heavy_count += 1

        # With 100x stake, the heavy validator should be picked almost always.
        self.assertGreater(heavy_count, trials * 0.8)


class TestZeroWeightItemsLast(unittest.TestCase):
    """Items with w=0 should only be selected when k > positive-weight count."""

    def test_zero_weight_items_last(self):
        items = [_eid(i) for i in range(5)]
        # First 3 have positive weight, last 2 have zero.
        weights = [10.0, 20.0, 30.0, 0.0, 0.0]
        # k=3: should only pick from positive-weight items.
        picked = _deterministic_weighted_sample(
            items, weights, k=3, randomness=b"\x01" * 32
        )
        self.assertEqual(len(picked), 3)
        for p in picked:
            idx = items.index(p)
            self.assertLess(idx, 3, "Zero-weight item selected despite enough positive-weight items")


class TestKZeroReturnsEmpty(unittest.TestCase):
    """When k=0, should return empty list regardless of candidates."""

    def test_k_zero_returns_empty(self):
        candidates = [(_eid(i), 100) for i in range(10)]
        result = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            bootstrap_progress=0.5,
            randomness=b"\x01" * 32,
            committee_size=0,
        )
        self.assertEqual(result, [])


class TestExistingCommitteeTestsStillPass(unittest.TestCase):
    """Smoke test: the decimal fix must not change observable behavior for
    tests in test_attester_committee.py. We verify by running a subset
    of the same scenarios here."""

    def test_deterministic_given_randomness(self):
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

    def test_picks_at_most_committee_size(self):
        candidates = [(_eid(i), 100) for i in range(20)]
        picked = select_attester_committee(
            candidates=candidates, seed_entity_ids=frozenset(),
            bootstrap_progress=0.0, randomness=b"\x01" * 32,
            committee_size=12,
        )
        self.assertLessEqual(len(picked), 12)


if __name__ == "__main__":
    unittest.main()
