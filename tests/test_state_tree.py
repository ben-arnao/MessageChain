"""
Tests for SparseMerkleTree — the incremental state commitment.

Covers the three invariants that actually matter for consensus:

    determinism  — same state → same root, regardless of insertion order
    incrementality — set/remove do O(TREE_DEPTH) work, not O(N)
    rollback     — begin/rollback restores prior state exactly

Plus a scaling benchmark so a future regression that drops us back to
O(N) per update gets caught before merge.
"""

import time
import unittest

from messagechain.core.state_tree import (
    SparseMerkleTree,
    TREE_DEPTH,
    EMPTY_ROOT,
    compute_state_root,
)


def _eid(i: int) -> bytes:
    return i.to_bytes(32, "big")


class TestSparseMerkleTreeBasics(unittest.TestCase):
    def test_empty_tree_has_fixed_root(self):
        tree = SparseMerkleTree()
        self.assertEqual(tree.root(), EMPTY_ROOT)

    def test_single_account_changes_root(self):
        tree = SparseMerkleTree()
        empty = tree.root()
        tree.set(_eid(1), balance=100, nonce=0, stake=0)
        self.assertNotEqual(tree.root(), empty)

    def test_idempotent_set(self):
        tree = SparseMerkleTree()
        tree.set(_eid(1), 100, 0, 0)
        r1 = tree.root()
        tree.set(_eid(1), 100, 0, 0)  # same triple
        r2 = tree.root()
        self.assertEqual(r1, r2)

    def test_remove_clears_contribution(self):
        tree = SparseMerkleTree()
        empty = tree.root()
        tree.set(_eid(7), 5, 2, 0)
        self.assertNotEqual(tree.root(), empty)
        tree.remove(_eid(7))
        self.assertEqual(tree.root(), empty)

    def test_zero_triple_treated_as_removal(self):
        tree = SparseMerkleTree()
        tree.set(_eid(1), 10, 1, 0)
        with_entry = tree.root()
        tree.set(_eid(1), 0, 0, 0)  # back to all-zero
        self.assertEqual(tree.root(), EMPTY_ROOT)
        self.assertNotEqual(with_entry, tree.root())


class TestDeterminismAndOrdering(unittest.TestCase):
    def test_insertion_order_independent(self):
        items = [(_eid(i), i * 10, i, 0) for i in range(50)]

        t1 = SparseMerkleTree()
        for eid, b, n, s in items:
            t1.set(eid, b, n, s)

        t2 = SparseMerkleTree()
        for eid, b, n, s in reversed(items):
            t2.set(eid, b, n, s)

        self.assertEqual(t1.root(), t2.root())

    def test_same_state_same_root(self):
        accounts = {_eid(i): (i + 100, i, 0) for i in range(30)}

        t1 = SparseMerkleTree()
        for eid, (b, n, s) in accounts.items():
            t1.set(eid, b, n, s)

        t2 = SparseMerkleTree()
        for eid, (b, n, s) in accounts.items():
            t2.set(eid, b, n, s)

        self.assertEqual(t1.root(), t2.root())

    def test_compute_state_root_order_independent(self):
        bals = {_eid(1): 100, _eid(2): 200, _eid(3): 300}
        nonces = {_eid(1): 0, _eid(2): 1, _eid(3): 2}
        staked = {_eid(2): 50}

        r1 = compute_state_root(bals, nonces, staked)
        r2 = compute_state_root(
            dict(reversed(list(bals.items()))),
            nonces,
            staked,
        )
        self.assertEqual(r1, r2)


class TestJournalRollback(unittest.TestCase):
    def test_rollback_restores_empty_tree(self):
        tree = SparseMerkleTree()
        empty = tree.root()
        tree.begin()
        tree.set(_eid(1), 100, 0, 0)
        tree.set(_eid(2), 200, 1, 0)
        self.assertNotEqual(tree.root(), empty)
        tree.rollback()
        self.assertEqual(tree.root(), empty)
        self.assertEqual(len(tree), 0)

    def test_rollback_restores_preexisting_accounts(self):
        tree = SparseMerkleTree()
        tree.set(_eid(1), 100, 0, 0)
        tree.set(_eid(2), 200, 1, 0)
        baseline = tree.root()

        tree.begin()
        tree.set(_eid(1), 999, 5, 0)  # modify existing
        tree.set(_eid(3), 50, 0, 0)   # add new
        tree.remove(_eid(2))          # remove existing
        self.assertNotEqual(tree.root(), baseline)
        tree.rollback()

        self.assertEqual(tree.root(), baseline)
        # Tree now stores an 8-tuple; slice to the (balance, nonce, stake)
        # prefix since the rollback test doesn't exercise authority fields.
        self.assertEqual(tree.get(_eid(1))[:3], (100, 0, 0))
        self.assertEqual(tree.get(_eid(2))[:3], (200, 1, 0))
        self.assertIsNone(tree.get(_eid(3)))

    def test_commit_keeps_changes(self):
        tree = SparseMerkleTree()
        tree.set(_eid(1), 100, 0, 0)
        tree.begin()
        tree.set(_eid(1), 999, 5, 0)
        tree.commit()
        tree.rollback()  # no-op, journal already cleared
        self.assertEqual(tree.get(_eid(1))[:3], (999, 5, 0))

    def test_nested_begin_raises(self):
        tree = SparseMerkleTree()
        tree.begin()
        with self.assertRaises(RuntimeError):
            tree.begin()


class TestSerialization(unittest.TestCase):
    def test_roundtrip_preserves_root(self):
        tree = SparseMerkleTree()
        # i+1 for balance so no account hits the all-zero "removal"
        # edge case — otherwise i=0 would be treated as absent.
        for i in range(20):
            tree.set(_eid(i), (i + 1) * 10, i, i % 3)
        root_before = tree.root()

        dumped = tree.serialize()
        restored = SparseMerkleTree.deserialize(dumped)
        self.assertEqual(restored.root(), root_before)
        self.assertEqual(len(restored), 20)

    def test_deserialize_empty(self):
        restored = SparseMerkleTree.deserialize({"version": 1, "accounts": []})
        self.assertEqual(restored.root(), EMPTY_ROOT)


class TestScalingEnvelope(unittest.TestCase):
    """Regression guard: per-update cost should NOT grow with N.

    If someone makes an update accidentally O(N) (e.g., by rebuilding
    the tree on every write) this test will fail well before a real
    user notices on a big chain.
    """

    def test_update_cost_independent_of_population(self):
        small = SparseMerkleTree()
        for i in range(50):
            small.set(_eid(i + 1), i + 1, 0, 0)

        large = SparseMerkleTree()
        for i in range(500):
            large.set(_eid(i + 1), i + 1, 0, 0)

        # Time a single extra update on each. The two should be
        # comparable — the constant factor for TREE_DEPTH dominates,
        # not population.
        t0 = time.time()
        small.set(_eid(99999), 1, 1, 1)
        small_elapsed = time.time() - t0

        t0 = time.time()
        large.set(_eid(99999), 1, 1, 1)
        large_elapsed = time.time() - t0

        # Generous envelope: large shouldn't be more than ~5x slower
        # than small even with cache/GC noise, because both do the
        # same TREE_DEPTH hash operations per update.
        self.assertLess(
            large_elapsed, max(small_elapsed * 5, 0.05),
            f"Update at N=500 ({large_elapsed:.4f}s) is much slower "
            f"than at N=100 ({small_elapsed:.4f}s) — likely O(N) regression",
        )


if __name__ == "__main__":
    unittest.main()
