"""Snapshot/restore symmetry for ``archive_reward_pool`` scalar.

Audit finding (same defect class as 1.37.0's evidence-collection
snapshot fix, 1.39.0's IL-processor snapshot fix, and 1.39.2's
archive-duty snapshot fix): ``Blockchain._snapshot_memory_state``
and ``_restore_memory_snapshot`` previously omitted the
consensus-relevant ``self.archive_reward_pool`` scalar.

``_apply_block_state`` mutates this scalar on two paths:

  * ``self.archive_reward_pool += _withheld`` at the validator-
    coverage withhold path (``blockchain.py:10987``-area), which
    funnels withheld attester rewards into the pool;
  * the ``ArchiveRewardPool`` wrapper write-back at the archive-
    rewards payout path (around ``blockchain.py:11536``-11559),
    which decrements the pool when challenge proofs are paid out.

The pool is captured in the on-disk state-snapshot blob via
``_GLOBAL_ARCHIVE_REWARD_POOL`` (state_snapshot.py) and restored
on state-sync via ``_install_state_snapshot``
(``blockchain.py:1731``).  But ``_snapshot_memory_state`` never
captures it and ``_restore_memory_snapshot`` never restores it.

A bad-state-root block whose apply path bumped the pool (or
drained it via a forged archive-rewards distribution) is caught
by the post-apply state_root check and rolled back via
``_restore_memory_snapshot``.  Pre-fix, the pool mutation
survives that rollback — the in-memory pool diverges from honest
peers' replayed state, which:

  1. silently drains future archive-reward payouts into a phantom
     pool balance the canonical chain never funded, and/or
  2. funnels withheld rewards onto a pool the honest peers see at
     a different baseline.

Either direction diverges total_supply accounting at the next
honest block whose post-state-root commitment includes the
archive-pool baseline, producing a silent fork.

No-fork: snapshot/restore is purely in-memory; the chaindb mirror
runs only after the state-root check passes, so historical replay
is byte-identical.  No activation gate needed — purely closes a
silent in-memory leak that was never observed under honest play.
"""

from __future__ import annotations

import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


class TestArchiveRewardPoolSnapshotSymmetry(unittest.TestCase):
    """Pin ``_snapshot_memory_state`` / ``_restore_memory_snapshot``
    captures and restores the archive_reward_pool scalar.

    Each test seeds the pool to a non-zero value, takes a snapshot,
    mutates the pool (simulating the apply path of a bad-state-root
    block), then restores from the snapshot and asserts the
    mutation was rolled back.
    """

    def setUp(self):
        self.proposer = Entity.create(b"arp-snap-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_pool_increment_is_rolled_back(self):
        """Withheld-rewards funnel poisoning: an apply-path increment
        to ``archive_reward_pool`` from a bad-state-root block must
        NOT survive the rollback.  Pre-fix the increment leaks past
        the rollback and inflates the pool baseline above honest
        peers, diverging future challenge-payout decisions.
        """
        self.chain.archive_reward_pool = 1_000
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path bumping the pool from a bad-state-root
        # block (e.g. a withhold path firing on attacker-chosen
        # bundle).
        self.chain.archive_reward_pool += 12_345

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.archive_reward_pool,
            1_000,
            "archive_reward_pool must be rolled back to the "
            "pre-apply value — pre-fix the increment survives a "
            "failed-state-root rollback and inflates the pool "
            "baseline above honest peers.",
        )

    def test_pool_decrement_is_rolled_back(self):
        """Symmetric to the increment case: an apply-path decrement
        (e.g. attacker-forged archive-rewards distribution that
        drained the pool) on a bad-state-root block must NOT leave
        the pool at the diminished value.  Pre-fix the canonical
        chain's pool balance is silently dropped and future payouts
        diverge.
        """
        self.chain.archive_reward_pool = 50_000
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path draining the pool via a forged payout
        # distribution.
        self.chain.archive_reward_pool = 0

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.archive_reward_pool,
            50_000,
            "archive_reward_pool must be rolled back when the "
            "rejected block drained it — pre-fix the canonical "
            "chain's pool balance is silently dropped.",
        )

    def test_pool_zero_baseline_round_trips(self):
        """A snapshot taken when the pool is at zero (cold-start
        baseline) and restored after a manual bump must zero the
        pool back out.  Catches a future restore-side bug where the
        default fallback for a missing key silently leaves the
        live value untouched."""
        self.chain.archive_reward_pool = 0
        snapshot = self.chain._snapshot_memory_state()

        # Manual mutation simulating the apply path.
        self.chain.archive_reward_pool = 999

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.archive_reward_pool,
            0,
            "archive_reward_pool must be reset to the zero baseline "
            "captured by the snapshot — pre-fix the live value "
            "leaks across the rollback boundary unconditionally.",
        )


class TestArchiveRewardPoolRestoreStructuralSymmetry(unittest.TestCase):
    """Structural guard locking the symmetry between snapshot and
    restore for archive_reward_pool.  Catches the next defect of
    this class at CI time: if a future refactor adds the snapshot
    key but forgets the restore (or vice versa), this blows up.
    """

    POOL_KEY = "archive_reward_pool"

    def setUp(self):
        self.proposer = Entity.create(b"arp-symm-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_archive_reward_pool_is_present_in_snapshot(self):
        """The snapshot dict must carry the archive_reward_pool key.
        If a future refactor renames or drops it, this fails
        immediately.
        """
        snapshot = self.chain._snapshot_memory_state()
        self.assertIn(
            self.POOL_KEY, snapshot,
            f"_snapshot_memory_state must include '{self.POOL_KEY}' — "
            f"missing key drops the archive_reward_pool scalar from "
            f"the rollback boundary, reintroducing the pool-balance "
            f"poisoning attack.",
        )

    def test_round_trip_restores_archive_reward_pool(self):
        """Mutate the pool, take a snapshot, blow live state away,
        restore, and check the value matches the snapshot."""
        self.chain.archive_reward_pool = 7_777_777

        snapshot = self.chain._snapshot_memory_state()

        # Reset live state.
        self.chain.archive_reward_pool = 0

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(self.chain.archive_reward_pool, 7_777_777)


if __name__ == "__main__":
    unittest.main()
