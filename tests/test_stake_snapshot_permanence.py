"""Tests for permanent retention of per-block stake snapshots.

CLAUDE.md principle #2 — message permanence & censorship resistance —
extends to consensus-critical state such as stake snapshots.  Historical
finality/attestation proofs must remain verifiable from the chain's
state forever, so snapshots cannot be pruned after a retention window.

Snapshots are tiny (a dict of {entity_id_32B: stake_int} per block).
At a few hundred validators they are on the order of a few tens of KB
per block, and the protocol's design trade-offs ("slow transactions
and expensive fees are acceptable if they combat ledger bloat") already
push against spamming churn, so unbounded retention is cheap relative
to block payloads.  See the companion commit message for a numeric
estimate.

These tests assert:
    1. _record_stake_snapshot never deletes earlier entries even when
       many more than the old `_stake_snapshot_retention` threshold
       have accumulated.
    2. A specifically-pinned early snapshot (e.g. block 0) survives
       past the old 1024-block cutoff.
    3. The old retention-driven pruning branch is gone: pumping
       thousands of snapshots keeps every single one.
"""

import unittest

from messagechain.core.blockchain import Blockchain


class TestStakeSnapshotPermanence(unittest.TestCase):
    """Snapshots are permanent — no retention-based pruning."""

    def test_record_many_snapshots_keeps_block_zero(self):
        """Record >1024 snapshots; the earliest one must still exist.

        The old code pruned entries whose block_number was below
        `latest_block - 1024`, so block 0 would be dropped once
        block 1025 was recorded.  With pruning removed, block 0
        stays put.
        """
        bc = Blockchain()
        # Record block 0 explicitly (initialize_genesis would do this
        # on a real founder node, but Blockchain() here is the bare
        # constructor).
        bc._stake_snapshots.clear()
        bc._record_stake_snapshot(0)
        self.assertIn(0, bc._stake_snapshots)

        # Simulate the proposer pipeline recording many subsequent
        # snapshots.  We bypass block validation because this test
        # targets _record_stake_snapshot in isolation — it's the
        # sole site of the retention branch we're removing.
        for n in range(1, 2000):
            bc._record_stake_snapshot(n)

        # Block 0's snapshot must still be retrievable.
        self.assertIn(
            0, bc._stake_snapshots,
            "Block 0 stake snapshot was pruned — violates chain "
            "permanence (CLAUDE.md principle #2).",
        )
        # And every intermediate block we recorded must also still
        # be there; pruning is gone completely, not merely shifted.
        for n in range(1, 2000):
            self.assertIn(
                n, bc._stake_snapshots,
                f"Block {n} stake snapshot was pruned.",
            )

    def test_no_pruning_at_1024_threshold(self):
        """Crossing the historical 1024 threshold triggers no deletions.

        This guards against regressions that reintroduce a bounded
        window.  After recording blocks 1..1030, all of them must be
        present alongside block 0.
        """
        bc = Blockchain()
        bc._stake_snapshots.clear()

        for n in range(0, 1031):
            bc._record_stake_snapshot(n)

        # Every recorded block must survive: no pruning at any height.
        self.assertEqual(
            len(bc._stake_snapshots),
            1031,
            "Snapshot map size did not grow by exactly the number "
            "of recordings — something is still pruning.",
        )

    def test_retention_attribute_is_gone_or_disabled(self):
        """The _stake_snapshot_retention field either no longer exists
        or is not used to drive deletion.  Either way,
        `_record_stake_snapshot` must not delete anything.

        We assert behaviorally: record one entry, then record 100000
        more at higher block numbers, and confirm the first is still
        there.  If any retention logic is wired up, it would drop it.
        """
        bc = Blockchain()
        bc._stake_snapshots.clear()
        bc._record_stake_snapshot(42)
        for n in range(100_000, 100_500):
            bc._record_stake_snapshot(n)
        self.assertIn(42, bc._stake_snapshots)


if __name__ == "__main__":
    unittest.main()
