"""
Tests for audit r48 #2 — ``Blockchain._stake_snapshots`` in-memory dict
must prune entries older than ``FINALITY_VOTE_MAX_AGE_BLOCKS``,
matching the chaindb mirror's prune window.

Pre-fix the in-memory dict was append-only forever: every applied block
added ``{block_number: {entity → stake}}`` and nothing removed old
entries.  The chaindb mirror was already pruned at the same cutoff
(``prune_stake_snapshots_before``), so a cold-restarted node only
rehydrates the trailing window regardless — the in-memory tail was
just inconsistent with the disk-mirror contract.

CLAUDE.md anchors at risk pre-fix:
  * Honest-operator insurance — OOM-driven restart churn on long-
    running validators turns into slashable false-positives during
    chaotic reboots.
  * Hobbyist full-node accessibility for centuries — multi-GB
    resident state inside a year (~2.6M block-entries/year ×
    ~50 validators × ~40 B per row).

No consensus consumer reads beyond the window:
  * Attestations target the immediate parent (1 block back).
  * Fork-choice walks ≤ MAX_REORG_DEPTH=100 blocks.
  * FinalityVotes older than FINALITY_VOTE_MAX_AGE_BLOCKS are
    rejected at validation before the consumer sees them.
  * ``_pinned_stake_at`` has a documented live-state fallback for
    snapshot-pruned-era callers.

Supersedes ``tests/test_stake_snapshot_permanence.py`` (commit
4af0c8d), which asserted in-memory permanence — a stronger property
than the chain actually delivers, since the chaindb mirror was
pruned even at the time that test landed.
"""

import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain


class TestStakeSnapshotsInMemoryPrune(unittest.TestCase):
    def test_record_stake_snapshot_prunes_old_in_memory_entries(self):
        """After recording many snapshots, the in-memory dict size is
        bounded by FINALITY_VOTE_MAX_AGE_BLOCKS — not by the total
        number of recorded heights."""
        bc = Blockchain()
        bc.supply.staked[b"\x01" * 32] = 1000

        window = config.FINALITY_VOTE_MAX_AGE_BLOCKS
        total = window * 3
        for h in range(1, total + 1):
            bc._record_stake_snapshot(h)

        self.assertLessEqual(
            len(bc._stake_snapshots), window + 1,
            f"_stake_snapshots in-memory dict has "
            f"{len(bc._stake_snapshots)} entries after recording "
            f"{total} heights; expected <= {window + 1} (trailing "
            "FINALITY_VOTE_MAX_AGE_BLOCKS window).",
        )

    def test_recent_snapshots_remain_after_prune(self):
        """The prune must NOT evict in-window pins — consumers
        (finality vote denominator, fork-choice walk) still need
        them."""
        bc = Blockchain()
        bc.supply.staked[b"\x01" * 32] = 1000

        window = config.FINALITY_VOTE_MAX_AGE_BLOCKS
        total = window * 2
        for h in range(1, total + 1):
            bc._record_stake_snapshot(h)

        for h in range(total - window + 1, total + 1):
            self.assertIn(
                h, bc._stake_snapshots,
                f"in-window height {h} was pruned — consumers need it.",
            )

    def test_old_snapshots_evicted_after_prune(self):
        """The prune must evict out-of-window pins so the map bounds."""
        bc = Blockchain()
        bc.supply.staked[b"\x01" * 32] = 1000

        window = config.FINALITY_VOTE_MAX_AGE_BLOCKS
        total = window * 2 + 5
        for h in range(1, total + 1):
            bc._record_stake_snapshot(h)

        cutoff = total - window
        self.assertNotIn(
            1, bc._stake_snapshots,
            "out-of-window height=1 still present after pruning past "
            "the window.",
        )
        if cutoff - 1 >= 1:
            self.assertNotIn(
                cutoff - 1, bc._stake_snapshots,
                f"out-of-window height={cutoff - 1} (below cutoff="
                f"{cutoff}) still present.",
            )

    def test_in_memory_and_chaindb_prune_windows_agree(self):
        """Structural: the in-memory prune uses the SAME cutoff as the
        chaindb mirror prune.  If they ever diverge, a cold-restarted
        node and a warm-running node read different in-memory shapes
        and could disagree on the pinned-stake fallback semantics."""
        import inspect
        src = inspect.getsource(Blockchain._record_stake_snapshot)
        # Both prune calls must reference the same cutoff variable.
        self.assertIn("_prune_stake_snapshots_before(cutoff)", src)
        self.assertIn("prune_stake_snapshots_before(cutoff)", src)
        # And the cutoff is computed once from FINALITY_VOTE_MAX_AGE_BLOCKS.
        self.assertIn("FINALITY_VOTE_MAX_AGE_BLOCKS", src)


if __name__ == "__main__":
    unittest.main()
