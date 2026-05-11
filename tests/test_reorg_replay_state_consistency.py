"""Pin: reorg-replay calls `_process_attestations` and
`_record_stake_snapshot` per replayed block, mirroring the
normal add_block path.

Background (2026-05-11 production incident on validator-2):
  * v2 was on its own losing fork from blocks 2199-2233.
  * At 12:53 UTC v2 reorged to v1's canonical chain (rollback 35,
    apply 46 from snapshot @ ancestor 2198).
  * The reorg-replay loop in `Blockchain._reorganize` applied each
    block via `_apply_block_state` BUT skipped two per-block calls
    that the normal `add_block` path makes:
      - `_process_attestations(block, supply.staked)` -- bumps
        `self.reputation` for every attester AND updates
        `self.finality`.  Reputation drives the bootstrap lottery
        winner pick (mints tokens via `select_lottery_winner`),
        so a frozen reputation tracker diverges balance state
        from uprestarted peers within a few blocks.
      - `_record_stake_snapshot(block.block_number)` -- pins the
        per-block stake map.  Without per-block pins on replay,
        future finality-vote processing for the replayed range
        falls back to live `supply.staked`, which can diverge
        the 2/3 denominator from peers.
  * Net effect: v2's runtime state at the new tip diverged from
    v1's canonical state.  When v1 produced its next block (#2245)
    at 13:01:24 v2 computed a different state_root from v1's
    commitment, rejected with "Invalid state_root — state
    commitment mismatch", and banned v1.

This test asserts the fix is in place by structural inspection
of `_reorganize`'s source.  A future refactor that drops either
call from the replay loop fails here loudly.

(A full end-to-end reorg reproduction is heavier infrastructure;
this structural pin is the minimum guarantee.)
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.core.blockchain import Blockchain


class ReorgReplayStateConsistencyTests(unittest.TestCase):

    def test_reorganize_calls_process_attestations_per_replay_block(self):
        """The forward-apply loop inside `_reorganize` MUST call
        `_process_attestations` for each replayed block.  The v2
        2026-05-11 incident was caused by this call being absent
        — the reputation tracker stayed frozen at the snapshot's
        value and the lottery picked different winners than
        uprestarted peers."""
        src = inspect.getsource(Blockchain._reorganize)
        # The replay loop appears AFTER `for blk in apply_blocks:`.
        # Both calls must appear in the function body.
        self.assertIn(
            "_process_attestations(blk, self.supply.staked)", src,
            "_reorganize must call _process_attestations per replayed "
            "block so reputation + finality state mirror the canonical "
            "forward-apply path (v2 2026-05-11 root cause).",
        )

    def test_reorganize_calls_record_stake_snapshot_per_replay_block(self):
        """The forward-apply loop inside `_reorganize` MUST also call
        `_record_stake_snapshot` for each replayed block so per-block
        stake pins exist for downstream finality vote processing.
        Without them, votes targeting the replayed range fall back
        to live `supply.staked` — the same divergence trap
        `_apply_finality_votes` closes for the long-range checkpoint
        layer."""
        src = inspect.getsource(Blockchain._reorganize)
        self.assertIn(
            "_record_stake_snapshot(blk.header.block_number)", src,
            "_reorganize must call _record_stake_snapshot per "
            "replayed block so the per-block stake pin exists for "
            "subsequent finality vote processing.",
        )

    def test_reorganize_calls_appear_after_apply_block_state(self):
        """The per-block bookkeeping MUST follow `_apply_block_state`
        — calling them before apply would feed pre-apply staked map
        into the attestation 2/3 check (diverging from canonical) and
        record a pre-apply stake pin (wrong height-to-stake mapping).
        Order: apply_block_state → process_attestations →
        record_stake_snapshot, mirroring `add_block` exactly."""
        src = inspect.getsource(Blockchain._reorganize)
        # Find the for-loop body that contains _apply_block_state(blk).
        # Both new calls must appear AFTER that line in the same loop.
        apply_idx = src.find("self._apply_block_state(blk)")
        proc_idx = src.find("self._process_attestations(blk")
        pin_idx = src.find("self._record_stake_snapshot(blk")
        self.assertGreater(
            apply_idx, 0, "_apply_block_state(blk) call site not found"
        )
        self.assertGreater(
            proc_idx, apply_idx,
            "_process_attestations must follow _apply_block_state in "
            "the replay loop (mirror normal add_block ordering).",
        )
        self.assertGreater(
            pin_idx, apply_idx,
            "_record_stake_snapshot must follow _apply_block_state in "
            "the replay loop.",
        )


if __name__ == "__main__":
    unittest.main()
