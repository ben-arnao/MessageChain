"""Tests for R2-#3: `blocks_since_last_finalization` must be reset by
`_reset_state` so that reorg replay does not start atop a stale counter.

Bug: `_reset_state` re-initialized supply / nonces / finality / reputation
/ escrow / bootstrap_ratchet but left `self.blocks_since_last_finalization`
untouched.  During reorg, `_reorganize` calls `_reset_state` and then
replays every pre-ancestor block from genesis.  The per-block increment
in `_apply_block_state` then stacks on top of the stale counter: if the
old fork had stalled finality (counter at e.g. 100), replay starts at
100 instead of 0.  If finality stalls again after the merge, honest
validators take a SECOND quadratic inactivity-leak penalty for the
same outage.
"""

import unittest

from messagechain.core.blockchain import Blockchain


class TestResetStateClearsCounter(unittest.TestCase):
    """Test A: `_reset_state` must zero the counter directly."""

    def test_reset_state_clears_blocks_since_last_finalization(self):
        chain = Blockchain()

        # Bring the counter up to 100 as if 100 blocks had passed
        # without finality firing.  In production this happens inside
        # `_apply_block_state` via `self.blocks_since_last_finalization += 1`;
        # here we set it directly to keep the test focused on the
        # `_reset_state` contract.
        chain.blocks_since_last_finalization = 100

        chain._reset_state()

        self.assertEqual(
            chain.blocks_since_last_finalization,
            0,
            "_reset_state must reset blocks_since_last_finalization to 0 "
            "so reorg replay does not double-count the leak window",
        )


class TestReorgReplayRestartsCounterFromZero(unittest.TestCase):
    """Test B: full reorg scenario — counter resets at ancestor, then
    resumes normally as the new chain is replayed."""

    def test_replay_after_reset_starts_from_zero_and_increments(self):
        """Simulate the reorg control flow:

        1. Chain is mid-stall: counter sits at 100.
        2. `_reorganize` calls `_reset_state` before replay.
        3. Replay of pre-ancestor blocks runs (simulated as a loop of
           counter increments — the same increment path
           `_apply_block_state` uses).
        4. A finality event lands in the new chain's replay window and
           zeros the counter again.
        5. A few more post-finality blocks advance it from 0 upward.
        """
        chain = Blockchain()

        # Old fork tip: finality has stalled for 100 blocks.
        chain.blocks_since_last_finalization = 100

        # Reorg entry point: _reset_state before replay.
        chain._reset_state()
        self.assertEqual(chain.blocks_since_last_finalization, 0)

        # Simulate replaying 50 pre-ancestor blocks that did NOT
        # achieve finality.  Each _apply_block_state call increments
        # the counter by 1 (see blockchain.py line ~5819).
        for _ in range(50):
            chain.blocks_since_last_finalization += 1

        self.assertEqual(
            chain.blocks_since_last_finalization,
            50,
            "Replay without finality should build the counter from 0, "
            "not from the stale 100",
        )

        # Now the new fork's replay hits a block whose attestations
        # justify a checkpoint — the finality reset path in
        # _process_attestations zeros the counter.
        chain.blocks_since_last_finalization = 0

        # Then a handful of post-finality blocks advance it again.
        for _ in range(5):
            chain.blocks_since_last_finalization += 1

        self.assertEqual(
            chain.blocks_since_last_finalization,
            5,
            "After the replay's finality event, counter resumes from 0",
        )

    def test_double_leak_regression(self):
        """Regression guard for the concrete double-leak scenario:
        without the fix, a post-reorg stall would land on top of the
        pre-reorg counter and trigger a second quadratic penalty for
        the same outage.  With the fix, the counter restarts at 0."""
        chain = Blockchain()

        chain.blocks_since_last_finalization = 200  # old-fork stall

        chain._reset_state()

        # Stall again on the new fork (same magnitude).  The
        # inactivity-leak penalty is quadratic in this counter; without
        # the reset, validators would pay the penalty for reaching 400
        # instead of 200.
        for _ in range(200):
            chain.blocks_since_last_finalization += 1

        self.assertEqual(
            chain.blocks_since_last_finalization,
            200,
            "Counter after reorg + fresh stall must equal the fresh "
            "stall length only — no carry-over from the old fork",
        )


class TestNormalForwardProgressionUnchanged(unittest.TestCase):
    """Test C: regression — normal (non-reorg) chain progression that
    periodically hits finality continues to work as designed.
    `_reset_state` must not be invoked by the forward path, so nothing
    here should change."""

    def test_counter_not_reset_midchain_without_reset_state(self):
        chain = Blockchain()

        # Build the counter up as if 20 non-finalizing blocks passed.
        for _ in range(20):
            chain.blocks_since_last_finalization += 1
        self.assertEqual(chain.blocks_since_last_finalization, 20)

        # Finality fires on a block: the same assignment
        # _process_attestations performs (blockchain.py line ~3654).
        chain.blocks_since_last_finalization = 0

        # More non-finalizing blocks.
        for _ in range(7):
            chain.blocks_since_last_finalization += 1

        self.assertEqual(
            chain.blocks_since_last_finalization,
            7,
            "Forward progression must track exactly the number of "
            "blocks since the last finality event — no spurious mid-"
            "chain resets",
        )


if __name__ == "__main__":
    unittest.main()
