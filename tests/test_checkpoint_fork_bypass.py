"""
R8-#1: lock in that the R2-#6 weak-subjectivity checkpoint gate runs on
EVERY block-entry path of Blockchain.add_block — including the
fork-storage path that dispatches to _handle_fork.

Threat: if a refactor ever places the gate below the fork-dispatch
branch, an attacker could bypass it by crafting a block whose prev_hash
already resolves to a known block (prior fork tip or canonical
ancestor).  _handle_fork would then store the block in
self._block_by_hash and register it as a fork tip in
self.fork_choice.tips without consulting self._trusted_checkpoints,
seeding a long-range reorg.

The existing test_checkpoint_enforced_in_add_block.py suite only
exercised the linear-extension branch of add_block (get_block_by_hash
returned None), so a fork-path regression would have slipped past it.
These tests close that coverage gap across:
  A) the fork-storage path (the bypass attack),
  B) legitimate forks at non-checkpointed heights still reach the fork path,
  C) matching-hash fork blocks at a checkpointed height pass the gate,
  D) the linear-extension path (regression for the original R2-#6 gate).
"""

import unittest
from unittest.mock import MagicMock

from messagechain.consensus.checkpoint import WeakSubjectivityCheckpoint
from messagechain.core.blockchain import Blockchain


def _fake_block(block_number: int, block_hash: bytes, prev_hash: bytes = b"\x00" * 32):
    """Minimal duck-typed block for gate testing.

    The checkpoint gate in add_block only reads block.header.block_number,
    block.header.prev_hash, and block.block_hash — nothing else — so a
    MagicMock is sufficient and sidesteps the signature-heavy real Block
    construction path.
    """
    blk = MagicMock()
    blk.header.block_number = block_number
    blk.header.prev_hash = prev_hash
    blk.block_hash = block_hash
    return blk


def _make_bc_with_checkpoint(cp_height: int, cp_hash: bytes) -> Blockchain:
    """Blockchain with one trusted checkpoint and stubs so add_block can
    reach the branch under test without building a real chain."""
    cp = WeakSubjectivityCheckpoint(
        block_number=cp_height, block_hash=cp_hash, state_root=b"\x00" * 32,
    )
    bc = Blockchain(trusted_checkpoints=[cp])
    # Simulate non-empty chain so the height==0 genesis branch is skipped.
    bc.chain = [MagicMock()]
    bc.has_block = lambda h: False
    return bc


class TestCheckpointGateForkBypass(unittest.TestCase):

    # ── Test A: fork-storage path MUST NOT bypass the checkpoint gate ──

    def test_fork_block_at_checkpoint_height_rejected(self):
        """The attack: prev_hash resolves to an existing block (so add_block
        dispatches to _handle_fork), and the block sits at a checkpointed
        height with a WRONG hash.  The gate must reject it before any
        storage side-effects."""
        good = bytes.fromhex("aa" * 32)
        bad = bytes.fromhex("bb" * 32)
        bc = _make_bc_with_checkpoint(50, good)

        # Current tip is at a DIFFERENT hash than our fork block's prev_hash,
        # so add_block won't take the linear-extension branch.
        current_tip_hash = b"\xcc" * 32
        bc.get_latest_block = lambda: MagicMock(block_hash=current_tip_hash)

        # The fork's parent exists (prior fork tip or canonical ancestor).
        fork_parent_hash = b"\xdd" * 32
        fake_parent = _fake_block(49, fork_parent_hash)
        bc.get_block_by_hash = lambda h: (
            fake_parent if h == fork_parent_hash else None
        )

        # Sanity: the fork-dispatch condition holds BEFORE the call:
        self.assertIsNotNone(bc.get_block_by_hash(fork_parent_hash))

        pre_by_hash = set(bc._block_by_hash.keys())
        pre_tips = set(bc.fork_choice.tips.keys()) if hasattr(
            bc.fork_choice, "tips"
        ) else set()

        forked = _fake_block(50, bad, prev_hash=fork_parent_hash)
        ok, reason = bc.add_block(forked)

        self.assertFalse(ok, f"checkpoint-violating fork block must be rejected (reason={reason!r})")
        self.assertIn("Checkpoint violation", reason)
        self.assertIn("50", reason)

        # Crucially: no storage side-effect occurred.
        self.assertNotIn(
            bad, bc._block_by_hash,
            "checkpoint-violating fork block must NOT be stored in _block_by_hash",
        )
        post_tips = set(bc.fork_choice.tips.keys()) if hasattr(
            bc.fork_choice, "tips"
        ) else set()
        self.assertNotIn(
            bad, post_tips,
            "checkpoint-violating fork block must NOT appear as a fork tip",
        )
        # And no other block was added as a side-effect either.
        self.assertEqual(
            set(bc._block_by_hash.keys()) - pre_by_hash, set(),
            "no fork-path side-effects on checkpoint violation",
        )
        self.assertEqual(
            post_tips - pre_tips, set(),
            "no fork_choice.tips side-effects on checkpoint violation",
        )

    # ── Test B: forks at non-checkpointed heights still take the fork path ──

    def test_fork_block_at_non_checkpoint_height_unaffected(self):
        """A fork block at a height OUTSIDE the checkpoint map must not be
        rejected by the checkpoint gate.  We don't assert storage success
        (downstream validation will still fail on a MagicMock), only that
        the failure is NOT a checkpoint violation."""
        good = bytes.fromhex("aa" * 32)
        bc = _make_bc_with_checkpoint(50, good)

        current_tip_hash = b"\xcc" * 32
        bc.get_latest_block = lambda: MagicMock(block_hash=current_tip_hash)
        fork_parent_hash = b"\xdd" * 32
        fake_parent = _fake_block(50, fork_parent_hash)  # non-checkpoint height
        bc.get_block_by_hash = lambda h: (
            fake_parent if h == fork_parent_hash else None
        )

        forked = _fake_block(51, b"\xbb" * 32, prev_hash=fork_parent_hash)
        ok, reason = bc.add_block(forked)
        self.assertNotIn(
            "Checkpoint violation", reason,
            f"non-checkpoint-height fork must not be rejected by gate: {reason!r}",
        )

    # ── Test C: fork block whose hash MATCHES the checkpoint passes the gate ──

    def test_fork_block_matching_checkpoint_passes_gate(self):
        """A fork block at checkpointed height whose hash equals the
        trusted hash must pass the gate.  Downstream validation may still
        reject (no real signatures here), but NOT with a checkpoint error."""
        good = bytes.fromhex("aa" * 32)
        bc = _make_bc_with_checkpoint(50, good)

        current_tip_hash = b"\xcc" * 32
        bc.get_latest_block = lambda: MagicMock(block_hash=current_tip_hash)
        fork_parent_hash = b"\xdd" * 32
        fake_parent = _fake_block(49, fork_parent_hash)
        bc.get_block_by_hash = lambda h: (
            fake_parent if h == fork_parent_hash else None
        )

        forked = _fake_block(50, good, prev_hash=fork_parent_hash)
        ok, reason = bc.add_block(forked)
        self.assertNotIn(
            "Checkpoint violation", reason,
            f"matching-hash fork block must pass the gate: {reason!r}",
        )

    # ── Test D: linear-extension path regression ──

    def test_linear_block_at_checkpoint_height_rejected(self):
        """The original R2-#6 behaviour must still hold for linear extension:
        a linear block at a checkpointed height with the wrong hash is
        rejected with a Checkpoint violation."""
        good = bytes.fromhex("aa" * 32)
        bad = bytes.fromhex("bb" * 32)
        bc = _make_bc_with_checkpoint(50, good)

        # Linear path: prev_hash == current tip's block_hash.
        current_tip_hash = b"\xee" * 32
        bc.get_latest_block = lambda: MagicMock(block_hash=current_tip_hash)
        bc.get_block_by_hash = lambda h: None  # unused on the linear path

        blk = _fake_block(50, bad, prev_hash=current_tip_hash)
        ok, reason = bc.add_block(blk)
        self.assertFalse(ok)
        self.assertIn("Checkpoint violation", reason)
        self.assertIn("50", reason)
        self.assertNotIn(
            bad, bc._block_by_hash,
            "linear-path checkpoint-violating block must not be stored",
        )


if __name__ == "__main__":
    unittest.main()
