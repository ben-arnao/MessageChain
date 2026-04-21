"""
R2-#6: weak-subjectivity checkpoints must gate every block-entry path,
not just the IBD header handler in sync.py.

Before this fix, ANNOUNCE_BLOCK and RESPONSE_BLOCK called
Blockchain.add_block directly; add_block had no checkpoint gate.  A
malicious peer could wait out IBD and then announce a block at a
checkpointed height with a wrong hash and have it processed.

These tests pin the behaviour on the Blockchain itself so every caller
(sync, announce, response, reorg replay) inherits the check.
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from messagechain.consensus.checkpoint import WeakSubjectivityCheckpoint
from messagechain.core.blockchain import Blockchain
from messagechain.network.ban import OFFENSE_CHECKPOINT_VIOLATION


def _fake_block(block_number: int, block_hash: bytes, prev_hash: bytes = b"\x00" * 32):
    """Build a minimal duck-typed block for the checkpoint gate.

    We don't need a real BlockHeader/Block here — the gate only touches
    block.header.block_number and block.block_hash BEFORE the structural
    validation code runs.  Using MagicMock keeps the test independent of
    the (signature-heavy) real block construction path.
    """
    blk = MagicMock()
    blk.header.block_number = block_number
    blk.header.prev_hash = prev_hash
    blk.block_hash = block_hash
    return blk


class TestCheckpointGateInAddBlock(unittest.TestCase):
    """Checkpoint enforcement lives on Blockchain.add_block so every
    block-entry path inherits it."""

    def test_constructor_accepts_trusted_checkpoints(self):
        good = bytes.fromhex("ab" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=100, block_hash=good, state_root=b"\x00" * 32,
        )
        bc = Blockchain(trusted_checkpoints=[cp])
        self.assertIn(100, bc._trusted_checkpoints)
        self.assertEqual(bc._trusted_checkpoints[100], good)

    def test_set_trusted_checkpoints_refreshes(self):
        bc = Blockchain()
        self.assertEqual(bc._trusted_checkpoints, {})
        good = bytes.fromhex("cd" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=77, block_hash=good, state_root=b"\x00" * 32,
        )
        bc.set_trusted_checkpoints([cp])
        self.assertEqual(bc._trusted_checkpoints[77], good)
        # A refresh with a different list replaces (doesn't merge forever)
        bc.set_trusted_checkpoints([])
        self.assertEqual(bc._trusted_checkpoints, {})

    # ── Test A: wrong hash at checkpoint height → rejected ──────────────

    def test_add_block_rejects_checkpoint_mismatch(self):
        good = bytes.fromhex("aa" * 32)
        bad = bytes.fromhex("bb" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=50, block_hash=good, state_root=b"\x00" * 32,
        )
        bc = Blockchain(trusted_checkpoints=[cp])
        # Simulate a post-IBD chain tall enough that height!=0 path runs.
        # We stub has_block / get_latest_block rather than building real
        # blocks because the gate fires BEFORE the usual chain checks.
        bc.has_block = lambda h: False
        bc.get_latest_block = lambda: MagicMock(block_hash=b"\xaa" * 32)
        bc.get_block_by_hash = lambda h: None
        bc.chain = [MagicMock()]  # height>=1 so genesis path is skipped

        blk = _fake_block(50, bad, prev_hash=b"\xaa" * 32)
        ok, reason = bc.add_block(blk)
        self.assertFalse(ok)
        self.assertIn("Checkpoint violation", reason)
        self.assertIn("50", reason)

    # ── Test B: matching hash at checkpoint height → gate passes ────────

    def test_add_block_allows_checkpoint_match(self):
        """When the block's hash MATCHES the checkpoint, the gate does
        not reject; any other outcome is from normal downstream validation."""
        good = bytes.fromhex("aa" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=50, block_hash=good, state_root=b"\x00" * 32,
        )
        bc = Blockchain(trusted_checkpoints=[cp])
        bc.has_block = lambda h: False
        bc.get_latest_block = lambda: MagicMock(block_hash=b"\xaa" * 32)
        bc.get_block_by_hash = lambda h: None
        bc.chain = [MagicMock()]

        blk = _fake_block(50, good, prev_hash=b"\xaa" * 32)
        ok, reason = bc.add_block(blk)
        # The reason is NOT the checkpoint-violation message.  Downstream
        # validation almost certainly still fails (no real signature, no
        # parent state, etc.), but NOT for "Checkpoint violation".
        self.assertNotIn("Checkpoint violation", reason)

    # ── Test C: non-checkpoint height → gate is a no-op ─────────────────

    def test_add_block_non_checkpoint_height_unaffected(self):
        good = bytes.fromhex("aa" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=50, block_hash=good, state_root=b"\x00" * 32,
        )
        bc = Blockchain(trusted_checkpoints=[cp])
        bc.has_block = lambda h: False
        bc.get_latest_block = lambda: MagicMock(block_hash=b"\xaa" * 32)
        bc.get_block_by_hash = lambda h: None
        bc.chain = [MagicMock()]

        # Height 51 is outside the checkpoint set — gate must not fire
        # even with a hash that would have mismatched at height 50.
        blk = _fake_block(51, bytes.fromhex("bb" * 32), prev_hash=b"\xaa" * 32)
        ok, reason = bc.add_block(blk)
        self.assertNotIn("Checkpoint violation", reason)

    # ── Test D: node-layer ANNOUNCE_BLOCK path records the offense ──────

    def test_announce_block_records_checkpoint_offense(self):
        """End-to-end: when add_block returns a checkpoint-violation
        reason, node.py's ANNOUNCE_BLOCK handler must record
        OFFENSE_CHECKPOINT_VIOLATION against the peer (not the generic
        OFFENSE_INVALID_BLOCK)."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity

        entity = Entity.create(b"cp_addblock_test".ljust(32, b"\x00"))
        node = Node(entity, port=19981)

        # Install a checkpoint on the blockchain via the public setter.
        good = bytes.fromhex("aa" * 32)
        bad_block_hash = bytes.fromhex("bb" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=42, block_hash=good, state_root=b"\x00" * 32,
        )
        node.blockchain.set_trusted_checkpoints([cp])

        # Replace add_block with a spy that returns the real violation
        # string — we're testing the node-layer dispatch, not the
        # validation plumbing.
        node.blockchain.add_block = MagicMock(
            return_value=(False, "Checkpoint violation at height 42"),
        )

        # Fabricate a peer + ANNOUNCE_BLOCK message pair
        from messagechain.network.protocol import NetworkMessage, MessageType
        from messagechain.network.peer import Peer

        peer = Peer(host="8.8.8.8", port=42)

        # Need enough of a "block" to pass pre-parse validate_block_hex_size —
        # stub Block.from_bytes to return our fake block.
        import messagechain.network.node as node_mod
        real_from_bytes = node_mod.Block.from_bytes
        node_mod.Block.from_bytes = staticmethod(
            lambda data: _fake_block(42, bad_block_hash)
        )
        try:
            msg = NetworkMessage(
                msg_type=MessageType.ANNOUNCE_BLOCK,
                payload={"block": "00" * 80},  # any hex within size limit
                sender_id=entity.entity_id_hex,
            )
            asyncio.run(node._handle_message(msg, peer))
        finally:
            node_mod.Block.from_bytes = staticmethod(real_from_bytes)

        # The ban_manager must have received an offense whose REASON
        # tags it as a checkpoint mismatch (both OFFENSE_CHECKPOINT_VIOLATION
        # and OFFENSE_INVALID_BLOCK happen to be equal numerically, so
        # reason-string is the discriminator).  PeerBanManager buckets
        # by IP; offenses live in PeerScore.offenses as
        # (timestamp, reason, points) tuples.
        ip = node.ban_manager._get_ip("8.8.8.8:42")
        ps = node.ban_manager._scores.get(ip)
        self.assertIsNotNone(ps, "peer should have a score entry")
        checkpoint_hits = [
            (reason, pts) for (_ts, reason, pts) in ps.offenses
            if pts == OFFENSE_CHECKPOINT_VIOLATION
            and "checkpoint" in reason.lower()
        ]
        self.assertTrue(
            checkpoint_hits,
            f"peer must receive a checkpoint-tagged offense; offenses={ps.offenses}",
        )
        # And add_block must NOT have been misrouted into the generic
        # invalid-block channel — every recorded offense in this run
        # should carry the "checkpoint_mismatch" tag.
        non_checkpoint = [
            (reason, pts) for (_ts, reason, pts) in ps.offenses
            if "checkpoint" not in reason.lower()
        ]
        self.assertFalse(
            non_checkpoint,
            f"checkpoint-mismatch must not fall through to other offense"
            f" buckets; saw: {non_checkpoint}",
        )


if __name__ == "__main__":
    unittest.main()
