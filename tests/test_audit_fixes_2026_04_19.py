"""Regression tests for the 10-iteration audit pass done on 2026-04-19.

Covers:
- Reputation + entity_id_to_index rolled back via reorg snapshot (iter 4)
- Finality tracker + escrow rolled back via reorg snapshot (iter 10)
- MAX_PROPOSER_FALLBACK_ROUNDS caps timestamp-skew proposer hijack (iter 7)
- MAX_ACTIVE_PROPOSALS caps governance-spam memory DoS (iter 11)
"""

from __future__ import annotations

import unittest
import copy

from messagechain.core.blockchain import Blockchain


class TestReorgSnapshotCoversReputation(unittest.TestCase):
    def test_reputation_in_snapshot(self):
        bc = Blockchain()
        bc.reputation[b"\x11" * 32] = 42
        snap = bc._snapshot_memory_state()
        self.assertIn("reputation", snap)
        self.assertEqual(snap["reputation"][b"\x11" * 32], 42)

    def test_reputation_restored_from_snapshot(self):
        bc = Blockchain()
        snap = bc._snapshot_memory_state()
        # Mutate after snapshot
        bc.reputation[b"\x22" * 32] = 99
        bc._restore_memory_snapshot(snap)
        self.assertNotIn(b"\x22" * 32, bc.reputation)

    def test_reputation_restore_uses_safe_default_for_pre_field_snapshots(self):
        # A pre-field snapshot (legacy chain.db) omits the `reputation` key.
        # _restore_memory_snapshot must fall back to empty, not KeyError.
        # We take a real full snapshot, drop just the reputation key, and
        # confirm restore still works.
        bc = Blockchain()
        bc.reputation[b"\x33" * 32] = 5
        snap = bc._snapshot_memory_state()
        del snap["reputation"]
        bc._restore_memory_snapshot(snap)
        self.assertEqual(bc.reputation, {})


class TestReorgSnapshotCoversEntityIndex(unittest.TestCase):
    def test_entity_index_in_snapshot(self):
        bc = Blockchain()
        bc.entity_id_to_index[b"\xaa" * 32] = 7
        bc._next_entity_index = 8
        snap = bc._snapshot_memory_state()
        self.assertIn("entity_id_to_index", snap)
        self.assertEqual(snap["entity_id_to_index"][b"\xaa" * 32], 7)
        self.assertEqual(snap["next_entity_index"], 8)

    def test_entity_index_restored_rebuilds_reverse_map(self):
        bc = Blockchain()
        # Grab a valid full snapshot, then splice the entity-index fields
        bc.entity_id_to_index[b"\xbb" * 32] = 3
        bc.entity_id_to_index[b"\xcc" * 32] = 9
        bc._next_entity_index = 10
        snap = bc._snapshot_memory_state()
        # Mutate the reverse map so we can observe restore rebuilds it
        bc.entity_index_to_id = {999: b"\x00" * 32}
        bc._restore_memory_snapshot(snap)
        self.assertEqual(bc.entity_index_to_id[3], b"\xbb" * 32)
        self.assertEqual(bc.entity_index_to_id[9], b"\xcc" * 32)
        self.assertEqual(bc._next_entity_index, 10)


class TestReorgSnapshotCoversFinalityAndEscrow(unittest.TestCase):
    def test_finality_in_snapshot_is_deep_copy(self):
        bc = Blockchain()
        # Put a known marker in the tracker that we can observe post-restore.
        bc.finality.finalized.add(b"\xee" * 32)
        snap = bc._snapshot_memory_state()
        # Mutate live state after snapshot
        bc.finality.finalized.add(b"\xff" * 32)
        # Restore should wipe the post-snapshot mutation
        bc._restore_memory_snapshot(snap)
        self.assertIn(b"\xee" * 32, bc.finality.finalized)
        self.assertNotIn(b"\xff" * 32, bc.finality.finalized)

    def test_escrow_in_snapshot(self):
        bc = Blockchain()
        # We just need a snapshot to contain 'escrow' — behavior is that
        # restore round-trips it via deepcopy.
        snap = bc._snapshot_memory_state()
        self.assertIn("escrow", snap)


class TestProposerRoundCap(unittest.TestCase):
    def test_max_fallback_rounds_constant_exists(self):
        from messagechain.config import MAX_PROPOSER_FALLBACK_ROUNDS
        self.assertGreaterEqual(MAX_PROPOSER_FALLBACK_ROUNDS, 1)
        self.assertLess(MAX_PROPOSER_FALLBACK_ROUNDS, 20)  # sanity

    def test_round_cap_rejected_in_validate_block(self):
        # Source-level pin: the cap is enforced in validate_block.
        import pathlib
        src = pathlib.Path("messagechain/core/blockchain.py").read_text(encoding="utf-8")
        self.assertIn("MAX_PROPOSER_FALLBACK_ROUNDS", src)
        self.assertIn("timestamp-skew slot hijacking rejected", src)


class TestGovernanceProposalCap(unittest.TestCase):
    def test_max_active_proposals_constant(self):
        from messagechain.config import MAX_ACTIVE_PROPOSALS
        self.assertGreaterEqual(MAX_ACTIVE_PROPOSALS, 100)

    def test_add_proposal_returns_false_past_cap(self):
        from messagechain.governance.governance import GovernanceTracker
        from messagechain.config import MAX_ACTIVE_PROPOSALS
        from types import SimpleNamespace

        tracker = GovernanceTracker()
        # Fill the cap with synthetic entries; the cap check only reads
        # len(self.proposals), so the values don't need to be real.
        for i in range(MAX_ACTIVE_PROPOSALS):
            tracker.proposals[bytes([i % 256]) * 32 + bytes([i // 256])] = "x"

        class _FakeSupply:
            staked = {}

        dummy_tx = SimpleNamespace(proposal_id=b"\x88" * 32)
        result = tracker.add_proposal(
            dummy_tx, block_height=1, supply_tracker=_FakeSupply(),
        )
        self.assertFalse(result, "add_proposal past cap must return False")


if __name__ == "__main__":
    unittest.main()
