"""FinalityTracker pruning bounds the per-(validator, height)
attestation maps so they can't grow for the chain's lifetime.

Background -- 2026-06-20 incident: ``FinalityTracker`` was append-only.
``_attestation_objects`` held a full ``Attestation`` per validator per
height forever; serialized into every per-block state snapshot it
reached ~6.7 MB (99% of the snapshot) at mainnet h=5255 and climbing,
which filled validator-1's 10 GB disk and wedged the node.  A ``prune``
method existed but was NEVER called.  ``Blockchain._record_stake_
snapshot`` now calls it every block at the ``FINALITY_ATTESTATION_
RETENTION_BLOCKS`` horizon -- a safe, near-tip cutoff because finality
status (``finalized`` / ``finalized_height``) is never pruned, finality
counting / proposer-draining only read near-tip heights, and
equivocation slashing runs through the independent equivocation_watcher.
It is a local storage knob, not a consensus parameter.

These tests pin the prune's safety contract: old attestation detail is
dropped, finality status is preserved, and the wiring fires at the
right cutoff.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.consensus.attestation import (
    FinalityTracker,
    create_attestation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


class TestFinalityTrackerPrune(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 8 + 1 attestation signs across the two tests -> tree_height 4
        # (16 leaves) is enough; the validator is shared and its signing
        # state advances across methods.
        cls.val = Entity.create(
            private_key=b"finality-prune-test-validator-001",
            tree_height=4,
        )

    def test_prune_clears_old_attestations_preserves_finality(self):
        tracker = FinalityTracker()
        pks = {self.val.entity_id: self.val.keypair.public_key}
        hashes = {}
        for h in range(1, 9):
            bh = bytes([h]) * 32
            hashes[h] = bh
            att = create_attestation(self.val, bh, h)
            tracker.add_attestation(
                att, validator_stake=1000, total_stake=1000,
                public_keys=pks, min_validator_count=1,
            )

        # Single validator at 100% stake finalizes every block.
        finalized_before = set(tracker.finalized)
        fheight_before = tracker.finalized_height
        self.assertEqual(len(finalized_before), 8)
        self.assertEqual(len(tracker._attestation_objects), 8)

        tracker.prune(below_height=5)

        # Heights 1..4: all attestation detail dropped.
        for h in range(1, 5):
            self.assertNotIn(
                (self.val.entity_id, h), tracker._attestation_by_height,
            )
            self.assertNotIn(
                (self.val.entity_id, h), tracker._attestation_objects,
            )
            self.assertNotIn(hashes[h], tracker.attestations)
            self.assertNotIn(hashes[h], tracker.attested_stake)
        # Heights 5..8: retained (within the window).
        for h in range(5, 9):
            self.assertIn(
                (self.val.entity_id, h), tracker._attestation_by_height,
            )
            self.assertIn(
                (self.val.entity_id, h), tracker._attestation_objects,
            )

        # SAFETY INVARIANT: pruning attestation detail must NEVER
        # un-finalize a block.  ``finalized`` / ``finalized_height`` are
        # untouched, and old finalized blocks still report finalized.
        self.assertEqual(tracker.finalized, finalized_before)
        self.assertEqual(tracker.finalized_height, fheight_before)
        for h in range(1, 9):
            self.assertTrue(tracker.is_finalized(hashes[h]))

    def test_prune_below_one_is_noop(self):
        tracker = FinalityTracker()
        pks = {self.val.entity_id: self.val.keypair.public_key}
        att = create_attestation(self.val, b"\xAA" * 32, 9)
        tracker.add_attestation(
            att, validator_stake=1000, total_stake=1000,
            public_keys=pks, min_validator_count=1,
        )
        before = dict(tracker._attestation_by_height)
        tracker.prune(below_height=1)  # nothing is below height 1
        self.assertEqual(tracker._attestation_by_height, before)


class TestRecordStakeSnapshotWiresFinalityPrune(unittest.TestCase):
    """``_record_stake_snapshot`` must drive ``finality.prune`` at the
    same cutoff it prunes stake snapshots -- otherwise the tracker grows
    unbounded again (the root cause of the 2026-06-20 disk wedge)."""

    def _bare_chain(self):
        # A db-less in-memory blockchain is enough: _record_stake_
        # snapshot only reads supply.staked + self._stake_snapshots and
        # calls the prune surfaces.
        return Blockchain(db=None)

    def test_prune_called_at_attestation_retention_cutoff(self):
        chain = self._bare_chain()
        calls = []
        chain.finality.prune = lambda below_height: calls.append(below_height)
        saved = _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS
        _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS = 3
        try:
            chain._record_stake_snapshot(10)  # cutoff = 10 - 3 = 7
        finally:
            _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS = saved
        self.assertEqual(
            calls, [7],
            "finality.prune must be called at "
            "block_number - FINALITY_ATTESTATION_RETENTION_BLOCKS",
        )

    def test_prune_not_called_when_cutoff_nonpositive(self):
        chain = self._bare_chain()
        calls = []
        chain.finality.prune = lambda below_height: calls.append(below_height)
        saved = _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS
        _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS = 100
        try:
            chain._record_stake_snapshot(10)  # cutoff = -90 -> skip
        finally:
            _cfg.FINALITY_ATTESTATION_RETENTION_BLOCKS = saved
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
