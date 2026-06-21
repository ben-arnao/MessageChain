"""FinalityTracker pruning bounds the per-(validator, height) attestation
maps WITHOUT changing any finalization decision.

Background -- two incidents:
  * 2026-06-20: the unbounded FinalityTracker (`_attestation_objects` held
    a full Attestation per validator per height forever) reached ~6.7 MB
    (99%) of every per-block state snapshot at mainnet h=5255 and filled
    validator-1's disk.
  * 2026-06-21 (1.97.2): a first attempt pruned the tracker at a TIGHT
    window (block-200) and caused a state_root divergence -- a pruned
    node re-accumulated a still-active target's attestations from zero
    and reached a different `justified` / `blocks_since_last_finalization`
    decision than an unpruned peer, which rejected its blocks.

The fix prunes at `block_number - FINALITY_VOTE_MAX_AGE_BLOCKS` -- the
SAME cutoff that prunes stake-snapshot pins.  Safety: `add_attestation`
accumulates `attestations[bh]` / `attested_stake[bh]` across blocks, but
an attestation is only admitted while its target's stake pin exists
(`resolve_pinned_attestation_stake` -> None -> skipped otherwise), and
that pin is pruned at exactly this cutoff.  So once a target falls below
the cutoff, no attestation for it can ever be admitted again -- its
tracker entry is frozen, and pruning it cannot change any decision.
`finalized` / `finalized_height` are never pruned.

These tests pin: (1) old detail dropped, finality status preserved;
(2) an in-window target keeps accumulating across a prune (the property
1.97.2 violated); (3) the wiring prunes at the stake-pin cutoff, never
tighter.
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
        cls.val_a = Entity.create(
            private_key=b"finality-prune-test-validator-a01",
            tree_height=4,
        )
        cls.val_b = Entity.create(
            private_key=b"finality-prune-test-validator-b01",
            tree_height=4,
        )

    def test_prune_clears_old_attestations_preserves_finality(self):
        tracker = FinalityTracker()
        A = self.val_a
        pks = {A.entity_id: A.keypair.public_key}
        hashes = {}
        for h in range(1, 9):
            bh = bytes([h]) * 32
            hashes[h] = bh
            tracker.add_attestation(
                create_attestation(A, bh, h),
                validator_stake=1000, total_stake=1000,
                public_keys=pks, min_validator_count=1,
            )

        finalized_before = set(tracker.finalized)
        fheight_before = tracker.finalized_height
        self.assertEqual(len(finalized_before), 8)
        self.assertEqual(len(tracker._attestation_objects), 8)

        tracker.prune(below_height=5)

        for h in range(1, 5):
            self.assertNotIn((A.entity_id, h), tracker._attestation_by_height)
            self.assertNotIn((A.entity_id, h), tracker._attestation_objects)
            self.assertNotIn(hashes[h], tracker.attestations)
            self.assertNotIn(hashes[h], tracker.attested_stake)
        for h in range(5, 9):
            self.assertIn((A.entity_id, h), tracker._attestation_by_height)
            self.assertIn((A.entity_id, h), tracker._attestation_objects)

        # SAFETY: pruning attestation detail must NEVER un-finalize.
        self.assertEqual(tracker.finalized, finalized_before)
        self.assertEqual(tracker.finalized_height, fheight_before)
        for h in range(1, 9):
            self.assertTrue(tracker.is_finalized(hashes[h]))

    def test_prune_preserves_in_window_accumulation(self):
        """The exact property 1.97.2 violated: a target still INSIDE the
        retention window must keep accumulating votes across blocks even
        after a prune drops OLDER targets, and still finalize.  If the
        prune reset the in-window target, the second vote would start
        from zero and never reach the 2/3 threshold."""
        tracker = FinalityTracker()
        A, B = self.val_a, self.val_b
        pks = {
            A.entity_id: A.keypair.public_key,
            B.entity_id: B.keypair.public_key,
        }
        # OLD target (height 1): a lone partial attestation.
        old_bh = b"\x11" * 32
        tracker.add_attestation(
            create_attestation(A, old_bh, 1),
            validator_stake=100, total_stake=300,
            public_keys=pks, min_validator_count=2,
        )
        # RECENT target (height 50): A votes first -> not yet finalized.
        recent_bh = b"\x22" * 32
        just1 = tracker.add_attestation(
            create_attestation(A, recent_bh, 50),
            validator_stake=100, total_stake=300,
            public_keys=pks, min_validator_count=2,
        )
        self.assertFalse(just1)
        self.assertNotIn(recent_bh, tracker.finalized)

        # Prune drops the OLD target but must keep the RECENT one.
        tracker.prune(below_height=10)
        self.assertNotIn((A.entity_id, 1), tracker._attestation_by_height)
        self.assertIn(recent_bh, tracker.attestations)
        self.assertEqual(tracker.attested_stake.get(recent_bh), 100)

        # B votes for the recent target in a LATER block.  It must
        # accumulate onto A's surviving vote (200/300 >= 2/3, 2 voters)
        # and finalize -- proving the prune did not reset it.
        just2 = tracker.add_attestation(
            create_attestation(B, recent_bh, 50),
            validator_stake=100, total_stake=300,
            public_keys=pks, min_validator_count=2,
        )
        self.assertTrue(
            just2,
            "in-window target must still finalize after cross-block "
            "accumulation; the prune must not have reset it",
        )
        self.assertIn(recent_bh, tracker.finalized)


class TestRecordStakeSnapshotWiresFinalityPrune(unittest.TestCase):
    """`_record_stake_snapshot` must prune the FinalityTracker at the
    SAME cutoff as the stake-snapshot pins -- never tighter.  Pruning
    tighter than the stake-pin retention is exactly the 1.97.2 bug."""

    def _bare_chain(self):
        return Blockchain(db=None)

    def test_prune_called_at_stake_pin_cutoff(self):
        chain = self._bare_chain()
        calls = []
        chain.finality.prune = lambda below_height: calls.append(below_height)
        saved = _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS
        _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS = 7
        try:
            chain._record_stake_snapshot(100)  # cutoff = 100 - 7 = 93
        finally:
            _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS = saved
        self.assertEqual(
            calls, [93],
            "finality.prune must fire at block_number - "
            "FINALITY_VOTE_MAX_AGE_BLOCKS (same as the stake-pin prune); "
            "a tighter cutoff re-introduces the 1.97.2 divergence",
        )

    def test_prune_not_called_when_cutoff_nonpositive(self):
        chain = self._bare_chain()
        calls = []
        chain.finality.prune = lambda below_height: calls.append(below_height)
        saved = _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS
        _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS = 1000
        try:
            chain._record_stake_snapshot(100)  # cutoff = -900 -> skip
        finally:
            _cfg.FINALITY_VOTE_MAX_AGE_BLOCKS = saved
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
