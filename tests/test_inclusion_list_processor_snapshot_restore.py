"""Snapshot/restore symmetry for ``InclusionListProcessor`` state.

Audit finding (same defect class as the Tier-N evidence-processor
snapshot fix that shipped in 1.37.0):
``Blockchain._snapshot_memory_state`` and
``_restore_memory_snapshot`` previously omitted the four mutable
collections owned by ``inclusion_list_processor``:

  * ``active_lists``         (dict[int, InclusionList])
  * ``inclusions_seen``      (dict[tuple[bytes, bytes], list[int]])
  * ``proposers_by_height``  (dict[bytes, dict[int, bytes]])
  * ``processed_violations`` (set[tuple[bytes, bytes, bytes]])

``_apply_block_state`` mutates every one of these on the
register / observe_block / process_inclusion_list_violation paths.
A block that passes structural validation but whose declared
``state_root`` mismatches ours is rolled back via
``_restore_memory_snapshot`` — pre-fix, the IL processor mutations
survive the rollback.

Two symmetric attack vectors:

  1. Dedup poisoning.  A coerced validator crafts a block carrying a
     valid InclusionListViolationEvidenceTx and a deliberately-wrong
     ``state_root``.  Honest peers run the apply path:
     ``processed_violations`` gets the (list_hash, tx_hash,
     proposer_id) triple bumped in.  The post-apply state_root check
     then rejects the block — but the dedup gate has been poisoned,
     so a later honest resubmission of the same violation evidence
     is silently dropped at the ``has_processed`` check
     (``inclusion_list.py:840``) and the offender escapes slashing
     forever.  Mirror of the NRE / BR dedup attack.

  2. ``active_lists`` poisoning.  A bad-state-root block that
     registers a forged InclusionList survives in ``active_lists``
     past the rollback.  Subsequent honest blocks observed against
     the now-phantom list mark proposers as having omitted txs the
     canonical chain never published — every proposer in the forged
     window is grounds for an InclusionListViolationEvidenceTx that
     would never have been admissible without the rollback bug.

No-fork: snapshot/restore is purely in-memory; the chaindb mirror
runs only after the state-root check passes, so historical replay
is byte-identical.  No activation gate needed.
"""

from __future__ import annotations

import copy
import hashlib
import unittest

from messagechain.config import (
    HASH_ALGO,
    INCLUSION_LIST_VERSION,
    INCLUSION_LIST_WINDOW,
)
from messagechain.consensus.inclusion_list import (
    InclusionList,
    InclusionListEntry,
)
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_inclusion_list(
    publish_height: int,
    tx_hashes: list[bytes],
    window: int = INCLUSION_LIST_WINDOW,
) -> InclusionList:
    """Build a bare InclusionList for snapshot/restore exercises.

    ``quorum_attestation`` is intentionally empty — the snapshot path
    does not care about quorum proof, only about the dataclass
    identity, which is what live state mutates.  Computing
    ``list_hash`` from the entries is enough to give the dedup keys
    something stable to test against.
    """
    entries = [
        InclusionListEntry(tx_hash=tx, first_seen_height=publish_height - 1)
        for tx in sorted(tx_hashes)
    ]
    return InclusionList(
        publish_height=publish_height,
        window_blocks=window,
        entries=entries,
        quorum_attestation=[],
        version=INCLUSION_LIST_VERSION,
    )


class TestInclusionListProcessorSnapshotSymmetry(unittest.TestCase):
    """Pin ``_snapshot_memory_state`` / ``_restore_memory_snapshot``
    captures and restores every mutable collection on
    ``inclusion_list_processor``.

    Each test seeds one collection, takes a snapshot, mutates the
    collection (simulating the apply path of a bad-state-root block),
    then restores from the snapshot and asserts the mutation was
    rolled back.
    """

    def setUp(self):
        self.proposer = Entity.create(b"il-snap-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.proc = self.chain.inclusion_list_processor

    def test_processed_violations_is_rolled_back(self):
        """The dedup-poisoning attack: an attacker-crafted bump to
        ``processed_violations`` must NOT survive a failed-state-root
        rollback.  Pre-fix the entry survives and silently blocks
        honest resubmission of the same (list, tx, proposer) triple.
        """
        prior_key = (_h(b"il-list-prior"), _h(b"il-tx-prior"), b"P" * 32)
        self.proc.processed_violations.add(prior_key)
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path bumping the dedup set with attacker key.
        attacker_key = (
            _h(b"il-list-poison"),
            _h(b"il-tx-poison"),
            b"X" * 32,
        )
        self.proc.processed_violations.add(attacker_key)

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_key,
            self.proc.processed_violations,
            "processed_violations must be rolled back to the pre-apply "
            "snapshot — pre-fix the attacker's (list, tx, proposer) "
            "triple survives a failed-state-root rollback and silently "
            "blocks honest resubmission of the same violation evidence.",
        )
        self.assertIn(
            prior_key,
            self.proc.processed_violations,
            "Pre-existing entries must be preserved by the restore.",
        )

    def test_active_lists_is_rolled_back(self):
        """The active-lists-poisoning attack: a forged ``register``
        from a bad-state-root block must NOT leave the InclusionList
        in ``active_lists`` past the rollback.  Pre-fix the forged
        list persists and honest validators slash proposers for
        omitting txs from a list the canonical chain never published.
        """
        prior_list = _make_inclusion_list(
            publish_height=10, tx_hashes=[_h(b"il-tx-prior")],
        )
        self.proc.active_lists[prior_list.publish_height] = prior_list
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path admitting a forged list.
        attacker_list = _make_inclusion_list(
            publish_height=20, tx_hashes=[_h(b"il-tx-poison")],
        )
        self.proc.active_lists[attacker_list.publish_height] = attacker_list
        # Also mutate the pre-existing list's inner mutable field —
        # the snapshot must be deep enough that mutating the live
        # object post-snapshot does NOT bleed back through the
        # captured copy.
        prior_list.entries.append(
            InclusionListEntry(
                tx_hash=_h(b"il-tx-injected-into-prior"),
                first_seen_height=9,
            )
        )

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_list.publish_height,
            self.proc.active_lists,
            "active_lists must be rolled back — pre-fix a forged "
            "registration persists past the rollback and grounds "
            "phantom InclusionListViolation slashes against honest "
            "proposers.",
        )
        self.assertIn(
            prior_list.publish_height,
            self.proc.active_lists,
            "Pre-existing active_lists entries must be preserved.",
        )
        # The restored prior list must NOT carry the post-snapshot
        # entries-list mutation — proves deepcopy isolation.
        restored_prior = self.proc.active_lists[prior_list.publish_height]
        restored_tx_hashes = {e.tx_hash for e in restored_prior.entries}
        self.assertNotIn(
            _h(b"il-tx-injected-into-prior"),
            restored_tx_hashes,
            "In-place mutations of the pre-existing InclusionList's "
            "entries list must also roll back — the snapshot must be "
            "deep enough to isolate the inner dataclass state.",
        )

    def test_inclusions_seen_is_rolled_back(self):
        """``inclusions_seen`` is appended to on every observe_block
        whose proposer included a list-mandated tx.  A bad-state-root
        apply that bumped the list must roll back BOTH the new
        composite-key entries AND any in-place appends to existing
        lists — phantom inclusions silently let an actually-censoring
        proposer escape an InclusionListViolation slash."""
        prior_key = (_h(b"il-list-prior"), _h(b"il-tx-prior"))
        self.proc.inclusions_seen[prior_key] = [5, 6]
        snapshot = self.chain._snapshot_memory_state()

        attacker_key = (_h(b"il-list-poison"), _h(b"il-tx-poison"))
        self.proc.inclusions_seen[attacker_key] = [99]
        # Append to the pre-existing list — deepcopy must isolate.
        self.proc.inclusions_seen[prior_key].append(777)

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_key,
            self.proc.inclusions_seen,
            "inclusions_seen must roll back attacker-injected keys.",
        )
        self.assertEqual(
            self.proc.inclusions_seen[prior_key],
            [5, 6],
            "In-place appends to existing inclusions_seen lists must "
            "also roll back — snapshot must be deep enough to isolate "
            "the inner list state.",
        )

    def test_proposers_by_height_is_rolled_back(self):
        """``proposers_by_height`` writes a per-list inner dict on
        every observe_block.  A bad-state-root apply must roll back
        BOTH new outer keys AND in-place writes to existing inner
        dicts."""
        prior_lh = _h(b"il-list-prior")
        self.proc.proposers_by_height[prior_lh] = {11: b"P" * 32}
        snapshot = self.chain._snapshot_memory_state()

        attacker_lh = _h(b"il-list-poison")
        self.proc.proposers_by_height[attacker_lh] = {22: b"X" * 32}
        # Inner-dict mutation — deepcopy must isolate.
        self.proc.proposers_by_height[prior_lh][12] = b"Q" * 32

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_lh,
            self.proc.proposers_by_height,
            "proposers_by_height must roll back attacker-injected "
            "per-list outer keys.",
        )
        self.assertEqual(
            self.proc.proposers_by_height[prior_lh],
            {11: b"P" * 32},
            "In-place writes to existing inner dicts must also roll "
            "back — snapshot must be deep enough to isolate.",
        )

    def test_restored_collections_are_fresh_objects(self):
        """Regression test for the deep/shallow-copy contract:
        the restored ``processed_violations`` set, ``active_lists``
        dict, ``inclusions_seen`` dict, and ``proposers_by_height``
        dict must each be fresh objects, NOT the same identity as
        the snapshot's stored container.  Otherwise a subsequent
        failed reorg could mutate the captured snapshot through the
        live reference, making future restores observe the leak."""
        # Seed each collection so the snapshot has something to
        # capture beyond an empty container.
        self.proc.active_lists[10] = _make_inclusion_list(
            publish_height=10, tx_hashes=[_h(b"il-tx-1")],
        )
        self.proc.inclusions_seen[(_h(b"L"), _h(b"T"))] = [5]
        self.proc.proposers_by_height[_h(b"L")] = {5: b"P" * 32}
        self.proc.processed_violations.add((_h(b"L"), _h(b"T"), b"P" * 32))

        snapshot = self.chain._snapshot_memory_state()
        self.chain._restore_memory_snapshot(snapshot)

        # Live objects must NOT alias the snapshot's stored copies.
        self.assertIsNot(
            self.proc.active_lists,
            snapshot["il_active_lists"],
            "active_lists restore must create a fresh dict, not "
            "alias the snapshot's stored copy.",
        )
        self.assertIsNot(
            self.proc.inclusions_seen,
            snapshot["il_inclusions_seen"],
            "inclusions_seen restore must create a fresh dict.",
        )
        self.assertIsNot(
            self.proc.proposers_by_height,
            snapshot["il_proposers_by_height"],
            "proposers_by_height restore must create a fresh dict.",
        )
        self.assertIsNot(
            self.proc.processed_violations,
            snapshot["il_processed_violations"],
            "processed_violations restore must create a fresh set.",
        )

        # Mutating the live state must NOT bleed back into the
        # snapshot.  This catches a future "shallow" regression where
        # the snapshot stores a reference to the live mapping.
        self.proc.active_lists[999] = _make_inclusion_list(
            publish_height=999, tx_hashes=[_h(b"post-restore")],
        )
        self.proc.processed_violations.add(
            (_h(b"post-L"), _h(b"post-T"), b"Y" * 32),
        )
        self.assertNotIn(999, snapshot["il_active_lists"])
        self.assertNotIn(
            (_h(b"post-L"), _h(b"post-T"), b"Y" * 32),
            snapshot["il_processed_violations"],
        )


class TestSnapshotRestoreStructuralSymmetry(unittest.TestCase):
    """Structural guard that locks the symmetry between the snapshot
    and restore paths for IL-processor state.

    Catches the next defect of this class at CI time: if a future
    refactor adds a key to ``_snapshot_memory_state`` but forgets to
    handle it in ``_restore_memory_snapshot`` (or vice versa), this
    test blows up.

    Scope is intentionally narrow — we don't try to enforce the
    contract on every snapshot key (some are scoped, conditional, or
    deliberately one-way like ``leaf_watermarks``).  We DO enforce
    that every IL-processor key the snapshot writes round-trips the
    state through the restore.
    """

    IL_KEYS = (
        "il_active_lists",
        "il_inclusions_seen",
        "il_proposers_by_height",
        "il_processed_violations",
    )

    def setUp(self):
        self.proposer = Entity.create(b"il-symm-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        self.proc = self.chain.inclusion_list_processor

    def test_all_il_keys_are_present_in_snapshot(self):
        """The snapshot dict must carry every IL-processor key.  If a
        future refactor renames or drops one, this fails immediately."""
        snapshot = self.chain._snapshot_memory_state()
        for key in self.IL_KEYS:
            self.assertIn(
                key, snapshot,
                f"_snapshot_memory_state must include '{key}' — "
                f"missing key drops the IL-processor's mutable state "
                f"from the rollback boundary, reintroducing the dedup "
                f"poisoning / active_lists poisoning attacks.",
            )

    def test_round_trip_restores_every_il_key(self):
        """Mutate every IL-processor collection, take a snapshot, blow
        the live state away, restore, and check all four collections
        match the snapshot's view.  This catches a forgotten restore-
        side handler for any of the four keys."""
        # Seed each collection with distinct, non-trivial state.
        list_for_round_trip = _make_inclusion_list(
            publish_height=10, tx_hashes=[_h(b"rt-1"), _h(b"rt-2")],
        )
        self.proc.active_lists[10] = list_for_round_trip
        self.proc.inclusions_seen[
            (list_for_round_trip.list_hash, _h(b"rt-1"))
        ] = [11, 12]
        self.proc.proposers_by_height[list_for_round_trip.list_hash] = {
            11: b"P1" * 16,
            12: b"P2" * 16,
        }
        self.proc.processed_violations.add(
            (list_for_round_trip.list_hash, _h(b"rt-2"), b"X" * 32),
        )

        snapshot = self.chain._snapshot_memory_state()

        # Reset the live state to fresh empty containers.
        self.proc.active_lists = {}
        self.proc.inclusions_seen = {}
        self.proc.proposers_by_height = {}
        self.proc.processed_violations = set()

        self.chain._restore_memory_snapshot(snapshot)

        # All four collections must come back populated.
        self.assertIn(
            10, self.proc.active_lists,
            "active_lists round-trip dropped the seeded entry — "
            "restore handler missing or broken.",
        )
        self.assertEqual(
            self.proc.inclusions_seen[
                (list_for_round_trip.list_hash, _h(b"rt-1"))
            ],
            [11, 12],
            "inclusions_seen round-trip dropped or mangled the entry.",
        )
        self.assertEqual(
            self.proc.proposers_by_height[list_for_round_trip.list_hash],
            {11: b"P1" * 16, 12: b"P2" * 16},
            "proposers_by_height round-trip dropped the entry.",
        )
        self.assertIn(
            (list_for_round_trip.list_hash, _h(b"rt-2"), b"X" * 32),
            self.proc.processed_violations,
            "processed_violations round-trip dropped the entry.",
        )

    def test_default_initialised_chain_has_clean_il_state_after_restore(self):
        """A snapshot taken on an empty processor and restored after
        a manual mutation must zero the live state back out.  Pre-fix
        the IL-processor state was never captured, so manual mutations
        leaked across the rollback boundary unconditionally — this
        test pins that the empty case is also correctly captured."""
        snapshot = self.chain._snapshot_memory_state()

        self.proc.active_lists[42] = _make_inclusion_list(
            publish_height=42, tx_hashes=[_h(b"leak")],
        )
        self.proc.inclusions_seen[(_h(b"L"), _h(b"T"))] = [99]
        self.proc.proposers_by_height[_h(b"L")] = {99: b"X" * 32}
        self.proc.processed_violations.add((_h(b"L"), _h(b"T"), b"X" * 32))

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(self.proc.active_lists, {})
        self.assertEqual(self.proc.inclusions_seen, {})
        self.assertEqual(self.proc.proposers_by_height, {})
        self.assertEqual(self.proc.processed_violations, set())


if __name__ == "__main__":
    unittest.main()
