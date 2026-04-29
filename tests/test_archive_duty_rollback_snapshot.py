"""Snapshot/restore symmetry for archive-duty in-memory state.

Audit finding (same defect class as 1.37.0's evidence-collection
snapshot fix and 1.39.0's IL-processor snapshot fix):
``Blockchain._snapshot_memory_state`` and
``_restore_memory_snapshot`` previously omitted the four mutable
collections owned by the archive-duty subsystem:

  * ``validator_archive_misses``         (dict[bytes, int])
  * ``validator_archive_success_streak`` (dict[bytes, int])
  * ``validator_first_active_block``     (dict[bytes, int])
  * ``archive_active_snapshot``          (Optional[ActiveValidatorSnapshot])

``_apply_archive_duty`` mutates every one of these every block:

  * ``validator_first_active_block`` is bumped each time a validator
    is observed above ``VALIDATOR_MIN_STAKE`` for the first time.
  * ``archive_active_snapshot`` is captured at every challenge block
    and cleared at epoch close.
  * ``validator_archive_misses`` and ``validator_archive_success_streak``
    are folded with new miss/streak deltas at every epoch close.

A block that passes structural validation but whose declared
``state_root`` mismatches the locally-recomputed root is rolled back
via ``_restore_memory_snapshot``.  Pre-fix, the archive-duty
mutations survive that rollback.

Symmetric attack vectors mirror the prior defect-class incidents:

  1. ``validator_first_active_block`` poisoning.  A coerced validator
     submits a bad-state-root block at height H.  Honest peers run
     the apply path — every brand-new validator above threshold gets
     their first-active stamped with H.  The post-apply state_root
     check rejects the block, but the bumped first-active stays in
     memory.  When that validator's bootstrap-grace exemption
     elapses based on the false H (instead of the canonical
     re-application height), they are exposed to archive-duty miss
     accounting earlier or later than honest peers — divergent miss
     counts → divergent withhold tiers → divergent supply.staked at
     epoch close → silent fork.

  2. ``archive_active_snapshot`` poisoning.  A bad-state-root block
     at a challenge height captures a forged
     ``ActiveValidatorSnapshot`` (e.g. with a stale active_set or
     adversarial challenge_heights).  The rollback reverts the
     state_root but leaves the forged snapshot live; the next
     epoch-close fold runs against attacker-chosen challenge heights
     and produces miss updates the canonical chain never sees.

  3. ``validator_archive_misses`` / ``validator_archive_success_streak``
     poisoning.  A bad-state-root block at an epoch-close height
     mutates the per-validator miss / streak maps.  Post-rollback
     leakage means honest validators carry phantom misses (or
     phantom streak credits) that affect their reward-withhold tier
     and their stake projection going forward.

No-fork: snapshot/restore is purely in-memory; the chaindb mirror
runs only after the state-root check passes, so historical replay
is byte-identical.  No activation gate needed — purely closes a
silent in-memory leak that was never observed under honest play.
"""

from __future__ import annotations

import unittest

from messagechain.consensus.archive_duty import ActiveValidatorSnapshot
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _eid(byte: int) -> bytes:
    return bytes([byte]) * 32


class TestArchiveDutySnapshotSymmetry(unittest.TestCase):
    """Pin ``_snapshot_memory_state`` / ``_restore_memory_snapshot``
    captures and restores every mutable archive-duty collection.

    Each test seeds one collection, takes a snapshot, mutates the
    collection (simulating the apply path of a bad-state-root block),
    then restores from the snapshot and asserts the mutation was
    rolled back.
    """

    def setUp(self):
        self.proposer = Entity.create(b"ad-snap-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_validator_archive_misses_is_rolled_back(self):
        """The miss-counter poisoning attack: an attacker-crafted
        bump to ``validator_archive_misses`` must NOT survive a
        failed-state-root rollback.  Pre-fix the bump survives and
        feeds a phantom miss into the next withhold-tier
        computation.
        """
        prior_eid = _eid(0xAA)
        self.chain.validator_archive_misses[prior_eid] = 2
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path bumping the miss counter.
        attacker_eid = _eid(0xBB)
        self.chain.validator_archive_misses[attacker_eid] = 5
        # Also mutate the pre-existing entry — the snapshot must be
        # deep enough that mutating the live value post-snapshot does
        # NOT bleed back through the captured copy.
        self.chain.validator_archive_misses[prior_eid] = 99

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_eid,
            self.chain.validator_archive_misses,
            "validator_archive_misses must be rolled back to the "
            "pre-apply snapshot — pre-fix the attacker-injected entry "
            "survives a failed-state-root rollback and feeds a phantom "
            "miss into the next withhold-tier computation.",
        )
        self.assertEqual(
            self.chain.validator_archive_misses[prior_eid],
            2,
            "Pre-existing entries must be preserved by the restore at "
            "their pre-mutation value.",
        )

    def test_validator_archive_success_streak_is_rolled_back(self):
        """The streak-counter poisoning attack: a bad-state-root block
        that bumped a validator's success streak must NOT leak past
        the rollback.  Pre-fix the bump survives and prematurely
        triggers the streak-based decay path on the next epoch close.
        """
        prior_eid = _eid(0xAA)
        self.chain.validator_archive_success_streak[prior_eid] = 1
        snapshot = self.chain._snapshot_memory_state()

        attacker_eid = _eid(0xBB)
        self.chain.validator_archive_success_streak[attacker_eid] = 7
        self.chain.validator_archive_success_streak[prior_eid] = 42

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_eid,
            self.chain.validator_archive_success_streak,
            "validator_archive_success_streak must be rolled back — "
            "pre-fix attacker-injected streak entries survive and "
            "prematurely trigger the streak-based decay path.",
        )
        self.assertEqual(
            self.chain.validator_archive_success_streak[prior_eid],
            1,
            "Pre-existing streak entries must be preserved at their "
            "pre-mutation value.",
        )

    def test_validator_first_active_block_is_rolled_back(self):
        """The first-active poisoning attack: a bad-state-root block
        that stamped a brand-new validator's first-active block must
        NOT leak past the rollback, otherwise that validator's
        bootstrap-grace window is anchored to an attacker-chosen
        height and they exit grace earlier or later than honest
        peers (divergent miss accounting → silent fork).
        """
        prior_eid = _eid(0xAA)
        self.chain.validator_first_active_block[prior_eid] = 100
        snapshot = self.chain._snapshot_memory_state()

        attacker_eid = _eid(0xBB)
        self.chain.validator_first_active_block[attacker_eid] = 250
        # Mutating the existing entry is not what the apply path does
        # (first_active is never advanced once set), but a buggy or
        # adversarial apply could attempt it; the snapshot must
        # restore the pre-mutation value regardless.
        self.chain.validator_first_active_block[prior_eid] = 999

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_eid,
            self.chain.validator_first_active_block,
            "validator_first_active_block must be rolled back — "
            "pre-fix attacker-injected first-active stamps anchor the "
            "validator's bootstrap-grace window to an attacker-chosen "
            "height, diverging miss accounting from honest peers.",
        )
        self.assertEqual(
            self.chain.validator_first_active_block[prior_eid],
            100,
            "Pre-existing first-active stamps must be preserved.",
        )

    def test_archive_active_snapshot_is_rolled_back(self):
        """The active-snapshot poisoning attack: a bad-state-root
        block at a challenge height that captured a forged
        ActiveValidatorSnapshot must NOT leave the snapshot live past
        the rollback.  Pre-fix the forged snapshot is consumed at the
        next epoch close, producing miss updates the canonical chain
        never agreed to.
        """
        prior_snap = ActiveValidatorSnapshot(
            challenge_block=10,
            active_set=frozenset({_eid(0xAA), _eid(0xBB)}),
            challenge_heights=(1, 2, 3),
        )
        self.chain.archive_active_snapshot = prior_snap
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path overwriting with a forged snapshot.
        attacker_snap = ActiveValidatorSnapshot(
            challenge_block=20,
            active_set=frozenset({_eid(0xCC)}),
            challenge_heights=(7, 8, 9),
        )
        self.chain.archive_active_snapshot = attacker_snap

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.archive_active_snapshot,
            prior_snap,
            "archive_active_snapshot must be rolled back to the "
            "pre-apply value — pre-fix a forged snapshot from a "
            "bad-state-root challenge block is consumed at the next "
            "epoch close, producing attacker-chosen miss updates.",
        )

    def test_archive_active_snapshot_clear_is_rolled_back(self):
        """Symmetric to the overwrite case: a bad-state-root block at
        an epoch-close height that cleared the snapshot must NOT
        leave it cleared past the rollback.  Pre-fix the canonical
        chain's still-open epoch is silently dropped.
        """
        prior_snap = ActiveValidatorSnapshot(
            challenge_block=10,
            active_set=frozenset({_eid(0xAA)}),
            challenge_heights=(1, 2, 3),
        )
        self.chain.archive_active_snapshot = prior_snap
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path clearing the snapshot at epoch close.
        self.chain.archive_active_snapshot = None

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.archive_active_snapshot,
            prior_snap,
            "archive_active_snapshot must be rolled back when the "
            "rejected block cleared it — pre-fix the canonical "
            "chain's open epoch is silently dropped.",
        )

    def test_restored_collections_are_fresh_objects(self):
        """Regression test for the deep/shallow-copy contract:
        the restored ``validator_archive_misses``,
        ``validator_archive_success_streak``, and
        ``validator_first_active_block`` dicts must each be fresh
        objects, NOT the same identity as the snapshot's stored
        container.  Otherwise a subsequent failed reorg could mutate
        the captured snapshot through the live reference, making
        future restores observe the leak."""
        # Seed each collection so the snapshot has something to
        # capture beyond an empty container.
        self.chain.validator_archive_misses[_eid(0x01)] = 1
        self.chain.validator_archive_success_streak[_eid(0x02)] = 2
        self.chain.validator_first_active_block[_eid(0x03)] = 3

        snapshot = self.chain._snapshot_memory_state()
        self.chain._restore_memory_snapshot(snapshot)

        self.assertIsNot(
            self.chain.validator_archive_misses,
            snapshot["validator_archive_misses"],
            "validator_archive_misses restore must create a fresh "
            "dict, not alias the snapshot's stored copy.",
        )
        self.assertIsNot(
            self.chain.validator_archive_success_streak,
            snapshot["validator_archive_success_streak"],
            "validator_archive_success_streak restore must create a "
            "fresh dict.",
        )
        self.assertIsNot(
            self.chain.validator_first_active_block,
            snapshot["validator_first_active_block"],
            "validator_first_active_block restore must create a fresh "
            "dict.",
        )

        # Mutating the live state must NOT bleed back into the
        # snapshot.  This catches a future "shallow" regression where
        # the snapshot stores a reference to the live mapping.
        self.chain.validator_archive_misses[_eid(0xFE)] = 99
        self.chain.validator_archive_success_streak[_eid(0xFE)] = 99
        self.chain.validator_first_active_block[_eid(0xFE)] = 99
        self.assertNotIn(_eid(0xFE), snapshot["validator_archive_misses"])
        self.assertNotIn(
            _eid(0xFE),
            snapshot["validator_archive_success_streak"],
        )
        self.assertNotIn(_eid(0xFE), snapshot["validator_first_active_block"])


class TestSnapshotRestoreStructuralSymmetry(unittest.TestCase):
    """Structural guard that locks the symmetry between the snapshot
    and restore paths for archive-duty state.

    Catches the next defect of this class at CI time: if a future
    refactor adds a key to ``_snapshot_memory_state`` but forgets to
    handle it in ``_restore_memory_snapshot`` (or vice versa), this
    test blows up.
    """

    ARCHIVE_DUTY_KEYS = (
        "validator_archive_misses",
        "validator_archive_success_streak",
        "validator_first_active_block",
        "archive_active_snapshot",
    )

    def setUp(self):
        self.proposer = Entity.create(b"ad-symm-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_all_archive_duty_keys_are_present_in_snapshot(self):
        """The snapshot dict must carry every archive-duty key.  If a
        future refactor renames or drops one, this fails immediately.
        """
        snapshot = self.chain._snapshot_memory_state()
        for key in self.ARCHIVE_DUTY_KEYS:
            self.assertIn(
                key, snapshot,
                f"_snapshot_memory_state must include '{key}' — "
                f"missing key drops the archive-duty mutable state "
                f"from the rollback boundary, reintroducing the "
                f"first-active / miss-counter / active-snapshot "
                f"poisoning attacks.",
            )

    def test_round_trip_restores_every_archive_duty_key(self):
        """Mutate every archive-duty collection, take a snapshot, blow
        the live state away, restore, and check all four match the
        snapshot's view.  Catches a forgotten restore-side handler
        for any of the four keys."""
        self.chain.validator_archive_misses[_eid(0x10)] = 4
        self.chain.validator_archive_success_streak[_eid(0x11)] = 5
        self.chain.validator_first_active_block[_eid(0x12)] = 6
        self.chain.archive_active_snapshot = ActiveValidatorSnapshot(
            challenge_block=42,
            active_set=frozenset({_eid(0x10), _eid(0x11)}),
            challenge_heights=(1, 2, 3),
        )

        snapshot = self.chain._snapshot_memory_state()

        # Reset live state to fresh empty containers.
        self.chain.validator_archive_misses = {}
        self.chain.validator_archive_success_streak = {}
        self.chain.validator_first_active_block = {}
        self.chain.archive_active_snapshot = None

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(self.chain.validator_archive_misses[_eid(0x10)], 4)
        self.assertEqual(
            self.chain.validator_archive_success_streak[_eid(0x11)], 5,
        )
        self.assertEqual(
            self.chain.validator_first_active_block[_eid(0x12)], 6,
        )
        self.assertEqual(
            self.chain.archive_active_snapshot,
            ActiveValidatorSnapshot(
                challenge_block=42,
                active_set=frozenset({_eid(0x10), _eid(0x11)}),
                challenge_heights=(1, 2, 3),
            ),
        )

    def test_default_initialised_chain_has_clean_archive_duty_state_after_restore(self):
        """A snapshot taken on an empty archive-duty state and
        restored after a manual mutation must zero the live state
        back out.  Pre-fix the archive-duty state was never
        captured, so manual mutations leaked across the rollback
        boundary unconditionally."""
        snapshot = self.chain._snapshot_memory_state()

        self.chain.validator_archive_misses[_eid(0x99)] = 9
        self.chain.validator_archive_success_streak[_eid(0x99)] = 9
        self.chain.validator_first_active_block[_eid(0x99)] = 9
        self.chain.archive_active_snapshot = ActiveValidatorSnapshot(
            challenge_block=99,
            active_set=frozenset({_eid(0x99)}),
            challenge_heights=(99,),
        )

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(self.chain.validator_archive_misses, {})
        self.assertEqual(self.chain.validator_archive_success_streak, {})
        self.assertEqual(self.chain.validator_first_active_block, {})
        self.assertIsNone(self.chain.archive_active_snapshot)


if __name__ == "__main__":
    unittest.main()
