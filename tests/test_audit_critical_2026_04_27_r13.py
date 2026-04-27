"""Critical-severity audit fix -- round 13 (2026-04-27).

ONE CRITICAL: successful-reorg path of `_reorganize` leaves stale
`reaction_choices` rows on disk -> silent state-root fork on the
next restart.

The round-12 fix correctly added wipe+re-insert for `reaction_choices`
inside `chaindb.restore_state_snapshot`, but that path only fires on
the FAILED-reorg branch.  The SUCCESSFUL-reorg branch calls
`_reset_state()` (instantiates a fresh empty `ReactionState()`) +
forward-replays + `_persist_state()`.  `_persist_state`'s reaction
loop only iterates `self.reaction_state._dirty_keys`, which contains
ONLY the keys touched during the new fork's replay -- old-fork-only
rows in chaindb's `reaction_choices` table are never DELETEd.

Cold restart -> `_load_from_db.get_all_reaction_choices()` rehydrates
the orphan vote -> `state_root_contribution()` mixes it in -> the
restarted node silently forks off peers that didn't restart.

Same defect class as round-12 #2; this closes the second of the two
reorg paths.

Fix: in `_persist_state`'s reaction loop, mirror the
`_dirty_entities is None` full-flush sentinel -- when `dirty is None`
(post `_reset_state`, post-reorg replay), wipe the
`reaction_choices` table and re-INSERT every entry from the
canonical-replay in-memory state.  Uses the same SQL transaction
already open in `_persist_state` so the DELETE+INSERTs are atomic.
The dirty-key optimization is preserved for the steady-state path.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.core.reaction import (
    ReactionState, REACT_CHOICE_UP, REACT_CHOICE_DOWN,
)
from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB


class TestPersistStateFullFlushWipesReactionChoices(unittest.TestCase):
    """`_persist_state` MUST drop orphan rows from chaindb's
    `reaction_choices` table when invoked in full-flush mode (the
    state `_reset_state` leaves the chain in after a successful
    reorg).  Pre-fix the per-key dirty loop only updated rows the
    canonical replay touched -- old-fork-only rows survived on disk
    and rehydrated on the next cold restart, silently forking the
    state root."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_clear_all_reaction_choices_helper_exists(self):
        """Round-13 added a wipe helper to chaindb so `_persist_state`
        can DELETE FROM reaction_choices inside the same SQL
        transaction as the subsequent re-INSERTs."""
        db = ChainDB(self.db_path)
        try:
            self.assertTrue(
                hasattr(db, "clear_all_reaction_choices"),
                "ChainDB MUST expose a wipe helper -- "
                "_persist_state's full-flush path needs to drop "
                "orphan rows atomically alongside re-INSERT.",
            )
            # Sanity: helper actually clears.
            db.set_reaction_choice(b"v" * 32, b"\xaa" * 32, True, REACT_CHOICE_UP)
            db._conn.commit()
            self.assertEqual(len(db.get_all_reaction_choices()), 1)
            db.clear_all_reaction_choices()
            db._conn.commit()
            self.assertEqual(db.get_all_reaction_choices(), {})
        finally:
            db.close()

    def test_full_flush_drops_orphan_fork_rows(self):
        """End-to-end: simulate the successful-reorg sequence.

        1. Apply 2 reactions (A and B) -> on disk.
        2. Simulate a reorg dropping reaction B: `_reset_state()`
           clears in-memory state; we replay-restore ONLY reaction A
           into in-memory.  `_dirty_entities = None` is the post-
           reset sentinel that triggers full-flush.
        3. `_persist_state()` MUST wipe and re-insert -- B's row
           must be GONE from chaindb post-flush.

        Pre-fix B's row survived on disk because `_persist_state`'s
        per-dirty-key loop never touched it.  Post-fix the
        full-flush branch wipes the table before re-INSERTing the
        canonical (replay-only) choices.
        """
        from messagechain.identity.identity import Entity
        db = ChainDB(self.db_path)
        try:
            alice = Entity.create(b"r13-alice".ljust(32, b"\x00"))
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)

            voter_a = b"voter_A".ljust(32, b"\x00")
            target_a = b"target_A".ljust(32, b"\x00")
            voter_b = b"voter_B".ljust(32, b"\x00")
            target_b = b"target_B".ljust(32, b"\x00")
            # Plant two votes via the public apply path.
            from messagechain.core.reaction import ReactTransaction
            from messagechain.crypto.keys import Signature
            placeholder_sig = Signature([], 0, [], b"", b"")
            tx_a = ReactTransaction(
                voter_id=voter_a, target=target_a, target_is_user=True,
                choice=REACT_CHOICE_UP, nonce=0, timestamp=0, fee=10,
                signature=placeholder_sig,
            )
            tx_b = ReactTransaction(
                voter_id=voter_b, target=target_b, target_is_user=False,
                choice=REACT_CHOICE_DOWN, nonce=0, timestamp=0, fee=10,
                signature=placeholder_sig,
            )
            chain.reaction_state.apply(tx_a)
            chain.reaction_state.apply(tx_b)
            # Use steady-state (dirty-key) path to flush both onto
            # disk -- mirrors what add_block does.
            chain._dirty_entities = set()  # not None: dirty-key path
            chain._persist_state()
            self.assertEqual(
                len(db.get_all_reaction_choices()), 2,
                "Both reactions should be on disk after the initial "
                "steady-state flush",
            )

            # Simulate the successful-reorg sequence: _reset_state
            # clears in-memory state.  Then the canonical-replay
            # only restores reaction A.
            chain.reaction_state = ReactionState()
            chain.reaction_state.apply(tx_a)  # canonical-replay
            chain._dirty_entities = None  # post-reset full-flush sentinel
            # _persist_state under the round-13 fix MUST drop B's
            # orphan row from disk while flushing A.
            chain._persist_state()

            disk_choices = db.get_all_reaction_choices()
            self.assertIn(
                (voter_a, target_a, True), disk_choices,
                "Canonical reaction A MUST survive the full-flush.",
            )
            self.assertNotIn(
                (voter_b, target_b, False), disk_choices,
                "Orphan reaction B from the rolled-back fork MUST "
                "be DELETEd from disk by the round-13 full-flush "
                "branch.  Pre-fix the dirty-key path skipped it, "
                "the row survived, and the next cold restart "
                "rehydrated it -> silent state-root fork.",
            )
        finally:
            db.close()

    def test_steady_state_dirty_path_still_skips_full_wipe(self):
        """Sanity: the round-13 fix MUST NOT degrade the steady-state
        path.  When `dirty is set()` (not None -- the post-block
        state), the per-dirty-key loop runs and the full-wipe is
        SKIPPED.  Otherwise every block would pay O(N_total) flush
        cost instead of O(K_touched)."""
        from messagechain.identity.identity import Entity
        from messagechain.core.reaction import ReactTransaction
        from messagechain.crypto.keys import Signature
        db = ChainDB(self.db_path)
        try:
            alice = Entity.create(b"r13-steady".ljust(32, b"\x00"))
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)

            placeholder_sig = Signature([], 0, [], b"", b"")
            tx = ReactTransaction(
                voter_id=b"v" * 32, target=b"\xab" * 32,
                target_is_user=True, choice=REACT_CHOICE_UP,
                nonce=0, timestamp=0, fee=10,
                signature=placeholder_sig,
            )
            chain.reaction_state.apply(tx)
            chain._dirty_entities = set()  # dirty-key path
            chain._persist_state()
            self.assertIn(
                (b"v" * 32, b"\xab" * 32, True),
                db.get_all_reaction_choices(),
            )

            # Now plant a row that's ON DISK but NOT in-memory and
            # NOT in dirty-keys.  Steady-state path must NOT delete
            # it (the dirty-key optimization is intentional).
            db.set_reaction_choice(
                b"orphan_disk".ljust(32, b"\x00"),
                b"\xcd" * 32, False, REACT_CHOICE_DOWN,
            )
            db._conn.commit()

            # Apply nothing further; flush via dirty-key path.
            chain._dirty_entities = set()
            chain._persist_state()
            # Orphan-disk row survives because steady-state path
            # doesn't touch it.  This is the steady-state behaviour
            # the dirty-key optimization is built around.
            self.assertIn(
                (b"orphan_disk".ljust(32, b"\x00"), b"\xcd" * 32, False),
                db.get_all_reaction_choices(),
                "Steady-state dirty-key path MUST NOT wipe orphan "
                "rows -- the dirty-key optimization is intentional. "
                "The full-flush wipe only fires when "
                "_dirty_entities is None (post-reorg / cold-start).",
            )
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
