"""Snapshot/restore symmetry for ``reaction_state`` in-memory state.

Audit finding (same defect class as 1.37.0's evidence-collection
snapshot fix, 1.39.0's IL-processor snapshot fix, and 1.39.2's
archive-duty snapshot fix): ``Blockchain._snapshot_memory_state``
and ``_restore_memory_snapshot`` previously omitted the mutable
``ReactionState`` owned by ``self.reaction_state``.

``_apply_block_state`` calls ``self.reaction_state.apply(rtx)`` for
every ``ReactTransaction`` in the block (``blockchain.py:10401``),
mutating three inner maps in lockstep:

  * ``choices``             (dict[(voter, target, target_is_user), choice])
  * ``_user_trust_score``   (dict[bytes, int])
  * ``_message_score``      (dict[bytes, int])

The reaction_state's contribution is mixed into the chain state
root via ``reaction_state.state_root_contribution()`` at
``blockchain.py:4364``.  A bad-state-root block whose apply path
called ``reaction_state.apply`` on attacker-chosen React txs is
caught by the post-apply state_root check and rolled back via
``_restore_memory_snapshot``.  Pre-fix, the reaction-state
mutations survive that rollback — the in-memory state is then
diverged from honest peers' replayed state, and the next
legitimate block's ``compute_current_state_root`` mixes in the
diverged contribution → silent fork at the next React-touching
block.

Symmetric attack vectors mirror the prior defect-class incidents:

  1. ``choices`` poisoning.  A coerced validator submits a
     bad-state-root block carrying React txs that flip a target's
     vote pair.  Honest peers run ``reaction_state.apply`` — the
     ``choices`` map is mutated.  The post-apply state_root check
     rejects the block, but the choice flip stays in memory.
     Every subsequent React tx that re-bases off this pair sees
     the attacker's choice as ``prev_choice`` and computes a
     diverged delta vs. honest peers that never accepted the
     bad block.

  2. Aggregate-score poisoning.  A bad-state-root block that
     bumped ``_user_trust_score`` or ``_message_score`` leaves
     the diverged aggregate live; the very next call to
     ``state_root_contribution`` (mixed into the next block's
     state_root) hashes the diverged ``choices`` map → state-root
     mismatch with honest peers → silent fork.

No-fork: snapshot/restore is purely in-memory; the chaindb mirror
runs only after the state-root check passes, so historical replay
is byte-identical.  No activation gate needed — purely closes a
silent in-memory leak that was never observed under honest play.
"""

from __future__ import annotations

import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.core.reaction import (
    REACT_CHOICE_DOWN,
    REACT_CHOICE_UP,
    ReactionState,
)
from messagechain.identity.identity import Entity


def _eid(byte: int) -> bytes:
    return bytes([byte]) * 32


class TestReactionStateSnapshotSymmetry(unittest.TestCase):
    """Pin ``_snapshot_memory_state`` / ``_restore_memory_snapshot``
    captures and restores every mutable field of ``reaction_state``.

    Each test seeds the inner state, takes a snapshot, mutates the
    state (simulating the apply path of a bad-state-root block),
    then restores from the snapshot and asserts the mutation was
    rolled back.
    """

    def setUp(self):
        self.proposer = Entity.create(b"react-snap-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_choices_is_rolled_back(self):
        """Choices-map poisoning attack: an attacker-crafted
        ``apply()`` mutation on the choices map must NOT survive a
        failed-state-root rollback.  Pre-fix the entry survives and
        feeds a phantom ``prev_choice`` into the next React tx's
        delta computation, diverging aggregates from honest peers.
        """
        prior_key = (_eid(0xAA), _eid(0xCC), True)
        self.chain.reaction_state.choices[prior_key] = REACT_CHOICE_UP
        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path injecting a new entry AND mutating the
        # pre-existing one — the snapshot must isolate both directions.
        attacker_key = (_eid(0xBB), _eid(0xDD), False)
        self.chain.reaction_state.choices[attacker_key] = REACT_CHOICE_DOWN
        self.chain.reaction_state.choices[prior_key] = REACT_CHOICE_DOWN

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_key,
            self.chain.reaction_state.choices,
            "reaction_state.choices must be rolled back to the "
            "pre-apply snapshot — pre-fix the attacker-injected "
            "choice survives a failed-state-root rollback and "
            "feeds a phantom prev_choice into the next React tx's "
            "delta computation.",
        )
        self.assertEqual(
            self.chain.reaction_state.choices[prior_key],
            REACT_CHOICE_UP,
            "Pre-existing choice entries must be preserved by the "
            "restore at their pre-mutation value.",
        )

    def test_user_trust_score_is_rolled_back(self):
        """Aggregate-score poisoning: the ``_user_trust_score`` map
        rolled by a bad-state-root block must NOT leak past the
        rollback.  Pre-fix the bumped score is hashed into the next
        block's state_root contribution and forks the chain.
        """
        prior_uid = _eid(0xAA)
        self.chain.reaction_state._user_trust_score[prior_uid] = 3
        snapshot = self.chain._snapshot_memory_state()

        attacker_uid = _eid(0xBB)
        self.chain.reaction_state._user_trust_score[attacker_uid] = 7
        self.chain.reaction_state._user_trust_score[prior_uid] = 99

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_uid,
            self.chain.reaction_state._user_trust_score,
            "reaction_state._user_trust_score must be rolled back — "
            "pre-fix attacker-injected trust scores survive and "
            "diverge state_root_contribution from honest peers.",
        )
        self.assertEqual(
            self.chain.reaction_state._user_trust_score[prior_uid],
            3,
            "Pre-existing trust-score entries must be preserved at "
            "their pre-mutation value.",
        )

    def test_message_score_is_rolled_back(self):
        """Aggregate-score poisoning (message-react variant): the
        ``_message_score`` map mutated by a bad-state-root block must
        NOT survive the rollback, otherwise the message-react
        aggregate diverges from honest peers and the next state_root
        check fails on a legitimate block.
        """
        prior_tx = _eid(0xAA)
        self.chain.reaction_state._message_score[prior_tx] = 5
        snapshot = self.chain._snapshot_memory_state()

        attacker_tx = _eid(0xBB)
        self.chain.reaction_state._message_score[attacker_tx] = 11
        self.chain.reaction_state._message_score[prior_tx] = -42

        self.chain._restore_memory_snapshot(snapshot)

        self.assertNotIn(
            attacker_tx,
            self.chain.reaction_state._message_score,
            "reaction_state._message_score must be rolled back — "
            "pre-fix attacker-injected message scores survive and "
            "diverge state_root_contribution from honest peers.",
        )
        self.assertEqual(
            self.chain.reaction_state._message_score[prior_tx],
            5,
            "Pre-existing message-score entries must be preserved.",
        )

    def test_state_root_contribution_rolls_back(self):
        """End-to-end: the byte-string committed into
        ``compute_current_state_root`` via
        ``reaction_state.state_root_contribution()`` must match the
        pre-snapshot value byte-for-byte after a rollback.  This is
        the consensus-critical invariant the audit cited."""
        prior_key = (_eid(0xAA), _eid(0xCC), True)
        self.chain.reaction_state.choices[prior_key] = REACT_CHOICE_UP
        self.chain.reaction_state._user_trust_score[_eid(0xCC)] = 1
        before = self.chain.reaction_state.state_root_contribution()

        snapshot = self.chain._snapshot_memory_state()

        # Simulate apply path adding several attacker-chosen entries.
        for i in range(5):
            self.chain.reaction_state.choices[
                (_eid(0xB0 + i), _eid(0xC0 + i), False)
            ] = REACT_CHOICE_DOWN
            self.chain.reaction_state._message_score[_eid(0xC0 + i)] = -1

        self.chain._restore_memory_snapshot(snapshot)

        after = self.chain.reaction_state.state_root_contribution()
        self.assertEqual(
            before, after,
            "reaction_state.state_root_contribution() must be "
            "byte-identical after rollback — any divergence here is "
            "the silent-fork primitive the audit flagged.",
        )

    def test_restored_reaction_state_is_independent_object(self):
        """Regression for the deep/shallow-copy contract: the
        restored ``reaction_state`` must NOT share inner-map identity
        with the snapshot's stored copy.  Otherwise a subsequent
        failed reorg could mutate the captured snapshot through the
        live reference, making future restores observe the leak."""
        # Seed each inner map so the snapshot has something to capture.
        self.chain.reaction_state.choices[(_eid(0x01), _eid(0x02), True)] = (
            REACT_CHOICE_UP
        )
        self.chain.reaction_state._user_trust_score[_eid(0x02)] = 1
        self.chain.reaction_state._message_score[_eid(0x03)] = 1

        snapshot = self.chain._snapshot_memory_state()
        self.chain._restore_memory_snapshot(snapshot)

        # Mutating live state must NOT bleed back into the snapshot.
        # (We don't pin the exact storage shape — list of entries vs
        # dict copy — only the isolation invariant.)
        self.chain.reaction_state.choices[(_eid(0xFE), _eid(0xFE), False)] = (
            REACT_CHOICE_DOWN
        )
        self.chain.reaction_state._user_trust_score[_eid(0xFE)] = 99
        self.chain.reaction_state._message_score[_eid(0xFE)] = 99

        # Re-restoring from the same snapshot must wipe the post-restore
        # mutations — proving the snapshot was never aliased to live.
        self.chain._restore_memory_snapshot(snapshot)
        self.assertNotIn(
            (_eid(0xFE), _eid(0xFE), False),
            self.chain.reaction_state.choices,
        )
        self.assertNotIn(
            _eid(0xFE), self.chain.reaction_state._user_trust_score,
        )
        self.assertNotIn(
            _eid(0xFE), self.chain.reaction_state._message_score,
        )


class TestReactionStateRestoreStructuralSymmetry(unittest.TestCase):
    """Structural guard locking the symmetry between snapshot and
    restore for reaction_state.  Catches the next defect of this
    class at CI time: if a future refactor adds the snapshot key
    but forgets the restore, or renames the field, this blows up.
    """

    REACTION_STATE_KEY = "reaction_state"

    def setUp(self):
        self.proposer = Entity.create(b"react-symm-prop".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def test_reaction_state_is_present_in_snapshot(self):
        """The snapshot dict must carry the reaction_state key.  If a
        future refactor renames or drops it, this fails immediately.
        """
        snapshot = self.chain._snapshot_memory_state()
        self.assertIn(
            self.REACTION_STATE_KEY, snapshot,
            f"_snapshot_memory_state must include "
            f"'{self.REACTION_STATE_KEY}' — missing key drops the "
            f"reaction-state mutable state from the rollback boundary, "
            f"reintroducing the choices / aggregate-score poisoning "
            f"attack.",
        )

    def test_round_trip_restores_reaction_state(self):
        """Mutate every inner map of reaction_state, take a snapshot,
        blow live state away, restore, and check all inner maps
        match the snapshot's view."""
        self.chain.reaction_state.choices[
            (_eid(0x10), _eid(0x11), True)
        ] = REACT_CHOICE_UP
        self.chain.reaction_state._user_trust_score[_eid(0x11)] = 4
        self.chain.reaction_state._message_score[_eid(0x12)] = 5

        snapshot = self.chain._snapshot_memory_state()

        # Reset live state to a fresh empty ReactionState.
        self.chain.reaction_state = ReactionState()

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            self.chain.reaction_state.choices[
                (_eid(0x10), _eid(0x11), True)
            ],
            REACT_CHOICE_UP,
        )
        self.assertEqual(
            self.chain.reaction_state._user_trust_score[_eid(0x11)], 4,
        )
        self.assertEqual(
            self.chain.reaction_state._message_score[_eid(0x12)], 5,
        )

    def test_default_initialised_chain_has_clean_reaction_state_after_restore(self):
        """A snapshot taken on an empty reaction_state and restored
        after a manual mutation must zero the live state back out.
        Pre-fix the reaction state was never captured, so manual
        mutations leaked across the rollback boundary
        unconditionally."""
        snapshot = self.chain._snapshot_memory_state()

        self.chain.reaction_state.choices[
            (_eid(0x99), _eid(0x99), True)
        ] = REACT_CHOICE_DOWN
        self.chain.reaction_state._user_trust_score[_eid(0x99)] = 9
        self.chain.reaction_state._message_score[_eid(0x99)] = 9

        self.chain._restore_memory_snapshot(snapshot)

        self.assertEqual(self.chain.reaction_state.choices, {})
        self.assertEqual(self.chain.reaction_state._user_trust_score, {})
        self.assertEqual(self.chain.reaction_state._message_score, {})


if __name__ == "__main__":
    unittest.main()
