"""Critical-severity audit fixes -- round 12 (2026-04-26).

Two CRITICAL Tier 17 wiring gaps -- not exploitable today
(REACT_TX_HEIGHT=9000, current tip << 9000) but MUST land before
activation block 9000 or first-touch turns into key compromise /
state-sync hard break.

#1 -- ReactTransaction skips the WOTS+ leaf-watermark check at
admission AND the in-block leaf-dedupe sweep.  Two distinct signed
payloads under the same WOTS+ leaf (e.g. a Transfer at leaf N + a
React at leaf N from the same voter) leak enough one-time-key
material for any observer to forge arbitrary signatures under that
leaf, including a TransferTransaction draining the voter's full
balance and stake.

Fix:
- `_validate_react_tx_in_block` rejects
  `rtx.signature.leaf_index < self.leaf_watermarks[rtx.voter_id]`
  (mirrors message / transfer / stake / governance)
- `_check_leaf` block-level sweep iterates `block.react_transactions`
  alongside every other tx kind
- `_check_leaf_across_all_pools` (server.py) scans the react_pool
- `_rpc_submit_react` calls `_check_leaf_across_all_pools` AND the
  per-entity watermark gate before mempool admission

#2 -- `ReactionState` ground-truth `choices` map missing from snapshot
encode/decode/install + chaindb save/restore symmetry.  Pre-fix:
  * `state_snapshot.serialize_state` didn't extract reaction_choices;
    `_TAG_REACTION_CHOICES` didn't exist; encode/decode didn't
    write/read it; `compute_state_root` committed zero reaction
    data.
  * `_install_state_snapshot` left `self.reaction_state` as the
    default empty `ReactionState()` after install.
  * `chaindb.save_state_snapshot` didn't capture reaction_choices;
    `restore_state_snapshot` didn't wipe / re-insert.

Once REACT_TX_HEIGHT activates, every checkpoint-bootstrapped node
fails the install-time root-equality check (synced node computes
root over empty reactions; canonical header committed root over
real reactions) -- state-sync becomes IMPOSSIBLE.  Reorg across a
React-bearing block leaves orphan-fork rows on disk -> cold restart
silently forks.

Fix:
- bump `STATE_SNAPSHOT_VERSION 20 -> 21`
- add `_TAG_REACTION_CHOICES` Merkle section + leaf builder
- `serialize_state` extracts `blockchain.reaction_state.choices`
- `_install_state_snapshot` rebuilds ReactionState from the
  snapshot map AND mirrors entries to chaindb
- `chaindb.save_state_snapshot` includes reaction_choices
- `chaindb.restore_state_snapshot` wipes the table and re-INSERTs
  inside the same SQL transaction
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from messagechain.identity.identity import Entity
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.core.blockchain import Blockchain
from messagechain.storage.chaindb import ChainDB
from messagechain.storage.state_snapshot import (
    STATE_SNAPSHOT_VERSION,
    _TAG_REACTION_CHOICES,
    serialize_state, encode_snapshot, decode_snapshot, deserialize_state,
    compute_state_root,
)


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #1 -- React-tx WOTS+ leaf-watermark + in-block sweep
# ─────────────────────────────────────────────────────────────────────


class TestReactTxWatermarkGuardSourcePresent(unittest.TestCase):
    """Source-level assertion: the watermark gate appears in
    `_validate_react_tx_in_block` (full source check; cheaper than
    plumbing a fake validate_block call with a constructed React-tx
    block, which requires header signing + merkle-root + every other
    block-validation gate to pass first)."""

    def test_validate_react_tx_in_block_checks_watermark(self):
        import inspect
        from messagechain.core.blockchain import Blockchain
        src = inspect.getsource(Blockchain.validate_block)
        # The watermark guard MUST appear inside the react-tx loop.
        self.assertIn(
            "rtx.signature.leaf_index < self.leaf_watermarks", src,
            "validate_block's react-tx loop MUST enforce the WOTS+ "
            "leaf-watermark gate -- pre-fix the react path admitted "
            "any leaf_index, leaking the WOTS+ secret on the second "
            "signed payload at that leaf.",
        )

    def test_check_leaf_sweep_iterates_react_transactions(self):
        """The in-block `_check_leaf` sweep MUST scan
        block.react_transactions -- otherwise two same-leaf signed
        payloads in the same block (e.g. Transfer + React) bypass
        the dedup, both apply, secret leaks."""
        import inspect
        from messagechain.core.blockchain import Blockchain
        src = inspect.getsource(Blockchain.validate_block)
        self.assertIn(
            'for rtx in getattr(block, "react_transactions", [])', src,
            "_check_leaf sweep MUST iterate react_transactions or two "
            "same-leaf signed payloads in the same block bypass dedup.",
        )


class TestReactTxCrossPoolLeafDedupe(unittest.TestCase):
    """`_check_leaf_across_all_pools` MUST scan the react pool -- a
    Transfer in _pending_*_txs at leaf N and a React in
    mempool.react_pool at leaf N from the same voter MUST be flagged
    as a leaf collision."""

    def setUp(self):
        from messagechain import config
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        from messagechain import config
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def test_check_leaf_across_pools_source_includes_react(self):
        import inspect
        from server import Server
        src = inspect.getsource(Server._check_leaf_across_all_pools)
        self.assertIn(
            "react_pool", src,
            "_check_leaf_across_all_pools MUST scan the react pool -- "
            "without this a Transfer-then-React (or Message-then-React) "
            "at the same leaf bypasses cross-pool dedup at admission.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2a -- snapshot encode/decode/install round-trip for
# reaction_choices
# ─────────────────────────────────────────────────────────────────────


class TestStateSnapshotIncludesReactionChoices(unittest.TestCase):
    """`serialize_state` extracts reaction_choices, encode/decode
    round-trips it, `compute_state_root` commits to it,
    `_install_state_snapshot` populates `self.reaction_state` from
    it AND mirrors entries to chaindb."""

    def test_version_bumped_to_21(self):
        self.assertEqual(
            STATE_SNAPSHOT_VERSION, 21,
            "Round-12 fix bumps STATE_SNAPSHOT_VERSION 20 -> 21 to "
            "carry reaction_choices in the wire format and snapshot "
            "root.",
        )

    def test_tag_present_and_distinct(self):
        self.assertEqual(_TAG_REACTION_CHOICES, b"react")

    def test_serialize_state_extracts_reaction_choices(self):
        alice = _entity(b"r12-extract-alice")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        # Plant a non-trivial reaction_choices map directly (bypass
        # apply path -- we're testing snapshot extraction).
        from messagechain.core.reaction import REACT_CHOICE_UP
        chain.reaction_state.choices[
            (b"v" * 32, b"\xaa" * 32, True)
        ] = REACT_CHOICE_UP
        chain.reaction_state.choices[
            (b"w" * 32, b"\xbb" * 32, False)
        ] = REACT_CHOICE_UP
        snap = serialize_state(chain)
        self.assertIn(
            "reaction_choices", snap,
            "serialize_state MUST extract reaction_choices for v21 "
            "snapshot root commitment.",
        )
        self.assertEqual(
            snap["reaction_choices"][(b"v" * 32, b"\xaa" * 32, True)],
            REACT_CHOICE_UP,
        )
        self.assertEqual(
            snap["reaction_choices"][(b"w" * 32, b"\xbb" * 32, False)],
            REACT_CHOICE_UP,
        )

    def test_encode_decode_round_trip_preserves_reaction_choices(self):
        alice = _entity(b"r12-rt-alice")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        from messagechain.core.reaction import (
            REACT_CHOICE_UP, REACT_CHOICE_DOWN,
        )
        chain.reaction_state.choices[
            (b"v1" + b"\x00" * 30, b"\x01" * 32, True)
        ] = REACT_CHOICE_UP
        chain.reaction_state.choices[
            (b"v2" + b"\x00" * 30, b"\x02" * 32, False)
        ] = REACT_CHOICE_DOWN
        snap = serialize_state(chain)
        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))
        self.assertEqual(
            decoded["reaction_choices"][(b"v1" + b"\x00" * 30, b"\x01" * 32, True)],
            REACT_CHOICE_UP,
        )
        self.assertEqual(
            decoded["reaction_choices"][(b"v2" + b"\x00" * 30, b"\x02" * 32, False)],
            REACT_CHOICE_DOWN,
        )

    def test_state_root_diverges_when_reaction_choices_differ(self):
        """Two snapshots identical except for reaction_choices MUST
        produce DIFFERENT state roots -- otherwise state-synced
        nodes that observed different reaction histories agree on
        root but disagree on `state_root_contribution()` and
        silently fork on the next contested vote."""
        alice = _entity(b"r12-div-alice")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        snap_a = serialize_state(chain)
        snap_b = serialize_state(chain)
        from messagechain.core.reaction import REACT_CHOICE_UP
        snap_a["reaction_choices"] = {}
        snap_b["reaction_choices"] = {
            (b"v" * 32, b"\xee" * 32, True): REACT_CHOICE_UP,
        }
        root_a = compute_state_root(snap_a)
        root_b = compute_state_root(snap_b)
        self.assertNotEqual(
            root_a, root_b,
            "State-snapshot root MUST commit to reaction_choices "
            "under _TAG_REACTION_CHOICES or two state-synced nodes "
            "with different reaction histories silently fork.",
        )

    def test_install_state_snapshot_round_trips_reaction_choices(self):
        from messagechain.core.reaction import (
            REACT_CHOICE_UP, REACT_CHOICE_DOWN, _score_value,
        )
        # Source chain: install non-trivial reaction state.
        src_alice = _entity(b"r12-inst-src")
        src = Blockchain()
        src.initialize_genesis(src_alice)
        eid_v = b"voter1" + b"\x00" * 26
        eid_t = b"target1" + b"\x00" * 25
        # User-trust UP: contributes +1 to user_trust_score[target]
        src.reaction_state.choices[(eid_v, eid_t, True)] = REACT_CHOICE_UP
        src.reaction_state._user_trust_score[eid_t] = (
            _score_value(REACT_CHOICE_UP)
        )
        # Message-react DOWN on a separate target: contributes -1.
        msg_h = b"\x77" * 32
        src.reaction_state.choices[(eid_v, msg_h, False)] = REACT_CHOICE_DOWN
        src.reaction_state._message_score[msg_h] = (
            _score_value(REACT_CHOICE_DOWN)
        )
        snap = serialize_state(src)
        blob = encode_snapshot(snap)
        decoded = deserialize_state(decode_snapshot(blob))
        # Destination chain: install into a fresh blockchain.
        dst_alice = _entity(b"r12-inst-dst")
        dst = Blockchain()
        dst.initialize_genesis(dst_alice)
        # Sanity: pre-install dst has empty reaction state.
        self.assertEqual(dst.reaction_state.choices, {})

        dst._install_state_snapshot(decoded)

        self.assertIn(
            (eid_v, eid_t, True), dst.reaction_state.choices,
            "_install_state_snapshot MUST install reaction_choices.",
        )
        self.assertEqual(
            dst.reaction_state.choices[(eid_v, eid_t, True)],
            REACT_CHOICE_UP,
        )
        self.assertEqual(
            dst.reaction_state.choices[(eid_v, msg_h, False)],
            REACT_CHOICE_DOWN,
        )
        # Aggregates rebuilt -- the invariant
        # `aggregate == sum_of_pairs(choices)` must hold post-install.
        self.assertEqual(
            dst.reaction_state.user_trust_score(eid_t),
            _score_value(REACT_CHOICE_UP),
        )
        self.assertEqual(
            dst.reaction_state.message_score(msg_h),
            _score_value(REACT_CHOICE_DOWN),
        )
        # Both nodes' state_root_contribution agree.
        self.assertEqual(
            src.reaction_state.state_root_contribution(),
            dst.reaction_state.state_root_contribution(),
            "Source and synced node MUST compute identical "
            "state_root_contribution() -- otherwise install-time "
            "root-equality check would fail and state-sync breaks.",
        )


# ─────────────────────────────────────────────────────────────────────
# CRITICAL #2b -- chaindb save/restore symmetry for reaction_choices
# ─────────────────────────────────────────────────────────────────────


class TestChaindbReactionChoicesSaveRestoreSymmetry(unittest.TestCase):
    """`save_state_snapshot` MUST capture reaction_choices and
    `restore_state_snapshot` MUST wipe + re-insert atomically.
    Pre-fix a successful reorg across a React-bearing block left the
    losing-fork vote permanently on disk -- cold restart rehydrated
    the orphan vote and silently forked."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "chain.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_state_snapshot_captures_reaction_choices(self):
        from messagechain.core.reaction import REACT_CHOICE_UP
        db = ChainDB(self.db_path)
        try:
            voter = b"v" * 32
            target = b"\xaa" * 32
            db.set_reaction_choice(voter, target, True, REACT_CHOICE_UP)
            db.flush_state()
            snap = db.save_state_snapshot()
            self.assertIn(
                "reaction_choices", snap,
                "save_state_snapshot MUST capture reaction_choices "
                "or restore wipes the table without re-population -- "
                "cold restart in the post-restore window forks on "
                "the next state-root computation that mixes "
                "ReactionState.state_root_contribution().",
            )
            self.assertEqual(
                snap["reaction_choices"][(voter, target, True)],
                REACT_CHOICE_UP,
            )
        finally:
            db.close()

    def test_restore_state_snapshot_reinserts_reaction_choices(self):
        from messagechain.core.reaction import (
            REACT_CHOICE_UP, REACT_CHOICE_DOWN,
        )
        db = ChainDB(self.db_path)
        try:
            voter = b"v" * 32
            target = b"\xbb" * 32
            db.set_reaction_choice(voter, target, True, REACT_CHOICE_UP)
            db.flush_state()
            snap = db.save_state_snapshot()
            # Mutate to simulate a losing-fork vote.
            db.set_reaction_choice(voter, target, True, REACT_CHOICE_DOWN)
            other_target = b"\xcc" * 32
            db.set_reaction_choice(voter, other_target, False, REACT_CHOICE_UP)
            db.flush_state()
            # Commit any auto-opened DML tx so restore's BEGIN can fire.
            db._conn.commit()
            db.restore_state_snapshot(snap)
            choices = db.get_all_reaction_choices()
            self.assertEqual(
                choices.get((voter, target, True)), REACT_CHOICE_UP,
                "restore MUST roll back the losing-fork mutation and "
                "re-insert the snapshot value.",
            )
            self.assertNotIn(
                (voter, other_target, False), choices,
                "Losing-fork-only vote MUST NOT survive restore.",
            )
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
