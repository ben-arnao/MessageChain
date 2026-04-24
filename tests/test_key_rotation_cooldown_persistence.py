"""Iter R6-B: KEY_ROTATION_COOLDOWN_BLOCKS map must be rebuilt on replay.

Bug: `validate_key_rotation` enforces the cooldown via
`self.key_rotation_last_height`, but that map was only updated by the
RPC-apply path (`apply_key_rotation`).  The block-apply path
(`_apply_authority_tx` for `KeyRotationTransaction`) updated
`public_keys`, `key_rotation_counts`, and `leaf_watermarks` but
forgot `key_rotation_last_height`.  Additionally the map was not
captured by `_snapshot_memory_state`, so a failed-reorg rollback
would leave it at whatever the mid-reorg replay produced rather
than the pre-reorg value.

Consequence: after any reorg (or any rotation applied through a
normal block, not via the RPC-apply path) the cooldown is forgotten,
letting an attacker rotate every block to erase forensic traceability
of recent slashable behaviour — the exact attack iter 6 H2 set out to
block.

These tests pin:
A. Block-apply path updates `key_rotation_last_height`.
B. Replay via `_reset_state` + `_apply_block_state` rebuilds the map.
C. `_snapshot_memory_state` + `_restore_memory_snapshot` round-trip
   the map, so a failed-reorg rollback restores it.
D. RPC-apply path still updates the map (regression guard).
"""

from __future__ import annotations

import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.key_rotation import (
    create_key_rotation, derive_rotated_keypair,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain: Blockchain, entity: Entity) -> None:
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _bootstrap(self):
        """Chain with staked proposer + staked alice, at genesis."""
        chain = Blockchain()
        proposer = _entity(b"proposer")
        alice = _entity(b"alice")
        self._register(chain, proposer)
        self._register(chain, alice)
        chain.supply.balances[proposer.entity_id] = 200_000_000
        chain.supply.staked[proposer.entity_id] = 100_000_000
        chain.supply.balances[alice.entity_id] = 10_000_000
        chain.initialize_genesis(proposer)
        consensus = ProofOfStake()
        consensus.register_validator(
            proposer.entity_id, stake_amount=100_000_000,
        )
        return chain, proposer, alice, consensus


class TestBlockApplyPathUpdatesCooldownMap(_Base):
    """Test A: applying a KeyRotation through the block pipeline must
    update `key_rotation_last_height`, otherwise the cooldown never
    fires for rotations included in regular blocks."""

    def test_block_apply_sets_last_height(self):
        chain, proposer, alice, consensus = self._bootstrap()
        self.assertNotIn(alice.entity_id, chain.key_rotation_last_height)

        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot_tx = create_key_rotation(alice, new_kp, rotation_number=0)
        blk = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[rot_tx],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)

        # After the block lands, height is 1 (genesis is block 0).  The
        # rotation was applied while self.height was 1 (the new block
        # is appended AFTER _apply_block_state), so last_height must be
        # exactly the pre-append height, matching apply_key_rotation's
        # RPC-path semantics.
        self.assertIn(
            alice.entity_id, chain.key_rotation_last_height,
            "Block-apply path must update key_rotation_last_height so the "
            "KEY_ROTATION_COOLDOWN_BLOCKS check actually fires on replay",
        )
        recorded = chain.key_rotation_last_height[alice.entity_id]
        # Whatever the precise height value is, it must be within the
        # cooldown window so that a second rotation attempted right
        # after is rejected.
        self.assertLess(
            chain.height - recorded, config.KEY_ROTATION_COOLDOWN_BLOCKS,
            "Recorded height must leave cooldown elapsed-count < window",
        )


class TestReplayRebuildsCooldownMap(_Base):
    """Test B: the reorg replay path `_apply_authority_tx` must rebuild
    `key_rotation_last_height`.  This is the reorg scenario:
    `_reorganize` calls `_reset_state` (which clears the map) then
    re-applies each canonical block's authority txs via
    `_apply_authority_tx`.  Without the fix the map stays empty and
    cooldown is lost on every reorg.

    We exercise `_apply_authority_tx` directly rather than invoking a
    full `_reorganize`, because the broader reorg replay path has
    unrelated dependencies (prior blocks must have rebuilt balance for
    the fee payment, and `_reset_state` preserves current pubkeys which
    defeats the rotation signature check — issues outside the R6-B
    scope).  The R6-B fix is specifically about `_apply_authority_tx`
    writing to the map, which is what this test pins down.
    """

    def test_apply_authority_tx_rebuilds_last_height(self):
        chain, _, alice, _ = self._bootstrap()

        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot_tx = create_key_rotation(alice, new_kp, rotation_number=0)

        # Simulate the post-_reset_state state that replay starts from:
        # map is empty, balance is available for the fee, rotation count
        # is 0 (cleared by _reset_state).  We leave public_keys[alice]
        # as the original pre-rotation key so validate_key_rotation's
        # signature check passes — authority_txs on replay are
        # validated against the pubkey seen at that block height, which
        # on a cleanly-rewound chain is the pre-rotation key.
        chain.key_rotation_last_height = {}
        chain.key_rotation_counts[alice.entity_id] = 0

        chain._apply_authority_tx(
            rot_tx, proposer_id=alice.entity_id, base_fee=100,
        )

        self.assertIn(
            alice.entity_id, chain.key_rotation_last_height,
            "Replay through _apply_authority_tx must rebuild "
            "key_rotation_last_height, otherwise reorg drops the "
            "cooldown and lets an attacker rotate again immediately",
        )
        self.assertEqual(
            chain.key_rotation_last_height[alice.entity_id], chain.height,
            "Rebuilt height must reflect the chain height at apply time",
        )


class TestCooldownActuallyEnforcedAfterBlockApply(_Base):
    """A second rotation attempted within the cooldown window must be
    rejected.  Pre-fix the block-apply path left the map empty, so
    validate_key_rotation computed elapsed = height - (-144) = height +
    144 >= 144 and accepted the second rotation immediately."""

    def test_second_rotation_within_cooldown_rejected(self):
        chain, proposer, alice, consensus = self._bootstrap()

        # First rotation through a block.
        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot_tx = create_key_rotation(alice, new_kp, rotation_number=0)
        blk = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[rot_tx],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)

        # Second rotation attempted immediately (well within cooldown).
        rotated_entity = Entity(
            entity_id=alice.entity_id,
            keypair=new_kp,
            _seed=alice._seed,
        )
        new_kp2 = derive_rotated_keypair(rotated_entity, rotation_number=1)
        rot_tx2 = create_key_rotation(
            rotated_entity, new_kp2, rotation_number=1,
        )
        valid, reason2 = chain.validate_key_rotation(rot_tx2)
        self.assertFalse(
            valid,
            "Second rotation within KEY_ROTATION_COOLDOWN_BLOCKS must "
            "be rejected; was accepted, indicating the block-apply path "
            "failed to record last_height",
        )
        self.assertIn("cooldown", reason2.lower())


class TestSnapshotRestoreRoundTrip(_Base):
    """Test C: `_snapshot_memory_state` must capture
    `key_rotation_last_height` and `_restore_memory_snapshot` must put
    it back.  This is the failed-reorg rollback path: if the new fork's
    state_root fails validation mid-replay, we restore the snapshot —
    without the map being snapshotted, the pre-reorg cooldown state
    is silently forgotten."""

    def test_snapshot_captures_last_height(self):
        chain, _, alice, _ = self._bootstrap()
        chain.key_rotation_last_height[alice.entity_id] = 42

        snap = chain._snapshot_memory_state()
        self.assertIn("key_rotation_last_height", snap)
        self.assertEqual(
            snap["key_rotation_last_height"].get(alice.entity_id), 42,
            "Snapshot must capture the map so reorg rollback preserves "
            "cooldown state",
        )

    def test_restore_replays_last_height(self):
        chain, _, alice, _ = self._bootstrap()
        chain.key_rotation_last_height[alice.entity_id] = 77

        snap = chain._snapshot_memory_state()

        # Mutate as if a mid-reorg apply advanced the map, then fail.
        chain.key_rotation_last_height[alice.entity_id] = 999
        chain.key_rotation_last_height[b"ghost" * 4] = 500

        chain._restore_memory_snapshot(snap)

        self.assertEqual(
            chain.key_rotation_last_height.get(alice.entity_id), 77,
            "Restore must overwrite mid-reorg mutations of the map",
        )
        self.assertNotIn(
            b"ghost" * 4, chain.key_rotation_last_height,
            "Restore must drop entries that did not exist in the snapshot",
        )

    def test_snapshot_deepcopies_map(self):
        """Subsequent mutations must not leak through the snapshot
        reference (same pattern as key_rotation_counts)."""
        chain, _, alice, _ = self._bootstrap()
        chain.key_rotation_last_height[alice.entity_id] = 10

        snap = chain._snapshot_memory_state()

        # Mutate live state after snapshot.
        chain.key_rotation_last_height[alice.entity_id] = 20

        # Snapshot must still reflect the original value.
        self.assertEqual(
            snap["key_rotation_last_height"].get(alice.entity_id), 10,
            "Snapshot stored a live reference — mutations after snapshot "
            "time leaked through",
        )


class TestRPCPathRegression(_Base):
    """Test D: the RPC-apply path `apply_key_rotation` must continue to
    set `key_rotation_last_height`.  The fix must not regress this; both
    paths should agree."""

    def test_rpc_apply_sets_last_height(self):
        chain = Blockchain()
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 10_000

        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot_tx = create_key_rotation(alice, new_kp, rotation_number=0)
        ok, _ = chain.apply_key_rotation(rot_tx, proposer_id=alice.entity_id)
        self.assertTrue(ok)

        self.assertIn(
            alice.entity_id, chain.key_rotation_last_height,
            "RPC-apply path regression — it must still update the map",
        )
        self.assertEqual(
            chain.key_rotation_last_height[alice.entity_id],
            chain.height,
            "RPC-apply must record the current chain height, matching "
            "the block-apply path semantics (both paths must agree so "
            "that a rotation yields the same cooldown regardless of how "
            "it was applied)",
        )


class TestColdBootChaindbRehydration(_Base):
    """Test E (v18 fix): a cold-booted node rehydrating from chaindb
    MUST restore `key_rotation_last_height` so the
    KEY_ROTATION_COOLDOWN_BLOCKS gate fires consistently with a warm
    cluster.  Before the v18 fix, the map was in-memory-only -- restart
    wiped it, and a rotation already rejected by warm peers was
    accepted by the restarted node, splitting consensus.
    """

    def test_chaindb_persists_and_rehydrates_cooldown_map(self):
        import tempfile
        import os
        from messagechain.storage.chaindb import ChainDB

        tmp = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)

            # Mimic apply-time write: record rotation_last_height for alice.
            alice_id = b"alice-cold".ljust(32, b"\x00")
            db.set_key_rotation_last_height(alice_id, 777)
            db.flush_state() if hasattr(db, "flush_state") else None

            # Re-open the DB (new handle) and confirm the row is readable.
            db2 = ChainDB(db_path)
            rehydrated = db2.get_all_key_rotation_last_height()
            self.assertEqual(
                rehydrated.get(alice_id), 777,
                "chaindb must persist key_rotation_last_height across a "
                "process restart -- without this, a cold-booted validator "
                "silently accepts rotations the warm cluster rejects, "
                "forking consensus",
            )
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_state_snapshot_roundtrip_includes_krlh(self):
        """The v18 state snapshot MUST round-trip
        key_rotation_last_height AND the snapshot root must change
        when the map changes (ensures the field participates in the
        consensus commitment, not just the wire format)."""
        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
            compute_state_root, STATE_SNAPSHOT_VERSION,
        )
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 18)
        chain, _, alice, _ = self._bootstrap()
        chain.key_rotation_last_height[alice.entity_id] = 42

        snap = serialize_state(chain)
        self.assertEqual(
            snap["key_rotation_last_height"].get(alice.entity_id), 42,
        )
        blob = encode_snapshot(snap)
        restored = decode_snapshot(blob)
        self.assertEqual(
            restored["key_rotation_last_height"].get(alice.entity_id), 42,
        )
        # Root sensitivity: changing krlh must change the root.  Without
        # this the field is not in the consensus commitment and two
        # nodes can disagree on the map without tripping root mismatch.
        root_with_42 = compute_state_root(snap)
        snap2 = dict(snap)
        snap2["key_rotation_last_height"] = dict(
            snap["key_rotation_last_height"],
        )
        snap2["key_rotation_last_height"][alice.entity_id] = 9999
        root_with_9999 = compute_state_root(snap2)
        self.assertNotEqual(
            root_with_42, root_with_9999,
            "state-root must commit to key_rotation_last_height -- "
            "otherwise two nodes disagreeing on the map compute the "
            "same root and fork silently at the next rotation",
        )


if __name__ == "__main__":
    unittest.main()
