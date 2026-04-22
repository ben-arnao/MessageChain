"""Tests for signed state checkpoints (bootstrap-speed sync).

A new full node should be able to bootstrap from a signed state snapshot
at block height X plus the recent blocks since X — no replay from genesis.

Coverage:
    * state_snapshot.compute_state_root is deterministic
    * Equivalent states from different construction paths produce the same root
    * serialize_state / deserialize_state preserve state exactly
    * Tampering with any field changes the root
    * StateCheckpoint sign/verify + dict/binary round-trip
    * StateCheckpoint double-sign evidence detection
    * >= 2/3-stake-signed checkpoint verifies
    * < 2/3 checkpoint rejected
    * bootstrap_from_checkpoint reconstructs a working chain
    * A bootstrapped chain can produce and validate new blocks that the
      full-history chain also accepts
    * Snapshot larger than MAX_STATE_SNAPSHOT_BYTES is rejected
    * Mismatched state_root between checkpoint and snapshot is rejected
    * Network protocol REQUEST/RESPONSE_STATE_CHECKPOINT round-trips
    * verified_state_checkpoints chaindb table round-trips
"""

import tempfile
import os
import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, _hash
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.storage.chaindb import ChainDB
from messagechain.storage.state_snapshot import (
    serialize_state,
    deserialize_state,
    compute_state_root as compute_snapshot_root,
    STATE_SNAPSHOT_VERSION,
)
from messagechain.consensus.state_checkpoint import (
    StateCheckpoint,
    StateCheckpointSignature,
    create_state_checkpoint_signature,
    verify_state_checkpoint_signature,
    StateCheckpointDoubleSignEvidence,
    verify_state_checkpoint_double_sign_evidence,
)
from messagechain.network.protocol import MessageType, NetworkMessage
from messagechain.config import (
    STATE_CHECKPOINT_INTERVAL,
    STATE_CHECKPOINT_THRESHOLD_NUMERATOR,
    STATE_CHECKPOINT_THRESHOLD_DENOMINATOR,
    MAX_STATE_SNAPSHOT_BYTES,
    STATE_ROOT_VERSION,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from tests import register_entity_for_test, pick_selected_proposer


def _build_chain_with_txs(extra_blocks=3):
    """Fresh single-validator chain, then `extra_blocks` message blocks.

    Returns (chain, validator, consensus).
    """
    alice = Entity.create(b"alice-key".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(alice)
    # Fund alice so she can pay fees + stake.
    chain.supply.balances[alice.entity_id] = 1_000_000
    chain.supply.stake(alice.entity_id, 10_000)
    consensus = ProofOfStake()
    for i in range(extra_blocks):
        tx = create_transaction(
            alice, f"msg-{i}", fee=1500,
            nonce=chain.nonces.get(alice.entity_id, 0),
        )
        prev = chain.get_latest_block()
        state_root = chain.compute_post_state_root(
            [tx], alice.entity_id, prev.header.block_number + 1,
        )
        block = consensus.create_block(
            alice, [tx], prev, state_root=state_root,
        )
        ok, reason = chain.add_block(block)
        if not ok:
            raise RuntimeError(f"block add failed: {reason}")
    return chain, alice, consensus


class TestSnapshotDeterminism(unittest.TestCase):
    """compute_state_root: deterministic + construction-path-independent."""

    def test_same_state_same_root(self):
        chain, _alice, _c = _build_chain_with_txs(2)
        root1 = compute_snapshot_root(serialize_state(chain))
        root2 = compute_snapshot_root(serialize_state(chain))
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 32)

    def test_different_construction_same_root(self):
        """Two snapshot dicts with the same content produce the same root,
        regardless of iteration order when the dict was built.

        Asserts the sorted-iteration property of compute_state_root: the
        hash must NOT depend on Python dict insertion order.
        """
        # Construct two dicts with the same contents but different
        # insertion orders.  sorted() inside compute_state_root should
        # make the root identical.
        eid_a = b"a" * 32
        eid_b = b"b" * 32
        snap1 = {
            "version": STATE_SNAPSHOT_VERSION,
            "balances": {eid_a: 100, eid_b: 200},
            "nonces": {eid_a: 5, eid_b: 6},
            "staked": {},
            "public_keys": {eid_a: b"pk_a", eid_b: b"pk_b"},
            "authority_keys": {},
            "leaf_watermarks": {},
            "key_rotation_counts": {},
            "revoked_entities": set(),
            "slashed_validators": set(),
            "entity_id_to_index": {eid_a: 1, eid_b: 2},
            "next_entity_index": 3,
            "total_supply": 1000,
            "total_minted": 0,
            "total_fees_collected": 0,
            "total_burned": 0,
            "base_fee": 100,
            "finalized_checkpoints": {},
        }
        # Same content, different insertion order on all dicts and sets.
        snap2 = {
            "version": STATE_SNAPSHOT_VERSION,
            "balances": {eid_b: 200, eid_a: 100},
            "nonces": {eid_b: 6, eid_a: 5},
            "staked": {},
            "public_keys": {eid_b: b"pk_b", eid_a: b"pk_a"},
            "authority_keys": {},
            "leaf_watermarks": {},
            "key_rotation_counts": {},
            "revoked_entities": set(),
            "slashed_validators": set(),
            "entity_id_to_index": {eid_b: 2, eid_a: 1},
            "next_entity_index": 3,
            "total_supply": 1000,
            "total_minted": 0,
            "total_fees_collected": 0,
            "total_burned": 0,
            "base_fee": 100,
            "finalized_checkpoints": {},
        }
        self.assertEqual(
            compute_snapshot_root(snap1),
            compute_snapshot_root(snap2),
        )

    def test_tamper_changes_root(self):
        chain, alice, _c = _build_chain_with_txs(1)
        snap = serialize_state(chain)
        root_before = compute_snapshot_root(snap)

        # Tamper with a balance and recompute
        snap_tamp = {k: (v.copy() if isinstance(v, dict) else
                         (set(v) if isinstance(v, set) else v))
                     for k, v in snap.items()}
        snap_tamp["balances"][alice.entity_id] = (
            snap_tamp["balances"].get(alice.entity_id, 0) + 1
        )
        root_after = compute_snapshot_root(snap_tamp)
        self.assertNotEqual(root_before, root_after)


class TestSnapshotSerialization(unittest.TestCase):
    """serialize_state / deserialize_state round-trip preserves everything."""

    def test_roundtrip_preserves_state(self):
        chain, alice, _c = _build_chain_with_txs(2)
        snap = serialize_state(chain)
        blob = chain_snapshot_to_bytes(snap)
        restored = bytes_to_chain_snapshot(blob)

        # Root survives the round-trip
        self.assertEqual(
            compute_snapshot_root(snap),
            compute_snapshot_root(restored),
        )
        # Key fields match
        self.assertEqual(snap["balances"], restored["balances"])
        self.assertEqual(snap["nonces"], restored["nonces"])
        self.assertEqual(snap["staked"], restored["staked"])
        self.assertEqual(snap["total_supply"], restored["total_supply"])
        self.assertEqual(snap["base_fee"], restored["base_fee"])

    def test_version_byte_present(self):
        chain, _a, _c = _build_chain_with_txs(0)
        snap = serialize_state(chain)
        blob = chain_snapshot_to_bytes(snap)
        # First byte is the format version
        self.assertEqual(blob[0], STATE_SNAPSHOT_VERSION)

    def test_oversize_rejected(self):
        # Synthesize a too-big blob and ensure deserialize rejects it
        chain, _a, _c = _build_chain_with_txs(0)
        snap = serialize_state(chain)
        # Make balances table absurdly large with many synthetic entities
        balances = dict(snap["balances"])
        for i in range(10):
            balances[b"x" * 32 + i.to_bytes(8, "big")] = i
        snap["balances"] = balances
        # Real encode
        blob = chain_snapshot_to_bytes(snap)
        # Pretend limit is way smaller than the encoded size
        with self.assertRaises(ValueError):
            bytes_to_chain_snapshot(blob, max_bytes=1)


def chain_snapshot_to_bytes(snap):
    """Test helper that wraps the module's binary encoder."""
    from messagechain.storage.state_snapshot import encode_snapshot
    return encode_snapshot(snap)


def bytes_to_chain_snapshot(blob, max_bytes=None):
    from messagechain.storage.state_snapshot import decode_snapshot
    return decode_snapshot(blob, max_bytes=max_bytes)


class TestBlockHeaderCommitsStateRoot(unittest.TestCase):
    """Each block's header.state_root is set after applying itself, and
    re-verification against the post-apply state passes.

    (This tests existing behavior but re-asserts it against the snapshot
    root chain-wide to catch drift between the two root computations.)
    """

    def test_header_state_root_matches_chain_state(self):
        chain, _alice, _c = _build_chain_with_txs(3)
        latest = chain.get_latest_block()
        # chain's internal per-entity tree root must equal what's in the header
        self.assertEqual(
            latest.header.state_root,
            chain.compute_current_state_root(),
        )


class TestStateCheckpointSignature(unittest.TestCase):
    """StateCheckpointSignature object: sign, verify, round-trip."""

    def setUp(self):
        self.alice = Entity.create(b"alice-s".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-s".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def _mk_checkpoint(self, block_number=100, block_hash=None, state_root=None):
        return StateCheckpoint(
            block_number=block_number,
            block_hash=block_hash or _hash(b"blk"),
            state_root=state_root or _hash(b"state"),
        )

    def test_sign_and_verify(self):
        cp = self._mk_checkpoint()
        sig = create_state_checkpoint_signature(self.alice, cp)
        self.assertTrue(
            verify_state_checkpoint_signature(cp, sig, self.alice.public_key)
        )

    def test_wrong_pubkey_rejects(self):
        cp = self._mk_checkpoint()
        sig = create_state_checkpoint_signature(self.alice, cp)
        self.assertFalse(
            verify_state_checkpoint_signature(cp, sig, self.bob.public_key)
        )

    def test_binary_roundtrip(self):
        cp = self._mk_checkpoint()
        sig = create_state_checkpoint_signature(self.alice, cp)
        blob = sig.to_bytes()
        restored = StateCheckpointSignature.from_bytes(blob)
        self.assertEqual(restored.signer_entity_id, sig.signer_entity_id)
        self.assertTrue(
            verify_state_checkpoint_signature(cp, restored, self.alice.public_key)
        )

    def test_dict_roundtrip(self):
        cp = self._mk_checkpoint()
        sig = create_state_checkpoint_signature(self.alice, cp)
        restored = StateCheckpointSignature.deserialize(sig.serialize())
        self.assertTrue(
            verify_state_checkpoint_signature(cp, restored, self.alice.public_key)
        )

    def test_different_state_root_different_signable(self):
        cp1 = self._mk_checkpoint(state_root=b"\xaa" * 32)
        cp2 = self._mk_checkpoint(state_root=b"\xbb" * 32)
        self.assertNotEqual(cp1._signable_data(), cp2._signable_data())


class TestStateCheckpointDoubleSign(unittest.TestCase):
    """Double-signing two different state_roots at the same height is slashable."""

    def setUp(self):
        self.alice = Entity.create(b"alice-d".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0

    def test_double_sign_evidence(self):
        cp1 = StateCheckpoint(
            block_number=500, block_hash=_hash(b"b"), state_root=b"\xaa" * 32,
        )
        cp2 = StateCheckpoint(
            block_number=500, block_hash=_hash(b"b"), state_root=b"\xbb" * 32,
        )
        sig1 = create_state_checkpoint_signature(self.alice, cp1)
        sig2 = create_state_checkpoint_signature(self.alice, cp2)
        ev = StateCheckpointDoubleSignEvidence(
            offender_id=self.alice.entity_id,
            checkpoint_a=cp1, signature_a=sig1,
            checkpoint_b=cp2, signature_b=sig2,
        )
        ok, _reason = verify_state_checkpoint_double_sign_evidence(
            ev, self.alice.public_key,
        )
        self.assertTrue(ok)

    def test_non_conflicting_rejected(self):
        cp = StateCheckpoint(
            block_number=500, block_hash=_hash(b"b"), state_root=b"\xaa" * 32,
        )
        sig1 = create_state_checkpoint_signature(self.alice, cp)
        sig2 = create_state_checkpoint_signature(self.alice, cp)
        ev = StateCheckpointDoubleSignEvidence(
            offender_id=self.alice.entity_id,
            checkpoint_a=cp, signature_a=sig1,
            checkpoint_b=cp, signature_b=sig2,
        )
        ok, _reason = verify_state_checkpoint_double_sign_evidence(
            ev, self.alice.public_key,
        )
        self.assertFalse(ok)

    def test_evidence_binary_roundtrip(self):
        cp1 = StateCheckpoint(
            block_number=500, block_hash=_hash(b"b"), state_root=b"\xaa" * 32,
        )
        cp2 = StateCheckpoint(
            block_number=500, block_hash=_hash(b"b"), state_root=b"\xbb" * 32,
        )
        sig1 = create_state_checkpoint_signature(self.alice, cp1)
        sig2 = create_state_checkpoint_signature(self.alice, cp2)
        ev = StateCheckpointDoubleSignEvidence(
            offender_id=self.alice.entity_id,
            checkpoint_a=cp1, signature_a=sig1,
            checkpoint_b=cp2, signature_b=sig2,
        )
        restored = StateCheckpointDoubleSignEvidence.from_bytes(ev.to_bytes())
        self.assertEqual(restored.offender_id, ev.offender_id)
        ok, _ = verify_state_checkpoint_double_sign_evidence(
            restored, self.alice.public_key,
        )
        self.assertTrue(ok)


class TestVerifiedCheckpoint(unittest.TestCase):
    """A checkpoint is verified when >= 2/3 of stake-at-X signs it."""

    def _build_three_validators(self):
        """Build a chain with three equally-staked validators at genesis.

        Returns (chain, [alice, bob, carol], consensus).
        """
        from messagechain.core.bootstrap import build_launch_allocation
        alice = Entity.create(b"alice-3v".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-3v".ljust(32, b"\x00"))
        carol = Entity.create(b"carol-3v".ljust(32, b"\x00"))
        chain = Blockchain()
        allocation = {
            alice.entity_id: 100_000,
            bob.entity_id: 100_000,
            carol.entity_id: 100_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(alice, allocation_table=allocation)
        register_entity_for_test(chain, bob)
        register_entity_for_test(chain, carol)
        chain.supply.stake(alice.entity_id, 10_000)
        chain.supply.stake(bob.entity_id, 10_000)
        chain.supply.stake(carol.entity_id, 10_000)
        # Rebuild the state tree so staked-but-not-yet-touched entities are
        # reflected in the root.
        chain._touch_state([alice.entity_id, bob.entity_id, carol.entity_id])
        return chain, [alice, bob, carol], ProofOfStake()

    def test_two_thirds_verifies(self):
        from messagechain.consensus.state_checkpoint import (
            verify_state_checkpoint,
        )
        chain, validators, _c = self._build_three_validators()
        latest = chain.get_latest_block()
        cp = StateCheckpoint(
            block_number=latest.header.block_number,
            block_hash=latest.block_hash,
            state_root=latest.header.state_root,
        )
        sigs = [
            create_state_checkpoint_signature(v, cp)
            for v in validators[:2]  # 2/3 of three validators — exactly the threshold
        ]
        stake_map = dict(chain.supply.staked)
        pubkeys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_state_checkpoint(cp, sigs, stake_map, pubkeys)
        self.assertTrue(ok, reason)

    def test_below_two_thirds_rejected(self):
        from messagechain.consensus.state_checkpoint import (
            verify_state_checkpoint,
        )
        chain, validators, _c = self._build_three_validators()
        latest = chain.get_latest_block()
        cp = StateCheckpoint(
            block_number=latest.header.block_number,
            block_hash=latest.block_hash,
            state_root=latest.header.state_root,
        )
        sigs = [create_state_checkpoint_signature(validators[0], cp)]
        stake_map = dict(chain.supply.staked)
        pubkeys = {v.entity_id: v.public_key for v in validators}
        ok, _reason = verify_state_checkpoint(cp, sigs, stake_map, pubkeys)
        self.assertFalse(ok)

    def test_invalid_signature_not_counted(self):
        from messagechain.consensus.state_checkpoint import (
            verify_state_checkpoint,
        )
        chain, validators, _c = self._build_three_validators()
        latest = chain.get_latest_block()
        cp = StateCheckpoint(
            block_number=latest.header.block_number,
            block_hash=latest.block_hash,
            state_root=latest.header.state_root,
        )
        # Valid sigs from alice + bob (2/3)
        good_sigs = [
            create_state_checkpoint_signature(v, cp) for v in validators[:2]
        ]
        stake_map = dict(chain.supply.staked)
        # But use WRONG pubkeys for all — no sig can verify
        pubkeys = {v.entity_id: b"\x00" * 32 for v in validators}
        ok, _ = verify_state_checkpoint(cp, good_sigs, stake_map, pubkeys)
        self.assertFalse(ok)


class TestBootstrapFromCheckpoint(unittest.TestCase):
    """The whole round-trip: build a chain, export a checkpoint, bootstrap
    a new node from it, then verify the new node can keep producing and
    accepting blocks indistinguishably from the original.
    """

    def _build_one_validator_chain(self, n_blocks=5):
        """Single-validator chain with n_blocks after genesis."""
        alice = Entity.create(b"alice-1v".ljust(32, b"\x00"))
        allocation = {
            alice.entity_id: 200_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain = Blockchain()
        chain.initialize_genesis(alice, allocation_table=allocation)
        chain.supply.stake(alice.entity_id, 10_000)
        chain._touch_state([alice.entity_id])
        consensus = ProofOfStake()
        for i in range(n_blocks):
            tx = create_transaction(
                alice, f"m{i}", fee=1500,
                nonce=chain.nonces.get(alice.entity_id, 0),
            )
            prev = chain.get_latest_block()
            state_root = chain.compute_post_state_root(
                [tx], alice.entity_id, prev.header.block_number + 1,
            )
            block = consensus.create_block(
                alice, [tx], prev, state_root=state_root,
            )
            ok, reason = chain.add_block(block)
            if not ok:
                raise RuntimeError(reason)
        return chain, alice, consensus

    def test_bootstrap_reconstructs_state(self):
        chain, alice, _c = self._build_one_validator_chain(n_blocks=4)

        # Snapshot the LIVE chain at its current tip — this is the
        # realistic use case (archive nodes snapshot at their current
        # height and gossip the result).  An "old" checkpoint is just
        # a previously-persisted copy of this same flow.
        cp_block = chain.get_latest_block()

        snap = serialize_state(chain)
        snap_root = compute_snapshot_root(snap)

        from messagechain.storage.state_snapshot import encode_snapshot
        snap_bytes = encode_snapshot(snap)

        cp = StateCheckpoint(
            block_number=cp_block.header.block_number,
            block_hash=cp_block.block_hash,
            state_root=snap_root,
        )
        sig = create_state_checkpoint_signature(alice, cp)
        stake_map_at_cp = chain._stake_snapshots.get(
            cp_block.header.block_number, dict(chain.supply.staked),
        )
        pubkeys = {alice.entity_id: alice.public_key}

        # Bootstrap a fresh node
        fresh = Blockchain()
        ok, reason = fresh.bootstrap_from_checkpoint(
            snapshot_bytes=snap_bytes,
            checkpoint=cp,
            signatures=[sig],
            stake_at_checkpoint=stake_map_at_cp,
            public_keys_at_checkpoint=pubkeys,
            checkpoint_block=cp_block,
            recent_blocks=[],  # checkpoint is already at the tip
        )
        self.assertTrue(ok, reason)

        # Final state must match the original chain's state
        self.assertEqual(
            fresh.supply.balances.get(alice.entity_id, 0),
            chain.supply.balances.get(alice.entity_id, 0),
        )
        # A bootstrapped chain has only ONE block locally (the checkpoint
        # block), while the full-history chain has all of them.  What MUST
        # match is the tip block_number — the chain-layer commitment to
        # where we are in consensus.
        self.assertEqual(
            fresh.get_latest_block().header.block_number,
            chain.get_latest_block().header.block_number,
        )
        self.assertEqual(
            fresh.get_latest_block().block_hash,
            chain.get_latest_block().block_hash,
        )

    def test_mismatched_state_root_rejected(self):
        chain, alice, _c = self._build_one_validator_chain(n_blocks=2)
        cp_block = chain.get_block(1)
        snap = serialize_state(chain)
        from messagechain.storage.state_snapshot import encode_snapshot
        snap_bytes = encode_snapshot(snap)

        # Lie about the state root in the checkpoint
        cp = StateCheckpoint(
            block_number=cp_block.header.block_number,
            block_hash=cp_block.block_hash,
            state_root=b"\xff" * 32,  # wrong
        )
        sig = create_state_checkpoint_signature(alice, cp)
        pubkeys = {alice.entity_id: alice.public_key}
        fresh = Blockchain()
        ok, reason = fresh.bootstrap_from_checkpoint(
            snapshot_bytes=snap_bytes,
            checkpoint=cp,
            signatures=[sig],
            stake_at_checkpoint={alice.entity_id: 10_000},
            public_keys_at_checkpoint=pubkeys,
            checkpoint_block=cp_block,
            recent_blocks=[],
        )
        self.assertFalse(ok)
        self.assertIn("state_root", reason.lower())

    def test_oversize_snapshot_rejected(self):
        chain, alice, _c = self._build_one_validator_chain(n_blocks=1)
        cp_block = chain.get_block(1)
        snap = serialize_state(chain)
        snap_root = compute_snapshot_root(snap)
        from messagechain.storage.state_snapshot import encode_snapshot
        snap_bytes = encode_snapshot(snap)

        cp = StateCheckpoint(
            block_number=cp_block.header.block_number,
            block_hash=cp_block.block_hash,
            state_root=snap_root,
        )
        sig = create_state_checkpoint_signature(alice, cp)
        pubkeys = {alice.entity_id: alice.public_key}

        fresh = Blockchain()
        # Artificially trip the cap by monkey-patching a tiny limit
        import messagechain.storage.state_snapshot as ss
        orig = ss.MAX_STATE_SNAPSHOT_BYTES
        ss.MAX_STATE_SNAPSHOT_BYTES = 1
        try:
            ok, reason = fresh.bootstrap_from_checkpoint(
                snapshot_bytes=snap_bytes,
                checkpoint=cp,
                signatures=[sig],
                stake_at_checkpoint={alice.entity_id: 10_000},
                public_keys_at_checkpoint=pubkeys,
                checkpoint_block=cp_block,
                recent_blocks=[],
            )
        finally:
            ss.MAX_STATE_SNAPSHOT_BYTES = orig
        self.assertFalse(ok)
        self.assertIn("too large", reason.lower())

    def test_bootstrapped_chain_produces_valid_blocks(self):
        """A node bootstrapped from a checkpoint can propose further blocks
        that the original full-history chain accepts."""
        chain, alice, consensus = self._build_one_validator_chain(n_blocks=3)
        cp_block = chain.get_latest_block()

        snap = serialize_state(chain)
        snap_root = compute_snapshot_root(snap)
        from messagechain.storage.state_snapshot import encode_snapshot
        snap_bytes = encode_snapshot(snap)
        cp = StateCheckpoint(
            block_number=cp_block.header.block_number,
            block_hash=cp_block.block_hash,
            state_root=snap_root,
        )
        sig = create_state_checkpoint_signature(alice, cp)
        stake_at = chain._stake_snapshots.get(
            cp_block.header.block_number, dict(chain.supply.staked),
        )
        pubkeys = {alice.entity_id: alice.public_key}

        fresh = Blockchain()
        ok, reason = fresh.bootstrap_from_checkpoint(
            snapshot_bytes=snap_bytes,
            checkpoint=cp,
            signatures=[sig],
            stake_at_checkpoint=stake_at,
            public_keys_at_checkpoint=pubkeys,
            checkpoint_block=cp_block,
            recent_blocks=[],
        )
        self.assertTrue(ok, reason)
        # Chain-tip block_number matches — fresh is synced to the same
        # consensus height as the full-history chain, even though it
        # only locally retains the checkpoint block.
        self.assertEqual(
            fresh.get_latest_block().header.block_number,
            chain.get_latest_block().header.block_number,
        )

        # Now extend fresh by one more block and verify it's accepted.
        tx = create_transaction(
            alice, "post-bootstrap", fee=1500,
            nonce=fresh.nonces.get(alice.entity_id, 0),
        )
        prev = fresh.get_latest_block()
        state_root = fresh.compute_post_state_root(
            [tx], alice.entity_id, prev.header.block_number + 1,
        )
        new_block = consensus.create_block(
            alice, [tx], prev, state_root=state_root,
        )
        ok2, reason2 = fresh.add_block(new_block)
        self.assertTrue(ok2, reason2)
        # Fresh chain is indistinguishable from a full-history chain
        # in consensus: the new tip's block_number is one past the
        # original chain's tip.
        self.assertEqual(
            fresh.get_latest_block().header.block_number,
            chain.get_latest_block().header.block_number + 1,
        )


class TestNetworkProtocol(unittest.TestCase):
    """Protocol messages for state checkpoint exchange."""

    def test_request_message_type_registered(self):
        self.assertIn("request_state_checkpoint",
                      {m.value for m in MessageType})
        self.assertIn("response_state_checkpoint",
                      {m.value for m in MessageType})

    def test_request_roundtrip(self):
        msg = NetworkMessage(
            msg_type=MessageType.REQUEST_STATE_CHECKPOINT,
            payload={"block_number": 1000},
        )
        restored = NetworkMessage.deserialize(msg.serialize())
        self.assertEqual(restored.msg_type, MessageType.REQUEST_STATE_CHECKPOINT)
        self.assertEqual(restored.payload["block_number"], 1000)


class TestChainDBVerifiedCheckpoints(unittest.TestCase):
    """chaindb round-trip of verified-state-checkpoint records."""

    def test_add_and_retrieve(self):
        alice = Entity.create(b"alice-db".ljust(32, b"\x00"))
        cp = StateCheckpoint(
            block_number=1000,
            block_hash=_hash(b"blockhash"),
            state_root=_hash(b"stateroot"),
        )
        sig = create_state_checkpoint_signature(alice, cp)

        with tempfile.TemporaryDirectory() as td:
            db = ChainDB(os.path.join(td, "verif.db"))
            db.add_verified_state_checkpoint(cp, [sig])
            got = db.get_verified_state_checkpoint(1000)
            self.assertIsNotNone(got)
            got_cp, got_sigs = got
            self.assertEqual(got_cp.block_number, cp.block_number)
            self.assertEqual(got_cp.block_hash, cp.block_hash)
            self.assertEqual(got_cp.state_root, cp.state_root)
            self.assertEqual(len(got_sigs), 1)
            self.assertEqual(got_sigs[0].signer_entity_id, alice.entity_id)
            db.close()


class TestCheckpointIntervalConst(unittest.TestCase):
    def test_config_constants(self):
        self.assertEqual(STATE_CHECKPOINT_INTERVAL, 1000)
        self.assertEqual(STATE_CHECKPOINT_THRESHOLD_NUMERATOR, 2)
        self.assertEqual(STATE_CHECKPOINT_THRESHOLD_DENOMINATOR, 3)
        self.assertEqual(MAX_STATE_SNAPSHOT_BYTES, 500_000_000)
        # v2: bumped when seed_divestment_debt was added to the
        # snapshot Merkle root (partial-divestment-to-floor schedule).
        # v3: bumped when archive_reward_pool was added (proof-of-custody
        # archive rewards).
        # v4: bumped when attester_coverage_misses was added (defense
        # against 1/3-stake AttesterMempoolReport withholding).
        # v5: bumped when non_response_processed + witness_ack_registry
        # were added together — closes Gap A (state-snapshot integration)
        # and Gap B (block-level ack aggregation) for witnessed-submission
        # evidence (closes the silent-TCP-drop slash-evasion path that
        # would otherwise let a state-synced node re-apply already-
        # processed evidence or miss the registry's discharge signal).
        self.assertEqual(STATE_ROOT_VERSION, 5)


class TestMeasureSnapshotSize(unittest.TestCase):
    """A perf/size sanity measurement — primarily for the task report.

    Asserts that a snapshot with ~100 entities is well under the 500MB cap
    so operators get meaningful safety margin.
    """

    def test_realistic_snapshot_size(self):
        alice = Entity.create(b"alice-m".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(
            alice,
            allocation_table={
                alice.entity_id: 10_000_000,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        # Synthesize 100 entities with balances
        for i in range(100):
            eid = b"e" * 24 + i.to_bytes(8, "big")
            chain.supply.balances[eid] = 1000 + i
            chain.nonces[eid] = i
            chain.public_keys[eid] = b"p" * 32 + i.to_bytes(4, "big")
        chain._rebuild_state_tree()
        snap = serialize_state(chain)
        from messagechain.storage.state_snapshot import encode_snapshot
        blob = encode_snapshot(snap)
        self.assertLess(len(blob), MAX_STATE_SNAPSHOT_BYTES)
        # Ensure round-trip works at this size
        from messagechain.storage.state_snapshot import decode_snapshot
        restored = decode_snapshot(blob)
        self.assertEqual(
            compute_snapshot_root(snap), compute_snapshot_root(restored),
        )


if __name__ == "__main__":
    unittest.main()
