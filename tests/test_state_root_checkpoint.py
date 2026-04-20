"""Tests for periodic state-root checkpoints committed into block headers.

The BlockHeader carries a `state_root_checkpoint` field.  On non-checkpoint
blocks it is zeroed.  On checkpoint blocks (block_number % CHECKPOINT_INTERVAL
== 0, block_number > 0) it commits to the full *snapshot* root computed by
storage.state_snapshot.compute_state_root over the post-application state.

This is a sync UX affordance, NOT a pruning mechanism — archive nodes still
retain every block.  The commitment makes state snapshots consensus-bound:
a new node that downloads a snapshot can verify the root against a finalized
checkpoint block's header rather than trusting an out-of-band signing
ceremony.
"""

import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import BlockHeader, Block
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.config import (
    CHECKPOINT_INTERVAL, CHECKPOINT_VERSION, is_state_root_checkpoint_block,
)
from messagechain.storage.state_snapshot import (
    serialize_state, compute_state_root as compute_snapshot_root,
)
from tests import register_entity_for_test


class TestCheckpointConstants(unittest.TestCase):
    """Sanity checks on the new config surface."""

    def test_checkpoint_interval_is_positive(self):
        self.assertIsInstance(CHECKPOINT_INTERVAL, int)
        self.assertGreater(CHECKPOINT_INTERVAL, 0)

    def test_checkpoint_version_is_current(self):
        """CHECKPOINT_VERSION must be set — 0 would trap uninitialized."""
        self.assertIsInstance(CHECKPOINT_VERSION, int)
        self.assertEqual(CHECKPOINT_VERSION, 1)

    def test_genesis_is_not_a_checkpoint_block(self):
        """Block 0 is never a checkpoint block — the multiple-of-interval
        rule explicitly excludes height 0 so genesis has a clean zero in
        the field, not the snapshot root of an empty chain."""
        self.assertFalse(is_state_root_checkpoint_block(0))

    def test_non_multiple_heights_are_not_checkpoints(self):
        for height in (1, 2, CHECKPOINT_INTERVAL - 1, CHECKPOINT_INTERVAL + 1):
            self.assertFalse(is_state_root_checkpoint_block(height))

    def test_multiples_of_interval_are_checkpoints(self):
        for height in (
            CHECKPOINT_INTERVAL,
            2 * CHECKPOINT_INTERVAL,
            10 * CHECKPOINT_INTERVAL,
        ):
            self.assertTrue(is_state_root_checkpoint_block(height))


class TestCheckpointHeaderField(unittest.TestCase):
    """BlockHeader carries the new field and it participates in block identity."""

    def test_header_has_zero_default(self):
        """Header built with no explicit checkpoint has 32 zero bytes."""
        h = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
        )
        self.assertEqual(h.state_root_checkpoint, b"\x00" * 32)

    def test_checkpoint_field_affects_signable_data(self):
        """Two headers differing only in state_root_checkpoint must have
        different signable_data — otherwise the field is not tamper-evident.
        """
        base_kwargs = dict(
            version=1, block_number=CHECKPOINT_INTERVAL,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
        )
        h1 = BlockHeader(**base_kwargs, state_root_checkpoint=b"\xaa" * 32)
        h2 = BlockHeader(**base_kwargs, state_root_checkpoint=b"\xbb" * 32)
        self.assertNotEqual(h1.signable_data(), h2.signable_data())

    def test_checkpoint_field_affects_block_hash(self):
        """Changing the checkpoint field changes the block hash — the field
        must bind to block identity, not sit as free-floating metadata."""
        base_kwargs = dict(
            version=1, block_number=CHECKPOINT_INTERVAL,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
        )
        h1 = BlockHeader(**base_kwargs, state_root_checkpoint=b"\xaa" * 32)
        h2 = BlockHeader(**base_kwargs, state_root_checkpoint=b"\xbb" * 32)
        b1 = Block(header=h1, transactions=[])
        b2 = Block(header=h2, transactions=[])
        self.assertNotEqual(b1.block_hash, b2.block_hash)

    def test_json_serialization_roundtrip(self):
        """serialize/deserialize preserves the checkpoint field."""
        h = BlockHeader(
            version=1, block_number=CHECKPOINT_INTERVAL,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
            state_root_checkpoint=b"\xcd" * 32,
        )
        data = h.serialize()
        restored = BlockHeader.deserialize(data)
        self.assertEqual(restored.state_root_checkpoint, b"\xcd" * 32)

    def test_binary_serialization_roundtrip(self):
        """to_bytes/from_bytes preserves the checkpoint field."""
        h = BlockHeader(
            version=1, block_number=CHECKPOINT_INTERVAL,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
            state_root_checkpoint=b"\xef" * 32,
        )
        blob = h.to_bytes()
        restored = BlockHeader.from_bytes(blob)
        self.assertEqual(restored.state_root_checkpoint, b"\xef" * 32)

    def test_non_checkpoint_header_roundtrips_with_zero(self):
        """A non-checkpoint header (the common case) survives both encode
        paths with its zero-valued checkpoint field intact."""
        h = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x01" * 32, timestamp=1000.0,
            proposer_id=b"\x02" * 32,
        )
        # binary
        restored_bin = BlockHeader.from_bytes(h.to_bytes())
        self.assertEqual(restored_bin.state_root_checkpoint, b"\x00" * 32)
        # json
        restored_json = BlockHeader.deserialize(h.serialize())
        self.assertEqual(restored_json.state_root_checkpoint, b"\x00" * 32)


class TestCheckpointBlockProduction(unittest.TestCase):
    """End-to-end: the chain's propose_block fills the field correctly on
    checkpoint heights and zeroes it everywhere else, and validation
    rejects mismatches."""

    def setUp(self):
        # Shrink the interval for test speed.  The field's behavior does
        # not depend on the specific interval — it depends on the
        # multiple-of-interval rule.  We patch at module level on both
        # config and block so propose_block / validate_block agree.
        import messagechain.config as _cfg
        self._orig_interval = _cfg.CHECKPOINT_INTERVAL
        _cfg.CHECKPOINT_INTERVAL = 2  # block 2, 4, 6, ... are checkpoints

        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10_000_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000_000
        self.consensus = ProofOfStake()

    def tearDown(self):
        import messagechain.config as _cfg
        _cfg.CHECKPOINT_INTERVAL = self._orig_interval

    def _propose_one(self, sender: Entity, message: str, nonce: int) -> Block:
        tx = create_transaction(sender, message, fee=1500, nonce=nonce)
        return self.chain.propose_block(self.consensus, sender, [tx])

    def test_non_checkpoint_block_has_zero_field(self):
        """Block 1 is not a checkpoint (with interval=2, checkpoints are
        block 2, 4, 6...).  Its state_root_checkpoint must be zero."""
        block = self._propose_one(self.alice, "b1", nonce=0)
        self.assertEqual(block.header.block_number, 1)
        self.assertEqual(block.header.state_root_checkpoint, b"\x00" * 32)
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_checkpoint_block_has_correct_snapshot_root(self):
        """Block 2 (with interval=2) must commit the snapshot root of the
        chain state AS OF the parent block — the state that serves as
        input to this block.  A bootstrapping node that trusts a
        finalized block at checkpoint height H reads this commitment,
        downloads a matching snapshot, and replays blocks H, H+1, ...
        forward from that state."""
        # Produce block 1 (non-checkpoint) first.
        b1 = self._propose_one(self.alice, "b1", nonce=0)
        ok, reason = self.chain.add_block(b1)
        self.assertTrue(ok, reason)

        # Snapshot root BEFORE proposing block 2 — this is what block 2
        # must commit, since its parent is block 1 and at proposal time
        # the live state is post-block-1.
        pre_block2_snapshot_root = compute_snapshot_root(
            serialize_state(self.chain),
        )

        # Block 2 is a checkpoint block (interval=2).
        b2 = self._propose_one(self.alice, "b2", nonce=1)
        self.assertEqual(b2.header.block_number, 2)
        self.assertNotEqual(
            b2.header.state_root_checkpoint, b"\x00" * 32,
            "Checkpoint block must commit a non-zero snapshot root",
        )
        self.assertEqual(
            b2.header.state_root_checkpoint, pre_block2_snapshot_root,
            "Checkpoint commitment must match the parent-state snapshot root",
        )
        ok, reason = self.chain.add_block(b2)
        self.assertTrue(ok, reason)

    def test_wrong_checkpoint_commitment_rejected(self):
        """A block at a checkpoint height with a fabricated checkpoint
        value must be rejected by validation."""
        b1 = self._propose_one(self.alice, "b1", nonce=0)
        ok, reason = self.chain.add_block(b1)
        self.assertTrue(ok, reason)

        # Produce a real block 2, then tamper with its checkpoint field and
        # re-sign so everything else is consistent.
        b2 = self._propose_one(self.alice, "b2", nonce=1)
        # Sanity: unmodified block must pass.
        self.assertEqual(b2.header.block_number, 2)

        # Tamper.  The signature will no longer cover the mutated header,
        # but validate_block's checkpoint check fires independently.  We
        # construct a fresh signed header to isolate the checkpoint check
        # from signature rejection.
        import hashlib
        from messagechain.config import HASH_ALGO
        tampered_root = b"\xde" * 32
        b2.header.state_root_checkpoint = tampered_root
        # Re-sign the header so we don't trip the signature check first.
        header_hash = hashlib.new(HASH_ALGO, b2.header.signable_data()).digest()
        b2.header.proposer_signature = self.alice.keypair.sign(header_hash)
        # Re-derive randao_mix + block_hash to be fully self-consistent.
        from messagechain.consensus.randao import derive_randao_mix
        prev = self.chain.get_block(1)
        b2.header.randao_mix = derive_randao_mix(
            prev.header.randao_mix, b2.header.proposer_signature,
        )
        b2.block_hash = b2._compute_hash()

        ok, reason = self.chain.add_block(b2)
        self.assertFalse(
            ok, "Block with wrong state_root_checkpoint must be rejected",
        )
        self.assertIn("checkpoint", reason.lower())

    def test_non_checkpoint_block_with_nonzero_field_rejected(self):
        """A non-checkpoint block must carry a zero checkpoint field.
        Allowing garbage in the field at non-checkpoint heights would
        let a proposer silently corrupt the consensus commitment for a
        future bootstrap consumer."""
        b1 = self._propose_one(self.alice, "b1-bad", nonce=0)
        # Force a non-zero field on a non-checkpoint block.
        b1.header.state_root_checkpoint = b"\x01" * 32
        import hashlib
        from messagechain.config import HASH_ALGO
        header_hash = hashlib.new(HASH_ALGO, b1.header.signable_data()).digest()
        b1.header.proposer_signature = self.alice.keypair.sign(header_hash)
        from messagechain.consensus.randao import derive_randao_mix
        prev = self.chain.get_block(0)
        b1.header.randao_mix = derive_randao_mix(
            prev.header.randao_mix, b1.header.proposer_signature,
        )
        b1.block_hash = b1._compute_hash()

        ok, reason = self.chain.add_block(b1)
        self.assertFalse(
            ok, "Non-checkpoint block must not carry a non-zero checkpoint",
        )
        self.assertIn("checkpoint", reason.lower())


if __name__ == "__main__":
    unittest.main()
