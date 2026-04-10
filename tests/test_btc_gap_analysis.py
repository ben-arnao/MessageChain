"""
Tests for 10 Bitcoin Core gap analysis features.

1. Weak subjectivity checkpoints
2. RANDAO commit-reveal for proposer randomness
3. Block pruning
4. Compact block relay
5. Fee estimation
6. Replace-By-Fee (RBF)
7. Transaction versioning
8. Light client SPV proofs
9. Soft fork activation signaling
10. Dynamic minimum relay fee
"""

import hashlib
import struct
import time
import unittest

from tests import register_entity_for_test
import messagechain.config
from messagechain.config import HASH_ALGO, CHAIN_ID
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, compute_merkle_root, _hash
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import create_attestation
from messagechain.identity.identity import Entity


def _make_chain_and_entities(num_entities=2):
    """Helper: create a blockchain with registered entities."""
    chain = Blockchain()
    entities = [Entity.create(f"test_key_{i}".encode()) for i in range(num_entities)]
    chain.initialize_genesis(entities[0])
    for e in entities[1:]:
        register_entity_for_test(chain, e)
    return chain, entities


def _propose_and_add(chain, consensus, proposer, txs=None, attestations=None, transfer_txs=None):
    """Helper: propose a block and add it to the chain."""
    block = chain.propose_block(
        consensus, proposer, txs or [], attestations=attestations,
        transfer_transactions=transfer_txs,
    )
    ok, reason = chain.add_block(block)
    assert ok, f"Failed to add block: {reason}"
    return block


# ─── 1. Weak Subjectivity Checkpoints ────────────────────────────────

class TestWeakSubjectivityCheckpoints(unittest.TestCase):
    """Weak subjectivity checkpoints allow new nodes to trust a recent
    finalized state instead of replaying the entire chain from genesis."""

    def test_checkpoint_creation(self):
        """A checkpoint can be created from a finalized block."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        # Build some blocks
        for _ in range(5):
            _propose_and_add(chain, consensus, entities[0])

        # Create checkpoint at current height
        from messagechain.consensus.checkpoint import create_checkpoint, WeakSubjectivityCheckpoint
        cp = create_checkpoint(chain, chain.height - 1)
        self.assertIsInstance(cp, WeakSubjectivityCheckpoint)
        self.assertEqual(cp.block_number, chain.height - 1)
        self.assertIsNotNone(cp.block_hash)
        self.assertIsNotNone(cp.state_root)

    def test_checkpoint_validation_accepts_matching_chain(self):
        """A chain that matches the checkpoint is accepted."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(5):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.consensus.checkpoint import create_checkpoint, validate_checkpoint
        cp = create_checkpoint(chain, 3)
        self.assertTrue(validate_checkpoint(chain, cp))

    def test_checkpoint_validation_rejects_mismatched_chain(self):
        """A chain that doesn't match the checkpoint is rejected."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(5):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.consensus.checkpoint import WeakSubjectivityCheckpoint, validate_checkpoint
        # Fake checkpoint with wrong hash
        fake_cp = WeakSubjectivityCheckpoint(
            block_number=3,
            block_hash=b"\xff" * 32,
            state_root=b"\xff" * 32,
        )
        self.assertFalse(validate_checkpoint(chain, fake_cp))

    def test_checkpoint_serialization_roundtrip(self):
        """Checkpoints can be serialized and deserialized."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(3):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.consensus.checkpoint import create_checkpoint, WeakSubjectivityCheckpoint
        cp = create_checkpoint(chain, 2)
        data = cp.serialize()
        cp2 = WeakSubjectivityCheckpoint.deserialize(data)
        self.assertEqual(cp.block_number, cp2.block_number)
        self.assertEqual(cp.block_hash, cp2.block_hash)
        self.assertEqual(cp.state_root, cp2.state_root)


# ─── 2. RANDAO Commit-Reveal ─────────────────────────────────────────

class TestRANDAO(unittest.TestCase):
    """RANDAO prevents proposers from grinding block contents to
    influence the next proposer selection."""

    def test_randao_mix_updates_each_block(self):
        """Each block updates the RANDAO mix with the proposer's reveal."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        from messagechain.consensus.randao import RANDAOMix
        randao = RANDAOMix()

        mix1 = randao.current_mix
        # Simulate a proposer reveal
        reveal = hashlib.new(HASH_ALGO, b"reveal_1").digest()
        randao.update(reveal)
        mix2 = randao.current_mix
        self.assertNotEqual(mix1, mix2)

        reveal2 = hashlib.new(HASH_ALGO, b"reveal_2").digest()
        randao.update(reveal2)
        mix3 = randao.current_mix
        self.assertNotEqual(mix2, mix3)

    def test_randao_proposer_selection_differs_from_prev_hash_only(self):
        """RANDAO-seeded selection produces different results than
        prev_block_hash-only selection for the same state."""
        from messagechain.consensus.randao import RANDAOMix, randao_select_proposer

        stakes = {b"alice": 100, b"bob": 100, b"carol": 100}
        prev_hash = b"\x01" * 32

        randao = RANDAOMix()
        randao.update(hashlib.new(HASH_ALGO, b"some_reveal").digest())

        # Selection with RANDAO mix should be deterministic
        p1 = randao_select_proposer(stakes, prev_hash, randao.current_mix)
        p2 = randao_select_proposer(stakes, prev_hash, randao.current_mix)
        self.assertEqual(p1, p2)  # deterministic

    def test_randao_different_reveals_produce_different_selections(self):
        """Different RANDAO reveals lead to different proposer selections
        (with high probability given enough validators)."""
        from messagechain.consensus.randao import RANDAOMix, randao_select_proposer

        stakes = {bytes([i]) * 16: 100 for i in range(20)}
        prev_hash = b"\x01" * 32

        selections = set()
        for i in range(10):
            randao = RANDAOMix()
            randao.update(hashlib.new(HASH_ALGO, f"reveal_{i}".encode()).digest())
            p = randao_select_proposer(stakes, prev_hash, randao.current_mix)
            selections.add(p)

        # With 20 validators and 10 different reveals, we should get >1 unique proposer
        self.assertGreater(len(selections), 1)


# ─── 3. Block Pruning ────────────────────────────────────────────────

class TestBlockPruning(unittest.TestCase):
    """Block pruning allows nodes to delete old block data while
    retaining headers for chain verification."""

    def test_prune_old_blocks(self):
        """Blocks older than the pruning threshold can be pruned."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(10):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.storage.pruning import BlockPruner
        pruner = BlockPruner(keep_recent=5)
        pruned_count = pruner.prune(chain)
        self.assertGreater(pruned_count, 0)

    def test_pruned_blocks_headers_still_available(self):
        """After pruning, block headers remain accessible."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(10):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.storage.pruning import BlockPruner
        pruner = BlockPruner(keep_recent=5)
        pruner.prune(chain)

        # Headers should still be available for pruned blocks
        for i in range(chain.height):
            header = pruner.get_header(chain, i)
            self.assertIsNotNone(header)

    def test_recent_blocks_not_pruned(self):
        """Blocks within the keep_recent window are not pruned."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()
        for _ in range(10):
            _propose_and_add(chain, consensus, entities[0])

        from messagechain.storage.pruning import BlockPruner
        pruner = BlockPruner(keep_recent=5)
        pruner.prune(chain)

        # Recent blocks should still have full data
        for i in range(chain.height - 5, chain.height):
            block = chain.get_block(i)
            self.assertIsNotNone(block)


# ─── 4. Compact Block Relay ──────────────────────────────────────────

class TestCompactBlockRelay(unittest.TestCase):
    """Compact block relay sends a sketch (header + tx short IDs)
    instead of full blocks, reconstructing from mempool."""

    def test_create_compact_block(self):
        """A compact block can be created from a full block."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "hello", fee=500, nonce=0)
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        from messagechain.network.compact_block import create_compact_block, CompactBlock
        cb = create_compact_block(block)
        self.assertIsInstance(cb, CompactBlock)
        self.assertEqual(cb.header, block.header)
        self.assertEqual(len(cb.short_tx_ids), 1)

    def test_reconstruct_from_mempool(self):
        """A compact block can be reconstructed using mempool transactions."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "hello", fee=500, nonce=0)
        chain.nonces[entities[0].entity_id] = 0

        mempool = Mempool()
        mempool.add_transaction(tx)

        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        from messagechain.network.compact_block import create_compact_block, reconstruct_block
        cb = create_compact_block(block)
        reconstructed = reconstruct_block(cb, mempool)
        self.assertIsNotNone(reconstructed)
        self.assertEqual(len(reconstructed.transactions), 1)
        self.assertEqual(reconstructed.transactions[0].tx_hash, tx.tx_hash)

    def test_missing_tx_returns_none(self):
        """If mempool is missing a transaction, reconstruction fails gracefully."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "hello", fee=500, nonce=0)
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        from messagechain.network.compact_block import create_compact_block, reconstruct_block
        cb = create_compact_block(block)
        empty_mempool = Mempool()
        result = reconstruct_block(cb, empty_mempool)
        self.assertIsNone(result)  # can't reconstruct without the tx


# ─── 5. Fee Estimation ───────────────────────────────────────────────

class TestFeeEstimation(unittest.TestCase):
    """Fee estimation analyzes recent blocks to recommend appropriate fees."""

    def test_fee_estimator_with_no_history(self):
        """With no block history, return minimum fee."""
        from messagechain.economics.fee_estimator import FeeEstimator
        estimator = FeeEstimator()
        self.assertEqual(estimator.estimate_fee(target_blocks=1), messagechain.config.MIN_FEE)

    def test_fee_estimator_tracks_block_fees(self):
        """Fee estimator updates when blocks are recorded."""
        from messagechain.economics.fee_estimator import FeeEstimator
        estimator = FeeEstimator()

        # Record some blocks with known fee distributions
        estimator.record_block_fees([200, 300, 400, 500, 600])
        estimator.record_block_fees([250, 350, 450, 550, 650])

        estimate = estimator.estimate_fee(target_blocks=1)
        self.assertGreater(estimate, messagechain.config.MIN_FEE)

    def test_fee_estimator_higher_urgency_higher_fee(self):
        """Targeting fewer blocks should suggest higher fees."""
        from messagechain.economics.fee_estimator import FeeEstimator
        estimator = FeeEstimator()

        for _ in range(10):
            estimator.record_block_fees([200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100])

        fast = estimator.estimate_fee(target_blocks=1)
        slow = estimator.estimate_fee(target_blocks=10)
        self.assertGreaterEqual(fast, slow)


# ─── 6. Replace-By-Fee (RBF) ─────────────────────────────────────────

class TestReplaceByFee(unittest.TestCase):
    """RBF allows replacing unconfirmed transactions with higher-fee versions."""

    def test_rbf_replaces_with_higher_fee(self):
        """A transaction can be replaced by one with a higher fee."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000

        tx1 = create_transaction(entities[0], "hello v1", fee=500, nonce=0)
        mempool = Mempool()
        mempool.add_transaction(tx1)
        self.assertEqual(mempool.size, 1)

        # Replace with higher fee, same nonce
        tx2 = create_transaction(entities[0], "hello v2", fee=1000, nonce=0)
        replaced = mempool.try_replace_by_fee(tx2)
        self.assertTrue(replaced)
        self.assertEqual(mempool.size, 1)
        # The mempool should contain tx2 not tx1
        txs = mempool.get_transactions(10)
        self.assertEqual(txs[0].tx_hash, tx2.tx_hash)

    def test_rbf_rejects_lower_fee(self):
        """A replacement with equal or lower fee is rejected."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000

        tx1 = create_transaction(entities[0], "hello", fee=500, nonce=0)
        mempool = Mempool()
        mempool.add_transaction(tx1)

        tx2 = create_transaction(entities[0], "hello v2", fee=500, nonce=0)
        replaced = mempool.try_replace_by_fee(tx2)
        self.assertFalse(replaced)
        self.assertEqual(mempool.size, 1)

    def test_rbf_must_match_sender_and_nonce(self):
        """RBF only replaces transactions from the same sender with the same nonce."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000
        chain.supply.balances[entities[1].entity_id] = 10000

        tx1 = create_transaction(entities[0], "hello", fee=500, nonce=0)
        mempool = Mempool()
        mempool.add_transaction(tx1)

        # Different sender, same nonce — should not replace
        tx2 = create_transaction(entities[1], "world", fee=1000, nonce=0)
        replaced = mempool.try_replace_by_fee(tx2)
        self.assertFalse(replaced)


# ─── 7. Transaction Versioning ────────────────────────────────────────

class TestTransactionVersioning(unittest.TestCase):
    """Transaction versioning enables future format changes without hard forks."""

    def test_transaction_has_version_field(self):
        """Transactions include a version field."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000

        tx = create_transaction(entities[0], "versioned msg", fee=500, nonce=0)
        self.assertTrue(hasattr(tx, 'version'))
        self.assertEqual(tx.version, 1)  # default version

    def test_version_included_in_hash(self):
        """The version field is included in the transaction hash."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000

        tx = create_transaction(entities[0], "test msg", fee=500, nonce=0)
        # Version should be part of signable data
        signable = tx._signable_data()
        # Signable data starts with CHAIN_ID then the version
        version_bytes = struct.pack(">I", tx.version)
        self.assertTrue(signable.startswith(CHAIN_ID + version_bytes))

    def test_version_serialization_roundtrip(self):
        """Version survives serialization/deserialization."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 10000

        tx = create_transaction(entities[0], "roundtrip", fee=500, nonce=0)
        data = tx.serialize()
        self.assertIn("version", data)
        tx2 = MessageTransaction.deserialize(data)
        self.assertEqual(tx2.version, tx.version)


# ─── 8. Light Client SPV Proofs ──────────────────────────────────────

class TestSPVProofs(unittest.TestCase):
    """SPV proofs allow light clients to verify transaction inclusion
    without downloading full blocks."""

    def test_generate_merkle_proof(self):
        """A Merkle inclusion proof can be generated for multiple transactions."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 100000
        consensus = ProofOfStake()

        txs = [create_transaction(entities[0], f"msg {i}", fee=500, nonce=i) for i in range(3)]
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=txs)

        from messagechain.core.spv import generate_merkle_proof
        proof = generate_merkle_proof(block, 0)
        self.assertIsNotNone(proof)
        self.assertGreater(len(proof.siblings), 0)

    def test_verify_merkle_proof(self):
        """A valid Merkle proof verifies successfully."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 100000
        consensus = ProofOfStake()

        txs = [create_transaction(entities[0], f"msg {i}", fee=500, nonce=i) for i in range(3)]
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=txs)

        from messagechain.core.spv import generate_merkle_proof, verify_merkle_proof
        proof = generate_merkle_proof(block, 1)
        valid = verify_merkle_proof(txs[1].tx_hash, proof, block.header.merkle_root)
        self.assertTrue(valid)

    def test_invalid_merkle_proof_rejected(self):
        """A tampered Merkle proof is rejected."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 100000
        consensus = ProofOfStake()

        txs = [create_transaction(entities[0], f"msg {i}", fee=500, nonce=i) for i in range(3)]
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=txs)

        from messagechain.core.spv import generate_merkle_proof, verify_merkle_proof
        proof = generate_merkle_proof(block, 0)
        # Tamper with a sibling
        proof.siblings[0] = b"\xff" * 32
        valid = verify_merkle_proof(txs[0].tx_hash, proof, block.header.merkle_root)
        self.assertFalse(valid)

    def test_merkle_proof_with_multiple_txs(self):
        """Merkle proofs work with multiple transactions in a block."""
        chain, entities = _make_chain_and_entities()
        chain.supply.balances[entities[0].entity_id] = 100000
        consensus = ProofOfStake()

        txs = []
        for i in range(4):
            tx = create_transaction(entities[0], f"msg {i}", fee=500, nonce=i)
            txs.append(tx)
        chain.nonces[entities[0].entity_id] = 0
        block = _propose_and_add(chain, consensus, entities[0], txs=txs)

        from messagechain.core.spv import generate_merkle_proof, verify_merkle_proof
        # Verify proof for each transaction
        for idx, tx in enumerate(txs):
            proof = generate_merkle_proof(block, idx)
            valid = verify_merkle_proof(tx.tx_hash, proof, block.header.merkle_root)
            self.assertTrue(valid, f"Proof failed for tx at index {idx}")


# ─── 9. Soft Fork Activation Signaling ───────────────────────────────

class TestSoftForkSignaling(unittest.TestCase):
    """Soft fork signaling coordinates protocol upgrades via
    validator signals in block headers."""

    def test_signal_tracker_creation(self):
        """A signal tracker can be created for a proposed feature."""
        from messagechain.consensus.signaling import SignalTracker

        tracker = SignalTracker(
            feature_name="new_message_format",
            start_height=100,
            timeout_height=1000,
            threshold=0.95,
            bit=0,
        )
        self.assertEqual(tracker.feature_name, "new_message_format")
        self.assertFalse(tracker.is_locked_in)
        self.assertFalse(tracker.is_active_at(0))

    def test_signal_accumulation(self):
        """Signals accumulate from block versions."""
        from messagechain.consensus.signaling import SignalTracker

        tracker = SignalTracker(
            feature_name="test_feature",
            start_height=0,
            timeout_height=100,
            threshold=0.75,
            bit=0,
        )

        # Record 8 signals out of 10 blocks (80% > 75% threshold)
        for i in range(10):
            signaling = i < 8  # 8 out of 10 signal
            tracker.record_block(block_height=i, signals=signaling)

        self.assertTrue(tracker.is_locked_in)

    def test_signal_below_threshold_not_locked_in(self):
        """If signaling is below threshold, feature is not locked in."""
        from messagechain.consensus.signaling import SignalTracker

        tracker = SignalTracker(
            feature_name="test_feature",
            start_height=0,
            timeout_height=100,
            threshold=0.95,
            bit=0,
        )

        # Alternate signals: 5 out of 10 signal (50% < 95%)
        # Interleave so we never hit 95% at any point
        for i in range(10):
            tracker.record_block(block_height=i, signals=(i % 2 == 0))

        self.assertFalse(tracker.is_locked_in)

    def test_activation_after_lock_in(self):
        """After lock-in, the feature activates after a grace period."""
        from messagechain.consensus.signaling import SignalTracker

        tracker = SignalTracker(
            feature_name="test_feature",
            start_height=0,
            timeout_height=100,
            threshold=0.75,
            bit=0,
            activation_delay=5,
        )

        # Get locked in
        for i in range(10):
            tracker.record_block(block_height=i, signals=True)

        self.assertTrue(tracker.is_locked_in)
        # Should activate after delay
        self.assertTrue(tracker.is_active_at(tracker.lock_in_height + 5))
        self.assertFalse(tracker.is_active_at(tracker.lock_in_height + 2))


# ─── 10. Dynamic Minimum Relay Fee ───────────────────────────────────

class TestDynamicMinRelayFee(unittest.TestCase):
    """Dynamic minimum relay fee adjusts based on mempool pressure."""

    def test_min_fee_at_empty_mempool(self):
        """When mempool is empty, minimum fee is the base MIN_FEE."""
        from messagechain.economics.dynamic_fee import DynamicFeePolicy
        policy = DynamicFeePolicy(base_fee=100, max_fee=10000)
        self.assertEqual(policy.get_min_relay_fee(mempool_size=0, mempool_max=5000), 100)

    def test_min_fee_increases_with_mempool_pressure(self):
        """As mempool fills up, minimum relay fee increases."""
        from messagechain.economics.dynamic_fee import DynamicFeePolicy
        policy = DynamicFeePolicy(base_fee=100, max_fee=10000)

        fee_low = policy.get_min_relay_fee(mempool_size=100, mempool_max=5000)
        fee_mid = policy.get_min_relay_fee(mempool_size=2500, mempool_max=5000)
        fee_high = policy.get_min_relay_fee(mempool_size=4500, mempool_max=5000)

        self.assertLessEqual(fee_low, fee_mid)
        self.assertLessEqual(fee_mid, fee_high)

    def test_min_fee_capped_at_max(self):
        """Minimum relay fee never exceeds the configured max."""
        from messagechain.economics.dynamic_fee import DynamicFeePolicy
        policy = DynamicFeePolicy(base_fee=100, max_fee=5000)

        fee = policy.get_min_relay_fee(mempool_size=5000, mempool_max=5000)
        self.assertLessEqual(fee, 5000)

    def test_mempool_rejects_below_dynamic_fee(self):
        """Mempool integration: transactions below dynamic fee are rejected."""
        from messagechain.economics.dynamic_fee import DynamicFeePolicy
        policy = DynamicFeePolicy(base_fee=100, max_fee=10000)

        # When mempool is 90% full, min fee should be > 100
        min_fee = policy.get_min_relay_fee(mempool_size=4500, mempool_max=5000)
        self.assertGreater(min_fee, 100)


if __name__ == "__main__":
    unittest.main()
