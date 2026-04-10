"""
Tests for critical security vulnerabilities found in deep audit.

Covers:
1. Duplicate transactions within a single block (same nonce, same entity)
2. Consensus stakes not synced after loading from database
3. State persistence atomicity (SQL transaction wrapping)
4. State root validation bypass via zero hash
"""

import hashlib
import os
import tempfile
import time
import unittest

from messagechain.config import HASH_ALGO, MIN_FEE, VALIDATOR_MIN_STAKE
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, compute_merkle_root, _hash
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.inflation import SupplyTracker
from messagechain.storage.chaindb import ChainDB
from messagechain.crypto.keys import KeyPair
from tests import register_entity_for_test


def _make_entity(name: str) -> Entity:
    return Entity.create(f"{name}-privkey".encode())


def _make_signed_block(proposer, prev_block, transactions, blockchain):
    """Helper to create a properly signed block."""
    tx_hashes = [tx.tx_hash for tx in transactions]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _hash(b"empty")

    header = BlockHeader(
        version=1,
        block_number=prev_block.header.block_number + 1,
        prev_hash=prev_block.block_hash,
        merkle_root=merkle_root,
        timestamp=time.time(),
        proposer_id=proposer.entity_id,
        state_root=b"\x00" * 32,
    )
    header_hash = _hash(header.signable_data())
    header.proposer_signature = proposer.keypair.sign(header_hash)

    block = Block(header=header, transactions=transactions, attestations=[])
    block.block_hash = block._compute_hash()
    return block


class TestDuplicateTransactionsInBlock(unittest.TestCase):
    """Critical #1: Two transactions from the same entity with the same nonce
    must NOT both pass validation within a single block.

    Previously, validate_block() checked each tx against the chain state
    without updating nonces between checks, so both would see the same
    expected nonce and both would pass.
    """

    def setUp(self):
        self.proposer = _make_entity("proposer")
        self.sender = _make_entity("sender")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.sender)
        # Give sender some balance for fees
        self.chain.supply.balances[self.sender.entity_id] = 1000

    def test_block_with_duplicate_nonce_rejected(self):
        """A block containing two txs from the same entity with the same nonce
        must be rejected."""
        # Create two transactions with nonce=0 from the same sender
        tx1 = create_transaction(
            self.sender, "First message", fee=MIN_FEE, nonce=0
        )
        tx2 = create_transaction(
            self.sender, "Second message", fee=MIN_FEE, nonce=0
        )

        # Build a block containing both
        block = _make_signed_block(
            self.proposer, self.chain.get_latest_block(), [tx1, tx2], self.chain
        )

        valid, reason = self.chain.validate_block(block)
        self.assertFalse(valid, "Block with duplicate-nonce txs must be rejected")
        self.assertIn("nonce", reason.lower())

    def test_block_with_sequential_nonces_accepted(self):
        """A block with properly sequential nonces (0, 1) from the same entity
        should be accepted."""
        tx1 = create_transaction(
            self.sender, "First message", fee=MIN_FEE, nonce=0
        )
        tx2 = create_transaction(
            self.sender, "Second message", fee=MIN_FEE, nonce=1
        )

        block = _make_signed_block(
            self.proposer, self.chain.get_latest_block(), [tx1, tx2], self.chain
        )

        valid, reason = self.chain.validate_block(block)
        self.assertTrue(valid, f"Block with sequential nonces should be valid: {reason}")

    def test_block_with_gap_nonce_rejected(self):
        """A block where nonces skip (0, 2) must be rejected."""
        tx1 = create_transaction(
            self.sender, "First message", fee=MIN_FEE, nonce=0
        )
        tx2 = create_transaction(
            self.sender, "Third message", fee=MIN_FEE, nonce=2
        )

        block = _make_signed_block(
            self.proposer, self.chain.get_latest_block(), [tx1, tx2], self.chain
        )

        valid, reason = self.chain.validate_block(block)
        self.assertFalse(valid, "Block with nonce gap must be rejected")

    def test_duplicate_nonce_double_spend_prevented(self):
        """Verify that a double-spend via duplicate nonce is actually prevented
        at the balance level too."""
        # Give sender exactly enough for one fee
        self.chain.supply.balances[self.sender.entity_id] = MIN_FEE

        tx1 = create_transaction(
            self.sender, "Spend all", fee=MIN_FEE, nonce=0
        )
        tx2 = create_transaction(
            self.sender, "Spend again", fee=MIN_FEE, nonce=0
        )

        block = _make_signed_block(
            self.proposer, self.chain.get_latest_block(), [tx1, tx2], self.chain
        )

        valid, _ = self.chain.validate_block(block)
        self.assertFalse(valid, "Double-spend via duplicate nonce must be rejected")


class TestConsensusStakeSyncOnRestart(unittest.TestCase):
    """Critical #2: After loading from DB, consensus.stakes must reflect
    the staked amounts from the supply tracker."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_stake_sync.db")

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_stakes_populated_after_db_load(self):
        """After restart from DB, consensus.stakes must contain staked validators."""
        entity = _make_entity("validator")

        # Phase 1: Create chain, stake, persist
        db1 = ChainDB(self.db_path)
        chain1 = Blockchain(db=db1)
        chain1.initialize_genesis(entity)

        # Simulate staking
        chain1.supply.balances[entity.entity_id] = 10000
        chain1.supply.stake(entity.entity_id, 500)
        chain1._persist_state()
        db1.close()

        # Phase 2: Reload from DB into fresh Blockchain + ProofOfStake
        db2 = ChainDB(self.db_path)
        chain2 = Blockchain(db=db2)
        pos = ProofOfStake()

        # The fix: sync stakes from supply tracker into consensus
        chain2.sync_consensus_stakes(pos)

        self.assertIn(entity.entity_id, pos.stakes,
                       "Validator stake must be in consensus after reload")
        self.assertEqual(pos.stakes[entity.entity_id], 500)
        self.assertGreater(pos.total_stake, 0,
                          "Total stake must be >0 after loading staked validators")
        db2.close()

    def test_empty_stakes_no_permissive_mode_after_reload(self):
        """After reload with staked validators, consensus must NOT be in
        permissive bootstrap mode."""
        entity = _make_entity("val2")

        db1 = ChainDB(self.db_path)
        chain1 = Blockchain(db=db1)
        chain1.initialize_genesis(entity)
        chain1.supply.balances[entity.entity_id] = 10000
        chain1.supply.stake(entity.entity_id, VALIDATOR_MIN_STAKE)
        chain1._persist_state()
        db1.close()

        db2 = ChainDB(self.db_path)
        chain2 = Blockchain(db=db2)
        pos = ProofOfStake()
        chain2.sync_consensus_stakes(pos)

        # With stakes loaded, permissive mode should be off
        self.assertTrue(len(pos.stakes) > 0,
                        "Stakes must be populated — bootstrap permissive mode must not apply")
        db2.close()


class TestAtomicStatePersistence(unittest.TestCase):
    """Critical #3: _persist_state() must use an atomic SQL transaction
    so a crash mid-write doesn't leave partial state."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_atomic.db")

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_persist_state_uses_transaction(self):
        """Verify _persist_state wraps writes in BEGIN/COMMIT."""
        entity = _make_entity("atomic")
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(entity)
        chain.supply.balances[entity.entity_id] = 5000

        # Track whether begin_transaction and commit_transaction are called
        calls = []
        original_begin = db.begin_transaction
        original_commit = db.commit_transaction
        original_rollback = db.rollback_transaction

        def mock_begin():
            calls.append("begin")
            original_begin()

        def mock_commit():
            calls.append("commit")
            original_commit()

        db.begin_transaction = mock_begin
        db.commit_transaction = mock_commit
        db.rollback_transaction = original_rollback

        chain._persist_state()

        self.assertIn("begin", calls, "_persist_state must call begin_transaction")
        self.assertIn("commit", calls, "_persist_state must call commit_transaction")

        # Verify the begin comes before commit
        begin_idx = calls.index("begin")
        commit_idx = calls.index("commit")
        self.assertLess(begin_idx, commit_idx, "begin must come before commit")
        db.close()

    def test_persist_state_rollback_on_error(self):
        """If an error occurs during _persist_state, the transaction must roll back."""
        entity = _make_entity("rollback")
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(entity)

        # Add a balance that will be persisted
        chain.supply.balances[entity.entity_id] = 9999

        # Sabotage one write to simulate a crash
        original_set_nonce = db.set_nonce
        def failing_set_nonce(eid, nonce):
            raise RuntimeError("Simulated crash during persist")
        db.set_nonce = failing_set_nonce

        with self.assertRaises(RuntimeError):
            chain._persist_state()

        # After rollback, the DB should not have the partially-written balance
        # (it should have the old state, not the new one)
        db2 = ChainDB(self.db_path)
        # The balance from the failed persist should NOT be 9999
        # It should be whatever was committed before
        bal = db2.get_balance(entity.entity_id)
        # The genesis init persists state once, so entity has GENESIS_ALLOCATION from genesis
        from messagechain.config import GENESIS_ALLOCATION
        self.assertEqual(bal, GENESIS_ALLOCATION,
                        "Failed persist must not leave partial state (balance should be genesis allocation)")
        db.close()
        db2.close()


class TestStateRootBypass(unittest.TestCase):
    """Critical #4: Blocks with explicit state_root must match post-state.
    Zero state_root means "state uncommitted" and skips validation."""

    def setUp(self):
        self.proposer = _make_entity("proposer-sr")
        self.sender = _make_entity("sender-sr")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.sender)
        self.chain.supply.balances[self.sender.entity_id] = 1000

    def test_wrong_state_root_rejected(self):
        """A block with an incorrect non-zero state_root must be rejected."""
        tx = create_transaction(
            self.sender, "Test message", fee=MIN_FEE, nonce=0
        )

        prev = self.chain.get_latest_block()
        tx_hashes = [tx.tx_hash]
        merkle_root = compute_merkle_root(tx_hashes)

        # Use a garbage state root (non-zero, so it will be validated)
        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer_id=self.proposer.entity_id,
            state_root=b"\xff" * 32,  # wrong state root
        )
        header_hash = _hash(header.signable_data())
        header.proposer_signature = self.proposer.keypair.sign(header_hash)

        block = Block(header=header, transactions=[tx], attestations=[])
        block.block_hash = block._compute_hash()

        valid, reason = self.chain.add_block(block)
        self.assertFalse(valid, "Block with wrong state_root must be rejected")
        self.assertIn("state_root", reason)

    def test_correct_state_root_accepted(self):
        """A block with the correct state root must be accepted."""
        tx = create_transaction(
            self.sender, "Test message", fee=MIN_FEE, nonce=0
        )

        prev = self.chain.get_latest_block()
        tx_hashes = [tx.tx_hash]
        merkle_root = compute_merkle_root(tx_hashes)
        proposer_id = self.proposer.entity_id
        block_height = prev.header.block_number + 1

        # Use blockchain's compute_post_state_root for correct post-state commitment
        expected_root = self.chain.compute_post_state_root(
            [tx], proposer_id, block_height,
        )

        header = BlockHeader(
            version=1,
            block_number=block_height,
            prev_hash=prev.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer_id=proposer_id,
            state_root=expected_root,
        )
        header_hash = _hash(header.signable_data())
        header.proposer_signature = self.proposer.keypair.sign(header_hash)

        block = Block(header=header, transactions=[tx], attestations=[])
        block.block_hash = block._compute_hash()

        valid, reason = self.chain.add_block(block)
        self.assertTrue(valid, f"Block with correct state root should be accepted: {reason}")


class TestRestoreStateSnapshotAtomic(unittest.TestCase):
    """Critical #3b: restore_state_snapshot must also be atomic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_restore_atomic.db")

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_restore_snapshot_replaces_state(self):
        """restore_state_snapshot must replace old data with snapshot data."""
        db = ChainDB(self.db_path)

        # Set some initial state
        db.set_balance(b"\x01" * 32, 100)
        db.flush_state()

        snapshot = {
            "balances": {b"\x02" * 32: 200},
            "staked": {},
            "nonces": {},
            "public_keys": {},
            "message_counts": {},
            "proposer_sig_counts": {},
            "total_supply": 1_000_000_000,
            "total_minted": 0,
            "total_fees_collected": 0,
        }

        db.restore_state_snapshot(snapshot)

        # Verify old data is gone and new data is present
        self.assertEqual(db.get_balance(b"\x01" * 32), 0)
        self.assertEqual(db.get_balance(b"\x02" * 32), 200)
        db.close()

    def test_restore_snapshot_rollback_on_error(self):
        """If restore_state_snapshot fails partway, old state must be preserved."""
        db = ChainDB(self.db_path)

        # Set initial state
        db.set_balance(b"\x01" * 32, 100)
        db.set_nonce(b"\x01" * 32, 5)
        db.flush_state()

        # Use a dict whose .items() raises mid-iteration to simulate crash
        class ExplodingDict(dict):
            def items(self):
                raise RuntimeError("Simulated crash mid-restore")

        snapshot = {
            "balances": {b"\x02" * 32: 200},
            "staked": {},
            "nonces": {},
            "public_keys": ExplodingDict(),  # Will blow up when iterated
            "message_counts": {},
            "proposer_sig_counts": {},
            "total_supply": 1_000_000_000,
            "total_minted": 0,
            "total_fees_collected": 0,
        }

        with self.assertRaises(RuntimeError):
            db.restore_state_snapshot(snapshot)

        # After rollback, old state must still be present
        self.assertEqual(db.get_balance(b"\x01" * 32), 100,
                        "Original balance must survive failed restore")
        self.assertEqual(db.get_nonce(b"\x01" * 32), 5,
                        "Original nonce must survive failed restore")
        db.close()


if __name__ == "__main__":
    unittest.main()
