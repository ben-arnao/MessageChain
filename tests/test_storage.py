"""
Tests for persistent storage (ChainDB), fork choice, chain reorg, and IBD sync.
"""

import os
import tempfile
import time

import unittest

from messagechain.identity.biometrics import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.fork_choice import (
    ForkChoice, compute_block_stake_weight, find_fork_point, find_common_ancestor,
)
from messagechain.storage.chaindb import ChainDB
from messagechain.network.sync import ChainSyncer, SyncState
from tests import register_entity_for_test

import hashlib
from messagechain.config import HASH_ALGO


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# ── Helpers ──────────────────────────────────────────────────────

def make_entity(name: str) -> Entity:
    return Entity.create(f"{name}-privkey".encode())


def make_chain_with_blocks(num_blocks: int, db=None) -> tuple[Blockchain, Entity]:
    """Create a blockchain with genesis + num_blocks blocks."""
    alice = make_entity("alice")
    bob = make_entity("bob")
    chain = Blockchain(db=db)
    chain.initialize_genesis(alice)
    register_entity_for_test(chain, bob)
    # Fund test entities so they can pay fees
    chain.supply.balances[alice.entity_id] = 10000
    chain.supply.balances[bob.entity_id] = 10000

    pos = ProofOfStake()

    for i in range(num_blocks):
        tx = create_transaction(bob, f"Message {i}", fee=2, nonce=i)
        block = chain.propose_block(pos, alice, [tx])
        success, reason = chain.add_block(block)
        assert success, f"Failed to add block {i}: {reason}"

    return chain, alice


def make_temp_db() -> tuple[ChainDB, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return ChainDB(path), path


# ══════════════════════════════════════════════════════════════════
# PERSISTENT STORAGE TESTS
# ══════════════════════════════════════════════════════════════════

class TestChainDB(unittest.TestCase):
    """Test SQLite-backed persistent storage."""

    def test_store_and_retrieve_block(self):
        db, path = make_temp_db()
        try:
            alice = make_entity("alice")
            chain = Blockchain()
            genesis = chain.initialize_genesis(alice)

            db.store_block(genesis)
            loaded = db.get_block_by_hash(genesis.block_hash)

            assert loaded is not None
            assert loaded.block_hash == genesis.block_hash
            assert loaded.header.block_number == 0
        finally:
            db.close()
            os.unlink(path)

    def test_has_block(self):
        db, path = make_temp_db()
        try:
            alice = make_entity("alice")
            chain = Blockchain()
            genesis = chain.initialize_genesis(alice)

            assert not db.has_block(genesis.block_hash)
            db.store_block(genesis)
            assert db.has_block(genesis.block_hash)
        finally:
            db.close()
            os.unlink(path)

    def test_balance_persistence(self):
        db, path = make_temp_db()
        try:
            eid = b"\x01" * 32
            assert db.get_balance(eid) == 0
            db.set_balance(eid, 5000)
            db.flush_state()
            assert db.get_balance(eid) == 5000
        finally:
            db.close()
            os.unlink(path)

    def test_nonce_persistence(self):
        db, path = make_temp_db()
        try:
            eid = b"\x02" * 32
            db.set_nonce(eid, 42)
            db.flush_state()
            assert db.get_nonce(eid) == 42
        finally:
            db.close()
            os.unlink(path)

    def test_chain_tips(self):
        db, path = make_temp_db()
        try:
            h1 = b"\xaa" * 32
            h2 = b"\xbb" * 32

            db.add_chain_tip(h1, 5, 100)
            db.add_chain_tip(h2, 6, 200)

            best = db.get_best_tip()
            assert best is not None
            assert best[0] == h2  # h2 has higher weight
            assert best[1] == 6
            assert best[2] == 200

            db.remove_chain_tip(h2)
            best = db.get_best_tip()
            assert best[0] == h1
        finally:
            db.close()
            os.unlink(path)

    def test_state_snapshot_and_restore(self):
        db, path = make_temp_db()
        try:
            eid = b"\x03" * 32
            db.set_balance(eid, 1000)
            db.set_nonce(eid, 5)
            db.set_public_key(eid, b"\xff" * 32)
            db.set_staked(eid, 200)
            db.set_message_count(eid, 10)
            db.set_supply_meta("total_supply", 2000000)
            db.flush_state()

            snapshot = db.save_state_snapshot()

            # Modify state
            db.set_balance(eid, 999)
            db.set_nonce(eid, 99)
            db.flush_state()

            # Restore
            db.restore_state_snapshot(snapshot)
            assert db.get_balance(eid) == 1000
            assert db.get_nonce(eid) == 5
        finally:
            db.close()
            os.unlink(path)


class TestPersistentBlockchain(unittest.TestCase):
    """Test Blockchain with SQLite persistence."""

    def test_persist_and_reload_chain(self):
        """Chain should survive a 'restart' (new Blockchain with same DB)."""
        db, path = make_temp_db()
        try:
            # Session 1: create chain with blocks
            chain1, alice = make_chain_with_blocks(3, db=db)
            height1 = chain1.height
            latest_hash1 = chain1.get_latest_block().block_hash
            alice_balance = chain1.supply.get_balance(alice.entity_id)

            assert height1 == 4  # genesis + 3 blocks

            # Session 2: reload from same database
            chain2 = Blockchain(db=db)
            assert chain2.height == height1
            assert chain2.get_latest_block().block_hash == latest_hash1
            assert chain2.supply.get_balance(alice.entity_id) == alice_balance
        finally:
            db.close()
            os.unlink(path)

    def test_persist_entity_registration(self):
        db, path = make_temp_db()
        try:
            alice = make_entity("alice")
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)

            bob = make_entity("bob")
            success, _ = register_entity_for_test(chain, bob)
            assert success

            # Reload
            chain2 = Blockchain(db=db)
            assert bob.entity_id in chain2.public_keys
            assert chain2.supply.get_balance(bob.entity_id) == 0
        finally:
            db.close()
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════
# FORK CHOICE TESTS
# ══════════════════════════════════════════════════════════════════

class TestForkChoice(unittest.TestCase):
    """Test fork choice rule (heaviest stake wins)."""

    def test_single_tip(self):
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)

        best = fc.get_best_tip()
        assert best is not None
        assert best[0] == b"\x01" * 32
        assert best[1] == 5
        assert best[2] == 100

    def test_heaviest_tip_wins(self):
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)  # lighter
        fc.add_tip(b"\x02" * 32, 4, 200)  # heavier (even though shorter)

        best = fc.get_best_tip()
        assert best[0] == b"\x02" * 32  # heavier chain wins

    def test_tiebreak_by_height(self):
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)
        fc.add_tip(b"\x02" * 32, 6, 100)  # same weight, taller

        best = fc.get_best_tip()
        assert best[0] == b"\x02" * 32  # taller wins on tie

    def test_remove_tip(self):
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)
        fc.add_tip(b"\x02" * 32, 6, 200)

        fc.remove_tip(b"\x02" * 32)
        best = fc.get_best_tip()
        assert best[0] == b"\x01" * 32

    def test_is_better_chain(self):
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)

        assert fc.is_better_chain(200, 4)  # heavier
        assert not fc.is_better_chain(50, 10)  # lighter
        assert fc.is_better_chain(100, 6)  # same weight, taller

    def test_compute_block_stake_weight(self):
        alice = make_entity("alice")
        chain = Blockchain()
        genesis = chain.initialize_genesis(alice)

        # No stake -> minimum weight of 1
        weight = compute_block_stake_weight(genesis, {})
        assert weight == 1

        # With stake
        stakes = {alice.entity_id: 500}
        weight = compute_block_stake_weight(genesis, stakes)
        assert weight == 500


class TestForkCommonAncestor(unittest.TestCase):
    """Test finding common ancestors between forking chains."""

    def test_find_ancestor_simple_fork(self):
        """Two chains diverging from the same parent."""
        alice = make_entity("alice")
        bob = make_entity("bob")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[alice.entity_id] = 10000
        chain.supply.balances[bob.entity_id] = 10000

        pos = ProofOfStake()
        parent = chain.get_latest_block()

        # Create block A (on main chain)
        tx_a = create_transaction(bob, "fork A", fee=2, nonce=0)
        block_a = chain.propose_block(pos, alice, [tx_a])
        chain.add_block(block_a)

        # Create block B (competing fork, same parent)
        tx_b = create_transaction(bob, "fork B", fee=3, nonce=0)
        block_b = pos.create_block(alice, [tx_b], parent)

        # Store block_b in the hash index
        chain._block_by_hash[block_b.block_hash] = block_b

        ancestor, rollback, apply_ = find_common_ancestor(
            block_a.block_hash, block_b.block_hash, chain.get_block_by_hash
        )

        assert ancestor == parent.block_hash
        assert len(rollback) == 1
        assert rollback[0].block_hash == block_a.block_hash
        assert len(apply_) == 1
        assert apply_[0].block_hash == block_b.block_hash


class TestChainReorg(unittest.TestCase):
    """Test chain reorganization."""

    def test_duplicate_block_rejected(self):
        chain, alice = make_chain_with_blocks(2)
        block = chain.get_block(1)
        success, reason = chain.add_block(block)
        assert not success
        assert "already known" in reason.lower()

    def test_orphan_block_rejected(self):
        chain, alice = make_chain_with_blocks(1)
        pos = ProofOfStake()

        # Create a block pointing to a non-existent parent
        fake_parent = Block(
            header=BlockHeader(1, 99, b"\xff" * 32, _hash(b"fake"), time.time(), alice.entity_id),
            transactions=[],
        )
        fake_parent.block_hash = fake_parent._compute_hash()

        bob = make_entity("bob-orphan")
        register_entity_for_test(chain, bob)
        chain.supply.balances[bob.entity_id] = 10000
        tx = create_transaction(bob, "orphan", fee=2, nonce=0)
        block = pos.create_block(alice, [tx], fake_parent)

        success, reason = chain.add_block(block)
        assert not success
        assert "orphan" in reason.lower() or "parent" in reason.lower()

    def test_fork_block_stored(self):
        """A fork block should be stored even if not on the best chain."""
        alice = make_entity("alice")
        bob = make_entity("bob")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, bob)
        chain.supply.balances[alice.entity_id] = 10000
        chain.supply.balances[bob.entity_id] = 10000
        # Give alice stake so main chain blocks have weight > 1,
        # ensuring the longer main chain is strictly heavier than the fork.
        chain.supply.staked[alice.entity_id] = 1000

        pos = ProofOfStake()
        genesis = chain.get_latest_block()

        # Build main chain 2 blocks deep so it's strictly better than a 1-block fork
        tx1 = create_transaction(bob, "main chain 1", fee=2, nonce=0)
        block1 = chain.propose_block(pos, alice, [tx1])
        chain.add_block(block1)

        tx2 = create_transaction(bob, "main chain 2", fee=2, nonce=1)
        block2 = chain.propose_block(pos, alice, [tx2])
        chain.add_block(block2)

        # Create competing fork block from genesis (shorter fork, won't trigger reorg)
        tx_fork = create_transaction(bob, "fork chain", fee=2, nonce=0)
        block_fork = pos.create_block(alice, [tx_fork], genesis)

        success, reason = chain.add_block(block_fork)
        assert success
        # Block should be findable by hash
        assert chain.get_block_by_hash(block_fork.block_hash) is not None

    def test_chain_info_shows_tips(self):
        chain, _ = make_chain_with_blocks(2)
        info = chain.get_chain_info()
        assert "chain_tips" in info
        assert info["chain_tips"] >= 1


# ══════════════════════════════════════════════════════════════════
# IBD / SYNC TESTS
# ══════════════════════════════════════════════════════════════════

class TestChainSyncer(unittest.TestCase):
    """Test the IBD sync state machine."""

    def test_initial_state(self):
        chain, _ = make_chain_with_blocks(0)
        syncer = ChainSyncer(chain, lambda addr: None)
        assert syncer.state == SyncState.IDLE
        assert not syncer.is_syncing
        assert syncer.sync_progress == 1.0

    def test_needs_sync_when_behind(self):
        chain, _ = make_chain_with_blocks(0)
        syncer = ChainSyncer(chain, lambda addr: None)

        # No peers, no sync needed
        assert not syncer.needs_sync()

        # Peer is ahead
        syncer.update_peer_height("peer1:9333", 10)
        assert syncer.needs_sync()

    def test_get_best_sync_peer(self):
        chain, _ = make_chain_with_blocks(0)
        syncer = ChainSyncer(chain, lambda addr: None)

        syncer.update_peer_height("peer1:9333", 5)
        syncer.update_peer_height("peer2:9333", 10)
        syncer.update_peer_height("peer3:9333", 3)

        best = syncer.get_best_sync_peer()
        assert best == "peer2:9333"

    def test_no_sync_when_caught_up(self):
        chain, _ = make_chain_with_blocks(5)
        syncer = ChainSyncer(chain, lambda addr: None)

        # Peer at same height
        syncer.update_peer_height("peer1:9333", chain.height)
        assert not syncer.needs_sync()
        assert syncer.get_best_sync_peer() is None

    def test_sync_status(self):
        chain, _ = make_chain_with_blocks(0)
        syncer = ChainSyncer(chain, lambda addr: None)

        status = syncer.get_sync_status()
        assert status["state"] == "idle"
        assert "our_height" in status
        assert "target_height" in status

    def test_headers_response_empty(self):
        """Empty headers response should transition to COMPLETE."""
        import asyncio

        chain, _ = make_chain_with_blocks(0)
        syncer = ChainSyncer(chain, lambda addr: None)
        syncer.state = SyncState.SYNCING_HEADERS

        asyncio.get_event_loop().run_until_complete(
            syncer.handle_headers_response([], "peer1:9333")
        )
        assert syncer.state == SyncState.COMPLETE


class TestSyncProtocol(unittest.TestCase):
    """Test the sync protocol message types exist and work."""

    def test_new_message_types_exist(self):
        from messagechain.network.protocol import MessageType
        assert MessageType.REQUEST_HEADERS.value == "request_headers"
        assert MessageType.RESPONSE_HEADERS.value == "response_headers"
        assert MessageType.REQUEST_BLOCKS_BATCH.value == "request_blocks_batch"
        assert MessageType.RESPONSE_BLOCKS_BATCH.value == "response_blocks_batch"

    def test_sync_message_serialization(self):
        from messagechain.network.protocol import NetworkMessage, MessageType, encode_message, decode_message

        msg = NetworkMessage(
            msg_type=MessageType.REQUEST_HEADERS,
            payload={"start_height": 0, "count": 100},
            sender_id="abc123",
        )
        encoded = encode_message(msg)
        decoded = decode_message(encoded[4:])  # skip length prefix
        assert decoded.msg_type == MessageType.REQUEST_HEADERS
        assert decoded.payload["start_height"] == 0
        assert decoded.payload["count"] == 100


# ══════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):
    """End-to-end tests combining storage + fork choice + sync."""

    def test_full_lifecycle_with_persistence(self):
        """Create chain, persist, reload, verify integrity."""
        db, path = make_temp_db()
        try:
            # Create and populate chain
            alice = make_entity("alice")
            bob = make_entity("bob")
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            register_entity_for_test(chain, bob)
            chain.supply.balances[alice.entity_id] = 10000
            chain.supply.balances[bob.entity_id] = 10000

            pos = ProofOfStake()
            for i in range(5):
                tx = create_transaction(bob, f"Msg {i}", fee=2, nonce=i)
                block = chain.propose_block(pos, alice, [tx])
                success, _ = chain.add_block(block)
                assert success

            original_height = chain.height
            original_balance = chain.supply.get_balance(bob.entity_id)
            original_nonce = chain.nonces[bob.entity_id]

            # Reload
            chain2 = Blockchain(db=db)
            assert chain2.height == original_height
            assert chain2.supply.get_balance(bob.entity_id) == original_balance
            assert chain2.nonces[bob.entity_id] == original_nonce
            assert bob.entity_id in chain2.public_keys
        finally:
            db.close()
            os.unlink(path)

    def test_fork_choice_with_persistence(self):
        """Fork choice data should persist across restarts."""
        db, path = make_temp_db()
        try:
            alice = make_entity("alice")
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)

            info = chain.get_chain_info()
            assert info["chain_tips"] >= 1

            # Reload and check tips are still there
            chain2 = Blockchain(db=db)
            assert len(chain2.fork_choice.tips) >= 1
        finally:
            db.close()
            os.unlink(path)

    def test_backward_compatible_in_memory(self):
        """Blockchain without db= still works (backward compatible)."""
        chain, alice = make_chain_with_blocks(3)
        assert chain.height == 4
        assert chain.db is None

        info = chain.get_chain_info()
        assert info["chain_tips"] == 1
        assert info["height"] == 4


if __name__ == "__main__":
    unittest.main()
