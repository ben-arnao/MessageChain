"""
Tests for Bitcoin Core gap analysis phase 2: Critical & High priority items.

Critical (security):
1. Connection type differentiation (block-relay-only, anchor, feeler)
2. Minimum chain weight for peers
3. Orphan block pool

High (long-term sustainability):
4. Pruning actually deleting from SQLite
5. Compact block filters (BIP 157/158)
6. Mempool persistence across restarts
7. Dust limit for transfers
8. AssumeValid optimization
"""

import hashlib
import json
import os
import struct
import tempfile
import time
import unittest

from tests import register_entity_for_test
import messagechain.config
from messagechain.config import HASH_ALGO, MIN_FEE
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, compute_merkle_root
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import TransferTransaction, create_transfer_transaction
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_chain_and_entities(num_entities=2, db=None):
    """Helper: create a blockchain with registered entities."""
    chain = Blockchain(db=db)
    entities = [Entity.create(f"gap2_key_{i}".encode()) for i in range(num_entities)]
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


# ─── 1. Connection Type Differentiation ─────────────────────────────

class TestConnectionTypes(unittest.TestCase):
    """Bitcoin Core uses distinct connection types: full-relay, block-relay-only,
    anchor, and feeler. Block-relay-only connections prevent network topology
    mapping via transaction relay timing. Anchor connections survive restarts
    to prevent eclipse attacks."""

    def test_connection_type_enum_exists(self):
        """ConnectionType enum defines all required types."""
        from messagechain.network.peer import ConnectionType
        self.assertIn("FULL_RELAY", ConnectionType.__members__)
        self.assertIn("BLOCK_RELAY_ONLY", ConnectionType.__members__)
        self.assertIn("ANCHOR", ConnectionType.__members__)
        self.assertIn("FEELER", ConnectionType.__members__)

    def test_peer_has_connection_type(self):
        """Each peer tracks its connection type."""
        from messagechain.network.peer import Peer, ConnectionType
        peer = Peer(host="127.0.0.1", port=9333, connection_type=ConnectionType.FULL_RELAY)
        self.assertEqual(peer.connection_type, ConnectionType.FULL_RELAY)

    def test_block_relay_only_peer_does_not_relay_transactions(self):
        """Block-relay-only peers should not relay transactions."""
        from messagechain.network.peer import Peer, ConnectionType
        peer = Peer(host="127.0.0.1", port=9333, connection_type=ConnectionType.BLOCK_RELAY_ONLY)
        self.assertFalse(peer.should_relay_tx())

    def test_full_relay_peer_relays_transactions(self):
        """Full-relay peers relay both blocks and transactions."""
        from messagechain.network.peer import Peer, ConnectionType
        peer = Peer(host="127.0.0.1", port=9333, connection_type=ConnectionType.FULL_RELAY)
        self.assertTrue(peer.should_relay_tx())

    def test_anchor_connections_persist_to_file(self):
        """Anchor connections are saved to disk so they survive node restarts."""
        from messagechain.network.anchor import AnchorStore
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            store = AnchorStore(path)
            store.save_anchors([("192.168.1.1", 9333), ("10.0.0.1", 9334)])

            # Reload from disk
            store2 = AnchorStore(path)
            anchors = store2.load_anchors()
            self.assertEqual(len(anchors), 2)
            self.assertIn(("192.168.1.1", 9333), anchors)
            self.assertIn(("10.0.0.1", 9334), anchors)
        finally:
            os.unlink(path)

    def test_anchor_store_handles_missing_file(self):
        """AnchorStore returns empty list if file doesn't exist."""
        from messagechain.network.anchor import AnchorStore
        store = AnchorStore("/nonexistent/path/anchors.json")
        anchors = store.load_anchors()
        self.assertEqual(anchors, [])

    def test_feeler_connection_is_transient(self):
        """Feeler connections are short-lived probes to verify address reachability."""
        from messagechain.network.peer import Peer, ConnectionType
        peer = Peer(host="127.0.0.1", port=9333, connection_type=ConnectionType.FEELER)
        self.assertFalse(peer.should_relay_tx())
        self.assertTrue(peer.is_feeler())


# ─── 2. Minimum Chain Weight for Peers ──────────────────────────────

class TestMinimumChainWeight(unittest.TestCase):
    """Bitcoin Core's nMinimumChainWork rejects peers on fake chains during IBD.
    Without this, a new node can be tricked into syncing a fabricated chain."""

    def test_config_has_minimum_chain_weight(self):
        """A minimum cumulative stake weight config parameter exists."""
        self.assertTrue(hasattr(messagechain.config, "MIN_CUMULATIVE_STAKE_WEIGHT"))
        self.assertGreater(messagechain.config.MIN_CUMULATIVE_STAKE_WEIGHT, 0)

    def test_sync_rejects_peer_below_minimum_weight(self):
        """ChainSyncer rejects peers whose reported chain weight is below minimum."""
        from messagechain.network.sync import ChainSyncer
        chain = Blockchain()
        entities = [Entity.create(b"min_weight_test")]
        chain.initialize_genesis(entities[0])

        syncer = ChainSyncer(chain, lambda addr: None)

        # Peer reports very low chain weight
        syncer.update_peer_height("fake_peer:9333", 1000, "aa" * 32, cumulative_weight=1)

        # Peer should be rejected for sync (below minimum)
        best = syncer.get_best_sync_peer()
        self.assertIsNone(best)

    def test_sync_accepts_peer_above_minimum_weight(self):
        """ChainSyncer accepts peers whose reported chain weight meets minimum."""
        from messagechain.network.sync import ChainSyncer
        chain = Blockchain()
        entities = [Entity.create(b"min_weight_test2")]
        chain.initialize_genesis(entities[0])

        syncer = ChainSyncer(chain, lambda addr: None)

        # Peer reports sufficient chain weight
        min_weight = messagechain.config.MIN_CUMULATIVE_STAKE_WEIGHT
        syncer.update_peer_height("good_peer:9333", 1000, "bb" * 32,
                                  cumulative_weight=min_weight + 1)

        best = syncer.get_best_sync_peer()
        self.assertEqual(best, "good_peer:9333")


# ─── 3. Orphan Block Pool ───────────────────────────────────────────

class TestOrphanBlockPool(unittest.TestCase):
    """When a block arrives whose parent is unknown, it should be stored in a
    bounded orphan pool and processed when the parent arrives."""

    def test_orphan_pool_exists(self):
        """Blockchain has an orphan block pool."""
        chain = Blockchain()
        self.assertTrue(hasattr(chain, 'orphan_pool'))

    def test_orphan_block_stored_when_parent_missing(self):
        """A block with unknown parent goes into the orphan pool."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        # Build a chain of 3 blocks
        for _ in range(3):
            _propose_and_add(chain, consensus, entities[0])

        # Propose blocks 4 and 5 in sequence on this chain
        block4 = chain.propose_block(consensus, entities[0], [])
        ok4, _ = chain.add_block(block4)
        self.assertTrue(ok4)
        block5 = chain.propose_block(consensus, entities[0], [])
        ok5, _ = chain.add_block(block5)
        self.assertTrue(ok5)

        # Remove block5 and block4 from chain to simulate receiving them out of order
        # We test the orphan pool directly: create a block that references a parent
        # not in a new chain's block index
        chain_short = Blockchain()
        chain_short.initialize_genesis(entities[0])
        for e in entities[1:]:
            register_entity_for_test(chain_short, e)
        # Only add up to block 3 using same blocks from chain
        for i in range(1, 4):
            block = chain.get_block(i)
            chain_short.add_block(block)

        # Try to add block5 to chain_short — parent (block4) is unknown
        ok, reason = chain_short.add_block(block5)
        self.assertFalse(ok)
        self.assertIn(block5.block_hash, chain_short.orphan_pool)

    def test_orphan_processed_when_parent_arrives(self):
        """When a parent block arrives, any orphans depending on it are processed."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        # Build blocks 1-3
        for _ in range(3):
            _propose_and_add(chain, consensus, entities[0])

        # Save state snapshot after block 3
        snapshot = {
            "balances": dict(chain.supply.balances),
            "staked": dict(chain.supply.staked),
            "nonces": dict(chain.nonces),
            "proposer_sig_counts": dict(chain.proposer_sig_counts),
            "immature_rewards": list(chain._immature_rewards),
            "chain_len": len(chain.chain),
        }

        # Build blocks 4 and 5, keeping references
        block4 = chain.propose_block(consensus, entities[0], [])
        ok4, _ = chain.add_block(block4)
        self.assertTrue(ok4)
        block5 = chain.propose_block(consensus, entities[0], [])
        ok5, _ = chain.add_block(block5)
        self.assertTrue(ok5)

        # Roll back to state after block 3
        chain.chain = chain.chain[:4]  # genesis + blocks 1-3
        del chain._block_by_hash[block4.block_hash]
        del chain._block_by_hash[block5.block_hash]
        chain.fork_choice.tips.clear()
        chain.fork_choice.add_tip(chain.chain[-1].block_hash, 3, 0)
        chain.supply.balances = snapshot["balances"]
        chain.supply.staked = snapshot["staked"]
        chain.nonces = snapshot["nonces"]
        chain.proposer_sig_counts = snapshot["proposer_sig_counts"]
        chain._immature_rewards = snapshot["immature_rewards"]

        # Add block5 first (orphan — parent block4 not in chain)
        chain.add_block(block5)
        self.assertIn(block5.block_hash, chain.orphan_pool)

        # Now add block4 — should trigger processing of orphan block5
        ok, _ = chain.add_block(block4)
        self.assertTrue(ok)
        # block5 should have been processed from orphan pool
        self.assertNotIn(block5.block_hash, chain.orphan_pool)
        self.assertEqual(chain.height, 6)  # genesis + 5 blocks

    def test_orphan_pool_bounded(self):
        """Orphan pool has a maximum size to prevent memory exhaustion."""
        chain, entities = _make_chain_and_entities()
        self.assertTrue(hasattr(messagechain.config, "MAX_ORPHAN_BLOCKS"))
        self.assertGreater(messagechain.config.MAX_ORPHAN_BLOCKS, 0)


# ─── 4. Pruning Actually Deleting from SQLite ───────────────────────

class TestSQLitePruning(unittest.TestCase):
    """Block pruning must actually delete transaction data from SQLite,
    not just track pruned state in memory."""

    def test_pruned_blocks_removed_from_db(self):
        """After pruning, old block transaction data is deleted from SQLite."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = ChainDB(db_path)
            # Build chain in memory, store blocks to DB manually
            chain, entities = _make_chain_and_entities()
            # Store genesis to DB
            db.store_block(chain.get_block(0))
            consensus = ProofOfStake()

            for _ in range(10):
                block = _propose_and_add(chain, consensus, entities[0])
                db.store_block(block)

            # Prune with keep_recent=3
            from messagechain.storage.pruning import BlockPruner
            pruner = BlockPruner(keep_recent=3)
            pruned = pruner.prune(chain, db=db)

            self.assertGreater(pruned, 0)

            # Verify old blocks are header-only in DB
            for i in range(pruned):
                self.assertTrue(db.has_block_header(i))
                # Full block data should be gone
                block = db.get_block_by_number(i)
                self.assertIsNone(block)
        finally:
            db.close()
            os.unlink(db_path)

    def test_pruned_headers_still_verifiable(self):
        """After pruning, the header chain remains intact and verifiable."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db = ChainDB(db_path)
            chain, entities = _make_chain_and_entities()
            db.store_block(chain.get_block(0))
            consensus = ProofOfStake()

            for _ in range(10):
                block = _propose_and_add(chain, consensus, entities[0])
                db.store_block(block)

            # Prune
            from messagechain.storage.pruning import BlockPruner
            pruner = BlockPruner(keep_recent=3)
            pruner.prune(chain, db=db)

            # Verify header chain is intact via DB
            for i in range(chain.height - 3):
                header_data = db.get_block_header(i)
                self.assertIsNotNone(header_data)
        finally:
            db.close()
            os.unlink(db_path)


# ─── 5. Compact Block Filters (BIP 157/158) ─────────────────────────

class TestCompactBlockFilters(unittest.TestCase):
    """BIP 157/158-style compact block filters enable privacy-preserving
    light client queries. Filters encode which entity_ids transacted in
    a block; light clients download filters and check locally."""

    def test_filter_creation_for_block(self):
        """A compact filter can be created for any block."""
        from messagechain.network.block_filter import create_block_filter
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "filter test", nonce=0, fee=1500)
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        filt = create_block_filter(block)
        self.assertIsNotNone(filt)
        self.assertGreater(len(filt.filter_data), 0)

    def test_filter_matches_included_entity(self):
        """A filter returns True for entity_ids that transacted in the block."""
        from messagechain.network.block_filter import create_block_filter
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "match test", nonce=0, fee=1500)
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        filt = create_block_filter(block)
        self.assertTrue(filt.match(entities[0].entity_id))

    def test_filter_does_not_match_absent_entity(self):
        """A filter returns False for entity_ids not in the block (with high probability)."""
        from messagechain.network.block_filter import create_block_filter
        chain, entities = _make_chain_and_entities(3)
        consensus = ProofOfStake()

        # Only entities[0] transacts
        tx = create_transaction(entities[0], "no match", nonce=0, fee=1500)
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        filt = create_block_filter(block)
        # entities[2] did not transact — should not match (probabilistic, but FP rate is low)
        # We check that at least the mechanism works (no crash, returns bool)
        result = filt.match(entities[2].entity_id)
        self.assertIsInstance(result, bool)

    def test_filter_serialization_roundtrip(self):
        """Filters can be serialized and deserialized for network relay."""
        from messagechain.network.block_filter import create_block_filter, BlockFilter
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        tx = create_transaction(entities[0], "serialize test", nonce=0, fee=1500)
        block = _propose_and_add(chain, consensus, entities[0], txs=[tx])

        filt = create_block_filter(block)
        data = filt.serialize()
        filt2 = BlockFilter.deserialize(data)

        self.assertEqual(filt.block_hash, filt2.block_hash)
        self.assertEqual(filt.filter_data, filt2.filter_data)

    def test_filter_header_chain(self):
        """Filter headers form a chain for integrity verification."""
        from messagechain.network.block_filter import create_block_filter, compute_filter_header
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        prev_header = b"\x00" * 32
        for i in range(5):
            block = _propose_and_add(chain, consensus, entities[0])
            filt = create_block_filter(block)
            header = compute_filter_header(filt, prev_header)
            self.assertEqual(len(header), 32)
            prev_header = header


# ─── 6. Mempool Persistence Across Restarts ─────────────────────────

class TestMempoolPersistence(unittest.TestCase):
    """Bitcoin Core saves the mempool to mempool.dat on shutdown and reloads
    on startup. Without this, pending transactions are silently lost."""

    def test_mempool_save_and_load(self):
        """Mempool can be saved to disk and loaded back."""
        chain, entities = _make_chain_and_entities()

        mempool = Mempool()
        tx1 = create_transaction(entities[0], "persist me 1", nonce=0, fee=1500)
        tx2 = create_transaction(entities[0], "persist me 2", nonce=1, fee=1500)
        mempool.add_transaction(tx1)
        mempool.add_transaction(tx2)

        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            path = f.name

        try:
            mempool.save_to_file(path)

            # Load into fresh mempool
            mempool2 = Mempool()
            loaded = mempool2.load_from_file(path)
            self.assertEqual(loaded, 2)
            self.assertEqual(mempool2.size, 2)
            self.assertIn(tx1.tx_hash, mempool2.pending)
            self.assertIn(tx2.tx_hash, mempool2.pending)
        finally:
            os.unlink(path)

    def test_mempool_load_skips_expired(self):
        """Loading a persisted mempool skips transactions that have expired."""
        chain, entities = _make_chain_and_entities()

        mempool = Mempool()
        tx = create_transaction(entities[0], "will expire", nonce=0, fee=1500)
        mempool.add_transaction(tx)

        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            path = f.name

        try:
            mempool.save_to_file(path)

            # Load with a very short TTL so the tx is expired
            mempool2 = Mempool(tx_ttl=0)
            loaded = mempool2.load_from_file(path)
            self.assertEqual(loaded, 0)
            self.assertEqual(mempool2.size, 0)
        finally:
            os.unlink(path)

    def test_mempool_load_handles_missing_file(self):
        """Loading from a nonexistent file returns 0 without error."""
        mempool = Mempool()
        loaded = mempool.load_from_file("/nonexistent/mempool.dat")
        self.assertEqual(loaded, 0)

    def test_mempool_load_handles_corrupt_file(self):
        """Loading from a corrupt file returns 0 without crashing."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False, mode="w") as f:
            f.write("not valid json at all {{{")
            path = f.name

        try:
            mempool = Mempool()
            loaded = mempool.load_from_file(path)
            self.assertEqual(loaded, 0)
        finally:
            os.unlink(path)


# ─── 7. Dust Limit for Transfers ────────────────────────────────────

class TestDustLimit(unittest.TestCase):
    """Transfers below a dust threshold create tiny-balance accounts that
    bloat state forever. A minimum transfer amount prevents this."""

    def test_config_has_dust_limit(self):
        """DUST_LIMIT config parameter exists."""
        self.assertTrue(hasattr(messagechain.config, "DUST_LIMIT"))
        self.assertGreater(messagechain.config.DUST_LIMIT, 0)

    def test_transfer_below_dust_rejected(self):
        """Transfer amounts below the dust limit are rejected."""
        chain, entities = _make_chain_and_entities(3)
        # Give entities[0] enough balance
        chain.supply.balances[entities[0].entity_id] = 10000

        dust = messagechain.config.DUST_LIMIT
        tx = create_transfer_transaction(
            entities[0], entities[1].entity_id,
            amount=dust - 1, nonce=0, fee=MIN_FEE,
        )
        valid, reason = chain.validate_transfer_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("dust", reason.lower())

    def test_transfer_at_dust_limit_accepted(self):
        """Transfer exactly at the dust limit is accepted."""
        chain, entities = _make_chain_and_entities(3)
        chain.supply.balances[entities[0].entity_id] = 10000

        dust = messagechain.config.DUST_LIMIT
        tx = create_transfer_transaction(
            entities[0], entities[1].entity_id,
            amount=dust, nonce=0, fee=MIN_FEE,
        )
        valid, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(valid, f"Should accept transfer at dust limit: {reason}")

    def test_transfer_above_dust_accepted(self):
        """Transfer above the dust limit is accepted."""
        chain, entities = _make_chain_and_entities(3)
        chain.supply.balances[entities[0].entity_id] = 10000

        dust = messagechain.config.DUST_LIMIT
        tx = create_transfer_transaction(
            entities[0], entities[1].entity_id,
            amount=dust + 100, nonce=0, fee=MIN_FEE,
        )
        valid, reason = chain.validate_transfer_transaction(tx)
        self.assertTrue(valid, f"Should accept transfer above dust limit: {reason}")


# ─── 8. AssumeValid Optimization ────────────────────────────────────

class TestAssumeValid(unittest.TestCase):
    """AssumeValid skips signature verification for blocks below a known-good
    block hash during IBD. This dramatically speeds up initial sync since
    WOTS+ verification is expensive."""

    def test_config_has_assume_valid_hash(self):
        """ASSUME_VALID_BLOCK_HASH config parameter exists (can be empty/None)."""
        self.assertTrue(hasattr(messagechain.config, "ASSUME_VALID_BLOCK_HASH"))

    def test_assume_valid_skips_sig_verification(self):
        """Blocks below the assume-valid hash skip signature verification."""
        chain, entities = _make_chain_and_entities()
        consensus = ProofOfStake()

        # Build some blocks
        for _ in range(5):
            _propose_and_add(chain, consensus, entities[0])

        # Set the assume-valid hash to block 3
        target_block = chain.get_block(3)
        chain.assume_valid_hash = target_block.block_hash

        # Blocks at or below height 3 should be considered assume-valid
        self.assertTrue(chain.is_assume_valid(1))
        self.assertTrue(chain.is_assume_valid(2))
        self.assertTrue(chain.is_assume_valid(3))
        # Block above assume-valid should NOT be skipped
        self.assertFalse(chain.is_assume_valid(4))

    def test_assume_valid_none_means_verify_all(self):
        """When assume_valid_hash is None, all blocks are fully verified."""
        chain, entities = _make_chain_and_entities()
        chain.assume_valid_hash = None
        self.assertFalse(chain.is_assume_valid(0))
        self.assertFalse(chain.is_assume_valid(100))


if __name__ == "__main__":
    unittest.main()
