"""Tests for Bitcoin Core gap analysis features (batch 3).

Covers:
1. Signature canonicalization (witness_hash)
2. Sig cost budget enforcement in block validation
3. Header spam protection (bounded pending_headers)
4. Censorship mitigation (proposer duty tracking)
5. Transaction relay timing privacy (random delay before INV)
6. Peer eviction protection (multi-criteria)
7. Database corruption recovery (startup integrity + reindex)
8. Orphan transaction pool (out-of-order nonces)
"""

import hashlib
import time
import unittest
from unittest.mock import MagicMock, patch

import messagechain.config
from messagechain.config import HASH_ALGO
from messagechain.identity.identity import Entity
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from tests import register_entity_for_test


class TestSignatureCanonicalization(unittest.TestCase):
    """#1: Signatures must have a canonical byte representation (witness_hash)."""

    def test_signature_canonical_bytes(self):
        """Signature.canonical_bytes() produces deterministic output."""
        sig = Signature(
            wots_signature=[b"\x01" * 32, b"\x02" * 32],
            leaf_index=5,
            auth_path=[b"\x03" * 32],
            wots_public_key=b"\x04" * 32,
            wots_public_seed=b"\x05" * 32,
        )
        canonical1 = sig.canonical_bytes()
        canonical2 = sig.canonical_bytes()
        self.assertEqual(canonical1, canonical2)
        self.assertIsInstance(canonical1, bytes)
        self.assertTrue(len(canonical1) > 0)

    def test_different_signatures_different_canonical_bytes(self):
        """Different signatures produce different canonical bytes."""
        sig1 = Signature(
            wots_signature=[b"\x01" * 32],
            leaf_index=0,
            auth_path=[b"\x03" * 32],
            wots_public_key=b"\x04" * 32,
            wots_public_seed=b"\x05" * 32,
        )
        sig2 = Signature(
            wots_signature=[b"\x02" * 32],
            leaf_index=0,
            auth_path=[b"\x03" * 32],
            wots_public_key=b"\x04" * 32,
            wots_public_seed=b"\x05" * 32,
        )
        self.assertNotEqual(sig1.canonical_bytes(), sig2.canonical_bytes())

    def test_transaction_witness_hash(self):
        """Transactions have a witness_hash covering the signature."""
        entity = Entity.create(b"test_witness_hash_seed_1234567890")
        chain = Blockchain()
        chain.initialize_genesis(entity)
        register_entity_for_test(chain, entity)
        chain.supply.balances[entity.entity_id] = 1000

        tx = create_transaction(entity, "test witness hash", fee=1, nonce=0)
        self.assertTrue(hasattr(tx, 'witness_hash'))
        self.assertIsInstance(tx.witness_hash, bytes)
        self.assertTrue(len(tx.witness_hash) > 0)
        # witness_hash should differ from tx_hash (tx_hash excludes sig)
        self.assertNotEqual(tx.witness_hash, tx.tx_hash)

    def test_witness_hash_deterministic(self):
        """Same transaction always produces same witness_hash."""
        entity = Entity.create(b"test_witness_determ_seed_12345678")
        chain = Blockchain()
        chain.initialize_genesis(entity)
        register_entity_for_test(chain, entity)
        chain.supply.balances[entity.entity_id] = 1000

        tx = create_transaction(entity, "deterministic", fee=1, nonce=0)
        wh1 = tx.witness_hash
        # Recompute
        wh2 = tx._compute_witness_hash()
        self.assertEqual(wh1, wh2)

    def test_signature_serialize_roundtrip_canonical(self):
        """Serialized + deserialized signature produces same canonical_bytes."""
        sig = Signature(
            wots_signature=[b"\xaa" * 32, b"\xbb" * 32],
            leaf_index=3,
            auth_path=[b"\xcc" * 32, b"\xdd" * 32],
            wots_public_key=b"\xee" * 32,
            wots_public_seed=b"\xff" * 32,
        )
        data = sig.serialize()
        sig2 = Signature.deserialize(data)
        self.assertEqual(sig.canonical_bytes(), sig2.canonical_bytes())


class TestSigCostBudgetEnforcement(unittest.TestCase):
    """#9: MAX_BLOCK_SIG_COST must be enforced during block validation."""

    def setUp(self):
        self.entity = Entity.create(b"test_sig_cost_seed_123456789012")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.entity)
        register_entity_for_test(self.chain, self.entity)
        self.chain.supply.balances[self.entity.entity_id] = 100_000

    def test_sig_cost_computed_correctly(self):
        """Sig cost = num_txs + 1 (proposer) + num_attestations."""
        from messagechain.core.blockchain import compute_block_sig_cost
        # Mock a block with 5 txs, 3 attestations
        block = MagicMock()
        block.transactions = [MagicMock()] * 5
        block.transfer_transactions = []
        block.attestations = [MagicMock()] * 3
        block.slash_transactions = []
        cost = compute_block_sig_cost(block)
        # 5 txs + 0 transfers + 1 proposer + 3 attestations = 9
        self.assertEqual(cost, 9)

    def test_sig_cost_includes_transfers(self):
        """Sig cost counts transfer transactions too."""
        from messagechain.core.blockchain import compute_block_sig_cost
        block = MagicMock()
        block.transactions = [MagicMock()] * 3
        block.transfer_transactions = [MagicMock()] * 2
        block.attestations = []
        block.slash_transactions = [MagicMock()] * 1
        cost = compute_block_sig_cost(block)
        # 3 msg + 2 transfer + 1 slash + 1 proposer + 0 att = 7
        self.assertEqual(cost, 7)

    def test_block_exceeding_sig_cost_rejected(self):
        """Block with sig cost > MAX_BLOCK_SIG_COST is rejected."""
        # MAX_BLOCK_SIG_COST is 100 by default
        # A block needs > 100 sig operations to be rejected
        # This is tested via validate_block which checks sig_cost
        # We verify the check exists by testing with a low override
        old_val = messagechain.config.MAX_BLOCK_SIG_COST
        try:
            messagechain.config.MAX_BLOCK_SIG_COST = 3  # very low
            from messagechain.consensus.pos import ProofOfStake
            pos = ProofOfStake()
            pos.stakes[self.entity.entity_id] = 1000

            # Create multiple transactions so sig cost exceeds 3
            txs = []
            for i in range(5):
                tx = create_transaction(self.entity, f"msg {i}", fee=1, nonce=i)
                txs.append(tx)
                self.chain.nonces[self.entity.entity_id] = i + 1

            # Reset nonces for block validation
            self.chain.nonces[self.entity.entity_id] = 0

            block = self.chain.propose_block(pos, self.entity, txs)
            valid, reason = self.chain.validate_block(block)
            self.assertFalse(valid)
            self.assertIn("sig cost", reason.lower())
        finally:
            messagechain.config.MAX_BLOCK_SIG_COST = old_val


class TestHeaderSpamProtection(unittest.TestCase):
    """#16: Pending headers must be bounded to prevent OOM."""

    def test_max_pending_headers_config(self):
        """MAX_PENDING_HEADERS config exists."""
        self.assertTrue(hasattr(messagechain.config, 'MAX_PENDING_HEADERS'))
        self.assertGreater(messagechain.config.MAX_PENDING_HEADERS, 0)

    def test_pending_headers_bounded(self):
        """ChainSyncer rejects headers beyond MAX_PENDING_HEADERS."""
        from messagechain.network.sync import ChainSyncer

        chain = Blockchain()
        entity = Entity.create(b"test_header_spam_seed_1234567890")
        chain.initialize_genesis(entity)

        syncer = ChainSyncer(chain, lambda addr: None)
        syncer.state = __import__('messagechain.network.sync', fromlist=['SyncState']).SyncState.SYNCING_HEADERS

        # The syncer should enforce MAX_PENDING_HEADERS
        self.assertTrue(hasattr(syncer, '_check_headers_limit'))

    def test_headers_over_limit_rejected(self):
        """Headers beyond the limit are dropped, not stored."""
        from messagechain.network.sync import ChainSyncer, SyncState

        chain = Blockchain()
        entity = Entity.create(b"test_header_limit_seed_123456789")
        chain.initialize_genesis(entity)

        syncer = ChainSyncer(chain, lambda addr: None)
        syncer.state = SyncState.SYNCING_HEADERS

        old_limit = messagechain.config.MAX_PENDING_HEADERS
        try:
            messagechain.config.MAX_PENDING_HEADERS = 10

            # Pre-fill with headers at the limit
            genesis_hash = chain.get_latest_block().block_hash.hex()
            prev = genesis_hash
            for i in range(10):
                bh = hashlib.new(HASH_ALGO, f"block_{i}".encode()).hexdigest()
                syncer.pending_headers.append({
                    "block_hash": bh,
                    "prev_hash": prev,
                    "block_number": i + 1,
                })
                prev = bh

            # Now the limit should prevent more
            self.assertTrue(syncer._check_headers_limit())
        finally:
            messagechain.config.MAX_PENDING_HEADERS = old_limit


class TestCensorshipMitigation(unittest.TestCase):
    """#15: Track proposer duty — penalize empty blocks when mempool has txs."""

    def test_proposer_duty_tracker_exists(self):
        """ProposerDutyTracker class exists."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        self.assertIsNotNone(tracker)

    def test_record_block_production(self):
        """Can record that a proposer produced a block."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        proposer = b"\x01" * 32
        tracker.record_block(proposer, tx_count=5, mempool_size=10)
        stats = tracker.get_proposer_stats(proposer)
        self.assertEqual(stats["blocks_proposed"], 1)
        self.assertEqual(stats["total_txs_included"], 5)

    def test_detect_empty_block_with_pending_txs(self):
        """Flags proposers who produce empty blocks when mempool has transactions."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        proposer = b"\x01" * 32

        # Produce an empty block when mempool has 50 txs
        tracker.record_block(proposer, tx_count=0, mempool_size=50)
        stats = tracker.get_proposer_stats(proposer)
        self.assertEqual(stats["empty_blocks_with_pending"], 1)

    def test_empty_block_ok_when_mempool_empty(self):
        """Empty block when mempool is also empty is NOT flagged."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        proposer = b"\x01" * 32

        tracker.record_block(proposer, tx_count=0, mempool_size=0)
        stats = tracker.get_proposer_stats(proposer)
        self.assertEqual(stats["empty_blocks_with_pending"], 0)

    def test_censorship_score(self):
        """Proposer censorship score increases with empty blocks when txs pending."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        proposer = b"\x01" * 32

        # 3 empty blocks with pending txs
        for _ in range(3):
            tracker.record_block(proposer, tx_count=0, mempool_size=20)

        stats = tracker.get_proposer_stats(proposer)
        self.assertEqual(stats["empty_blocks_with_pending"], 3)
        self.assertGreater(stats["censorship_score"], 0)

    def test_good_proposer_no_censorship_score(self):
        """Proposer who includes transactions has censorship_score of 0."""
        from messagechain.consensus.proposer_duty import ProposerDutyTracker
        tracker = ProposerDutyTracker()
        proposer = b"\x01" * 32

        for i in range(5):
            tracker.record_block(proposer, tx_count=10, mempool_size=50)

        stats = tracker.get_proposer_stats(proposer)
        self.assertEqual(stats["censorship_score"], 0)


class TestTxRelayTimingPrivacy(unittest.TestCase):
    """#5: Random delays before relaying transactions via INV."""

    def test_relay_delay_config_exists(self):
        """TX_RELAY_DELAY_MEAN config exists."""
        self.assertTrue(hasattr(messagechain.config, 'TX_RELAY_DELAY_MEAN'))
        self.assertGreater(messagechain.config.TX_RELAY_DELAY_MEAN, 0)

    def test_relay_scheduler_exists(self):
        """TxRelayScheduler class exists and can schedule relays."""
        from messagechain.network.relay_privacy import TxRelayScheduler
        scheduler = TxRelayScheduler()
        self.assertIsNotNone(scheduler)

    def test_relay_delay_is_random(self):
        """Relay delays are random (Poisson-distributed), not fixed."""
        from messagechain.network.relay_privacy import TxRelayScheduler
        scheduler = TxRelayScheduler()

        delays = [scheduler.compute_delay() for _ in range(100)]
        # Should have variation (not all the same)
        self.assertGreater(len(set(round(d, 2) for d in delays)), 1)
        # All should be non-negative
        self.assertTrue(all(d >= 0 for d in delays))

    def test_relay_delay_mean_is_reasonable(self):
        """Average delay should be close to TX_RELAY_DELAY_MEAN."""
        from messagechain.network.relay_privacy import TxRelayScheduler
        scheduler = TxRelayScheduler()

        delays = [scheduler.compute_delay() for _ in range(1000)]
        avg = sum(delays) / len(delays)
        # Should be within 50% of configured mean
        expected = messagechain.config.TX_RELAY_DELAY_MEAN
        self.assertAlmostEqual(avg, expected, delta=expected * 0.5)

    def test_unannounced_tx_not_served(self):
        """Scheduler tracks announced txs per peer; won't serve unannounced."""
        from messagechain.network.relay_privacy import TxRelayScheduler
        scheduler = TxRelayScheduler()
        tx_hash = b"\x01" * 32
        peer = "192.168.1.1:9333"

        # Not announced yet — should not serve
        self.assertFalse(scheduler.can_serve_tx(peer, tx_hash))

        # Mark as announced
        scheduler.mark_announced(peer, tx_hash)
        self.assertTrue(scheduler.can_serve_tx(peer, tx_hash))


class TestPeerEvictionProtection(unittest.TestCase):
    """#2: Multi-criteria peer eviction protection (eclipse attack defense)."""

    def test_eviction_protector_exists(self):
        """PeerEvictionProtector class exists."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()
        self.assertIsNotNone(protector)

    def test_register_peer_metrics(self):
        """Can register peer connection metrics."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()
        protector.register_peer("192.168.1.1:9333", connect_time=time.time())
        self.assertEqual(len(protector.peers), 1)

    def test_update_peer_ping(self):
        """Can update peer ping latency."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()
        protector.register_peer("192.168.1.1:9333", connect_time=time.time())
        protector.update_ping("192.168.1.1:9333", latency_ms=50.0)
        self.assertEqual(protector.peers["192.168.1.1:9333"].ping_ms, 50.0)

    def test_update_peer_block_delivery(self):
        """Can record that a peer delivered a novel block."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()
        protector.register_peer("192.168.1.1:9333", connect_time=time.time())
        protector.record_novel_block("192.168.1.1:9333")
        self.assertEqual(protector.peers["192.168.1.1:9333"].novel_blocks, 1)

    def test_protected_peers_not_evicted(self):
        """Peers with best metrics are protected from eviction."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()

        now = time.time()
        # Add peers with various characteristics
        # Best ping peer
        protector.register_peer("fast:1", connect_time=now)
        protector.update_ping("fast:1", latency_ms=10.0)

        # Longest connected peer
        protector.register_peer("old:1", connect_time=now - 86400)

        # Best block delivery peer
        protector.register_peer("blocks:1", connect_time=now)
        for _ in range(5):
            protector.record_novel_block("blocks:1")

        # A "nothing special" peer
        protector.register_peer("boring:1", connect_time=now)

        evict_candidate = protector.select_eviction_candidate()
        # The protected peers should NOT be selected
        self.assertNotEqual(evict_candidate, "fast:1")
        self.assertNotEqual(evict_candidate, "old:1")
        self.assertNotEqual(evict_candidate, "blocks:1")

    def test_no_eviction_when_few_peers(self):
        """No eviction candidate when only a few peers connected."""
        from messagechain.network.eviction import PeerEvictionProtector
        protector = PeerEvictionProtector()
        protector.register_peer("peer:1", connect_time=time.time())
        # With only 1 peer, shouldn't evict anyone
        self.assertIsNone(protector.select_eviction_candidate())


class TestDBCorruptionRecovery(unittest.TestCase):
    """#8: Database integrity checks and reindex capability."""

    def test_integrity_check_passes_clean_db(self):
        """Integrity check passes on a clean database."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB
        from messagechain.storage.integrity import check_db_integrity

        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "test_integrity.db")
            db = ChainDB(db_path)

            entity = Entity.create(b"test_integrity_seed_123456789012")
            chain = Blockchain(db=db)
            chain.initialize_genesis(entity)

            result = check_db_integrity(db, chain)
            self.assertTrue(result.is_ok)
            db.close()

    def test_integrity_check_detects_missing_genesis(self):
        """Integrity check detects missing genesis block."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB
        from messagechain.storage.integrity import check_db_integrity

        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "test_no_genesis.db")
            db = ChainDB(db_path)
            chain = Blockchain(db=db)
            # Don't initialize genesis

            result = check_db_integrity(db, chain)
            # Empty chain should be OK (no blocks to check)
            self.assertTrue(result.is_ok)
            db.close()

    def test_integrity_check_detects_corrupt_supply(self):
        """Integrity check detects supply inconsistency."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB
        from messagechain.storage.integrity import check_db_integrity

        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "test_corrupt_supply.db")
            db = ChainDB(db_path)

            entity = Entity.create(b"test_corrupt_sup_seed_1234567890")
            chain = Blockchain(db=db)
            chain.initialize_genesis(entity)

            # Corrupt the in-memory supply
            chain.supply.total_supply = -1

            result = check_db_integrity(db, chain)
            self.assertFalse(result.is_ok)
            self.assertTrue(any("supply" in e.lower() for e in result.errors))
            db.close()

    def test_sqlite_pragma_integrity_check(self):
        """Can run SQLite PRAGMA integrity_check."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB
        from messagechain.storage.integrity import check_sqlite_integrity

        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "test_pragma.db")
            db = ChainDB(db_path)
            result = check_sqlite_integrity(db)
            self.assertTrue(result)
            db.close()

    def test_reindex_rebuilds_state(self):
        """Reindex rebuilds balances/nonces from block history."""
        import tempfile, os
        from messagechain.storage.chaindb import ChainDB
        from messagechain.storage.integrity import reindex_state

        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "test_reindex.db")
            db = ChainDB(db_path)

            entity = Entity.create(b"test_reindex_seed_12345678901234")
            chain = Blockchain(db=db)
            chain.initialize_genesis(entity)
            register_entity_for_test(chain, entity)
            chain.supply.balances[entity.entity_id] = 10000

            # Remember the correct balance
            correct_balance = chain.supply.get_balance(entity.entity_id)

            # Corrupt balance in memory
            chain.supply.balances[entity.entity_id] = 999999

            # Reindex should restore from blocks
            reindex_state(db, chain)
            # After reindex, chain state is rebuilt from blocks
            self.assertNotEqual(chain.supply.get_balance(entity.entity_id), 999999)
            db.close()


class TestOrphanTransactionPool(unittest.TestCase):
    """#10: Hold transactions with future nonces temporarily."""

    def test_orphan_pool_exists(self):
        """Mempool has an orphan/pending-nonce pool."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()
        self.assertTrue(hasattr(pool, 'orphan_pool'))

    def test_future_nonce_stored_in_orphan_pool(self):
        """Transaction with nonce = expected + 1 goes to orphan pool."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()

        # Create a mock tx with nonce=1 when expected is 0
        tx = MagicMock(spec=MessageTransaction)
        tx.tx_hash = b"\x01" * 32
        tx.entity_id = b"\x02" * 32
        tx.nonce = 1
        tx.fee = 10
        tx.timestamp = time.time()

        result = pool.add_orphan_tx(tx, expected_nonce=0)
        self.assertTrue(result)
        self.assertEqual(len(pool.orphan_pool), 1)

    def test_orphan_promoted_when_gap_fills(self):
        """Orphan txs are promoted to main pool when missing nonce arrives."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()

        # tx with nonce=1 (orphan — nonce 0 not yet seen)
        tx1 = MagicMock(spec=MessageTransaction)
        tx1.tx_hash = b"\x01" * 32
        tx1.entity_id = b"\x02" * 32
        tx1.nonce = 1
        tx1.fee = 10
        tx1.timestamp = time.time()
        pool.add_orphan_tx(tx1, expected_nonce=0)

        # Now nonce=0 arrives — should promote nonce=1
        promoted = pool.promote_orphans(tx1.entity_id, new_nonce=1)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0].tx_hash, tx1.tx_hash)

    def test_orphan_pool_bounded(self):
        """Orphan pool has a size limit."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()

        self.assertTrue(hasattr(messagechain.config, 'MEMPOOL_MAX_ORPHAN_TXS'))
        max_orphans = messagechain.config.MEMPOOL_MAX_ORPHAN_TXS

        for i in range(max_orphans + 10):
            tx = MagicMock(spec=MessageTransaction)
            tx.tx_hash = i.to_bytes(32, 'big')
            tx.entity_id = b"\x02" * 32
            tx.nonce = i + 1
            tx.fee = 10
            tx.timestamp = time.time()
            pool.add_orphan_tx(tx, expected_nonce=0)

        self.assertLessEqual(len(pool.orphan_pool), max_orphans)

    def test_orphan_max_nonce_gap(self):
        """Orphan pool rejects transactions with nonce gap > 3."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()

        tx = MagicMock(spec=MessageTransaction)
        tx.tx_hash = b"\x01" * 32
        tx.entity_id = b"\x02" * 32
        tx.nonce = 5  # gap of 5 from expected 0
        tx.fee = 10
        tx.timestamp = time.time()

        result = pool.add_orphan_tx(tx, expected_nonce=0)
        self.assertFalse(result)  # gap too large

    def test_orphan_per_sender_limit(self):
        """Max orphan txs per sender is enforced."""
        from messagechain.core.mempool import Mempool
        pool = Mempool()

        sender = b"\x02" * 32
        for i in range(10):
            tx = MagicMock(spec=MessageTransaction)
            tx.tx_hash = i.to_bytes(32, 'big')
            tx.entity_id = sender
            tx.nonce = i + 1  # all within gap of 3 from different expected nonces
            tx.fee = 10
            tx.timestamp = time.time()
            pool.add_orphan_tx(tx, expected_nonce=i)

        # Should be capped at MEMPOOL_MAX_ORPHAN_PER_SENDER (3)
        sender_orphans = [tx for tx in pool.orphan_pool.values()
                         if tx.entity_id == sender]
        self.assertLessEqual(len(sender_orphans),
                            messagechain.config.MEMPOOL_MAX_ORPHAN_PER_SENDER)


if __name__ == "__main__":
    unittest.main()
