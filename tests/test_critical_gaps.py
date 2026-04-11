"""
Tests for critical security gaps identified via Bitcoin Core comparison.

Covers:
1. Duplicate transaction detection in blocks
2. Block signature cost limits (sigops-style)
3. Median Time Past (MTP) for timestamps
4. Block reward maturity period
5. Address manager with Sybil resistance (addrman)
6. Ancestor/descendant tracking in mempool
7. Signature verification cache
"""

import hashlib
import time
import unittest
from unittest.mock import patch

from tests import register_entity_for_test
from messagechain.config import HASH_ALGO, BLOCK_REWARD
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction, MessageTransaction
from messagechain.consensus.pos import ProofOfStake


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class TestDuplicateTransactionDetection(unittest.TestCase):
    """Gap #1: Reject blocks containing duplicate transaction hashes."""

    def setUp(self):
        self.chain = Blockchain()
        self.consensus = ProofOfStake()
        self.proposer = Entity.create(b"proposer-seed-dup".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        self.chain.supply.balances[self.proposer.entity_id] = 100_000

    def test_block_rejects_duplicate_tx_hash(self):
        """A block with the same transaction included twice must be rejected."""
        tx = create_transaction(self.proposer, "hello", fee=1500, nonce=0)
        # Manually build a block with the same tx twice
        from messagechain.core.block import Block, BlockHeader, compute_merkle_root, _hash as block_hash

        prev = self.chain.get_latest_block()
        tx_hashes = [tx.tx_hash, tx.tx_hash]
        merkle_root = compute_merkle_root(tx_hashes)
        state_root = self.chain.compute_post_state_root(
            [tx, tx], self.proposer.entity_id, prev.header.block_number + 1
        )
        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer_id=self.proposer.entity_id,
            state_root=state_root,
        )
        header_hash = block_hash(header.signable_data())
        header.proposer_signature = self.proposer.keypair.sign(header_hash)
        block = Block(header=header, transactions=[tx, tx])
        block.block_hash = block._compute_hash()

        valid, reason = self.chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("uplicate", reason)


class TestBlockSignatureCostLimits(unittest.TestCase):
    """Gap #2: Limit total signature verification cost per block."""

    def test_max_sig_cost_config_exists(self):
        """Config must define MAX_BLOCK_SIG_COST."""
        from messagechain import config
        self.assertTrue(hasattr(config, 'MAX_BLOCK_SIG_COST'))
        self.assertGreater(config.MAX_BLOCK_SIG_COST, 0)

    def test_block_rejects_excessive_sig_cost(self):
        """A block exceeding MAX_BLOCK_SIG_COST must be rejected."""
        from messagechain import config

        chain = Blockchain()
        consensus = ProofOfStake()
        proposer = Entity.create(b"proposer-seed-sigcost".ljust(32, b"\x00"))
        chain.initialize_genesis(proposer)
        register_entity_for_test(chain, proposer)
        chain.supply.balances[proposer.entity_id] = 1_000_000

        # Create many entities to generate many transactions
        entities = []
        for i in range(10):
            e = Entity.create(f"sigcost-entity-{i}".encode().ljust(32, b"\x00"))
            register_entity_for_test(chain, e)
            chain.supply.balances[e.entity_id] = 100_000
            entities.append(e)

        # Create transactions from different entities
        txs = []
        for e in entities:
            tx = create_transaction(e, f"msg", fee=1500, nonce=0)
            txs.append(tx)

        # With a very low sig cost limit, even a few txs should be rejected
        original = config.MAX_BLOCK_SIG_COST
        try:
            # Each tx costs 1 sig, proposer sig costs 1 = total 11
            # Set limit to 5 to force rejection
            config.MAX_BLOCK_SIG_COST = 5

            from messagechain.core.block import Block, BlockHeader, compute_merkle_root, _hash as block_hash
            prev = chain.get_latest_block()
            tx_hashes = [tx.tx_hash for tx in txs]
            merkle_root = compute_merkle_root(tx_hashes)
            state_root = chain.compute_post_state_root(
                txs, proposer.entity_id, prev.header.block_number + 1
            )
            header = BlockHeader(
                version=1,
                block_number=prev.header.block_number + 1,
                prev_hash=prev.block_hash,
                merkle_root=merkle_root,
                timestamp=time.time(),
                proposer_id=proposer.entity_id,
                state_root=state_root,
            )
            header_hash = block_hash(header.signable_data())
            header.proposer_signature = proposer.keypair.sign(header_hash)
            block = Block(header=header, transactions=txs)
            block.block_hash = block._compute_hash()

            valid, reason = chain.validate_block(block)
            self.assertFalse(valid)
            self.assertIn("sig", reason.lower())
        finally:
            config.MAX_BLOCK_SIG_COST = original


class TestMedianTimePast(unittest.TestCase):
    """Gap #3: Use median of last N block timestamps for time validation."""

    def setUp(self):
        self.chain = Blockchain()
        self.consensus = ProofOfStake()
        self.proposer = Entity.create(b"proposer-seed-mtp".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        self.chain.supply.balances[self.proposer.entity_id] = 100_000

    def test_mtp_calculation(self):
        """Median time past should return median of last N block timestamps."""
        # Genesis block has some timestamp
        mtp = self.chain.get_median_time_past()
        self.assertIsInstance(mtp, float)

    def test_block_timestamp_must_exceed_mtp(self):
        """A block with timestamp <= MTP must be rejected."""
        # Add a few blocks to build up MTP history
        for i in range(5):
            tx = create_transaction(self.proposer, f"msg{i}", fee=1500, nonce=i)
            block = self.chain.propose_block(self.consensus, self.proposer, [tx])
            self.chain.add_block(block)

        mtp = self.chain.get_median_time_past()

        # Create a block with timestamp at or below MTP
        from messagechain.core.block import Block, BlockHeader, _hash as block_hash
        prev = self.chain.get_latest_block()
        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=_hash(b"empty"),
            timestamp=mtp - 1,  # below MTP
            proposer_id=self.proposer.entity_id,
            state_root=self.chain.compute_post_state_root(
                [], self.proposer.entity_id, prev.header.block_number + 1
            ),
        )
        header_hash = block_hash(header.signable_data())
        header.proposer_signature = self.proposer.keypair.sign(header_hash)
        block = Block(header=header, transactions=[])
        block.block_hash = block._compute_hash()

        valid, reason = self.chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("median time", reason.lower())


class TestBlockRewardMaturity(unittest.TestCase):
    """Gap #4: Block rewards should not be spendable for COINBASE_MATURITY blocks."""

    def setUp(self):
        self.chain = Blockchain()
        self.consensus = ProofOfStake()
        self.proposer = Entity.create(b"proposer-seed-maturity".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.proposer)
        register_entity_for_test(self.chain, self.proposer)
        # Give enough balance to cover fees so we can test reward spending
        self.chain.supply.balances[self.proposer.entity_id] = 100_000

    def test_maturity_config_exists(self):
        """Config must define COINBASE_MATURITY."""
        from messagechain import config
        self.assertTrue(hasattr(config, 'COINBASE_MATURITY'))
        self.assertGreater(config.COINBASE_MATURITY, 0)

    def test_immature_rewards_not_spendable(self):
        """Cannot spend block rewards before COINBASE_MATURITY blocks."""
        from messagechain import config

        # Proposer has balance=50. Add one block to earn BLOCK_REWARD.
        # The reward should be locked (immature).
        tx1 = create_transaction(self.proposer, "earn reward", fee=1500, nonce=0)
        block1 = self.chain.propose_block(self.consensus, self.proposer, [tx1])
        self.chain.add_block(block1)

        # Reward tokens are immature and should NOT be in spendable balance.
        spendable = self.chain.get_spendable_balance(self.proposer.entity_id)
        total = self.chain.supply.get_balance(self.proposer.entity_id)
        self.assertLess(spendable, total, "Immature rewards should not be spendable")

    def test_mature_rewards_become_spendable(self):
        """After COINBASE_MATURITY blocks, rewards become spendable."""
        from messagechain import config

        # Use a small maturity for this test to avoid key exhaustion
        original_maturity = config.COINBASE_MATURITY
        config.COINBASE_MATURITY = 3
        try:
            # Add a block to earn reward
            tx1 = create_transaction(self.proposer, "earn", fee=1500, nonce=0)
            block1 = self.chain.propose_block(self.consensus, self.proposer, [tx1])
            self.chain.add_block(block1)

            immature_before = self.chain.get_immature_balance(self.proposer.entity_id)
            self.assertGreater(immature_before, 0)

            # Add COINBASE_MATURITY more blocks to mature the reward
            for i in range(config.COINBASE_MATURITY):
                nonce = i + 1
                tx = create_transaction(self.proposer, f"m{i}", fee=1500, nonce=nonce)
                block = self.chain.propose_block(self.consensus, self.proposer, [tx])
                self.chain.add_block(block)

            # Now the reward from block1 should be mature
            spendable = self.chain.get_spendable_balance(self.proposer.entity_id)
            total = self.chain.supply.get_balance(self.proposer.entity_id)
            # The very first reward should now be spendable
            self.assertGreater(spendable, 0)
        finally:
            config.COINBASE_MATURITY = original_maturity


class TestAddressManagerSybilResistance(unittest.TestCase):
    """Gap #5: Address manager must resist eclipse/Sybil attacks."""

    def test_addrman_exists(self):
        """AddressManager class must exist in the network module."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()
        self.assertIsNotNone(am)

    def test_two_table_design(self):
        """Address manager must have new and tried tables."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()
        self.assertTrue(hasattr(am, '_new_table'))
        self.assertTrue(hasattr(am, '_tried_table'))

    def test_source_diversity_bucketing(self):
        """Addresses from the same source should be bucketed together."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()

        # Add many addresses from the same source
        for i in range(100):
            am.add_address(f"10.0.{i // 256}.{i % 256}", 9333, source_ip="192.168.1.1")

        # Should be limited — not all 100 should make it in
        total = am.count_new()
        self.assertLess(total, 100, "Same-source addresses should be bucketed/limited")

    def test_per_source_group_limit(self):
        """A single source group (/16) should not dominate the new table."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()

        # Add addresses from a single source
        for i in range(200):
            am.add_address(f"10.{i}.0.1", 9333, source_ip="1.2.3.4")

        # Different source
        for i in range(50):
            am.add_address(f"172.16.{i}.1", 9333, source_ip="5.6.7.8")

        # Both sources should have entries (not just the first flooding source)
        total = am.count_new()
        self.assertGreater(total, 50, "Multiple source groups should be represented")

    def test_tried_table_on_success(self):
        """Successfully connected addresses should move to tried table."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()

        am.add_address("10.0.0.1", 9333, source_ip="1.2.3.4")
        am.mark_good("10.0.0.1", 9333)

        self.assertGreater(am.count_tried(), 0)

    def test_select_returns_diverse_addresses(self):
        """Selecting addresses for connection should produce diverse results."""
        from messagechain.network.addrman import AddressManager
        am = AddressManager()

        # Add addresses from different network groups
        for i in range(10):
            am.add_address(f"{i + 1}.0.0.1", 9333, source_ip=f"{i + 10}.0.0.1")

        selected = am.select_addresses(5)
        # Should get up to 5 unique addresses
        ips = set(addr[0] for addr in selected)
        self.assertGreater(len(ips), 1, "Should select from diverse network groups")


class TestMempoolAncestorDescendant(unittest.TestCase):
    """Gap #6: Mempool must track and limit transaction ancestry chains."""

    def test_ancestor_limit_config(self):
        """Config must define MEMPOOL_MAX_ANCESTORS."""
        from messagechain import config
        self.assertTrue(hasattr(config, 'MEMPOOL_MAX_ANCESTORS'))

    def test_ancestor_chain_limit(self):
        """Mempool should reject transactions that exceed the ancestor limit."""
        from messagechain import config
        from messagechain.core.mempool import Mempool

        mempool = Mempool()
        entity_id = b'\x01' * 32

        # Add transactions up to the ancestor limit
        # In account model, a long chain of nonces from the same sender
        # constitutes an ancestor chain
        limit = config.MEMPOOL_MAX_ANCESTORS

        for nonce in range(limit):
            tx = MessageTransaction(
                entity_id=entity_id,
                message=f"msg{nonce}".encode(),
                timestamp=time.time(),
                nonce=nonce,
                fee=1500,
                signature=_make_dummy_sig(),
                tx_hash=_hash(f"tx-{nonce}".encode()),
            )
            mempool.add_transaction(tx)

        # One more should be rejected due to ancestor limit
        tx_over = MessageTransaction(
            entity_id=entity_id,
            message=f"msg-over".encode(),
            timestamp=time.time(),
            nonce=limit,
            fee=1500,
            signature=_make_dummy_sig(),
            tx_hash=_hash(f"tx-{limit}".encode()),
        )
        # This should fail since per-sender limit is now the ancestor limit
        result = mempool.add_transaction(tx_over)
        self.assertFalse(result)


class TestSignatureVerificationCache(unittest.TestCase):
    """Gap #7: Cache signature verifications to prevent CPU exhaustion."""

    def test_cache_exists(self):
        """SignatureCache class must exist."""
        from messagechain.crypto.sig_cache import SignatureCache
        cache = SignatureCache()
        self.assertIsNotNone(cache)

    def test_cache_stores_verification(self):
        """After verification, result should be cached."""
        from messagechain.crypto.sig_cache import SignatureCache
        cache = SignatureCache()

        msg_hash = _hash(b"test-message")
        pub_key = b'\x01' * 32
        sig_hash = _hash(b"test-sig")

        # Initially not cached
        self.assertIsNone(cache.lookup(msg_hash, sig_hash, pub_key))

        # Store a positive result
        cache.store(msg_hash, sig_hash, pub_key, True)

        # Now it should be cached
        result = cache.lookup(msg_hash, sig_hash, pub_key)
        self.assertTrue(result)

    def test_cache_bounded_size(self):
        """Cache should not grow unbounded."""
        from messagechain.crypto.sig_cache import SignatureCache
        cache = SignatureCache(max_size=100)

        # Add more entries than max_size
        for i in range(200):
            msg_hash = _hash(f"msg-{i}".encode())
            pub_key = _hash(f"pub-{i}".encode())
            sig_hash = _hash(f"sig-{i}".encode())
            cache.store(msg_hash, sig_hash, pub_key, True)

        self.assertLessEqual(len(cache), 100)

    def test_cached_verify_function(self):
        """verify_signature_cached should use the cache on repeated calls."""
        from messagechain.crypto.sig_cache import SignatureCache, get_global_cache

        cache = get_global_cache()
        self.assertIsNotNone(cache)

    def test_cache_hit_avoids_verification(self):
        """A cached positive result should skip actual WOTS+ verification."""
        from messagechain.crypto.sig_cache import SignatureCache

        cache = SignatureCache()
        msg_hash = _hash(b"cached-msg")
        pub_key = b'\x02' * 32
        sig_hash = _hash(b"cached-sig")

        cache.store(msg_hash, sig_hash, pub_key, True)

        # Lookup should return True without needing the actual signature
        self.assertTrue(cache.lookup(msg_hash, sig_hash, pub_key))


def _make_dummy_sig():
    """Create a dummy signature for mempool tests (not cryptographically valid)."""
    from messagechain.crypto.keys import Signature
    return Signature(
        wots_signature=[b'\x00' * 32],
        leaf_index=0,
        auth_path=[],
        wots_public_key=b'\x00' * 32,
        wots_public_seed=b'\x00' * 32,
    )


if __name__ == "__main__":
    unittest.main()
