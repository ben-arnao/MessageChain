"""Integration tests for the full MessageChain."""

import unittest
from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction, verify_transaction
from messagechain.core.mempool import Mempool
from messagechain.consensus.pos import ProofOfStake


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris")
        self.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.register_entity(self.bob)
        # Fund test entities so they can pay fees
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.consensus = ProofOfStake()

    def test_genesis_block(self):
        self.assertEqual(self.chain.height, 1)
        genesis = self.chain.get_block(0)
        self.assertIsNotNone(genesis)

    def test_duplicate_entity_rejected(self):
        """Same biometrics cannot register twice — one person one wallet."""
        alice_dup = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris")
        success, msg = self.chain.register_entity(alice_dup)
        self.assertFalse(success)
        self.assertIn("duplicate", msg.lower())

    def test_post_message(self):
        tx = create_transaction(
            self.alice, "Hello world!", BiometricType.FINGERPRINT,
            fee=10, nonce=0
        )
        valid, reason = self.chain.validate_transaction(tx)
        self.assertTrue(valid, reason)

    def test_create_and_add_block(self):
        tx = create_transaction(
            self.alice, "Test message", BiometricType.DNA,
            fee=5, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = self.consensus.create_block(self.alice, [tx], prev)
        success, reason = self.chain.add_block(block)
        self.assertTrue(success, reason)
        self.assertEqual(self.chain.height, 2)

    def test_fee_goes_to_proposer(self):
        """Block proposer collects fees from transactions."""
        alice_balance_before = self.chain.supply.get_balance(self.alice.entity_id)
        tx = create_transaction(
            self.bob, "Bob pays fee", BiometricType.IRIS,
            fee=20, nonce=0
        )
        prev = self.chain.get_latest_block()
        # Alice proposes the block, collects Bob's fee + block reward
        block = self.consensus.create_block(self.alice, [tx], prev)
        self.chain.add_block(block)

        alice_balance_after = self.chain.supply.get_balance(self.alice.entity_id)
        # Alice gained: fee (20) + block reward (50)
        self.assertGreater(alice_balance_after, alice_balance_before)

    def test_inflation_over_blocks(self):
        """Supply increases with each block (inflation via block rewards)."""
        initial_supply = self.chain.supply.total_supply
        for i in range(5):
            entity = self.alice if i % 2 == 0 else self.bob
            nonce = self.chain.nonces.get(entity.entity_id, 0)
            tx = create_transaction(
                entity, f"Message {i}", BiometricType.DNA,
                fee=5, nonce=nonce
            )
            prev = self.chain.get_latest_block()
            block = self.consensus.create_block(entity, [tx], prev)
            self.chain.add_block(block)

        self.assertGreater(self.chain.supply.total_supply, initial_supply)
        self.assertGreater(self.chain.supply.total_minted, 0)

    def test_fee_bidding_priority(self):
        """Higher fee transactions are prioritized in mempool."""
        mempool = Mempool()
        nonce = self.chain.nonces.get(self.alice.entity_id, 0)

        low = create_transaction(self.alice, "low fee", BiometricType.DNA, fee=1, nonce=nonce)
        high = create_transaction(self.alice, "high fee", BiometricType.DNA, fee=100, nonce=nonce + 1)
        mid = create_transaction(self.alice, "mid fee", BiometricType.DNA, fee=10, nonce=nonce + 2)

        mempool.add_transaction(low)
        mempool.add_transaction(high)
        mempool.add_transaction(mid)

        ordered = mempool.get_transactions(10)
        self.assertEqual(ordered[0].fee, 100)  # highest first
        self.assertEqual(ordered[1].fee, 10)
        self.assertEqual(ordered[2].fee, 1)

    def test_biometric_type_recorded(self):
        for bio_type in BiometricType:
            nonce = self.chain.nonces.get(self.alice.entity_id, 0)
            tx = create_transaction(
                self.alice, f"Signed with {bio_type.value}",
                bio_type, fee=5, nonce=nonce
            )
            prev = self.chain.get_latest_block()
            block = self.consensus.create_block(self.alice, [tx], prev)
            self.chain.add_block(block)
            stored_tx = self.chain.chain[-1].transactions[0]
            self.assertEqual(stored_tx.biometric_type, bio_type)

    def test_timestamp_present(self):
        """Every transaction must be timestamped."""
        tx = create_transaction(
            self.alice, "Timestamped message", BiometricType.FINGERPRINT,
            fee=5, nonce=0
        )
        self.assertGreater(tx.timestamp, 0)

    def test_invalid_nonce_rejected(self):
        tx = create_transaction(
            self.alice, "Test", BiometricType.DNA,
            fee=5, nonce=99  # wrong nonce
        )
        valid, reason = self.chain.validate_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("nonce", reason.lower())

    def test_message_too_long_rejected(self):
        long_msg = " ".join(["word"] * 101)  # 101 words
        with self.assertRaises(ValueError):
            create_transaction(
                self.alice, long_msg, BiometricType.DNA,
                fee=5, nonce=0
            )

    def test_100_words_accepted(self):
        msg = " ".join(["word"] * 100)  # exactly 100 words
        tx = create_transaction(
            self.alice, msg, BiometricType.DNA,
            fee=5, nonce=0
        )
        self.assertIsNotNone(tx)

    def test_chain_info(self):
        info = self.chain.get_chain_info()
        self.assertIn("height", info)
        self.assertIn("total_supply", info)
        self.assertIn("registered_entities", info)
        self.assertEqual(info["registered_entities"], 2)

    def test_block_serialization_roundtrip(self):
        tx = create_transaction(
            self.alice, "Serialize me", BiometricType.FINGERPRINT,
            fee=15, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = self.consensus.create_block(self.alice, [tx], prev)

        data = block.serialize()
        from messagechain.core.block import Block
        restored = Block.deserialize(data)
        self.assertEqual(restored.block_hash, block.block_hash)
        self.assertEqual(len(restored.transactions), 1)
        self.assertEqual(restored.transactions[0].fee, 15)


if __name__ == "__main__":
    unittest.main()
