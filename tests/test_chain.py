"""Integration tests for the full MessageChain."""

import unittest
from messagechain.identity.biometrics import Entity, BiometricType
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction, verify_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.deflation import SupplyTracker


class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-dna", b"alice-finger", b"alice-iris")
        self.bob = Entity.create(b"bob-dna", b"bob-finger", b"bob-iris")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.register_entity(self.bob)
        self.consensus = ProofOfStake()

    def test_genesis_block(self):
        self.assertEqual(self.chain.height, 1)
        genesis = self.chain.get_block(0)
        self.assertIsNotNone(genesis)

    def test_post_message(self):
        tx = create_transaction(
            self.alice, "Hello world!", BiometricType.FINGERPRINT,
            self.chain.supply, nonce=0
        )
        valid, reason = self.chain.validate_transaction(tx)
        self.assertTrue(valid, reason)

    def test_create_and_add_block(self):
        tx = create_transaction(
            self.alice, "Test message", BiometricType.DNA,
            self.chain.supply, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = self.consensus.create_block(self.alice, [tx], prev)
        success, reason = self.chain.add_block(block)
        self.assertTrue(success, reason)
        self.assertEqual(self.chain.height, 2)

    def test_multiple_entities_posting(self):
        # Alice posts
        tx1 = create_transaction(
            self.alice, "Alice's message", BiometricType.IRIS,
            self.chain.supply, nonce=0
        )
        prev = self.chain.get_latest_block()
        block1 = self.consensus.create_block(self.alice, [tx1], prev)
        self.chain.add_block(block1)

        # Bob posts
        tx2 = create_transaction(
            self.bob, "Bob's message", BiometricType.FINGERPRINT,
            self.chain.supply, nonce=0
        )
        prev = self.chain.get_latest_block()
        block2 = self.consensus.create_block(self.bob, [tx2], prev)
        success, reason = self.chain.add_block(block2)
        self.assertTrue(success, reason)

    def test_deflation_over_messages(self):
        initial_supply = self.chain.supply.total_supply
        for i in range(5):
            entity = self.alice if i % 2 == 0 else self.bob
            nonce = self.chain.nonces.get(entity.entity_id, 0)
            tx = create_transaction(
                entity, f"Message {i}", BiometricType.DNA,
                self.chain.supply, nonce=nonce
            )
            prev = self.chain.get_latest_block()
            block = self.consensus.create_block(entity, [tx], prev)
            self.chain.add_block(block)

        self.assertLess(self.chain.supply.total_supply, initial_supply)
        self.assertGreater(self.chain.supply.total_burned, 0)

    def test_biometric_type_recorded(self):
        for bio_type in BiometricType:
            nonce = self.chain.nonces.get(self.alice.entity_id, 0)
            tx = create_transaction(
                self.alice, f"Signed with {bio_type.value}",
                bio_type, self.chain.supply, nonce=nonce
            )
            prev = self.chain.get_latest_block()
            block = self.consensus.create_block(self.alice, [tx], prev)
            self.chain.add_block(block)
            # Verify the biometric type is preserved
            stored_tx = self.chain.chain[-1].transactions[0]
            self.assertEqual(stored_tx.biometric_type, bio_type)

    def test_invalid_nonce_rejected(self):
        tx = create_transaction(
            self.alice, "Test", BiometricType.DNA,
            self.chain.supply, nonce=99  # wrong nonce
        )
        valid, reason = self.chain.validate_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("nonce", reason.lower())

    def test_message_too_long_rejected(self):
        with self.assertRaises(ValueError):
            create_transaction(
                self.alice, "x" * 300, BiometricType.DNA,
                self.chain.supply, nonce=0
            )

    def test_chain_info(self):
        info = self.chain.get_chain_info()
        self.assertIn("height", info)
        self.assertIn("total_supply", info)
        self.assertIn("registered_entities", info)
        self.assertEqual(info["registered_entities"], 2)

    def test_block_serialization_roundtrip(self):
        tx = create_transaction(
            self.alice, "Serialize me", BiometricType.FINGERPRINT,
            self.chain.supply, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = self.consensus.create_block(self.alice, [tx], prev)

        data = block.serialize()
        from messagechain.core.block import Block
        restored = Block.deserialize(data)
        self.assertEqual(restored.block_hash, block.block_hash)
        self.assertEqual(len(restored.transactions), 1)
        self.assertEqual(restored.transactions[0].message, tx.message)


if __name__ == "__main__":
    unittest.main()
