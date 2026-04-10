"""Tests for critical security fixes from the security audit."""

import unittest
import time
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.crypto.keys import Signature
from tests import register_entity_for_test


class TestHashVerificationOnDeserialize(unittest.TestCase):
    """Fix #2: Reject deserialized objects with spoofed hashes."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 10000

    def test_tx_with_spoofed_hash_rejected(self):
        """A transaction with a tampered tx_hash must be rejected on deserialize."""
        tx = create_transaction(
            self.alice, "Legit message", fee=500, nonce=0
        )
        data = tx.serialize()
        # Tamper with the hash
        data["tx_hash"] = "aa" * 32
        with self.assertRaises(ValueError) as ctx:
            MessageTransaction.deserialize(data)
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_tx_with_correct_hash_accepted(self):
        """A transaction with a correct hash deserializes without error."""
        tx = create_transaction(
            self.alice, "Legit message", fee=500, nonce=0
        )
        data = tx.serialize()
        restored = MessageTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_block_with_spoofed_hash_rejected(self):
        """A block with a tampered block_hash must be rejected on deserialize."""
        consensus = ProofOfStake()
        tx = create_transaction(
            self.alice, "Block test", fee=500, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = consensus.create_block(self.alice, [tx], prev)
        data = block.serialize()
        # Tamper with the hash
        data["block_hash"] = "bb" * 32
        with self.assertRaises(ValueError) as ctx:
            Block.deserialize(data)
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_block_with_correct_hash_accepted(self):
        """A block with a correct hash deserializes without error."""
        consensus = ProofOfStake()
        tx = create_transaction(
            self.alice, "Block test", fee=500, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = consensus.create_block(self.alice, [tx], prev)
        data = block.serialize()
        restored = Block.deserialize(data)
        self.assertEqual(restored.block_hash, block.block_hash)


class TestMandatoryProposerSignature(unittest.TestCase):
    """Fix #5: Unsigned blocks must be rejected."""

    def setUp(self):
        self.alice = Entity.create(b"alice-private-key")
        self.bob = Entity.create(b"bob-private-key")
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000

    def test_unsigned_block_rejected(self):
        """A block with no proposer signature must be rejected."""
        tx = create_transaction(
            self.bob, "Unsigned block test", fee=500, nonce=0
        )
        prev = self.chain.get_latest_block()
        from messagechain.core.block import compute_merkle_root
        merkle_root = compute_merkle_root([tx.tx_hash])

        header = BlockHeader(
            version=1,
            block_number=prev.header.block_number + 1,
            prev_hash=prev.block_hash,
            merkle_root=merkle_root,
            timestamp=time.time(),
            proposer_id=self.alice.entity_id,
            proposer_signature=None,  # NO SIGNATURE
        )
        block = Block(header=header, transactions=[tx])
        block.block_hash = block._compute_hash()

        valid, reason = self.chain.validate_block(block)
        self.assertFalse(valid)
        self.assertIn("signature", reason.lower())

    def test_signed_block_accepted(self):
        """A properly signed block is accepted."""
        consensus = ProofOfStake()
        tx = create_transaction(
            self.bob, "Signed block test", fee=500, nonce=0
        )
        prev = self.chain.get_latest_block()
        block = consensus.create_block(self.alice, [tx], prev)
        valid, reason = self.chain.validate_block(block)
        self.assertTrue(valid, reason)


class TestRegisterEntityPublicOnly(unittest.TestCase):
    """Fix #3/#4: Registration must accept only public data (entity_id + public_key)."""

    def test_register_with_public_data_only(self):
        """register_entity accepts entity_id and public_key, not Entity objects."""
        alice = Entity.create(b"alice-private-key")
        bob = Entity.create(b"bob-private-key")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        # Register using only public data + registration proof
        success, msg = register_entity_for_test(chain, bob)
        self.assertTrue(success)
        self.assertEqual(chain.public_keys[bob.entity_id], bob.public_key)
        self.assertEqual(chain.nonces[bob.entity_id], 0)

    def test_duplicate_public_data_rejected(self):
        """Duplicate entity_id is still rejected."""
        alice = Entity.create(b"alice-private-key")
        chain = Blockchain()
        chain.initialize_genesis(alice)

        # Alice is already registered via initialize_genesis
        success, msg = register_entity_for_test(chain, alice)
        self.assertFalse(success)
        self.assertIn("duplicate", msg.lower())


if __name__ == "__main__":
    unittest.main()
