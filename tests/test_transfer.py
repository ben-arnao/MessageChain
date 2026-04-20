"""Tests for TransferTransaction — token transfers between entities."""

import hashlib
import time
import unittest

from messagechain.config import HASH_ALGO, MIN_FEE, GENESIS_ALLOCATION
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from tests import register_entity_for_test


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class TestTransferTransaction(unittest.TestCase):
    """Unit tests for TransferTransaction creation, signing, and verification."""

    def setUp(self):
        self.sender = Entity.create(b"sender_key".ljust(32, b"\x00"))
        self.recipient = Entity.create(b"recipient_key".ljust(32, b"\x00"))

    def test_create_transfer_transaction(self):
        """Basic creation produces a valid signed transfer."""
        from messagechain.core.transfer import create_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0)
        self.assertEqual(tx.entity_id, self.sender.entity_id)
        self.assertEqual(tx.recipient_id, self.recipient.entity_id)
        self.assertEqual(tx.amount, 50)
        self.assertEqual(tx.nonce, 0)
        self.assertGreater(tx.fee, 0)
        self.assertNotEqual(tx.tx_hash, b"")

    def test_verify_transfer_valid(self):
        """A correctly signed transfer passes verification."""
        from messagechain.core.transfer import create_transfer_transaction, verify_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0)
        self.assertTrue(verify_transfer_transaction(tx, self.sender.public_key))

    def test_verify_transfer_wrong_key(self):
        """Verification fails with wrong public key."""
        from messagechain.core.transfer import create_transfer_transaction, verify_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0)
        self.assertFalse(verify_transfer_transaction(tx, self.recipient.public_key))

    def test_transfer_zero_amount_rejected(self):
        """Amount must be > 0."""
        from messagechain.core.transfer import create_transfer_transaction
        with self.assertRaises(ValueError):
            create_transfer_transaction(self.sender, self.recipient.entity_id, 0, nonce=0)

    def test_transfer_negative_amount_rejected(self):
        """Negative amount rejected."""
        from messagechain.core.transfer import create_transfer_transaction
        with self.assertRaises(ValueError):
            create_transfer_transaction(self.sender, self.recipient.entity_id, -10, nonce=0)

    def test_transfer_self_rejected(self):
        """Cannot transfer to yourself."""
        from messagechain.core.transfer import create_transfer_transaction
        with self.assertRaises(ValueError):
            create_transfer_transaction(self.sender, self.sender.entity_id, 50, nonce=0)

    def test_transfer_low_fee_rejected(self):
        """Fee below MIN_FEE rejected in verification."""
        from messagechain.core.transfer import create_transfer_transaction, verify_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0, fee=MIN_FEE)
        # Manually tamper fee to 0 — verification should fail
        tx.fee = 0
        tx.tx_hash = tx._compute_hash()
        self.assertFalse(verify_transfer_transaction(tx, self.sender.public_key))

    def test_serialization_roundtrip(self):
        """Serialize -> deserialize produces identical transaction."""
        from messagechain.core.transfer import TransferTransaction, create_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0)
        data = tx.serialize()
        restored = TransferTransaction.deserialize(data)
        self.assertEqual(restored.entity_id, tx.entity_id)
        self.assertEqual(restored.recipient_id, tx.recipient_id)
        self.assertEqual(restored.amount, tx.amount)
        self.assertEqual(restored.nonce, tx.nonce)
        self.assertEqual(restored.fee, tx.fee)
        self.assertEqual(restored.tx_hash, tx.tx_hash)

    def test_deserialize_hash_mismatch_rejected(self):
        """Tampered hash in serialized data is detected."""
        from messagechain.core.transfer import TransferTransaction, create_transfer_transaction
        tx = create_transfer_transaction(self.sender, self.recipient.entity_id, 50, nonce=0)
        data = tx.serialize()
        data["tx_hash"] = "00" * 32  # tampered
        with self.assertRaises(ValueError):
            TransferTransaction.deserialize(data)


class TestTransferOnChain(unittest.TestCase):
    """Integration tests for transfer transactions on the blockchain."""

    def setUp(self):
        self.chain = Blockchain()
        self.genesis = Entity.create(b"genesis_key".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.genesis)

        self.recipient = Entity.create(b"recipient_key".ljust(32, b"\x00"))
        register_entity_for_test(self.chain, self.recipient)

    def test_validate_transfer_valid(self):
        """A valid transfer passes blockchain validation."""
        from messagechain.core.transfer import create_transfer_transaction

        # Genesis entity has GENESIS_ALLOCATION tokens
        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )
        tx = create_transfer_transaction(
            self.genesis, self.recipient.entity_id, 100, nonce=nonce, fee=1500,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        self.assertTrue(valid, reason)

    def test_validate_transfer_insufficient_balance(self):
        """Transfer fails if sender can't cover amount + fee."""
        from messagechain.core.transfer import create_transfer_transaction

        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )
        tx = create_transfer_transaction(
            self.genesis, self.recipient.entity_id,
            GENESIS_ALLOCATION + 1,  # more than available
            nonce=nonce, fee=1500,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("Insufficient", reason)

    def test_validate_transfer_unknown_sender_without_pubkey_reveal(self):
        """Receive-to-exist: unknown sender without sender_pubkey is rejected
        (the chain has no way to verify the signature)."""
        from messagechain.core.transfer import create_transfer_transaction
        unknown = Entity.create(b"unknown_key".ljust(32, b"\x00"))
        # include_pubkey defaults to False — without it, this unknown entity
        # cannot validate.
        tx = create_transfer_transaction(
            unknown, self.recipient.entity_id, 50, nonce=0, fee=1500,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("sender_pubkey", reason.lower())

    def test_validate_transfer_unknown_sender_with_first_spend_reveal(self):
        """Receive-to-exist: unknown sender WITH valid sender_pubkey passes
        validation (modulo balance — for this test we just verify the
        error is no longer about the sender being unknown)."""
        from messagechain.core.transfer import create_transfer_transaction
        unknown = Entity.create(b"unknown_key_rev".ljust(32, b"\x00"))
        tx = create_transfer_transaction(
            unknown, self.recipient.entity_id, 50, nonce=0, fee=1500,
            include_pubkey=True,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        # Will fail on "Insufficient spendable balance" (unknown entity has 0)
        # but NOT on "Unknown sender" — that's the behavior change.
        self.assertFalse(valid)
        self.assertIn("insufficient", reason.lower())

    def test_validate_transfer_unknown_recipient_is_accepted(self):
        """Receive-to-exist: unknown recipient is accepted — they get
        a balance entry on apply."""
        from messagechain.core.transfer import create_transfer_transaction
        unknown = Entity.create(b"unknown_recipient".ljust(32, b"\x00"))
        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )
        tx = create_transfer_transaction(
            self.genesis, unknown.entity_id, 50, nonce=nonce, fee=1500,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        self.assertTrue(valid, f"Unknown recipient should validate: {reason}")

    def test_validate_transfer_wrong_nonce(self):
        """Wrong nonce is rejected."""
        from messagechain.core.transfer import create_transfer_transaction
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )
        tx = create_transfer_transaction(
            self.genesis, self.recipient.entity_id, 50, nonce=999, fee=1500,
        )
        valid, reason = self.chain.validate_transfer_transaction(tx)
        self.assertFalse(valid)
        self.assertIn("nonce", reason.lower())

    def test_apply_transfer_balances(self):
        """Applying a transfer moves tokens correctly."""
        from messagechain.core.transfer import create_transfer_transaction

        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )

        amount = 500
        fee = 500
        proposer_id = self.genesis.entity_id

        sender_before = self.chain.supply.get_balance(self.genesis.entity_id)
        recipient_before = self.chain.supply.get_balance(self.recipient.entity_id)

        tx = create_transfer_transaction(
            self.genesis, self.recipient.entity_id, amount, nonce=nonce, fee=fee,
        )
        self.chain.apply_transfer_transaction(tx, proposer_id)

        sender_after = self.chain.supply.get_balance(self.genesis.entity_id)
        recipient_after = self.chain.supply.get_balance(self.recipient.entity_id)

        # Sender loses amount + fee, but gets fee back as proposer
        self.assertEqual(sender_after, sender_before - amount - fee + fee)
        # Recipient gains amount
        self.assertEqual(recipient_after, recipient_before + amount)
        # Nonce incremented
        self.assertEqual(self.chain.nonces[self.genesis.entity_id], nonce + 1)

    def test_transfer_in_block(self):
        """Transfer transactions are included in blocks and applied."""
        from messagechain.core.transfer import create_transfer_transaction
        from messagechain.consensus.pos import ProofOfStake

        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )

        amount = 100
        tx = create_transfer_transaction(
            self.genesis, self.recipient.entity_id, amount, nonce=nonce, fee=1500,
        )

        recipient_before = self.chain.supply.get_balance(self.recipient.entity_id)

        # Create block with the transfer
        consensus = ProofOfStake()
        block = self.chain.propose_block(
            consensus, self.genesis, [],  # no message txs
            transfer_transactions=[tx],
        )

        success, reason = self.chain.add_block(block)
        self.assertTrue(success, reason)

        recipient_after = self.chain.supply.get_balance(self.recipient.entity_id)
        self.assertEqual(recipient_after, recipient_before + amount)


class TestTransferCLI(unittest.TestCase):
    """Test CLI parser accepts transfer commands."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_transfer_command(self):
        args = self.parser.parse_args(["transfer", "--to", "ab" * 32, "--amount", "100"])
        self.assertEqual(args.command, "transfer")
        self.assertEqual(args.amount, 100)

    def test_transfer_with_fee(self):
        args = self.parser.parse_args(["transfer", "--to", "ab" * 32, "--amount", "50", "--fee", "5"])
        self.assertEqual(args.fee, 5)

    def test_transfer_with_server(self):
        args = self.parser.parse_args(["transfer", "--to", "ab" * 32, "--amount", "50", "--server", "10.0.0.1:9334"])
        self.assertEqual(args.server, "10.0.0.1:9334")


class TestBalanceCLI(unittest.TestCase):
    """Test CLI parser accepts balance command."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_balance_command(self):
        args = self.parser.parse_args(["balance"])
        self.assertEqual(args.command, "balance")

    def test_balance_with_server(self):
        args = self.parser.parse_args(["balance", "--server", "10.0.0.1:9334"])
        self.assertEqual(args.server, "10.0.0.1:9334")


class TestStakeUnstakeCLI(unittest.TestCase):
    """Test CLI parser accepts stake/unstake commands."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_stake_command(self):
        args = self.parser.parse_args(["stake", "--amount", "100"])
        self.assertEqual(args.command, "stake")
        self.assertEqual(args.amount, 100)

    def test_stake_with_fee(self):
        args = self.parser.parse_args(["stake", "--amount", "100", "--fee", "5"])
        self.assertEqual(args.fee, 5)

    def test_unstake_command(self):
        args = self.parser.parse_args(["unstake", "--amount", "50"])
        self.assertEqual(args.command, "unstake")
        self.assertEqual(args.amount, 50)

    def test_unstake_with_fee(self):
        args = self.parser.parse_args(["unstake", "--amount", "50", "--fee", "3"])
        self.assertEqual(args.fee, 3)


class TestGenerateKeyCLI(unittest.TestCase):
    """Test CLI parser accepts generate-key command."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_generate_key_command(self):
        args = self.parser.parse_args(["generate-key"])
        self.assertEqual(args.command, "generate-key")


class TestReadCLI(unittest.TestCase):
    """Test CLI parser accepts read command."""

    def setUp(self):
        from messagechain.cli import build_parser
        self.parser = build_parser()

    def test_read_command(self):
        args = self.parser.parse_args(["read"])
        self.assertEqual(args.command, "read")

    def test_read_with_last(self):
        args = self.parser.parse_args(["read", "--last", "20"])
        self.assertEqual(args.last, 20)

    def test_read_with_server(self):
        args = self.parser.parse_args(["read", "--last", "5", "--server", "10.0.0.1:9334"])
        self.assertEqual(args.server, "10.0.0.1:9334")


class TestReadMessages(unittest.TestCase):
    """Tests for reading messages from the blockchain."""

    def setUp(self):
        self.chain = Blockchain()
        self.genesis = Entity.create(b"genesis_key".ljust(32, b"\x00"))
        self.chain.initialize_genesis(self.genesis)

    def test_get_recent_messages_empty(self):
        """Empty chain returns empty list."""
        messages = self.chain.get_recent_messages(10)
        self.assertEqual(messages, [])

    def test_get_recent_messages_returns_messages(self):
        """Messages from blocks are returned."""
        from messagechain.core.transaction import create_transaction
        from messagechain.consensus.pos import ProofOfStake

        nonce = self.chain.nonces[self.genesis.entity_id]
        self.genesis.keypair.advance_to_leaf(
            self.chain.get_wots_leaves_used(self.genesis.entity_id)
        )
        tx = create_transaction(self.genesis, "Hello chain!", fee=1500, nonce=nonce)

        consensus = ProofOfStake()
        block = self.chain.propose_block(consensus, self.genesis, [tx])
        success, _ = self.chain.add_block(block)
        self.assertTrue(success)

        messages = self.chain.get_recent_messages(10)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["message"], "Hello chain!")

    def test_get_recent_messages_respects_count(self):
        """Only returns the requested number of messages."""
        from messagechain.core.transaction import create_transaction
        from messagechain.consensus.pos import ProofOfStake

        consensus = ProofOfStake()

        for i in range(3):
            nonce = self.chain.nonces[self.genesis.entity_id]
            self.genesis.keypair.advance_to_leaf(
                self.chain.get_wots_leaves_used(self.genesis.entity_id)
            )
            tx = create_transaction(self.genesis, f"Message {i}", fee=1500, nonce=nonce)
            block = self.chain.propose_block(consensus, self.genesis, [tx])
            self.chain.add_block(block)

        messages = self.chain.get_recent_messages(2)
        self.assertEqual(len(messages), 2)

    def test_get_recent_messages_most_recent_first(self):
        """Most recent messages come first."""
        from messagechain.core.transaction import create_transaction
        from messagechain.consensus.pos import ProofOfStake

        consensus = ProofOfStake()

        for i in range(3):
            nonce = self.chain.nonces[self.genesis.entity_id]
            self.genesis.keypair.advance_to_leaf(
                self.chain.get_wots_leaves_used(self.genesis.entity_id)
            )
            tx = create_transaction(self.genesis, f"Message {i}", fee=1500, nonce=nonce)
            block = self.chain.propose_block(consensus, self.genesis, [tx])
            self.chain.add_block(block)

        messages = self.chain.get_recent_messages(10)
        self.assertEqual(messages[0]["message"], "Message 2")
        self.assertEqual(messages[1]["message"], "Message 1")
        self.assertEqual(messages[2]["message"], "Message 0")


if __name__ == "__main__":
    unittest.main()
