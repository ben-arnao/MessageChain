"""
Tests for critical security audit fixes.

Covers:
1. Infinite loop fix in find_common_ancestor
2. WOTS+ leaf tracking for all signature types
3. Hash verification on deserialize for SlashTx, Evidence, KeyRotation
4. Stake/unstake must go through on-chain transactions
5. Stake/unstake signature replay protection (nonce)
6. Genesis entity must not use hardcoded keys
7. Attestation and slash gossip handlers exist
"""

import hashlib
import struct
import time
import unittest

from messagechain.config import HASH_ALGO, MERKLE_TREE_HEIGHT, SLASH_FINDER_REWARD_PCT
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, create_genesis_block, _hash
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.slashing import (
    SlashingEvidence, AttestationSlashingEvidence, SlashTransaction,
    create_slash_transaction,
)
from messagechain.consensus.attestation import Attestation, create_attestation
from messagechain.consensus.fork_choice import find_common_ancestor, MAX_REORG_DEPTH
from messagechain.core.key_rotation import KeyRotationTransaction, create_key_rotation, derive_rotated_keypair
from messagechain.crypto.keys import KeyPair, Signature
from tests import register_entity_for_test


def _make_entity(name: str) -> Entity:
    return Entity.create(f"{name}-privkey".encode().ljust(32, b"\x00"))


class TestForkChoiceInfiniteLoop(unittest.TestCase):
    """Fix #1: find_common_ancestor must not hang on any input."""

    def test_find_common_ancestor_does_not_hang(self):
        """The old code had a while/pass infinite loop. Verify it terminates."""
        entity = _make_entity("fork-test")
        genesis = create_genesis_block(entity)

        # Build two diverging chains from genesis
        blocks = {genesis.block_hash: genesis}

        def make_block(parent, proposer, n):
            header = BlockHeader(
                version=1,
                block_number=n,
                prev_hash=parent.block_hash,
                merkle_root=_hash(b"empty"),
                timestamp=time.time(),
                proposer_id=proposer.entity_id,
            )
            header_hash = _hash(header.signable_data())
            header.proposer_signature = proposer.keypair.sign(header_hash)
            block = Block(header=header, transactions=[])
            block.block_hash = block._compute_hash()
            blocks[block.block_hash] = block
            return block

        # Chain A: genesis -> A1 -> A2 -> A3
        a1 = make_block(genesis, entity, 1)
        a2 = make_block(a1, entity, 2)
        a3 = make_block(a2, entity, 3)

        # Chain B: genesis -> B1 -> B2 -> B3
        entity_b = _make_entity("fork-b")
        b1 = make_block(genesis, entity_b, 1)
        b2 = make_block(b1, entity_b, 2)
        b3 = make_block(b2, entity_b, 3)

        def get_block(h):
            return blocks.get(h)

        # This should find genesis as common ancestor and NOT hang
        ancestor, rollback, apply_ = find_common_ancestor(
            a3.block_hash, b3.block_hash, get_block
        )
        self.assertEqual(ancestor, genesis.block_hash)
        self.assertEqual(len(rollback), 3)
        self.assertEqual(len(apply_), 3)

    def test_find_common_ancestor_asymmetric_chains(self):
        """Test where one chain is longer than the other."""
        entity = _make_entity("asym")
        genesis = create_genesis_block(entity)
        blocks = {genesis.block_hash: genesis}

        def make_block(parent, proposer, n):
            header = BlockHeader(
                version=1, block_number=n, prev_hash=parent.block_hash,
                merkle_root=_hash(b"empty"), timestamp=time.time(),
                proposer_id=proposer.entity_id,
            )
            header_hash = _hash(header.signable_data())
            header.proposer_signature = proposer.keypair.sign(header_hash)
            block = Block(header=header, transactions=[])
            block.block_hash = block._compute_hash()
            blocks[block.block_hash] = block
            return block

        # Chain A: genesis -> A1
        a1 = make_block(genesis, entity, 1)

        # Chain B: genesis -> B1 -> B2 -> B3
        entity_b = _make_entity("asym-b")
        b1 = make_block(genesis, entity_b, 1)
        b2 = make_block(b1, entity_b, 2)
        b3 = make_block(b2, entity_b, 3)

        def get_block(h):
            return blocks.get(h)

        ancestor, rollback, apply_ = find_common_ancestor(
            a1.block_hash, b3.block_hash, get_block
        )
        self.assertEqual(ancestor, genesis.block_hash)
        self.assertEqual(len(rollback), 1)
        self.assertEqual(len(apply_), 3)


class TestDeserializeHashVerification(unittest.TestCase):
    """Fix #3: All deserialize methods must recompute and verify hashes."""

    def test_slash_transaction_rejects_tampered_hash(self):
        """SlashTransaction.deserialize must reject mismatched tx_hash."""
        entity_a = _make_entity("slash-a")
        entity_b = _make_entity("slash-b")

        # Create two different headers at same height (double-sign evidence)
        header_a = BlockHeader(
            version=1, block_number=5, prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"a"), timestamp=1.0,
            proposer_id=entity_a.entity_id,
        )
        header_a.proposer_signature = entity_a.keypair.sign(
            _hash(header_a.signable_data())
        )
        header_b = BlockHeader(
            version=1, block_number=5, prev_hash=b"\x01" * 32,
            merkle_root=_hash(b"b"), timestamp=2.0,
            proposer_id=entity_a.entity_id,
        )
        header_b.proposer_signature = entity_a.keypair.sign(
            _hash(header_b.signable_data())
        )

        evidence = SlashingEvidence(
            offender_id=entity_a.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx = create_slash_transaction(entity_b, evidence)

        # Serialize, tamper with tx_hash, try to deserialize
        data = slash_tx.serialize()
        data["tx_hash"] = "ab" * 32  # tampered
        with self.assertRaises(ValueError):
            SlashTransaction.deserialize(data)

    def test_slashing_evidence_rejects_tampered_hash(self):
        """SlashingEvidence.deserialize must reject mismatched evidence_hash."""
        entity = _make_entity("ev-tamper")
        header_a = BlockHeader(
            version=1, block_number=5, prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"a"), timestamp=1.0,
            proposer_id=entity.entity_id,
        )
        header_a.proposer_signature = entity.keypair.sign(
            _hash(header_a.signable_data())
        )
        header_b = BlockHeader(
            version=1, block_number=5, prev_hash=b"\x01" * 32,
            merkle_root=_hash(b"b"), timestamp=2.0,
            proposer_id=entity.entity_id,
        )
        header_b.proposer_signature = entity.keypair.sign(
            _hash(header_b.signable_data())
        )

        evidence = SlashingEvidence(
            offender_id=entity.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        data = evidence.serialize()
        data["evidence_hash"] = "cd" * 32  # tampered
        with self.assertRaises(ValueError):
            SlashingEvidence.deserialize(data)

    def test_attestation_slashing_evidence_rejects_tampered_hash(self):
        """AttestationSlashingEvidence.deserialize must reject mismatched hash."""
        entity = _make_entity("att-ev-tamper")
        att_a = create_attestation(entity, b"\x01" * 32, 5)
        att_b = create_attestation(entity, b"\x02" * 32, 5)
        evidence = AttestationSlashingEvidence(
            offender_id=entity.entity_id,
            attestation_a=att_a,
            attestation_b=att_b,
        )
        data = evidence.serialize()
        data["evidence_hash"] = "ef" * 32  # tampered
        with self.assertRaises(ValueError):
            AttestationSlashingEvidence.deserialize(data)

    def test_key_rotation_rejects_tampered_hash(self):
        """KeyRotationTransaction.deserialize must reject mismatched tx_hash."""
        entity = _make_entity("kr-tamper")
        new_kp = derive_rotated_keypair(entity, 0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)

        data = rot_tx.serialize()
        data["tx_hash"] = "ff" * 32  # tampered
        with self.assertRaises(ValueError):
            KeyRotationTransaction.deserialize(data)


class TestWotsLeafTracking(unittest.TestCase):
    """Fix #2: WOTS+ leaf tracking must count ALL signature types."""

    def _setup_chain_with_validator(self):
        """Set up a blockchain with a registered, staked validator."""
        proposer = _make_entity("proposer")
        validator = _make_entity("validator")

        chain = Blockchain()
        chain.initialize_genesis(proposer)
        register_entity_for_test(chain, validator)

        # Give validator some balance and stake
        chain.supply.balances[validator.entity_id] = 10000
        chain.supply.stake(validator.entity_id, 1000)

        return chain, proposer, validator

    def test_attestation_signature_counted(self):
        """Attestation signatures must be counted in WOTS+ leaf tracking."""
        chain, proposer, validator = self._setup_chain_with_validator()

        # Validator creates an attestation (consumes a WOTS+ leaf)
        genesis = chain.get_latest_block()
        att = create_attestation(validator, genesis.block_hash, 0)

        # Create a block that includes this attestation (with correct state root)
        pos = ProofOfStake()
        pos.stakes[proposer.entity_id] = 1000
        state_root = chain.compute_post_state_root(
            [], proposer.entity_id, 1, attestations=[att],
        )
        block = pos.create_block(
            proposer, [], genesis,
            state_root=state_root, attestations=[att],
        )
        chain.add_block(block)

        # The validator signed one attestation, so leaf count should include it
        leaves = chain.get_wots_leaves_used(validator.entity_id)
        self.assertGreaterEqual(leaves, 1,
            "Attestation signature must be counted in WOTS+ leaf tracking")

    def test_slash_submission_signature_counted(self):
        """Slash transaction submitter signatures must be counted."""
        chain, proposer, validator = self._setup_chain_with_validator()

        # The slash submission itself consumes a WOTS+ leaf from the submitter
        # We just need to verify the counter tracks it
        # Simulate: submitter has submitted 1 slash tx
        chain.slash_sig_counts[validator.entity_id] = 1

        leaves = chain.get_wots_leaves_used(validator.entity_id)
        self.assertGreaterEqual(leaves, 1,
            "Slash submission signature must be counted")

    def test_key_rotation_signature_counted(self):
        """Key rotation signatures must be counted in WOTS+ leaf tracking."""
        chain, proposer, validator = self._setup_chain_with_validator()

        # Key rotation consumes a WOTS+ leaf
        chain.key_rotation_counts[validator.entity_id] = 1

        leaves = chain.get_wots_leaves_used(validator.entity_id)
        # Should include the key rotation count
        self.assertGreaterEqual(leaves, 1,
            "Key rotation signature must be counted")


class TestStakeUnstakeOnChain(unittest.TestCase):
    """Fix #4 & #5: Stake/unstake must be on-chain transactions with replay protection."""

    def test_stake_transaction_has_nonce(self):
        """StakeTransaction must include a nonce for replay protection."""
        from messagechain.core.staking import StakeTransaction
        entity = _make_entity("stake-nonce")
        tx = StakeTransaction(
            entity_id=entity.entity_id,
            amount=100,
            nonce=0,
            timestamp=time.time(),
            fee=1500,
            signature=Signature([], 0, [], b"", b""),
        )
        self.assertEqual(tx.nonce, 0)

    def test_stake_transaction_serialize_deserialize(self):
        """StakeTransaction must survive serialize/deserialize with hash verification."""
        from messagechain.core.staking import StakeTransaction, create_stake_transaction
        entity = _make_entity("stake-serde")
        tx = create_stake_transaction(entity, amount=100, nonce=0)

        data = tx.serialize()
        restored = StakeTransaction.deserialize(data)
        self.assertEqual(restored.entity_id, tx.entity_id)
        self.assertEqual(restored.amount, tx.amount)
        self.assertEqual(restored.nonce, tx.nonce)

    def test_stake_transaction_rejects_tampered_hash(self):
        """StakeTransaction.deserialize must reject tampered tx_hash."""
        from messagechain.core.staking import StakeTransaction, create_stake_transaction
        entity = _make_entity("stake-tamper")
        tx = create_stake_transaction(entity, amount=100, nonce=0)

        data = tx.serialize()
        data["tx_hash"] = "ab" * 32
        with self.assertRaises(ValueError):
            StakeTransaction.deserialize(data)

    def test_unstake_transaction_has_nonce(self):
        """UnstakeTransaction must include a nonce for replay protection."""
        from messagechain.core.staking import UnstakeTransaction
        entity = _make_entity("unstake-nonce")
        tx = UnstakeTransaction(
            entity_id=entity.entity_id,
            amount=50,
            nonce=0,
            timestamp=time.time(),
            fee=1500,
            signature=Signature([], 0, [], b"", b""),
        )
        self.assertEqual(tx.nonce, 0)


class TestGenesisNotHardcoded(unittest.TestCase):
    """Fix #6: Genesis entity must not use publicly-known hardcoded keys."""

    def test_genesis_uses_random_key(self):
        """Two server instances must produce different genesis entities."""
        # The old code used hardcoded deterministic keys which are public.
        # The fix should use os.urandom.
        # We verify by checking the code doesn't pass hardcoded byte literals to Entity.create
        import inspect
        import server as server_module
        source = inspect.getsource(server_module.Server.start)
        # Check that the actual Entity.create call doesn't use hardcoded strings
        self.assertNotIn('b"genesis-key"', source,
            "Server must not use hardcoded genesis keys")
        self.assertNotIn("b'genesis-key'", source,
            "Server must not use hardcoded genesis keys")
        # Verify os.urandom is used instead
        self.assertIn("os.urandom", source,
            "Server must use os.urandom for genesis key")


class TestAttestationSlashGossip(unittest.TestCase):
    """Fix #7: Node must handle ANNOUNCE_ATTESTATION and ANNOUNCE_SLASH messages."""

    def test_node_handles_attestation_message_type(self):
        """Node._handle_message must have a handler for ANNOUNCE_ATTESTATION."""
        from messagechain.network.node import Node
        from messagechain.network.protocol import MessageType
        import inspect

        source = inspect.getsource(Node._handle_message)
        self.assertIn("ANNOUNCE_ATTESTATION", source,
            "Node must handle ANNOUNCE_ATTESTATION messages")

    def test_node_handles_slash_message_type(self):
        """Node._handle_message must have a handler for ANNOUNCE_SLASH."""
        from messagechain.network.node import Node
        from messagechain.network.protocol import MessageType
        import inspect

        source = inspect.getsource(Node._handle_message)
        self.assertIn("ANNOUNCE_SLASH", source,
            "Node must handle ANNOUNCE_SLASH messages")

    def test_server_handles_attestation_message_type(self):
        """Server._handle_p2p_message must have a handler for ANNOUNCE_ATTESTATION."""
        import server as server_module
        import inspect

        source = inspect.getsource(server_module.Server._handle_p2p_message)
        self.assertIn("ANNOUNCE_ATTESTATION", source,
            "Server must handle ANNOUNCE_ATTESTATION messages")

    def test_server_handles_slash_message_type(self):
        """Server._handle_p2p_message must have a handler for ANNOUNCE_SLASH."""
        import server as server_module
        import inspect

        source = inspect.getsource(server_module.Server._handle_p2p_message)
        self.assertIn("ANNOUNCE_SLASH", source,
            "Server must handle ANNOUNCE_SLASH messages")


if __name__ == "__main__":
    unittest.main()
