"""
Test that a block proposer who also has transactions in the block
does not collide on WOTS+ leaf indices between their tx signature(s)
and the proposer (block header) signature.

Regression test for: proposer signs a tx (consuming leaf N), then the
keypair's _next_leaf is reset (e.g., keypair reconstructed from seed
without advancing past the tx's leaf). When the proposer then signs the
block header, it reuses leaf N — causing "Block contains duplicate
WOTS+ leaf use" rejection.

In production this happens when:
  - The tx was signed and submitted to the mempool
  - The keypair was reconstructed from seed (restart, failover) without
    advancing _next_leaf past the mempool tx's leaf
  - The proposer slot arrives and _try_produce_block gathers the tx from
    the mempool and signs the block header with the same leaf
"""

import hashlib
import time
import unittest

import messagechain.config
from messagechain.config import HASH_ALGO, VALIDATOR_MIN_STAKE, MIN_FEE
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import MessageTransaction
from messagechain.core.transfer import TransferTransaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from tests import register_entity_for_test


# Fee high enough to pass base-fee validation.
_FEE = MIN_FEE * 10


def _setup_single_validator():
    """Create a chain with one registered+staked validator."""
    entity = Entity.create(b"proposer_leaf_test_key".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(entity)
    consensus = ProofOfStake()
    chain.supply.balances[entity.entity_id] = (
        chain.supply.balances.get(entity.entity_id, 0) + 100_000
    )
    chain.supply.stake(entity.entity_id, VALIDATOR_MIN_STAKE)
    consensus.stakes[entity.entity_id] = VALIDATOR_MIN_STAKE
    return chain, consensus, entity


def _sign_message_tx(entity, chain, message=b"hello"):
    """Create and sign a MessageTransaction from `entity`."""
    nonce = chain.nonces.get(entity.entity_id, 0)
    tx = MessageTransaction(
        entity_id=entity.entity_id,
        message=message,
        timestamp=time.time(),
        nonce=nonce,
        fee=_FEE,
        signature=Signature([], 0, [], b"", b""),
    )
    h = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(h)
    tx.tx_hash = tx._compute_hash()
    tx.witness_hash = tx._compute_witness_hash()
    return tx


def _sign_transfer_tx(entity, recipient_id, amount, chain, nonce_offset=0):
    """Create and sign a TransferTransaction from `entity`."""
    nonce = chain.nonces.get(entity.entity_id, 0) + nonce_offset
    tx = TransferTransaction(
        entity_id=entity.entity_id,
        recipient_id=recipient_id,
        amount=amount,
        timestamp=time.time(),
        nonce=nonce,
        fee=_FEE,
        signature=Signature([], 0, [], b"", b""),
    )
    h = hashlib.new(HASH_ALGO, tx._signable_data()).digest()
    tx.signature = entity.keypair.sign(h)
    tx.tx_hash = tx._compute_hash()
    return tx


class TestProposerLeafReuse(unittest.TestCase):
    """Proposer's block-header signature must not collide with any tx
    signed by the same entity in the same block."""

    def test_proposer_message_tx_stale_counter_no_leaf_collision(self):
        """Simulates a keypair whose _next_leaf was NOT advanced past a
        mempool tx's leaf (e.g., after restart). The block builder must
        detect the collision and advance the keypair before signing."""
        chain, consensus, proposer = _setup_single_validator()

        msg_tx = _sign_message_tx(proposer, chain)
        tx_leaf = msg_tx.signature.leaf_index

        # Simulate stale counter: reset _next_leaf back to the tx's leaf
        # as if the keypair was reconstructed without knowing about the tx.
        proposer.keypair._next_leaf = tx_leaf

        block = chain.propose_block(consensus, proposer, [msg_tx])
        success, reason = chain.add_block(block)
        self.assertTrue(success, f"Block rejected: {reason}")

        # The proposer signature must use a leaf AFTER the tx's leaf.
        self.assertGreater(
            block.header.proposer_signature.leaf_index,
            tx_leaf,
            "Proposer signature must use a leaf after the tx's leaf",
        )

    def test_proposer_transfer_tx_stale_counter_no_leaf_collision(self):
        """Same scenario with a transfer tx instead of a message tx."""
        chain, consensus, proposer = _setup_single_validator()

        recipient = Entity.create(b"recipient_leaf_test_k".ljust(32, b"\x00"))
        register_entity_for_test(chain, recipient)

        xfer_tx = _sign_transfer_tx(proposer, recipient.entity_id, 100, chain)
        tx_leaf = xfer_tx.signature.leaf_index

        # Simulate stale counter
        proposer.keypair._next_leaf = tx_leaf

        block = chain.propose_block(
            consensus, proposer, [],
            transfer_transactions=[xfer_tx],
        )
        success, reason = chain.add_block(block)
        self.assertTrue(success, f"Block rejected: {reason}")

        self.assertGreater(
            block.header.proposer_signature.leaf_index,
            tx_leaf,
            "Proposer signature must use a leaf after the transfer tx's leaf",
        )

    def test_proposer_multiple_txs_stale_counter_no_leaf_collision(self):
        """Proposer has two txs in the block and a stale counter.
        All three leaf indices must be unique after the fix."""
        chain, consensus, proposer = _setup_single_validator()

        recipient = Entity.create(b"recipient2_leaf_test".ljust(32, b"\x00"))
        register_entity_for_test(chain, recipient)

        msg_tx = _sign_message_tx(proposer, chain, message=b"msg from proposer")
        xfer_tx = _sign_transfer_tx(
            proposer, recipient.entity_id, 50, chain, nonce_offset=1,
        )

        # Reset counter back to the first tx's leaf (worst case)
        proposer.keypair._next_leaf = msg_tx.signature.leaf_index

        block = chain.propose_block(
            consensus, proposer, [msg_tx],
            transfer_transactions=[xfer_tx],
        )
        success, reason = chain.add_block(block)
        self.assertTrue(success, f"Block rejected: {reason}")

        # All three leaf indices must be distinct.
        leaves = {
            msg_tx.signature.leaf_index,
            xfer_tx.signature.leaf_index,
            block.header.proposer_signature.leaf_index,
        }
        self.assertEqual(len(leaves), 3, "All leaf indices must be unique")


if __name__ == "__main__":
    unittest.main()
