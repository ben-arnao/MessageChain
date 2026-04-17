"""
Tests for mempool-level nonce tracking.

Users should be able to submit multiple transactions without waiting
for each to be mined.  The mempool tracks "pending nonces" so that
tx nonce=1 is accepted even though the on-chain nonce is still 0
(because nonce=0 is already in the mempool).
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from tests import register_entity_for_test

_STATIC_FEE = DynamicFeePolicy(base_fee=100, max_fee=100)
_TEST_FEE = 1500


class TestMempoolNonceTracking(unittest.TestCase):
    """validate_transaction accepts sequential nonces when earlier ones are in mempool."""

    def setUp(self):
        self.alice = Entity.create(b"alice-nonce-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-nonce-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 100_000
        self.chain.supply.balances[self.bob.entity_id] = 100_000
        self.mempool = Mempool(fee_policy=_STATIC_FEE)
        self.consensus = ProofOfStake()

    def _make_block(self, proposer, txs, prev=None):
        if prev is None:
            prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1
        # The proposer's block signature will consume the next leaf.
        # We must tell compute_post_state_root which leaf that is, so
        # the simulated state root matches the one after actual signing.
        proposer_leaf = getattr(proposer.keypair, "_next_leaf", 0)
        state_root = self.chain.compute_post_state_root(
            txs, proposer.entity_id, block_height,
            proposer_signature_leaf_index=proposer_leaf,
        )
        return self.consensus.create_block(proposer, txs, prev, state_root=state_root)

    def test_sequential_nonces_both_accepted(self):
        """Submit nonce=0 then nonce=1 -- both should pass validation."""
        tx0 = create_transaction(self.alice, "msg 0", fee=_TEST_FEE, nonce=0)
        tx1 = create_transaction(self.alice, "msg 1", fee=_TEST_FEE, nonce=1)

        # First tx validates against on-chain nonce (0)
        valid0, reason0 = self.chain.validate_transaction(tx0)
        self.assertTrue(valid0, reason0)
        self.mempool.add_transaction(tx0)

        # Second tx validates using pending nonce from mempool
        on_chain = self.chain.nonces.get(self.alice.entity_id, 0)
        pending = self.mempool.get_pending_nonce(self.alice.entity_id, on_chain)
        valid1, reason1 = self.chain.validate_transaction(tx1, expected_nonce=pending)
        self.assertTrue(valid1, reason1)

    def test_nonce_gap_rejected(self):
        """Submit nonce=0 then nonce=2 (skipping 1) -- nonce=2 must be rejected."""
        tx0 = create_transaction(self.alice, "msg 0", fee=_TEST_FEE, nonce=0)
        tx2 = create_transaction(self.alice, "msg gap", fee=_TEST_FEE, nonce=2)

        valid0, _ = self.chain.validate_transaction(tx0)
        self.assertTrue(valid0)
        self.mempool.add_transaction(tx0)

        on_chain = self.chain.nonces.get(self.alice.entity_id, 0)
        pending = self.mempool.get_pending_nonce(self.alice.entity_id, on_chain)
        valid2, reason2 = self.chain.validate_transaction(tx2, expected_nonce=pending)
        self.assertFalse(valid2)
        self.assertIn("nonce", reason2.lower())

    def test_after_block_mines_remaining_tx_still_valid(self):
        """After nonce=0 is mined, nonce=1 in mempool should still be valid.

        Bob proposes the block so Alice's leaf watermark is only bumped
        by the transactions she signed (tx0 uses leaf 0, tx1 uses leaf 1).
        After mining tx0, the watermark advances past leaf 0 but tx1's
        leaf 1 is still above the watermark.
        """
        tx0 = create_transaction(self.alice, "msg 0", fee=_TEST_FEE, nonce=0)
        tx1 = create_transaction(self.alice, "msg 1", fee=_TEST_FEE, nonce=1)

        # Accept both into mempool
        self.mempool.add_transaction(tx0)
        self.mempool.add_transaction(tx1)

        # Mine a block containing only tx0 — bob proposes so alice's
        # watermark is only bumped by tx0 (leaf 0 -> watermark 1).
        block = self._make_block(self.bob, [tx0])
        success, reason = self.chain.add_block(block)
        self.assertTrue(success, reason)
        self.mempool.remove_transactions([tx0.tx_hash])

        # On-chain nonce is now 1 -- tx1 should validate against chain state directly
        valid1, reason1 = self.chain.validate_transaction(tx1)
        self.assertTrue(valid1, reason1)

    def test_transfer_sequential_nonces(self):
        """Transfer transactions also support pending nonces."""
        tx0 = create_transaction(self.alice, "msg 0", fee=_TEST_FEE, nonce=0)
        ttx1 = create_transfer_transaction(
            self.alice, self.bob.entity_id, amount=100, fee=_TEST_FEE, nonce=1,
        )

        valid0, reason0 = self.chain.validate_transaction(tx0)
        self.assertTrue(valid0, reason0)
        self.mempool.add_transaction(tx0)

        on_chain = self.chain.nonces.get(self.alice.entity_id, 0)
        pending = self.mempool.get_pending_nonce(self.alice.entity_id, on_chain)
        valid1, reason1 = self.chain.validate_transfer_transaction(
            ttx1, expected_nonce=pending,
        )
        self.assertTrue(valid1, reason1)

    def test_pending_nonce_computed_from_mempool(self):
        """The pending nonce should equal max nonce in mempool + 1."""
        tx0 = create_transaction(self.alice, "msg 0", fee=_TEST_FEE, nonce=0)
        tx1 = create_transaction(self.alice, "msg 1", fee=_TEST_FEE, nonce=1)

        self.mempool.add_transaction(tx0)
        self.mempool.add_transaction(tx1)

        on_chain = self.chain.nonces.get(self.alice.entity_id, 0)
        pending = self.mempool.get_pending_nonce(self.alice.entity_id, on_chain)
        self.assertEqual(pending, 2)

    def test_no_pending_txs_uses_chain_nonce(self):
        """With no pending txs, pending nonce equals on-chain nonce."""
        on_chain = self.chain.nonces.get(self.alice.entity_id, 0)
        pending = self.mempool.get_pending_nonce(self.alice.entity_id, on_chain)
        self.assertEqual(pending, on_chain)


if __name__ == "__main__":
    unittest.main()
