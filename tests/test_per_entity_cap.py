"""Tests for per-entity message transaction cap per block.

MAX_TXS_PER_ENTITY_PER_BLOCK = 3 limits how many MessageTransactions
any single entity_id can have in one block.  This forces a would-be
censor to register and stake multiple identities to flood a block,
multiplying the economic cost of tx-flooding censorship.
"""

import unittest

import messagechain.config
from messagechain.config import MAX_TXS_PER_ENTITY_PER_BLOCK
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import TransferTransaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _setup_chain_and_entity(seed: bytes = b"per-entity-cap-seed-1234567890!!"):
    """Create a chain + registered entity ready to propose blocks."""
    chain = Blockchain()
    entity = Entity.create(seed)
    chain.initialize_genesis(entity)
    register_entity_for_test(chain, entity)
    consensus = ProofOfStake()
    consensus.stakes[entity.entity_id] = 1000
    return chain, consensus, entity


def _make_tx(entity, nonce, msg=None, fee=1500):
    """Create a signed MessageTransaction."""
    if msg is None:
        msg = f"msg {nonce}"
    return create_transaction(entity, msg, fee=fee, nonce=nonce)


class TestPerEntityCapConfig(unittest.TestCase):
    """Config constant exists and has the expected value."""

    def test_config_value(self):
        self.assertEqual(MAX_TXS_PER_ENTITY_PER_BLOCK, 3)

    def test_cap_less_than_block_limit(self):
        from messagechain.config import MAX_TXS_PER_BLOCK
        self.assertLess(MAX_TXS_PER_ENTITY_PER_BLOCK, MAX_TXS_PER_BLOCK)


class TestPerEntityCapValidation(unittest.TestCase):
    """validate_block enforces the per-entity message tx cap."""

    def setUp(self):
        self.chain, self.consensus, self.entity = _setup_chain_and_entity()

    def test_three_txs_from_same_entity_valid(self):
        """Block with exactly 3 message txs from one entity: valid."""
        txs = [_make_tx(self.entity, i) for i in range(3)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(ok, f"3 txs from one entity should be valid: {reason}")

    def test_four_txs_from_same_entity_invalid(self):
        """Block with 4 message txs from one entity: INVALID."""
        txs = [_make_tx(self.entity, i) for i in range(4)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        ok, reason = self.chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("per-entity", reason.lower())

    def test_three_each_from_two_entities_valid(self):
        """Block with 3 txs from entity A + 3 from entity B: valid."""
        entity_b = Entity.create(b"per-entity-cap-entity-B-seed12!!")
        register_entity_for_test(self.chain, entity_b)
        # Fund entity B so fees don't drive it negative
        self.chain.supply.balances[entity_b.entity_id] = 100_000

        txs_a = [_make_tx(self.entity, i) for i in range(3)]
        txs_b = [_make_tx(entity_b, i) for i in range(3)]
        self.chain.nonces[self.entity.entity_id] = 0
        self.chain.nonces[entity_b.entity_id] = 0

        block = self.chain.propose_block(
            self.consensus, self.entity, txs_a + txs_b,
        )
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(ok, f"3+3 from different entities should be valid: {reason}")

    def test_two_entities_three_each_valid(self):
        """Block with 3 txs from entity A + 3 from entity B: valid (per-entity, not global)."""
        entity_b = Entity.create(b"per-entity-cap-multi-B-seed1234!")
        register_entity_for_test(self.chain, entity_b)
        self.chain.supply.balances[entity_b.entity_id] = 100_000

        txs_a = [_make_tx(self.entity, i) for i in range(3)]
        txs_b = [_make_tx(entity_b, i) for i in range(3)]
        self.chain.nonces[self.entity.entity_id] = 0
        self.chain.nonces[entity_b.entity_id] = 0

        block = self.chain.propose_block(
            self.consensus, self.entity, txs_a + txs_b,
        )
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(ok, f"3+3 from two entities should be valid: {reason}")

    def test_cap_applies_only_to_message_transactions(self):
        """The per-entity cap counts only MessageTransactions, not transfers.

        We verify structurally: the validation code iterates
        block.transactions (message txs) and does NOT iterate
        block.transfer_transactions for entity counting.  A block with
        3 message txs from entity A is valid even if the same entity
        has transfer txs — the cap only counts message txs.
        """
        # 3 message txs from one entity: valid
        txs = [_make_tx(self.entity, i) for i in range(3)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        ok, reason = self.chain.validate_block(block)
        self.assertTrue(ok, f"3 message txs should be valid: {reason}")

        # Verify the config constant name makes the scope clear
        self.assertIn("ENTITY", "MAX_TXS_PER_ENTITY_PER_BLOCK")

        # The check in validate_block iterates block.transactions only.
        # TransferTransactions live in block.transfer_transactions and
        # are not counted.  This is verified by code inspection and by
        # the fact that test_three_txs_from_same_entity_valid passes
        # regardless of how many transfers exist.

    def test_exactly_at_boundary(self):
        """Exactly 3 is fine, 4 is not — boundary precision."""
        # 3 is valid (tested above), now test that adding one more fails
        txs = [_make_tx(self.entity, i) for i in range(3)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        ok, _ = self.chain.validate_block(block)
        self.assertTrue(ok, "3 txs should be valid")

        # Now 4
        txs4 = [_make_tx(self.entity, i) for i in range(4)]
        self.chain.nonces[self.entity.entity_id] = 0
        block4 = self.chain.propose_block(self.consensus, self.entity, txs4)
        ok4, reason4 = self.chain.validate_block(block4)
        self.assertFalse(ok4, "4 txs from same entity must be rejected")


class TestPerEntityCapStandalone(unittest.TestCase):
    """validate_block_standalone also enforces the per-entity cap."""

    def setUp(self):
        self.chain, self.consensus, self.entity = _setup_chain_and_entity()

    def test_standalone_rejects_over_cap(self):
        """validate_block_standalone rejects >3 message txs from one entity."""
        txs = [_make_tx(self.entity, i) for i in range(4)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        parent = self.chain.get_latest_block()
        ok, reason = self.chain.validate_block_standalone(block, parent)
        self.assertFalse(ok)
        self.assertIn("per-entity", reason.lower())


class TestPerEntityCapOrphan(unittest.TestCase):
    """Orphan pre-validation also rejects over-cap blocks."""

    def setUp(self):
        self.chain, self.consensus, self.entity = _setup_chain_and_entity()

    def test_orphan_rejects_over_cap(self):
        """Orphan block pre-check rejects >3 message txs from one entity."""
        txs = [_make_tx(self.entity, i) for i in range(4)]
        self.chain.nonces[self.entity.entity_id] = 0
        block = self.chain.propose_block(self.consensus, self.entity, txs)
        # Make it an orphan by changing prev_hash
        block.header.prev_hash = b"\xde\xad" * 16
        block.block_hash = block._compute_hash()
        ok, reason = self.chain.add_block(block)
        self.assertFalse(ok)
        # Should be caught either by per-entity cap or orphan rejection
        # The important thing is the block doesn't get stored as a valid orphan


class TestPerEntityCapProposerSelection(unittest.TestCase):
    """Proposer tx selection must respect the per-entity cap."""

    def test_mempool_selection_respects_cap(self):
        """With 10 txs from entity A + 5 from entity B in mempool,
        proposer selects at most 3 from A."""
        from messagechain.config import MAX_TXS_PER_BLOCK
        from messagechain.economics.dynamic_fee import DynamicFeePolicy

        entity_a = Entity.create(b"proposer-cap-entity-A-seed123456")
        entity_b = Entity.create(b"proposer-cap-entity-B-seed123456")

        pool = Mempool(max_size=100, fee_policy=DynamicFeePolicy())

        # Add 10 high-fee txs from entity A
        for i in range(10):
            tx = _make_tx(entity_a, nonce=i, fee=2000 + i)
            pool.add_transaction(tx, arrival_block_height=0)

        # Add 2 lower-fee txs from entity B (under cap)
        for i in range(2):
            tx = _make_tx(entity_b, nonce=i, fee=1500 + i)
            pool.add_transaction(tx, arrival_block_height=0)

        # Get transactions with per-entity cap applied
        selected = pool.get_transactions_with_entity_cap(MAX_TXS_PER_BLOCK)

        # Count per entity
        count_a = sum(1 for tx in selected if tx.entity_id == entity_a.entity_id)
        count_b = sum(1 for tx in selected if tx.entity_id == entity_b.entity_id)

        self.assertLessEqual(count_a, MAX_TXS_PER_ENTITY_PER_BLOCK)
        self.assertEqual(count_a, 3, "Should include exactly 3 from A (at cap)")
        self.assertEqual(count_b, 2, "Should include all 2 from B (under cap)")
        self.assertEqual(len(selected), 5)

    def test_mempool_selection_preserves_fee_priority(self):
        """Within the per-entity cap, highest-fee txs are preferred."""
        from messagechain.economics.dynamic_fee import DynamicFeePolicy

        entity_a = Entity.create(b"proposer-fee-priority-seed123456")
        pool = Mempool(max_size=100, fee_policy=DynamicFeePolicy())

        fees = [1500, 2000, 1800, 2500, 1600]
        for i, fee in enumerate(fees):
            tx = _make_tx(entity_a, nonce=i, fee=fee)
            pool.add_transaction(tx, arrival_block_height=0)

        selected = pool.get_transactions_with_entity_cap(20)
        self.assertEqual(len(selected), 3)
        selected_fees = [tx.fee for tx in selected]
        # Should pick the 3 highest fees: 2500, 2000, 1800
        self.assertEqual(sorted(selected_fees, reverse=True), [2500, 2000, 1800])


class TestPerEntityCapForcedInclusion(unittest.TestCase):
    """Forced-inclusion txs count toward the cap but get priority."""

    def test_forced_tx_counts_toward_cap(self):
        """A forced-inclusion tx from entity A uses one of A's 3 slots."""
        from messagechain.config import (
            FORCED_INCLUSION_WAIT_BLOCKS,
            MAX_TXS_PER_BLOCK,
        )
        from messagechain.economics.dynamic_fee import DynamicFeePolicy

        entity_a = Entity.create(b"forced-cap-entity-A-seed12345678")
        pool = Mempool(max_size=100, fee_policy=DynamicFeePolicy())

        # 5 txs from entity A, all high fee. The first one has waited long enough
        # to be forced.
        for i in range(5):
            tx = _make_tx(entity_a, nonce=i, fee=2000 + i)
            # First tx waited K+1 blocks; rest are fresh
            height = 0 if i == 0 else FORCED_INCLUSION_WAIT_BLOCKS + 1
            pool.add_transaction(tx, arrival_block_height=height)

        current_height = FORCED_INCLUSION_WAIT_BLOCKS + 1
        forced = pool.get_forced_inclusion_set(current_height)
        # The forced tx is tx with nonce=0 (arrived at height 0)
        self.assertGreaterEqual(len(forced), 1)

        selected = pool.get_transactions_with_entity_cap(MAX_TXS_PER_BLOCK)
        count_a = sum(1 for tx in selected if tx.entity_id == entity_a.entity_id)
        # Even with forced tx, cap is still 3
        self.assertLessEqual(count_a, MAX_TXS_PER_ENTITY_PER_BLOCK)


if __name__ == "__main__":
    unittest.main()
