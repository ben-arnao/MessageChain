"""
Regression: two txs in the SAME block using the same WOTS+ leaf_index must
be rejected.

The per-tx watermark check in validate_transaction reads chain state that
hasn't been bumped yet when validating the second tx in a block — both
pass validation individually.  validate_block must defend against this
by scanning the block's signed items for duplicate (entity_id, leaf_index)
pairs.
"""

import time
import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestInBlockLeafReuse(unittest.TestCase):

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def test_same_entity_same_leaf_twice_in_one_block_rejected(self):
        """Two txs signed at the same leaf_index must never both apply."""
        from messagechain.core.blockchain import _hash as block_hash
        chain = Blockchain()
        genesis = _entity(b"genesis")
        sender = _entity(b"sender")
        self._register(chain, genesis)
        self._register(chain, sender)
        chain.supply.balances[sender.entity_id] = 100_000

        # Initialize genesis so the chain has a tip
        chain.initialize_genesis(genesis)

        # Build two message txs signed at the SAME leaf index (rewind trick)
        tx1 = create_transaction(sender, "hi1", fee=500, nonce=0)
        # Rewind keypair so next sign reuses the same leaf
        sender.keypair._next_leaf = tx1.signature.leaf_index
        tx2 = create_transaction(sender, "hi2", fee=500, nonce=1)
        self.assertEqual(tx2.signature.leaf_index, tx1.signature.leaf_index,
                         "test setup: both txs must share a leaf_index")

        # Assemble a block that contains BOTH. Both pass validate_transaction
        # individually (watermark hasn't moved yet), so only a block-level
        # dedupe check can catch this.
        consensus = ProofOfStake()
        consensus.register_validator(genesis.entity_id, stake_amount=100)
        block = chain.propose_block(
            consensus=consensus,
            proposer_entity=genesis,
            transactions=[tx1, tx2],
        )
        ok, reason = chain.validate_block(block)
        self.assertFalse(
            ok,
            "validate_block must reject a block containing two txs from the "
            "same entity at the same leaf_index (WOTS+ reuse)",
        )
        self.assertTrue(
            "leaf" in reason.lower() or "reuse" in reason.lower(),
            f"expected a leaf-reuse error, got: {reason}",
        )

    def test_different_entities_same_leaf_is_fine(self):
        """Only the (entity_id, leaf_index) pair matters — different senders
        at the same leaf_index in the same block is not reuse."""
        chain = Blockchain()
        genesis = _entity(b"genesis")
        alice = _entity(b"alice")
        bob = _entity(b"bob")
        self._register(chain, genesis)
        self._register(chain, alice)
        self._register(chain, bob)
        chain.supply.balances[alice.entity_id] = 100_000
        chain.supply.balances[bob.entity_id] = 100_000
        chain.initialize_genesis(genesis)

        tx_a = create_transaction(alice, "ha", fee=500, nonce=0)
        tx_b = create_transaction(bob, "hb", fee=500, nonce=0)
        # Different entities using the same leaf_index (each in their own tree)
        # is fine — leaves are namespaced per-entity.
        self.assertEqual(tx_a.signature.leaf_index, tx_b.signature.leaf_index)

        consensus = ProofOfStake()
        consensus.register_validator(genesis.entity_id, stake_amount=100)
        block = chain.propose_block(
            consensus=consensus,
            proposer_entity=genesis,
            transactions=[tx_a, tx_b],
        )
        ok, reason = chain.validate_block(block)
        self.assertTrue(ok, f"should not be rejected: {reason}")


if __name__ == "__main__":
    unittest.main()
