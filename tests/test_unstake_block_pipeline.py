"""
Unstake transactions must flow through the block pipeline.

Before this wiring, `_pending_unstake_txs` on the server was a write-only
memory sink: the RPC accepted unstakes but nothing ever drained them into
a block, so unstake had no on-chain effect and didn't propagate to peers.
"""

import time
import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.block import Block
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import UnstakeTransaction
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _bootstrap(self, extras=()):
        """Chain + staked proposer + genesis. Returns (chain, proposer,
        consensus, extras_dict).

        NOTE: proposer stake is set high (500M) so stake-weighted
        proposer selection in _selected_proposer_for_slot reliably
        picks `proposer` even when `extras` includes other staked
        entities.  `create_genesis_block` uses time.time(), so
        genesis block_hash is non-deterministic across runs — a
        dominant proposer stake drops the "wrong proposer for slot"
        flake rate from percent-scale to sub-permille.  See the
        equivalent fix in test_authority_tx_block_pipeline.py.
        """
        chain = Blockchain()
        proposer = _entity(b"proposer")
        self._register(chain, proposer)
        chain.supply.balances[proposer.entity_id] = 1_000_000_000
        chain.supply.staked[proposer.entity_id] = 500_000_000
        extras_d = {}
        for seed, balance, stake in extras:
            e = _entity(seed)
            self._register(chain, e)
            chain.supply.balances[e.entity_id] = balance
            if stake:
                chain.supply.staked[e.entity_id] = stake
            extras_d[seed] = e
        chain.initialize_genesis(proposer)
        consensus = ProofOfStake()
        consensus.register_validator(proposer.entity_id, stake_amount=500_000_000)
        return chain, proposer, consensus, extras_d


def _make_unstake(signer, entity_id, amount, nonce, fee=500):
    tx = UnstakeTransaction(
        entity_id=entity_id, amount=amount, nonce=nonce,
        timestamp=time.time(), fee=fee,
        signature=Signature([], 0, [], b"", b""),
    )
    tx.signature = signer.keypair.sign(_hash(tx._signable_data()))
    tx.tx_hash = tx._compute_hash()
    return tx


class TestUnstakeThroughBlock(_Base):

    def test_block_with_unstake_applies_and_unbonds(self):
        """An UnstakeTransaction in a block moves stake into pending unbond."""
        chain, proposer, consensus, extras = self._bootstrap(
            extras=[(b"val", 10_000, 5_000)],
        )
        val = extras[b"val"]

        # val hasn't set a cold key, so signing key == authority key.
        unstake = _make_unstake(val, val.entity_id, amount=1_000, nonce=0)
        block = chain.propose_block(
            consensus, proposer, transactions=[],
            unstake_transactions=[unstake],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)

        # Active stake decreases; pending unbond increases by the same amount.
        self.assertEqual(chain.supply.get_staked(val.entity_id), 4_000)
        pending = chain.supply.pending_unstakes.get(val.entity_id, [])
        self.assertEqual(sum(amt for amt, _ in pending), 1_000)

    def test_unstake_rejected_from_hot_key_after_cold_key_set(self):
        """Once a cold key is promoted, unstake must be signed by it."""
        chain, proposer, consensus, extras = self._bootstrap(
            extras=[(b"val", 10_000, 5_000)],
        )
        hot = extras[b"val"]
        cold = _entity(b"val-cold")

        # block 1: promote cold key
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        b1 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_tx],
        )
        ok, reason = chain.add_block(b1)
        self.assertTrue(ok, reason)

        # block 2: unstake signed by HOT key — should be rejected
        bad_unstake = _make_unstake(hot, hot.entity_id, amount=1_000, nonce=1)
        b2 = chain.propose_block(
            consensus, proposer, transactions=[],
            unstake_transactions=[bad_unstake],
        )
        ok, reason = chain.add_block(b2)
        self.assertFalse(ok)
        self.assertIn("authority", reason.lower())

    def test_unstake_accepted_when_signed_by_cold_key(self):
        chain, proposer, consensus, extras = self._bootstrap(
            extras=[(b"val", 10_000, 5_000)],
        )
        hot = extras[b"val"]
        cold = _entity(b"val-cold")

        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        b1 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_tx],
        )
        chain.add_block(b1)

        good_unstake = _make_unstake(cold, hot.entity_id, amount=1_000, nonce=1)
        b2 = chain.propose_block(
            consensus, proposer, transactions=[],
            unstake_transactions=[good_unstake],
        )
        ok, reason = chain.add_block(b2)
        self.assertTrue(ok, reason)
        self.assertEqual(chain.supply.get_staked(hot.entity_id), 4_000)

    def test_unstake_round_trips_through_serialized_block(self):
        """An unstake-containing block survives serialize/deserialize."""
        chain, proposer, consensus, extras = self._bootstrap(
            extras=[(b"val", 10_000, 5_000)],
        )
        val = extras[b"val"]
        unstake = _make_unstake(val, val.entity_id, amount=500, nonce=0)
        block = chain.propose_block(
            consensus, proposer, transactions=[],
            unstake_transactions=[unstake],
        )
        rehydrated = Block.deserialize(block.serialize())
        self.assertEqual(len(rehydrated.unstake_transactions), 1)
        self.assertEqual(
            rehydrated.unstake_transactions[0].entity_id, val.entity_id,
        )


if __name__ == "__main__":
    unittest.main()
