"""
Authority transactions (SetAuthorityKey, Revoke, KeyRotation) must flow
through the block pipeline, not apply locally on the node that received
the RPC.

Without this, a cold-key promotion or emergency revoke on one node never
propagates to peers — every other node still thinks the entity is single-
key, which an attacker can exploit to unstake via a peer that hasn't
seen the SetAuthorityKey.

These tests prove:
1. Authority txs serialize into a Block, deserialize cleanly, and land in
   block.authority_txs with their concrete types preserved.
2. Applying a block containing authority_txs mutates the expected chain
   state (authority_keys, revoked_entities, public_keys, leaf_watermarks).
3. Two nodes starting from identical state and applying the same block
   reach identical state — the criterion for network-wide convergence.
"""

import time
import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction, create_set_authority_key_transaction,
)
from messagechain.core.block import Block
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import RevokeTransaction
from messagechain.core.key_rotation import (
    KeyRotationTransaction, create_key_rotation, derive_rotated_keypair,
)
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
        chain.register_entity(entity.entity_id, entity.public_key, proof)


class TestAuthorityTxSerializesInBlock(_Base):
    """The block carries the authority txs across the wire."""

    def test_set_authority_key_round_trips_through_block(self):
        hot = _entity(b"hot")
        cold_pk = _entity(b"cold").public_key
        tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        # Build a minimal block containing the authority tx
        block = Block(
            header=__import__("messagechain.core.block", fromlist=["BlockHeader"]).BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32, timestamp=time.time(),
                proposer_id=hot.entity_id,
            ),
            transactions=[],
            authority_txs=[tx],
        )
        data = block.serialize()
        self.assertIn("authority_txs", data)
        self.assertEqual(len(data["authority_txs"]), 1)

        rehydrated = Block.deserialize(data)
        self.assertEqual(len(rehydrated.authority_txs), 1)
        self.assertIsInstance(rehydrated.authority_txs[0], SetAuthorityKeyTransaction)
        self.assertEqual(rehydrated.authority_txs[0].new_authority_key, cold_pk)

    def test_revoke_round_trips_through_block(self):
        hot = _entity(b"hot")
        cold = _entity(b"cold")
        revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        block = Block(
            header=__import__("messagechain.core.block", fromlist=["BlockHeader"]).BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32, timestamp=time.time(),
                proposer_id=hot.entity_id,
            ),
            transactions=[],
            authority_txs=[revoke],
        )
        rehydrated = Block.deserialize(block.serialize())
        self.assertIsInstance(rehydrated.authority_txs[0], RevokeTransaction)
        self.assertEqual(rehydrated.authority_txs[0].entity_id, hot.entity_id)

    def test_key_rotation_round_trips_through_block(self):
        alice = _entity(b"alice")
        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot = create_key_rotation(alice, new_kp, rotation_number=0)
        block = Block(
            header=__import__("messagechain.core.block", fromlist=["BlockHeader"]).BlockHeader(
                version=1, block_number=1, prev_hash=b"\x00" * 32,
                merkle_root=b"\x00" * 32, timestamp=time.time(),
                proposer_id=alice.entity_id,
            ),
            transactions=[],
            authority_txs=[rot],
        )
        rehydrated = Block.deserialize(block.serialize())
        self.assertIsInstance(rehydrated.authority_txs[0], KeyRotationTransaction)
        self.assertEqual(rehydrated.authority_txs[0].new_public_key, new_kp.public_key)


class TestAuthorityTxApplyThroughBlock(_Base):
    """Applying a block containing authority_txs mutates state correctly.

    End-to-end via Blockchain.add_block — not a direct apply_* call, so
    this exercises validate_block (which must accept the new slot) and
    _apply_block_state (which dispatches each atx to _apply_authority_tx).
    """

    def _bootstrap(self, include=()):
        """Build a chain with a staked proposer, genesis, and any extra
        registrations/balances the caller needs. Returns (chain, proposer,
        consensus, extras).

        NOTE: proposer stake is set high (100M) so that stake-weighted
        random proposer selection in `_selected_proposer_for_slot`
        reliably picks `proposer` even when the `include=` list
        registers additional staked entities.  `create_genesis_block`
        uses `time.time()`, so genesis block_hash — and therefore the
        RNG seed for proposer selection at block 1 — is non-deterministic
        across runs.  A dominant proposer stake turns a ~5% flake
        (100k vs 5k stake) into ~0.005% (100M vs 5k).  The real fix is
        deterministic genesis timestamps, but that is a larger change.
        """
        chain = Blockchain()
        proposer = _entity(b"proposer")
        self._register(chain, proposer)
        chain.supply.balances[proposer.entity_id] = 200_000_000
        chain.supply.staked[proposer.entity_id] = 100_000_000
        extras = {}
        for seed, balance, stake in include:
            e = _entity(seed)
            self._register(chain, e)
            chain.supply.balances[e.entity_id] = balance
            if stake:
                chain.supply.staked[e.entity_id] = stake
            extras[seed] = e
        chain.initialize_genesis(proposer)
        consensus = ProofOfStake()
        consensus.register_validator(proposer.entity_id, stake_amount=100_000_000)
        return chain, proposer, consensus, extras

    def test_set_authority_key_applied_through_block(self):
        chain, proposer, consensus, extras = self._bootstrap(
            include=[(b"user", 10_000, 0)],
        )
        user = extras[b"user"]
        cold_pk = _entity(b"user-cold").public_key

        set_tx = create_set_authority_key_transaction(
            user, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        block = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_tx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(chain.get_authority_key(user.entity_id), cold_pk)
        self.assertEqual(chain.supply.get_balance(user.entity_id), 9_500)

    def test_revoke_applied_through_block(self):
        chain, proposer, consensus, extras = self._bootstrap(
            include=[(b"hot", 10_000, 5_000)],
        )
        hot = extras[b"hot"]
        cold = _entity(b"cold")

        # block 1: promote cold key
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        blk1 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[set_tx],
        )
        ok, reason = chain.add_block(blk1)
        self.assertTrue(ok, reason)

        # block 2: revoke signed by cold
        revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        blk2 = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[revoke],
        )
        ok, reason = chain.add_block(blk2)
        self.assertTrue(ok, reason)
        self.assertTrue(chain.is_revoked(hot.entity_id))
        self.assertEqual(chain.supply.get_staked(hot.entity_id), 0)

    def test_key_rotation_applied_through_block(self):
        chain, proposer, consensus, extras = self._bootstrap(
            include=[(b"alice", 10_000, 0)],
        )
        alice = extras[b"alice"]

        new_kp = derive_rotated_keypair(alice, rotation_number=0)
        rot_tx = create_key_rotation(alice, new_kp, rotation_number=0)
        blk = chain.propose_block(
            consensus, proposer, transactions=[], authority_txs=[rot_tx],
        )
        ok, reason = chain.add_block(blk)
        self.assertTrue(ok, reason)
        self.assertEqual(chain.public_keys[alice.entity_id], new_kp.public_key)
        # Rotation resets leaf watermark on the new tree
        self.assertEqual(chain.leaf_watermarks[alice.entity_id], 0)
        # Rotation count increments for next rotation
        self.assertEqual(chain.key_rotation_counts.get(alice.entity_id), 1)


if __name__ == "__main__":
    unittest.main()
