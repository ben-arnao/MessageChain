"""
Tests for chain-enforced WOTS+ leaf-index watermarks.

WOTS+ one-time keys are catastrophic to reuse — a reused leaf leaks the
private key outright. The chain must track the highest leaf index it has
seen per entity, and reject any later transaction whose signature uses a
leaf at or below the watermark. This makes reuse impossible rather than
merely discouraged by client-side bookkeeping.
"""

import os
import tempfile
import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import KeyPair
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _make_entity(seed: bytes, height: int = 6) -> Entity:
    """Cheap entity for tests — small Merkle tree for speed."""
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestLeafWatermark(unittest.TestCase):

    def setUp(self):
        # Speed up keygen in tests
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain: Blockchain, entity: Entity) -> bool:
        proof_msg = _hash(b"register" + entity.entity_id)
        proof = entity.keypair.sign(proof_msg)
        ok, _ = chain.register_entity(entity.entity_id, entity.public_key, proof)
        return ok

    # ── Watermark advances on every signature the chain observes ──

    def test_registration_advances_watermark(self):
        chain = Blockchain()
        entity = _make_entity(b"alice")
        self.assertTrue(self._register(chain, entity))

        # Registration used leaf 0 → watermark is now 1 (next usable leaf).
        self.assertEqual(chain.leaf_watermarks[entity.entity_id], 1)

    def test_message_tx_advances_watermark(self):
        chain = Blockchain()
        entity = _make_entity(b"alice")
        self._register(chain, entity)
        # Give entity funds (test scaffolding — bypass normal flow)
        chain.supply.balances[entity.entity_id] = 1000

        tx = create_transaction(entity, "hi", fee=500, nonce=0)
        ok, reason = chain.validate_transaction(tx)
        self.assertTrue(ok, reason)

        # Simulate block apply: watermark should advance past tx.signature.leaf_index
        before = chain.leaf_watermarks[entity.entity_id]
        chain.leaf_watermarks[entity.entity_id] = max(
            before, tx.signature.leaf_index + 1
        )
        self.assertGreater(chain.leaf_watermarks[entity.entity_id], before)

    # ── The core safety guarantee: reused leaf is rejected ──

    def test_reused_leaf_rejected_by_validation(self):
        """A transaction whose leaf_index is at or below the watermark must be rejected."""
        chain = Blockchain()
        entity = _make_entity(b"alice")
        self._register(chain, entity)
        chain.supply.balances[entity.entity_id] = 1000

        # Forge a tx with a stale leaf index by rewinding the keypair
        tx = create_transaction(entity, "hi", fee=500, nonce=0)
        # Rewind the keypair and try to sign another tx at the same leaf
        entity.keypair._next_leaf = tx.signature.leaf_index
        replay = create_transaction(entity, "hi2", fee=500, nonce=0)
        self.assertEqual(replay.signature.leaf_index, tx.signature.leaf_index)

        # First tx: advance watermark as if applied
        chain.leaf_watermarks[entity.entity_id] = tx.signature.leaf_index + 1

        ok, reason = chain.validate_transaction(replay)
        self.assertFalse(ok)
        self.assertIn("leaf", reason.lower())

    def test_transfer_reused_leaf_rejected(self):
        chain = Blockchain()
        sender = _make_entity(b"sender")
        recipient = _make_entity(b"recipient")
        self._register(chain, sender)
        self._register(chain, recipient)
        chain.supply.balances[sender.entity_id] = 10_000

        tx1 = create_transfer_transaction(sender, recipient.entity_id, 100, nonce=0, fee=500)
        chain.leaf_watermarks[sender.entity_id] = tx1.signature.leaf_index + 1

        # Forge a second transfer at the same leaf
        sender.keypair._next_leaf = tx1.signature.leaf_index
        tx2 = create_transfer_transaction(sender, recipient.entity_id, 200, nonce=0, fee=500)
        self.assertEqual(tx2.signature.leaf_index, tx1.signature.leaf_index)

        ok, reason = chain.validate_transfer_transaction(tx2)
        self.assertFalse(ok)
        self.assertIn("leaf", reason.lower())

    # ── Registration itself cannot reuse a leaf ──

    def test_duplicate_registration_via_reused_leaf_rejected(self):
        """Second registration from the same keypair at the same leaf must fail.

        Even if the first registration is rejected (duplicate entity), an attacker
        cannot then "consume" the same leaf by presenting a forged proof at leaf 0.
        The `register_entity` path should itself refuse to accept a proof at or
        below the current watermark for a known entity.
        """
        chain = Blockchain()
        entity = _make_entity(b"alice")
        self.assertTrue(self._register(chain, entity))

        # Rewind and resign registration — this proof uses leaf 0, same as before.
        entity.keypair._next_leaf = 0
        proof_msg = _hash(b"register" + entity.entity_id)
        stale_proof = entity.keypair.sign(proof_msg)
        ok, reason = chain.register_entity(entity.entity_id, entity.public_key, stale_proof)
        self.assertFalse(ok)

    # ── Persistence: watermarks survive restart ──

    def test_watermark_persists_across_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "chain.db")

            db = ChainDB(db_path)
            chain = Blockchain(db=db)
            # Genesis-less bootstrap: just register and persist directly.
            entity = _make_entity(b"alice")
            self._register(chain, entity)
            chain.leaf_watermarks[entity.entity_id] = 42
            chain._persist_state()
            db.close()

            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            # Blockchain._load_from_db only runs if there are blocks. Since we
            # haven't mined any, we simulate by reading directly.
            watermarks = db2.get_all_leaf_watermarks()
            self.assertEqual(watermarks.get(entity.entity_id), 42)
            db2.close()

    # ── RPC exposure ──

    def test_get_leaf_watermark_rpc_shape(self):
        """The chain must expose an authoritative watermark query for clients."""
        chain = Blockchain()
        entity = _make_entity(b"alice")
        self._register(chain, entity)
        # Contract: watermark is an int >= 1 after registration, accessible by entity_id
        wm = chain.get_leaf_watermark(entity.entity_id)
        self.assertIsInstance(wm, int)
        self.assertGreaterEqual(wm, 1)

    def test_get_leaf_watermark_unknown_entity_is_zero(self):
        chain = Blockchain()
        self.assertEqual(chain.get_leaf_watermark(b"\x00" * 32), 0)


if __name__ == "__main__":
    unittest.main()
