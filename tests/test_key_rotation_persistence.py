"""
Tests for end-to-end key rotation: persistence, entity_id portability,
and state carry-over.

Key rotation already exists as a library-level transaction. This test
suite locks in the properties that make entity_ids truly portable across
key generations: after rotation, every scrap of state keyed by the
entity_id must survive unchanged except for the public_key itself. This
is the property that lets a user exhaust one WOTS+ tree and move to a
fresh one without losing their identity, balance, stake, or cold-key
binding.
"""

import os
import tempfile
import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.core.key_rotation import (
    create_key_rotation,
    derive_rotated_keypair,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


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


class TestEntityIdPortability(_Base):

    def test_entity_id_unchanged_after_rotation(self):
        """The entity_id (wallet address) MUST stay the same across rotation."""
        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000
        original_entity_id = entity.entity_id

        new_kp = derive_rotated_keypair(entity, rotation_number=0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
        ok, _ = chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)
        self.assertTrue(ok)

        # entity_id is unchanged
        self.assertIn(original_entity_id, chain.public_keys)
        # but public_key has advanced
        self.assertEqual(chain.public_keys[original_entity_id], new_kp.public_key)
        self.assertNotEqual(chain.public_keys[original_entity_id], entity.public_key)

    def test_balance_carries_over_rotation(self):
        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000

        new_kp = derive_rotated_keypair(entity, rotation_number=0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
        chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)

        # Balance is preserved modulo the rotation fee.
        self.assertGreater(chain.supply.get_balance(entity.entity_id), 0)

    def test_stake_carries_over_rotation(self):
        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000
        chain.supply.staked[entity.entity_id] = 5_000

        new_kp = derive_rotated_keypair(entity, rotation_number=0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
        chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)

        self.assertEqual(chain.supply.get_staked(entity.entity_id), 5_000)

    def test_authority_key_carries_over_rotation(self):
        """Cold-key binding survives rotation of the hot key."""
        from messagechain.core.authority_key import create_set_authority_key_transaction

        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold_pk = _entity(b"validator-cold").public_key
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000

        # Set cold key first
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Rotate the hot key
        new_kp = derive_rotated_keypair(hot, rotation_number=0)
        rot_tx = create_key_rotation(hot, new_kp, rotation_number=0)
        chain.apply_key_rotation(rot_tx, proposer_id=hot.entity_id)

        # Cold key binding unchanged
        self.assertEqual(chain.get_authority_key(hot.entity_id), cold_pk)


class TestLeafWatermarkResetOnRotation(_Base):

    def test_leaf_watermark_resets_for_new_tree(self):
        """The new Merkle tree has an independent leaf space starting at 0."""
        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)  # burns leaf 0
        chain.supply.balances[entity.entity_id] = 10_000

        # After registration, watermark > 0 since leaf 0 was consumed.
        self.assertGreater(chain.leaf_watermarks[entity.entity_id], 0)

        new_kp = derive_rotated_keypair(entity, rotation_number=0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
        ok, reason = chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)
        self.assertTrue(ok, reason)

        # Watermark resets to 0 — new tree's leaves are unseen.
        self.assertEqual(chain.leaf_watermarks[entity.entity_id], 0)


class TestRotationCountPersistence(_Base):

    def test_rotation_count_survives_restart(self):
        """After rotation, persisted state must remember rotation_number."""
        tmp = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmp, "chain.db")

            db = ChainDB(db_path)
            chain = Blockchain(db=db)
            entity = _entity(b"alice")
            self._register(chain, entity)
            chain.supply.balances[entity.entity_id] = 10_000

            new_kp = derive_rotated_keypair(entity, rotation_number=0)
            rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
            chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)

            # Expected: rotation count is now 1
            self.assertEqual(chain.key_rotation_counts.get(entity.entity_id), 1)

            chain._persist_state()
            db.close()

            # Reopen — rotation count must survive
            db2 = ChainDB(db_path)
            # We can't easily exercise the full reload (needs blocks), so
            # query the DB directly via a getter.
            counts = db2.get_all_key_rotation_counts()
            self.assertEqual(counts.get(entity.entity_id), 1)
            db2.close()
        finally:
            # Windows needs a moment to release WAL/shm handles.
            import shutil
            import time
            for _ in range(5):
                try:
                    shutil.rmtree(tmp)
                    break
                except PermissionError:
                    time.sleep(0.1)


class TestLeafExhaustionRecovery(_Base):
    """The rotation flow is the recovery path from leaf exhaustion."""

    def test_rotated_keypair_is_usable_for_signing(self):
        """After rotation, the derived new keypair can sign transactions that
        verify under the new public_key stored on chain."""
        from messagechain.core.transaction import create_transaction
        from messagechain.core.transaction import verify_transaction

        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000

        new_kp = derive_rotated_keypair(entity, rotation_number=0)
        rot_tx = create_key_rotation(entity, new_kp, rotation_number=0)
        chain.apply_key_rotation(rot_tx, proposer_id=entity.entity_id)

        # Build a tx signed by the NEW keypair for the SAME entity_id
        rotated_entity = Entity(
            entity_id=entity.entity_id,
            keypair=new_kp,
            _seed=entity._seed,
        )
        tx = create_transaction(rotated_entity, "hi after rotation", fee=500, nonce=1)

        # Should verify under the new public key stored on chain
        on_chain_pk = chain.public_keys[entity.entity_id]
        self.assertEqual(on_chain_pk, new_kp.public_key)
        self.assertTrue(verify_transaction(tx, on_chain_pk))


if __name__ == "__main__":
    unittest.main()
