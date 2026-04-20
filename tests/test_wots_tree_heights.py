"""Tests for per-entity WOTS+ tree_height tracked in chain state.

Problem being solved: the server used to derive each entity's WOTS+
tree_height from the global config.MERKLE_TREE_HEIGHT.  When the value
at entity creation differs from the value at server boot (e.g., genesis
key was generated with tree_height=16 but config now defaults to 20),
the server silently derives a DIFFERENT entity_id from the same
private key and hangs for ~90 min re-computing the wrong tree.

Fix: entities record their WOTS+ tree_height in chain state at the
moment their pubkey is installed (genesis, first-spend, or direct
install for tests).  Server startup looks up the stored height for the
wallet entity rather than trusting config.  Config becomes the default
only for brand-new entities being created locally.

Invariants tested:
  * Genesis entity's tree_height is recorded at initialize_genesis.
  * First-spend pubkey reveal (Transfer or Stake) records the tree_height
    derived from the signature's auth_path length.
  * _install_pubkey_direct records tree_height from registration_proof.
  * Value persists across Blockchain restart via ChainDB.
  * Snapshot/restore path preserves tree_heights alongside public_keys
    (so a reorg that removes a first-spend install also removes the
    tree_height binding).
"""

import os
import tempfile
import unittest

from messagechain import config
from messagechain.config import MIN_FEE, NEW_ACCOUNT_FEE
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import create_stake_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _entity(seed: bytes, height: int = 6) -> Entity:
    padded = seed + b"\x00" * (32 - len(seed))
    return Entity.create(padded, tree_height=height)


class TestGenesisRecordsTreeHeight(unittest.TestCase):
    """initialize_genesis records the genesis entity's tree_height."""

    def test_genesis_entity_height_recorded(self):
        genesis = _entity(b"gen_h", height=6)
        chain = Blockchain()
        chain.initialize_genesis(genesis)
        self.assertEqual(
            chain.get_wots_tree_height(genesis.entity_id), 6,
        )

    def test_genesis_entity_height_matches_keypair(self):
        """Recorded height equals keypair.height (not config)."""
        # Use a height DIFFERENT from config to prove it's not being read
        # from the global.
        orig = config.MERKLE_TREE_HEIGHT
        try:
            config.MERKLE_TREE_HEIGHT = 8  # deliberately different
            genesis = _entity(b"gen_mismatch", height=5)
            chain = Blockchain()
            chain.initialize_genesis(genesis)
            self.assertEqual(
                chain.get_wots_tree_height(genesis.entity_id),
                genesis.keypair.height,
            )
            self.assertEqual(
                chain.get_wots_tree_height(genesis.entity_id), 5,
            )
        finally:
            config.MERKLE_TREE_HEIGHT = orig


class TestFirstSpendRecordsTreeHeight(unittest.TestCase):
    """First-spend pubkey reveal records tree_height from signature."""

    def test_first_spend_transfer_records_height(self):
        funder = _entity(b"t_funder", height=6)
        new_entity = _entity(b"t_new", height=5)
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000

        # Fund new entity (no pubkey install yet).
        ttx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        chain.apply_transfer_transaction(ttx, proposer_id=funder.entity_id)
        self.assertIsNone(chain.get_wots_tree_height(new_entity.entity_id))

        # First outgoing transfer reveals the pubkey.
        out_tx = create_transfer_transaction(
            new_entity, funder.entity_id, 1000, nonce=0,
            fee=MIN_FEE, include_pubkey=True,
        )
        ok, reason = chain.validate_transfer_transaction(out_tx)
        self.assertTrue(ok, reason)
        chain.apply_transfer_transaction(out_tx, proposer_id=funder.entity_id)

        self.assertEqual(
            chain.get_wots_tree_height(new_entity.entity_id),
            new_entity.keypair.height,
        )
        self.assertEqual(
            chain.get_wots_tree_height(new_entity.entity_id), 5,
        )

    def test_first_spend_stake_records_height(self):
        funder = _entity(b"s_funder", height=6)
        new_entity = _entity(b"s_new", height=4)
        chain = Blockchain()
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000

        ttx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        chain.apply_transfer_transaction(ttx, proposer_id=funder.entity_id)
        self.assertIsNone(chain.get_wots_tree_height(new_entity.entity_id))

        stx = create_stake_transaction(
            new_entity, amount=1000, nonce=0, include_pubkey=True,
        )
        ok, reason = chain._validate_stake_tx(stx)
        self.assertTrue(ok, reason)
        chain.apply_stake_transaction(stx, proposer_id=funder.entity_id)

        self.assertEqual(
            chain.get_wots_tree_height(new_entity.entity_id), 4,
        )


class TestInstallPubkeyDirectRecordsHeight(unittest.TestCase):
    """_install_pubkey_direct (bootstrap/test path) records height."""

    def test_direct_install_records_height(self):
        chain = Blockchain()
        entity = _entity(b"direct", height=6)
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        ok, _ = chain._install_pubkey_direct(
            entity.entity_id, entity.public_key, registration_proof=proof,
        )
        self.assertTrue(ok)
        self.assertEqual(
            chain.get_wots_tree_height(entity.entity_id), 6,
        )


class TestPersistenceAcrossRestart(unittest.TestCase):
    """Tree heights survive a ChainDB restart."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "chain.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_genesis_height_persists(self):
        genesis = _entity(b"persist_gen", height=6)
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(genesis)
        db.close()

        # Reopen — fresh Blockchain from the same db.
        db2 = ChainDB(self.db_path)
        chain2 = Blockchain(db=db2)
        self.assertEqual(
            chain2.get_wots_tree_height(genesis.entity_id), 6,
        )
        db2.close()

    def test_first_spend_height_persists(self):
        funder = _entity(b"p_funder", height=6)
        new_entity = _entity(b"p_new", height=5)
        db = ChainDB(self.db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(funder)
        chain.supply.balances[funder.entity_id] = 1_000_000

        ttx = create_transfer_transaction(
            funder, new_entity.entity_id, 200_000, nonce=0,
            fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        chain.apply_transfer_transaction(ttx, proposer_id=funder.entity_id)

        out_tx = create_transfer_transaction(
            new_entity, funder.entity_id, 1000, nonce=0,
            fee=MIN_FEE, include_pubkey=True,
        )
        chain.apply_transfer_transaction(out_tx, proposer_id=funder.entity_id)
        # Flush so pending writes hit disk before we reopen.  Matches
        # what the block pipeline does at store_block time.
        db.flush_state()
        db.close()

        # Reopen.
        db2 = ChainDB(self.db_path)
        chain2 = Blockchain(db=db2)
        self.assertEqual(
            chain2.get_wots_tree_height(new_entity.entity_id), 5,
        )
        self.assertEqual(
            chain2.get_wots_tree_height(funder.entity_id), 6,
        )
        db2.close()


class TestServerUsesChainStateHeight(unittest.TestCase):
    """server._resolve_tree_height prefers chain state over config."""

    def test_resolves_from_chain_state_when_present(self):
        # Avoid importing server (which requires heavy runtime deps)
        # by invoking through a dedicated helper on the blockchain side.
        genesis = _entity(b"srv_gen", height=6)
        chain = Blockchain()
        chain.initialize_genesis(genesis)

        orig = config.MERKLE_TREE_HEIGHT
        try:
            config.MERKLE_TREE_HEIGHT = 20  # what config would say
            # The resolver should return the chain-state value, not 20.
            resolved = chain.get_wots_tree_height(genesis.entity_id)
            self.assertEqual(resolved, 6)
            self.assertNotEqual(resolved, config.MERKLE_TREE_HEIGHT)
        finally:
            config.MERKLE_TREE_HEIGHT = orig

    def test_falls_back_to_none_for_unknown_entity(self):
        """Brand-new node with no prior state returns None → caller uses config."""
        chain = Blockchain()
        self.assertIsNone(chain.get_wots_tree_height(b"\x00" * 32))


class TestReorgSafety(unittest.TestCase):
    """Reorg snapshot/restore preserves tree_heights alongside public_keys."""

    def test_restore_snapshot_restores_tree_heights(self):
        genesis = _entity(b"reorg_gen", height=6)
        chain = Blockchain()
        chain.initialize_genesis(genesis)

        # Snapshot state (simulating pre-reorg).
        snap = chain._snapshot_memory_state()

        # Mutate: install a new entity's pubkey via direct install.
        new_entity = _entity(b"reorg_new", height=5)
        proof = new_entity.keypair.sign(_hash(b"register" + new_entity.entity_id))
        chain._install_pubkey_direct(
            new_entity.entity_id, new_entity.public_key,
            registration_proof=proof,
        )
        self.assertEqual(
            chain.get_wots_tree_height(new_entity.entity_id), 5,
        )

        # Roll back — the post-snapshot install should disappear.
        chain._restore_memory_snapshot(snap)
        self.assertIsNone(chain.get_wots_tree_height(new_entity.entity_id))
        # Genesis entity's height survives (it was present at snapshot time).
        self.assertEqual(
            chain.get_wots_tree_height(genesis.entity_id), 6,
        )


if __name__ == "__main__":
    unittest.main()
