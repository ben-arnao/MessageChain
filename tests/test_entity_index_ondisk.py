"""
Tests for entity-index bloat reduction at the on-disk layer.

The prior entity-index work (commit 5d00ca0) added varint compact
encoding for entity references when the tx/block serializer receives
a `state` kwarg. BUT `ChainDB.store_block` was still calling
`block.to_bytes()` without threading state through, so the compact
form never made it to disk — which is the whole point of the bloat
reduction work.

This suite locks in:

  * `ChainDB.store_block(block, state=state)` writes the compact form.
    The stored BLOB is smaller than the state-free form for any block
    that references at least one registered entity.
  * Round-trip: a block stored via `store_block(block, state=state)`
    decodes back to a semantically identical Block (same tx_hashes,
    same block_hash, same entity_ids on every tx) when loaded via
    `get_block_by_hash(hash, state=state)`.
  * Backward compat: `store_block(block)` with no state still works
    (emits the legacy full-id form).
  * Real-chain regression: driving the normal `Blockchain.add_block`
    persistence path puts compact-form bytes in the DB, and the
    persisted sizes are strictly smaller than the same blocks
    serialized without state.
  * Restart resilience: an index assigned pre-restart still maps to
    the same entity_id post-restart, so compact-form blocks decode
    correctly after a cold reload.
"""

import os
import tempfile
import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _mk_entity(seed: str) -> Entity:
    return Entity.create(seed.encode().ljust(32, b"\x00"))


def _mk_tempdb() -> tuple[ChainDB, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return ChainDB(path), path


class TestStoreBlockUsesState(unittest.TestCase):
    """store_block(block, state=state) must emit the compact form."""

    def setUp(self):
        self._orig_h = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_h

    def test_compact_form_is_smaller_on_disk(self):
        """A stored block's disk BLOB is smaller when state is threaded."""
        db, path = _mk_tempdb()
        try:
            alice = _mk_entity("alice")
            bob = _mk_entity("bob")
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            register_entity_for_test(chain, bob)
            chain.supply.balances[alice.entity_id] = 100_000
            chain.supply.balances[bob.entity_id] = 100_000

            pos = ProofOfStake()
            txs = [
                create_transaction(bob, f"msg {i}", fee=1500, nonce=i)
                for i in range(3)
            ]
            block = chain.propose_block(pos, alice, txs)
            ok, _ = chain.add_block(block)
            self.assertTrue(ok)

            # Read the raw BLOB back from the database.
            cur = db._conn.execute(
                "SELECT data FROM blocks WHERE block_hash = ?",
                (block.block_hash,),
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            on_disk = bytes(row[0])

            state_free = block.to_bytes()  # no state => full 32-byte refs
            self.assertLess(
                len(on_disk), len(state_free),
                f"on-disk form ({len(on_disk)} B) should be smaller than "
                f"state-free form ({len(state_free)} B) — without state "
                f"threading the bloat-reduction work saves nothing."
            )
        finally:
            db.close()
            os.unlink(path)

    def test_roundtrip_with_state(self):
        """store(state) + load(state) yields a Block with identical txs."""
        db, path = _mk_tempdb()
        try:
            alice = _mk_entity("alice")
            bob = _mk_entity("bob")
            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            register_entity_for_test(chain, bob)
            chain.supply.balances[alice.entity_id] = 100_000
            chain.supply.balances[bob.entity_id] = 100_000

            pos = ProofOfStake()
            txs = [create_transaction(bob, "hello", fee=1500, nonce=0)]
            block = chain.propose_block(pos, alice, txs)
            ok, _ = chain.add_block(block)
            self.assertTrue(ok)

            # Fresh DB handle would re-open the same file; use the
            # existing one but round-trip through load.
            loaded = db.get_block_by_hash(block.block_hash, state=chain)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.block_hash, block.block_hash)
            self.assertEqual(
                [tx.tx_hash for tx in loaded.transactions],
                [tx.tx_hash for tx in block.transactions],
            )
            for orig, reloaded in zip(block.transactions, loaded.transactions):
                self.assertEqual(orig.entity_id, reloaded.entity_id)
        finally:
            db.close()
            os.unlink(path)

    def test_stateless_store_still_works(self):
        """Calling store_block without state is backward-compatible."""
        db, path = _mk_tempdb()
        try:
            alice = _mk_entity("alice")
            chain = Blockchain()  # no db
            genesis = chain.initialize_genesis(alice)

            # Legacy call signature — no state kwarg.
            db.store_block(genesis)
            loaded = db.get_block_by_hash(genesis.block_hash)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.block_hash, genesis.block_hash)
        finally:
            db.close()
            os.unlink(path)


class TestPersistedSizesShrink(unittest.TestCase):
    """
    End-to-end regression: blocks written by the real
    `Blockchain.add_block` path are smaller on disk than the
    state-free form would be for the same block.
    """

    def setUp(self):
        self._orig_h = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_h

    def test_multi_block_savings(self):
        db, path = _mk_tempdb()
        try:
            alice = _mk_entity("alice")
            bob = _mk_entity("bob")
            carol = _mk_entity("carol")

            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            register_entity_for_test(chain, bob)
            register_entity_for_test(chain, carol)
            chain.supply.balances[alice.entity_id] = 1_000_000
            chain.supply.balances[bob.entity_id] = 1_000_000
            chain.supply.balances[carol.entity_id] = 1_000_000

            pos = ProofOfStake()
            total_on_disk = 0
            total_state_free = 0
            produced_blocks = []

            # Each block has 2 message txs referencing registered entities.
            # Both senders share the per-entity nonce counter, so we must
            # advance nonces strictly in order across blocks.
            bob_nonce = 0
            carol_nonce = 0
            for i in range(4):
                tx_bob = create_transaction(
                    bob, f"m-{i}", fee=1500, nonce=bob_nonce,
                )
                bob_nonce += 1
                tx_carol = create_transaction(
                    carol, f"n-{i}", fee=1500, nonce=carol_nonce,
                )
                carol_nonce += 1
                block = chain.propose_block(pos, alice, [tx_bob, tx_carol])
                ok, reason = chain.add_block(block)
                self.assertTrue(ok, f"block {i}: {reason}")
                produced_blocks.append(block)

            for blk in produced_blocks:
                cur = db._conn.execute(
                    "SELECT data FROM blocks WHERE block_hash = ?",
                    (blk.block_hash,),
                )
                on_disk = bytes(cur.fetchone()[0])
                total_on_disk += len(on_disk)
                total_state_free += len(blk.to_bytes())

            # Every block with at least one registered-entity tx ref
            # must save at least 1 byte vs the state-free form.
            self.assertLess(
                total_on_disk, total_state_free,
                "on-disk total should be strictly smaller than "
                "state-free total — indicates wiring is broken"
            )
            # Rough sanity: we expect ~29 B saved per registered-entity
            # reference (32-byte id replaced with 1 tag + 1-byte varint).
            # 4 blocks * 2 message txs = 8 refs; at least 8 * 15 = 120 B.
            self.assertGreaterEqual(
                total_state_free - total_on_disk, 100,
                "expected sizeable savings from compact entity refs"
            )
        finally:
            db.close()
            os.unlink(path)


class TestRestartWithCompactForm(unittest.TestCase):
    """After a cold restart, compact-form blocks still decode correctly."""

    def setUp(self):
        self._orig_h = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_h

    def test_entity_indices_survive_restart(self):
        db, path = _mk_tempdb()
        try:
            alice = _mk_entity("alice")
            bob = _mk_entity("bob")

            chain = Blockchain(db=db)
            chain.initialize_genesis(alice)
            register_entity_for_test(chain, bob)
            chain.supply.balances[alice.entity_id] = 100_000
            chain.supply.balances[bob.entity_id] = 100_000

            pos = ProofOfStake()
            txs = [create_transaction(bob, "pre-restart", fee=1500, nonce=0)]
            block = chain.propose_block(pos, alice, txs)
            ok, _ = chain.add_block(block)
            self.assertTrue(ok)

            alice_idx_before = chain.entity_id_to_index[alice.entity_id]
            bob_idx_before = chain.entity_id_to_index[bob.entity_id]
            original_block_hash = block.block_hash
            original_tx_hash = txs[0].tx_hash
            db.close()

            # Cold restart
            db2 = ChainDB(path)
            chain2 = Blockchain(db=db2)
            self.assertEqual(
                chain2.entity_id_to_index[alice.entity_id],
                alice_idx_before,
                "alice's index must be identical after restart",
            )
            self.assertEqual(
                chain2.entity_id_to_index[bob.entity_id],
                bob_idx_before,
                "bob's index must be identical after restart",
            )

            # The persisted compact-form block must decode correctly.
            reloaded = chain2.get_block_by_hash(original_block_hash)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded.block_hash, original_block_hash)
            self.assertEqual(
                reloaded.transactions[0].tx_hash, original_tx_hash
            )
            self.assertEqual(
                reloaded.transactions[0].entity_id, bob.entity_id
            )
            db2.close()
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
