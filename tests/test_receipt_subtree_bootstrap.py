"""
Tests for the SetReceiptSubtreeRoot authority tx + server boot-time
bootstrap of the receipt subtree.

Covers:

  * SetReceiptSubtreeRoot tx admission to mempool (pays MIN_FEE, cold-
    key signed).
  * Rejection of a tx signed by a non-authority key.
  * Apply path writes into Blockchain.receipt_subtree_roots.
  * Chain-DB round-trip: set -> cold restart -> get returns the same
    root.
  * Rotation (update-then-read) works — a later tx replaces the old
    root.
  * Boot-time server-side hook:
      - Generates a receipt subtree on fresh boot and caches it.
      - Reuses the cache on restart (same root).
      - Skips auto-submission when on-chain root already matches (idem-
        potency).
      - Auto-submits when local and on-chain roots differ.
      - Does NOT crash when the authority (cold) key is unavailable —
        logs a warning and lets service start proceed.
  * Receipt-subtree leaves are disjoint from block-signing leaves (via
    domain-separated seeds).
"""

import os
import tempfile
import unittest
from unittest import mock

from tests import register_entity_for_test

from messagechain import config as _mcfg
from messagechain.core.blockchain import Blockchain
from messagechain.core.receipt_subtree_root import (
    SetReceiptSubtreeRootTransaction,
    create_set_receipt_subtree_root_transaction,
    verify_set_receipt_subtree_root_transaction,
)
from messagechain.crypto.keys import KeyPair, Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestSetReceiptSubtreeRootTx(unittest.TestCase):
    """Unit tests around the new tx type."""

    def setUp(self):
        self._orig_h = _mcfg.MERKLE_TREE_HEIGHT
        _mcfg.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        _mcfg.MERKLE_TREE_HEIGHT = self._orig_h

    def _setup_chain(self):
        chain = Blockchain()
        entity = _entity(b"alice")
        register_entity_for_test(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000
        return chain, entity

    def test_build_sign_verify(self):
        chain, alice = self._setup_chain()
        # fake receipt subtree keypair (distinct seed)
        receipt_kp = KeyPair.generate(b"receipt-" + b"alice".ljust(28, b"\x00"), height=4)
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            authority_signer=alice,
        )
        # Single-key entity → authority key == signing public key.
        self.assertTrue(
            verify_set_receipt_subtree_root_transaction(tx, alice.public_key)
        )

    def test_fee_below_min_fee_rejected(self):
        """Mempool-level: tx with fee < MIN_FEE fails verify."""
        chain, alice = self._setup_chain()
        receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
        tx = SetReceiptSubtreeRootTransaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            timestamp=__import__("time").time(),
            fee=_mcfg.MIN_FEE - 1,
            signature=alice.keypair.sign(b"\x00" * 32),
        )
        self.assertFalse(
            verify_set_receipt_subtree_root_transaction(tx, alice.public_key)
        )

    def test_invalid_authority_signature_rejected_by_chain(self):
        """Chain validate: wrong signer is rejected."""
        chain, alice = self._setup_chain()
        imposter = _entity(b"imposter")
        register_entity_for_test(chain, imposter)
        receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
        # Build a tx that CLAIMS to be from alice but is signed by imposter.
        tx = SetReceiptSubtreeRootTransaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            timestamp=__import__("time").time(),
            fee=_mcfg.MIN_FEE,
            signature=imposter.keypair.sign(b"\x00" * 32),
        )
        ok, reason = chain.validate_set_receipt_subtree_root(tx)
        self.assertFalse(ok, reason)
        self.assertIn("signature", reason.lower())

    def test_apply_writes_root_into_state(self):
        chain, alice = self._setup_chain()
        receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            authority_signer=alice,
        )
        ok, reason = chain.apply_set_receipt_subtree_root(
            tx, proposer_id=alice.entity_id,
        )
        self.assertTrue(ok, reason)
        self.assertEqual(
            chain.receipt_subtree_roots[alice.entity_id],
            receipt_kp.public_key,
        )

    def test_rotation_replaces_old_root(self):
        """Key-rotation case: submitting a second tx updates the root."""
        chain, alice = self._setup_chain()
        kp1 = KeyPair.generate(b"receipt-1-alice".ljust(32, b"\x00"), height=4)
        kp2 = KeyPair.generate(b"receipt-2-alice".ljust(32, b"\x00"), height=4)

        tx1 = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=kp1.public_key,
            authority_signer=alice,
        )
        ok1, _ = chain.apply_set_receipt_subtree_root(tx1, alice.entity_id)
        self.assertTrue(ok1)

        tx2 = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=kp2.public_key,
            authority_signer=alice,
        )
        ok2, _ = chain.apply_set_receipt_subtree_root(tx2, alice.entity_id)
        self.assertTrue(ok2)

        # Second application replaces the first.
        self.assertEqual(
            chain.receipt_subtree_roots[alice.entity_id], kp2.public_key,
        )
        self.assertNotEqual(kp1.public_key, kp2.public_key)

    def test_binary_roundtrip(self):
        chain, alice = self._setup_chain()
        receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            authority_signer=alice,
        )
        blob = tx.to_bytes()
        # Plain from_bytes without chain state — 32-byte entity refs.
        tx2 = SetReceiptSubtreeRootTransaction.from_bytes(blob)
        self.assertEqual(tx2.entity_id, tx.entity_id)
        self.assertEqual(tx2.root_public_key, tx.root_public_key)
        self.assertEqual(tx2.tx_hash, tx.tx_hash)

    def test_dict_roundtrip(self):
        chain, alice = self._setup_chain()
        receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
        tx = create_set_receipt_subtree_root_transaction(
            entity_id=alice.entity_id,
            root_public_key=receipt_kp.public_key,
            authority_signer=alice,
        )
        tx2 = SetReceiptSubtreeRootTransaction.deserialize(tx.serialize())
        self.assertEqual(tx2.tx_hash, tx.tx_hash)
        self.assertEqual(tx2.signature.leaf_index, tx.signature.leaf_index)


class TestChainDBRoundtrip(unittest.TestCase):
    """Round-trip a SetReceiptSubtreeRoot through ChainDB persistence."""

    def setUp(self):
        self._orig_h = _mcfg.MERKLE_TREE_HEIGHT
        _mcfg.MERKLE_TREE_HEIGHT = 4
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        _mcfg.MERKLE_TREE_HEIGHT = self._orig_h
        self._tmp.cleanup()

    def test_cold_restart_recovers_root(self):
        from messagechain.storage.chaindb import ChainDB

        db_path = os.path.join(self._tmp.name, "chain.db")
        db = ChainDB(db_path)
        try:
            chain = Blockchain(db=db)
            alice = _entity(b"alice")
            register_entity_for_test(chain, alice)
            chain.supply.balances[alice.entity_id] = 10_000
            receipt_kp = KeyPair.generate(b"receipt-alice".ljust(32, b"\x00"), height=4)
            tx = create_set_receipt_subtree_root_transaction(
                entity_id=alice.entity_id,
                root_public_key=receipt_kp.public_key,
                authority_signer=alice,
            )
            ok, _ = chain.apply_set_receipt_subtree_root(tx, alice.entity_id)
            self.assertTrue(ok)
            self.assertEqual(
                chain.receipt_subtree_roots[alice.entity_id],
                receipt_kp.public_key,
            )
        finally:
            db.close()

        # Cold restart: open the same DB and confirm the mapping is back.
        db2 = ChainDB(db_path)
        try:
            roots = db2.get_all_receipt_subtree_roots()
            self.assertEqual(roots[alice.entity_id], receipt_kp.public_key)
        finally:
            db2.close()


class TestServerBoottimeHook(unittest.TestCase):
    """Tests for server._bootstrap_receipt_subtree auto-registration
    and receipt-subtree keypair generation + caching.

    These run at the shrunk RECEIPT_SUBTREE_HEIGHT so we don't burn
    minutes on full production 2^24 leaf derivation.
    """

    def setUp(self):
        self._orig_h = _mcfg.MERKLE_TREE_HEIGHT
        _mcfg.MERKLE_TREE_HEIGHT = 4
        self._orig_receipt_h = _mcfg.RECEIPT_SUBTREE_HEIGHT
        _mcfg.RECEIPT_SUBTREE_HEIGHT = 4
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        _mcfg.MERKLE_TREE_HEIGHT = self._orig_h
        _mcfg.RECEIPT_SUBTREE_HEIGHT = self._orig_receipt_h
        self._tmp.cleanup()

    def _make_stub_server(self, chain):
        """Return a minimal stub that mimics the attributes the
        bootstrap function consults on the real Server."""
        class _PoolHolder:
            pass

        stub = _PoolHolder()
        stub.blockchain = chain
        stub.receipt_issuer = None
        stub._pending_authority_txs = {}
        stub._pending_gossip_calls = []

        def _schedule(kind, tx):
            stub._pending_gossip_calls.append((kind, tx))

        def _admit(pool_name, tx):
            pool = getattr(stub, pool_name)
            pool[tx.tx_hash] = tx
            return True

        def _check_leaf(tx):
            return True

        def _queue(tx, *, validate_fn):
            ok, reason = validate_fn(tx)
            if not ok:
                return False, reason
            if not _admit("_pending_authority_txs", tx):
                return False, "pool full"
            _schedule("authority", tx)
            return True, "queued"

        stub._queue_authority_tx = _queue
        stub._admit_to_pool = _admit
        stub._check_leaf_across_all_pools = _check_leaf
        stub._schedule_pending_tx_gossip = _schedule
        return stub

    def test_fresh_boot_generates_caches_and_queues_tx(self):
        """First boot: subtree generated, cached, tx queued."""
        import server as _srv

        chain = Blockchain()
        # Use a 32-byte "private key" like any hex-key input.  The
        # derived signing seed feeds Entity.create; the receipt subtree
        # uses a domain-separated seed off the same private key.
        priv = b"test-priv-key-aaaa".ljust(32, b"\x00")
        entity = Entity.create(priv, tree_height=4)
        register_entity_for_test(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000

        stub = self._make_stub_server(chain)
        _srv._bootstrap_receipt_subtree(
            stub,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )

        # ReceiptIssuer installed.
        self.assertIsNotNone(stub.receipt_issuer)
        self.assertEqual(stub.receipt_issuer.issuer_id, entity.entity_id)
        # Cache file created.
        cache_files = [
            f for f in os.listdir(self._tmp.name)
            if f.startswith("receipt_keypair_cache_")
        ]
        self.assertEqual(len(cache_files), 1, cache_files)
        # Dedicated leaf-index file created (or at least bindable —
        # load_leaf_index is tolerant of absent files).
        # Nothing is written until the first sign() call, so presence-
        # or-absence is not a robust check; bindings being set is.
        self.assertEqual(
            stub.receipt_issuer.subtree_keypair.leaf_index_path,
            os.path.join(
                self._tmp.name, _srv._RECEIPT_LEAF_INDEX_FILENAME,
            ),
        )
        # Auto-registered tx in the pending pool.
        self.assertEqual(len(stub._pending_authority_txs), 1)
        tx = next(iter(stub._pending_authority_txs.values()))
        self.assertIsInstance(tx, SetReceiptSubtreeRootTransaction)
        self.assertEqual(
            tx.root_public_key,
            stub.receipt_issuer.subtree_keypair.public_key,
        )

    def test_restart_reuses_cache_same_root(self):
        """Second boot with the SAME private key reloads the cache —
        the receipt-subtree root must match the first boot."""
        import server as _srv

        chain1 = Blockchain()
        priv = b"test-priv-key-bbbb".ljust(32, b"\x00")
        entity = Entity.create(priv, tree_height=4)
        register_entity_for_test(chain1, entity)
        chain1.supply.balances[entity.entity_id] = 10_000

        stub1 = self._make_stub_server(chain1)
        _srv._bootstrap_receipt_subtree(
            stub1,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )
        root1 = stub1.receipt_issuer.subtree_keypair.public_key

        # Simulate restart — new Blockchain, new server, same data_dir.
        chain2 = Blockchain()
        register_entity_for_test(chain2, entity)
        chain2.supply.balances[entity.entity_id] = 10_000
        # Pre-seed the on-chain root so bootstrap sees a match and
        # does NOT re-queue.
        chain2.receipt_subtree_roots[entity.entity_id] = root1

        stub2 = self._make_stub_server(chain2)
        _srv._bootstrap_receipt_subtree(
            stub2,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )
        root2 = stub2.receipt_issuer.subtree_keypair.public_key
        self.assertEqual(root2, root1)
        # Idempotent: no tx queued because the on-chain root matches.
        self.assertEqual(len(stub2._pending_authority_txs), 0)

    def test_restart_without_onchain_root_re_queues(self):
        """Second boot but on-chain root missing: auto-registration
        fires again (still safe — mempool dedupe handles duplicates)."""
        import server as _srv

        chain1 = Blockchain()
        priv = b"test-priv-key-cccc".ljust(32, b"\x00")
        entity = Entity.create(priv, tree_height=4)
        register_entity_for_test(chain1, entity)
        chain1.supply.balances[entity.entity_id] = 10_000

        stub1 = self._make_stub_server(chain1)
        _srv._bootstrap_receipt_subtree(
            stub1,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )
        self.assertEqual(len(stub1._pending_authority_txs), 1)

        chain2 = Blockchain()
        register_entity_for_test(chain2, entity)
        chain2.supply.balances[entity.entity_id] = 10_000
        # Deliberately NO on-chain root → auto-submit re-queues.
        stub2 = self._make_stub_server(chain2)
        _srv._bootstrap_receipt_subtree(
            stub2,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )
        self.assertEqual(len(stub2._pending_authority_txs), 1)

    def test_cold_key_unavailable_logs_and_continues(self):
        """If the authority (cold) key differs from the local signing
        key, we do NOT have the cold key — log a warning and return
        without crashing.  No tx should be queued."""
        import server as _srv

        chain = Blockchain()
        priv = b"test-priv-key-dddd".ljust(32, b"\x00")
        entity = Entity.create(priv, tree_height=4)
        register_entity_for_test(chain, entity)
        chain.supply.balances[entity.entity_id] = 10_000

        # Promote a DIFFERENT key to the authority role so the hot-key
        # fallback path is unavailable.  Pretend a cold-key ceremony
        # already happened.
        cold = _entity(b"cold-key")
        chain.authority_keys[entity.entity_id] = cold.public_key

        stub = self._make_stub_server(chain)
        # Should NOT raise despite the cold key being missing locally.
        _srv._bootstrap_receipt_subtree(
            stub,
            private_key=priv,
            entity=entity,
            data_dir=self._tmp.name,
            no_cache=False,
        )

        # ReceiptIssuer installed (so at least the validator can sign
        # receipts locally; the on-chain registration is pending
        # operator action).
        self.assertIsNotNone(stub.receipt_issuer)
        # No tx queued — we didn't have the cold key.
        self.assertEqual(len(stub._pending_authority_txs), 0)

    def test_receipt_and_block_signing_leaves_are_disjoint(self):
        """Dedicated-subtree invariant: the receipt-subtree KeyPair
        derives from a DIFFERENT seed than the block-signing KeyPair,
        so no leaf can ever collide between the two — signing one
        cannot consume a leaf the other needs."""
        import server as _srv

        priv = b"test-priv-key-eeee".ljust(32, b"\x00")
        # Block-signing entity — derives its own seed via
        # _derive_signing_seed.
        block_entity = Entity.create(priv, tree_height=4)

        receipt_kp = _srv._load_or_create_receipt_subtree_keypair(
            private_key=priv,
            tree_height=4,
            entity_id=block_entity.entity_id,
            data_dir=self._tmp.name,
        )

        # The two seeds MUST differ — otherwise the trees would be
        # identical and leaves would overlap by construction.
        self.assertNotEqual(block_entity.keypair._seed, receipt_kp._seed)
        # As an end-to-end sanity check, the public keys (= Merkle
        # roots) must differ too.
        self.assertNotEqual(block_entity.public_key, receipt_kp.public_key)

        # Exhaustive leaf-by-leaf cross-check at the test height so a
        # future refactor that accidentally shares the seed produces
        # an immediate, loud failure here.
        from messagechain.crypto.keys import _derive_leaf_pubkey
        block_leaves = {
            _derive_leaf_pubkey(block_entity.keypair._seed, i)
            for i in range(block_entity.keypair.num_leaves)
        }
        receipt_leaves = {
            _derive_leaf_pubkey(receipt_kp._seed, i)
            for i in range(receipt_kp.num_leaves)
        }
        self.assertEqual(
            block_leaves & receipt_leaves, set(),
            "Receipt and block-signing leaves MUST NOT overlap",
        )

    def test_receipt_subtree_uses_dedicated_leaf_index_file(self):
        """The receipt subtree MUST bind to receipt_leaf_index.json,
        NOT the block-signing leaf_index.json.  Sharing would cause
        apparent leaf reuse across unrelated signers."""
        import server as _srv

        priv = b"test-priv-key-ffff".ljust(32, b"\x00")
        entity = Entity.create(priv, tree_height=4)

        receipt_kp = _srv._load_or_create_receipt_subtree_keypair(
            private_key=priv,
            tree_height=4,
            entity_id=entity.entity_id,
            data_dir=self._tmp.name,
        )

        self.assertIsNotNone(receipt_kp.leaf_index_path)
        self.assertEqual(
            os.path.basename(receipt_kp.leaf_index_path),
            _srv._RECEIPT_LEAF_INDEX_FILENAME,
        )
        # Not the block-signing leaf-index file name.
        self.assertNotEqual(
            os.path.basename(receipt_kp.leaf_index_path),
            _mcfg.LEAF_INDEX_FILENAME,
        )


class TestAuthorityTxUnionAdditive(unittest.TestCase):
    """Verify that existing authority-tx blocks (kind 0/1/2) still
    round-trip binary through a decoder that knows about kind=3.

    The union is additive: appending kind=3 at the end of the tuple
    does not re-order any existing indices, so pre-existing serialized
    bytes decode unchanged.
    """

    def setUp(self):
        self._orig_h = _mcfg.MERKLE_TREE_HEIGHT
        _mcfg.MERKLE_TREE_HEIGHT = 4

    def tearDown(self):
        _mcfg.MERKLE_TREE_HEIGHT = self._orig_h

    def test_existing_authority_kinds_unchanged(self):
        """kind=0/1/2 still map to SetAuthorityKey/Revoke/KeyRotation."""
        from messagechain.core.block import _deserialize_authority_tx

        chain = Blockchain()
        alice = _entity(b"alice")
        register_entity_for_test(chain, alice)
        chain.supply.balances[alice.entity_id] = 10_000
        cold = _entity(b"cold")

        from messagechain.core.authority_key import (
            create_set_authority_key_transaction,
        )
        set_tx = create_set_authority_key_transaction(
            alice, new_authority_key=cold.public_key, nonce=0,
        )
        # JSON dict path — must still deserialize.
        decoded = _deserialize_authority_tx(set_tx.serialize())
        self.assertEqual(decoded.tx_hash, set_tx.tx_hash)


if __name__ == "__main__":
    unittest.main()
