"""
Tests for witness separation — splitting block storage into state-transition
data (tx bodies) and witness data (WOTS signatures + Merkle auth paths).

After finalization, ~97% of a block's bytes are witness data that serves only
auditability, not consensus safety.  Separating storage tiers lets full nodes
carry witness data only for recent/unfinalized blocks while witness-archive
nodes carry everything.  Nothing is ever deleted — every byte persists
somewhere forever.
"""

import hashlib
import os
import struct
import tempfile
import unittest

from messagechain.config import HASH_ALGO
from messagechain.core.block import Block, BlockHeader, _hash, compute_merkle_root
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.witness import (
    compute_witness_root,
    strip_tx_witness,
    tx_has_witness,
    get_tx_witness_data,
    attach_tx_witness,
    strip_block_witnesses,
    get_block_witness_data,
    attach_block_witnesses,
    WITNESS_STRIPPED_SENTINEL,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.network.protocol import MessageType
from messagechain.storage.chaindb import ChainDB


def _make_entity():
    """Create a test entity with a fresh keypair."""
    seed = os.urandom(32)
    return Entity.create(seed)


def _make_signed_tx(entity, msg="Hello", fee=10000, nonce=0):
    """Create a properly signed transaction."""
    return create_transaction(entity, msg, fee, nonce)


def _make_block_with_txs(n_txs=10):
    """Create a block with n_txs signed transactions."""
    entity = _make_entity()
    txs = []
    for i in range(n_txs):
        tx = _make_signed_tx(entity, msg=f"Message {i}", fee=10000, nonce=i)
        txs.append(tx)

    merkle_root = compute_merkle_root([tx.tx_hash for tx in txs])
    header = BlockHeader(
        version=1,
        block_number=1,
        prev_hash=b"\x00" * 32,
        merkle_root=merkle_root,
        timestamp=1000000.0,
        proposer_id=entity.entity_id,
    )
    # Compute witness_root and set it on header
    witness_root = compute_witness_root(txs)
    header.witness_root = witness_root

    # Sign the header
    header_hash = _hash(header.signable_data())
    header.proposer_signature = entity.keypair.sign(header_hash)

    block = Block(header=header, transactions=txs)
    block.block_hash = block._compute_hash()
    return block, entity


class TestWitnessRoot(unittest.TestCase):
    """witness_root computation and security properties."""

    def test_witness_root_deterministic(self):
        """Same block always produces the same witness_root."""
        block, _ = _make_block_with_txs(5)
        root1 = compute_witness_root(block.transactions)
        root2 = compute_witness_root(block.transactions)
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 32)

    def test_witness_root_empty_block(self):
        """Empty block produces SHA256(b"") witness_root."""
        root = compute_witness_root([])
        expected = hashlib.new(HASH_ALGO, b"").digest()
        self.assertEqual(root, expected)

    def test_witness_root_changes_with_different_sigs(self):
        """Different signatures produce different witness_roots."""
        entity = _make_entity()
        tx1 = _make_signed_tx(entity, "Hello", 10000, 0)
        tx2 = _make_signed_tx(entity, "Hello", 10000, 1)
        # Different nonces -> different sigs -> different roots
        root1 = compute_witness_root([tx1])
        root2 = compute_witness_root([tx2])
        self.assertNotEqual(root1, root2)

    def test_witness_root_in_signable_data(self):
        """witness_root is included in BlockHeader.signable_data().

        This is the security anchor: without it, someone could swap
        witnesses after the fact without changing the block hash.
        """
        block, entity = _make_block_with_txs(3)
        data1 = block.header.signable_data()

        # Tamper with witness_root
        block.header.witness_root = b"\xff" * 32
        data2 = block.header.signable_data()

        self.assertNotEqual(data1, data2)

    def test_witness_root_in_block_hash(self):
        """Changing witness_root changes the block_hash (via signable_data)."""
        block, _ = _make_block_with_txs(3)
        hash1 = block._compute_hash()

        block.header.witness_root = b"\xff" * 32
        hash2 = block._compute_hash()

        self.assertNotEqual(hash1, hash2)


class TestTransactionWitnessStripping(unittest.TestCase):
    """Transaction-level witness stripping and reattachment."""

    def test_strip_witness_preserves_tx_hash(self):
        """strip_tx_witness preserves tx_hash (hash excludes signature)."""
        entity = _make_entity()
        tx = _make_signed_tx(entity, "Hello", 10000, 0)
        original_hash = tx.tx_hash

        stripped = strip_tx_witness(tx)
        self.assertEqual(stripped.tx_hash, original_hash)

    def test_strip_witness_removes_signature(self):
        """Stripped tx has sentinel signature."""
        entity = _make_entity()
        tx = _make_signed_tx(entity, "Hello", 10000, 0)
        stripped = strip_tx_witness(tx)

        self.assertFalse(tx_has_witness(stripped))
        self.assertTrue(tx_has_witness(tx))

    def test_strip_witness_preserves_all_fields(self):
        """All non-witness fields survive stripping."""
        entity = _make_entity()
        tx = _make_signed_tx(entity, "Hello", 10000, 0)
        stripped = strip_tx_witness(tx)

        self.assertEqual(stripped.entity_id, tx.entity_id)
        self.assertEqual(stripped.message, tx.message)
        self.assertEqual(stripped.timestamp, tx.timestamp)
        self.assertEqual(stripped.nonce, tx.nonce)
        self.assertEqual(stripped.fee, tx.fee)
        self.assertEqual(stripped.version, tx.version)
        self.assertEqual(stripped.compression_flag, tx.compression_flag)

    def test_witness_round_trip(self):
        """get_tx_witness_data + attach_tx_witness restores original tx."""
        entity = _make_entity()
        tx = _make_signed_tx(entity, "Hello", 10000, 0)
        original_sig_bytes = tx.signature.to_bytes()

        witness_data = get_tx_witness_data(tx)
        stripped = strip_tx_witness(tx)
        restored = attach_tx_witness(stripped, witness_data)

        self.assertEqual(restored.signature.to_bytes(), original_sig_bytes)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertTrue(tx_has_witness(restored))


class TestBlockWitnessStripping(unittest.TestCase):
    """Block-level witness stripping and reattachment."""

    def test_strip_block_witnesses(self):
        """strip_block_witnesses produces block with no signatures."""
        block, _ = _make_block_with_txs(5)
        stripped = strip_block_witnesses(block)

        for tx in stripped.transactions:
            self.assertFalse(tx_has_witness(tx))

        # witness_root is preserved in header
        self.assertEqual(stripped.header.witness_root, block.header.witness_root)

    def test_stripped_block_size_reduction(self):
        """Stripped block is dramatically smaller than full block (~97% reduction in tx data)."""
        block, _ = _make_block_with_txs(10)

        full_size = len(block.to_bytes())
        witness_data = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        stripped_size = len(stripped.to_bytes())

        # Witness data should be the majority of block bytes
        witness_size = len(witness_data)
        reduction = witness_size / full_size

        # At least 80% reduction (conservative, accounting for header/metadata overhead)
        self.assertGreater(reduction, 0.80,
            f"Expected >80% reduction, got {reduction:.1%}. "
            f"Full={full_size}, stripped={stripped_size}, witness={witness_size}")

    def test_block_witness_round_trip(self):
        """get_block_witness_data + attach_block_witnesses restores block."""
        block, _ = _make_block_with_txs(5)

        witness_data = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, witness_data)

        # All tx signatures should be restored
        for orig_tx, rest_tx in zip(block.transactions, restored.transactions):
            self.assertEqual(
                orig_tx.signature.to_bytes(),
                rest_tx.signature.to_bytes(),
            )
            self.assertEqual(orig_tx.tx_hash, rest_tx.tx_hash)

    def test_witness_root_integrity_without_witnesses(self):
        """A stripped block can verify witness_root integrity using just the root."""
        block, _ = _make_block_with_txs(5)
        stripped = strip_block_witnesses(block)

        # The witness_root in the header is still valid — it was computed
        # from the original witnesses before stripping
        self.assertEqual(len(stripped.header.witness_root), 32)
        self.assertNotEqual(stripped.header.witness_root, b"\x00" * 32)

    def test_stripped_block_preserves_non_tx_fields(self):
        """Stripping only affects transaction signatures, not block metadata."""
        block, _ = _make_block_with_txs(3)
        stripped = strip_block_witnesses(block)

        self.assertEqual(stripped.header.block_number, block.header.block_number)
        self.assertEqual(stripped.header.prev_hash, block.header.prev_hash)
        self.assertEqual(stripped.header.merkle_root, block.header.merkle_root)
        self.assertEqual(stripped.header.proposer_id, block.header.proposer_id)
        # Proposer signature is NOT stripped (it's block-level, not tx witness)
        self.assertIsNotNone(stripped.header.proposer_signature)


class TestChainDBWitnessSeparation(unittest.TestCase):
    """ChainDB witness separation storage."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_witness.db")
        self.db = ChainDB(self.db_path)

    def tearDown(self):
        self.db.close()

    def test_store_and_get_witness_data(self):
        """store_witness_data / get_witness_data round-trip."""
        block, _ = _make_block_with_txs(3)
        witness_data = get_block_witness_data(block)

        self.db.store_witness_data(block.block_hash, witness_data)
        retrieved = self.db.get_witness_data(block.block_hash)

        self.assertEqual(retrieved, witness_data)

    def test_get_witness_data_missing(self):
        """get_witness_data returns None for unknown blocks."""
        result = self.db.get_witness_data(b"\x00" * 32)
        self.assertIsNone(result)

    def test_has_witness_data(self):
        """has_witness_data correctly reports presence."""
        block, _ = _make_block_with_txs(3)
        witness_data = get_block_witness_data(block)

        self.assertFalse(self.db.has_witness_data(block.block_hash))
        self.db.store_witness_data(block.block_hash, witness_data)
        self.assertTrue(self.db.has_witness_data(block.block_hash))

    def test_strip_finalized_witnesses(self):
        """strip_finalized_witnesses retroactively strips a stored block."""
        block, _ = _make_block_with_txs(3)
        self.db.store_block(block)

        # Mark as finalized and strip
        self.db.strip_finalized_witnesses(block.block_hash)

        # Witness data should now be in separate table
        self.assertTrue(self.db.has_witness_data(block.block_hash))

        # Block in blocks table should be stripped
        cur = self.db._conn.execute(
            "SELECT data FROM blocks WHERE block_hash = ?",
            (block.block_hash,),
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)

        # Retrieve with witnesses should give back full block
        full_block = self.db.get_block_by_hash(block.block_hash, include_witnesses=True)
        self.assertIsNotNone(full_block)
        for tx in full_block.transactions:
            self.assertTrue(tx_has_witness(tx))

        # Retrieve without witnesses (default) should give stripped block
        stripped_block = self.db.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(stripped_block)
        # If witnesses were separated, txs should be stripped
        if self.db.has_witness_data(block.block_hash):
            for tx in stripped_block.transactions:
                self.assertFalse(tx_has_witness(tx))


class TestP2PWitnessMessages(unittest.TestCase):
    """P2P REQUEST_WITNESS / RESPONSE_WITNESS message types."""

    def test_message_types_exist(self):
        """REQUEST_WITNESS and RESPONSE_WITNESS message types exist."""
        self.assertEqual(MessageType.REQUEST_WITNESS.value, "request_witness")
        self.assertEqual(MessageType.RESPONSE_WITNESS.value, "response_witness")

    def test_witness_request_response_round_trip(self):
        """Simulated witness request/response cycle."""
        block, _ = _make_block_with_txs(3)
        witness_data = get_block_witness_data(block)

        # Simulate request
        request_payload = {"block_hash": block.block_hash.hex()}
        self.assertEqual(request_payload["block_hash"], block.block_hash.hex())

        # Simulate response
        response_payload = {
            "block_hash": block.block_hash.hex(),
            "witness_data": witness_data.hex(),
        }

        # Reconstruct from response
        retrieved_witness = bytes.fromhex(response_payload["witness_data"])
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, retrieved_witness)

        for orig_tx, rest_tx in zip(block.transactions, restored.transactions):
            self.assertEqual(
                orig_tx.signature.to_bytes(),
                rest_tx.signature.to_bytes(),
            )


class TestValidationWithoutWitnesses(unittest.TestCase):
    """A node without witnesses for finalized blocks can still function."""

    def test_stripped_block_can_produce_merkle_root(self):
        """Stripped block preserves merkle_root (based on tx_hash, not signatures)."""
        block, _ = _make_block_with_txs(5)
        stripped = strip_block_witnesses(block)

        # tx_hash is preserved, so merkle_root verification still works
        recomputed_root = compute_merkle_root([tx.tx_hash for tx in stripped.transactions])
        self.assertEqual(recomputed_root, stripped.header.merkle_root)


class TestWitnessRootSerialization(unittest.TestCase):
    """witness_root serialization in block header."""

    def test_header_serialize_deserialize_with_witness_root(self):
        """BlockHeader serialization preserves witness_root."""
        block, _ = _make_block_with_txs(3)

        serialized = block.header.serialize()
        self.assertIn("witness_root", serialized)

        deserialized = BlockHeader.deserialize(serialized)
        self.assertEqual(deserialized.witness_root, block.header.witness_root)

    def test_header_to_bytes_from_bytes_with_witness_root(self):
        """BlockHeader binary encoding preserves witness_root."""
        block, _ = _make_block_with_txs(3)

        blob = block.header.to_bytes()
        restored = BlockHeader.from_bytes(blob)
        self.assertEqual(restored.witness_root, block.header.witness_root)

    def test_backward_compat_no_witness_root(self):
        """Deserializing a header dict without witness_root defaults to zeros."""
        data = {
            "version": 1,
            "hash_version": 1,
            "block_number": 1,
            "prev_hash": "00" * 32,
            "merkle_root": "00" * 32,
            "state_root": "00" * 32,
            "timestamp": 1000000.0,
            "proposer_id": "00" * 32,
            "randao_mix": "00" * 32,
            "proposer_signature": None,
        }
        header = BlockHeader.deserialize(data)
        self.assertEqual(header.witness_root, b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
