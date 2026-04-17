"""Binary serialization for storage and wire.

Current JSON+hex storage inflates a raw transaction from ~2.7KB binary to
~5.7KB stored — a ~2x bloat. The full-history model means that wasted byte
compounds forever, so we add a compact binary format for on-disk and on-wire
bytes while keeping dict-based serialize() methods for human-readable
RPC/CLI output.

Tests assert:
- Round-trip: to_bytes → from_bytes preserves every field exactly.
- Consensus hashes are UNCHANGED — binary format is storage-only, not
  consensus-layer. _signable_data continues to produce the same bytes so
  tx_hash / block_hash are identical before and after the change.
- Stored block size is < 60% of the current JSON-hex size for a realistic
  block (10 message txs with 100-byte payloads each).
- SQLite stores block data as BLOB, not TEXT.
"""

import json
import os
import tempfile
import time
import unittest

from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import TransferTransaction, create_transfer_transaction
from messagechain.core.staking import (
    StakeTransaction, UnstakeTransaction,
    create_stake_transaction, create_unstake_transaction,
)
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction,
    create_set_authority_key_transaction,
)
from messagechain.core.emergency_revoke import (
    RevokeTransaction, create_revoke_transaction,
)
from messagechain.core.key_rotation import (
    KeyRotationTransaction, create_key_rotation, derive_rotated_keypair,
)
from messagechain.core.block import Block, BlockHeader, compute_merkle_root, _hash
from messagechain.consensus.attestation import Attestation, create_attestation
from messagechain.consensus.slashing import (
    SlashingEvidence, AttestationSlashingEvidence, SlashTransaction,
    create_slash_transaction,
)
from messagechain.governance.governance import (
    ProposalTransaction, VoteTransaction, TreasurySpendTransaction,
    create_proposal, create_vote, create_treasury_spend_proposal,
)
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


class TestMessageTransactionBinary(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-binary-key".ljust(32, b"\x00"))

    def test_roundtrip_preserves_fields(self):
        tx = create_transaction(self.alice, "hello, world!", fee=1500, nonce=0)
        blob = tx.to_bytes()
        self.assertIsInstance(blob, bytes)
        decoded = MessageTransaction.from_bytes(blob)
        self.assertEqual(decoded.entity_id, tx.entity_id)
        self.assertEqual(decoded.message, tx.message)
        self.assertEqual(decoded.timestamp, tx.timestamp)
        self.assertEqual(decoded.nonce, tx.nonce)
        self.assertEqual(decoded.fee, tx.fee)
        self.assertEqual(decoded.ttl, tx.ttl)
        self.assertEqual(decoded.version, tx.version)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.signature.wots_signature, tx.signature.wots_signature)
        self.assertEqual(decoded.signature.leaf_index, tx.signature.leaf_index)
        self.assertEqual(decoded.signature.auth_path, tx.signature.auth_path)
        self.assertEqual(decoded.signature.wots_public_key, tx.signature.wots_public_key)
        self.assertEqual(decoded.signature.wots_public_seed, tx.signature.wots_public_seed)

    def test_binary_is_smaller_than_json(self):
        """Binary encoding of a tx is much smaller than its JSON-hex form."""
        tx = create_transaction(self.alice, "A" * 100, fee=5000, nonce=0)
        binary_size = len(tx.to_bytes())
        json_size = len(json.dumps(tx.serialize()).encode("utf-8"))
        # Binary must be < 60% of JSON for this realistic tx
        self.assertLess(binary_size, json_size * 0.6,
                        f"binary={binary_size} json={json_size}")

    def test_consensus_hash_unchanged(self):
        """Binary format is storage-only — tx_hash is unchanged."""
        tx = create_transaction(self.alice, "consensus test", fee=1500, nonce=0)
        recorded = tx.tx_hash
        decoded = MessageTransaction.from_bytes(tx.to_bytes())
        # tx_hash derives from _signable_data — same bytes → same hash
        self.assertEqual(decoded.tx_hash, recorded)
        # And _signable_data itself must be byte-identical
        self.assertEqual(decoded._signable_data(), tx._signable_data())

    def test_from_bytes_rejects_truncated(self):
        tx = create_transaction(self.alice, "ok", fee=1500, nonce=0)
        blob = tx.to_bytes()
        with self.assertRaises(Exception):
            MessageTransaction.from_bytes(blob[:-10])

    def test_from_bytes_tamper_detected(self):
        """Flipping a consensus-covered byte yields a hash mismatch on decode.

        The tx layout starts with 4 bytes of version, then a 1-byte
        entity-ref tag, then the 32-byte entity_id (tag=0x00 legacy
        form). Flipping a bit inside entity_id desyncs _signable_data
        from the declared tx_hash, so from_bytes raises on the
        integrity check. (WOTS chain bytes are NOT hash-integrity-
        checked at decode — they're verified separately by
        verify_signature, so flipping one there would pass decode and
        fail later validation.)
        """
        tx = create_transaction(self.alice, "tamper", fee=1500, nonce=0)
        blob = bytearray(tx.to_bytes())
        # Flip the first byte of entity_id (offset 5, after u32 version
        # at [0..4) and the 1-byte entity-ref tag at [4]).
        blob[5] ^= 0x01
        with self.assertRaises(Exception):
            MessageTransaction.from_bytes(bytes(blob))


class TestSignatureBinary(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-sig-binary".ljust(32, b"\x00"))
        self.tx = create_transaction(self.alice, "sig test", fee=1500, nonce=0)

    def test_signature_roundtrip(self):
        sig = self.tx.signature
        blob = sig.to_bytes()
        decoded = Signature.from_bytes(blob)
        self.assertEqual(decoded.wots_signature, sig.wots_signature)
        self.assertEqual(decoded.leaf_index, sig.leaf_index)
        self.assertEqual(decoded.auth_path, sig.auth_path)
        self.assertEqual(decoded.wots_public_key, sig.wots_public_key)
        self.assertEqual(decoded.wots_public_seed, sig.wots_public_seed)


class TestBlockBinary(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-block-bin".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-block-bin".ljust(32, b"\x00"))

    def _make_tx(self, entity, nonce, msg="hello"):
        return create_transaction(entity, msg, fee=2000, nonce=nonce)

    def test_empty_block_roundtrip(self):
        header = BlockHeader(
            version=1, block_number=0,
            prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"genesis"),
            timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        sig_hash = _hash(header.signable_data())
        header.proposer_signature = self.alice.keypair.sign(sig_hash)
        block = Block(header=header, transactions=[])
        block.block_hash = block._compute_hash()

        blob = block.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.block_hash, block.block_hash)
        self.assertEqual(decoded.header.block_number, block.header.block_number)
        self.assertEqual(decoded.header.proposer_id, block.header.proposer_id)
        self.assertEqual(decoded.transactions, [])

    def test_block_with_messages_roundtrip(self):
        txs = [self._make_tx(self.alice, i, f"msg {i}") for i in range(3)]
        merkle = compute_merkle_root([t.tx_hash for t in txs])
        header = BlockHeader(
            version=1, block_number=5,
            prev_hash=b"\xaa" * 32,
            merkle_root=merkle,
            timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        header.proposer_signature = self.alice.keypair.sign(_hash(header.signable_data()))
        block = Block(header=header, transactions=txs)

        blob = block.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.block_hash, block.block_hash)
        self.assertEqual(len(decoded.transactions), 3)
        for orig, new in zip(txs, decoded.transactions):
            self.assertEqual(new.tx_hash, orig.tx_hash)
            self.assertEqual(new.message, orig.message)

    def test_block_with_validator_signatures(self):
        txs = [self._make_tx(self.alice, 0, "m1")]
        merkle = compute_merkle_root([t.tx_hash for t in txs])
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x11" * 32,
            merkle_root=merkle, timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        header.proposer_signature = self.alice.keypair.sign(_hash(header.signable_data()))

        vsig = self.bob.keypair.sign(_hash(b"validator-test"))
        val_sigs = [(self.bob.entity_id, vsig)]
        block = Block(header=header, transactions=txs, validator_signatures=val_sigs)

        blob = block.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(len(decoded.validator_signatures), 1)
        self.assertEqual(decoded.validator_signatures[0][0], self.bob.entity_id)
        self.assertEqual(
            decoded.validator_signatures[0][1].wots_public_key,
            vsig.wots_public_key,
        )

    def test_realistic_block_under_60pct_of_json(self):
        """Storage goal: a 10-tx block (100-byte payloads) is < 60% of current JSON-hex."""
        txs = [self._make_tx(self.alice, i, "X" * 100) for i in range(10)]
        merkle = compute_merkle_root([t.tx_hash for t in txs])
        header = BlockHeader(
            version=1, block_number=42, prev_hash=b"\x00" * 32,
            merkle_root=merkle, timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        header.proposer_signature = self.alice.keypair.sign(_hash(header.signable_data()))
        block = Block(header=header, transactions=txs)

        binary_size = len(block.to_bytes())
        json_size = len(json.dumps(block.serialize()).encode("utf-8"))
        self.assertLess(binary_size, json_size * 0.6,
                        f"binary={binary_size} json={json_size} ratio={binary_size/json_size:.2%}")
        # Also confirm the reduction is a substantial fraction
        self.assertLess(binary_size / json_size, 0.55)

    def test_block_with_all_tx_types(self):
        """Roundtrip a block that carries every tx type the block supports."""
        # Message tx
        msg_tx = self._make_tx(self.alice, 0, "all types")

        # Transfer tx
        xfer_tx = create_transfer_transaction(
            self.alice, self.bob.entity_id, amount=100, nonce=1, fee=100,
        )

        # Stake / unstake
        stake_tx = create_stake_transaction(self.alice, amount=1_000_000, nonce=2)
        unstake_tx = create_unstake_transaction(self.alice, amount=500_000, nonce=3)

        # Authority / revoke / rotation
        auth_tx = create_set_authority_key_transaction(
            self.alice, new_authority_key=self.bob.public_key, nonce=4,
        )
        revoke_tx = create_revoke_transaction(self.alice)
        new_kp = derive_rotated_keypair(self.alice, rotation_number=1)
        rotate_tx = create_key_rotation(self.alice, new_kp, rotation_number=1)

        # Governance
        prop_tx = create_proposal(self.alice, "Test proposal", "description text")
        vote_tx = create_vote(self.alice, prop_tx.tx_hash, approve=True)
        treasury_tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, amount=500, title="T", description="D",
        )

        # Attestation
        att = create_attestation(self.bob, msg_tx.tx_hash, block_number=1)

        merkle = compute_merkle_root([msg_tx.tx_hash])
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x22" * 32,
            merkle_root=merkle, timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        header.proposer_signature = self.alice.keypair.sign(_hash(header.signable_data()))
        block = Block(
            header=header,
            transactions=[msg_tx],
            transfer_transactions=[xfer_tx],
            stake_transactions=[stake_tx],
            unstake_transactions=[unstake_tx],
            authority_txs=[auth_tx, revoke_tx, rotate_tx],
            governance_txs=[prop_tx, vote_tx, treasury_tx],
            attestations=[att],
        )

        blob = block.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.block_hash, block.block_hash)
        self.assertEqual(len(decoded.transactions), 1)
        self.assertEqual(len(decoded.transfer_transactions), 1)
        self.assertEqual(len(decoded.stake_transactions), 1)
        self.assertEqual(len(decoded.unstake_transactions), 1)
        self.assertEqual(len(decoded.authority_txs), 3)
        self.assertEqual(len(decoded.governance_txs), 3)
        self.assertEqual(len(decoded.attestations), 1)
        # Hash preservation
        self.assertEqual(decoded.transfer_transactions[0].tx_hash, xfer_tx.tx_hash)
        self.assertEqual(decoded.stake_transactions[0].tx_hash, stake_tx.tx_hash)
        self.assertEqual(decoded.attestations[0].block_hash, att.block_hash)


class TestBlockHeaderBinary(unittest.TestCase):
    def test_header_roundtrip_with_signature(self):
        alice = Entity.create(b"alice-hdr".ljust(32, b"\x00"))
        header = BlockHeader(
            version=1, block_number=42,
            prev_hash=b"\x11" * 32, merkle_root=b"\x22" * 32,
            state_root=b"\x33" * 32, randao_mix=b"\x44" * 32,
            timestamp=time.time(), proposer_id=alice.entity_id,
        )
        header.proposer_signature = alice.keypair.sign(_hash(header.signable_data()))

        blob = header.to_bytes()
        decoded = BlockHeader.from_bytes(blob)
        self.assertEqual(decoded.version, header.version)
        self.assertEqual(decoded.block_number, header.block_number)
        self.assertEqual(decoded.prev_hash, header.prev_hash)
        self.assertEqual(decoded.merkle_root, header.merkle_root)
        self.assertEqual(decoded.state_root, header.state_root)
        self.assertEqual(decoded.randao_mix, header.randao_mix)
        self.assertEqual(int(decoded.timestamp), int(header.timestamp))
        self.assertEqual(decoded.proposer_id, header.proposer_id)
        self.assertIsNotNone(decoded.proposer_signature)
        self.assertEqual(
            decoded.proposer_signature.wots_public_key,
            header.proposer_signature.wots_public_key,
        )

    def test_header_roundtrip_without_signature(self):
        alice = Entity.create(b"alice-hdr2".ljust(32, b"\x00"))
        header = BlockHeader(
            version=1, block_number=0,
            prev_hash=b"\x00" * 32, merkle_root=b"\x11" * 32,
            timestamp=time.time(), proposer_id=alice.entity_id,
        )
        blob = header.to_bytes()
        decoded = BlockHeader.from_bytes(blob)
        self.assertIsNone(decoded.proposer_signature)


class TestChainDBBinaryStorage(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "chain.db")
        self.db = ChainDB(self.db_path)
        self.alice = Entity.create(b"alice-chaindb-bin".ljust(32, b"\x00"))

    def tearDown(self):
        self.db.close()
        for f in os.listdir(self.tmpdir):
            try:
                os.remove(os.path.join(self.tmpdir, f))
            except OSError:
                pass
        os.rmdir(self.tmpdir)

    def _make_block(self):
        txs = [
            create_transaction(self.alice, f"msg {i}", fee=5000, nonce=i)
            for i in range(3)
        ]
        merkle = compute_merkle_root([t.tx_hash for t in txs])
        header = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=merkle, timestamp=time.time(),
            proposer_id=self.alice.entity_id,
        )
        header.proposer_signature = self.alice.keypair.sign(_hash(header.signable_data()))
        return Block(header=header, transactions=txs)

    def test_store_and_retrieve_block(self):
        block = self._make_block()
        self.db.store_block(block)
        loaded = self.db.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.block_hash, block.block_hash)
        self.assertEqual(len(loaded.transactions), 3)

    def test_blocks_stored_as_blob(self):
        """Blocks are stored in a BLOB column, not TEXT."""
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("PRAGMA table_info(blocks)")
        cols = {row[1]: row[2] for row in cur.fetchall()}
        self.assertEqual(cols["data"], "BLOB")
        conn.close()

    def test_stored_bytes_match_binary_serialization(self):
        """The bytes in the DB are exactly block.to_bytes()."""
        import sqlite3
        block = self._make_block()
        self.db.store_block(block)
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("SELECT data FROM blocks WHERE block_hash = ?", (block.block_hash,))
        row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(bytes(row[0]), block.to_bytes())


class TestMiscTxBinary(unittest.TestCase):
    """Spot-check other tx types have working to_bytes/from_bytes."""

    def setUp(self):
        self.alice = Entity.create(b"alice-misc-bin".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-misc-bin".ljust(32, b"\x00"))

    def test_transfer_tx_roundtrip(self):
        tx = create_transfer_transaction(
            self.alice, self.bob.entity_id, amount=1000, nonce=0, fee=100,
        )
        decoded = TransferTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.recipient_id, tx.recipient_id)
        self.assertEqual(decoded.amount, tx.amount)

    def test_stake_tx_roundtrip(self):
        tx = create_stake_transaction(self.alice, amount=1_000_000, nonce=0)
        decoded = StakeTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.amount, tx.amount)

    def test_unstake_tx_roundtrip(self):
        tx = create_unstake_transaction(self.alice, amount=500_000, nonce=0)
        decoded = UnstakeTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)

    def test_set_authority_key_roundtrip(self):
        tx = create_set_authority_key_transaction(
            self.alice, new_authority_key=self.bob.public_key, nonce=0,
        )
        decoded = SetAuthorityKeyTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.new_authority_key, tx.new_authority_key)

    def test_revoke_tx_roundtrip(self):
        tx = create_revoke_transaction(self.alice)
        decoded = RevokeTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)

    def test_key_rotation_roundtrip(self):
        new_kp = derive_rotated_keypair(self.alice, rotation_number=1)
        tx = create_key_rotation(self.alice, new_kp, rotation_number=1)
        decoded = KeyRotationTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.new_public_key, tx.new_public_key)

    def test_proposal_roundtrip(self):
        tx = create_proposal(self.alice, "title", "description")
        decoded = ProposalTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.title, tx.title)

    def test_vote_roundtrip(self):
        prop = create_proposal(self.alice, "title", "desc")
        tx = create_vote(self.alice, prop.tx_hash, approve=True)
        decoded = VoteTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.approve, True)

    def test_treasury_spend_roundtrip(self):
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, amount=100, title="t", description="d",
        )
        decoded = TreasurySpendTransaction.from_bytes(tx.to_bytes())
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        self.assertEqual(decoded.amount, tx.amount)

    def test_attestation_roundtrip(self):
        att = create_attestation(self.alice, b"\xff" * 32, block_number=42)
        decoded = Attestation.from_bytes(att.to_bytes())
        self.assertEqual(decoded.validator_id, att.validator_id)
        self.assertEqual(decoded.block_hash, att.block_hash)
        self.assertEqual(decoded.block_number, att.block_number)


if __name__ == "__main__":
    unittest.main()
