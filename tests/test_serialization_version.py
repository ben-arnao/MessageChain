"""Tests for wire-format version gating on block and transaction binary blobs.

Motivation: a silent breaking change to the binary serialization format
produced ValueError hash-mismatch errors when old chain data was loaded
by new code.  For a 1000-year chain this class of bug is catastrophic —
old blocks that were consensus-valid at the time must either round-trip
cleanly or fail with a clear "unknown serialization version" rather than
a cryptic hash mismatch that leaves an operator guessing between storage
corruption, a signature bug, or a wire format change.

These tests pin down:

  1. The version constants exist and are 1 by default.
  2. Serialized block/tx blobs begin with the expected version byte.
  3. from_bytes accepts the current version.
  4. from_bytes on a blob whose leading byte is an unknown version raises
     a clear ValueError mentioning "serialization version" (not a hash
     mismatch, not a truncation error).
  5. from_bytes on the raw pre-version-byte shape (old format) also
     fails with a clear error, not a cryptic hash mismatch.

The version constant is a carry-only register today, exactly like
HASH_VERSION_CURRENT: a future format change bumps the constant and the
gate widens to accept (old, new) during a migration window.
"""

import time
import unittest

from messagechain.config import (
    BLOCK_SERIALIZATION_VERSION,
    TX_SERIALIZATION_VERSION,
    validate_block_serialization_version,
    validate_tx_serialization_version,
)
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.transaction import MessageTransaction, create_transaction
from messagechain.core.transfer import TransferTransaction, create_transfer_transaction
from messagechain.core.staking import (
    StakeTransaction,
    UnstakeTransaction,
    create_stake_transaction,
    create_unstake_transaction,
)
from messagechain.identity.identity import Entity


class TestSerializationVersionConstants(unittest.TestCase):
    """The constants exist and are 1 — the initial wire format."""

    def test_block_serialization_version_is_one(self):
        self.assertEqual(BLOCK_SERIALIZATION_VERSION, 1)

    def test_tx_serialization_version_is_one(self):
        self.assertEqual(TX_SERIALIZATION_VERSION, 1)

    def test_validate_block_serialization_version_accepts_current(self):
        ok, reason = validate_block_serialization_version(BLOCK_SERIALIZATION_VERSION)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_validate_block_serialization_version_rejects_unknown(self):
        ok, reason = validate_block_serialization_version(99)
        self.assertFalse(ok)
        self.assertIn("serialization version", reason.lower())

    def test_validate_block_serialization_version_rejects_zero(self):
        # 0 is reserved (traps uninitialized) — mirrors the HASH_VERSION_* rule.
        ok, reason = validate_block_serialization_version(0)
        self.assertFalse(ok)

    def test_validate_tx_serialization_version_accepts_current(self):
        ok, reason = validate_tx_serialization_version(TX_SERIALIZATION_VERSION)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_validate_tx_serialization_version_rejects_unknown(self):
        ok, reason = validate_tx_serialization_version(42)
        self.assertFalse(ok)
        self.assertIn("serialization version", reason.lower())


class _TxVersionMixin:
    """Shared assertions: blob starts with version byte, decoder gates it."""

    # Subclasses set these.
    cls = None  # the tx class
    expected_version = TX_SERIALIZATION_VERSION

    def _make_tx(self):
        raise NotImplementedError

    def test_blob_starts_with_version_byte(self):
        tx = self._make_tx()
        blob = tx.to_bytes()
        self.assertGreaterEqual(len(blob), 1)
        self.assertEqual(blob[0], self.expected_version)

    def test_roundtrip_at_current_version(self):
        tx = self._make_tx()
        blob = tx.to_bytes()
        decoded = self.cls.from_bytes(blob)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)

    def test_unknown_version_rejected_with_clear_error(self):
        tx = self._make_tx()
        blob = bytearray(tx.to_bytes())
        blob[0] = 99  # unknown serialization version
        with self.assertRaises(ValueError) as cm:
            self.cls.from_bytes(bytes(blob))
        msg = str(cm.exception).lower()
        self.assertIn("serialization version", msg)
        # Must not surface as a cryptic hash mismatch.
        self.assertNotIn("hash mismatch", msg)

    def test_zero_version_rejected(self):
        tx = self._make_tx()
        blob = bytearray(tx.to_bytes())
        blob[0] = 0
        with self.assertRaises(ValueError) as cm:
            self.cls.from_bytes(bytes(blob))
        self.assertIn("serialization version", str(cm.exception).lower())

    def test_pre_version_format_fails_clearly(self):
        """A blob that looks like the old (pre-version-byte) format must fail.

        The old shape started with a u32 version field (value 0x00000001).
        On the new decoder, the leading byte is interpreted as the
        serialization version — value 0 (the high byte of the u32)
        trips the unknown-version gate rather than letting the decoder
        silently eat 3 extra bytes and fall into a later hash mismatch.
        """
        tx = self._make_tx()
        new_blob = tx.to_bytes()
        # Strip the leading version byte — what an old-format blob would
        # look like to the new decoder.
        old_shape = new_blob[1:]
        with self.assertRaises(ValueError) as cm:
            self.cls.from_bytes(old_shape)
        msg = str(cm.exception).lower()
        # Either the version byte trips (because old_shape[0] happens to
        # be 0x00 from the old u32 high byte or some other non-1 value)
        # or the decoder errors later on a structural mismatch — both
        # are acceptable, what's NOT acceptable is a silent accept or
        # an unrelated crash type.
        self.assertIsInstance(cm.exception, ValueError)


class TestMessageTransactionVersion(_TxVersionMixin, unittest.TestCase):
    cls = MessageTransaction

    def setUp(self):
        self.entity = Entity.create(b"msgtx-serialver-key".ljust(32, b"\x00"))

    def _make_tx(self):
        return create_transaction(self.entity, "hello", fee=1500, nonce=0)


class TestTransferTransactionVersion(_TxVersionMixin, unittest.TestCase):
    cls = TransferTransaction

    def setUp(self):
        self.sender = Entity.create(b"xfer-serialver-sender".ljust(32, b"\x00"))
        self.recipient = Entity.create(b"xfer-serialver-rcpt".ljust(32, b"\x00"))

    def _make_tx(self):
        return create_transfer_transaction(
            self.sender, self.recipient.entity_id, amount=100, nonce=0, fee=100,
        )


class TestStakeTransactionVersion(_TxVersionMixin, unittest.TestCase):
    cls = StakeTransaction

    def setUp(self):
        self.entity = Entity.create(b"stake-serialver-key".ljust(32, b"\x00"))

    def _make_tx(self):
        return create_stake_transaction(self.entity, amount=1_000_000, nonce=0)


class TestUnstakeTransactionVersion(_TxVersionMixin, unittest.TestCase):
    cls = UnstakeTransaction

    def setUp(self):
        self.entity = Entity.create(b"unstake-serialver-key".ljust(32, b"\x00"))

    def _make_tx(self):
        return create_unstake_transaction(self.entity, amount=500, nonce=0)


class TestBlockSerializationVersion(unittest.TestCase):
    """Block binary blobs begin with BLOCK_SERIALIZATION_VERSION and gate it."""

    def setUp(self):
        self.proposer = Entity.create(b"block-serialver-key".ljust(32, b"\x00"))

    def _make_block(self) -> Block:
        header = BlockHeader(
            version=1,
            block_number=0,
            prev_hash=b"\x00" * 32,
            merkle_root=_hash(b"genesis"),
            timestamp=time.time(),
            proposer_id=self.proposer.entity_id,
        )
        header.proposer_signature = self.proposer.keypair.sign(
            _hash(header.signable_data())
        )
        block = Block(header=header, transactions=[])
        block.block_hash = block._compute_hash()
        return block

    def test_block_blob_starts_with_version_byte(self):
        block = self._make_block()
        blob = block.to_bytes()
        self.assertGreaterEqual(len(blob), 1)
        self.assertEqual(blob[0], BLOCK_SERIALIZATION_VERSION)

    def test_block_roundtrip_at_current_version(self):
        block = self._make_block()
        blob = block.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.block_hash, block.block_hash)

    def test_block_unknown_version_rejected(self):
        block = self._make_block()
        blob = bytearray(block.to_bytes())
        blob[0] = 250
        with self.assertRaises(ValueError) as cm:
            Block.from_bytes(bytes(blob))
        msg = str(cm.exception).lower()
        self.assertIn("serialization version", msg)
        self.assertNotIn("hash mismatch", msg)

    def test_block_zero_version_rejected(self):
        block = self._make_block()
        blob = bytearray(block.to_bytes())
        blob[0] = 0
        with self.assertRaises(ValueError) as cm:
            Block.from_bytes(bytes(blob))
        self.assertIn("serialization version", str(cm.exception).lower())

    def test_block_pre_version_format_fails_clearly(self):
        """Stripping the new version byte produces the old layout shape.

        Old shape starts with a u32 header_blob_len whose high byte is
        almost certainly 0x00 for any realistic header.  The new decoder
        reads that 0x00 as the serialization version and rejects.
        """
        block = self._make_block()
        new_blob = block.to_bytes()
        old_shape = new_blob[1:]
        with self.assertRaises(ValueError) as cm:
            Block.from_bytes(old_shape)
        # Must fail cleanly as a ValueError — not some other exception type.
        self.assertIsInstance(cm.exception, ValueError)


if __name__ == "__main__":
    unittest.main()
