"""Witness tiering — opt-in auto-separation driver.

Phase A on-disk slice.  Witness-stripping helpers and the separate
block_witnesses table already exist (see test_witness_separation.py);
this exercises `ChainDB.auto_separate_finalized_witnesses(finalized_height, ...)`
— opt-in driver that moves witnesses of finalized blocks older than
WITNESS_RETENTION_BLOCKS from inline storage to the side table.  Gated
on WITNESS_AUTO_SEPARATION_ENABLED so the current default behavior
(witnesses inline, no callers silently broken) is unchanged.

Permanence: separation NEVER deletes witnesses — it moves them from
the `blocks.data` BLOB into the `block_witnesses.witness_data` BLOB
in the same database.  Full reassembly via
get_block_by_hash(..., include_witnesses=True) is always possible on
this node.

Reattach integrity (the trust anchor for any phase-B/C/D flow that
re-fetches witnesses from peers) lives in
`tests/test_witness_reattach_verification.py` —
`attach_block_witnesses` self-verifies against the committed
`header.witness_root` post-activation.  The legacy single-slot
`verify_witness_data` helper used to live here; it was retired with
the Tier 48 audit because its leaf rule is incompatible with the
canonical `compute_block_witness_root` and shipping it as a public
helper invited a chain-halting bug.
"""
import os
import tempfile
import unittest

import messagechain.config as _cfg
from messagechain.core.block import Block, BlockHeader, _hash, compute_merkle_root
from messagechain.core.transaction import create_transaction
from messagechain.core.witness import (
    compute_witness_root,
    get_block_witness_data,
    tx_has_witness,
)
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _make_entity():
    return Entity.create(os.urandom(32))


def _make_block_with_txs(n_txs=3, block_number=1):
    entity = _make_entity()
    txs = [
        create_transaction(entity, f"msg {i}", 10_000, i)
        for i in range(n_txs)
    ]
    merkle_root = compute_merkle_root([t.tx_hash for t in txs])
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=b"\x00" * 32,
        merkle_root=merkle_root,
        timestamp=1_000_000.0 + block_number,
        proposer_id=entity.entity_id,
    )
    header.witness_root = compute_witness_root(txs)
    header.proposer_signature = entity.keypair.sign(_hash(header.signable_data()))
    block = Block(header=header, transactions=txs)
    block.block_hash = block._compute_hash()
    return block


class TestAutoSeparationFlag(unittest.TestCase):
    """The auto-separation driver is gated on
    WITNESS_AUTO_SEPARATION_ENABLED.  Default False means no caller
    sees any behavior change until an operator opts in.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = ChainDB(os.path.join(self.tmpdir, "test.db"))
        # Capture + restore the flag so tests don't leak state.
        self._saved_flag = getattr(
            _cfg, "WITNESS_AUTO_SEPARATION_ENABLED", False,
        )
        self._saved_retention = _cfg.WITNESS_RETENTION_BLOCKS
        # Pin the fork height to 0 so tests using small block numbers
        # exercise post-fork behavior unconditionally.  The
        # WITNESS_AUTO_SEPARATION_HEIGHT gate has its own dedicated
        # tests in test_witness_separation_default_on.py.
        self._saved_height = getattr(
            _cfg, "WITNESS_AUTO_SEPARATION_HEIGHT", 0,
        )
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 0

    def tearDown(self):
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = self._saved_flag
        _cfg.WITNESS_RETENTION_BLOCKS = self._saved_retention
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = self._saved_height
        self.db.close()

    def test_noop_when_disabled(self):
        """Disabled flag: driver returns 0 and touches nothing."""
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = False
        _cfg.WITNESS_RETENTION_BLOCKS = 0
        block = _make_block_with_txs(3, block_number=1)
        self.db.store_block(block)

        n = self.db.auto_separate_finalized_witnesses(finalized_height=100)
        self.assertEqual(n, 0)
        self.assertFalse(self.db.has_witness_data(block.block_hash))

    def test_separates_old_blocks_when_enabled(self):
        """With the flag on and retention=0, any finalized block is
        a candidate.  The driver strips inline witnesses into the
        side table and the block remains fully reassemblable.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_RETENTION_BLOCKS = 0
        block = _make_block_with_txs(3, block_number=1)
        self.db.store_block(block)
        self.assertFalse(self.db.has_witness_data(block.block_hash))

        n = self.db.auto_separate_finalized_witnesses(finalized_height=1)
        self.assertEqual(n, 1)
        self.assertTrue(self.db.has_witness_data(block.block_hash))

    def test_skips_blocks_within_retention_window(self):
        """A block finalized but still within the retention window
        must NOT be separated — the window gives recent auditors
        cheap local access to witnesses.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_RETENTION_BLOCKS = 50
        block = _make_block_with_txs(3, block_number=40)
        self.db.store_block(block)

        # Finalized height 45; block at height 40 is within the
        # 50-block retention window of the finality horizon.
        n = self.db.auto_separate_finalized_witnesses(finalized_height=45)
        self.assertEqual(n, 0)
        self.assertFalse(self.db.has_witness_data(block.block_hash))

    def test_idempotent(self):
        """Running the driver twice must not double-process or raise.

        This matters because a node calling the driver on every
        finality advance will call it many times over a block's
        lifetime; the second-and-later calls must be no-ops.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_RETENTION_BLOCKS = 0
        block = _make_block_with_txs(3, block_number=1)
        self.db.store_block(block)

        n1 = self.db.auto_separate_finalized_witnesses(finalized_height=1)
        n2 = self.db.auto_separate_finalized_witnesses(finalized_height=1)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 0)
        self.assertTrue(self.db.has_witness_data(block.block_hash))


class TestSeparatedBlockRoundTrip(unittest.TestCase):
    """After separation, a node must still be able to serve the full
    block to auditors.  The separated witnesses must also verify
    against the committed witness_root — this is the property that
    keeps phase B (wire-level tiering) sound later.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = ChainDB(os.path.join(self.tmpdir, "test.db"))
        self._saved_flag = getattr(
            _cfg, "WITNESS_AUTO_SEPARATION_ENABLED", False,
        )
        self._saved_retention = _cfg.WITNESS_RETENTION_BLOCKS
        self._saved_height = getattr(
            _cfg, "WITNESS_AUTO_SEPARATION_HEIGHT", 0,
        )
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_RETENTION_BLOCKS = 0
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 0

    def tearDown(self):
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = self._saved_flag
        _cfg.WITNESS_RETENTION_BLOCKS = self._saved_retention
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = self._saved_height
        self.db.close()

    def test_reassembled_block_has_original_signatures(self):
        block = _make_block_with_txs(4, block_number=1)
        original_sigs = [tx.signature.to_bytes() for tx in block.transactions]
        original_hash = block.block_hash

        self.db.store_block(block)
        self.db.auto_separate_finalized_witnesses(finalized_height=1)

        reassembled = self.db.get_block_by_hash(
            block.block_hash, include_witnesses=True,
        )
        self.assertIsNotNone(reassembled)
        self.assertEqual(reassembled.block_hash, original_hash)
        for tx, orig in zip(reassembled.transactions, original_sigs):
            self.assertTrue(tx_has_witness(tx))
            self.assertEqual(tx.signature.to_bytes(), orig)

    def test_separated_blob_present_in_side_table(self):
        """The side-table row must be populated by auto-separation —
        the integrity check that the blob matches the committed
        witness_root happens at reattach time (see
        `tests/test_witness_reattach_verification.py`).
        """
        block = _make_block_with_txs(4, block_number=1)
        self.db.store_block(block)
        self.db.auto_separate_finalized_witnesses(finalized_height=1)

        blob = self.db.get_witness_data(block.block_hash)
        self.assertIsNotNone(blob)
        self.assertGreater(len(blob), 4)  # At least the tx_count prefix.

    def test_default_read_still_returns_core(self):
        """A caller that doesn't opt into witnesses gets the stripped
        block — the same pattern as today's get_block_by_hash.  This
        is the safety rail: auto-separation never silently attaches
        witnesses where the caller didn't ask for them.
        """
        block = _make_block_with_txs(3, block_number=1)
        self.db.store_block(block)
        self.db.auto_separate_finalized_witnesses(finalized_height=1)

        core_only = self.db.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(core_only)
        for tx in core_only.transactions:
            self.assertFalse(tx_has_witness(tx))


if __name__ == "__main__":
    unittest.main()
