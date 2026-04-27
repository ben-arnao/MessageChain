"""Witness auto-separation default-on hard-fork gate.

Witness data (WOTS+ signatures + auth paths) is ~73% of full-node
storage at saturation but serves only auditability after a block is
finalized.  The framework to move it into a side-table already exists
(``ChainDB.auto_separate_finalized_witnesses`` /
``strip_finalized_witnesses``); historically it was opt-in via
``WITNESS_AUTO_SEPARATION_ENABLED = False`` so no caller silently lost
inline access.

This module turns auto-separation default-on at a coordinated hard fork
height (``WITNESS_AUTO_SEPARATION_HEIGHT``) so the chain materializes
the witness-storage savings going forward.  Anchored properties:

  * Pre-fork blocks (``block_number < WITNESS_AUTO_SEPARATION_HEIGHT``)
    are NEVER stripped — historical replay determinism requires inline
    witnesses for every block whose original encoding the protocol
    committed to inline.
  * Post-fork finalized blocks past the retention window ARE stripped.
  * Stripping moves bytes only; nothing is deleted.  Reassembly via
    ``get_block_by_hash(..., include_witnesses=True)`` works on every
    node that still has the side-table row.
  * The witness root committed in the block header is preserved
    bit-for-bit by stripping (header bytes are untouched), so consensus
    is unaffected.
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
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


# ── Helpers ────────────────────────────────────────────────────────────


def _make_entity():
    return Entity.create(os.urandom(32))


def _make_block_with_txs(n_txs=3, block_number=1, entity=None):
    if entity is None:
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


class _AutoSeparationHeightTestBase(unittest.TestCase):
    """Shared setUp/tearDown that captures + restores the fork-height
    config so tests can pin a known fork height without leaking state
    across the suite."""

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

    def tearDown(self):
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = self._saved_flag
        _cfg.WITNESS_RETENTION_BLOCKS = self._saved_retention
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = self._saved_height
        self.db.close()


class TestForkHeightConstantWired(unittest.TestCase):
    """The constant must exist, be a positive integer, and the live
    config must default to auto-separation ON.  This catches a
    regression that flips the default back to opt-in or removes the
    height gate.
    """

    def test_constant_exists_and_is_positive_int(self):
        self.assertTrue(
            hasattr(_cfg, "WITNESS_AUTO_SEPARATION_HEIGHT"),
            "WITNESS_AUTO_SEPARATION_HEIGHT must be defined in config",
        )
        h = _cfg.WITNESS_AUTO_SEPARATION_HEIGHT
        self.assertIsInstance(h, int)
        self.assertGreater(h, 0)

    def test_default_is_enabled(self):
        """The audit finding is the witness path is wired but defaulted
        OFF.  After this fix, the default must be ON."""
        self.assertTrue(
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED,
            "WITNESS_AUTO_SEPARATION_ENABLED must default to True",
        )

    def test_helper_is_active_at_and_above_fork_height(self):
        from messagechain.core.witness import is_witness_separation_active

        # Pin a known small fork height for the test
        prev = _cfg.WITNESS_AUTO_SEPARATION_HEIGHT
        prev_flag = _cfg.WITNESS_AUTO_SEPARATION_ENABLED
        try:
            _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 100
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
            self.assertFalse(is_witness_separation_active(0))
            self.assertFalse(is_witness_separation_active(99))
            self.assertTrue(is_witness_separation_active(100))
            self.assertTrue(is_witness_separation_active(101))
            self.assertTrue(is_witness_separation_active(10_000))

            # Even at/above the fork, if the master flag is False the
            # helper is False — operator-facing kill switch.
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = False
            self.assertFalse(is_witness_separation_active(10_000))
        finally:
            _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = prev
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = prev_flag


class TestPreForkBlockNeverStripped(_AutoSeparationHeightTestBase):
    """Pre-fork blocks must NEVER be stripped — the chain committed to
    their inline encoding before the fork activated, and historical
    replay determinism requires the original bytes to stay where they
    are.  The fork height is one-way."""

    def test_witness_separation_disabled_below_fork_height(self):
        """A finalized block at ``block_number < fork_height`` retains
        its inline witnesses even when the sweep is invoked.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
        _cfg.WITNESS_RETENTION_BLOCKS = 0

        # Block at height 500 — well below the fork height
        block = _make_block_with_txs(3, block_number=500)
        self.db.store_block(block)

        # Drive the sweep with a finalized_height that is itself below
        # the fork — separation must be inert.
        n = self.db.auto_separate_finalized_witnesses(finalized_height=500)
        self.assertEqual(n, 0)
        self.assertFalse(self.db.has_witness_data(block.block_hash))

        # The block read-back path must still see inline witnesses.
        rt = self.db.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(rt)
        for tx in rt.transactions:
            self.assertTrue(tx_has_witness(tx))

    def test_pre_fork_finalized_blocks_stay_un_stripped_after_fork_activates(self):
        """A pre-fork block already on disk MUST stay inline even after
        the chain advances past the fork height and the sweep starts
        running on newly-finalized blocks.

        This is the "fork height is one-way" invariant — pre-fork
        encodings are committed to inline witnesses forever.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
        _cfg.WITNESS_RETENTION_BLOCKS = 0

        # A pre-fork block (height 500) that gets stored before the
        # fork has activated.
        pre_fork_block = _make_block_with_txs(3, block_number=500)
        self.db.store_block(pre_fork_block)

        # The chain advances past the fork height; the post-fork
        # block at height 1500 is also finalized.
        post_fork_block = _make_block_with_txs(3, block_number=1500)
        self.db.store_block(post_fork_block)

        # Sweep runs at the new finality horizon, well past the fork.
        self.db.auto_separate_finalized_witnesses(finalized_height=1500)

        # Pre-fork block: STILL inline.
        self.assertFalse(
            self.db.has_witness_data(pre_fork_block.block_hash),
            "pre-fork block must not be stripped even after fork activates",
        )
        rt_pre = self.db.get_block_by_hash(pre_fork_block.block_hash)
        self.assertIsNotNone(rt_pre)
        for tx in rt_pre.transactions:
            self.assertTrue(
                tx_has_witness(tx),
                "pre-fork tx must retain inline witness",
            )

        # Post-fork block: stripped (sanity — confirms the sweep ran).
        self.assertTrue(
            self.db.has_witness_data(post_fork_block.block_hash),
            "post-fork block past retention window should be stripped",
        )


class TestPostForkBlockStripped(_AutoSeparationHeightTestBase):
    """Post-fork finalized blocks past the retention window are
    stripped.  This is the storage-saving payoff."""

    def test_witness_separation_active_at_and_above_fork_height(self):
        """A block finalized at ``height >= fork_height + retention``
        gets its inline witnesses replaced with the sentinel and the
        side-table row populated.
        """
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
        _cfg.WITNESS_RETENTION_BLOCKS = 50

        # Block exactly at fork height
        block_a = _make_block_with_txs(3, block_number=1_000)
        # Block well above fork height
        block_b = _make_block_with_txs(3, block_number=1_500)
        self.db.store_block(block_a)
        self.db.store_block(block_b)

        # Finalized horizon at 2_000: both blocks are past the retention
        # window of 50 (horizon - retention = 1_950), so both are
        # candidates.
        n = self.db.auto_separate_finalized_witnesses(finalized_height=2_000)
        self.assertEqual(n, 2)
        self.assertTrue(self.db.has_witness_data(block_a.block_hash))
        self.assertTrue(self.db.has_witness_data(block_b.block_hash))


class TestRetentionWindowRespected(_AutoSeparationHeightTestBase):
    """Even post-fork, blocks within the retention window of the
    finality horizon stay inline — operators / auditors get cheap
    local access to recent witnesses without a side-table fetch."""

    def test_witness_separation_respects_retention_window(self):
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
        _cfg.WITNESS_RETENTION_BLOCKS = 200

        # Block at 1_900; finalized horizon at 2_000.  Difference is
        # 100, which is INSIDE the 200-block retention window.
        block = _make_block_with_txs(3, block_number=1_900)
        self.db.store_block(block)

        n = self.db.auto_separate_finalized_witnesses(finalized_height=2_000)
        self.assertEqual(n, 0)
        self.assertFalse(self.db.has_witness_data(block.block_hash))

        # Once the chain advances enough that the block falls past the
        # retention window, the next sweep DOES strip it.
        n2 = self.db.auto_separate_finalized_witnesses(finalized_height=2_200)
        self.assertEqual(n2, 1)
        self.assertTrue(self.db.has_witness_data(block.block_hash))


class TestWitnessRootInvariant(_AutoSeparationHeightTestBase):
    """Stripping changes only the on-disk body bytes; the block header
    (and therefore ``compute_witness_root`` over the transactions, plus
    the committed ``header.witness_root``) is invariant.  This is the
    consensus-safety anchor: stripping is invisible to the protocol.
    """

    def test_witness_root_unchanged_after_separation(self):
        _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
        _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
        _cfg.WITNESS_RETENTION_BLOCKS = 0

        block = _make_block_with_txs(4, block_number=1_500)

        # Witness root computed before the block ever touches the DB
        original_root = compute_witness_root(block.transactions)
        original_header_root = block.header.witness_root
        self.assertEqual(original_root, original_header_root)

        self.db.store_block(block)
        self.db.auto_separate_finalized_witnesses(finalized_height=1_500)

        # Read back with witnesses (reassembly path) — root over the
        # restored transactions must equal the original committed root.
        reassembled = self.db.get_block_by_hash(
            block.block_hash, include_witnesses=True,
        )
        self.assertIsNotNone(reassembled)
        self.assertEqual(
            compute_witness_root(reassembled.transactions), original_root,
        )

        # And the header's committed root is byte-identical.
        self.assertEqual(reassembled.header.witness_root, original_header_root)

        # Block hash (which commits to the header, including
        # witness_root) is unchanged.
        self.assertEqual(reassembled.block_hash, block.block_hash)


class TestReplayDeterminism(_AutoSeparationHeightTestBase):
    """Two nodes — one with separation enabled, one with separation
    disabled — must converge on byte-identical block read-backs (when
    each reads with the witness reassembly path).  Separation is a
    storage-shape optimization; consensus output cannot diverge.
    """

    def test_chain_replay_determinism_post_separation(self):
        # Two independent DBs sharing identical input blocks
        db_separated = ChainDB(os.path.join(self.tmpdir, "with_sep.db"))
        db_inline = ChainDB(os.path.join(self.tmpdir, "no_sep.db"))
        try:
            # Build a synthetic post-fork chain of 3 blocks
            blocks = [
                _make_block_with_txs(2, block_number=1_500 + i)
                for i in range(3)
            ]
            for b in blocks:
                db_separated.store_block(b)
                db_inline.store_block(b)

            # Node A: separation ON post-fork; sweep finalizes
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True
            _cfg.WITNESS_AUTO_SEPARATION_HEIGHT = 1_000
            _cfg.WITNESS_RETENTION_BLOCKS = 0
            db_separated.auto_separate_finalized_witnesses(finalized_height=1_502)

            # Node B: separation OFF; nothing happens.
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = False
            db_inline.auto_separate_finalized_witnesses(finalized_height=1_502)

            # Re-enable for the rest of teardown sanity
            _cfg.WITNESS_AUTO_SEPARATION_ENABLED = True

            for original in blocks:
                with_sep = db_separated.get_block_by_hash(
                    original.block_hash, include_witnesses=True,
                )
                without_sep = db_inline.get_block_by_hash(
                    original.block_hash,
                )
                self.assertIsNotNone(with_sep)
                self.assertIsNotNone(without_sep)
                # Block hashes (commits to header + witness_root) match
                self.assertEqual(with_sep.block_hash, without_sep.block_hash)
                self.assertEqual(
                    with_sep.header.witness_root,
                    without_sep.header.witness_root,
                )
                # Witness root over reassembled txs matches the
                # never-stripped node
                self.assertEqual(
                    compute_witness_root(with_sep.transactions),
                    compute_witness_root(without_sep.transactions),
                )
                # Per-tx signature bytes match — separation was
                # round-trip lossless
                for a, b in zip(with_sep.transactions, without_sep.transactions):
                    self.assertEqual(
                        a.signature.to_bytes(), b.signature.to_bytes(),
                    )
        finally:
            db_separated.close()
            db_inline.close()


if __name__ == "__main__":
    unittest.main()
