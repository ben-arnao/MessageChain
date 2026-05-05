"""B-2 strip/attach verification — the integrity surface that gives the
witness-root commit its meaning at reattach time.

The 1.55.0 release shipped the witness-root *commit* path
(`compute_block_witness_root` + header.witness_root validation in
`Blockchain.validate_block`).  This file pins the *verification* side of
that commit:

  * `attach_block_witnesses` MUST re-derive the consensus-binding
    witness root from the restored block and reject any blob that does
    not reproduce `header.witness_root`.  This closes the surface where
    disk corruption, an attacker with archive-node write access, or a
    future B-3 peer-fetch path could substitute fabricated WOTS+ blobs
    that deserialize cleanly while the header (and therefore the
    block_hash) stays untouched.

  * The check is gated on
        block_number >= WITNESS_ROOT_ACTIVATION_HEIGHT
    because pre-activation blocks carry the all-zero header default by
    design — enforcing on those would reject every historical block.
    Gate matches the matching gate in `pos.create_block` and
    `Blockchain.validate_block`.

  * `ChainDB.get_block_by_hash(include_witnesses=True)` MUST surface a
    tampered side-table row as a defined error path (raise
    `WitnessRootMismatchError`) rather than silently returning attacker-
    controlled signatures up to RPC callers.

Permanence anchor: witnesses themselves are explicitly NOT permanent
(the anchor is "message payloads only"), so the strip/attach surface
MUST be cryptographically self-checking — it is the only barrier
between an attacker-rewritten witness side-table and downstream code
that treats reattached signatures as authentic.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

import messagechain.config as _cfg
from messagechain.config import WITNESS_ROOT_ACTIVATION_HEIGHT
from messagechain.core.block import Block, BlockHeader, _hash, compute_merkle_root
from messagechain.core.transaction import create_transaction
from messagechain.core.witness import (
    WitnessRootMismatchError,
    attach_block_witnesses,
    compute_block_witness_root,
    compute_witness_root,
    get_block_witness_data,
    strip_block_witnesses,
)
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _make_entity():
    return Entity.create(os.urandom(32))


def _make_block_at_height(block_number: int, n_txs: int = 3, *, post_activation: bool):
    """Build a signed block at `block_number` with `n_txs` real txs.

    If `post_activation` is True, header.witness_root is populated with
    the canonical multi-slot `compute_block_witness_root`.  Otherwise it
    is left at the all-zero pre-activation default — replicates exactly
    what `pos.create_block` does on either side of the gate.
    """
    entity = _make_entity()
    txs = [
        create_transaction(entity, f"msg {i}", 10_000, i)
        for i in range(n_txs)
    ]
    merkle_root = compute_merkle_root([t.tx_hash for t in txs]) if txs else _hash(b"empty")
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=b"\x00" * 32,
        merkle_root=merkle_root,
        timestamp=1_000_000.0 + block_number,
        proposer_id=entity.entity_id,
    )
    block = Block(header=header, transactions=txs)
    if post_activation:
        header.witness_root = compute_block_witness_root(block)
    else:
        header.witness_root = b"\x00" * 32
    header.proposer_signature = entity.keypair.sign(_hash(header.signable_data()))
    block.block_hash = block._compute_hash()
    return block


# ── attach_block_witnesses ────────────────────────────────────────────


class TestAttachBlockWitnessesPreActivation(unittest.TestCase):
    """Pre-activation blocks carry the all-zero header.witness_root by
    design.  Reattach must NOT enforce — every historical block on chain
    today would fail otherwise.
    """

    def test_pre_activation_reattach_no_enforcement(self):
        # block_number well below activation; header.witness_root is the
        # legacy all-zero default.  Strip + attach must round-trip
        # without raising even though `compute_block_witness_root` of
        # the restored block does NOT equal b"\x00" * 32.
        target = max(1, WITNESS_ROOT_ACTIVATION_HEIGHT - 1000)
        block = _make_block_at_height(target, n_txs=3, post_activation=False)
        self.assertEqual(block.header.witness_root, b"\x00" * 32)

        blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        # Must not raise — pre-activation enforcement is off.
        restored = attach_block_witnesses(stripped, blob)
        self.assertEqual(restored.block_hash, block.block_hash)
        self.assertEqual(len(restored.transactions), 3)


class TestAttachBlockWitnessesPostActivation(unittest.TestCase):
    """Post-activation blocks carry a real witness_root.  Reattach must
    re-derive and assert equality, raising WitnessRootMismatchError on
    any mismatch.
    """

    def test_clean_roundtrip(self):
        block = _make_block_at_height(
            WITNESS_ROOT_ACTIVATION_HEIGHT + 5, n_txs=4,
            post_activation=True,
        )
        blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, blob)
        # Round-trip preserves the block_hash and every signature.
        self.assertEqual(restored.block_hash, block.block_hash)
        for tx_orig, tx_restored in zip(block.transactions, restored.transactions):
            self.assertEqual(
                tx_orig.signature.to_bytes(),
                tx_restored.signature.to_bytes(),
            )
        # The restored block's recomputed witness_root must equal the
        # header's.
        self.assertEqual(
            compute_block_witness_root(restored),
            restored.header.witness_root,
        )

    def test_tampered_signature_raises(self):
        """Flip a byte inside one signature in the witness blob — the
        restored block's witness_root will diverge and reattach must
        raise WitnessRootMismatchError with usable context.
        """
        block = _make_block_at_height(
            WITNESS_ROOT_ACTIVATION_HEIGHT + 5, n_txs=3,
            post_activation=True,
        )
        blob = bytearray(get_block_witness_data(block))
        # Past the 4-byte tx_count + 4-byte first-sig-len prefixes —
        # lands inside the first signature payload.
        blob[12] ^= 0xFF
        stripped = strip_block_witnesses(block)
        with self.assertRaises(WitnessRootMismatchError) as cm:
            attach_block_witnesses(stripped, bytes(blob))
        # Error must surface enough context to be actionable.
        err = cm.exception
        self.assertEqual(err.block_number, block.header.block_number)
        self.assertEqual(err.expected_root, block.header.witness_root)
        self.assertNotEqual(err.actual_root, block.header.witness_root)

    def test_empty_block_post_activation_roundtrip(self):
        """An empty post-activation block must still round-trip cleanly
        (the empty-block sentinel root is well-defined)."""
        block = _make_block_at_height(
            WITNESS_ROOT_ACTIVATION_HEIGHT + 5, n_txs=0,
            post_activation=True,
        )
        blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        restored = attach_block_witnesses(stripped, blob)
        self.assertEqual(restored.block_hash, block.block_hash)


# ── ChainDB.get_block_by_hash(include_witnesses=True) ────────────────


class TestChainDBReattachVerification(unittest.TestCase):
    """get_block_by_hash(include_witnesses=True) must propagate the
    verification error rather than returning attacker-substituted
    signatures to RPC callers."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = ChainDB(os.path.join(self.tmpdir, "test.db"))

    def tearDown(self):
        self.db.close()

    def _store_post_activation_block(self):
        # Post-activation block stored stripped + side-table populated
        # exactly as `strip_finalized_witnesses` would produce.
        block = _make_block_at_height(
            WITNESS_ROOT_ACTIVATION_HEIGHT + 7, n_txs=3,
            post_activation=True,
        )
        blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)
        self.db.store_block(stripped)
        self.db.store_witness_data(block.block_hash, blob)
        return block, blob

    def test_clean_roundtrip_via_chaindb(self):
        block, _ = self._store_post_activation_block()
        restored = self.db.get_block_by_hash(
            block.block_hash, include_witnesses=True,
        )
        self.assertIsNotNone(restored)
        self.assertEqual(restored.block_hash, block.block_hash)
        # Reattached signatures must exactly match the originals.
        for tx_orig, tx_restored in zip(block.transactions, restored.transactions):
            self.assertEqual(
                tx_orig.signature.to_bytes(),
                tx_restored.signature.to_bytes(),
            )

    def test_tampered_side_table_raises(self):
        """Tamper the stored witness blob (e.g. attacker with archive
        write access).  The chaindb read MUST raise — silently returning
        the attacker's substituted signatures up to RPC is the
        vulnerability we are closing.
        """
        block, blob = self._store_post_activation_block()
        # Tamper a byte inside the first signature in the side-table
        # row.  We overwrite the whole row via the public store helper.
        bad = bytearray(blob)
        bad[12] ^= 0xFF
        self.db.store_witness_data(block.block_hash, bytes(bad))

        with self.assertRaises(WitnessRootMismatchError):
            self.db.get_block_by_hash(
                block.block_hash, include_witnesses=True,
            )

    def test_default_read_unaffected_by_tampered_witnesses(self):
        """A caller that does NOT opt into witnesses gets the stripped
        block back even when the side table is corrupt.  The verify
        check is scoped to include_witnesses=True — corrupt witnesses
        don't take down the core read path.
        """
        block, blob = self._store_post_activation_block()
        bad = bytearray(blob)
        bad[12] ^= 0xFF
        self.db.store_witness_data(block.block_hash, bytes(bad))

        core_only = self.db.get_block_by_hash(block.block_hash)
        self.assertIsNotNone(core_only)
        self.assertEqual(core_only.block_hash, block.block_hash)


# ── Activation-gate sanity ───────────────────────────────────────────


class TestActivationGateMatchesValidator(unittest.TestCase):
    """The reattach gate must use the same WITNESS_ROOT_ACTIVATION_HEIGHT
    constant as `pos.create_block` and `Blockchain.validate_block`.  If
    these drift, a block accepted by validate_block could later fail
    reattach (or vice-versa) on a fresh node syncing from witnesses.
    """

    def test_gate_at_activation_height_enforces(self):
        # Build a block AT exactly the activation height with a real
        # witness_root, tamper the blob, and confirm the verification
        # fires (i.e., the gate is `>= activation`, not `> activation`).
        block = _make_block_at_height(
            WITNESS_ROOT_ACTIVATION_HEIGHT, n_txs=2,
            post_activation=True,
        )
        blob = bytearray(get_block_witness_data(block))
        blob[12] ^= 0xFF
        stripped = strip_block_witnesses(block)
        with self.assertRaises(WitnessRootMismatchError):
            attach_block_witnesses(stripped, bytes(blob))


if __name__ == "__main__":
    unittest.main()
