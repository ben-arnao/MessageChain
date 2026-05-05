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


class TestStripAttachPreservesAllSignedSlots(unittest.TestCase):
    """strip + attach must preserve every slot ``enumerate_block_signatures``
    walks, not just transactions / transfers / stakes / governance /
    authority / finality / slash / attestation.

    Pre-fix, ``strip_block_witnesses`` and ``attach_block_witnesses``
    constructed the new ``Block`` from only 10 of the 17 signed-body
    slots; these 7 were silently dropped:

      * ``react_transactions``                       (SLOT_TX_REACTION)
      * ``custody_proofs``                           (SLOT_CUSTODY_PROOF)
      * ``inclusion_list``                           (SLOT_INCLUSION_LIST)
      * ``censorship_evidence_txs``                  (SLOT_CENSORSHIP_EVIDENCE)
      * ``bogus_rejection_evidence_txs``             (SLOT_BOGUS_REJECT_EVIDENCE)
      * ``inclusion_list_violation_evidence_txs``    (SLOT_INCLUSION_VIOLATION_EVIDENCE)
      * ``non_response_evidence_txs``                (SLOT_NON_RESPONSE_EVIDENCE)

    With any of those slots populated by an item carrying a real
    ``Signature``, the post-activation ``witness_root`` commitment FAILS
    at reattach: the original commits to leaves contributed by the
    dropped slot, but the stripped/attached block sees an empty list
    and recomputes a different root.  Pre-1712 the same defect silently
    deletes the slot data on disk; post-1712 it raises
    ``WitnessRootMismatchError`` on every read of any block that
    carried any of those slots.
    """

    def test_post_activation_roundtrip_preserves_all_seven_slots(self):
        from dataclasses import dataclass as _dc, field as _field
        from messagechain.crypto.keys import Signature as _Sig

        @_dc
        class _SignedStub:
            """Minimal duck-typed item carrying a real ``Signature`` so
            ``_safe_signature`` admits it as a witness leaf contributor.
            We deliberately avoid the real consensus types here — the
            bug is at the ``Block`` constructor (slots passed through),
            not at the per-item serialiser level."""
            signature: _Sig
            tx_hash: bytes = _field(default=b"\x00" * 32)

        entity = _make_entity()
        # One real Signature is enough — every leaf is keyed by
        # (slot_id, item_index, signature.canonical_bytes()), so reusing
        # the same sig across stubs still produces 7 distinct leaves.
        sig = entity.keypair.sign(b"witness-stub-signable-bytes")
        stub = _SignedStub(signature=sig, tx_hash=b"\xaa" * 32)

        msg_tx = create_transaction(entity, "msg 0", 10_000, 0)

        merkle_root = compute_merkle_root([msg_tx.tx_hash])
        header = BlockHeader(
            version=1,
            block_number=WITNESS_ROOT_ACTIVATION_HEIGHT + 5,
            prev_hash=b"\x00" * 32,
            merkle_root=merkle_root,
            timestamp=1_000_001.0,
            proposer_id=entity.entity_id,
        )
        # archive_proof_bundle pre-set so __post_init__ does NOT try to
        # auto-derive a real ``ArchiveProofBundle`` from the stubbed
        # custody_proofs (which would fail real-type validation).
        block = Block(
            header=header,
            transactions=[msg_tx],
            react_transactions=[stub],
            custody_proofs=[stub],
            archive_proof_bundle=stub,
            inclusion_list=stub,
            censorship_evidence_txs=[stub],
            bogus_rejection_evidence_txs=[stub],
            inclusion_list_violation_evidence_txs=[stub],
            non_response_evidence_txs=[stub],
        )
        # Witness_root must be computed AFTER the slots are populated so
        # the leaves they contribute are baked into the commitment the
        # proposer signs.
        header.witness_root = compute_block_witness_root(block)
        header.proposer_signature = entity.keypair.sign(
            _hash(header.signable_data())
        )
        block.block_hash = block._compute_hash()

        blob = get_block_witness_data(block)
        stripped = strip_block_witnesses(block)

        # Every populated slot must survive ``strip``.  The pre-fix code
        # constructed ``stripped`` from only 10 of 17 slots; this is the
        # assertion that fails on pre-fix ``origin/main``.
        for slot_name in (
            "react_transactions",
            "custody_proofs",
            "censorship_evidence_txs",
            "bogus_rejection_evidence_txs",
            "inclusion_list_violation_evidence_txs",
            "non_response_evidence_txs",
        ):
            self.assertEqual(
                list(getattr(stripped, slot_name)),
                list(getattr(block, slot_name)),
                f"{slot_name} lost on strip — witness_root commitment broken",
            )
        self.assertIs(stripped.inclusion_list, block.inclusion_list)
        self.assertIs(stripped.archive_proof_bundle, block.archive_proof_bundle)

        # Reattach must succeed without raising — every slot's leaves
        # are present, so the recomputed witness_root equals the
        # committed header.witness_root.  Pre-fix this raises
        # WitnessRootMismatchError because the seven slots are empty
        # on the restored block and their leaves are missing from the
        # recomputed root.
        restored = attach_block_witnesses(stripped, blob)
        for slot_name in (
            "react_transactions",
            "custody_proofs",
            "censorship_evidence_txs",
            "bogus_rejection_evidence_txs",
            "inclusion_list_violation_evidence_txs",
            "non_response_evidence_txs",
        ):
            self.assertEqual(
                list(getattr(restored, slot_name)),
                list(getattr(block, slot_name)),
            )
        self.assertIs(restored.inclusion_list, block.inclusion_list)
        self.assertEqual(
            compute_block_witness_root(restored), header.witness_root,
        )


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
