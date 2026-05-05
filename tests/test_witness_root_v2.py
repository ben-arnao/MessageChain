"""B-1 — block-level witness_root that commits to ALL signed body slots.

The legacy `compute_witness_root(transactions: list)` only commits to
`MessageTransaction` signatures.  The activation-fork version
`compute_block_witness_root(block)` walks every signed body slot in
canonical order so the header's witness_root is a complete commitment to
every signature byte in the block.

These tests are the consensus contract for B-1:
    1. Every signed slot contributes to the root.
    2. Tampering ANY signature in ANY slot changes the root.
    3. Slot identity matters — the same signature in slot A vs slot B
       produces different roots (no cross-slot grafting).
    4. Within-slot order matters — reordering changes the root.
    5. Empty-block root is a distinguishable sentinel, NOT b"\\x00" * 32.
    6. Legacy `compute_witness_root` is unaffected.
"""

from __future__ import annotations

import os
import unittest
from dataclasses import dataclass, field

from messagechain.core.witness import (
    SLOT_TX_MESSAGE,
    SLOT_TX_TRANSFER,
    SLOT_FINALITY_VOTE,
    SLOT_VALIDATOR_SIG,
    SLOT_CUSTODY_PROOF,
    compute_block_witness_root,
    compute_witness_root,
    enumerate_block_signatures,
)
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


# ── Stub objects ─────────────────────────────────────────────────────
#
# enumerate_block_signatures only requires `.signature` attributes on
# items inside body lists; the tests construct minimal stubs rather
# than full TransferTransaction / FinalityVote / etc objects so the
# tests stay decoupled from those types' construction surface.  Real
# Signature instances are used (not fakes) so canonical_bytes is
# deterministic and the leaf-hash math is real.


@dataclass
class _SignedStub:
    signature: Signature


@dataclass
class _BlockStub:
    transactions: list = field(default_factory=list)
    transfer_transactions: list = field(default_factory=list)
    stake_transactions: list = field(default_factory=list)
    unstake_transactions: list = field(default_factory=list)
    governance_txs: list = field(default_factory=list)
    authority_txs: list = field(default_factory=list)
    react_transactions: list = field(default_factory=list)
    finality_votes: list = field(default_factory=list)
    slash_transactions: list = field(default_factory=list)
    attestations: list = field(default_factory=list)
    validator_signatures: list = field(default_factory=list)
    custody_proofs: list = field(default_factory=list)
    inclusion_list: object = None
    censorship_evidence_txs: list = field(default_factory=list)
    bogus_rejection_evidence_txs: list = field(default_factory=list)
    inclusion_list_violation_evidence_txs: list = field(default_factory=list)


def _real_signature(entity: Entity, payload: bytes) -> Signature:
    """Produce a real Signature by signing `payload` under `entity`'s key."""
    import hashlib
    from messagechain.config import HASH_ALGO

    h = hashlib.new(HASH_ALGO, payload).digest()
    return entity.keypair.sign(h)


class TestComputeBlockWitnessRoot(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Single shared entity — keygen is the expensive part; reuse
        # it across the suite.  Each test consumes a few WOTS leaves.
        cls.entity = Entity.create(os.urandom(32))
        # Pre-sign a small pool of distinct signatures — the tests
        # combine these into stubs in different shapes to drive the
        # enumeration logic.  Each call consumes one leaf.
        cls.sig_a = _real_signature(cls.entity, b"a")
        cls.sig_b = _real_signature(cls.entity, b"b")
        cls.sig_c = _real_signature(cls.entity, b"c")
        cls.sig_d = _real_signature(cls.entity, b"d")

    def test_empty_block_returns_sentinel_not_zero(self):
        block = _BlockStub()
        root = compute_block_witness_root(block)
        self.assertEqual(len(root), 32)
        # Critical invariant: empty-block root MUST NOT be the all-zero
        # default of `header.witness_root` — a builder that forgets to
        # populate the field would otherwise collide with the empty-body
        # commitment.
        self.assertNotEqual(root, b"\x00" * 32)

    def test_deterministic(self):
        block = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
            transfer_transactions=[_SignedStub(self.sig_b)],
        )
        r1 = compute_block_witness_root(block)
        r2 = compute_block_witness_root(block)
        self.assertEqual(r1, r2)

    def test_changes_when_message_tx_sig_tampered(self):
        block_a = _BlockStub(transactions=[_SignedStub(self.sig_a)])
        block_b = _BlockStub(transactions=[_SignedStub(self.sig_b)])
        self.assertNotEqual(
            compute_block_witness_root(block_a),
            compute_block_witness_root(block_b),
        )

    def test_changes_when_transfer_sig_tampered(self):
        block_a = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
            transfer_transactions=[_SignedStub(self.sig_b)],
        )
        block_b = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
            transfer_transactions=[_SignedStub(self.sig_c)],
        )
        self.assertNotEqual(
            compute_block_witness_root(block_a),
            compute_block_witness_root(block_b),
        )

    def test_changes_when_finality_vote_sig_tampered(self):
        block_a = _BlockStub(finality_votes=[_SignedStub(self.sig_a)])
        block_b = _BlockStub(finality_votes=[_SignedStub(self.sig_b)])
        self.assertNotEqual(
            compute_block_witness_root(block_a),
            compute_block_witness_root(block_b),
        )

    def test_validator_signatures_excluded(self):
        """validator_signatures are added AFTER the proposer signs the
        header, so they cannot be in witness_root.  Two blocks differing
        only in validator_signatures must produce the same witness_root.
        """
        eid = self.entity.entity_id
        block_no_validator_sigs = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
        )
        block_with_validator_sigs = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
            validator_signatures=[(eid, self.sig_b), (eid, self.sig_c)],
        )
        self.assertEqual(
            compute_block_witness_root(block_no_validator_sigs),
            compute_block_witness_root(block_with_validator_sigs),
        )

    def test_changes_when_custody_proof_sig_tampered(self):
        block_a = _BlockStub(custody_proofs=[_SignedStub(self.sig_a)])
        block_b = _BlockStub(custody_proofs=[_SignedStub(self.sig_b)])
        self.assertNotEqual(
            compute_block_witness_root(block_a),
            compute_block_witness_root(block_b),
        )

    def test_no_cross_slot_collision(self):
        """Same signature in different slots → different roots.

        Closes a relayer attack where a sig moves between slots without
        invalidating the witness_root: domain-separation by slot_id
        means the leaf hash depends on which slot the sig is in.
        """
        in_message = _BlockStub(transactions=[_SignedStub(self.sig_a)])
        in_transfer = _BlockStub(transfer_transactions=[_SignedStub(self.sig_a)])
        in_finality = _BlockStub(finality_votes=[_SignedStub(self.sig_a)])
        roots = {
            "message": compute_block_witness_root(in_message),
            "transfer": compute_block_witness_root(in_transfer),
            "finality": compute_block_witness_root(in_finality),
        }
        self.assertEqual(len(set(roots.values())), 3)

    def test_no_within_slot_reorder_collision(self):
        """Reordering items within a slot changes the root.

        Closes a relayer attack where two items in the same slot trade
        positions without invalidating the witness_root: per-leaf
        item_index makes leaves position-dependent.
        """
        order_ab = _BlockStub(
            transactions=[_SignedStub(self.sig_a), _SignedStub(self.sig_b)],
        )
        order_ba = _BlockStub(
            transactions=[_SignedStub(self.sig_b), _SignedStub(self.sig_a)],
        )
        self.assertNotEqual(
            compute_block_witness_root(order_ab),
            compute_block_witness_root(order_ba),
        )

    def test_unsigned_items_contribute_nothing(self):
        """Items without a `.signature` attribute (or signature=None)
        are silently skipped — they have no witness data to commit to.
        """
        # `inclusion_list` is None on the common path; setting it to
        # an unsigned object should not affect the root.
        block_no_inclusion = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
        )

        @dataclass
        class _UnsignedItem:
            value: int = 1

        block_with_unsigned = _BlockStub(
            transactions=[_SignedStub(self.sig_a)],
            inclusion_list=_UnsignedItem(value=42),
        )
        self.assertEqual(
            compute_block_witness_root(block_no_inclusion),
            compute_block_witness_root(block_with_unsigned),
        )


class TestEnumerateBlockSignatures(unittest.TestCase):
    """`enumerate_block_signatures` is the consensus iterator — order
    must be (a) stable across runs and (b) match the slot-id ordering."""

    @classmethod
    def setUpClass(cls):
        cls.entity = Entity.create(os.urandom(32))
        cls.sig = _real_signature(cls.entity, b"shared")

    def test_yields_in_slot_id_order(self):
        # Populate three slots in non-canonical insertion order; the
        # iterator must still yield them in slot-id ascending order.
        block = _BlockStub(
            transactions=[_SignedStub(self.sig)],          # SLOT 0x01
            transfer_transactions=[_SignedStub(self.sig)], # SLOT 0x02
            finality_votes=[_SignedStub(self.sig)],        # SLOT 0x08
            custody_proofs=[_SignedStub(self.sig)],        # SLOT 0x0C
        )
        emitted = enumerate_block_signatures(block)
        slot_ids = [slot for (slot, _idx, _sig) in emitted]
        self.assertEqual(slot_ids, sorted(slot_ids))
        # And the specific slots we populated:
        self.assertEqual(
            slot_ids,
            [SLOT_TX_MESSAGE, SLOT_TX_TRANSFER,
             SLOT_FINALITY_VOTE, SLOT_CUSTODY_PROOF],
        )

    def test_validator_signatures_not_emitted(self):
        # Architectural rule: validator_signatures are added post-sign,
        # so they cannot be in the iterator either.  A block carrying
        # only validator_signatures emits zero leaves.
        eid = self.entity.entity_id
        block = _BlockStub(validator_signatures=[(eid, self.sig)])
        emitted = enumerate_block_signatures(block)
        self.assertEqual(emitted, [])


class TestLegacyWitnessRootUnchanged(unittest.TestCase):
    """The legacy compute_witness_root(transactions) is consumed by
    existing tests + fixtures.  B-1 must not change its output."""

    @classmethod
    def setUpClass(cls):
        cls.entity = Entity.create(os.urandom(32))

    def test_legacy_empty_unchanged(self):
        # Pre-B-1 behavior: empty list returns hash of empty bytes.
        import hashlib
        from messagechain.config import HASH_ALGO

        self.assertEqual(
            compute_witness_root([]),
            hashlib.new(HASH_ALGO, b"").digest(),
        )

    def test_legacy_and_block_form_disagree(self):
        """Legacy form and new block form are intentionally NOT
        byte-equivalent on equivalent inputs — the new form has different
        leaf domain tags and Merkle padding.  This test pins that they
        DO differ so a future refactor doesn't accidentally collapse
        them and break consensus by silently shifting witness_root.
        """
        sig = _real_signature(self.entity, b"shared")
        legacy_root = compute_witness_root([_SignedStub(sig)])
        block_root = compute_block_witness_root(
            _BlockStub(transactions=[_SignedStub(sig)]),
        )
        self.assertNotEqual(legacy_root, block_root)


if __name__ == "__main__":
    unittest.main()
