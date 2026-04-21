"""Tests for ArchiveProofBundle — aggregated custody-proof commitment.

Design context: every validator in the active set must submit a
CustodyProof once per challenge epoch (duty-coupled archive rewards).
Naively carrying every validator's full proof in the block body scales
linearly in validator count and bloats the 1000-year ledger.

The ArchiveProofBundle is the aggregation primitive that lets consensus
commit to "these validators submitted a valid proof this epoch" without
paying O(validators × proof_size) in on-chain bytes permanently.

What the bundle commits to:
    - Sorted list of participating validator entity_ids.
    - Merkle root over (entity_id || proof_tx_hash) pairs, sorted by
      entity_id.  Any single participant can produce a membership proof
      against this root to demonstrate "my proof was credited."

These tests cover the data-structure layer only — no block-format
integration, no duty enforcement, no reward withholding.  Those are
separate iterations.
"""

from __future__ import annotations

import hashlib
import unittest

from messagechain.config import HASH_ALGO
from messagechain.consensus.archive_challenge import (
    ArchiveProofBundle,
    CustodyProof,
    build_custody_proof,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _mini_block_parts(txs: list[bytes], block_number: int = 1) -> dict:
    """Fake block context just rich enough to build a CustodyProof.

    Mirrors the helper in test_archive_challenge.py — intentionally
    lightweight so these tests don't pull in Blockchain.
    """
    import struct
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    block_hash = _h(header_bytes)
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": block_hash,
    }


def _make_proof(prover_byte: int, block: dict, tx_index: int = 0) -> CustodyProof:
    return build_custody_proof(
        prover_id=bytes([prover_byte]) * 32,
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=tx_index,
        tx_bytes=block["tx_bytes_list"][tx_index],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. Empty bundle
# ---------------------------------------------------------------------------


class TestEmptyBundle(unittest.TestCase):
    def test_empty_bundle_has_deterministic_root(self):
        """An epoch with zero participants yields a sentinel root.

        Must be deterministic: two nodes that both see zero participants
        must agree on the same bundle-root.
        """
        b1 = ArchiveProofBundle.from_proofs([])
        b2 = ArchiveProofBundle.from_proofs([])
        self.assertEqual(b1.root, b2.root)
        self.assertEqual(b1.participants, [])
        self.assertEqual(b1.participant_count, 0)

    def test_empty_bundle_root_is_domain_tagged(self):
        """The empty root is not the hash-of-empty-string — it carries a
        domain tag so nobody can confuse it with a hash of arbitrary
        zero-length input.
        """
        b = ArchiveProofBundle.from_proofs([])
        self.assertNotEqual(b.root, _h(b""))


# ---------------------------------------------------------------------------
# 2. Single-entity bundle
# ---------------------------------------------------------------------------


class TestSingleEntityBundle(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block_parts(
            [f"tx-{i}".encode() * 10 for i in range(3)], 5,
        )

    def test_single_participant_root_is_leaf_hash(self):
        """With one participant, the bundle root is just that leaf's
        hash — the Merkle tree degenerates to a single leaf.
        """
        proof = _make_proof(0x11, self.block)
        bundle = ArchiveProofBundle.from_proofs([proof])
        # Multi-height format: participants is [(entity_id, target_height)].
        self.assertEqual(
            bundle.participants,
            [(proof.prover_id, int(proof.target_height))],
        )
        self.assertEqual(bundle.participant_count, 1)

    def test_single_bundle_root_depends_on_proof_content(self):
        """Flipping the proof (different tx_index) changes the leaf, so
        the bundle root changes too.
        """
        a = _make_proof(0x11, self.block, tx_index=0)
        b = _make_proof(0x11, self.block, tx_index=1)
        self.assertNotEqual(
            ArchiveProofBundle.from_proofs([a]).root,
            ArchiveProofBundle.from_proofs([b]).root,
        )


# ---------------------------------------------------------------------------
# 3. Multi-entity bundle — sort determinism + root stability
# ---------------------------------------------------------------------------


class TestMultiEntityBundle(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block_parts(
            [f"tx-{i}".encode() * 10 for i in range(3)], 5,
        )
        # Three proofs from three distinct prover_ids, in non-sorted
        # order on purpose so we can assert the bundle re-sorts.
        self.proofs = [
            _make_proof(0x33, self.block),
            _make_proof(0x11, self.block),
            _make_proof(0x22, self.block),
        ]

    def test_participants_are_sorted(self):
        """Bundle must expose participants in ascending
        (entity_id, target_height) order regardless of submission
        order.  Determinism = every node agrees on the same bundle-
        root for the same set of proofs.
        """
        bundle = ArchiveProofBundle.from_proofs(self.proofs)
        self.assertEqual(
            bundle.participants,
            sorted([(p.prover_id, int(p.target_height)) for p in self.proofs]),
        )

    def test_root_is_order_invariant(self):
        """Submitting the same proofs in any order yields the same root.
        """
        import random
        roots = set()
        for _ in range(5):
            shuffled = list(self.proofs)
            random.shuffle(shuffled)
            roots.add(ArchiveProofBundle.from_proofs(shuffled).root)
        self.assertEqual(len(roots), 1)

    def test_different_sets_yield_different_roots(self):
        """Adding a participant changes the root — we can't have two
        different sets collapsing to the same commitment.
        """
        r1 = ArchiveProofBundle.from_proofs(self.proofs).root
        extra = _make_proof(0x44, self.block)
        r2 = ArchiveProofBundle.from_proofs(self.proofs + [extra]).root
        self.assertNotEqual(r1, r2)

    def test_duplicate_prover_ids_rejected(self):
        """A single prover submitting twice is a malformed bundle — the
        bundle must refuse rather than silently dedupe, since we can't
        tell which proof was intended to be the canonical one.
        """
        dupe = _make_proof(0x11, self.block)
        with self.assertRaises(ValueError):
            ArchiveProofBundle.from_proofs([dupe, dupe])

    def test_participant_count_matches_list_length(self):
        bundle = ArchiveProofBundle.from_proofs(self.proofs)
        self.assertEqual(bundle.participant_count, len(self.proofs))
        self.assertEqual(len(bundle.participants), len(self.proofs))


# ---------------------------------------------------------------------------
# 4. Canonical bytes (consensus serialization)
# ---------------------------------------------------------------------------


class TestCanonicalBytes(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block_parts(
            [f"tx-{i}".encode() * 10 for i in range(3)], 5,
        )
        self.proofs = [_make_proof(i + 1, self.block) for i in range(4)]

    def test_canonical_bytes_roundtrip(self):
        """Encode then decode recovers an identical bundle."""
        original = ArchiveProofBundle.from_proofs(self.proofs)
        decoded = ArchiveProofBundle.from_bytes(original.to_bytes())
        self.assertEqual(decoded.root, original.root)
        self.assertEqual(decoded.participants, original.participants)
        self.assertEqual(decoded.participant_count, original.participant_count)

    def test_canonical_bytes_is_stable_across_orderings(self):
        """Because the bundle sorts participants, two different
        construction orders must produce the same canonical bytes.
        """
        a = ArchiveProofBundle.from_proofs(self.proofs)
        b = ArchiveProofBundle.from_proofs(list(reversed(self.proofs)))
        self.assertEqual(a.to_bytes(), b.to_bytes())

    def test_empty_bundle_roundtrip(self):
        empty = ArchiveProofBundle.from_proofs([])
        decoded = ArchiveProofBundle.from_bytes(empty.to_bytes())
        self.assertEqual(decoded.root, empty.root)
        self.assertEqual(decoded.participants, [])

    def test_from_bytes_rejects_truncated_blob(self):
        """A malformed blob (truncated partway) must raise, not
        silently return a partial bundle — consensus must not accept
        undefined-state commitments.
        """
        good = ArchiveProofBundle.from_proofs(self.proofs).to_bytes()
        with self.assertRaises(ValueError):
            ArchiveProofBundle.from_bytes(good[:10])

    def test_from_bytes_rejects_trailing_garbage(self):
        """Appending extra bytes must be rejected — keeps the wire
        format unambiguous and prevents a relayer from smuggling extra
        data past a permissive decoder.
        """
        good = ArchiveProofBundle.from_proofs(self.proofs).to_bytes()
        with self.assertRaises(ValueError):
            ArchiveProofBundle.from_bytes(good + b"\x00\x01")


# ---------------------------------------------------------------------------
# 5. Membership verification
# ---------------------------------------------------------------------------


class TestMembershipVerify(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block_parts(
            [f"tx-{i}".encode() * 10 for i in range(3)], 5,
        )
        self.proofs = [_make_proof(i + 1, self.block) for i in range(5)]
        self.bundle = ArchiveProofBundle.from_proofs(self.proofs)

    def test_contains_identifies_participants(self):
        """Sanity: every proof's (prover_id, target_height) pair is in
        the bundle.
        """
        for p in self.proofs:
            self.assertTrue(
                self.bundle.contains(p.prover_id, int(p.target_height)),
            )

    def test_contains_rejects_non_participant(self):
        stranger = bytes([0xFE]) * 32
        self.assertFalse(self.bundle.contains(stranger, target_height=5))

    def test_membership_proof_verifies(self):
        """Given the bundle root + (entity_id, target_height) + their
        submitted CustodyProof, we can generate a Merkle inclusion proof
        that third parties verify against root alone.  This is the
        primitive a pruned chain uses: the full bundle body is gone, but
        the root persists in block state, and anyone with their own
        submitted CustodyProof can prove they were credited.
        """
        # Pick the middle prover.
        target = self.proofs[2]
        membership = self.bundle.build_membership_proof(
            target.prover_id, int(target.target_height),
        )
        ok = ArchiveProofBundle.verify_membership(
            root=self.bundle.root,
            entity_id=target.prover_id,
            target_height=int(target.target_height),
            proof_tx_hash=target.tx_hash,
            membership_proof=membership,
        )
        self.assertTrue(ok)

    def test_membership_proof_rejects_wrong_entity(self):
        """A membership proof built for prover A cannot be replayed by
        prover B — entity_id is part of the leaf.
        """
        target = self.proofs[2]
        imposter = self.proofs[0]
        membership = self.bundle.build_membership_proof(
            target.prover_id, int(target.target_height),
        )
        ok = ArchiveProofBundle.verify_membership(
            root=self.bundle.root,
            entity_id=imposter.prover_id,
            target_height=int(target.target_height),
            proof_tx_hash=target.tx_hash,
            membership_proof=membership,
        )
        self.assertFalse(ok)

    def test_membership_proof_rejects_forged_path(self):
        """Flipping a sibling hash breaks verification."""
        target = self.proofs[2]
        membership = self.bundle.build_membership_proof(
            target.prover_id, int(target.target_height),
        )
        self.assertGreater(
            len(membership["siblings"]), 0,
            "need >1 participant for a non-trivial path",
        )
        bad = bytearray(membership["siblings"][0])
        bad[0] ^= 0xFF
        forged = dict(membership)
        forged["siblings"] = [bytes(bad)] + list(membership["siblings"][1:])
        ok = ArchiveProofBundle.verify_membership(
            root=self.bundle.root,
            entity_id=target.prover_id,
            target_height=int(target.target_height),
            proof_tx_hash=target.tx_hash,
            membership_proof=forged,
        )
        self.assertFalse(ok)

    def test_build_membership_proof_rejects_non_participant(self):
        stranger = bytes([0xFE]) * 32
        with self.assertRaises(ValueError):
            self.bundle.build_membership_proof(stranger, target_height=5)

    def test_single_participant_membership_verifies(self):
        """Edge: single-leaf tree.  Membership proof is empty-siblings
        but must still verify against the trivial root.
        """
        solo = [self.proofs[0]]
        bundle = ArchiveProofBundle.from_proofs(solo)
        membership = bundle.build_membership_proof(
            solo[0].prover_id, int(solo[0].target_height),
        )
        ok = ArchiveProofBundle.verify_membership(
            root=bundle.root,
            entity_id=solo[0].prover_id,
            target_height=int(solo[0].target_height),
            proof_tx_hash=solo[0].tx_hash,
            membership_proof=membership,
        )
        self.assertTrue(ok)


# ---------------------------------------------------------------------------
# 6. Bytes efficiency: commitment size is constant-ish in validator count
# ---------------------------------------------------------------------------


class TestCommitmentSize(unittest.TestCase):
    """The whole point of aggregation: commitment size grows O(log N)
    implicitly via the Merkle path, but the header commitment itself is
    O(1) (a root + count).  This test guards against regressions where
    someone accidentally puts the full participant list in the header.
    """

    def test_root_is_fixed_size(self):
        block = _mini_block_parts(
            [f"tx-{i}".encode() * 10 for i in range(3)], 5,
        )
        small = ArchiveProofBundle.from_proofs([
            _make_proof(i + 1, block) for i in range(3)
        ])
        large = ArchiveProofBundle.from_proofs([
            _make_proof(i + 1, block) for i in range(100)
        ])
        # Root size is the hash size — does not grow with participant count.
        self.assertEqual(len(small.root), len(large.root))
        self.assertEqual(len(small.root), 32)


if __name__ == "__main__":
    unittest.main()
