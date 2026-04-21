"""Tests for multi-height archive challenges + per-(prover, height)
bundle leaves.

Sub-iteration 3a of the validator-duty archive-reward redesign.
Strengthens the custody challenge from one-tx-per-epoch to K-distinct-
historical-heights-per-epoch, so a validator that keeps only a 1%
slice of history can no longer reliably pass.  Duty enforcement (the
piece that actually withholds rewards on miss) is iteration 3b.

Scope of this file:
    * compute_challenges() returns K deterministic challenges per
      block_hash, each at a distinct historical height.
    * ArchiveProofBundle leaves now key on (prover_id, target_height)
      rather than prover_id alone, so the same validator can submit
      proofs for K distinct heights in one epoch and each is credited
      separately.
    * Dedup rejects duplicate (prover_id, target_height) pairs only —
      same prover_id at different heights is legal.
    * `contains(prover_id, target_height)` is the per-height
      membership query the duty layer will use in iteration 3b.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import HASH_ALGO, ARCHIVE_CHALLENGE_K
from messagechain.consensus.archive_challenge import (
    ArchiveChallenge,
    ArchiveProofBundle,
    CustodyProof,
    build_custody_proof,
    compute_challenge,
    compute_challenges,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _mini_block(txs: list[bytes], block_number: int) -> dict:
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


def _make_proof(prover_byte: int, target_height: int) -> CustodyProof:
    block = _mini_block(
        [f"tx-{i}".encode() * 10 for i in range(3)], target_height,
    )
    return build_custody_proof(
        prover_id=bytes([prover_byte]) * 32,
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=0,
        tx_bytes=block["tx_bytes_list"][0],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. compute_challenges: K-deterministic challenges per block hash
# ---------------------------------------------------------------------------


class TestComputeChallenges(unittest.TestCase):
    def test_returns_k_challenges(self):
        """Default K (from config) returns exactly that many challenges."""
        block_hash = _h(b"block-1")
        challenges = compute_challenges(block_hash, 500)
        self.assertEqual(len(challenges), ARCHIVE_CHALLENGE_K)

    def test_explicit_k_honored(self):
        """Passing K=5 returns exactly 5 challenges, regardless of
        the config default — lets governance tune K without plumbing
        through every callsite.
        """
        challenges = compute_challenges(_h(b"block-1"), 500, k=5)
        self.assertEqual(len(challenges), 5)

    def test_challenges_are_distinct_heights_in_common_case(self):
        """With B much larger than K the K challenges hit K distinct
        heights with overwhelming probability.  Collisions are allowed
        by the protocol (a K that's larger than B cannot avoid them)
        but the common-case test guards against an off-by-one in the
        index-domain-separation scheme.
        """
        challenges = compute_challenges(_h(b"block-1"), 10_000, k=5)
        heights = {c.target_height for c in challenges}
        self.assertEqual(len(heights), 5)

    def test_index_0_matches_single_compute_challenge(self):
        """compute_challenge(bh, B) is the K=1 case of
        compute_challenges; index 0 of the multi-challenge output must
        match bit-for-bit for backwards compatibility.
        """
        block_hash = _h(b"block-x")
        single = compute_challenge(block_hash, 1000)
        multi = compute_challenges(block_hash, 1000, k=1)
        self.assertEqual(len(multi), 1)
        self.assertEqual(multi[0].target_height, single.target_height)
        self.assertEqual(multi[0].target_leaf_seed, single.target_leaf_seed)

    def test_challenges_determistic(self):
        """Same block_hash -> same challenge set, every time."""
        bh = _h(b"block-deterministic")
        a = compute_challenges(bh, 2000, k=4)
        b = compute_challenges(bh, 2000, k=4)
        self.assertEqual(
            [c.target_height for c in a],
            [c.target_height for c in b],
        )
        self.assertEqual(
            [c.target_leaf_seed for c in a],
            [c.target_leaf_seed for c in b],
        )

    def test_different_block_hashes_give_different_sets(self):
        """Two distinct block hashes must not land on the same K-set —
        sanity check on the per-index domain separation.
        """
        a = compute_challenges(_h(b"block-A"), 2000, k=4)
        b = compute_challenges(_h(b"block-B"), 2000, k=4)
        self.assertNotEqual(
            [c.target_height for c in a],
            [c.target_height for c in b],
        )

    def test_rejects_k_zero_or_negative(self):
        with self.assertRaises(ValueError):
            compute_challenges(_h(b"x"), 100, k=0)
        with self.assertRaises(ValueError):
            compute_challenges(_h(b"x"), 100, k=-1)

    def test_rejects_nonpositive_B(self):
        """Same guard compute_challenge enforces — no history to
        challenge at B=0.
        """
        with self.assertRaises(ValueError):
            compute_challenges(_h(b"x"), 0, k=3)
        with self.assertRaises(ValueError):
            compute_challenges(_h(b"x"), -1, k=3)


# ---------------------------------------------------------------------------
# 2. Bundle leaf keys on (prover_id, target_height)
# ---------------------------------------------------------------------------


class TestBundlePerHeightLeaves(unittest.TestCase):
    def test_same_prover_distinct_heights_both_credited(self):
        """Validator V submits a proof at height 5 and another at
        height 10 — both must be present in the bundle and both must be
        independently queryable.
        """
        p1 = _make_proof(0x11, target_height=5)
        p2 = _make_proof(0x11, target_height=10)
        bundle = ArchiveProofBundle.from_proofs([p1, p2])
        self.assertEqual(bundle.participant_count, 2)  # two leaves, not one
        self.assertTrue(bundle.contains(p1.prover_id, target_height=5))
        self.assertTrue(bundle.contains(p1.prover_id, target_height=10))
        self.assertFalse(bundle.contains(p1.prover_id, target_height=7))

    def test_duplicate_prover_height_pair_rejected(self):
        """The same (prover_id, target_height) submitted twice is a
        malformed bundle — two distinct proofs for the same pair means
        we cannot tell which one is canonical.
        """
        p1 = _make_proof(0x11, target_height=5)
        p2 = _make_proof(0x11, target_height=5)
        with self.assertRaises(ValueError):
            ArchiveProofBundle.from_proofs([p1, p2])

    def test_distinct_provers_same_height_both_credited(self):
        """Two validators submit for the same challenge height —
        bundle carries both as independent leaves, neither dedup'd.
        """
        p1 = _make_proof(0x11, target_height=5)
        p2 = _make_proof(0x22, target_height=5)
        bundle = ArchiveProofBundle.from_proofs([p1, p2])
        self.assertEqual(bundle.participant_count, 2)
        self.assertTrue(bundle.contains(p1.prover_id, target_height=5))
        self.assertTrue(bundle.contains(p2.prover_id, target_height=5))

    def test_bundle_root_order_invariant_across_height_and_id(self):
        """Sort order is (prover_id, target_height).  Submitting the
        same set in any order yields the same root.
        """
        import random
        proofs = [
            _make_proof(0x11, 5),
            _make_proof(0x11, 10),
            _make_proof(0x22, 5),
            _make_proof(0x22, 10),
        ]
        roots = set()
        for _ in range(5):
            shuffled = list(proofs)
            random.shuffle(shuffled)
            roots.add(ArchiveProofBundle.from_proofs(shuffled).root)
        self.assertEqual(len(roots), 1)

    def test_participants_list_contains_height_pairs(self):
        """participants now exposes (prover_id, target_height) tuples
        so the duty layer can enumerate the full credit set without
        re-deriving from leaf hashes.  Sorted by (prover_id, height).
        """
        p1 = _make_proof(0x22, 5)
        p2 = _make_proof(0x11, 10)
        p3 = _make_proof(0x11, 5)
        bundle = ArchiveProofBundle.from_proofs([p1, p2, p3])
        self.assertEqual(
            bundle.participants,
            [
                (bytes([0x11]) * 32, 5),
                (bytes([0x11]) * 32, 10),
                (bytes([0x22]) * 32, 5),
            ],
        )


# ---------------------------------------------------------------------------
# 3. Canonical bytes preserve (prover, height) pairs
# ---------------------------------------------------------------------------


class TestCanonicalBytesWithHeight(unittest.TestCase):
    def test_roundtrip_preserves_prover_height_pairs(self):
        proofs = [
            _make_proof(0x11, 5),
            _make_proof(0x11, 10),
            _make_proof(0x22, 5),
        ]
        original = ArchiveProofBundle.from_proofs(proofs)
        decoded = ArchiveProofBundle.from_bytes(original.to_bytes())
        self.assertEqual(decoded.root, original.root)
        self.assertEqual(decoded.participants, original.participants)

    def test_contains_works_after_roundtrip(self):
        proofs = [
            _make_proof(0x11, 5),
            _make_proof(0x11, 10),
        ]
        original = ArchiveProofBundle.from_proofs(proofs)
        decoded = ArchiveProofBundle.from_bytes(original.to_bytes())
        self.assertTrue(decoded.contains(bytes([0x11]) * 32, target_height=5))
        self.assertTrue(decoded.contains(bytes([0x11]) * 32, target_height=10))
        self.assertFalse(decoded.contains(bytes([0x11]) * 32, target_height=7))


# ---------------------------------------------------------------------------
# 4. Membership proofs still work at the new granularity
# ---------------------------------------------------------------------------


class TestMembershipAtHeightGranularity(unittest.TestCase):
    def test_membership_proof_binds_target_height(self):
        """A membership proof built for (V, h=5) cannot be replayed as
        proof-of-custody for (V, h=10) — target_height is part of the
        leaf, so the leaf hashes differ and the Merkle path fails for
        any other height.
        """
        p5 = _make_proof(0x11, 5)
        p10 = _make_proof(0x11, 10)
        bundle = ArchiveProofBundle.from_proofs([p5, p10])
        # Membership proof for (V, h=5)
        m5 = bundle.build_membership_proof(
            entity_id=p5.prover_id, target_height=5,
        )
        # Verifies against (V, h=5) — expected-ok.
        ok = ArchiveProofBundle.verify_membership(
            root=bundle.root,
            entity_id=p5.prover_id,
            target_height=5,
            proof_tx_hash=p5.tx_hash,
            membership_proof=m5,
        )
        self.assertTrue(ok)
        # Does NOT verify if we claim the same path proves (V, h=10) —
        # different leaf hash, path reconstructs wrong root.
        ok_wrong_height = ArchiveProofBundle.verify_membership(
            root=bundle.root,
            entity_id=p5.prover_id,
            target_height=10,
            proof_tx_hash=p5.tx_hash,
            membership_proof=m5,
        )
        self.assertFalse(ok_wrong_height)

    def test_build_membership_rejects_unseen_pair(self):
        """Asking for a (prover, height) not in the bundle raises."""
        bundle = ArchiveProofBundle.from_proofs([_make_proof(0x11, 5)])
        with self.assertRaises(ValueError):
            bundle.build_membership_proof(
                entity_id=bytes([0x11]) * 32, target_height=99,
            )


# ---------------------------------------------------------------------------
# 5. Backward-compat: existing single-height API still callable
# ---------------------------------------------------------------------------


class TestSingleChallengeBackCompat(unittest.TestCase):
    def test_compute_challenge_still_returns_single(self):
        """compute_challenge (singular) must keep behaving as before
        so downstream callers that don't yet know about K=3 aren't
        forced to update in the same PR.
        """
        c = compute_challenge(_h(b"x"), 500)
        self.assertIsInstance(c, ArchiveChallenge)
        self.assertGreaterEqual(c.target_height, 0)
        self.assertLess(c.target_height, 500)


if __name__ == "__main__":
    unittest.main()
