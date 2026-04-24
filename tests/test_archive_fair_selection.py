"""Tests for iteration 3g: fair proposer-side proof selection.

Closes the proposer-inclusion fairness concern at the proposer side
(the concern that a single proposer's block could be packed with
cartel-preferred proofs while ignoring outsiders in their mempool).

Note on scope: the wider multi-proposer submission window already
structurally limits cartel gatekeeping — a single honest proposer in
the 100-block window includes outsiders, and the deterministic
lottery in apply_archive_rewards (iter 3e) fairly picks winners among
them.  What 3g adds is fairness WITHIN a single proposer's block: when
the mempool holds more proofs than the cap, the cap-selected subset
is chosen by a deterministic shuffle keyed by parent-randao, not by
the proposer's ad-hoc preference.

Combined with 3e's shuffle at payout time, the whole pipeline is now
randomness-driven end-to-end — no point where a single operator can
tilt the selection toward their preferred provers.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import (
    ARCHIVE_PROOFS_PER_CHALLENGE,
    HASH_ALGO,
)
from messagechain.consensus.archive_challenge import (
    CustodyProof,
    build_custody_proof,
)
from messagechain.consensus.archive_proof_mempool import ArchiveProofMempool


# Use a pool of lightweight entities (tree_height=2 → 4 WOTS+ leaves
# per entity) so tests can add many proofs cheaply.
_ENTITY_POOL: list = []


def _entity(i: int):
    """Pool with tree_height=3 (8 leaves) per entity.  Each test
    method signs one proof per entity in setUp; 7 test methods reuse
    entities 0..29 across them so each entity burns ~7 leaves total,
    fitting in the 8-leaf budget with one spare.  At tree_height=2
    the pool would exhaust partway through the suite."""
    from messagechain.identity.identity import Entity
    while len(_ENTITY_POOL) <= i:
        seed = f"fair-{len(_ENTITY_POOL)}".encode().ljust(32, b"\x00")
        _ENTITY_POOL.append(Entity.create(seed, tree_height=3))
    return _ENTITY_POOL[i]


def _h(b: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b).digest()


def _mini_block(txs, block_number):
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": _h(header_bytes),
    }


def _make_proof(entity_idx: int, challenge_block: int, block: dict):
    return build_custody_proof(
        entity=_entity(entity_idx),
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=None,
        tx_bytes=b"",
        all_tx_hashes=[],
    )


class TestFairSelection(unittest.TestCase):
    def setUp(self):
        self.pool = ArchiveProofMempool()
        self.target = _mini_block([], block_number=5)
        # Submit 30 proofs from 30 different entities into the mempool
        # for the same challenge.  Cap in tests is 10 (sufficient to
        # exercise selection; smaller than default cap so we exercise
        # the "more in mempool than cap" branch).
        self.challenge_block = 100
        self.cap = 10
        self.submitted_provers: list[bytes] = []
        for i in range(30):
            proof = _make_proof(i, self.challenge_block, self.target)
            self.pool.add_proof(
                proof, challenge_block_number=self.challenge_block,
            )
            self.submitted_provers.append(proof.prover_id)

    def test_select_returns_cap_or_fewer(self):
        """Selection never returns more than `cap` proofs."""
        chosen = self.pool.select_for_inclusion(
            self.challenge_block,
            cap=self.cap,
            selection_seed=_h(b"seed"),
        )
        self.assertEqual(len(chosen), self.cap)

    def test_select_deterministic_for_same_seed(self):
        """Same seed → same selection.  Two independent proposers
        applying the same rule to the same mempool pick the same
        subset — consensus-relevant property for future enforcement
        work."""
        seed = _h(b"seed-deterministic")
        a = self.pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=seed,
        )
        b = self.pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=seed,
        )
        self.assertEqual(
            [p.prover_id for p in a],
            [p.prover_id for p in b],
        )

    def test_different_seeds_select_different_subsets(self):
        """Different parent randao → different subset.  Proves the
        selection uses the seed, not a latent FCFS bias."""
        a = self.pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=_h(b"seed-A"),
        )
        b = self.pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=_h(b"seed-B"),
        )
        self.assertNotEqual(
            [p.prover_id for p in a], [p.prover_id for p in b],
        )

    def test_selection_is_not_strict_fcfs_arrival_order(self):
        """The strongest test: FCFS would always return provers
        [0..9] (first 10 by arrival).  Deterministic shuffle should
        almost never produce exactly that set.  Try a few seeds."""
        fcfs_winners = {p for p in self.submitted_provers[:self.cap]}
        seen_non_fcfs = False
        for i in range(5):
            chosen = self.pool.select_for_inclusion(
                self.challenge_block, cap=self.cap,
                selection_seed=_h(f"round-{i}".encode()),
            )
            winners = {p.prover_id for p in chosen}
            if winners != fcfs_winners:
                seen_non_fcfs = True
                break
        self.assertTrue(
            seen_non_fcfs,
            "fair selection is indistinguishable from FCFS — arrival-"
            "order bias is not broken at the proposer side",
        )

    def test_selection_covers_every_submitter_across_seeds(self):
        """Across many seeds, every submitter in the mempool should
        eventually appear in the selected subset.  This is what
        "fair" actually means — no submitter is permanently excluded
        by the selection rule."""
        ever_chosen: set[bytes] = set()
        for i in range(80):
            chosen = self.pool.select_for_inclusion(
                self.challenge_block, cap=self.cap,
                selection_seed=_h(f"cover-{i}".encode()),
            )
            for p in chosen:
                ever_chosen.add(p.prover_id)
        # With 30 submitters, 10 picked per draw, 80 draws, every
        # submitter's probability of never appearing is (20/30)^80 ≈
        # 8e-15 — × 30 provers ≈ 2e-13.  Safely never fails.
        self.assertEqual(
            len(ever_chosen), 30,
            f"only {len(ever_chosen)}/30 submitters ever got picked "
            "by the fair-selection rule",
        )

    def test_mempool_with_fewer_than_cap_returns_all(self):
        """When mempool has fewer proofs than cap, selection returns
        all of them (no drops).  Shuffle order may vary but the set
        is unchanged."""
        small_pool = ArchiveProofMempool()
        for i in range(5):
            proof = _make_proof(i + 100, self.challenge_block, self.target)
            small_pool.add_proof(
                proof, challenge_block_number=self.challenge_block,
            )
        chosen = small_pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=_h(b"x"),
        )
        self.assertEqual(len(chosen), 5)

    def test_selection_falls_back_to_fcfs_without_seed(self):
        """Backward compat: selection_seed=None gives the legacy
        FCFS behavior.  Used by tests and callers that haven't been
        updated to supply randomness.  Live-chain callers always
        pass parent randao."""
        chosen = self.pool.select_for_inclusion(
            self.challenge_block, cap=self.cap, selection_seed=None,
        )
        # FCFS order = arrival order = first 10 provers submitted.
        self.assertEqual(
            [p.prover_id for p in chosen],
            self.submitted_provers[:self.cap],
        )


if __name__ == "__main__":
    unittest.main()
