"""Canonical block tx-hash list — single source of truth for merkle
root composition across proposer, validator, and SPV-proof paths.

The project's merkle-root input list was independently re-built at four
call sites:
  1. pos.create_block          (proposer side — CANONICAL, 10 + bundle)
  2. blockchain.validate_block (primary validator — CANONICAL, 10 + bundle)
  3. blockchain.validate_block_standalone (fork validator — 6 vars, BUG)
  4. spv.generate_merkle_proof (SPV-proof builder — 2 vars, BUG)

Sites 3 and 4 had drifted — any block carrying finality_votes,
custody_proofs, censorship_evidence, bogus_rejection_evidence, or an
archive_proof_bundle would have its merkle root computed DIFFERENTLY
by the fork-path validator, causing spurious "Invalid merkle root"
rejections on legitimately-constructed blocks.

This module's helper `canonical_block_tx_hashes` is now the SINGLE
source of truth.  The four callers above MUST route through it.

These tests pin the helper's output shape against a hand-assembled
block covering every tx variant, so a future contributor adding a new
tx list (or a new commitment like archive_proof_bundle) sees a loud
test failure if they forget to update the helper.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field


@dataclass
class _FakeTx:
    tx_hash: bytes

    def consensus_hash(self) -> bytes:
        return self.tx_hash


@dataclass
class _FakeCustodyProof:
    """Minimal shape that ArchiveProofBundle.from_proofs tolerates:
    needs tx_hash (for the canonical list) plus prover_id +
    target_height (for the bundle-ordering sort)."""
    tx_hash: bytes
    prover_id: bytes = b"\x00" * 32
    target_height: int = 0


@dataclass
class _FakeBundle:
    tx_hash: bytes


@dataclass
class _FakeBlock:
    transactions: list = field(default_factory=list)
    transfer_transactions: list = field(default_factory=list)
    slash_transactions: list = field(default_factory=list)
    governance_txs: list = field(default_factory=list)
    authority_txs: list = field(default_factory=list)
    stake_transactions: list = field(default_factory=list)
    unstake_transactions: list = field(default_factory=list)
    finality_votes: list = field(default_factory=list)
    custody_proofs: list = field(default_factory=list)
    censorship_evidence_txs: list = field(default_factory=list)
    bogus_rejection_evidence_txs: list = field(default_factory=list)
    archive_proof_bundle: object = None


def _h(tag: str) -> bytes:
    """Distinct 32-byte hashes so we can eyeball the ordering."""
    return tag.encode().ljust(32, b"\x00")


class TestCanonicalOrdering(unittest.TestCase):

    def test_empty_block_returns_empty_list(self):
        from messagechain.core.block import canonical_block_tx_hashes
        self.assertEqual(canonical_block_tx_hashes(_FakeBlock()), [])

    def test_full_variant_ordering(self):
        """Every tx variant contributes exactly once, in the documented
        order: message, transfer, slash, governance, authority, stake,
        unstake, finality_votes, custody_proofs, censorship_evidence,
        bogus_rejection_evidence, then archive_proof_bundle last."""
        from messagechain.core.block import canonical_block_tx_hashes
        from messagechain.consensus.archive_challenge import (
            ArchiveProofBundle,
        )

        block = _FakeBlock(
            transactions=[_FakeTx(_h("msg"))],
            transfer_transactions=[_FakeTx(_h("xfer"))],
            slash_transactions=[_FakeTx(_h("slash"))],
            governance_txs=[_FakeTx(_h("gov"))],
            authority_txs=[_FakeTx(_h("auth"))],
            stake_transactions=[_FakeTx(_h("stk"))],
            unstake_transactions=[_FakeTx(_h("unstk"))],
            finality_votes=[_FakeTx(_h("finv"))],
            custody_proofs=[_FakeCustodyProof(_h("cust"))],
            censorship_evidence_txs=[_FakeTx(_h("cens"))],
            bogus_rejection_evidence_txs=[_FakeTx(_h("bogus"))],
        )
        # The helper auto-derives the bundle from custody_proofs when
        # they exist, so we don't set archive_proof_bundle explicitly.
        expected_bundle_hash = ArchiveProofBundle.from_proofs(
            block.custody_proofs
        ).tx_hash

        result = canonical_block_tx_hashes(block)
        self.assertEqual(
            result,
            [
                _h("msg"),
                _h("xfer"),
                _h("slash"),
                _h("gov"),
                _h("auth"),
                _h("stk"),
                _h("unstk"),
                _h("finv"),
                _h("cust"),
                _h("cens"),
                _h("bogus"),
                expected_bundle_hash,
            ],
        )

    def test_bundle_not_appended_when_custody_proofs_empty(self):
        """archive_proof_bundle is a derived commitment over custody_proofs —
        when there's nothing to commit to, no bundle hash is appended."""
        from messagechain.core.block import canonical_block_tx_hashes
        block = _FakeBlock(
            transactions=[_FakeTx(_h("msg"))],
            custody_proofs=[],
        )
        self.assertEqual(canonical_block_tx_hashes(block), [_h("msg")])

    def test_only_message_txs_returns_just_message_hashes(self):
        """Regression: the OLD spv.generate_merkle_proof implementation
        built the tree from only message+transfer txs.  A block with
        ONLY those txs MUST still produce the same hashes as before, so
        existing happy-path SPV tests don't break silently."""
        from messagechain.core.block import canonical_block_tx_hashes
        block = _FakeBlock(
            transactions=[_FakeTx(_h("a")), _FakeTx(_h("b"))],
            transfer_transactions=[_FakeTx(_h("c"))],
        )
        self.assertEqual(
            canonical_block_tx_hashes(block),
            [_h("a"), _h("b"), _h("c")],
        )

    def test_finality_votes_use_consensus_hash(self):
        """FinalityVote doesn't have tx_hash — it has consensus_hash().
        The canonical list must call that, not getattr(v, 'tx_hash')."""
        from messagechain.core.block import canonical_block_tx_hashes

        class _FakeVote:
            def consensus_hash(self):
                return _h("vote-consensus")
            # NO tx_hash attribute — getattr fallback must NOT find one.

        block = _FakeBlock(finality_votes=[_FakeVote()])
        self.assertEqual(
            canonical_block_tx_hashes(block),
            [_h("vote-consensus")],
        )


class TestCallerParity(unittest.TestCase):
    """Every caller of `compute_merkle_root` in production code that
    reasons about a Block's tx list must route through the canonical
    helper — otherwise future tx-variant additions drift silently.

    Source-grep approach: scan the codebase and assert no production
    path re-implements the list outside canonical_block_tx_hashes.
    """

    def test_no_direct_merkle_root_from_handbuilt_list_in_prod(self):
        import os
        import re

        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        prod_paths = [
            os.path.join(repo_root, "messagechain", "core", "blockchain.py"),
            os.path.join(repo_root, "messagechain", "consensus", "pos.py"),
            os.path.join(repo_root, "messagechain", "core", "spv.py"),
        ]

        # Pattern: a fat ordered list that starts with tx.tx_hash
        # followed by a `+` continuation — signature of a hand-rolled
        # canonical list that should have been routed through the
        # helper.  One contiguous chain of `[... for tx in block.FOO]`
        # concat expressions, three or more variants.
        #
        # We look for the combination of message + transfer in a single
        # list comprehension chain that concatenates at least 3
        # variants — the old drift signature.
        pat = re.compile(
            r"\[tx\.tx_hash for tx in (?:all_txs|block\.transactions)\][\s\S]{0,50}"
            r"\+[\s\S]{0,500}"
            r"\+[\s\S]{0,500}\+",
            re.MULTILINE,
        )

        for p in prod_paths:
            with open(p, encoding="utf-8") as f:
                src = f.read()
            matches = pat.findall(src)
            self.assertEqual(
                matches, [],
                f"{p} still builds the canonical tx-hash list by hand; "
                f"route through messagechain.core.block."
                f"canonical_block_tx_hashes(block) instead.",
            )


if __name__ == "__main__":
    unittest.main()
