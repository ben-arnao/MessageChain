"""Tests for Block integration of ArchiveProofBundle.

Iteration 2 of the validator-duty archive-reward redesign.  Adds the
aggregated bundle to the block body so it survives independently of
custody_proofs after a future pruning iteration.

Scope:
    * Block carries an optional archive_proof_bundle field.
    * Bundle is auto-derived from custody_proofs when the field is
      left as the default None.
    * Round-trips through dict + binary serialization.
    * Bundle.tx_hash is folded into merkle_root so relayers cannot
      strip it in transit.
    * Block validation rejects blocks whose bundle doesn't match the
      derivation from their custody_proofs (forgery defense).

Out of scope for this iteration:
    * Duty enforcement / reward withholding.
    * Bootstrap grace.
    * Post-finality pruning of proof bodies.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import HASH_ALGO
from messagechain.consensus.archive_challenge import (
    ArchiveProofBundle,
    CustodyProof,
    build_custody_proof,
)
from messagechain.core.block import Block, compute_merkle_root


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _mini_block_parts(txs: list[bytes], block_number: int = 1) -> dict:
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


def _make_proof(prover_byte: int) -> CustodyProof:
    ctx = _mini_block_parts(
        [f"tx-{i}".encode() * 10 for i in range(3)], 5,
    )
    return build_custody_proof(
        prover_id=bytes([prover_byte]) * 32,
        target_height=ctx["block_number"],
        target_block_hash=ctx["block_hash"],
        header_bytes=ctx["header_bytes"],
        merkle_root=ctx["merkle_root"],
        tx_index=0,
        tx_bytes=ctx["tx_bytes_list"][0],
        all_tx_hashes=ctx["tx_hashes"],
    )


def _make_block_with_proofs(chain, proposer, pos, proofs):
    """Propose a block on `chain` carrying the given custody proofs.

    Uses the live ProofOfStake.propose_block path so merkle_root, state
    root, proposer signature, etc. are all real — we're testing
    integration, not unit-level construction.
    """
    return chain.propose_block(pos, proposer, transactions=[], custody_proofs=proofs)


def _fresh_chain():
    from messagechain.identity.identity import Entity
    from messagechain.core.blockchain import Blockchain
    from messagechain.consensus.pos import ProofOfStake
    alice = Entity.create(b"alice-bundle-test".ljust(32, b"\x00"))
    chain = Blockchain()
    chain.initialize_genesis(alice)
    chain.supply.balances[alice.entity_id] = 10_000_000
    chain.supply.stake(alice.entity_id, 100_000)
    return chain, alice, ProofOfStake()


# ---------------------------------------------------------------------------
# 1. Auto-derivation of bundle from custody_proofs
# ---------------------------------------------------------------------------


class TestAutoDerive(unittest.TestCase):
    def test_empty_custody_proofs_yields_none_bundle(self):
        """A block with no custody_proofs must have no bundle — the
        bundle's raison d'etre is to commit to participants, and there
        are none here.
        """
        block = Block(header=_dummy_header(), transactions=[])
        self.assertIsNone(block.archive_proof_bundle)

    def test_nonempty_proofs_derives_bundle(self):
        """A block with custody_proofs auto-populates a matching bundle
        when the caller leaves the field unset.
        """
        proofs = [_make_proof(i + 1) for i in range(3)]
        block = Block(
            header=_dummy_header(),
            transactions=[],
            custody_proofs=proofs,
        )
        self.assertIsNotNone(block.archive_proof_bundle)
        expected = ArchiveProofBundle.from_proofs(proofs)
        self.assertEqual(block.archive_proof_bundle.root, expected.root)
        self.assertEqual(
            block.archive_proof_bundle.participants, expected.participants,
        )

    def test_explicit_bundle_not_overwritten(self):
        """If the caller passes their own bundle (even a wrong one),
        __post_init__ does not overwrite.  Validation catches wrong
        bundles elsewhere — __post_init__ is just a convenience for the
        common case.
        """
        proofs = [_make_proof(i + 1) for i in range(3)]
        wrong_proofs = [_make_proof(9), _make_proof(8)]  # disjoint set
        wrong_bundle = ArchiveProofBundle.from_proofs(wrong_proofs)
        block = Block(
            header=_dummy_header(),
            transactions=[],
            custody_proofs=proofs,
            archive_proof_bundle=wrong_bundle,
        )
        self.assertEqual(block.archive_proof_bundle.root, wrong_bundle.root)


# ---------------------------------------------------------------------------
# 2. Dict serialization round-trip
# ---------------------------------------------------------------------------


class TestDictRoundTrip(unittest.TestCase):
    def test_block_with_bundle_dict_roundtrip(self):
        """End-to-end through Blockchain so all invariants (merkle_root,
        signatures) are real — serialize the produced block to dict,
        deserialize, and confirm the bundle survives intact.
        """
        chain, alice, pos = _fresh_chain()
        proofs = [_make_proof(i + 1) for i in range(2)]
        block = _make_block_with_proofs(chain, alice, pos, proofs)
        self.assertIsNotNone(block.archive_proof_bundle)
        data = block.serialize()
        self.assertIn("archive_proof_bundle", data)
        restored = Block.deserialize(data)
        self.assertEqual(
            restored.archive_proof_bundle.root,
            block.archive_proof_bundle.root,
        )
        self.assertEqual(
            restored.archive_proof_bundle.participants,
            block.archive_proof_bundle.participants,
        )

    def test_block_without_bundle_dict_roundtrip(self):
        """A block with no bundle round-trips cleanly — the key is
        absent (or None) and restoration produces a None bundle.
        """
        chain, alice, pos = _fresh_chain()
        block = _make_block_with_proofs(chain, alice, pos, [])
        self.assertIsNone(block.archive_proof_bundle)
        data = block.serialize()
        restored = Block.deserialize(data)
        self.assertIsNone(restored.archive_proof_bundle)


# ---------------------------------------------------------------------------
# 3. Binary serialization round-trip
# ---------------------------------------------------------------------------


class TestBinaryRoundTrip(unittest.TestCase):
    def test_block_with_bundle_binary_roundtrip(self):
        chain, alice, pos = _fresh_chain()
        proofs = [_make_proof(i + 1) for i in range(3)]
        block = _make_block_with_proofs(chain, alice, pos, proofs)
        blob = block.to_bytes()
        restored = Block.from_bytes(blob)
        self.assertIsNotNone(restored.archive_proof_bundle)
        self.assertEqual(
            restored.archive_proof_bundle.root,
            block.archive_proof_bundle.root,
        )
        self.assertEqual(
            restored.archive_proof_bundle.participants,
            block.archive_proof_bundle.participants,
        )

    def test_block_without_bundle_binary_roundtrip(self):
        chain, alice, pos = _fresh_chain()
        block = _make_block_with_proofs(chain, alice, pos, [])
        blob = block.to_bytes()
        restored = Block.from_bytes(blob)
        self.assertIsNone(restored.archive_proof_bundle)


# ---------------------------------------------------------------------------
# 4. Bundle tx_hash folds into merkle_root
# ---------------------------------------------------------------------------


class TestMerkleRootIncludesBundle(unittest.TestCase):
    def test_bundle_has_tx_hash_property(self):
        """ArchiveProofBundle must expose a tx_hash property for the
        same hygiene pattern every other block-body type uses.  Tx hash
        is a 32-byte commitment over the bundle's canonical bytes.
        """
        bundle = ArchiveProofBundle.from_proofs([_make_proof(1)])
        self.assertTrue(hasattr(bundle, "tx_hash"))
        self.assertEqual(len(bundle.tx_hash), 32)

    def test_block_merkle_root_changes_if_bundle_stripped(self):
        """A live chain block carrying custody_proofs has the bundle's
        tx_hash folded into its merkle_root.  If you strip the bundle
        (simulate a relayer attack) and recompute merkle_root from the
        remaining body, it differs from the block's header.
        """
        chain, alice, pos = _fresh_chain()
        proofs = [_make_proof(i + 1) for i in range(2)]
        block = _make_block_with_proofs(chain, alice, pos, proofs)
        # Reconstruct merkle_root WITHOUT the bundle's tx_hash.
        tx_hashes_no_bundle = (
            [tx.tx_hash for tx in block.transactions]
            + [p.tx_hash for p in block.custody_proofs]
        )
        root_no_bundle = (
            compute_merkle_root(tx_hashes_no_bundle)
            if tx_hashes_no_bundle else _h(b"empty")
        )
        # Actual header root is computed WITH the bundle.
        self.assertNotEqual(block.header.merkle_root, root_no_bundle)


# ---------------------------------------------------------------------------
# 5. Block validation rejects bundles that don't match custody_proofs
# ---------------------------------------------------------------------------


class TestValidationRejectsForgedBundle(unittest.TestCase):
    def test_add_block_rejects_mismatched_bundle(self):
        """If a proposer builds a block whose bundle does not equal
        ArchiveProofBundle.from_proofs(custody_proofs), the chain must
        reject it on submission.  This is the core derivation-integrity
        check that ensures the aggregated commitment is honest.
        """
        chain, alice, pos = _fresh_chain()
        proofs = [_make_proof(i + 1) for i in range(2)]
        block = _make_block_with_proofs(chain, alice, pos, proofs)
        # Tamper: replace the bundle with one built from different
        # prover_ids.  The block's merkle_root and signature are now
        # stale, but that's exactly what validation must detect.
        forged_proofs = [_make_proof(9), _make_proof(8)]
        block.archive_proof_bundle = ArchiveProofBundle.from_proofs(
            forged_proofs,
        )
        ok, reason = chain.add_block(block)
        self.assertFalse(
            ok, "tampered bundle must be rejected at add_block",
        )

    def test_add_block_rejects_missing_bundle_on_challenge_block(self):
        """If custody_proofs is non-empty but bundle is absent (None),
        reject — the derivation rule is 'if custody_proofs non-empty,
        bundle must be the derived one.'
        """
        chain, alice, pos = _fresh_chain()
        proofs = [_make_proof(i + 1) for i in range(2)]
        block = _make_block_with_proofs(chain, alice, pos, proofs)
        block.archive_proof_bundle = None
        ok, reason = chain.add_block(block)
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy_header():
    """Minimal BlockHeader for dataclass-only tests.

    These tests don't care about signatures or state roots — just that
    Block.__post_init__ interacts with the archive_proof_bundle field
    correctly.
    """
    import time
    from messagechain.core.block import BlockHeader
    return BlockHeader(
        version=1,
        block_number=1,
        prev_hash=b"\x00" * 32,
        merkle_root=_h(b"empty"),
        timestamp=int(time.time()),
        proposer_id=b"\xaa" * 32,
    )


if __name__ == "__main__":
    unittest.main()
