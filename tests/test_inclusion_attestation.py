"""Tests for the inclusion-attestation censorship-accountability layer.

The proposer signs a commitment to their mempool state (the Merkle root
of sorted tx hashes) and embeds it in the block header.  This creates
cryptographic evidence of which txs the proposer saw at proposal time.

These tests are audit-layer only — no auto-slashing.  The proposer's
mempool is subjective, so governance reviews evidence and decides.
"""

import hashlib
import unittest

from messagechain.config import (
    HASH_ALGO,
    MAX_BLOCK_MESSAGE_BYTES,
    MAX_TXS_PER_BLOCK,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
)
from messagechain.consensus.inclusion_attestation import (
    compute_mempool_snapshot_root,
    prove_tx_in_snapshot,
    verify_tx_in_snapshot,
    check_proposer_censorship,
)
from messagechain.core.block import BlockHeader, Block


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


class TestMempoolSnapshotRoot(unittest.TestCase):
    """compute_mempool_snapshot_root: deterministic Merkle commitment."""

    def test_deterministic_same_input(self):
        """Same mempool produces the same root every time."""
        hashes = [_hash(i.to_bytes(4, "big")) for i in range(5)]
        root1 = compute_mempool_snapshot_root(hashes)
        root2 = compute_mempool_snapshot_root(hashes)
        self.assertEqual(root1, root2)

    def test_different_mempool_different_root(self):
        """Different mempools produce different roots."""
        hashes_a = [_hash(i.to_bytes(4, "big")) for i in range(5)]
        hashes_b = [_hash(i.to_bytes(4, "big")) for i in range(3)]
        root_a = compute_mempool_snapshot_root(hashes_a)
        root_b = compute_mempool_snapshot_root(hashes_b)
        self.assertNotEqual(root_a, root_b)

    def test_empty_mempool_well_defined(self):
        """Empty mempool has a well-defined root (not crash)."""
        root = compute_mempool_snapshot_root([])
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)

    def test_order_independent(self):
        """Root is order-independent — internally sorted."""
        h1 = _hash(b"tx1")
        h2 = _hash(b"tx2")
        root_forward = compute_mempool_snapshot_root([h1, h2])
        root_reverse = compute_mempool_snapshot_root([h2, h1])
        self.assertEqual(root_forward, root_reverse)

    def test_single_tx(self):
        """Single tx produces a 32-byte root."""
        h = _hash(b"only_tx")
        root = compute_mempool_snapshot_root([h])
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)


class TestBlockHeaderSnapshotField(unittest.TestCase):
    """BlockHeader includes mempool_snapshot_root in signable_data."""

    def _make_header(self, snapshot_root=b"\x00" * 32):
        return BlockHeader(
            version=1,
            block_number=1,
            prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32,
            timestamp=1000.0,
            proposer_id=b"\x01" * 32,
            mempool_snapshot_root=snapshot_root,
        )

    def test_field_present(self):
        """BlockHeader has mempool_snapshot_root field."""
        hdr = self._make_header(b"\xaa" * 32)
        self.assertEqual(hdr.mempool_snapshot_root, b"\xaa" * 32)

    def test_default_is_zero(self):
        """Default snapshot root is 32 zero bytes."""
        hdr = BlockHeader(
            version=1, block_number=1, prev_hash=b"\x00" * 32,
            merkle_root=b"\x00" * 32, timestamp=1000.0,
            proposer_id=b"\x01" * 32,
        )
        self.assertEqual(hdr.mempool_snapshot_root, b"\x00" * 32)

    def test_in_signable_data_tampering_changes_hash(self):
        """Changing mempool_snapshot_root changes signable_data (hence block_hash)."""
        hdr_a = self._make_header(b"\x00" * 32)
        hdr_b = self._make_header(b"\xff" * 32)
        self.assertNotEqual(hdr_a.signable_data(), hdr_b.signable_data())

    def test_serialize_deserialize_roundtrip(self):
        """Dict serialization round-trips the snapshot_root."""
        hdr = self._make_header(b"\xab" * 32)
        d = hdr.serialize()
        hdr2 = BlockHeader.deserialize(d)
        self.assertEqual(hdr2.mempool_snapshot_root, b"\xab" * 32)

    def test_to_bytes_from_bytes_roundtrip(self):
        """Binary serialization round-trips the snapshot_root."""
        hdr = self._make_header(b"\xcd" * 32)
        blob = hdr.to_bytes()
        hdr2 = BlockHeader.from_bytes(blob)
        self.assertEqual(hdr2.mempool_snapshot_root, b"\xcd" * 32)


class TestMerkleProof(unittest.TestCase):
    """Merkle inclusion proofs for auditing the snapshot."""

    def test_proof_for_included_tx(self):
        """Prove a tx IS in the snapshot."""
        tx_hashes = [_hash(i.to_bytes(4, "big")) for i in range(8)]
        root = compute_mempool_snapshot_root(tx_hashes)
        target = tx_hashes[3]
        proof = prove_tx_in_snapshot(target, tx_hashes)
        self.assertTrue(verify_tx_in_snapshot(target, proof, root))

    def test_proof_for_excluded_tx_fails(self):
        """Proof for a tx NOT in the snapshot fails verification."""
        tx_hashes = [_hash(i.to_bytes(4, "big")) for i in range(8)]
        root = compute_mempool_snapshot_root(tx_hashes)
        outsider = _hash(b"not_in_mempool")
        # Can't even build a valid proof for an outsider
        proof = prove_tx_in_snapshot(outsider, tx_hashes)
        self.assertIsNone(proof)

    def test_proof_single_element(self):
        """Proof works when mempool has a single tx."""
        h = _hash(b"solo")
        root = compute_mempool_snapshot_root([h])
        proof = prove_tx_in_snapshot(h, [h])
        self.assertTrue(verify_tx_in_snapshot(h, proof, root))

    def test_proof_tampered_hash_fails(self):
        """Altering the tx_hash makes the proof fail."""
        tx_hashes = [_hash(i.to_bytes(4, "big")) for i in range(4)]
        root = compute_mempool_snapshot_root(tx_hashes)
        target = tx_hashes[1]
        proof = prove_tx_in_snapshot(target, tx_hashes)
        self.assertTrue(verify_tx_in_snapshot(target, proof, root))
        tampered = _hash(b"tampered")
        self.assertFalse(verify_tx_in_snapshot(tampered, proof, root))

    def test_proof_empty_mempool(self):
        """No proof possible for empty mempool."""
        proof = prove_tx_in_snapshot(_hash(b"x"), [])
        self.assertIsNone(proof)


class TestCheckProposerCensorship(unittest.TestCase):
    """check_proposer_censorship: identifies omitted-but-seen txs."""

    def test_identifies_omitted_txs(self):
        """Txs in snapshot but not in block (no excuse) are flagged."""
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(5)]
        included = set(all_hashes[:3])
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts={},
            tx_entity_map={},
            is_includable=None,
        )
        self.assertEqual(set(omitted), set(all_hashes[3:]))

    def test_excuses_when_block_full_by_bytes(self):
        """Txs excused when block byte budget is exhausted."""
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(5)]
        included = set(all_hashes[:3])
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=0,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts={},
            tx_entity_map={},
            is_includable=None,
        )
        self.assertEqual(omitted, [])

    def test_excuses_when_block_full_by_count(self):
        """Txs excused when block tx count cap reached."""
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(5)]
        included = set(all_hashes[:3])
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=0,
            entity_counts={},
            tx_entity_map={},
            is_includable=None,
        )
        self.assertEqual(omitted, [])

    def test_excuses_per_entity_cap(self):
        """Txs excused when per-entity cap is reached."""
        entity = b"\x01" * 32
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(3)]
        included = set(all_hashes[:1])
        # The omitted txs belong to an entity already at cap
        tx_entity_map = {h: entity for h in all_hashes}
        entity_counts = {entity: MAX_TXS_PER_ENTITY_PER_BLOCK}
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts=entity_counts,
            tx_entity_map=tx_entity_map,
            is_includable=None,
        )
        self.assertEqual(omitted, [])

    def test_excuses_invalid_tx(self):
        """Txs excused when is_includable says they're invalid."""
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(3)]
        included = set(all_hashes[:1])
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts={},
            tx_entity_map={},
            is_includable=lambda h: False,  # all invalid
        )
        self.assertEqual(omitted, [])

    def test_all_included_no_evidence(self):
        """If all mempool txs are included, no censorship evidence."""
        all_hashes = [_hash(i.to_bytes(4, "big")) for i in range(3)]
        included = set(all_hashes)
        omitted = check_proposer_censorship(
            mempool_tx_hashes=all_hashes,
            included_tx_hashes=included,
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts={},
            tx_entity_map={},
            is_includable=None,
        )
        self.assertEqual(omitted, [])

    def test_empty_mempool_no_evidence(self):
        """Empty mempool produces no evidence."""
        omitted = check_proposer_censorship(
            mempool_tx_hashes=[],
            included_tx_hashes=set(),
            block_byte_budget_remaining=MAX_BLOCK_MESSAGE_BYTES,
            block_tx_count_remaining=MAX_TXS_PER_BLOCK,
            entity_counts={},
            tx_entity_map={},
            is_includable=None,
        )
        self.assertEqual(omitted, [])


class TestProposerBlockBuildingFlow(unittest.TestCase):
    """Integration: proposer computes snapshot root during block building."""

    def _make_chain(self):
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity
        from messagechain.config import VALIDATOR_MIN_STAKE
        from tests import register_entity_for_test

        proposer = Entity.create(b"proposer_seed_key_______________")
        chain = Blockchain()
        chain.initialize_genesis(proposer)
        consensus = ProofOfStake()
        chain.supply.balances[proposer.entity_id] = chain.supply.balances.get(proposer.entity_id, 0) + 5000
        chain.supply.stake(proposer.entity_id, VALIDATOR_MIN_STAKE)
        consensus.stakes[proposer.entity_id] = VALIDATOR_MIN_STAKE
        return chain, consensus, proposer

    def test_snapshot_root_computed_and_in_header(self):
        """propose_block includes a non-zero snapshot root when mempool is non-empty."""
        chain, consensus, proposer = self._make_chain()

        # Create a dummy tx hash for the mempool
        fake_tx_hash = _hash(b"some_pending_transaction")

        block = chain.propose_block(
            consensus, proposer, [],
            mempool_tx_hashes=[fake_tx_hash],
        )
        self.assertNotEqual(block.header.mempool_snapshot_root, b"\x00" * 32)

    def test_empty_mempool_zero_snapshot_root(self):
        """propose_block with no mempool_tx_hashes keeps zero snapshot root."""
        chain, consensus, proposer = self._make_chain()

        block = chain.propose_block(consensus, proposer, [])
        # No mempool provided → zero snapshot root
        self.assertEqual(block.header.mempool_snapshot_root, b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
