"""
Simplified Payment Verification (SPV) proofs for MessageChain.

Problem: Light clients can't download every block. They need a way to
verify that a specific transaction was included in a block using only
the block header (which contains the Merkle root).

Solution: Merkle inclusion proofs. Given a transaction hash and its
position in the block, generate the sibling hashes along the path
from the leaf to the root. A verifier can recompute the root from
the leaf + siblings and check it matches the header's Merkle root.

This is the same mechanism Bitcoin uses for SPV wallets (BIP 37).
"""

import hashlib
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO
from messagechain.core.block import Block


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


@dataclass
class MerkleProof:
    """A Merkle inclusion proof for a transaction.

    Fields:
        tx_hash: The hash of the transaction being proven.
        tx_index: The index of the transaction in the block.
        siblings: The sibling hashes along the path to the root.
        directions: For each sibling, whether it goes on the left (True)
                    or right (False) when combining.
    """
    tx_hash: bytes
    tx_index: int
    siblings: list[bytes] = field(default_factory=list)
    directions: list[bool] = field(default_factory=list)

    def serialize(self) -> dict:
        return {
            "tx_hash": self.tx_hash.hex(),
            "tx_index": self.tx_index,
            "siblings": [s.hex() for s in self.siblings],
            "directions": self.directions,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "MerkleProof":
        return cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            tx_index=data["tx_index"],
            siblings=[bytes.fromhex(s) for s in data["siblings"]],
            directions=data["directions"],
        )


def generate_merkle_proof(block: Block, tx_index: int) -> MerkleProof:
    """Generate a Merkle inclusion proof for a transaction in a block.

    Args:
        block: The block containing the transaction.
        tx_index: Index of the transaction in block.transactions.

    Returns:
        A MerkleProof that can verify the transaction's inclusion.

    Raises:
        IndexError: If tx_index is out of range.
    """
    all_txs = list(block.transactions) + list(block.transfer_transactions)
    if tx_index < 0 or tx_index >= len(all_txs):
        raise IndexError(f"tx_index {tx_index} out of range (block has {len(all_txs)} txs)")

    tx_hashes = [tx.tx_hash for tx in all_txs]
    tx_hash = tx_hashes[tx_index]

    # Build Merkle tree layer by layer, recording siblings
    siblings = []
    directions = []

    layer = list(tx_hashes)
    idx = tx_index

    while len(layer) > 1:
        # Pad to even
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        # Record sibling
        if idx % 2 == 0:
            # Our node is on the left; sibling is on the right
            sibling_idx = idx + 1
            directions.append(False)  # sibling goes on right
        else:
            # Our node is on the right; sibling is on the left
            sibling_idx = idx - 1
            directions.append(True)  # sibling goes on left

        siblings.append(layer[sibling_idx])

        # Build next layer
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(layer[i] + layer[i + 1])
            next_layer.append(combined)

        layer = next_layer
        idx = idx // 2

    return MerkleProof(
        tx_hash=tx_hash,
        tx_index=tx_index,
        siblings=siblings,
        directions=directions,
    )


def verify_merkle_proof(tx_hash: bytes, proof: MerkleProof, merkle_root: bytes) -> bool:
    """Verify a Merkle inclusion proof against a known Merkle root.

    Args:
        tx_hash: The transaction hash to verify.
        proof: The Merkle proof (siblings + directions).
        merkle_root: The expected Merkle root from the block header.

    Returns:
        True if the proof is valid (tx_hash is included in the tree).
    """
    current = tx_hash

    for sibling, is_left in zip(proof.siblings, proof.directions):
        if is_left:
            # Sibling is on the left
            current = _hash(sibling + current)
        else:
            # Sibling is on the right
            current = _hash(current + sibling)

    return current == merkle_root
