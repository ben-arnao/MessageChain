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
from messagechain.core.block import Block, canonical_block_tx_hashes
from messagechain.crypto.hashing import default_hash


def _hash(data: bytes) -> bytes:
    return default_hash(data)


# Cap on siblings.  A path for a tree with N leaves is at most
# ceil(log2(N)) levels deep.  At N = 2^30 (~1B leaves, well beyond
# any realistic block cap) the path is 30 levels.  64 gives generous
# headroom while preventing a malicious peer from pumping an unbounded
# proof through verify_merkle_proof.
_MAX_PROOF_SIBLINGS = 64


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
        tx_index = data["tx_index"]
        if not isinstance(tx_index, int) or isinstance(tx_index, bool):
            raise ValueError(f"tx_index must be int, got {type(tx_index).__name__}")
        if tx_index < 0:
            raise ValueError(f"tx_index must be non-negative, got {tx_index}")
        directions = data["directions"]
        if not isinstance(directions, list):
            raise ValueError("directions must be a list of bool")
        directions = [bool(d) for d in directions]
        siblings = [bytes.fromhex(s) for s in data["siblings"]]
        if len(siblings) != len(directions):
            raise ValueError(
                f"siblings/directions length mismatch: "
                f"{len(siblings)} vs {len(directions)}"
            )
        if len(siblings) > _MAX_PROOF_SIBLINGS:
            raise ValueError(
                f"proof too deep: {len(siblings)} siblings exceeds "
                f"cap {_MAX_PROOF_SIBLINGS}"
            )
        return cls(
            tx_hash=bytes.fromhex(data["tx_hash"]),
            tx_index=tx_index,
            siblings=siblings,
            directions=directions,
        )


def generate_merkle_proof(block: Block, tx_index: int) -> MerkleProof:
    """Generate a Merkle inclusion proof for a transaction in a block.

    Args:
        block: The block containing the transaction.
        tx_index: Index in the CANONICAL merkle-input ordering — the
            order that `canonical_block_tx_hashes(block)` produces.
            Covers message, transfer, slash, governance, authority,
            stake, unstake, finality_votes, custody_proofs,
            censorship_evidence, bogus_rejection_evidence, and
            archive_proof_bundle commitments.

    Returns:
        A MerkleProof that can verify the transaction's inclusion
        against the block header's merkle_root.

    Raises:
        IndexError: If tx_index is out of range.

    Note: prior versions built the tree from only `block.transactions
    + block.transfer_transactions`.  That produced proofs which did
    NOT verify against the real block merkle_root whenever the block
    contained any other commitment variant — a trap for future
    light-client / block-explorer integrations.  Routing through the
    canonical helper closes it.
    """
    tx_hashes = canonical_block_tx_hashes(block)
    if tx_index < 0 or tx_index >= len(tx_hashes):
        raise IndexError(
            f"tx_index {tx_index} out of range "
            f"(block has {len(tx_hashes)} merkle entries)"
        )

    tx_hash = tx_hashes[tx_index]

    # Build Merkle tree layer by layer, recording siblings.
    # Uses the same tagged-node construction as compute_merkle_root:
    #   - Leaves are tagged with b"\x00" prefix
    #   - Internal nodes are tagged with b"\x01" prefix
    #   - Odd-length layers are padded with _hash(b"\x02sentinel")
    siblings = []
    directions = []

    # Tag leaves with 0x00 prefix (matches compute_merkle_root)
    layer = [_hash(b"\x00" + h) for h in tx_hashes]
    idx = tx_index

    while len(layer) > 1:
        # Pad odd layers with sentinel (not duplicate)
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02sentinel"))

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
            # Tag internal nodes with 0x01 prefix
            combined = _hash(b"\x01" + layer[i] + layer[i + 1])
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
    # Validate proof structure: siblings and directions must match in length
    if len(proof.siblings) != len(proof.directions):
        return False
    # Bound the path length.  A real path for a tree with 2^30 leaves
    # is 30 siblings deep; we cap at 64.  Reject excessive proofs
    # before doing any hashing so an untrusted verifier call stays
    # cheap on malicious inputs.
    if len(proof.siblings) > _MAX_PROOF_SIBLINGS:
        return False
    # proof.tx_hash is metadata; the caller-supplied tx_hash argument
    # is authoritative.  Treat mismatch as invalid instead of silently
    # tolerating it — catches a wrapper that passes proof.tx_hash and
    # a divergent tx_hash argument.
    if proof.tx_hash != tx_hash:
        return False

    # Start from the tagged leaf (matches compute_merkle_root)
    current = _hash(b"\x00" + tx_hash)

    for sibling, is_left in zip(proof.siblings, proof.directions):
        if is_left:
            # Sibling is on the left
            current = _hash(b"\x01" + sibling + current)
        else:
            # Sibling is on the right
            current = _hash(b"\x01" + current + sibling)

    return current == merkle_root


def verify_spv_proof_with_header(
    tx_hash: bytes,
    proof: MerkleProof,
    block_header: "BlockHeader",
    header_signature_verifier=None,
) -> bool:
    """Full SPV verification: tx-in-block AND block header validity.

    Args:
        tx_hash: The transaction hash to verify.
        proof: The Merkle proof (siblings + directions).
        block_header: The block header containing the merkle_root.
        header_signature_verifier: Optional callable(header) -> bool that
            verifies the proposer's signature. If None, only Merkle
            inclusion is checked (no header authentication).

    Returns:
        True if the transaction is provably included in a valid block.
    """
    # Step 1: Verify Merkle inclusion
    if not verify_merkle_proof(tx_hash, proof, block_header.merkle_root):
        return False

    # Step 2: Verify block header signature (if verifier provided)
    if header_signature_verifier is not None:
        if not header_signature_verifier(block_header):
            return False

    return True
