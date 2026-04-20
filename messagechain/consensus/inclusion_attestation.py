"""Inclusion attestation — proposer mempool-snapshot accountability.

Each proposer embeds a Merkle root of their mempool's tx hashes in
the block header.  This creates cryptographic evidence of which txs
the proposer saw at proposal time.  If a tx appears in the snapshot
but not in the block (without a valid excuse), the evidence is on-chain
and cryptographically undeniable.

This is an audit layer — NOT auto-slash.  The proposer's mempool is
subjective (nodes see different txs at different times), so false
positives are possible.  Governance reviews evidence and decides.

The proposer's block signature already covers the snapshot root (it's
in signable_data), so no separate snapshot signature is needed.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

from messagechain.config import (
    HASH_ALGO,
    MAX_TXS_PER_ENTITY_PER_BLOCK,
)


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def compute_mempool_snapshot_root(tx_hashes: list[bytes]) -> bytes:
    """Compute a deterministic Merkle root from a list of tx hashes.

    The list is sorted before tree construction so order of insertion
    into the mempool doesn't matter — two nodes with the same set of
    txs produce the same root regardless of arrival order.

    Uses tagged nodes (0x00 for leaves, 0x01 for internal, 0x02 for
    sentinel padding) matching the block Merkle tree construction to
    prevent second-preimage attacks.

    Returns a 32-byte root.  Empty list produces hash(b"empty_mempool").
    """
    if not tx_hashes:
        return _hash(b"empty_mempool")

    sorted_hashes = sorted(tx_hashes)

    # Build tagged leaf layer
    layer = [_hash(b"\x00" + h) for h in sorted_hashes]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(b"\x01" + layer[i] + layer[i + 1])
            next_layer.append(combined)
        layer = next_layer

    return layer[0]


def prove_tx_in_snapshot(
    tx_hash: bytes,
    tx_hashes: list[bytes],
) -> "list[tuple[bytes, str]] | None":
    """Build a Merkle inclusion proof for tx_hash in the snapshot.

    Returns a list of (sibling_hash, side) pairs where side is 'L' or 'R',
    or None if tx_hash is not in tx_hashes (or tx_hashes is empty).

    The proof can be verified with verify_tx_in_snapshot.
    """
    if not tx_hashes:
        return None

    sorted_hashes = sorted(tx_hashes)

    if tx_hash not in sorted_hashes:
        return None

    target_idx = sorted_hashes.index(tx_hash)

    # Build the tree layer by layer, recording the proof path
    layer = [_hash(b"\x00" + h) for h in sorted_hashes]
    proof = []

    idx = target_idx
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(_hash(b"\x02sentinel"))
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = _hash(b"\x01" + layer[i] + layer[i + 1])
            next_layer.append(combined)
        # Record sibling
        if idx % 2 == 0:
            proof.append((layer[idx + 1], "R"))
        else:
            proof.append((layer[idx - 1], "L"))
        layer = next_layer
        idx //= 2

    return proof


def verify_tx_in_snapshot(
    tx_hash: bytes,
    proof: "list[tuple[bytes, str]]",
    snapshot_root: bytes,
) -> bool:
    """Verify a Merkle inclusion proof for tx_hash against snapshot_root.

    Returns True if the proof is valid.
    """
    current = _hash(b"\x00" + tx_hash)

    for sibling, side in proof:
        if side == "L":
            current = _hash(b"\x01" + sibling + current)
        else:
            current = _hash(b"\x01" + current + sibling)

    return current == snapshot_root


def check_proposer_censorship(
    mempool_tx_hashes: list[bytes],
    included_tx_hashes: set[bytes],
    block_byte_budget_remaining: int,
    block_tx_count_remaining: int,
    entity_counts: dict[bytes, int],
    tx_entity_map: dict[bytes, bytes],
    is_includable: Optional[Callable[[bytes], bool]] = None,
) -> list[bytes]:
    """Return tx_hashes that were in the proposer's declared mempool but
    not included, with no valid excuse.

    This produces censorship EVIDENCE for governance review, not
    automatic slashing.

    Valid excuses (matching forced_inclusion.py):
    - Block byte budget full (block_byte_budget_remaining <= 0)
    - Block tx count cap reached (block_tx_count_remaining <= 0)
    - Tx invalid at block time (is_includable returns False)
    - Per-entity cap reached

    Parameters:
        mempool_tx_hashes:          All tx hashes the proposer declared
                                    in their snapshot.
        included_tx_hashes:         Set of tx hashes actually in the block.
        block_byte_budget_remaining: Bytes remaining after included txs.
        block_tx_count_remaining:   Tx slots remaining after included txs.
        entity_counts:              {entity_id: count_in_block} for
                                    per-entity cap checking.
        tx_entity_map:              {tx_hash: entity_id} for the mempool
                                    txs (needed for per-entity cap).
        is_includable:              Optional callback. Called with tx_hash.
                                    Returns False if the tx is invalid at
                                    block time (nonce, balance, etc.).
    """
    if not mempool_tx_hashes:
        return []

    # Global structural excuses — if the block is full, all omissions
    # are excused.
    if block_byte_budget_remaining <= 0:
        return []
    if block_tx_count_remaining <= 0:
        return []

    evidence = []
    for tx_hash in mempool_tx_hashes:
        if tx_hash in included_tx_hashes:
            continue

        # Per-entity cap excuse
        entity = tx_entity_map.get(tx_hash)
        if entity is not None:
            if entity_counts.get(entity, 0) >= MAX_TXS_PER_ENTITY_PER_BLOCK:
                continue

        # Validity excuse
        if is_includable is not None and not is_includable(tx_hash):
            continue

        evidence.append(tx_hash)

    return evidence
