"""
Compact block filters for MessageChain (BIP 157/158-inspired).

Enables privacy-preserving light client queries. Each block gets a compact
filter encoding which entity_ids transacted in it. Light clients download
filters, check locally if any match their entity_id, then request only
matching blocks.

Unlike BIP37 bloom filters (deprecated), these are:
- Server-computed and deterministic (no DoS vector)
- Client-checked locally (server doesn't learn what you're looking for)

Uses a Golomb-Rice coded set (GCS) approach simplified for entity_id matching.
"""

import hashlib
import struct
from dataclasses import dataclass

from messagechain.config import HASH_ALGO
from messagechain.core.block import Block


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


# GCS parameters (simplified)
GCS_P = 19  # false positive rate = 1/2^P ≈ 1 in 524,288
GCS_M_FACTOR = (1 << GCS_P)  # M = N * 2^P, where N = number of elements


def _siphash_mod(key: bytes, item: bytes, m: int) -> int:
    """Map an item to [0, m) using a keyed hash. Deterministic per block."""
    h = hashlib.new(HASH_ALGO, key + item).digest()
    val = int.from_bytes(h[:8], "big")
    return val % m


@dataclass
class BlockFilter:
    """A compact block filter for a single block."""
    block_hash: bytes
    filter_data: bytes  # encoded filter
    n_elements: int     # number of elements in the filter

    def match(self, entity_id: bytes) -> bool:
        """Check if an entity_id might be in this block.

        Returns True if the entity_id matches (may be false positive).
        Returns False if the entity_id is definitely not in this block.
        """
        if self.n_elements == 0:
            return False

        m = self.n_elements * GCS_M_FACTOR
        target = _siphash_mod(self.block_hash, entity_id, m)

        # Decode the sorted values and check for match
        values = _decode_gcs(self.filter_data, self.n_elements)
        return target in values

    def serialize(self) -> dict:
        return {
            "block_hash": self.block_hash.hex(),
            "filter_data": self.filter_data.hex(),
            "n_elements": self.n_elements,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "BlockFilter":
        return cls(
            block_hash=bytes.fromhex(data["block_hash"]),
            filter_data=bytes.fromhex(data["filter_data"]),
            n_elements=data["n_elements"],
        )


def create_block_filter(block: Block) -> BlockFilter:
    """Create a compact block filter for a block.

    The filter encodes the set of entity_ids that transacted in the block
    (message senders, transfer senders/recipients, proposer).
    """
    # Collect all entity_ids involved in this block
    entity_ids = set()

    for tx in block.transactions:
        entity_ids.add(tx.entity_id)

    for tx in block.transfer_transactions:
        entity_ids.add(tx.entity_id)
        entity_ids.add(tx.recipient_id)

    # Include proposer
    if block.header.proposer_id:
        entity_ids.add(block.header.proposer_id)

    if not entity_ids:
        return BlockFilter(
            block_hash=block.block_hash,
            filter_data=b"",
            n_elements=0,
        )

    n = len(entity_ids)
    m = n * GCS_M_FACTOR

    # Map each entity_id to [0, m) and sort
    values = sorted(_siphash_mod(block.block_hash, eid, m) for eid in entity_ids)

    # Encode as GCS (Golomb-Rice coded set)
    filter_data = _encode_gcs(values, n)

    return BlockFilter(
        block_hash=block.block_hash,
        filter_data=filter_data,
        n_elements=n,
    )


def compute_filter_header(filt: BlockFilter, prev_header: bytes) -> bytes:
    """Compute a filter header that chains to the previous filter header.

    This allows light clients to detect if a full node is providing fake
    filters by comparing headers from multiple peers.
    """
    filter_hash = _hash(filt.filter_data)
    return _hash(filter_hash + prev_header)


def _encode_gcs(sorted_values: list[int], n: int) -> bytes:
    """Encode sorted values as a simplified Golomb-Rice coded set.

    For simplicity, we store delta-encoded values as varint bytes.
    A production implementation would use proper Golomb-Rice coding.
    """
    if not sorted_values:
        return b""

    # Delta-encode: store differences between consecutive values
    deltas = [sorted_values[0]]
    for i in range(1, len(sorted_values)):
        deltas.append(sorted_values[i] - sorted_values[i - 1])

    # Encode deltas as varints
    parts = []
    for d in deltas:
        parts.append(_encode_varint(d))
    return b"".join(parts)


MAX_FILTER_ELEMENTS = 100_000  # safety cap for untrusted n_elements


def _decode_gcs(data: bytes, n: int) -> set[int]:
    """Decode a GCS back into a set of values."""
    if not data or n == 0:
        return set()
    # Cap n to prevent resource exhaustion from untrusted deserialization
    if n > MAX_FILTER_ELEMENTS:
        raise ValueError(f"n_elements {n} exceeds safety cap {MAX_FILTER_ELEMENTS}")

    values = []
    offset = 0
    cumulative = 0
    for _ in range(n):
        if offset >= len(data):
            break
        delta, bytes_read = _decode_varint(data, offset)
        cumulative += delta
        values.append(cumulative)
        offset += bytes_read

    return set(values)


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a variable-length integer."""
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


MAX_VARINT_BYTES = 10  # 10 bytes = 70 bits, enough for any reasonable value


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a varint from data at offset. Returns (value, bytes_consumed)."""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        if shift >= MAX_VARINT_BYTES * 7:
            raise ValueError("varint too long — possible memory exhaustion attack")
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, pos - offset
