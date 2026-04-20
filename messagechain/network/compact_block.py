"""
Compact block relay for MessageChain.

Problem: Sending full blocks over the network is bandwidth-intensive.
Most transactions in a new block are already in the receiver's mempool.

Solution: Send a compact block containing only the block header and
short transaction IDs. The receiver reconstructs the full block from
its mempool. If any transactions are missing, it requests just those.

This mirrors Bitcoin's BIP 152 compact block relay, which reduces
block propagation bandwidth by ~90%.
"""

import hashlib
from dataclasses import dataclass, field
from messagechain.config import HASH_ALGO
from messagechain.core.block import Block, BlockHeader
from messagechain.core.transaction import MessageTransaction


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _short_tx_id(tx_hash: bytes, nonce: bytes = b"") -> bytes:
    """Compute a 6-byte short ID for a transaction hash.

    Uses the first 6 bytes of hash(nonce || tx_hash) to create a
    compact identifier. Collision probability is negligible for
    typical block sizes (< 50 transactions).
    """
    return _hash(nonce + tx_hash)[:6]


@dataclass
class CompactBlock:
    """A compact representation of a block for efficient relay.

    Contains the full header but only short IDs for transactions.
    The receiver reconstructs full transactions from its mempool.
    """
    header: BlockHeader
    short_tx_ids: list[bytes] = field(default_factory=list)
    nonce: bytes = b""  # randomization to prevent short ID grinding
    block_hash: bytes = b""
    # Prefilled transactions the sender thinks the receiver might not have
    prefilled_txs: list[MessageTransaction] = field(default_factory=list)

    def serialize(self) -> dict:
        return {
            "header": self.header.serialize(),
            "short_tx_ids": [sid.hex() for sid in self.short_tx_ids],
            "nonce": self.nonce.hex(),
            "block_hash": self.block_hash.hex(),
            "prefilled_txs": [tx.serialize() for tx in self.prefilled_txs],
        }


def create_compact_block(block: Block) -> CompactBlock:
    """Create a compact block from a full block."""
    nonce = _hash(block.block_hash)[:8]  # per-block nonce

    short_ids = [_short_tx_id(tx.tx_hash, nonce) for tx in block.transactions]

    return CompactBlock(
        header=block.header,
        short_tx_ids=short_ids,
        nonce=nonce,
        block_hash=block.block_hash,
    )


def reconstruct_block(compact: CompactBlock, mempool) -> Block | None:
    """Reconstruct a full block from a compact block and mempool.

    Returns the full block if all transactions are found in the mempool,
    or None if any are missing.
    """
    # Build a lookup: short_id -> full transaction
    short_id_to_tx: dict[bytes, MessageTransaction] = {}
    for tx in mempool.pending.values():
        sid = _short_tx_id(tx.tx_hash, compact.nonce)
        short_id_to_tx[sid] = tx

    # Add prefilled transactions
    for tx in compact.prefilled_txs:
        sid = _short_tx_id(tx.tx_hash, compact.nonce)
        short_id_to_tx[sid] = tx

    # Reconstruct transaction list
    transactions = []
    for sid in compact.short_tx_ids:
        tx = short_id_to_tx.get(sid)
        if tx is None:
            return None  # missing transaction — need to request it
        transactions.append(tx)

    return Block(
        header=compact.header,
        transactions=transactions,
        block_hash=compact.block_hash,
    )
