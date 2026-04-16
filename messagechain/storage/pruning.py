"""
Block pruning for MessageChain.

Problem: Storing every block forever is incompatible with the 1000-year
design goal. Full block data (transactions, signatures) grows unboundedly.

Solution: Prune old block transaction data while retaining headers.
Headers form a verifiable chain (each commits to prev_hash) and contain
the Merkle root and state root, enabling chain verification without
full transaction data. Recent blocks are kept in full for reorg safety.

This mirrors Bitcoin Core's pruning mode, where old block data is deleted
but the header chain and UTXO set are retained.
"""

from dataclasses import dataclass
from messagechain.config import MESSAGE_DEFAULT_TTL
from messagechain.core.block import Block, BlockHeader


@dataclass
class PrunedBlockRecord:
    """A block that has been pruned — only header retained."""
    header: BlockHeader
    block_hash: bytes
    is_pruned: bool = True


class BlockPruner:
    """Manages block pruning, keeping recent blocks and headers for old ones.

    Args:
        keep_recent: Number of recent blocks to keep in full (not pruned).
    """

    def __init__(self, keep_recent: int = MESSAGE_DEFAULT_TTL):
        self.keep_recent = keep_recent
        # block_number -> PrunedBlockRecord (headers of pruned blocks)
        self._pruned_headers: dict[int, PrunedBlockRecord] = {}

    def prune(self, chain, db=None) -> int:
        """Prune old blocks from the chain, retaining only headers.

        If a ChainDB instance is provided, block transaction data is actually
        deleted from SQLite and replaced with header-only records. This is
        essential for the 1000-year design goal — without it, storage grows
        without bound.

        Returns the number of blocks pruned.
        """
        chain_height = chain.height
        prune_up_to = chain_height - self.keep_recent

        if prune_up_to <= 0:
            return 0

        pruned_count = 0
        for i in range(prune_up_to):
            block = chain.get_block(i)
            if block is None:
                continue
            if i in self._pruned_headers:
                continue  # already pruned

            # Save header before pruning
            self._pruned_headers[i] = PrunedBlockRecord(
                header=block.header,
                block_hash=block.block_hash,
            )

            # Actually delete from SQLite if db is available.  `chain`
            # doubles as the entity-index registry state so the compact-
            # form on-disk block can be decoded to extract the header.
            if db is not None:
                db.prune_block_to_header(i, state=chain)

            pruned_count += 1

        return pruned_count

    def get_header(self, chain, block_number: int) -> BlockHeader | None:
        """Get a block header, whether pruned or not.

        For pruned blocks, returns the saved header.
        For unpruned blocks, returns the header from the full block.
        """
        # Check pruned headers first
        if block_number in self._pruned_headers:
            return self._pruned_headers[block_number].header

        # Fall back to full block
        block = chain.get_block(block_number)
        if block is not None:
            return block.header

        return None

    def is_pruned(self, block_number: int) -> bool:
        """Check if a block has been pruned."""
        return block_number in self._pruned_headers

    @property
    def pruned_count(self) -> int:
        return len(self._pruned_headers)
