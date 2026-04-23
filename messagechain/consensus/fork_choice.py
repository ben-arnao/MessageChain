"""
Fork choice rule and chain reorganization for MessageChain.

Inspired by Bitcoin's longest-chain rule, adapted for Proof-of-Stake:
- Bitcoin picks the chain with the most cumulative proof-of-work
- We pick the chain with the most cumulative stake weight

When a fork is detected (two blocks at the same height with different hashes),
we compare cumulative stake weight. If a competing chain has more weight,
we reorganize: roll back our current tip, replay the better chain.

Reorg safety:
- Finalized blocks (2/3+ attestations) cannot be reverted — finality boundary
- State snapshots are taken before reorg so we can roll back if the new
  chain fails validation
- Deep reorgs (beyond MAX_REORG_DEPTH) are rejected to prevent long-range attacks
"""

import hashlib
import logging

from messagechain.config import HASH_ALGO
from messagechain.core.block import Block
from messagechain.crypto.hashing import default_hash

logger = logging.getLogger(__name__)

MAX_REORG_DEPTH = 100  # reject reorgs deeper than this (long-range attack protection)


def _hash(data: bytes) -> bytes:
    return default_hash(data)


def compute_block_stake_weight(block: Block, stakes: dict[bytes, int]) -> int:
    """
    Compute the stake weight contributed by this block.

    Weight = proposer's stake at time of proposal. This makes chains
    proposed by heavily-staked validators "heavier" — analogous to
    Bitcoin's cumulative PoW.
    """
    proposer_stake = stakes.get(block.header.proposer_id, 0)
    # Minimum weight of 1 so blocks always add some weight (bootstrap mode)
    return max(1, proposer_stake)


class ForkChoice:
    """
    Manages chain tips and selects the canonical chain.

    Tracks all known chain tips (leaf blocks with no known children).
    The "best" tip is the one with the highest cumulative stake weight.
    """

    def __init__(self):
        # tip_hash -> (block_number, cumulative_weight)
        self.tips: dict[bytes, tuple[int, int]] = {}

    def add_tip(self, block_hash: bytes, block_number: int, cumulative_weight: int):
        self.tips[block_hash] = (block_number, cumulative_weight)

    def remove_tip(self, block_hash: bytes):
        self.tips.pop(block_hash, None)

    def get_best_tip(self) -> tuple[bytes, int, int] | None:
        """Return (hash, height, weight) of the best chain tip."""
        if not self.tips:
            return None
        # Tie-break on lex-smaller tip hash, not height: grinding the hash
        # costs a full proposer signature per attempt, so an attacker can't
        # cheaply produce an equal-weight longer fork to force a reorg.
        best_hash = max(
            self.tips,
            key=lambda h: (self.tips[h][1], tuple(255 - b for b in h)),
        )
        height, weight = self.tips[best_hash]
        return (best_hash, height, weight)

    def is_better_chain(
        self,
        new_weight: int,
        new_height: int,
        new_tip_hash: bytes | None = None,
    ) -> bool:
        """Check if a chain with given weight/tip-hash beats our current best.

        Height is retained in the signature for call-site compatibility but
        is NOT used in tie-breaking (see get_best_tip for rationale).
        """
        best = self.get_best_tip()
        if best is None:
            return True
        cur_hash, _, cur_weight = best
        if new_weight > cur_weight:
            return True
        if new_weight == cur_weight and new_tip_hash is not None and new_tip_hash < cur_hash:
            return True
        return False


def find_common_ancestor(
    chain_a_tip: bytes,
    chain_b_tip: bytes,
    get_block: callable,
    finalized_hashes: set[bytes] | None = None,
) -> tuple[bytes | None, list[Block], list[Block]]:
    """
    Find the common ancestor of two chain tips.

    Returns:
        (ancestor_hash, blocks_to_rollback, blocks_to_apply)
        - blocks_to_rollback: blocks on chain_a after the ancestor (current chain)
        - blocks_to_apply: blocks on chain_b after the ancestor (new chain)
    """
    # Collect ancestors of both chains
    chain_a_blocks = []
    chain_b_blocks = []
    a_hashes = set()
    b_hashes = set()

    a_hash = chain_a_tip
    b_hash = chain_b_tip

    # Walk both chains back simultaneously
    a_block = get_block(a_hash)
    b_block = get_block(b_hash)

    if a_block is None or b_block is None:
        return None, [], []

    depth = 0
    while depth < MAX_REORG_DEPTH:
        if a_hash == b_hash:
            # Found common ancestor
            return a_hash, chain_a_blocks, chain_b_blocks

        # H3: Reject reorgs past finalized blocks. If any block we would
        # roll back is finalized, the reorg is invalid.
        if finalized_hashes:
            for blk in chain_a_blocks:
                if blk.block_hash in finalized_hashes:
                    logger.warning(
                        f"Reorg rejected: would roll back finalized block "
                        f"{blk.block_hash.hex()[:16]} at height {blk.header.block_number}"
                    )
                    return None, [], []

        # Check if a's current hash is in b's history
        if a_hash in b_hashes:
            # a_hash is the ancestor — rebuild b's list to only include
            # blocks after the ancestor, connected by prev_hash linkage
            trimmed = []
            for blk in chain_b_blocks:
                if blk.header.prev_hash == a_hash or (trimmed and trimmed[-1].block_hash == blk.header.prev_hash):
                    trimmed.append(blk)
            return a_hash, chain_a_blocks, trimmed

        if b_hash in a_hashes:
            # b_hash is the ancestor — rebuild a's list similarly
            trimmed = []
            for blk in chain_a_blocks:
                if blk.header.prev_hash == b_hash or (trimmed and trimmed[-1].block_hash == blk.header.prev_hash):
                    trimmed.append(blk)
            return b_hash, trimmed, chain_b_blocks

        a_hashes.add(a_hash)
        b_hashes.add(b_hash)

        if a_block:
            chain_a_blocks.insert(0, a_block)
            a_hash = a_block.header.prev_hash
            a_block = get_block(a_hash) if a_hash != b"\x00" * 32 else None

        if b_block:
            chain_b_blocks.insert(0, b_block)
            b_hash = b_block.header.prev_hash
            b_block = get_block(b_hash) if b_hash != b"\x00" * 32 else None

        depth += 1

    logger.warning(f"Reorg depth exceeded {MAX_REORG_DEPTH} — rejecting (long-range attack protection)")
    return None, [], []


def find_fork_point(
    our_tip: bytes,
    their_tip: bytes,
    get_block: callable,
) -> tuple[bytes | None, list[Block], list[Block]]:
    """
    Higher-level wrapper for find_common_ancestor.

    Returns (fork_point_hash, rollback_blocks, apply_blocks) or
    (None, [], []) if no common ancestor found within MAX_REORG_DEPTH.
    """
    ancestor, rollback, apply_ = find_common_ancestor(our_tip, their_tip, get_block)
    if ancestor is None:
        logger.warning("No common ancestor found — chains are incompatible or reorg too deep")
    else:
        logger.info(
            f"Fork point: {ancestor.hex()[:16]} | "
            f"rollback {len(rollback)} blocks, apply {len(apply_)} blocks"
        )
    return ancestor, rollback, apply_
