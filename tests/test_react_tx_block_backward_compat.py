"""Regression test for the 1.19.1 wire-format backward-compat fix.

The 1.19.0 release added Tier 17 `react_transactions` to
`Block.from_bytes` UNCONDITIONALLY -- decoding a pre-Tier-17 blob
(every block already on disk pre-1.19.0) raised "Block blob
truncated" because the decoder ran off the end looking for a
non-existent `u32` count of react_transactions.

Crash trace seen on validator-1's first 1.19.0 startup:
    File "messagechain/core/blockchain.py", _load_from_db
    File "messagechain/storage/chaindb.py", get_block_by_number
    File "messagechain/core/block.py:1364", from_bytes
        react_transactions = dec_list(ReactTransaction)
    File "messagechain/core/block.py:1184", take
        raise ValueError("Block blob truncated")

The fix: detect end-of-blob (exactly 32 bytes remaining = the
trailing declared_hash and nothing else) and treat
react_transactions as `[]` without consuming any bytes.  This
preserves backward-compat for every existing block on disk while
keeping post-Tier-17 blocks decoded normally.
"""

from __future__ import annotations

import time
import unittest

from messagechain.identity.identity import Entity
from messagechain.core.block import Block, BlockHeader
import hashlib
from messagechain.config import HASH_ALGO


def _hb(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(seed: bytes, height: int = 4) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_minimal_block(proposer: Entity) -> Block:
    """Construct a minimal valid Block.  Mirrors the helper used by
    `tests/test_acks_observed_block_field.py`."""
    header = BlockHeader(
        version=1,
        block_number=1,
        prev_hash=b"\x00" * 32,
        merkle_root=_hb(b"empty"),
        timestamp=int(time.time()),
        proposer_id=proposer.entity_id,
    )
    header.proposer_signature = proposer.keypair.sign(
        _hb(header.signable_data())
    )
    blk = Block(
        header=header,
        transactions=[],
    )
    blk.block_hash = blk._compute_hash()
    return blk


class TestPreTier17BlobDecodes(unittest.TestCase):
    """A blob serialized BEFORE Tier 17 (i.e., without the trailing
    `react_transactions` u32 count) MUST still round-trip through
    Block.from_bytes.  The 1.19.0 release crashed on this case
    inside `_load_from_db` and took validator-1 down on first
    startup."""

    def test_strip_react_field_still_decodes(self):
        proposer = _entity(b"r1191-proposer")
        blk = _build_minimal_block(proposer)
        blob = blk.to_bytes()

        # Surgery: a 1.19.0+ encoder writes `u32(0)` for an empty
        # react_transactions list immediately before the trailing
        # 32-byte declared_hash.  Strip those 4 bytes to simulate a
        # pre-Tier-17 blob (a real on-disk block from 1.18.0 or
        # earlier).  declared_hash is computed over the header, not
        # the body, so it stays valid.
        # Layout at this point: [...body...] || u32(0) || 32B hash
        self.assertEqual(blob[-36:-32], b"\x00\x00\x00\x00",
            "1.19.0+ encoder must write u32(0) for empty "
            "react_transactions immediately before declared_hash")
        legacy_blob = blob[:-36] + blob[-32:]

        # Pre-fix: this raises "Block blob truncated" because
        # dec_list(ReactTransaction) tries to read a u32 count from
        # the 32-byte declared_hash bytes and then read more.
        # Post-fix: the end-of-blob shim sees `remaining == 32` and
        # treats react_transactions as [] without consuming bytes.
        decoded = Block.from_bytes(legacy_blob)
        self.assertEqual(
            decoded.react_transactions, [],
            "Pre-Tier-17 blob MUST decode with an empty "
            "react_transactions list -- otherwise existing on-disk "
            "blocks crash _load_from_db on node startup.",
        )
        self.assertEqual(decoded.header.block_number, 1)
        self.assertEqual(decoded.block_hash, blk.block_hash)

    def test_post_tier17_blob_with_empty_react_still_decodes(self):
        """Sanity: the canonical (post-fix) encode/decode round-trip
        with an empty react_transactions list still works.  Guards
        against the shim being too eager and short-circuiting the
        normal decode path."""
        proposer = _entity(b"r1191-proposer-2")
        blk = _build_minimal_block(proposer)
        blob = blk.to_bytes()
        decoded = Block.from_bytes(blob)
        self.assertEqual(decoded.react_transactions, [])
        self.assertEqual(decoded.block_hash, blk.block_hash)


if __name__ == "__main__":
    unittest.main()
