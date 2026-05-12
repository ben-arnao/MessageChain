"""ChainDB.get_block_by_number must return the canonical-chain block.

Audit r49 #1.  Pre-fix `get_block_by_number(h)` ran
``SELECT data FROM blocks WHERE block_number=? LIMIT 1`` with no
``ORDER BY`` and no join against ``chain_tips`` — when competing forks
coexisted in the blocks table at the same height, sqlite returned an
arbitrary sibling.  Docstring claimed "the one on the best chain"; the
SQL didn't enforce it.

Callers that walk ``range(tip_height + 1)`` to rebuild chain state
(``Blockchain._load_from_db``, ``integrity.reindex_state``,
``ChainDB._migrate_v1_to_v2`` / ``_migrate_v2_to_v3``, and the
``get_message_author`` tx-status path) could silently pick non-canonical
siblings after a reorg + restart — a chain-divergence vector against
honest validators.

This test stores two siblings at the same height, marks one as the
canonical chain tip, and asserts the lookup returns the canonical
sibling deterministically.  It also exercises the chain-tip-swap path:
after the tip flips to the other sibling, the same call must return
the now-canonical block.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.storage.chaindb import ChainDB


def _make_block(*, block_number: int, prev_hash: bytes, marker: bytes) -> Block:
    """Return a syntactically-valid empty Block with a deterministic hash.

    ``marker`` perturbs ``merkle_root`` so two blocks with the same
    ``prev_hash`` and ``block_number`` still get distinct block_hashes.
    No proposer signature is needed for the round-trip; ``to_bytes``
    handles a ``None`` signature.
    """
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=prev_hash,
        merkle_root=_hash(marker),
        timestamp=1_700_000_000.0 + block_number,
        proposer_id=b"\x00" * 32,
    )
    block = Block(header=header, transactions=[])
    block.block_hash = block._compute_hash()
    return block


class TestGetBlockByNumberCanonical(unittest.TestCase):

    def _fresh_db(self) -> tuple[ChainDB, str]:
        tmp = tempfile.mkdtemp(prefix="mc_r49_get_block_")
        return ChainDB(db_path=os.path.join(tmp, "chain.db")), tmp

    def test_returns_canonical_sibling_at_same_height(self):
        db, _tmp = self._fresh_db()
        try:
            genesis = _make_block(
                block_number=0, prev_hash=b"\x00" * 32, marker=b"genesis"
            )
            db.store_block(genesis)
            db.add_chain_tip(genesis.block_hash, 0, cumulative_stake=1)

            # Two competing siblings at height=1 chained to the same
            # genesis.  Distinct ``merkle_root`` produces distinct
            # block_hash; both are valid descendants of genesis.
            sibling_a = _make_block(
                block_number=1, prev_hash=genesis.block_hash, marker=b"sibling-A"
            )
            sibling_b = _make_block(
                block_number=1, prev_hash=genesis.block_hash, marker=b"sibling-B"
            )
            self.assertNotEqual(sibling_a.block_hash, sibling_b.block_hash)

            # Store A first, then B (insertion order is what the buggy
            # LIMIT-1 path returned).
            db.store_block(sibling_a)
            db.store_block(sibling_b)

            # B is the canonical tip (higher cumulative_stake).  Remove
            # the genesis tip so chain_tips reflects current best.
            db.remove_chain_tip(genesis.block_hash)
            db.add_chain_tip(sibling_a.block_hash, 1, cumulative_stake=10)
            db.add_chain_tip(sibling_b.block_hash, 1, cumulative_stake=20)

            # Pre-fix this returned whichever sibling sqlite picked
            # (insertion order => A).  Post-fix it must return B — the
            # one chain_tips identifies as canonical.
            got = db.get_block_by_number(1)
            self.assertIsNotNone(got)
            self.assertEqual(got.block_hash, sibling_b.block_hash)

            # And get_block_by_number(0) must still return genesis.
            got0 = db.get_block_by_number(0)
            self.assertIsNotNone(got0)
            self.assertEqual(got0.block_hash, genesis.block_hash)
        finally:
            db.close()

    def test_canonical_swap_after_tip_change(self):
        """When fork choice flips best_tip, the lookup must follow."""
        db, _tmp = self._fresh_db()
        try:
            genesis = _make_block(
                block_number=0, prev_hash=b"\x00" * 32, marker=b"genesis"
            )
            db.store_block(genesis)

            sib_a = _make_block(
                block_number=1, prev_hash=genesis.block_hash, marker=b"A"
            )
            sib_b = _make_block(
                block_number=1, prev_hash=genesis.block_hash, marker=b"B"
            )
            db.store_block(sib_a)
            db.store_block(sib_b)

            # Phase 1: A is canonical.
            db.add_chain_tip(sib_a.block_hash, 1, cumulative_stake=100)
            db.add_chain_tip(sib_b.block_hash, 1, cumulative_stake=50)
            self.assertEqual(
                db.get_block_by_number(1).block_hash, sib_a.block_hash
            )

            # Phase 2: fork choice swaps — B's tip overtakes.  Pre-fix
            # the lookup was insensitive to chain_tips so it would not
            # follow the swap.
            db.remove_chain_tip(sib_a.block_hash)
            db.add_chain_tip(sib_b.block_hash, 1, cumulative_stake=200)
            self.assertEqual(
                db.get_block_by_number(1).block_hash, sib_b.block_hash
            )

            # Phase 3: A overtakes again.
            db.add_chain_tip(sib_a.block_hash, 1, cumulative_stake=300)
            db.remove_chain_tip(sib_b.block_hash)
            self.assertEqual(
                db.get_block_by_number(1).block_hash, sib_a.block_hash
            )
        finally:
            db.close()

    def test_missing_height_returns_none(self):
        db, _tmp = self._fresh_db()
        try:
            genesis = _make_block(
                block_number=0, prev_hash=b"\x00" * 32, marker=b"genesis"
            )
            db.store_block(genesis)
            db.add_chain_tip(genesis.block_hash, 0, cumulative_stake=1)
            self.assertIsNone(db.get_block_by_number(42))
        finally:
            db.close()

    def test_no_tip_returns_none_for_non_genesis(self):
        """With no chain_tips entries the canonical map is empty, so
        even a stored block is not reachable via the canonical lookup.
        ``get_block_by_hash`` remains the unambiguous escape hatch."""
        db, _tmp = self._fresh_db()
        try:
            orphan = _make_block(
                block_number=5, prev_hash=b"\xff" * 32, marker=b"orphan"
            )
            db.store_block(orphan)
            # No chain_tips written.
            self.assertIsNone(db.get_block_by_number(5))
            # But get_block_by_hash still resolves it.
            self.assertIsNotNone(db.get_block_by_hash(orphan.block_hash))
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
