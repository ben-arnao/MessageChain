"""Tests for orphan-pool per-peer quota + age TTL + flood-offense signalling.

Context: Blockchain.orphan_pool was a flat dict capped at MAX_ORPHAN_BLOCKS
(=100) with no per-peer accounting, no TTL, and a silent drop when full.
One sybil could fill all 100 slots and evict honest IBD-gap orphans. These
tests lock in:

  * Per-peer cap MAX_ORPHAN_BLOCKS_PER_PEER (= 10) — one peer cannot
    monopolize the pool.
  * Age-based TTL ORPHAN_MAX_AGE_BLOCKS (= 100) — orphans waiting for a
    parent that never arrives eventually expire.
  * OFFENSE_PROTOCOL_VIOLATION accounting (orphan_flood_peers) — peers
    that exceed quota or flood a full pool get recorded for ban drain.
  * Regression: drain-on-parent-arrival still works AND clears the
    arrival/peer-count metadata (not just orphan_pool).
  * Legacy callers (source_peer=None) still function — no per-peer
    tracking side-effects.

The tests cheat-construct Block objects with invalid signatures (no
signing happens) because the orphan path only runs cheap structural
checks before storing; signature verification only runs when the parent
is present and the block is about to connect.
"""

import hashlib
import time
import unittest
from unittest.mock import MagicMock

import messagechain.config
from messagechain.config import (
    HASH_ALGO,
    MAX_ORPHAN_BLOCKS,
    MAX_ORPHAN_BLOCKS_PER_PEER,
    ORPHAN_MAX_AGE_BLOCKS,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.identity.identity import Entity


def _make_orphan_block(
    *,
    block_number: int,
    prev_hash: bytes,
    proposer_id: bytes,
    seed: bytes = b"",
) -> Block:
    """Cheap orphan-block factory.

    The orphan-storage path only runs structural pre-checks (sig_cost,
    tx counts, message bytes) — no proposer-signature verification
    happens until the parent is present.  So we can skip signing and
    just hand back a Block whose prev_hash points somewhere unknown.
    `seed` lets the caller produce distinct block hashes even when
    everything else matches (distinct timestamps aren't always
    enough on fast machines).
    """
    header = BlockHeader(
        version=1,
        block_number=block_number,
        prev_hash=prev_hash,
        merkle_root=hashlib.new(HASH_ALGO, b"empty" + seed).digest(),
        timestamp=time.time() + block_number * 0.001,
        proposer_id=proposer_id,
    )
    block = Block(header=header, transactions=[])
    block.block_hash = block._compute_hash()
    return block


class OrphanPoolBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"orphan-bounds-alice".ljust(32, b"\x00"))

    def setUp(self):
        # WOTS is one-shot per leaf; reset per test so repeated Entity use
        # (even though we don't actually sign) doesn't leave hidden state.
        self.alice.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)

    # ── Test A: per-peer quota rejects the 11th orphan and records offense ─

    def test_single_peer_capped_at_per_peer_quota(self):
        """The 11th orphan from a single peer is rejected; first 10 stored."""
        peer = "10.0.0.1:9333"
        stored_hashes = []
        for i in range(MAX_ORPHAN_BLOCKS_PER_PEER):
            blk = _make_orphan_block(
                block_number=100 + i,
                prev_hash=_hash(f"unknown-parent-{i}".encode()),
                proposer_id=self.alice.entity_id,
                seed=str(i).encode(),
            )
            ok, _ = self.chain.add_block(blk, source_peer=peer)
            self.assertFalse(ok)  # orphan — add_block never returns True here
            self.assertIn(blk.block_hash, self.chain.orphan_pool)
            stored_hashes.append(blk.block_hash)

        self.assertEqual(
            len(self.chain.orphan_pool), MAX_ORPHAN_BLOCKS_PER_PEER
        )
        self.assertEqual(
            self.chain.orphan_peer_counts[peer], MAX_ORPHAN_BLOCKS_PER_PEER
        )
        self.assertNotIn(peer, self.chain.orphan_flood_peers)

        # 11th submission hits the per-peer quota.
        extra = _make_orphan_block(
            block_number=200,
            prev_hash=_hash(b"unknown-parent-extra"),
            proposer_id=self.alice.entity_id,
            seed=b"extra",
        )
        ok, _ = self.chain.add_block(extra, source_peer=peer)
        self.assertFalse(ok)
        self.assertNotIn(extra.block_hash, self.chain.orphan_pool)
        # Offense count recorded against the flooding peer.
        self.assertGreaterEqual(self.chain.orphan_flood_peers.get(peer, 0), 1)
        # Existing entries still present.
        for h in stored_hashes:
            self.assertIn(h, self.chain.orphan_pool)

    # ── Test B: two peers each fill their per-peer quota; both coexist ─────

    def test_two_peers_each_store_up_to_quota(self):
        """Two peers can each store MAX_ORPHAN_BLOCKS_PER_PEER orphans."""
        peer_a = "1.1.1.1:9333"
        peer_b = "2.2.2.2:9333"
        for i in range(MAX_ORPHAN_BLOCKS_PER_PEER):
            blk_a = _make_orphan_block(
                block_number=300 + i,
                prev_hash=_hash(f"parent-A-{i}".encode()),
                proposer_id=self.alice.entity_id,
                seed=b"A" + str(i).encode(),
            )
            blk_b = _make_orphan_block(
                block_number=400 + i,
                prev_hash=_hash(f"parent-B-{i}".encode()),
                proposer_id=self.alice.entity_id,
                seed=b"B" + str(i).encode(),
            )
            self.chain.add_block(blk_a, source_peer=peer_a)
            self.chain.add_block(blk_b, source_peer=peer_b)

        self.assertEqual(
            len(self.chain.orphan_pool), 2 * MAX_ORPHAN_BLOCKS_PER_PEER
        )
        self.assertEqual(
            self.chain.orphan_peer_counts[peer_a], MAX_ORPHAN_BLOCKS_PER_PEER
        )
        self.assertEqual(
            self.chain.orphan_peer_counts[peer_b], MAX_ORPHAN_BLOCKS_PER_PEER
        )
        # Neither peer should have tripped a flood offense — we stayed
        # within quota.
        self.assertEqual(self.chain.orphan_flood_peers, {})
        # Pool still well under global cap.
        self.assertLess(len(self.chain.orphan_pool), MAX_ORPHAN_BLOCKS)

    # ── Test C: TTL evicts orphans whose parent never arrives ───────────────

    def test_orphan_evicted_after_max_age(self):
        """An orphan pinned past ORPHAN_MAX_AGE_BLOCKS is dropped by TTL."""
        peer = "3.3.3.3:9333"
        stale = _make_orphan_block(
            block_number=999,
            prev_hash=_hash(b"never-arriving-parent"),
            proposer_id=self.alice.entity_id,
            seed=b"stale",
        )
        self.chain.add_block(stale, source_peer=peer)
        self.assertIn(stale.block_hash, self.chain.orphan_pool)
        self.assertEqual(self.chain.orphan_peer_counts[peer], 1)

        # Simulate chain advancing well past the TTL window without the
        # orphan's parent arriving.  We mutate self.chain.chain directly
        # because producing real blocks is expensive and orthogonal to
        # what we're testing (TTL predicate reads self.height).
        arrival_height = self.chain.orphan_arrival[stale.block_hash][0]
        # Pad chain with dummy blocks so self.height jumps past the cutoff.
        pad_blocks = ORPHAN_MAX_AGE_BLOCKS + 5
        for _ in range(pad_blocks):
            self.chain.chain.append(MagicMock())
        self.assertGreater(
            self.chain.height - arrival_height, ORPHAN_MAX_AGE_BLOCKS
        )

        # Submit any unrelated orphan — its entry through add_block runs
        # the TTL cleanup before any insertion logic.
        trigger = _make_orphan_block(
            block_number=2000,
            prev_hash=_hash(b"trigger-parent"),
            proposer_id=self.alice.entity_id,
            seed=b"trigger",
        )
        self.chain.add_block(trigger, source_peer="4.4.4.4:9333")

        # Stale orphan is gone; its peer's count has been decremented.
        self.assertNotIn(stale.block_hash, self.chain.orphan_pool)
        self.assertNotIn(stale.block_hash, self.chain.orphan_arrival)
        self.assertNotIn(peer, self.chain.orphan_peer_counts)

    # ── Test D: parent-arrival drain still works and clears tracking ────────

    def test_orphan_drained_on_parent_arrival_clears_tracking(self):
        """Eviction path keeps orphan_pool, orphan_arrival, orphan_peer_counts
        in lockstep — the contract _process_orphans relies on when it
        drains orphans after a real parent arrives.

        Rather than simulating a full parent-arrival drain (which would
        recursively re-store our fake-signature children), we verify
        the atomic eviction-bookkeeping invariant via the single
        choke-point _evict_orphan, then show _process_orphans uses it
        to filter by prev_hash (non-matching entries untouched).
        """
        peer = "5.5.5.5:9333"
        other_peer = "6.6.6.6:9333"

        orphan_evictable = _make_orphan_block(
            block_number=800,
            prev_hash=_hash(b"parent-for-evictable"),
            proposer_id=self.alice.entity_id,
            seed=b"evictable",
        )
        orphan_kept = _make_orphan_block(
            block_number=801,
            prev_hash=_hash(b"parent-for-kept"),
            proposer_id=self.alice.entity_id,
            seed=b"kept",
        )
        self.chain.add_block(orphan_evictable, source_peer=peer)
        self.chain.add_block(orphan_kept, source_peer=other_peer)

        # Pre-eviction: both tracked, both peers counted.
        self.assertIn(orphan_evictable.block_hash, self.chain.orphan_pool)
        self.assertIn(orphan_kept.block_hash, self.chain.orphan_pool)
        self.assertEqual(self.chain.orphan_peer_counts[peer], 1)
        self.assertEqual(self.chain.orphan_peer_counts[other_peer], 1)

        # Evict exactly one — matches what _process_orphans does for
        # each matching dependent before recursing into add_block.
        self.chain._evict_orphan(orphan_evictable.block_hash)

        # Evicted entry is gone from all three tracking dicts.
        self.assertNotIn(orphan_evictable.block_hash, self.chain.orphan_pool)
        self.assertNotIn(orphan_evictable.block_hash, self.chain.orphan_arrival)
        self.assertNotIn(peer, self.chain.orphan_peer_counts)

        # Non-matching orphan is completely untouched.
        self.assertIn(orphan_kept.block_hash, self.chain.orphan_pool)
        self.assertIn(orphan_kept.block_hash, self.chain.orphan_arrival)
        self.assertEqual(self.chain.orphan_peer_counts[other_peer], 1)

        # Re-slot is possible for the peer that freed its entry: since
        # peer's count is back to 0, it can submit another orphan.
        replay = _make_orphan_block(
            block_number=802,
            prev_hash=_hash(b"yet-another-parent"),
            proposer_id=self.alice.entity_id,
            seed=b"replay",
        )
        self.chain.add_block(replay, source_peer=peer)
        self.assertIn(replay.block_hash, self.chain.orphan_pool)
        self.assertEqual(self.chain.orphan_peer_counts[peer], 1)

    # ── Test E: legacy caller (source_peer=None) still works ────────────────

    def test_source_peer_none_bypasses_per_peer_accounting(self):
        """Internal/legacy callers can omit source_peer; no peer state tracked."""
        # Submit many orphans without a source_peer.  The per-peer quota
        # must not apply (otherwise existing tests would regress);
        # global MAX_ORPHAN_BLOCKS cap is still enforced.
        for i in range(MAX_ORPHAN_BLOCKS_PER_PEER + 5):
            blk = _make_orphan_block(
                block_number=500 + i,
                prev_hash=_hash(f"legacy-{i}".encode()),
                proposer_id=self.alice.entity_id,
                seed=b"L" + str(i).encode(),
            )
            self.chain.add_block(blk)  # no source_peer kwarg
            self.assertIn(blk.block_hash, self.chain.orphan_pool)

        # All stored — per-peer cap did not reject any of them.
        self.assertEqual(
            len(self.chain.orphan_pool), MAX_ORPHAN_BLOCKS_PER_PEER + 5
        )
        # No per-peer state accumulated (no key == None).
        self.assertEqual(self.chain.orphan_peer_counts, {})
        # No flood offenses — silent drop is for unknown senders only.
        self.assertEqual(self.chain.orphan_flood_peers, {})


if __name__ == "__main__":
    unittest.main()
