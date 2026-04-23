"""
Tests for the tightened block-header future-timestamp bound and the
proposer-side parent-timestamp clamp.

Background: at Bitcoin's 7200 s future tolerance a single adversarial
proposer could stamp a header up to 2 h ahead, and because every
subsequent block must have `timestamp > parent.timestamp`, every honest
proposer whose wall clock was less than 2 h fast would have their
block rejected — systematic slot denial by future-dating.

Fix (two parts):
  * `MAX_BLOCK_FUTURE_DRIFT` tightened to 120 s in `messagechain.config`
    so the adversary's maximum forward-skew per block is bounded by a
    single NTP-size margin instead of a dozen slots.
  * `ProofOfStake.create_block` clamps `timestamp = max(time.time(),
    parent.header.timestamp + 1)` so an honest proposer whose wall
    clock trails a future-dated parent still emits a block that passes
    the strict monotonicity check.
"""

import time
import unittest
from unittest.mock import patch

from messagechain.config import MAX_BLOCK_FUTURE_DRIFT, BLOCK_TIME_TARGET
from messagechain.core.block import Block, BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


class TestFutureDriftConstant(unittest.TestCase):
    def test_constant_is_tight(self):
        """Bound should be well under BLOCK_TIME_TARGET so a single
        future-dated block cannot deny many slots of honest proposers."""
        self.assertLess(MAX_BLOCK_FUTURE_DRIFT, BLOCK_TIME_TARGET)

    def test_constant_is_positive(self):
        self.assertGreater(MAX_BLOCK_FUTURE_DRIFT, 0)


class TestBlockFutureDriftRejection(unittest.TestCase):
    """A header whose timestamp exceeds wall-clock + MAX_BLOCK_FUTURE_DRIFT
    must be rejected — regardless of any other field being valid."""

    def test_block_beyond_new_bound_rejected(self):
        chain = Blockchain()
        alice = Entity.create(b"alice-future".ljust(32, b"\x00"))
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)

        header = BlockHeader(
            version=1, block_number=1,
            prev_hash=chain.chain[0].block_hash,
            merkle_root=_hash(b"empty"),
            # Well past the new bound but well under the legacy 7200 s
            # tolerance — would have been accepted pre-fix.
            timestamp=time.time() + MAX_BLOCK_FUTURE_DRIFT + 600,
            proposer_id=alice.entity_id,
            state_root=b"\x00" * 32,
        )
        header_hash = _hash(header.signable_data())
        header.proposer_signature = alice.keypair.sign(header_hash)
        block = Block(header=header, transactions=[])
        block.block_hash = block._compute_hash()

        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("future", reason)


class TestProposerClampAgainstFutureParent(unittest.TestCase):
    """If the parent header is future-dated (e.g., after the tightened
    bound was applied to an earlier run, or in a malicious setup), the
    honest proposer's create_block must still produce a block that
    satisfies `block.ts > parent.ts` — i.e., the timestamp is clamped
    up to parent + 1 rather than left at wall-clock."""

    def test_clamps_above_future_parent(self):
        alice = Entity.create(b"prop-future-clamp".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)
        consensus = ProofOfStake()

        # Simulate a parent that is ahead of this node's wall clock by
        # several seconds (within the new bound so the parent itself
        # could legally exist).  Honest proposer's wall clock sits on
        # `fake_now`, which is BEFORE parent.ts.
        fake_now = chain.chain[0].header.timestamp - 10
        # Rewrite genesis parent ts to sit just above fake_now so the
        # clamp must kick in.  Use an in-memory edit only — we're
        # asserting on create_block's picked timestamp, not persisting.
        chain.chain[0].header.timestamp = fake_now + 5

        latest = chain.get_latest_block()
        with patch("time.time", return_value=fake_now), \
             patch(
                 "messagechain.consensus.pos.time.time",
                 return_value=fake_now,
             ):
            block = consensus.create_block(
                alice, [], latest,
                state_root=chain.compute_post_state_root(
                    [], alice.entity_id, 1,
                ),
            )
        self.assertGreater(
            block.header.timestamp, latest.header.timestamp,
            "Proposer must clamp block.ts to parent.ts + 1 when wall "
            "clock trails the parent — otherwise the block fails the "
            "strict-monotonic timestamp check and the honest slot is "
            "silently forfeit.",
        )

    def test_explicit_timestamp_bypasses_clamp(self):
        """When a caller passes an explicit `timestamp=` kwarg, the
        clamp must NOT kick in — negative-path tests need to be able
        to construct invalid blocks on purpose."""
        alice = Entity.create(b"prop-explicit-ts".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)
        consensus = ProofOfStake()

        latest = chain.get_latest_block()
        too_early = latest.header.timestamp - 100
        block = consensus.create_block(
            alice, [], latest,
            state_root=chain.compute_post_state_root(
                [], alice.entity_id, 1,
            ),
            timestamp=too_early,
        )
        self.assertEqual(block.header.timestamp, too_early)


if __name__ == "__main__":
    unittest.main()
