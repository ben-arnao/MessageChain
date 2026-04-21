"""
Fork-choice cumulative weight must use per-block pinned stake snapshots,
not the live `supply.staked` dict.

Canonical path: in `add_block`, the additive cumulative weight is taken
at apply time (line ~6439) with the then-current stake map, then pinned
into `_stake_snapshots[block_number]`.  After ANY subsequent stake
change (stake tx, unstake, slash), a walk-back recomputation that reads
the live `supply.staked` for every ancestor disagrees with the stored
cumulative value.  Under the lex-smaller-hash tiebreak, two tips that
*should* differ in weight can end up numerically equal — and the one
with the smaller hash wins a spurious reorg.

These tests pin the correctness invariant: a walk-back recomputation
must equal the additive path's stored value, across any stake change.
"""

import hashlib
import time
import unittest

from messagechain.config import HASH_ALGO
from messagechain.consensus.fork_choice import compute_block_stake_weight
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.block import Block, BlockHeader
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _hash(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _entity(name: str) -> Entity:
    return Entity.create(f"{name}-privkey".encode().ljust(32, b"\x00"))


def _bootstrap_chain(proposer_stake: int = 100):
    """Genesis + staked proposer, returns (chain, proposer, pos)."""
    alice = _entity("alice")
    bob = _entity("bob")
    chain = Blockchain()
    chain.initialize_genesis(alice)
    register_entity_for_test(chain, bob)
    chain.supply.balances[alice.entity_id] = 1_000_000
    chain.supply.balances[bob.entity_id] = 1_000_000
    chain.supply.staked[alice.entity_id] = proposer_stake
    pos = ProofOfStake()
    pos.register_validator(alice.entity_id, stake_amount=proposer_stake)
    return chain, alice, bob, pos


class TestAdditiveCumulativeWeightStored(unittest.TestCase):
    """Test A: the additive path stores sum-of-proposer-stakes in tips."""

    def test_two_block_canonical_weight_equals_sum_of_stakes(self):
        chain, alice, bob, pos = _bootstrap_chain(proposer_stake=100)

        tx0 = create_transaction(bob, "m0", fee=1500, nonce=0)
        b1 = chain.propose_block(pos, alice, [tx0])
        ok, _ = chain.add_block(b1)
        self.assertTrue(ok)

        tx1 = create_transaction(bob, "m1", fee=1500, nonce=1)
        b2 = chain.propose_block(pos, alice, [tx1])
        ok, _ = chain.add_block(b2)
        self.assertTrue(ok)

        # Proposer had stake 100 when block 1 was applied and still 100
        # when block 2 was applied, so the stored cumulative weight is 200.
        _, stored_weight = chain.fork_choice.tips[b2.block_hash]
        self.assertEqual(stored_weight, 200)


class TestForkBlockUsesSnapshotNotLiveStake(unittest.TestCase):
    """Test B: a fork block's recomputed weight must use pinned snapshots.

    Without the fix, after a stake change the walk sees the *current*
    stakes for every ancestor and produces a historically-wrong number.
    """

    def test_fork_weight_reflects_stake_at_fork_height(self):
        chain, alice, bob, pos = _bootstrap_chain(proposer_stake=100)
        genesis = chain.get_latest_block()

        # Build canonical blocks 1 and 2 (both proposed by alice, stake 100).
        tx0 = create_transaction(bob, "m0", fee=1500, nonce=0)
        b1 = chain.propose_block(pos, alice, [tx0])
        self.assertTrue(chain.add_block(b1)[0])

        tx1 = create_transaction(bob, "m1", fee=1500, nonce=1)
        b2 = chain.propose_block(pos, alice, [tx1])
        self.assertTrue(chain.add_block(b2)[0])

        # Now a new entity Y appears with a fat stake.  At the fork
        # heights (1 and 2) Y had nothing.  The pinned snapshots at
        # heights 1 and 2 therefore show Y at 0.
        yolanda = _entity("yolanda")
        register_entity_for_test(chain, yolanda)
        chain.supply.balances[yolanda.entity_id] = 1_000_000
        chain.supply.staked[yolanda.entity_id] = 500

        # Construct a lightweight fork block at height 1, proposed by Y,
        # pointing at genesis.  We don't need a valid signature for
        # `_compute_cumulative_weight` — it only reads prev_hash,
        # block_number, and proposer_id while walking.
        fork_header = BlockHeader(
            version=1,
            block_number=1,
            prev_hash=genesis.block_hash,
            merkle_root=_hash(b"fork"),
            timestamp=time.time(),
            proposer_id=yolanda.entity_id,
        )
        fork_block = Block(header=fork_header, transactions=[])
        fork_block.block_hash = fork_block._compute_hash()
        chain._block_by_hash[fork_block.block_hash] = fork_block

        # With the fix: the walk consults _stake_snapshots[1].  But the
        # fork block itself (height 1) wasn't applied, so there's no
        # pinned snapshot for *this* block — the only snapshot at height
        # 1 is the canonical one, which shows Y at 0.  Either way the
        # correct weight is bounded by Y's historical stake (0 -> floor 1),
        # NOT Y's current 500.
        weight = chain._compute_cumulative_weight(fork_block)
        self.assertLess(
            weight, 500,
            "Fork weight must NOT be computed against live stakes — "
            "a brand-new staker at height 0 would otherwise get credit "
            "for stake they didn't have, letting them force a reorg.",
        )
        self.assertEqual(
            weight, 1,
            "Y had 0 stake at fork height — bootstrap floor gives weight 1.",
        )


class TestRecomputeMatchesStoredAcrossStakeChange(unittest.TestCase):
    """Test C: recomputed weight (walk-back) == additive stored weight.

    For every tip, across a block sequence that includes a stake change.
    This is the core consistency invariant — if it fails, the fork
    choice sees different numbers depending on which path computed them.
    """

    def test_walk_back_matches_stored_after_stake_change(self):
        chain, alice, bob, pos = _bootstrap_chain(proposer_stake=100)

        # Block 1: proposer stake 100 at apply time.
        tx0 = create_transaction(bob, "m0", fee=1500, nonce=0)
        b1 = chain.propose_block(pos, alice, [tx0])
        self.assertTrue(chain.add_block(b1)[0])

        # Mutate stake AFTER block 1 is pinned — simulates a stake
        # change that would only take effect from block 2 onwards.
        chain.supply.staked[alice.entity_id] = 300
        pos.register_validator(alice.entity_id, stake_amount=300)

        # Block 2: proposer stake is now 300.
        tx1 = create_transaction(bob, "m1", fee=1500, nonce=1)
        b2 = chain.propose_block(pos, alice, [tx1])
        self.assertTrue(chain.add_block(b2)[0])

        # Mutate again AFTER block 2 — this is the attack surface: a
        # walk-back that reads the current dict would count this new
        # value against block 1 and block 2 both, when in fact each
        # block was applied under its own pinned stake.
        chain.supply.staked[alice.entity_id] = 700

        # For every tip, recomputed weight must equal the stored value.
        for tip_hash, (_, stored_weight) in list(chain.fork_choice.tips.items()):
            tip_block = chain.get_block_by_hash(tip_hash)
            self.assertIsNotNone(tip_block)
            recomputed = chain._compute_cumulative_weight(tip_block)
            self.assertEqual(
                recomputed, stored_weight,
                f"Walk-back recomputation diverged from additive stored "
                f"weight at tip {tip_hash.hex()[:16]} "
                f"(stored={stored_weight}, recomputed={recomputed}) — "
                f"this is the spurious-reorg bug.",
            )


if __name__ == "__main__":
    unittest.main()
