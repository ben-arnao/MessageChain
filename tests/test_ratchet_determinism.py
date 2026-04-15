"""Bootstrap-progress ratchet is deterministic from chain history.

Earlier versions updated the ratchet as a side-effect of every
`bootstrap_progress` property access.  That made the ratchet's value
depend on "did anyone query it before the stake dropped" — a
non-chain-state signal.  Two nodes with identical chain history but
different query timing could see different progress values, compute
different attester committees, and diverge on state_root.

The fix:
  * Ratchet updates happen ONLY in `_apply_block_state`.
  * The property returns the stored max without any side effects.
  * DB persistence survives restart.

These tests pin the invariant:
  * Multiple reads don't change the value.
  * Replaying from genesis produces the same final ratchet on two
    independent Blockchain instances.
  * The observed max from chain replay never regresses — a stake
    decrease between blocks can't pull it down.
"""

import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from messagechain.config import TREASURY_ENTITY_ID


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=4)


class TestRatchetReadIdempotent(unittest.TestCase):
    """Reading `bootstrap_progress` many times must not mutate it.

    Prevents a class of bugs where the observation itself is a side
    effect: e.g. node A queries progress during a stake dip, node B
    queries after recovery, and they latch onto different values.
    """

    def test_many_reads_return_same_value(self):
        alice = _entity(b"a")
        chain = Blockchain()
        chain.initialize_genesis(alice)
        first = chain.bootstrap_progress
        for _ in range(100):
            self.assertEqual(chain.bootstrap_progress, first)

    def test_stake_change_between_reads_without_block_does_not_ratchet(self):
        """Mutating supply.staked directly should NOT move the ratchet —
        only block applies are allowed to change it.  Guards against a
        hot-path query pulling in uncommitted stake state."""
        alice = _entity(b"a")
        chain = Blockchain()
        chain.initialize_genesis(alice, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            alice.entity_id: 100_000,
        })
        initial = chain.bootstrap_progress
        # Raw mutation, NOT via a block apply — simulates an in-flight
        # tx or a buggy caller poking supply directly.
        bob = _entity(b"b")
        chain.supply.balances[bob.entity_id] = 1_000_000
        chain.supply.staked[bob.entity_id] = 500_000
        after = chain.bootstrap_progress
        # Ratchet must not have observed this non-block mutation.
        self.assertEqual(initial, after)


class TestRatchetDeterministicAcrossInstances(unittest.TestCase):
    """Two Blockchains that applied the same blocks have the same ratchet.

    This is the load-bearing consensus-safety invariant.  If it breaks,
    honest nodes fork on committee selection.
    """

    def _apply_n_empty_blocks(self, chain: Blockchain, proposer: Entity, n: int):
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        consensus.register_validator(proposer.entity_id, 100_000)
        chain.supply.stake(proposer.entity_id, 100_000)
        for _ in range(n):
            prev = chain.get_latest_block()
            block_height = prev.header.block_number + 1
            state_root = chain.compute_post_state_root(
                [], proposer.entity_id, block_height,
            )
            block = consensus.create_block(
                proposer, [], prev, state_root=state_root,
            )
            ok, reason = chain.add_block(block)
            if not ok:
                raise AssertionError(f"block add failed: {reason}")

    def test_two_chains_same_blocks_same_ratchet(self):
        """Parallel chains applying the same sequence get the same max."""
        # Chain A: built fresh
        a_genesis = _entity(b"a_gen")
        chain_a = Blockchain()
        chain_a.initialize_genesis(a_genesis, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            a_genesis.entity_id: 1_000_000,
        })
        self._apply_n_empty_blocks(chain_a, a_genesis, 5)

        # Chain B: identical build
        b_genesis = _entity(b"a_gen")  # same seed → same entity_id
        chain_b = Blockchain()
        chain_b.initialize_genesis(b_genesis, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            b_genesis.entity_id: 1_000_000,
        })
        self._apply_n_empty_blocks(chain_b, b_genesis, 5)

        # Invariant: same blocks in → same bootstrap_progress out.
        self.assertEqual(
            chain_a.bootstrap_progress, chain_b.bootstrap_progress,
        )


class TestRatchetMonotonic(unittest.TestCase):
    """Even if stake distribution fluctuates across blocks, progress
    never regresses.  This is what the ratchet exists for."""

    def test_stake_drop_does_not_regress_progress(self):
        """Apply a block with stake at peak, then a block with stake
        dropped — progress holds at the peak observed at block 1."""
        alice = _entity(b"a-mono")
        bob = _entity(b"b-mono")
        chain = Blockchain()
        chain.initialize_genesis(alice, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            alice.entity_id: 1_000_000,
        })

        # Stake bob heavily; ratchet should bump up as non-seed stake
        # becomes significant.
        chain.supply.balances[bob.entity_id] = 1_000_000
        chain.supply.stake(bob.entity_id, 900_000)
        # Apply a block to trigger ratchet update
        from messagechain.consensus.pos import ProofOfStake
        consensus = ProofOfStake()
        consensus.register_validator(alice.entity_id, 1_000_000)
        chain.supply.stake(alice.entity_id, 1_000_000)
        prev = chain.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = chain.compute_post_state_root(
            [], alice.entity_id, block_height,
        )
        block1 = consensus.create_block(
            alice, [], prev, state_root=state_root,
        )
        chain.add_block(block1)
        peak = chain.bootstrap_progress

        # Now simulate bob unstaking most of their holdings by direct
        # mutation — the ratchet must ignore this non-block mutation
        # path and hold peak.  (Real unstakes are block txs; this
        # simulates a malicious local node manipulating supply state.)
        chain.supply.staked[bob.entity_id] = 100
        self.assertEqual(chain.bootstrap_progress, peak)


if __name__ == "__main__":
    unittest.main()
