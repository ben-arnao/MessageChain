"""Supply invariant: total_supply == genesis + total_minted - total_burned.

Two coupled concerns:

  1. **Lottery bug (R8-#2 CRITICAL).**  The bootstrap-era lottery
     credits ``bounty`` tokens to the winner's balance and bumps
     ``total_supply`` but previously forgot to bump ``total_minted``.
     Every ``LOTTERY_INTERVAL`` blocks the invariant
     ``total_supply == GENESIS_SUPPLY + total_minted - total_burned``
     drifted by one bounty — silent corruption, accumulating unbounded.

  2. **No post-block invariant check (R8-#3 HIGH).**  Because
     ``_apply_block_state`` never asserted the invariant, the drift
     was invisible.  Adding the assertion catches this class of bug
     at block-apply time instead of at an eventual audit.

Tests:
  * ``Test A`` (lottery reproducer): run the chain long enough to fire
    the lottery.  Invariant must hold afterwards.  Pre-fix this
    FAILS (drift == bounty).
  * ``Test B`` (invariant catches drift): monkey-patch a balance
    mutation that bumps ``total_supply`` without touching
    ``total_minted``, then apply a block.  Must raise
    ``ChainIntegrityError`` (previously ``AssertionError``, but that
    class of raise is stripped under ``python -O``).
  * ``Test C`` (baseline): run many blocks and assert the invariant
    at every height.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.config import GENESIS_SUPPLY


def _make_chain_with_seeds(n_seeds: int = 1, stake_per_seed: int = 100_000):
    """Build a dev chain with ``n_seeds`` seed validators, all staked."""
    from messagechain.identity.identity import Entity
    from messagechain.core.blockchain import Blockchain
    from messagechain.core.bootstrap import build_launch_allocation
    from messagechain.consensus.pos import ProofOfStake

    seeds = [
        Entity.create(b"inv-seed-" + bytes([i]) + b"\x00" * 22)
        for i in range(n_seeds)
    ]
    for s in seeds:
        s.keypair._next_leaf = 0
    chain = Blockchain()
    allocation = build_launch_allocation(
        [s.entity_id for s in seeds],
        stake_per_seed=stake_per_seed, fee_buffer=0,
    )
    chain.initialize_genesis(seeds[0], allocation_table=allocation)
    for s in seeds:
        chain.supply.stake(s.entity_id, stake_per_seed)
    consensus = ProofOfStake()
    chain.sync_consensus_stakes(consensus)
    return chain, seeds, consensus


def _invariant_holds(chain) -> bool:
    """True iff total_supply == GENESIS_SUPPLY + minted - burned."""
    return (
        chain.supply.total_supply
        == GENESIS_SUPPLY
        + chain.supply.total_minted
        - chain.supply.total_burned
    )


def _invariant_gap(chain) -> int:
    """Signed residual; 0 when invariant holds."""
    return (
        chain.supply.total_supply
        - GENESIS_SUPPLY
        - chain.supply.total_minted
        + chain.supply.total_burned
    )


class TestInvariantBaselineHoldsAtGenesis(unittest.TestCase):
    """Sanity check: the invariant must be true on a fresh chain."""

    def test_fresh_chain_invariant_holds(self):
        chain, _seeds, _pos = _make_chain_with_seeds()
        self.assertTrue(
            _invariant_holds(chain),
            f"invariant broken at genesis: gap={_invariant_gap(chain)}",
        )


class TestInvariantAcrossBlocks(unittest.TestCase):
    """Run a handful of blocks and assert the invariant after each."""

    def test_invariant_holds_across_several_blocks(self):
        from tests import pick_selected_proposer

        chain, seeds, consensus = _make_chain_with_seeds()
        n_blocks = 10
        for _ in range(n_blocks):
            proposer = pick_selected_proposer(chain, seeds)
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, f"add_block failed: {reason}")
            self.assertTrue(
                _invariant_holds(chain),
                f"invariant broken at height {chain.height}: "
                f"gap={_invariant_gap(chain)}",
            )


class TestLotteryBountyPreservesInvariant(unittest.TestCase):
    """Fire the lottery and assert the invariant still holds.

    Pre-fix: ``total_supply`` moves on lottery mint but ``total_minted``
    does not, so the invariant drifts by exactly one bounty per
    lottery-firing block.  This test is the bug reproducer.
    """

    def test_invariant_holds_after_lottery_fires(self):
        from tests import pick_selected_proposer
        from messagechain.identity.identity import Entity
        from messagechain.consensus.attestation import create_attestation

        # Keep LOTTERY_INTERVAL tiny so the test runs quickly, but the
        # apply path reads it via `from messagechain.config import
        # LOTTERY_INTERVAL` at call time — module-level mutation is
        # visible to the apply path without any further wiring.
        original_interval = _cfg.LOTTERY_INTERVAL
        _cfg.LOTTERY_INTERVAL = 3
        try:
            chain, seeds, consensus = _make_chain_with_seeds(n_seeds=1)
            # Lottery excludes seeds; register a non-seed validator with
            # some reputation so there's an eligible winner and the
            # bounty mint actually fires.
            newcomer = Entity.create(
                b"inv-newcomer".ljust(32, b"\x00"),
            )
            newcomer.keypair._next_leaf = 0
            from tests import register_entity_for_test
            register_entity_for_test(chain, newcomer)
            # Bump reputation directly so the first lottery has a
            # positive-reputation candidate to pick (avoids the
            # no-positive-reputation uniform fallback path).
            chain.reputation[newcomer.entity_id] = 5

            # Produce enough blocks that the lottery fires at least
            # once.  With LOTTERY_INTERVAL=3 we only need ~3 blocks.
            # Verify the invariant after every block.
            last_minted = chain.supply.total_minted
            lottery_fired = False
            for _ in range(7):
                proposer = pick_selected_proposer(chain, seeds)
                blk = chain.propose_block(consensus, proposer, [])
                ok, reason = chain.add_block(blk)
                self.assertTrue(ok, f"add_block failed: {reason}")
                # Lottery firing is visible as an extra mint beyond the
                # block reward; detect it so the test confirms the
                # bug-reproducer path actually executed.
                delta_minted = chain.supply.total_minted - last_minted
                expected_block_reward = (
                    chain.supply.calculate_block_reward(chain.height)
                )
                if delta_minted > expected_block_reward:
                    lottery_fired = True
                last_minted = chain.supply.total_minted

                self.assertTrue(
                    _invariant_holds(chain),
                    f"invariant broken at height {chain.height}: "
                    f"gap={_invariant_gap(chain)} "
                    f"(supply={chain.supply.total_supply}, "
                    f"minted={chain.supply.total_minted}, "
                    f"burned={chain.supply.total_burned})",
                )
            self.assertTrue(
                lottery_fired,
                "Lottery never fired — test setup is wrong "
                "(invariant check is trivially passing)",
            )
        finally:
            _cfg.LOTTERY_INTERVAL = original_interval


class TestInvariantAssertionCatchesDrift(unittest.TestCase):
    """Monkey-patch a mutation that breaks the invariant and confirm
    that ``_apply_block_state`` trips its assertion rather than silently
    corrupting state.  Guards against future regressions of the
    R8-#2-class bug: any mint that forgets to bump ``total_minted``
    (or any burn that forgets ``total_burned``) must be caught at
    block-apply time, not at an eventual audit.
    """

    def test_silent_mint_without_total_minted_raises(self):
        from tests import pick_selected_proposer
        from messagechain.core.blockchain import ChainIntegrityError

        chain, seeds, consensus = _make_chain_with_seeds()
        # Inject a drift: bump total_supply without total_minted, as
        # the buggy lottery path was doing.  Do this BEFORE applying
        # the block so the invariant check at end-of-apply catches it.
        chain.supply.total_supply += 7  # phantom mint

        proposer = pick_selected_proposer(chain, seeds)
        blk = chain.propose_block(consensus, proposer, [])
        with self.assertRaises(ChainIntegrityError):
            # _apply_block_state is the guarded path; add_block funnels
            # through it.  Either call site must trip.  Must be
            # ChainIntegrityError (not AssertionError) so the check
            # survives ``python -O`` / PYTHONOPTIMIZE=1.
            chain._apply_block_state(blk)


if __name__ == "__main__":
    unittest.main()
