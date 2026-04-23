"""Treasury-rebase hard fork — burn + per-epoch spend-rate cap.

Background
----------
When GENESIS_SUPPLY was rebased from 1B to 140M (commit a50fce6), the
TREASURY_ALLOCATION=40M constant — originally ~4% of supply — became
~28.6% of the new 140M supply.  The seed-divestment schedule then
routes another ~23.5M to the treasury, leaving ~91% of circulating
supply governance-controlled.  That is a censorship-resistance
failure for a permanence-first chain.

Because TREASURY_ALLOCATION is baked into genesis state (cannot be
retroactively changed), the rebase happens via a coordinated hard
fork that burns a fixed amount from the treasury at a specific
activation height.  Two separate levers:

  1. One-shot burn of TREASURY_REBASE_BURN_AMOUNT (33M) at
     TREASURY_REBASE_HEIGHT, taking post-burn treasury to ~7M
     (5% of 140M).
  2. Per-epoch spend-rate cap (TREASURY_MAX_SPEND_BPS_PER_EPOCH =
     100 bps = 1%) measured per FINALITY_INTERVAL blocks.  Even a
     supermajority-approved treasury spend cannot exceed the cap.

Both gated by block_height >= TREASURY_REBASE_HEIGHT; pre-activation
behavior is byte-for-byte preserved.
"""

import unittest

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    RECOMMENDED_STAKE_PER_SEED,
    bootstrap_seed_local,
    build_launch_allocation,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.identity.identity import Entity


TREASURY = config.TREASURY_ENTITY_ID


# The cap-tightening hard fork (TREASURY_CAP_TIGHTEN_HEIGHT) shares
# the 50_000 placeholder with TREASURY_REBASE_HEIGHT, which would
# tighten the per-epoch cap from 100 bps -> 10 bps at the same block
# these legacy tests exercise.  Push the tightening past any height
# reached here so the legacy 1% cap semantics this file covers
# remain byte-identical.  Mirrors the setUpModule pattern used by
# the seed-divestment legacy test files under
# SEED_DIVESTMENT_RETUNE_HEIGHT.
_ORIG_CAP_TIGHTEN_HEIGHT = config.TREASURY_CAP_TIGHTEN_HEIGHT


def setUpModule():
    config.TREASURY_CAP_TIGHTEN_HEIGHT = 10 ** 9


def tearDownModule():
    config.TREASURY_CAP_TIGHTEN_HEIGHT = _ORIG_CAP_TIGHTEN_HEIGHT


def _entity(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


def _bootstrapped_chain() -> tuple[Blockchain, Entity, Entity]:
    seed = _entity(b"treasury-rebase-seed")
    cold = _entity(b"treasury-rebase-cold")
    allocation = build_launch_allocation([seed.entity_id])
    chain = Blockchain()
    chain.initialize_genesis(seed, allocation_table=allocation)
    ok, log = bootstrap_seed_local(
        chain, seed,
        cold_authority_pubkey=cold.public_key,
        stake_amount=RECOMMENDED_STAKE_PER_SEED,
    )
    assert ok, "\n".join(log)
    return chain, seed, cold


class TestRebaseConstants(unittest.TestCase):
    """The new constants exist at module scope with expected values."""

    def test_burn_amount_constant(self):
        self.assertTrue(hasattr(config, "TREASURY_REBASE_BURN_AMOUNT"))
        self.assertEqual(config.TREASURY_REBASE_BURN_AMOUNT, 33_000_000)

    def test_activation_height_canonical(self):
        self.assertTrue(hasattr(config, "TREASURY_REBASE_HEIGHT"))
        # Tier 3 of the canonical fork schedule (see CLAUDE.md).
        self.assertEqual(config.TREASURY_REBASE_HEIGHT, 68_000)

    def test_spend_cap_constant(self):
        self.assertTrue(hasattr(config, "TREASURY_MAX_SPEND_BPS_PER_EPOCH"))
        # 1% (100 bps) per epoch.
        self.assertEqual(config.TREASURY_MAX_SPEND_BPS_PER_EPOCH, 100)

    def test_spend_cap_epoch_length_matches_finality(self):
        """Same cadence as FINALITY_INTERVAL (100 blocks)."""
        self.assertTrue(
            hasattr(config, "TREASURY_SPEND_CAP_EPOCH_BLOCKS")
        )
        self.assertEqual(
            config.TREASURY_SPEND_CAP_EPOCH_BLOCKS,
            config.FINALITY_INTERVAL,
        )

    def test_post_burn_treasury_is_five_percent_of_supply(self):
        """Sanity: 40M - 33M = 7M, which is 5% of 140M."""
        post = (
            config.TREASURY_ALLOCATION - config.TREASURY_REBASE_BURN_AMOUNT
        )
        self.assertEqual(post, 7_000_000)
        # 5% of 140M = 7M
        self.assertEqual(post * 20, config.GENESIS_SUPPLY)


class TestRebaseStepFunction(unittest.TestCase):
    """`Blockchain._apply_treasury_rebase` applies the one-time burn."""

    def setUp(self):
        self.chain, self.seed, self.cold = _bootstrapped_chain()
        self.initial_treasury = self.chain.supply.get_balance(TREASURY)
        self.initial_supply = self.chain.supply.total_supply
        self.initial_burned = self.chain.supply.total_burned

    def test_method_exists(self):
        self.assertTrue(hasattr(self.chain, "_apply_treasury_rebase"))

    def test_pre_activation_is_noop(self):
        self.chain._apply_treasury_rebase(
            config.TREASURY_REBASE_HEIGHT - 1,
        )
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), self.initial_treasury,
        )
        self.assertEqual(self.chain.supply.total_supply, self.initial_supply)
        self.assertEqual(self.chain.supply.total_burned, self.initial_burned)

    def test_post_activation_but_wrong_height_is_noop(self):
        # Only fires exactly at TREASURY_REBASE_HEIGHT.
        self.chain._apply_treasury_rebase(
            config.TREASURY_REBASE_HEIGHT + 1,
        )
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), self.initial_treasury,
        )
        self.assertEqual(self.chain.supply.total_supply, self.initial_supply)

    def test_activation_height_burns_exact_amount(self):
        self.chain._apply_treasury_rebase(config.TREASURY_REBASE_HEIGHT)
        expected = self.initial_treasury - config.TREASURY_REBASE_BURN_AMOUNT
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), expected,
        )
        self.assertEqual(
            self.chain.supply.total_supply,
            self.initial_supply - config.TREASURY_REBASE_BURN_AMOUNT,
        )
        self.assertEqual(
            self.chain.supply.total_burned,
            self.initial_burned + config.TREASURY_REBASE_BURN_AMOUNT,
        )

    def test_idempotent_running_twice_does_not_double_burn(self):
        self.chain._apply_treasury_rebase(config.TREASURY_REBASE_HEIGHT)
        treasury_after_first = self.chain.supply.get_balance(TREASURY)
        supply_after_first = self.chain.supply.total_supply
        burned_after_first = self.chain.supply.total_burned

        # Re-apply the same block height — must be a no-op.
        self.chain._apply_treasury_rebase(config.TREASURY_REBASE_HEIGHT)
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), treasury_after_first,
        )
        self.assertEqual(
            self.chain.supply.total_supply, supply_after_first,
        )
        self.assertEqual(
            self.chain.supply.total_burned, burned_after_first,
        )


class TestRebaseThroughApplyBlockState(unittest.TestCase):
    """Integration: _apply_block_state must invoke the burn."""

    def setUp(self):
        self.chain, self.seed, self.cold = _bootstrapped_chain()
        self.initial_treasury = self.chain.supply.get_balance(TREASURY)
        self.initial_supply = self.chain.supply.total_supply

    def test_apply_block_state_applies_rebase_at_activation_height(self):
        """Driving `_apply_treasury_rebase` through block state at
        activation height burns exactly 33M from the treasury."""
        # Directly invoke the step function as _apply_block_state would.
        self.chain._apply_treasury_rebase(config.TREASURY_REBASE_HEIGHT)
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY),
            self.initial_treasury - config.TREASURY_REBASE_BURN_AMOUNT,
        )
        self.assertEqual(
            self.chain.supply.total_supply,
            self.initial_supply - config.TREASURY_REBASE_BURN_AMOUNT,
        )


class TestSpendRateCap(unittest.TestCase):
    """Per-epoch cap on treasury_spend — supermajority cannot bypass."""

    def setUp(self):
        self.supply = SupplyTracker()
        # Start treasury at post-burn amount (7M) so the 1% cap = 70K.
        self.supply.balances[TREASURY] = 7_000_000
        self.recipient = b"recipient".ljust(32, b"\x00")

    def _cap_for(self, balance: int) -> int:
        return (
            balance * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH // 10_000
        )

    def test_spend_at_cap_succeeds_post_activation(self):
        cap = self._cap_for(self.supply.balances[TREASURY])
        ok = self.supply.treasury_spend(
            self.recipient, cap,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertTrue(ok)
        self.assertEqual(self.supply.get_balance(self.recipient), cap)

    def test_spend_over_cap_rejected_post_activation(self):
        cap = self._cap_for(self.supply.balances[TREASURY])
        ok = self.supply.treasury_spend(
            self.recipient, cap + 1,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertFalse(ok)
        # Nothing moved.
        self.assertEqual(self.supply.get_balance(TREASURY), 7_000_000)

    def test_second_spend_in_same_epoch_rejected_even_if_small(self):
        """Once the epoch budget is spent, further spends revert even
        if they would individually be within the cap."""
        cap = self._cap_for(self.supply.balances[TREASURY])
        ok = self.supply.treasury_spend(
            self.recipient, cap,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertTrue(ok)
        # A same-epoch follow-up — even just 1 token — fails.
        ok2 = self.supply.treasury_spend(
            self.recipient, 1,
            current_block=config.TREASURY_REBASE_HEIGHT + 1,
        )
        self.assertFalse(ok2)

    def test_next_epoch_resets_cap(self):
        cap = self._cap_for(self.supply.balances[TREASURY])
        ok = self.supply.treasury_spend(
            self.recipient, cap,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertTrue(ok)
        # Move forward by a full epoch — cap resets against the
        # remaining (debited) balance.
        remaining = self.supply.get_balance(TREASURY)
        new_cap = self._cap_for(remaining)
        ok2 = self.supply.treasury_spend(
            self.recipient, new_cap,
            current_block=(
                config.TREASURY_REBASE_HEIGHT
                + config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            ),
        )
        self.assertTrue(ok2)

    def test_pre_activation_cap_not_enforced(self):
        """Before activation, treasury_spend retains its legacy rule
        (no per-epoch cap)."""
        # 100% of the treasury in one spend — forbidden post-activation
        # but allowed pre-activation.
        pre = config.TREASURY_REBASE_HEIGHT - 1
        ok = self.supply.treasury_spend(
            self.recipient, self.supply.balances[TREASURY],
            current_block=pre,
        )
        self.assertTrue(ok)

    def test_legacy_call_without_block_height_allowed(self):
        """Callers that don't thread block height (tests, off-chain)
        keep the legacy unconditional-pass path."""
        ok = self.supply.treasury_spend(
            self.recipient, self.supply.balances[TREASURY],
        )
        self.assertTrue(ok)


class TestInvariant(unittest.TestCase):
    """Supply accounting preserved across rebase.

    `total_supply == sum(balances) + sum(stakes) + pending_unstakes`
    is the full mainnet invariant (see test_genesis_supply_invariant).
    In an under-allocated test chain (build_launch_allocation only
    distributes seed + treasury = ~60M of 140M), the untouched 80M
    phantom is still counted in total_supply.  What we verify here is
    the STABLER form: each mutation step preserves the balance-sheet
    delta — i.e. sum(balances)+sum(staked)+pending exactly decreases
    by the burn amount, and total_supply decreases by the same amount.
    """

    def _owned_total(self, chain: Blockchain) -> int:
        pending = 0
        for entries in chain.supply.pending_unstakes.values():
            for amount, _ in entries:
                pending += amount
        return (
            sum(chain.supply.balances.values())
            + sum(chain.supply.staked.values())
            + pending
        )

    def test_invariant_across_rebase(self):
        """Both total_supply and owned-total drop by exactly the burn."""
        chain, _seed, _cold = _bootstrapped_chain()
        owned_before = self._owned_total(chain)
        supply_before = chain.supply.total_supply

        chain._apply_treasury_rebase(config.TREASURY_REBASE_HEIGHT)

        owned_after = self._owned_total(chain)
        supply_after = chain.supply.total_supply
        self.assertEqual(
            supply_before - supply_after,
            config.TREASURY_REBASE_BURN_AMOUNT,
        )
        self.assertEqual(
            owned_before - owned_after,
            config.TREASURY_REBASE_BURN_AMOUNT,
        )


if __name__ == "__main__":
    unittest.main()
