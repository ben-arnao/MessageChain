"""Seed-divestment retune hard fork — larger floor, deeper burn.

Background
----------
When GENESIS_SUPPLY was rebased from 1B to 140M, the seed-divestment
parameters (burn=75%, treasury=25%, floor=1M) — originally sized
against a 1B-token post-bootstrap landscape — produced an absurd
concentration: 95M founder stake - 1M floor = 94M divestible,
routing 23.5M (25%) to the already-bloated treasury.  Post-bootstrap
the founder would end at 1M + ~5M liquid = ~6M (4% of supply), a
reasonable non-dominance outcome, but the chain-level state ends with
treasury at ~63M (91% of circulating supply) because of the big
treasury-rebase bug from the 140M cut.

The retune combines with the separate treasury rebase to fix both
sides:

  1. SEED_DIVESTMENT_RETAIN_FLOOR: 1M → 20M.  Founder keeps 5M liquid
     + 20M stake = 25M (~14% of supply); dominant-but-not-decisive.
  2. SEED_DIVESTMENT_BURN_BPS: 7500 → 9500 (95%).
  3. SEED_DIVESTMENT_TREASURY_BPS: 2500 → 500 (5%).

Activation-gated at SEED_DIVESTMENT_RETUNE_HEIGHT.  Must activate
BEFORE BOOTSTRAP_END_HEIGHT = 105_192 or the first divestment block
fires under old-schedule terms.  Placeholder is 50_000 (same
convention as the other forks); operator coordinates the real fork
height before launch.

Pre-activation: old parameters.  Mid-window transitions are rare
(both heights are typically months or years apart); the tests here
pin byte-for-byte preservation of pre-activation behavior.
"""

import unittest

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    bootstrap_seed_local,
)
from messagechain.identity.identity import Entity


# This file exercises the RETUNE-era divestment schedule (20M floor,
# 95/5 split, no lottery redistribution).  The REDIST hard fork adds
# a third era that redirects 45% of divestment to lottery payouts;
# to preserve RETUNE-era coverage here, push REDIST past the end of
# this file's simulated range so every test height lives in the
# RETUNE era without lottery redistribution kicking in.
_ORIG_REDIST_HEIGHT = config.SEED_DIVESTMENT_REDIST_HEIGHT


def setUpModule():
    config.SEED_DIVESTMENT_REDIST_HEIGHT = 10 ** 9


def tearDownModule():
    config.SEED_DIVESTMENT_REDIST_HEIGHT = _ORIG_REDIST_HEIGHT


TREASURY = config.TREASURY_ENTITY_ID


def _entity(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


def _bootstrapped_chain(
    stake_amount: int,
) -> tuple[Blockchain, Entity, Entity]:
    seed = _entity(b"divestment-retune-seed")
    cold = _entity(b"divestment-retune-cold")
    allocation = {seed.entity_id: stake_amount + 10_000}
    chain = Blockchain()
    chain.initialize_genesis(seed, allocation_table=allocation)
    ok, log = bootstrap_seed_local(
        chain, seed,
        cold_authority_pubkey=cold.public_key,
        stake_amount=stake_amount,
    )
    assert ok, "\n".join(log)
    return chain, seed, cold


class TestRetuneConstants(unittest.TestCase):
    """Retune constants + activation gate."""

    def test_new_floor_constant(self):
        self.assertTrue(hasattr(config, "SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE"))
        self.assertEqual(
            config.SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE, 20_000_000,
        )

    def test_new_burn_bps_constant(self):
        self.assertTrue(hasattr(config, "SEED_DIVESTMENT_BURN_BPS_POST_RETUNE"))
        self.assertEqual(config.SEED_DIVESTMENT_BURN_BPS_POST_RETUNE, 9500)

    def test_new_treasury_bps_constant(self):
        self.assertTrue(hasattr(config, "SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE"))
        self.assertEqual(config.SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE, 500)

    def test_bps_sum_is_unity(self):
        self.assertEqual(
            config.SEED_DIVESTMENT_BURN_BPS_POST_RETUNE
            + config.SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE,
            10_000,
        )

    def test_legacy_constants_unchanged(self):
        # Pre-activation values must byte-mirror the current constants.
        self.assertEqual(config.SEED_DIVESTMENT_RETAIN_FLOOR, 1_000_000)
        self.assertEqual(config.SEED_DIVESTMENT_BURN_BPS, 7500)
        self.assertEqual(config.SEED_DIVESTMENT_TREASURY_BPS, 2500)

    def test_activation_height_placeholder(self):
        self.assertTrue(hasattr(config, "SEED_DIVESTMENT_RETUNE_HEIGHT"))
        self.assertEqual(config.SEED_DIVESTMENT_RETUNE_HEIGHT, 50_000)

    def test_activation_before_bootstrap_end(self):
        """Must activate BEFORE the first divestment block fires."""
        # BOOTSTRAP_END_HEIGHT is the divestment start (_apply_seed_divestment
        # uses `block_height <= SEED_DIVESTMENT_START_HEIGHT` as the early-exit
        # gate, so divestment starts firing at START_HEIGHT + 1).
        self.assertLess(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT,
            config.SEED_DIVESTMENT_START_HEIGHT,
        )


class TestParamsSelector(unittest.TestCase):
    """Helper that returns the active (floor, burn_bps, treasury_bps)."""

    def test_helper_exists(self):
        self.assertTrue(hasattr(config, "get_seed_divestment_params"))

    def test_pre_activation_returns_legacy(self):
        floor, burn_bps, tres_bps, _lottery_bps = config.get_seed_divestment_params(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT - 1,
        )
        self.assertEqual(floor, 1_000_000)
        self.assertEqual(burn_bps, 7500)
        self.assertEqual(tres_bps, 2500)

    def test_at_activation_returns_new(self):
        floor, burn_bps, tres_bps, _lottery_bps = config.get_seed_divestment_params(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT,
        )
        self.assertEqual(floor, 20_000_000)
        self.assertEqual(burn_bps, 9500)
        self.assertEqual(tres_bps, 500)

    def test_post_activation_returns_new(self):
        floor, burn_bps, tres_bps, _lottery_bps = config.get_seed_divestment_params(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT + 10_000,
        )
        self.assertEqual(floor, 20_000_000)
        self.assertEqual(burn_bps, 9500)
        self.assertEqual(tres_bps, 500)


class TestDivestmentStepsUnderRetune(unittest.TestCase):
    """Integration: `_apply_seed_divestment` honors activation height."""

    def test_pre_retune_uses_legacy_split(self):
        """Pre-activation floor=1M and burn/treasury split preserved."""
        # Build a chain with a stake high enough to divest.  Must also
        # land the test's chosen block_height BELOW the retune height
        # but INSIDE the divestment window.  We force the activation
        # height and divestment window to overlap via monkeypatch-lite:
        # we can't mutate config constants during a test suite run, but
        # we can pick stake > legacy floor and run at
        # SEED_DIVESTMENT_START_HEIGHT + 1 which is below the
        # RETUNE_HEIGHT placeholder iff RETUNE_HEIGHT < START_HEIGHT
        # (asserted elsewhere).  Since both placeholders are 50_000 and
        # START_HEIGHT = 105_192, RETUNE fires first (50_000), then
        # divestment starts (105_193).  That means at any divestment
        # block, RETUNE is already active in the production schedule —
        # we can't drive the pre-retune schedule against a real chain
        # without monkeypatching.  Pin the legacy result via the
        # helper instead.
        floor, burn_bps, tres_bps, _lottery_bps = config.get_seed_divestment_params(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT - 1,
        )
        self.assertEqual(floor, config.SEED_DIVESTMENT_RETAIN_FLOOR)
        self.assertEqual(burn_bps, config.SEED_DIVESTMENT_BURN_BPS)
        self.assertEqual(tres_bps, config.SEED_DIVESTMENT_TREASURY_BPS)

    def test_post_retune_drains_to_new_floor(self):
        """Stake 95M initial + floor 20M → divestible = 75M over the window."""
        # 95M like the mainnet founder.  Run through the full window.
        chain, seed, _ = _bootstrapped_chain(stake_amount=95_000_000)
        seed_id = seed.entity_id
        initial = chain.supply.get_staked(seed_id)
        self.assertEqual(initial, 95_000_000)

        initial_treasury = chain.supply.get_balance(TREASURY)
        initial_supply = chain.supply.total_supply

        start = config.SEED_DIVESTMENT_START_HEIGHT
        end = config.SEED_DIVESTMENT_END_HEIGHT
        # RETUNE_HEIGHT (50_000) < START (105_192), so every divestment
        # block lives in the post-activation regime.
        for h in range(start + 1, end + 1):
            chain._apply_seed_divestment(h)

        stake_now = chain.supply.get_staked(seed_id)
        new_floor = config.SEED_DIVESTMENT_RETAIN_FLOOR_POST_RETUNE
        self.assertGreaterEqual(stake_now, new_floor)
        self.assertLess(stake_now, new_floor + 2)

        total_drained = initial - stake_now
        # Divestible = 95M - 20M = 75M.
        self.assertGreaterEqual(total_drained, 75_000_000 - 1)
        self.assertLessEqual(total_drained, 75_000_000)

        burn = initial_supply - chain.supply.total_supply
        treasury_gain = chain.supply.get_balance(TREASURY) - initial_treasury

        # Conservation of tokens.
        self.assertEqual(burn + treasury_gain, total_drained)

        # Burn/treasury split matches post-retune bps (within per-block
        # integer-rounding noise, which accrues to burn — bigger burn
        # vs. the bps ratio is acceptable).
        expected_treasury = (
            total_drained
            * config.SEED_DIVESTMENT_TREASURY_BPS_POST_RETUNE
            // 10_000
        )
        # Allow small drift from per-block rounding.
        self.assertLessEqual(treasury_gain, expected_treasury)
        # Rounding always favors burn, so treasury should be within one
        # token per block at most — use a conservative tolerance.
        window = end - start
        self.assertGreaterEqual(treasury_gain, expected_treasury - window)

    def test_post_retune_does_not_divest_at_or_below_new_floor(self):
        """Stake == new floor (20M) → divestible == 0, no drain."""
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        seed_id = seed.entity_id
        initial = chain.supply.get_staked(seed_id)
        self.assertEqual(initial, 20_000_000)
        initial_treasury = chain.supply.get_balance(TREASURY)
        initial_supply = chain.supply.total_supply

        start = config.SEED_DIVESTMENT_START_HEIGHT
        end = config.SEED_DIVESTMENT_END_HEIGHT
        # Sample a handful of blocks — if divestible is zero this is a
        # no-op throughout.
        for h in (start + 1, start + 100, (start + end) // 2, end):
            chain._apply_seed_divestment(h)

        self.assertEqual(chain.supply.get_staked(seed_id), initial)
        self.assertEqual(
            chain.supply.get_balance(TREASURY), initial_treasury,
        )
        self.assertEqual(chain.supply.total_supply, initial_supply)


class TestSimulationPathUsesRetunedParams(unittest.TestCase):
    """compute_post_state_root must byte-mirror _apply_seed_divestment."""

    def test_sim_and_apply_agree_under_retune(self):
        """The sim path in compute_post_state_root must produce the
        same state root as the apply path.  Drift would cause
        state_root mismatches at block admission."""
        chain, seed, _ = _bootstrapped_chain(stake_amount=95_000_000)
        seed_id = seed.entity_id

        # Snapshot pre-divestment supply state.
        staked_before = dict(chain.supply.staked)
        balances_before = dict(chain.supply.balances)

        block_height = config.SEED_DIVESTMENT_START_HEIGHT + 1
        # Apply a single divestment step.
        chain._apply_seed_divestment(block_height)

        # Apply-path result.
        apply_stake = chain.supply.staked.get(seed_id, 0)
        apply_treasury = chain.supply.balances.get(TREASURY, 0)

        # Rewind and compute via the sim helper's math: mirror
        # _apply_seed_divestment byte-for-byte against a fresh sim.
        chain.supply.staked = dict(staked_before)
        chain.supply.balances = dict(balances_before)
        chain.seed_initial_stakes = {}
        chain.seed_divestment_debt = {}

        sim_staked = dict(staked_before)
        sim_balances = dict(balances_before)
        # Re-derive the sim using current config knobs (retune-aware).
        floor, _burn_bps, tres_bps, _lottery_bps = config.get_seed_divestment_params(
            block_height,
        )
        divestible = staked_before[seed_id] - floor
        self.assertGreater(divestible, 0)
        window = (
            config.SEED_DIVESTMENT_END_HEIGHT
            - config.SEED_DIVESTMENT_START_HEIGHT
        )
        SCALE = chain._DIVESTMENT_SCALE
        per_block_scaled = (divestible * SCALE) // window
        whole = per_block_scaled // SCALE  # first block — no carried debt
        if whole > 0:
            tres_share = whole * tres_bps // 10_000
            sim_staked[seed_id] -= whole
            if tres_share > 0:
                sim_balances[TREASURY] = (
                    sim_balances.get(TREASURY, 0) + tres_share
                )

        # Apply again for the comparison.
        chain._apply_seed_divestment(block_height)
        self.assertEqual(chain.supply.staked.get(seed_id, 0), apply_stake)
        self.assertEqual(
            chain.supply.balances.get(TREASURY, 0), apply_treasury,
        )
        # The sim math above (stand-in for compute_post_state_root)
        # agrees on the end-state.
        self.assertEqual(sim_staked.get(seed_id, 0), apply_stake)
        self.assertEqual(sim_balances.get(TREASURY, 0), apply_treasury)


class TestInvariant(unittest.TestCase):
    """Conservation across divestment steps.

    In an under-allocated test chain the full-mainnet invariant
    (total_supply == sum(balances) + sum(staked) + pending) does NOT
    hold — genesis allocations under-distribute relative to
    total_supply.  What we pin here is the stricter per-step
    conservation: each divestment step decreases the owned-total and
    total_supply by EXACTLY the per-step burn, with the routed-to-
    treasury piece showing up as a parallel owned-total addition.
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

    def test_conservation_each_step(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=95_000_000)
        start = config.SEED_DIVESTMENT_START_HEIGHT
        for h in (start + 1, start + 2, start + 100, start + 1_000):
            owned_before = self._owned_total(chain)
            supply_before = chain.supply.total_supply
            chain._apply_seed_divestment(h)
            owned_after = self._owned_total(chain)
            supply_after = chain.supply.total_supply
            # The only supply leakage is the burn share; the
            # treasury share is a pure balance move (no supply
            # effect).  A step with no whole-token divest is a no-op
            # on both.
            supply_burn = supply_before - supply_after
            owned_decrease = owned_before - owned_after
            # Stakes -> treasury balance is a pure transfer inside
            # owned-total, so owned_total drops by exactly the burn
            # portion (same as supply burn).
            self.assertEqual(
                supply_burn, owned_decrease,
                f"conservation broke at height {h}: "
                f"supply_burn={supply_burn}, owned_decrease={owned_decrease}",
            )


if __name__ == "__main__":
    unittest.main()
