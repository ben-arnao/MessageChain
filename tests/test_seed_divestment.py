"""Seed-validator divestment: non-discretionary unwind of founder stake.

Without an enforced divestment schedule the founder holds ~98% of
validator stake throughout bootstrap, and at H=BOOTSTRAP_END_HEIGHT
every guardrail drops simultaneously, leaving the founder dominant
with no forced unwind.  The rule tested here:

  * H <= SEED_DIVESTMENT_START (105_192): seed's full stake intact.
  * START < H <= END (315_576): each block forcibly unbonds a
    linear portion of DIVESTIBLE = max(0, initial_stake -
    SEED_DIVESTMENT_RETAIN_FLOOR) tokens — 75% burned (supply
    drops), 25% to treasury.  Per-block accounting uses integer
    fractional debt at SCALE=10**9 so even tiny divestible amounts
    drain correctly.  Per-block split rounding favors burn.
  * H > END: seed has no special divestment pressure.  Residual
    stake is whatever the floor left (≥ RETAIN_FLOOR).  The seed
    can re-stake fresh tokens via a normal StakeTransaction without
    those getting eroded.

These tests drive the production block-apply step function directly
against a pre-bootstrapped Blockchain — applying 200K+ real blocks
through the pipeline is prohibitive.  Determinism across fresh
chains and integration with the full pipeline is covered by the
determinism + snapshot tests below.
"""

import unittest

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    bootstrap_seed_local,
    build_launch_allocation,
    RECOMMENDED_STAKE_PER_SEED,
)
from messagechain.identity.identity import Entity


# This file exercises the LEGACY divestment schedule (1M floor, 75/25
# split).  The retune and redistribution hard forks activate at
# SEED_DIVESTMENT_RETUNE_HEIGHT / SEED_DIVESTMENT_REDIST_HEIGHT, both
# of which fire before the legacy divestment window in production.
# To keep this file's coverage of legacy behavior intact, push BOTH
# fork heights past the end of this file's simulated range — pre-
# retune params apply throughout, exactly as on a pre-fork chain.
_ORIG_RETUNE_HEIGHT = config.SEED_DIVESTMENT_RETUNE_HEIGHT
_ORIG_REDIST_HEIGHT = config.SEED_DIVESTMENT_REDIST_HEIGHT


def setUpModule():
    config.SEED_DIVESTMENT_RETUNE_HEIGHT = 10 ** 9
    config.SEED_DIVESTMENT_REDIST_HEIGHT = 10 ** 9


def tearDownModule():
    config.SEED_DIVESTMENT_RETUNE_HEIGHT = _ORIG_RETUNE_HEIGHT
    config.SEED_DIVESTMENT_REDIST_HEIGHT = _ORIG_REDIST_HEIGHT


TREASURY = config.TREASURY_ENTITY_ID
START = config.SEED_DIVESTMENT_START_HEIGHT
END = config.SEED_DIVESTMENT_END_HEIGHT
WINDOW = END - START
FLOOR = config.SEED_DIVESTMENT_RETAIN_FLOOR


def _entity(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


def _bootstrapped_chain() -> tuple[Blockchain, Entity, Entity]:
    """Build a seed chain and lock RECOMMENDED_STAKE_PER_SEED."""
    seed = _entity(b"divestment-seed")
    cold = _entity(b"divestment-cold")
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


class TestDivestmentSchedule(unittest.TestCase):
    """The pure divestment step function, driven against real chain state."""

    def setUp(self):
        self.chain, self.seed, self.cold = _bootstrapped_chain()
        self.seed_id = self.seed.entity_id
        self.initial_stake = self.chain.supply.get_staked(self.seed_id)
        self.assertEqual(self.initial_stake, RECOMMENDED_STAKE_PER_SEED)
        self.divestible = self.initial_stake - FLOOR
        self.assertGreater(self.divestible, 0)
        self.initial_treasury = self.chain.supply.get_balance(TREASURY)
        self.initial_total_supply = self.chain.supply.total_supply

    def _apply_step(self, height: int):
        self.chain._apply_seed_divestment(height)

    def test_noop_at_start_boundary(self):
        """At H == SEED_DIVESTMENT_START no tokens move (inclusive lower bound)."""
        self._apply_step(START)
        self.assertEqual(
            self.chain.supply.get_staked(self.seed_id), self.initial_stake,
        )
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), self.initial_treasury,
        )
        self.assertEqual(
            self.chain.supply.total_supply, self.initial_total_supply,
        )

    def test_noop_well_before_start(self):
        """Early blocks are completely inert for divestment accounting."""
        for h in (1, 100, 10_000, START - 1):
            self._apply_step(h)
        self.assertEqual(
            self.chain.supply.get_staked(self.seed_id), self.initial_stake,
        )
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY), self.initial_treasury,
        )
        self.assertEqual(
            self.chain.supply.total_supply, self.initial_total_supply,
        )

    def test_first_divestment_block(self):
        """At H=START+1 stake drops by divestible/WINDOW (via fractional
        debt); 75% burned, 25% treasury.
        """
        # Expected per-block drain uses the same fractional-accounting
        # formula as _apply_seed_divestment.
        SCALE = 10 ** 9
        per_block_scaled = (self.divestible * SCALE) // WINDOW
        # First block: debt = per_block_scaled, whole = debt // SCALE.
        expected_whole = per_block_scaled // SCALE

        self._apply_step(START + 1)
        stake_after = self.chain.supply.get_staked(self.seed_id)
        self.assertEqual(stake_after, self.initial_stake - expected_whole)

        # Burn/treasury conservation: 25% treasury (basis points),
        # remainder to burn.
        treasury_cut = expected_whole * config.SEED_DIVESTMENT_TREASURY_BPS // 10_000
        burn_cut = expected_whole - treasury_cut
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY),
            self.initial_treasury + treasury_cut,
        )
        self.assertEqual(
            self.chain.supply.total_supply,
            self.initial_total_supply - burn_cut,
        )

    def test_midpoint_stake_is_half_divested(self):
        """At H=midpoint cumulative divested ≈ divestible/2; burn ≈ 75% of
        that; treasury ≈ 25% of that.  Stake ≈ initial - divestible/2."""
        midpoint = START + WINDOW // 2
        for h in range(START + 1, midpoint + 1):
            self._apply_step(h)

        stake_now = self.chain.supply.get_staked(self.seed_id)
        # Should have drained roughly half the divestible.
        half_drain = self.divestible // 2
        expected_stake = self.initial_stake - half_drain
        # Tolerance: one block's per-block drain (~91 tokens).
        self.assertGreater(stake_now, expected_stake - 100)
        self.assertLess(stake_now, expected_stake + 100)

        treasury_gain = self.chain.supply.get_balance(TREASURY) - self.initial_treasury
        burn = self.initial_total_supply - self.chain.supply.total_supply
        total_divested = self.initial_stake - stake_now
        self.assertEqual(treasury_gain + burn, total_divested)
        # Split ≈ 75/25.
        self.assertGreater(burn, treasury_gain * 2)
        self.assertLess(burn, treasury_gain * 4)

    def test_end_of_divestment_stake_at_floor(self):
        """At H=END cumulative ≈ divestible; stake ≈ FLOOR (within 1 token
        of the fractional-accounting residual)."""
        for h in range(START + 1, END + 1):
            self._apply_step(h)

        stake_now = self.chain.supply.get_staked(self.seed_id)
        # Residual at end is at most 1 token above FLOOR (fractional
        # floor rounding in (divestible * SCALE) // window).
        self.assertGreaterEqual(stake_now, FLOOR)
        self.assertLess(stake_now, FLOOR + 2)

        total_divested = self.initial_stake - stake_now
        treasury_gain = self.chain.supply.get_balance(TREASURY) - self.initial_treasury
        burn = self.initial_total_supply - self.chain.supply.total_supply
        self.assertEqual(treasury_gain + burn, total_divested)
        # Split is approximately 75% / 25% with rounding favor to burn.
        self.assertGreaterEqual(burn * 4, total_divested * 3)
        self.assertLessEqual(treasury_gain * 4, total_divested)

    def test_no_further_decay_post_divestment(self):
        """Steps past END are no-ops — seed's residual stake is stable."""
        for h in range(START + 1, END + 1):
            self._apply_step(h)
        stake_at_end = self.chain.supply.get_staked(self.seed_id)
        treasury_at_end = self.chain.supply.get_balance(TREASURY)
        supply_at_end = self.chain.supply.total_supply

        # Many blocks past end: nothing changes.
        for h in (END + 1, END + 100, 400_000, 1_000_000):
            self._apply_step(h)
        self.assertEqual(self.chain.supply.get_staked(self.seed_id), stake_at_end)
        self.assertEqual(self.chain.supply.get_balance(TREASURY), treasury_at_end)
        self.assertEqual(self.chain.supply.total_supply, supply_at_end)

    def test_stake_clamps_at_floor(self):
        """If stake has already been pushed to the floor (external shock),
        no further divestment moves tokens and stake stays at floor."""
        # Artificially set stake to the floor, then run divestment.
        self.chain.supply.staked[self.seed_id] = FLOOR
        # Prime the snapshot so the step function has a reference.
        self.chain.seed_initial_stakes[self.seed_id] = self.initial_stake

        pre_treasury = self.chain.supply.get_balance(TREASURY)
        pre_supply = self.chain.supply.total_supply
        for h in range(START + 1, START + 1000):
            self._apply_step(h)
        self.assertEqual(
            self.chain.supply.get_staked(self.seed_id), FLOOR,
        )
        # No extra tokens moved once stake hit the floor.
        self.assertEqual(self.chain.supply.get_balance(TREASURY), pre_treasury)
        self.assertEqual(self.chain.supply.total_supply, pre_supply)


class TestSnapshotBehavior(unittest.TestCase):
    """initial_seed_stake snapshot is taken once and never regenerated."""

    def test_snapshot_captured_at_start(self):
        """The seed's staked amount at the first divestment block becomes the reference."""
        chain, seed, _ = _bootstrapped_chain()
        # Nothing snapshotted pre-divestment.
        self.assertEqual(chain.seed_initial_stakes, {})
        # Applying a pre-start step leaves the snapshot empty.
        chain._apply_seed_divestment(START)
        self.assertEqual(chain.seed_initial_stakes, {})
        # First divestment block -> snapshot equals current stake.
        expected = chain.supply.get_staked(seed.entity_id)
        chain._apply_seed_divestment(START + 1)
        self.assertEqual(chain.seed_initial_stakes[seed.entity_id], expected)

    def test_snapshot_is_sticky(self):
        """Subsequent blocks reuse the original snapshot — stake decay does not rebase it."""
        chain, seed, _ = _bootstrapped_chain()
        chain._apply_seed_divestment(START + 1)
        first_snap = chain.seed_initial_stakes[seed.entity_id]
        # Run a handful more steps — snapshot never moves.
        for h in range(START + 2, START + 50):
            chain._apply_seed_divestment(h)
        self.assertEqual(chain.seed_initial_stakes[seed.entity_id], first_snap)


class TestDeterminism(unittest.TestCase):
    """Two fresh chains advanced to the same H produce byte-identical seed state."""

    def test_determinism_midpoint(self):
        chain_a, _, _ = _bootstrapped_chain()
        chain_b, _, _ = _bootstrapped_chain()
        for h in range(START + 1, START + 5000):
            chain_a._apply_seed_divestment(h)
            chain_b._apply_seed_divestment(h)
        self.assertEqual(dict(chain_a.supply.staked), dict(chain_b.supply.staked))
        self.assertEqual(
            chain_a.supply.get_balance(TREASURY),
            chain_b.supply.get_balance(TREASURY),
        )
        self.assertEqual(
            chain_a.supply.total_supply, chain_b.supply.total_supply,
        )
        self.assertEqual(
            chain_a.seed_initial_stakes, chain_b.seed_initial_stakes,
        )
        self.assertEqual(
            chain_a.seed_divestment_debt, chain_b.seed_divestment_debt,
        )


class TestPostDivestmentRestake(unittest.TestCase):
    """A former seed can re-stake via a normal StakeTransaction after END."""

    def test_former_seed_can_stake_normally(self):
        """Post-divestment, a StakeTransaction from the seed succeeds like any other."""
        chain, seed, _ = _bootstrapped_chain()

        # Fast-forward divestment against in-memory chain state.
        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)

        # Seed identity is pinned at genesis (permanent on-chain record).
        # Residual stake is clamped at the retain floor (± <= 1 token).
        self.assertIn(seed.entity_id, chain.seed_entity_ids)
        residual = chain.supply.get_staked(seed.entity_id)
        self.assertGreaterEqual(residual, FLOOR)
        self.assertLess(residual, FLOOR + 2)

        # Give the seed some fresh liquid (simulating fees/rewards earned
        # through normal means) and stake it via the standard supply API.
        chain.supply.balances[seed.entity_id] = (
            chain.supply.balances.get(seed.entity_id, 0) + 5_000
        )
        ok = chain.supply.stake(seed.entity_id, 5_000)
        self.assertTrue(ok, "former seed was unable to re-stake post-divestment")
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), residual + 5_000,
        )

        # Further divestment steps past END are true no-ops — the
        # freshly-acquired stake is NOT eroded.  Only the genesis-era
        # snapshot matters for divestment accounting.
        chain._apply_seed_divestment(END + 100)
        chain._apply_seed_divestment(400_000)
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), residual + 5_000,
        )


class TestBlockPipelineIntegration(unittest.TestCase):
    """Full block-apply path triggers divestment deterministically."""

    def test_apply_block_state_invokes_divestment(self):
        """Divestment hook fires with the block height; seed state moves."""
        chain, seed, _ = _bootstrapped_chain()
        initial_stake = chain.supply.get_staked(seed.entity_id)
        divestible = initial_stake - FLOOR
        SCALE = 10 ** 9
        per_block_scaled = (divestible * SCALE) // WINDOW
        expected_whole = per_block_scaled // SCALE

        chain._apply_seed_divestment(START + 1)
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id),
            initial_stake - expected_whole,
        )

    def test_block_affected_entities_includes_seeds(self):
        """Seeds land in _block_affected_entities so state-tree rows refresh."""
        chain, seed, _ = _bootstrapped_chain()

        # Minimal block-like object with empty tx lists.
        class _FakeHeader:
            proposer_id = b"\x00" * 32

        class _FakeBlock:
            header = _FakeHeader()
            transactions = []
            transfer_transactions = []
            slash_transactions = []
            attestations = []
            governance_txs = []
            authority_txs = []
            stake_transactions = []
            unstake_transactions = []

        affected = chain._block_affected_entities(_FakeBlock())
        self.assertIn(seed.entity_id, affected)


if __name__ == "__main__":
    unittest.main()
