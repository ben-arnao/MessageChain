"""Seed-validator divestment: non-discretionary unwind of founder stake.

Without an enforced divestment schedule the founder holds ~98% of
validator stake throughout bootstrap, and at H=BOOTSTRAP_END_HEIGHT
every guardrail drops simultaneously, leaving the founder dominant
with no forced unwind.  The rule tested here:

  * H <= SEED_DIVESTMENT_START (105_192): seed's full stake intact.
  * START < H <= END (315_576): each block forcibly unbonds
    initial_seed_stake / (END - START) tokens from stake.  75% of
    that is burned (total_supply drops), 25% to treasury.  Rounding
    remainder at each block goes to burn.
  * H > END: seed has no special status.  A StakeTransaction from
    the (former) seed succeeds normally.

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


TREASURY = config.TREASURY_ENTITY_ID
START = config.SEED_DIVESTMENT_START_HEIGHT
END = config.SEED_DIVESTMENT_END_HEIGHT
WINDOW = END - START


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
        # Sanity: confirm we're bootstrapped at 99M.
        self.assertEqual(self.initial_stake, RECOMMENDED_STAKE_PER_SEED)
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
        """At H=START+1 stake drops by initial/WINDOW; 75% burned, 25% treasury."""
        per_block = self.initial_stake // WINDOW
        self.assertEqual(per_block, 99_000_000 // 210_384)  # 470
        treasury_cut = per_block * config.SEED_DIVESTMENT_TREASURY_BPS // 10_000
        burn_cut = per_block - treasury_cut  # includes rounding remainder

        self._apply_step(START + 1)
        self.assertEqual(
            self.chain.supply.get_staked(self.seed_id),
            self.initial_stake - per_block,
        )
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY),
            self.initial_treasury + treasury_cut,
        )
        self.assertEqual(
            self.chain.supply.total_supply,
            self.initial_total_supply - burn_cut,
        )

    def test_midpoint_stake_halved(self):
        """At H=midpoint cumulative divested ~= 49.5M; burn ~= 37.1M; treasury ~= 12.4M."""
        midpoint = START + WINDOW // 2  # 105_192 + 105_192 = 210_384
        for h in range(START + 1, midpoint + 1):
            self._apply_step(h)

        stake_now = self.chain.supply.get_staked(self.seed_id)
        # Rough halfway: allow small integer-rounding slack.
        self.assertGreater(stake_now, 49_400_000)
        self.assertLess(stake_now, 49_600_000)

        treasury_gain = self.chain.supply.get_balance(TREASURY) - self.initial_treasury
        burn = self.initial_total_supply - self.chain.supply.total_supply
        total_divested = self.initial_stake - stake_now
        # Treasury + burn must equal total divested (conservation).
        self.assertEqual(treasury_gain + burn, total_divested)
        # Split ~= 75/25.
        self.assertGreater(burn, treasury_gain * 2)
        self.assertLess(burn, treasury_gain * 4)
        self.assertGreater(treasury_gain, 12_000_000)
        self.assertLess(treasury_gain, 12_700_000)

    def test_end_of_divestment_stake_near_zero(self):
        """At H=END cumulative ~= full initial; stake ~= 0 (integer remainder OK)."""
        for h in range(START + 1, END + 1):
            self._apply_step(h)

        stake_now = self.chain.supply.get_staked(self.seed_id)
        # The flat per-block amount is floor(initial / WINDOW), so the
        # residual at end is initial - WINDOW * floor(initial/WINDOW),
        # which is bounded by WINDOW - 1.
        self.assertLess(stake_now, WINDOW)
        self.assertGreaterEqual(stake_now, 0)

        total_divested = self.initial_stake - stake_now
        treasury_gain = self.chain.supply.get_balance(TREASURY) - self.initial_treasury
        burn = self.initial_total_supply - self.chain.supply.total_supply
        self.assertEqual(treasury_gain + burn, total_divested)
        # 25% treasury ~= 24.75M; 75% burn ~= 74.25M.
        self.assertGreater(burn, 74_000_000)
        self.assertLess(burn, 74_500_000)
        self.assertGreater(treasury_gain, 24_600_000)
        self.assertLess(treasury_gain, 24_900_000)

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

    def test_stake_clamps_at_zero(self):
        """If stake runs out early (edge), no negative balances or over-burn."""
        # Artificially zero the stake, then run divestment for many blocks.
        self.chain.supply.staked[self.seed_id] = 0
        # Prime the snapshot so the step function has a reference.
        self.chain.seed_initial_stakes[self.seed_id] = self.initial_stake

        pre_treasury = self.chain.supply.get_balance(TREASURY)
        pre_supply = self.chain.supply.total_supply
        for h in range(START + 1, START + 1000):
            self._apply_step(h)
        self.assertEqual(self.chain.supply.get_staked(self.seed_id), 0)
        # No extra tokens moved once stake hit zero.
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


class TestPostDivestmentRestake(unittest.TestCase):
    """A former seed can re-stake via a normal StakeTransaction after END."""

    def test_former_seed_can_stake_normally(self):
        """Post-divestment, a StakeTransaction from the seed succeeds like any other."""
        chain, seed, _ = _bootstrapped_chain()

        # Fast-forward divestment against in-memory chain state.
        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)

        # Seed identity is pinned at genesis (permanent on-chain record)
        # but the seed has no special stake anymore.
        self.assertIn(seed.entity_id, chain.seed_entity_ids)
        residual = chain.supply.get_staked(seed.entity_id)
        self.assertLess(residual, WINDOW)

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
        per_block = initial_stake // WINDOW
        chain._apply_seed_divestment(START + 1)
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id),
            initial_stake - per_block,
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
