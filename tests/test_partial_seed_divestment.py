"""Partial seed-validator divestment: drain down to a fixed floor.

Two changes tested here, both reshaping the existing seed divestment
schedule:

  1. **Partial divestment to a floor**: the founder keeps a small
     fixed floor (SEED_DIVESTMENT_RETAIN_FLOOR = 1_000_000 tokens)
     rather than being drained to zero.  The idea: founder ends
     the divestment window as "one of the bigger players but not
     dominant".  The floor is ~0.1% of GENESIS_SUPPLY and roughly
     10x the expected average non-seed validator stake after
     bootstrap.

  2. **Fractional accounting for consensus-safe precision**: the old
     formula was `per_block = initial // window`.  For any seed whose
     initial stake was smaller than the window length (210,384 blocks
     ≈ 4 years), `per_block` would integer-floor to 0 and divestment
     would silently no-op — a bug for testnets / small-stake
     deployments.  The fix uses a per-seed `seed_divestment_debt`
     dict carrying a fractional remainder at SCALE = 10**9, so even
     tiny divestible amounts drain correctly over many blocks.

Determinism: debt is integer-only (no floats), sorted-key iterable,
and committed to the snapshot root for state-sync parity.  Rounding
in the burn/treasury split continues to favor burn.
"""

import unittest

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    bootstrap_seed_local,
    build_launch_allocation,
)
from messagechain.identity.identity import Entity


TREASURY = config.TREASURY_ENTITY_ID
START = config.SEED_DIVESTMENT_START_HEIGHT
END = config.SEED_DIVESTMENT_END_HEIGHT
WINDOW = END - START
FLOOR = config.SEED_DIVESTMENT_RETAIN_FLOOR


def _entity(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


def _bootstrapped_chain(
    stake_amount: int,
) -> tuple[Blockchain, Entity, Entity]:
    """Bootstrap a single-seed chain at a custom stake level."""
    seed = _entity(b"partial-div-seed")
    cold = _entity(b"partial-div-cold")
    # Allocate enough liquid to cover stake + a small fee buffer.
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


class TestRetainFloorConstant(unittest.TestCase):
    """SEED_DIVESTMENT_RETAIN_FLOOR must exist and be a sensible value."""

    def test_floor_constant_defined(self):
        self.assertTrue(hasattr(config, "SEED_DIVESTMENT_RETAIN_FLOOR"))
        self.assertEqual(config.SEED_DIVESTMENT_RETAIN_FLOOR, 1_000_000)

    def test_floor_is_below_recommended_stake(self):
        """The floor must be strictly below the recommended stake,
        otherwise there is nothing to divest."""
        from messagechain.core.bootstrap import RECOMMENDED_STAKE_PER_SEED
        self.assertLess(
            config.SEED_DIVESTMENT_RETAIN_FLOOR,
            RECOMMENDED_STAKE_PER_SEED,
        )


class TestDrainsDownToFloor(unittest.TestCase):
    """After full-window divestment, residual stake == floor exactly."""

    def test_20M_initial_drains_to_floor(self):
        """Initial=20M, floor=1M → after full window, stake ≈ 1M (≥ floor,
        within 1 token due to fractional-accounting floor rounding).
        """
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        initial = chain.supply.get_staked(seed.entity_id)
        self.assertEqual(initial, 20_000_000)
        initial_treasury = chain.supply.get_balance(TREASURY)
        initial_supply = chain.supply.total_supply

        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)

        stake_now = chain.supply.get_staked(seed.entity_id)
        # The fractional-accounting floor on (divestible * SCALE) //
        # window leaves up to ≤ 1 whole token of undrained residual;
        # residual is always on the CORRECT side (stake stays ≥ floor).
        self.assertGreaterEqual(stake_now, FLOOR)
        self.assertLess(stake_now, FLOOR + 2)

        total_drained = initial - stake_now
        # Divestible = 20M - 1M = 19M.  Total drained is 19M minus at
        # most 1 token of fractional rounding residual.
        self.assertGreaterEqual(total_drained, 19_000_000 - 1)
        self.assertLessEqual(total_drained, 19_000_000)

        burn = initial_supply - chain.supply.total_supply
        treasury_gain = chain.supply.get_balance(TREASURY) - initial_treasury

        # Conservation of tokens.
        self.assertEqual(burn + treasury_gain, total_drained)

        # 75% burn / 25% treasury.  Per-block rounding favors burn, so
        # burn can be slightly more than exact 75% and treasury slightly
        # less.  Tolerance: burn >= 14.25M - small slack for residual,
        # treasury <= 4.75M + small slack.
        self.assertGreaterEqual(burn, 14_250_000 - 1)
        self.assertLessEqual(treasury_gain, 4_750_000)
        # Outer bounds keep the rounding error small.
        self.assertLess(burn, 14_250_000 + WINDOW)
        self.assertGreater(treasury_gain, 4_750_000 - WINDOW)


class TestNoOpBelowFloor(unittest.TestCase):
    """A seed whose initial stake is below the floor never divests."""

    def test_stake_below_floor_is_inert(self):
        """initial=500K → no divestment regardless of height."""
        chain, seed, _ = _bootstrapped_chain(stake_amount=500_000)
        initial_stake = chain.supply.get_staked(seed.entity_id)
        self.assertEqual(initial_stake, 500_000)
        self.assertLess(initial_stake, FLOOR)

        initial_treasury = chain.supply.get_balance(TREASURY)
        initial_supply = chain.supply.total_supply

        # Run many divestment blocks; nothing should change.
        for h in range(START + 1, START + 10_000):
            chain._apply_seed_divestment(h)

        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), initial_stake,
        )
        self.assertEqual(
            chain.supply.get_balance(TREASURY), initial_treasury,
        )
        self.assertEqual(chain.supply.total_supply, initial_supply)

    def test_stake_equal_to_floor_is_inert(self):
        """initial == floor → divestible is 0, no-op."""
        chain, seed, _ = _bootstrapped_chain(stake_amount=FLOOR)
        initial_stake = chain.supply.get_staked(seed.entity_id)
        self.assertEqual(initial_stake, FLOOR)

        initial_supply = chain.supply.total_supply
        for h in range(START + 1, START + 1_000):
            chain._apply_seed_divestment(h)

        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), FLOOR,
        )
        self.assertEqual(chain.supply.total_supply, initial_supply)


class TestFractionalAccountingForSmallStakes(unittest.TestCase):
    """The old integer-floor bug: initial < window would silently no-op.

    With fractional accounting at SCALE=10**9, even tiny divestible
    amounts drain correctly over many blocks.
    """

    def test_tiny_divestible_drains(self):
        """initial=5M, floor=1M → divestible=4M over 210,384 blocks.
        After N blocks, drained ≈ N * 4M / 210384.
        """
        chain, seed, _ = _bootstrapped_chain(stake_amount=5_000_000)
        initial = chain.supply.get_staked(seed.entity_id)
        self.assertEqual(initial, 5_000_000)
        divestible = initial - FLOOR  # 4_000_000

        # Per-block fractional amount in scaled units (SCALE=10**9):
        SCALE = 10 ** 9
        per_block_scaled = (divestible * SCALE) // WINDOW

        # Advance N blocks and compare cumulative drain against the
        # exact fractional-accounting expectation.
        N = 1000
        for h in range(START + 1, START + 1 + N):
            chain._apply_seed_divestment(h)

        stake_now = chain.supply.get_staked(seed.entity_id)
        drained = initial - stake_now
        # Expected = (N * per_block_scaled) // SCALE  [whole tokens only].
        expected_drained = (N * per_block_scaled) // SCALE
        self.assertEqual(
            drained, expected_drained,
            f"Expected drained={expected_drained} after {N} blocks, got {drained}",
        )

        # Sanity: with divestible=4M and window=210384, per_block ≈ 19
        # tokens/block; after 1000 blocks ≈ 19,011 tokens drained.
        self.assertGreater(drained, 18_500)
        self.assertLess(drained, 19_500)

    def test_old_bug_initial_less_than_window_would_noop(self):
        """Verify the bug-fix: initial=50K would have per_block=0 under
        the old integer-floor formula; with fractional accounting it
        still drains the divestible portion correctly.

        Because initial=50K < FLOOR=1M, divestible=0 → legitimately
        no-op.  This test explicitly confirms that 'initial < window' no
        longer silently deadlocks divestment, by using a mid-sized
        initial where the old formula would have floored to 0 but the
        new formula correctly drains down to the floor.
        """
        # initial=1.1M, floor=1M → divestible=100K over 210,384 blocks.
        # Old formula: per_block = 100_000 // 210_384 = 0  → NEVER drains.
        # New formula: fractional debt accrues; drains over time.
        chain, seed, _ = _bootstrapped_chain(stake_amount=1_100_000)
        initial = chain.supply.get_staked(seed.entity_id)
        self.assertEqual(initial, 1_100_000)

        # Full-window divestment should drain the 100K divestible down
        # to the floor, within the ≤1-token fractional-accounting
        # residual.  The old integer-floor bug would have drained 0.
        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)

        stake_now = chain.supply.get_staked(seed.entity_id)
        # Old bug behavior: stake stuck at 1_100_000.  New behavior:
        # stake drained to floor (± <= 1 token residual).
        self.assertGreaterEqual(stake_now, FLOOR)
        self.assertLess(
            stake_now, FLOOR + 2,
            f"Expected stake ≈ floor={FLOOR} after full window, got {stake_now}. "
            "If stake is 1_100_000, the old integer-floor bug has returned — "
            "per_block was floored to 0 because divestible < window.",
        )


class TestStakeNeverDropsBelowFloor(unittest.TestCase):
    """Even at END and beyond, stake stays >= floor — hard invariant."""

    def test_stake_stays_at_or_above_floor_through_full_window(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)
            stake_now = chain.supply.get_staked(seed.entity_id)
            self.assertGreaterEqual(
                stake_now, FLOOR,
                f"At h={h}: stake={stake_now} dropped below floor={FLOOR}",
            )

    def test_stake_stable_after_end(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)
        stake_at_end = chain.supply.get_staked(seed.entity_id)
        self.assertGreaterEqual(stake_at_end, FLOOR)
        self.assertLess(stake_at_end, FLOOR + 2)

        # Run past end: no-op.
        for h in range(END + 1, END + 1000):
            chain._apply_seed_divestment(h)
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), stake_at_end,
        )


class TestReorgPreservesDebt(unittest.TestCase):
    """seed_divestment_debt must round-trip through snapshot/restore."""

    def test_snapshot_restore_rewinds_debt(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        # Advance partway into the window.
        for h in range(START + 1, START + 101):
            chain._apply_seed_divestment(h)

        snap = chain._snapshot_memory_state()
        # Field must exist in snapshot.
        self.assertIn("seed_divestment_debt", snap)
        # For 20M initial / 1M floor / 19M divestible, some per-block
        # scaled debt has accumulated.  Exact value is checked in the
        # restore path below.
        debt_at_snap = dict(snap["seed_divestment_debt"])
        self.assertIn(seed.entity_id, debt_at_snap)

        stake_at_snap = chain.supply.get_staked(seed.entity_id)

        # Advance more blocks, growing the debt and draining more stake.
        for h in range(START + 101, START + 201):
            chain._apply_seed_divestment(h)

        stake_after = chain.supply.get_staked(seed.entity_id)
        self.assertLess(stake_after, stake_at_snap)
        debt_after = dict(chain.seed_divestment_debt)
        self.assertNotEqual(debt_after, debt_at_snap)

        # Restore: debt and stake both rewind.
        chain._restore_memory_snapshot(snap)
        self.assertEqual(
            dict(chain.seed_divestment_debt), debt_at_snap,
        )
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), stake_at_snap,
        )

    def test_debt_round_trips_through_state_snapshot(self):
        """seed_divestment_debt must be committed to the snapshot root
        so state-synced nodes stay in lockstep with replaying ones."""
        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
            compute_state_root,
        )
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        for h in range(START + 1, START + 51):
            chain._apply_seed_divestment(h)

        snap = serialize_state(chain)
        self.assertIn("seed_divestment_debt", snap)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["seed_divestment_debt"], snap["seed_divestment_debt"],
        )

        # Changing the debt dict must move the root.
        root_before = compute_state_root(snap)
        mutated = dict(snap)
        mutated["seed_divestment_debt"] = dict(snap["seed_divestment_debt"])
        mutated["seed_divestment_debt"][seed.entity_id] = (
            mutated["seed_divestment_debt"][seed.entity_id] + 1
        )
        root_after = compute_state_root(mutated)
        self.assertNotEqual(
            root_before, root_after,
            "Snapshot root does NOT commit to seed_divestment_debt — "
            "state-sync fork risk",
        )


class TestSplitRatio(unittest.TestCase):
    """75/25 burn/treasury split preserved; rounding favors burn."""

    def test_split_holds_over_full_window(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        initial_treasury = chain.supply.get_balance(TREASURY)
        initial_supply = chain.supply.total_supply

        for h in range(START + 1, END + 1):
            chain._apply_seed_divestment(h)

        burn = initial_supply - chain.supply.total_supply
        treasury_gain = chain.supply.get_balance(TREASURY) - initial_treasury
        total = burn + treasury_gain
        # Divestible = 19M; fractional-accounting residual is at most 1.
        self.assertGreaterEqual(total, 19_000_000 - 1)
        self.assertLessEqual(total, 19_000_000)

        # Ratio: ≥ 75% burn because rounding always favors burn.
        # Per-block round-off of 2500/10000 on small whole-token drains
        # (e.g. 90 per block: 90*2500//10000 = 22, leaving 68 to burn
        # instead of 67.5) systematically biases toward burn.  The
        # observed ratio is ~75.64% — within 1% of the target and
        # strictly on the favored side.
        ratio_burn = burn * 10_000 // total
        self.assertGreaterEqual(ratio_burn, 7_500)      # >= 75%
        self.assertLess(ratio_burn, 7_500 + 100)        # within ~1%


class TestSkipsWhenCurrentStakeAtOrBelowFloor(unittest.TestCase):
    """If current stake has already been clamped to the floor (or below
    via some external slash-like event), divestment stops."""

    def test_skipped_when_at_floor(self):
        chain, seed, _ = _bootstrapped_chain(stake_amount=20_000_000)
        # Prime the capture.
        chain._apply_seed_divestment(START + 1)

        # Artificially drop current stake to floor.
        chain.supply.staked[seed.entity_id] = FLOOR
        supply_before = chain.supply.total_supply
        treasury_before = chain.supply.get_balance(TREASURY)

        # More divestment blocks must not push below floor.
        for h in range(START + 2, START + 1000):
            chain._apply_seed_divestment(h)
        self.assertEqual(
            chain.supply.get_staked(seed.entity_id), FLOOR,
        )
        self.assertEqual(chain.supply.total_supply, supply_before)
        self.assertEqual(
            chain.supply.get_balance(TREASURY), treasury_before,
        )


if __name__ == "__main__":
    unittest.main()
