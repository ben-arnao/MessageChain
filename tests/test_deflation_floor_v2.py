"""Tests for the fee-responsive deflation floor (v2 hard fork).

Background
----------
The original v1 anchor (DEFLATION_FLOOR_HEIGHT = 50_000) doubled
BLOCK_REWARD when total_supply < TARGET_CIRCULATING_SUPPLY_FLOOR.  At the
floor era that produces 8 tokens/block × 52,600 = 420K/yr — but
steady-state burn at moderate traffic is ~13M/yr, so the 2× multiplier
is ~31× too small to arrest deflation.

v2 fix: replace the fixed 2× multiplier with a fee-responsive rebate.
At/after DEFLATION_FLOOR_V2_HEIGHT, when supply < TARGET, issuance is
    max(base_reward, rolling_fee_burn_rate * DEFLATION_REBATE_BPS / 10_000)
The rolling burn rate is the sum of burns in the last
DEFLATION_REBATE_WINDOW_BLOCKS, divided by the window.

Pre-activation (block_height < DEFLATION_FLOOR_V2_HEIGHT): v1 2× behavior
preserved byte-for-byte.  Between v1 activation (50_000) and v2
activation (70_000) the 2× multiplier continues to fire.

This file pins:
  * Rolling-window accumulation and prune.
  * High-burn epoch → high issuance (rebate fires).
  * Low-burn epoch → base reward (floor behavior).
  * Pre-activation: 2× behavior preserved (regression guard for the
    v1 tests' expectation).
  * Snapshot round-trip for rolling_fee_burn (reorg safety).
  * State-root commitment changes when rolling_fee_burn changes.
"""

import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    GENESIS_SUPPLY,
    TARGET_CIRCULATING_SUPPLY_FLOOR,
    DEFLATION_ISSUANCE_MULTIPLIER,
    DEFLATION_FLOOR_HEIGHT,
    DEFLATION_FLOOR_V2_HEIGHT,
    DEFLATION_REBATE_BPS,
    DEFLATION_REBATE_WINDOW_BLOCKS,
)


PRE_V2_HEIGHT = DEFLATION_FLOOR_V2_HEIGHT - 1  # v1 era, 2× multiplier still valid
POST_V2_HEIGHT = DEFLATION_FLOOR_V2_HEIGHT
PROPOSER = b"p" * 32


class TestPreV2ActivationPreservesOldMultiplier(unittest.TestCase):
    """Below DEFLATION_FLOOR_V2_HEIGHT but above DEFLATION_FLOOR_HEIGHT,
    the legacy 2× multiplier still applies.  This guards the pre-v2
    byte-for-byte preservation promise."""

    def test_pre_v2_low_supply_uses_2x_multiplier(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Pre-v2 but post-v1.
        reward = supply.calculate_block_reward(PRE_V2_HEIGHT)
        self.assertEqual(
            reward, BLOCK_REWARD * DEFLATION_ISSUANCE_MULTIPLIER,
        )

    def test_pre_v1_activation_no_boost_either(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        reward = supply.calculate_block_reward(DEFLATION_FLOOR_HEIGHT - 1)
        self.assertEqual(reward, BLOCK_REWARD)


class TestPostV2ActivationAboveFloorNoRebate(unittest.TestCase):
    """Supply above floor post-activation: no rebate, base reward."""

    def test_post_v2_supply_above_floor_no_boost(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR + 1
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)


class TestPostV2LowBurnFallsBackToBase(unittest.TestCase):
    """Supply below floor but rolling burn rate is zero / low: the
    rebate formula returns < base_reward, so max() picks base_reward.
    Behavior equals base_reward (NOT the old 2×)."""

    def test_post_v2_low_supply_zero_burn_returns_base(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Empty rolling window → burn_rate = 0 → rebate = 0.
        self.assertEqual(supply.rolling_fee_burn, [])
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)

    def test_post_v2_low_supply_low_burn_returns_base(self):
        """burn_rate = 1 token/block; rebate = 1 * 7000 / 10_000 = 0.
        max(16, 0) = 16."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Populate window with tiny burns.
        supply.rolling_fee_burn = [
            (POST_V2_HEIGHT - 1, 1) for _ in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)


class TestPostV2HighBurnDrivesRebate(unittest.TestCase):
    """With sustained heavy burn, the rebate formula exceeds base_reward
    and drives issuance upward."""

    def test_high_burn_rebate_exceeds_base(self):
        """burn_rate = 1000 tokens/block; rebate = 1000 * 7000 / 10_000
        = 700.  max(16, 700) = 700."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Window full of 1000-token burns.
        supply.rolling_fee_burn = [
            (POST_V2_HEIGHT - 1 - i, 1000)
            for i in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        expected_rate = 1000  # sum=1000*W, /W = 1000
        expected = expected_rate * DEFLATION_REBATE_BPS // 10_000
        self.assertEqual(reward, expected)
        self.assertGreater(reward, BLOCK_REWARD)

    def test_high_burn_rebate_is_floor_of_burn_rate_times_bps(self):
        """Exact arithmetic: burns totaling 7,000,000 over the window,
        burn_rate = 7000/block; rebate = 7000 * 7000 / 10_000 = 4900."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Total burn = 7,000,000 across window.
        per_block_burn = 7_000_000 // DEFLATION_REBATE_WINDOW_BLOCKS  # 7000
        supply.rolling_fee_burn = [
            (POST_V2_HEIGHT - 1 - i, per_block_burn)
            for i in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        expected = per_block_burn * DEFLATION_REBATE_BPS // 10_000
        self.assertEqual(reward, expected)


class TestRollingWindowPruneAndSum(unittest.TestCase):
    """Entries older than DEFLATION_REBATE_WINDOW_BLOCKS are pruned
    before the rolling sum is computed."""

    def test_prune_old_entries(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Mix of in-window and out-of-window entries.
        in_window = [
            (POST_V2_HEIGHT - 1 - i, 1000)
            for i in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        # These are far older than the window start — should be pruned.
        out_of_window = [
            (POST_V2_HEIGHT - DEFLATION_REBATE_WINDOW_BLOCKS - 5_000, 10_000_000),
            (POST_V2_HEIGHT - DEFLATION_REBATE_WINDOW_BLOCKS - 10_000, 99_999_999),
        ]
        supply.rolling_fee_burn = out_of_window + in_window
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        # Only in-window entries should count: sum = 1000 * W, rate = 1000,
        # rebate = 1000 * 7000 / 10_000 = 700.
        self.assertEqual(reward, 700)

    def test_prune_leaves_sum_zero_after_full_rotation(self):
        """If every entry is older than the window, rolling_rate = 0,
        and reward falls back to base."""
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # All entries far older than the window.
        supply.rolling_fee_burn = [
            (POST_V2_HEIGHT - DEFLATION_REBATE_WINDOW_BLOCKS - 10_000 - i, 1_000_000)
            for i in range(100)
        ]
        reward = supply.calculate_block_reward(POST_V2_HEIGHT)
        self.assertEqual(reward, BLOCK_REWARD)


class TestPayFeeWithBurnAppendsToRolling(unittest.TestCase):
    """Post-v2-activation, every fee-burn appends (block_height,
    actual_burn) to rolling_fee_burn.  Pre-activation it does not."""

    def test_post_v2_pay_fee_appends(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        supply.balances[sender] = 10_000
        supply.balances[PROPOSER] = 0
        ok = supply.pay_fee_with_burn(
            sender, PROPOSER, fee=200, base_fee=100,
            block_height=POST_V2_HEIGHT,
        )
        self.assertTrue(ok)
        # Exactly one entry appended with current block_height.
        self.assertEqual(len(supply.rolling_fee_burn), 1)
        h, amt = supply.rolling_fee_burn[0]
        self.assertEqual(h, POST_V2_HEIGHT)
        # amt is the actual_burn (post-attester-share split).  Doesn't
        # need to equal base_fee when attester-fee funding is also
        # active at this height; what matters is it's > 0.
        self.assertGreater(amt, 0)

    def test_pre_v2_pay_fee_does_not_append(self):
        supply = SupplyTracker()
        sender = b"s" * 32
        supply.balances[sender] = 10_000
        supply.balances[PROPOSER] = 0
        supply.pay_fee_with_burn(
            sender, PROPOSER, fee=200, base_fee=100,
            block_height=PRE_V2_HEIGHT,
        )
        self.assertEqual(supply.rolling_fee_burn, [])


class TestFloorEraRebateDominates(unittest.TestCase):
    """At the floor era (BLOCK_REWARD_FLOOR=4), base_reward is small,
    so rebate dominates even more."""

    def test_floor_era_high_burn_rebate(self):
        from messagechain.config import HALVING_INTERVAL
        floor_era_height = HALVING_INTERVAL * 3 + 1
        # Make sure floor_era_height >= DEFLATION_FLOOR_V2_HEIGHT (it is
        # well past: 3 * 210_240 = 630_720 >> 70_000).
        self.assertGreaterEqual(floor_era_height, DEFLATION_FLOOR_V2_HEIGHT)
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # 1000 tokens/block burn → rebate = 700.  Base at floor era = 4.
        supply.rolling_fee_burn = [
            (floor_era_height - 1 - i, 1000)
            for i in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        reward = supply.calculate_block_reward(floor_era_height)
        self.assertEqual(reward, 700)
        self.assertGreater(reward, BLOCK_REWARD_FLOOR)


class TestSnapshotRoundTripRollingFeeBurn(unittest.TestCase):
    """Reorg safety: _snapshot_memory_state / _restore_memory_snapshot
    round-trip rolling_fee_burn so a reorg that undoes blocks restores
    the pre-reorg window exactly."""

    def test_snapshot_restore_preserves_rolling_list(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        # Seed the rolling list.
        bc.supply.rolling_fee_burn = [
            (100, 1000), (101, 2000), (102, 3000),
        ]
        snap = bc._snapshot_memory_state()
        # Clobber.
        bc.supply.rolling_fee_burn = [(999, 999)]
        bc._restore_memory_snapshot(snap)
        self.assertEqual(
            bc.supply.rolling_fee_burn,
            [(100, 1000), (101, 2000), (102, 3000)],
        )


class TestStateSnapshotCommitsRollingFeeBurn(unittest.TestCase):
    """Mutating rolling_fee_burn must change compute_state_root so
    state-synced nodes that inherit a stale window are detectable."""

    def test_mutation_changes_state_root(self):
        from messagechain.storage.state_snapshot import compute_state_root
        base = _blank_snapshot()
        base_root = compute_state_root(base)
        mutated = dict(base)
        mutated["rolling_fee_burn"] = [(100, 1000)]
        mutated_root = compute_state_root(mutated)
        self.assertNotEqual(base_root, mutated_root)


class TestSnapshotWireRoundTripRollingFeeBurn(unittest.TestCase):
    """Binary round-trip: encode a snapshot with a rolling_fee_burn
    list, decode it, and confirm the list survives byte-for-byte."""

    def test_wire_roundtrip(self):
        from messagechain.storage.state_snapshot import (
            encode_snapshot, decode_snapshot, STATE_SNAPSHOT_VERSION,
        )
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 14)
        snap = _blank_snapshot()
        snap["rolling_fee_burn"] = [
            (100, 5000),
            (200, 10_000),
            (300, 1234567),
        ]
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["rolling_fee_burn"],
            [(100, 5000), (200, 10_000), (300, 1234567)],
        )


class TestNetInflationInvariant(unittest.TestCase):
    """The supply invariant must hold across v2 activation even when
    the rebate fires."""

    def test_invariant_holds_post_v2_with_rebate(self):
        supply = SupplyTracker()
        supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        # Window full of heavy burn — rebate fires.
        supply.rolling_fee_burn = [
            (POST_V2_HEIGHT - 1 - i, 1000)
            for i in range(DEFLATION_REBATE_WINDOW_BLOCKS)
        ]
        baseline_gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        supply.balances[PROPOSER] = 0
        result = supply.mint_block_reward(
            PROPOSER, block_height=POST_V2_HEIGHT,
        )
        # Verify the rebate actually fired.
        self.assertEqual(result["total_reward"], 700)
        gap = (
            supply.total_supply
            - (GENESIS_SUPPLY + supply.total_minted - supply.total_burned)
        )
        self.assertEqual(gap, baseline_gap)


# ── Helpers ──────────────────────────────────────────────────────────

def _blank_snapshot() -> dict:
    from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
    return {
        "version": STATE_SNAPSHOT_VERSION,
        "balances": {},
        "nonces": {},
        "staked": {},
        "public_keys": {},
        "authority_keys": {},
        "leaf_watermarks": {},
        "key_rotation_counts": {},
        "revoked_entities": set(),
        "slashed_validators": set(),
        "entity_id_to_index": {},
        "next_entity_index": 1,
        "total_supply": 0,
        "total_minted": 0,
        "total_fees_collected": 0,
        "total_burned": 0,
        "base_fee": 0,
        "finalized_checkpoints": {},
        "seed_initial_stakes": {},
        "seed_divestment_debt": {},
        "archive_reward_pool": 0,
        "censorship_pending": {},
        "censorship_processed": set(),
        "receipt_subtree_roots": {},
        "bogus_rejection_processed": set(),
        "inclusion_list_active": {},
        "inclusion_list_processed_violations": set(),
        "validator_archive_misses": {},
        "validator_first_active_block": {},
        "archive_active_snapshot": None,
        "validator_archive_success_streak": {},
        "lottery_prize_pool": 0,
        "attester_coverage_misses": {},
        "treasury_spend_rolling_debits": [],
        "attester_epoch_earnings": {},
        "attester_epoch_earnings_start": -1,
        "non_response_processed": set(),
        "witness_ack_registry": {},
        "rolling_fee_burn": [],
    }


if __name__ == "__main__":
    unittest.main()
