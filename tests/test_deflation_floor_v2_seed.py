"""Tests for the fee-responsive deflation-floor activation-seed fix.

Background
----------
The v2 fork (DEFLATION_FLOOR_V2_HEIGHT) replaces the fixed 2× multiplier
with a fee-responsive rebate driven by ``SupplyTracker.rolling_fee_burn``
— a rolling window of (block_height, actual_burn) entries appended by
``pay_fee_with_burn`` at/after activation.

Latent gap: at exactly the activation block the rolling window is empty,
so the first ~DEFLATION_REBATE_WINDOW_BLOCKS post-activation blocks
compute rate = 0 and fall back to base_reward.  If total_supply was
< TARGET at activation (the only case where the fork matters), that's
roughly one week at full deflation with zero defense — defeating the
fork at exactly the moment it's needed.

Fix: seed ``rolling_fee_burn`` once at activation from the lifetime
burn-per-block average (``total_burned // block_height``), placed at
the oldest edge of the window so the synthetic entry rotates out over
DEFLATION_REBATE_WINDOW_BLOCKS of real accumulation.  One-shot per
canonical chain history, guarded by ``rolling_fee_burn_seeded``
(mirrors ``treasury_rebase_applied``).
"""

import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.core.blockchain import Blockchain
from messagechain.config import (
    BLOCK_REWARD,
    TARGET_CIRCULATING_SUPPLY_FLOOR,
    DEFLATION_FLOOR_V2_HEIGHT,
    DEFLATION_REBATE_BPS,
    DEFLATION_REBATE_WINDOW_BLOCKS,
)


PRE_V2_HEIGHT = DEFLATION_FLOOR_V2_HEIGHT - 1
POST_V2_HEIGHT = DEFLATION_FLOOR_V2_HEIGHT


class TestSeedFlagDefault(unittest.TestCase):
    """Fresh SupplyTracker has the seeded flag at False."""

    def test_flag_default_false(self):
        supply = SupplyTracker()
        self.assertTrue(hasattr(supply, "rolling_fee_burn_seeded"))
        self.assertFalse(supply.rolling_fee_burn_seeded)


class TestPreActivationSeedDoesNotFire(unittest.TestCase):
    """Before DEFLATION_FLOOR_V2_HEIGHT the seed step is a no-op.

    Flag stays False; rolling_fee_burn stays empty.  Byte-for-byte
    preservation of legacy behavior at heights below activation.
    """

    def test_flag_stays_false_pre_activation(self):
        bc = Blockchain()
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(PRE_V2_HEIGHT)
        self.assertFalse(bc.supply.rolling_fee_burn_seeded)
        self.assertEqual(bc.supply.rolling_fee_burn, [])


class TestAtActivationSeedFires(unittest.TestCase):
    """At DEFLATION_FLOOR_V2_HEIGHT the seed fires exactly once.

    Flag flips True, synthetic entry appears in rolling_fee_burn with
    (seed_height, synthetic_total) derived from lifetime burn rate.
    """

    def test_flag_flips_at_activation(self):
        bc = Blockchain()
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        self.assertTrue(bc.supply.rolling_fee_burn_seeded)

    def test_synthetic_entry_matches_lifetime_rate(self):
        bc = Blockchain()
        # Lifetime: 1,000,000 burned over POST_V2_HEIGHT blocks.
        # avg_per_block = 1_000_000 // POST_V2_HEIGHT
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        avg_per_block = 1_000_000 // POST_V2_HEIGHT
        synthetic_total = avg_per_block * DEFLATION_REBATE_WINDOW_BLOCKS
        seed_height = max(0, POST_V2_HEIGHT - DEFLATION_REBATE_WINDOW_BLOCKS + 1)
        self.assertEqual(bc.supply.rolling_fee_burn, [(seed_height, synthetic_total)])

    def test_rebate_fires_on_first_post_activation_block(self):
        """With supply < TARGET and nonzero lifetime burn, the FIRST
        post-activation block's issuance MUST exceed base_reward.
        Proves the ramp-up gap is closed — no week-long defense-off
        window post-activation."""
        bc = Blockchain()
        # Lifetime burn rate picked so rebate clearly exceeds base_reward.
        # Need rate such that rate * 7000 / 10000 > BLOCK_REWARD (16).
        # rate > 16 * 10000 / 7000 ≈ 23.  Use rate = 100 tokens/block.
        bc.supply.total_burned = 100 * POST_V2_HEIGHT
        bc.supply.total_supply = TARGET_CIRCULATING_SUPPLY_FLOOR - 1
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        reward = bc.supply.calculate_block_reward(POST_V2_HEIGHT)
        # synthetic_total covers the full window, so rolling_rate ≈ 100
        # → rebate ≈ 70.  That exceeds BLOCK_REWARD=16.
        self.assertGreater(reward, BLOCK_REWARD)


class TestPostActivationDoesNotReSeed(unittest.TestCase):
    """After the first firing the flag guards against re-seeding.

    A second call at the activation height (or any later height) leaves
    rolling_fee_burn unchanged.
    """

    def test_second_call_at_activation_is_noop(self):
        bc = Blockchain()
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        first_state = list(bc.supply.rolling_fee_burn)
        # Mutate total_burned — a re-seed would use the new value.
        bc.supply.total_burned = 999_999_999_999
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        self.assertEqual(bc.supply.rolling_fee_burn, first_state)

    def test_call_at_later_height_is_noop(self):
        bc = Blockchain()
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        first_state = list(bc.supply.rolling_fee_burn)
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT + 500)
        self.assertEqual(bc.supply.rolling_fee_burn, first_state)
        self.assertTrue(bc.supply.rolling_fee_burn_seeded)


class TestColdStartNoBurnHistory(unittest.TestCase):
    """total_burned == 0 at activation: no synthetic entry added
    (avoid zero-amount noise in the rolling list), but the flag still
    flips so the guard works."""

    def test_zero_burn_no_entry_flag_flips(self):
        bc = Blockchain()
        bc.supply.total_burned = 0
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        self.assertTrue(bc.supply.rolling_fee_burn_seeded)
        self.assertEqual(bc.supply.rolling_fee_burn, [])


class TestReorgRollbackUnfiresSeed(unittest.TestCase):
    """Snapshot taken pre-mutation, mutation applied, restore: the
    flag and the synthetic entry both rewind to pre-mutation state.

    Exercises the reorg path past the activation block.
    """

    def test_snapshot_restore_reverts_seed_state(self):
        bc = Blockchain()
        # Pre-seed state: fresh tracker, flag False, list empty.
        snap = bc._snapshot_memory_state()
        # Simulate "reached activation, seed fired".
        bc.supply.total_burned = 1_000_000
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        self.assertTrue(bc.supply.rolling_fee_burn_seeded)
        self.assertNotEqual(bc.supply.rolling_fee_burn, [])
        # Reorg rollback — snapshot predates the activation block.
        bc._restore_memory_snapshot(snap)
        self.assertFalse(bc.supply.rolling_fee_burn_seeded)
        self.assertEqual(bc.supply.rolling_fee_burn, [])

    def test_replay_after_rollback_re_fires_cleanly(self):
        """After rolling back to pre-activation state, a replay across
        the activation block must re-seed with the same deterministic
        synthetic entry."""
        bc = Blockchain()
        bc.supply.total_burned = 1_000_000
        snap = bc._snapshot_memory_state()
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        first_list = list(bc.supply.rolling_fee_burn)
        # Reorg-rollback: snapshot captured the same total_burned, so
        # replay must produce byte-identical result.
        bc._restore_memory_snapshot(snap)
        self.assertFalse(bc.supply.rolling_fee_burn_seeded)
        bc._apply_deflation_floor_v2_seed(POST_V2_HEIGHT)
        self.assertEqual(bc.supply.rolling_fee_burn, first_list)


class TestWireRoundTripSeedFlag(unittest.TestCase):
    """Binary encode/decode preserves rolling_fee_burn_seeded across
    a wire round-trip — v17 bump."""

    def test_wire_version_is_at_least_17(self):
        from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 17)

    def test_seed_flag_survives_encode_decode_true(self):
        from messagechain.storage.state_snapshot import (
            encode_snapshot, decode_snapshot,
        )
        snap = _blank_snapshot()
        snap["rolling_fee_burn_seeded"] = True
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertTrue(decoded["rolling_fee_burn_seeded"])

    def test_seed_flag_survives_encode_decode_false(self):
        from messagechain.storage.state_snapshot import (
            encode_snapshot, decode_snapshot,
        )
        snap = _blank_snapshot()
        snap["rolling_fee_burn_seeded"] = False
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertFalse(decoded["rolling_fee_burn_seeded"])


class TestStateRootCommitsSeedFlag(unittest.TestCase):
    """Mutating rolling_fee_burn_seeded changes compute_state_root so a
    state-synced node that inherited a stale flag is detectable."""

    def test_mutation_changes_state_root(self):
        from messagechain.storage.state_snapshot import compute_state_root
        base = _blank_snapshot()
        base["rolling_fee_burn_seeded"] = False
        base_root = compute_state_root(base)
        mutated = dict(base)
        mutated["rolling_fee_burn_seeded"] = True
        mutated_root = compute_state_root(mutated)
        self.assertNotEqual(base_root, mutated_root)


# ── Helpers ──────────────────────────────────────────────────────────

def _blank_snapshot() -> dict:
    """Minimal snapshot dict carrying every section deserialize_state
    populates via setdefault, plus the new rolling_fee_burn_seeded
    boolean for v17 tests."""
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
        "registered_validators": set(),
        "rolling_fee_burn_seeded": False,
    }


if __name__ == "__main__":
    unittest.main()
