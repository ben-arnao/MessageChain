"""Tier 47 — Dormancy-filtered active-supply controller.

Anchored in CLAUDE.md "Issuance targets a stable active supply, not a
fixed schedule."  Replaces the legacy halving + deflation-floor levers
with a proportional refill controller targeting a fixed nominal point
for `active_supply` (= sum of balances filtered by how recently their
owner was active).

This file covers the structural invariants:
  * Smooth-taper dormancy weight at every boundary.
  * Controller output at-target / below-target / max-clamp.
  * Pre-fork legacy schedule preserved byte-for-byte (regression
    guard against the height-gate breaking re-validation).
  * SparseMerkleTree leaf hash byte-identical to legacy when
    last_active_height == 0 (data-driven gate, not height-gate).
  * Activity bump dispatcher iterates every kind in
    _BLOCK_TX_LIST_ATTRS and yields the right signer field.
  * Activation backfill is one-shot and idempotent.
  * Reorg snapshot/restore round-trips the dormancy state.
  * ChainDB persistence: bump_active mirrors to disk, cold-start
    rehydrates the dict.
"""

import os
import tempfile
import unittest

from messagechain.config import (
    DORMANCY_CONTROLLER_HEIGHT,
    DORMANCY_WINDOW_BLOCKS,
    DORMANCY_TAPER_BLOCKS,
    DORMANCY_TARGET_ACTIVE_SUPPLY,
    DORMANCY_CONTROLLER_K_NUM,
    DORMANCY_CONTROLLER_K_DEN,
    DORMANCY_MAX_ISSUANCE_PER_BLOCK,
    BLOCK_REWARD,
    BLOCK_REWARD_FLOOR,
    HALVING_INTERVAL,
)
from messagechain.economics.inflation import SupplyTracker
from messagechain.core.state_tree import _leaf_value


# ───────── 1. Taper math ───────────────────────────────────────────

class TestDormancyWeightTaper(unittest.TestCase):
    """Boundary checks on _dormancy_weight_bps."""

    def setUp(self):
        self.s = SupplyTracker()

    def test_age_zero_full_active(self):
        self.assertEqual(self.s._dormancy_weight_bps(0), 10_000)

    def test_age_negative_full_active(self):
        # Defensive: a "future" last_active should not falsely dormant
        # an entity.  Caller invariants prevent this in practice.
        self.assertEqual(self.s._dormancy_weight_bps(-1), 10_000)

    def test_age_just_below_cliff_full_active(self):
        cliff = DORMANCY_WINDOW_BLOCKS - DORMANCY_TAPER_BLOCKS
        self.assertEqual(self.s._dormancy_weight_bps(cliff - 1), 10_000)

    def test_age_at_cliff_full_active(self):
        # Cliff = WINDOW - TAPER is the FIRST age that enters the
        # taper.  By formula 10_000 * (WINDOW - cliff) // TAPER =
        # 10_000 * TAPER // TAPER = 10_000 — the boundary value is
        # still 100% active, taper begins strictly above the cliff.
        cliff = DORMANCY_WINDOW_BLOCKS - DORMANCY_TAPER_BLOCKS
        self.assertEqual(self.s._dormancy_weight_bps(cliff), 10_000)

    def test_age_mid_taper_about_half(self):
        cliff = DORMANCY_WINDOW_BLOCKS - DORMANCY_TAPER_BLOCKS
        mid = cliff + DORMANCY_TAPER_BLOCKS // 2
        # Linear interpolation midpoint should land at ~5000 bps.
        weight = self.s._dormancy_weight_bps(mid)
        self.assertGreaterEqual(weight, 4_999)
        self.assertLessEqual(weight, 5_001)

    def test_age_just_below_window_near_zero(self):
        # One block before the window cliff, weight is small (a few
        # bps depending on TAPER granularity) but not yet zero.
        weight = self.s._dormancy_weight_bps(DORMANCY_WINDOW_BLOCKS - 1)
        self.assertLess(weight, 100)
        self.assertGreaterEqual(weight, 0)

    def test_age_at_window_zero(self):
        self.assertEqual(
            self.s._dormancy_weight_bps(DORMANCY_WINDOW_BLOCKS), 0,
        )

    def test_age_far_past_window_zero(self):
        self.assertEqual(
            self.s._dormancy_weight_bps(DORMANCY_WINDOW_BLOCKS * 10), 0,
        )


# ───────── 2. compute_active_supply ────────────────────────────────

class TestComputeActiveSupply(unittest.TestCase):
    """active_supply = Σ balance × weight_bps // 10_000."""

    def test_empty_supply_zero(self):
        s = SupplyTracker()
        s.balances = {}
        s.staked = {}
        self.assertEqual(s.compute_active_supply(DORMANCY_CONTROLLER_HEIGHT), 0)

    def test_all_active_equals_total_supply_when_recent(self):
        s = SupplyTracker()
        s.balances = {b"A" * 32: 100, b"B" * 32: 200, b"C" * 32: 300}
        h = DORMANCY_CONTROLLER_HEIGHT + 1000
        # All bumped at h → age=0 → 100% active.
        for eid in s.balances:
            s.bump_active(eid, h)
        self.assertEqual(s.compute_active_supply(h), 600)

    def test_dormant_entities_excluded(self):
        s = SupplyTracker()
        # Use a current_height beyond WINDOW so default-0 last_active
        # entities show as dormant.
        h = DORMANCY_WINDOW_BLOCKS + 100
        s.balances = {b"A" * 32: 100, b"B" * 32: 200}
        # A is dormant (default last_active=0 → age = h, past window).
        # B is active (just bumped).
        s.bump_active(b"B" * 32, h)
        self.assertEqual(s.compute_active_supply(h), 200)

    def test_taper_partial_weight(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_HEIGHT + DORMANCY_WINDOW_BLOCKS + 100
        s.balances = {b"X" * 32: 1000}
        # Bump at exactly the taper midpoint → weight ≈ 5000 bps.
        cliff = DORMANCY_WINDOW_BLOCKS - DORMANCY_TAPER_BLOCKS
        mid_age = cliff + DORMANCY_TAPER_BLOCKS // 2
        s.bump_active(b"X" * 32, h - mid_age)
        active = s.compute_active_supply(h)
        # 1000 * ~5000 / 10_000 = ~500
        self.assertGreaterEqual(active, 499)
        self.assertLessEqual(active, 501)

    def test_zero_balance_zero_contribution(self):
        s = SupplyTracker()
        s.balances = {b"A" * 32: 0}
        s.bump_active(b"A" * 32, DORMANCY_CONTROLLER_HEIGHT)
        self.assertEqual(s.compute_active_supply(DORMANCY_CONTROLLER_HEIGHT), 0)

    def test_staked_balances_count(self):
        s = SupplyTracker()
        h = DORMANCY_CONTROLLER_HEIGHT + 100
        s.balances = {}
        s.staked = {b"V" * 32: 10_000}
        s.bump_active(b"V" * 32, h)
        self.assertEqual(s.compute_active_supply(h), 10_000)


# ───────── 2b. Treasury is excluded from active_supply ─────────────

class TestTreasuryExcludedFromActiveSupply(unittest.TestCase):
    """Treasury balance is governance state, not a live economic user.

    Without the exclusion, founder (100M) + treasury (40M) = exactly
    GENESIS_SUPPLY = DORMANCY_TARGET_ACTIVE_SUPPLY (140M), so at Tier-47
    activation the controller computes gap=0 and mints zero — for ~25
    years (until the dormancy window expires).  Excluding treasury
    pulls active_supply to 100M (founder only), gap=40M, and the
    controller mints at the configured per-block rate.

    Anchor: CLAUDE.md "stake/attestation/proposal activity counts as
    active without a transfer" — treasury never produces any of those
    signals, so absent this skip it would forever be max-weighted and
    the gap would never close.
    """

    def setUp(self):
        from messagechain.config import TREASURY_ENTITY_ID
        self.TREASURY = TREASURY_ENTITY_ID
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_HEIGHT + 100

    def test_treasury_balance_excluded_from_active_supply(self):
        # Treasury alone, just-bumped → would be 40M without exclusion.
        self.s.balances = {self.TREASURY: 40_000_000}
        self.s.bump_active(self.TREASURY, self.h)
        self.assertEqual(self.s.compute_active_supply(self.h), 0)

    def test_treasury_staked_excluded_from_active_supply(self):
        # Defensive: treasury never stakes today, but if a future
        # governance lever moved tokens into staked under the same
        # entity_id, the exclusion must hold there too.
        self.s.balances = {}
        self.s.staked = {self.TREASURY: 40_000_000}
        self.s.bump_active(self.TREASURY, self.h)
        self.assertEqual(self.s.compute_active_supply(self.h), 0)

    def test_founder_plus_treasury_at_target_still_yields_gap(self):
        # The exact mainnet shape at Tier-47 activation: founder=100M,
        # treasury=40M, sum=GENESIS_SUPPLY=TARGET.  Without the fix,
        # gap=0 and controller mints 0.  With the fix, treasury drops
        # out, active_supply=100M, gap=40M, controller mints non-zero.
        founder = b"F" * 32
        self.s.balances = {founder: 100_000_000, self.TREASURY: 40_000_000}
        self.s.bump_active(founder, self.h)
        self.s.bump_active(self.TREASURY, self.h)
        active = self.s.compute_active_supply(self.h)
        self.assertEqual(active, 100_000_000)
        gap = DORMANCY_TARGET_ACTIVE_SUPPLY - active
        self.assertEqual(gap, 40_000_000)
        # Controller must mint a positive amount, not zero.
        issuance = self.s.compute_dormancy_issuance(self.h)
        self.assertGreater(issuance, 0)
        # And it should be capped at the per-block ceiling.
        self.assertLessEqual(issuance, DORMANCY_MAX_ISSUANCE_PER_BLOCK)

    def test_treasury_excluded_alongside_other_holders(self):
        # Mixed: a regular holder + treasury, both active.  Active supply
        # must equal the regular holder's balance only.
        a = b"A" * 32
        self.s.balances = {a: 5_000_000, self.TREASURY: 40_000_000}
        self.s.bump_active(a, self.h)
        self.s.bump_active(self.TREASURY, self.h)
        self.assertEqual(self.s.compute_active_supply(self.h), 5_000_000)


# ───────── 3. Controller output ────────────────────────────────────

class TestDormancyController(unittest.TestCase):

    def setUp(self):
        self.s = SupplyTracker()
        self.h = DORMANCY_CONTROLLER_HEIGHT + 100

    def test_at_target_zero_issuance(self):
        # active_supply == TARGET → gap = 0 → issuance = 0.
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY}
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_above_target_zero_issuance(self):
        # gap = TARGET - active.  If active > TARGET, gap is negative,
        # the helper clamps to 0.
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY * 2}
        self.s.bump_active(b"X" * 32, self.h)
        self.assertEqual(self.s.compute_dormancy_issuance(self.h), 0)

    def test_zero_supply_clamps_to_max(self):
        self.s.balances = {}
        # active=0, gap=TARGET, issuance=TARGET//K which is huge —
        # clamped to MAX.
        self.assertEqual(
            self.s.compute_dormancy_issuance(self.h),
            DORMANCY_MAX_ISSUANCE_PER_BLOCK,
        )

    def test_small_gap_proportional(self):
        # gap = K_DEN tokens → raw issuance = 1 → not yet at clamp.
        gap = DORMANCY_CONTROLLER_K_DEN
        self.s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY - gap}
        self.s.bump_active(b"X" * 32, self.h)
        expected = (gap * DORMANCY_CONTROLLER_K_NUM) // DORMANCY_CONTROLLER_K_DEN
        self.assertEqual(
            self.s.compute_dormancy_issuance(self.h),
            min(DORMANCY_MAX_ISSUANCE_PER_BLOCK, expected),
        )


# ───────── 4. Pre-fork legacy schedule preserved ───────────────────

class TestLegacyScheduleByteForByte(unittest.TestCase):
    """The Tier-47 dispatch must preserve pre-fork output byte-for-byte
    so re-validation of historical blocks works on upgraded nodes."""

    def test_pre_fork_routes_through_legacy(self):
        s = SupplyTracker()
        # Heights below activation should produce the legacy schedule
        # output.  At height 0, that's BLOCK_REWARD = 16.
        legacy = s._calculate_legacy_block_reward(0)
        dispatch = s.calculate_block_reward(0)
        self.assertEqual(dispatch, legacy)
        self.assertEqual(dispatch, BLOCK_REWARD)

    def test_post_fork_routes_through_controller(self):
        s = SupplyTracker()
        # Above activation, dispatch must NOT match the legacy formula
        # — it should produce controller output, which for a default
        # SupplyTracker (empty balances) is MAX_ISSUANCE_PER_BLOCK.
        dispatch = s.calculate_block_reward(DORMANCY_CONTROLLER_HEIGHT + 1)
        self.assertEqual(dispatch, DORMANCY_MAX_ISSUANCE_PER_BLOCK)
        legacy = s._calculate_legacy_block_reward(
            DORMANCY_CONTROLLER_HEIGHT + 1,
        )
        # Legacy at this height is BLOCK_REWARD (no halvings yet) =
        # 16; controller output is the clamp = 64.  They differ —
        # confirms dispatch took the controller path.
        self.assertNotEqual(dispatch, legacy)

    def test_at_activation_height_routes_through_controller(self):
        # The boundary is `>=`, so the activation height itself is
        # post-fork.  Pre-fork is strictly below.
        s = SupplyTracker()
        self.assertEqual(
            s.calculate_block_reward(DORMANCY_CONTROLLER_HEIGHT - 1),
            s._calculate_legacy_block_reward(DORMANCY_CONTROLLER_HEIGHT - 1),
        )
        # At exactly activation, controller fires.
        self.assertEqual(
            s.calculate_block_reward(DORMANCY_CONTROLLER_HEIGHT),
            s.compute_dormancy_issuance(DORMANCY_CONTROLLER_HEIGHT),
        )


# ───────── 5. Leaf hash backwards-compatible ───────────────────────

class TestLeafHashBackwardsCompat(unittest.TestCase):
    """_leaf_value with last_active_height=0 must produce byte-
    identical output to the pre-Tier-47 hash, and a non-zero value
    must produce a different (but deterministic) hash."""

    def test_default_zero_byte_identical_to_legacy(self):
        # Reconstruct what the pre-Tier-47 hash body looked like, then
        # hash via the chain's canonical hash function.  Equivalence
        # to _leaf_value(last_active_height=0) proves the Tier-47
        # extension is data-driven (0 contributes nothing), not a
        # hash-format change.
        import struct
        from messagechain.crypto.hashing import default_hash
        eid = b"E" * 32
        ak = b""
        pk = b"\xab" * 32
        legacy_input = (
            eid
            + struct.pack(">Q", 1234)
            + struct.pack(">Q", 5)
            + struct.pack(">Q", 67890)
            + struct.pack(">H", len(ak)) + ak
            + struct.pack(">H", len(pk)) + pk
            + struct.pack(">Q", 7)
            + struct.pack(">Q", 2)
            + b"\x00" + b"\x00"
        )
        legacy_hash = default_hash(legacy_input)
        new_hash = _leaf_value(
            eid, 1234, 5, 67890,
            authority_key=ak, public_key=pk,
            leaf_watermark=7, rotation_count=2,
            is_revoked=False, is_slashed=False,
            last_active_height=0,
        )
        self.assertEqual(new_hash, legacy_hash)

    def test_nonzero_dormancy_changes_hash(self):
        eid = b"E" * 32
        h0 = _leaf_value(eid, 100, 0, 0, last_active_height=0)
        h1 = _leaf_value(eid, 100, 0, 0, last_active_height=1)
        h2 = _leaf_value(eid, 100, 0, 0, last_active_height=2)
        self.assertNotEqual(h0, h1)
        self.assertNotEqual(h1, h2)

    def test_dormancy_height_deterministic(self):
        eid = b"E" * 32
        # Same input → same hash.
        h_a = _leaf_value(eid, 100, 0, 0, last_active_height=12345)
        h_b = _leaf_value(eid, 100, 0, 0, last_active_height=12345)
        self.assertEqual(h_a, h_b)


# ───────── 6. bump_active monotonicity ─────────────────────────────

class TestBumpActiveMonotonic(unittest.TestCase):

    def test_higher_height_wins(self):
        s = SupplyTracker()
        eid = b"E" * 32
        s.bump_active(eid, 100)
        s.bump_active(eid, 200)
        self.assertEqual(s.last_active_heights[eid], 200)

    def test_lower_height_ignored(self):
        s = SupplyTracker()
        eid = b"E" * 32
        s.bump_active(eid, 200)
        s.bump_active(eid, 100)
        self.assertEqual(s.last_active_heights[eid], 200)

    def test_equal_height_noop(self):
        s = SupplyTracker()
        eid = b"E" * 32
        s.bump_active(eid, 200)
        s.bump_active(eid, 200)
        self.assertEqual(s.last_active_heights[eid], 200)


# ───────── 7. get_supply_stats exposes dormancy fields ─────────────

class TestSupplyStatsExposesDormancy(unittest.TestCase):

    def test_active_supply_present(self):
        s = SupplyTracker()
        stats = s.get_supply_stats(DORMANCY_CONTROLLER_HEIGHT + 1)
        self.assertIn("active_supply", stats)
        self.assertIn("dormancy_target_active_supply", stats)
        self.assertIn("dormancy_gap", stats)
        self.assertIn("dormancy_window_blocks", stats)
        self.assertIn("dormancy_taper_blocks", stats)
        self.assertIn("dormancy_controller_height", stats)
        self.assertIn("dormancy_backfill_applied", stats)

    def test_target_constant_matches(self):
        s = SupplyTracker()
        stats = s.get_supply_stats(0)
        self.assertEqual(
            stats["dormancy_target_active_supply"],
            DORMANCY_TARGET_ACTIVE_SUPPLY,
        )

    def test_gap_is_target_minus_active(self):
        s = SupplyTracker()
        s.balances = {b"X" * 32: DORMANCY_TARGET_ACTIVE_SUPPLY // 4}
        s.bump_active(b"X" * 32, DORMANCY_CONTROLLER_HEIGHT)
        stats = s.get_supply_stats(DORMANCY_CONTROLLER_HEIGHT)
        expected_gap = (
            DORMANCY_TARGET_ACTIVE_SUPPLY
            - DORMANCY_TARGET_ACTIVE_SUPPLY // 4
        )
        self.assertEqual(stats["dormancy_gap"], expected_gap)


# ───────── 8. Activation backfill ──────────────────────────────────

class TestActivationBackfill(unittest.TestCase):
    """The one-shot backfill at DORMANCY_CONTROLLER_HEIGHT stamps every
    existing balance/stake holder with last_active = activation_height,
    is idempotent, and is reorg-safe."""

    def _make_chain(self):
        from messagechain.core.blockchain import Blockchain
        return Blockchain()

    def test_backfill_stamps_balance_holders(self):
        chain = self._make_chain()
        # Plant some balances pre-fork.
        chain.supply.balances = {
            b"A" * 32: 100,
            b"B" * 32: 200,
            b"C" * 32: 300,
        }
        # Plant a staker too.
        chain.supply.staked = {b"V" * 32: 5_000}
        # Run the backfill via the helper directly (no need to mint a
        # whole block).
        chain._apply_dormancy_for_block(
            DORMANCY_CONTROLLER_HEIGHT, signers=iter(()),
        )
        for eid in (b"A" * 32, b"B" * 32, b"C" * 32, b"V" * 32):
            self.assertEqual(
                chain.supply.last_active_heights[eid],
                DORMANCY_CONTROLLER_HEIGHT,
            )
        self.assertTrue(chain.supply.dormancy_backfill_applied)

    def test_backfill_idempotent(self):
        chain = self._make_chain()
        chain.supply.balances = {b"A" * 32: 100}
        chain._apply_dormancy_for_block(
            DORMANCY_CONTROLLER_HEIGHT, signers=iter(()),
        )
        # Mutate a pre-existing entry, then call again — the flag
        # short-circuits and the entry is preserved.
        chain.supply.last_active_heights[b"A" * 32] = (
            DORMANCY_CONTROLLER_HEIGHT + 500
        )
        chain._apply_dormancy_for_block(
            DORMANCY_CONTROLLER_HEIGHT + 1, signers=iter(()),
        )
        self.assertEqual(
            chain.supply.last_active_heights[b"A" * 32],
            DORMANCY_CONTROLLER_HEIGHT + 500,
        )

    def test_pre_fork_backfill_not_applied(self):
        chain = self._make_chain()
        chain.supply.balances = {b"A" * 32: 100}
        # At a height below activation, the helper short-circuits and
        # does nothing.
        chain._apply_dormancy_for_block(
            DORMANCY_CONTROLLER_HEIGHT - 1, signers=iter(()),
        )
        self.assertFalse(chain.supply.dormancy_backfill_applied)
        self.assertNotIn(b"A" * 32, chain.supply.last_active_heights)


# ───────── 9. Reorg snapshot/restore round-trip ────────────────────

class TestReorgSnapshotRoundTrip(unittest.TestCase):
    """_snapshot_memory_state captures last_active_heights and
    dormancy_backfill_applied; _restore_memory_snapshot replays them."""

    def test_round_trip_preserves_dict(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        chain.supply.last_active_heights = {
            b"A" * 32: 1000,
            b"B" * 32: 2000,
        }
        chain.supply.dormancy_backfill_applied = True
        snap = chain._snapshot_memory_state()
        # Clobber.
        chain.supply.last_active_heights = {b"Z" * 32: 9999}
        chain.supply.dormancy_backfill_applied = False
        chain._restore_memory_snapshot(snap)
        self.assertEqual(
            chain.supply.last_active_heights,
            {b"A" * 32: 1000, b"B" * 32: 2000},
        )
        self.assertTrue(chain.supply.dormancy_backfill_applied)

    def test_legacy_snapshot_restores_default(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        # A snapshot that predates Tier-47 will have neither key —
        # restore should default both to the pristine pre-fork state.
        snap = chain._snapshot_memory_state()
        snap.pop("last_active_heights", None)
        snap.pop("dormancy_backfill_applied", None)
        # Set non-defaults so we can detect the restore-to-default.
        chain.supply.last_active_heights = {b"X" * 32: 1234}
        chain.supply.dormancy_backfill_applied = True
        chain._restore_memory_snapshot(snap)
        self.assertEqual(chain.supply.last_active_heights, {})
        self.assertFalse(chain.supply.dormancy_backfill_applied)


# ───────── 10. ChainDB persistence round-trip ──────────────────────

class TestChainDBPersistenceRoundTrip(unittest.TestCase):
    """bump_active mirrors the write into the entity_last_active table;
    a fresh ChainDB read produces the same dict."""

    def test_set_get_round_trip(self):
        from messagechain.storage.chaindb import ChainDB
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "chain.db")
            db = ChainDB(db_path)
            try:
                db.set_last_active_height(b"A" * 32, 5934)
                db.set_last_active_height(b"B" * 32, 12345)
                # Re-write to test INSERT OR REPLACE.
                db.set_last_active_height(b"A" * 32, 6000)
                # set_last_active_height auto-commits via _maybe_commit;
                # explicit no-op here for clarity.
                # Read all back.
                rehydrated = db.get_all_last_active_heights()
                self.assertEqual(
                    rehydrated,
                    {b"A" * 32: 6000, b"B" * 32: 12345},
                )
            finally:
                db.close()

    def test_clear_removes_entry(self):
        from messagechain.storage.chaindb import ChainDB
        with tempfile.TemporaryDirectory() as tmp:
            db = ChainDB(os.path.join(tmp, "chain.db"))
            try:
                db.set_last_active_height(b"A" * 32, 100)
                db.set_last_active_height(b"B" * 32, 200)
                db.clear_last_active_height(b"A" * 32)
                # set_last_active_height auto-commits via _maybe_commit;
                # explicit no-op here for clarity.
                self.assertEqual(
                    db.get_all_last_active_heights(),
                    {b"B" * 32: 200},
                )
            finally:
                db.close()

    def test_bump_active_mirrors_when_db_set(self):
        from messagechain.storage.chaindb import ChainDB
        with tempfile.TemporaryDirectory() as tmp:
            db = ChainDB(os.path.join(tmp, "chain.db"))
            try:
                s = SupplyTracker()
                s.db = db
                s.bump_active(b"E" * 32, 12345)
                # set_last_active_height auto-commits via _maybe_commit;
                # explicit no-op here for clarity.
                self.assertEqual(
                    db.get_all_last_active_heights(),
                    {b"E" * 32: 12345},
                )
                # Lower-height bump is a dict no-op AND a DB no-op.
                s.bump_active(b"E" * 32, 100)
                # set_last_active_height auto-commits via _maybe_commit;
                # explicit no-op here for clarity.
                self.assertEqual(
                    db.get_all_last_active_heights(),
                    {b"E" * 32: 12345},
                )
            finally:
                db.close()


# ───────── 11. Signer dispatcher for activity bumps ────────────────

class TestSignerDispatcher(unittest.TestCase):
    """_signer_of probes a deterministic field order and returns the
    first match.  Every tx kind in _BLOCK_TX_LIST_ATTRS must yield a
    signer through this dispatcher (or be explicitly None in
    _DORMANCY_SIGNER_ATTRS)."""

    def test_message_tx_yields_entity_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            entity_id = b"E" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"E" * 32)

    def test_react_tx_yields_voter_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            voter_id = b"V" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"V" * 32)

    def test_attestation_yields_validator_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            validator_id = b"V" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"V" * 32)

    def test_evidence_yields_submitter_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            submitter_id = b"S" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"S" * 32)

    def test_finality_vote_yields_signer_entity_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            signer_entity_id = b"V" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"V" * 32)

    def test_custody_proof_yields_prover_id(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            prover_id = b"P" * 32
        self.assertEqual(Blockchain._signer_of(Fake()), b"P" * 32)

    def test_no_signer_field_returns_none(self):
        from messagechain.core.blockchain import Blockchain
        class Fake:
            unrelated = 42
        self.assertIsNone(Blockchain._signer_of(Fake()))


# ───────── 12. Iter signers covers proposer + every kind ───────────

class TestIterBlockSigners(unittest.TestCase):

    def test_proposer_yielded_first(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        signers = list(chain._iter_block_signers(
            proposer_id=b"P" * 32,
        ))
        self.assertEqual(signers, [b"P" * 32])

    def test_includes_all_signed_actors(self):
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        class _M:
            entity_id = b"M" * 32
        class _T:
            entity_id = b"T" * 32
        class _A:
            validator_id = b"A" * 32
        class _R:
            voter_id = b"R" * 32
        signers = list(chain._iter_block_signers(
            proposer_id=b"P" * 32,
            transactions=[_M()],
            transfer_transactions=[_T()],
            attestations=[_A()],
            react_transactions=[_R()],
        ))
        self.assertIn(b"P" * 32, signers)
        self.assertIn(b"M" * 32, signers)
        self.assertIn(b"T" * 32, signers)
        self.assertIn(b"A" * 32, signers)
        self.assertIn(b"R" * 32, signers)


if __name__ == "__main__":
    unittest.main()
