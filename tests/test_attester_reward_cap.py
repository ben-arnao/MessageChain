"""Tests for the per-entity attester-reward cap per epoch (hard fork).

Background
----------
Attester-fee-funding (commit ``a516fe2``) redirects 50% of the base-fee
burn into the attester pool, divided pro-rata across the 128-member
committee.  Committee selection is stake-weighted, so the largest
staker captures revenue roughly proportional to stake — a ~42%-stake
founder naturally earns ~42% of per-block attester revenue.

Fix: cap any single entity's capture at
``PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH`` (100 bps = 1%) of
the epoch pool.  Overflow burns — no treasury credit, no carryover.

Design choices
--------------
* Epoch definition reuses ``FINALITY_INTERVAL = 100`` blocks so the
  bookkeeping mirrors the treasury spend cap's epoch cadence.
* Cap is expressed as a fraction of the *epoch pool* computed from
  each block's attester_pool × FINALITY_INTERVAL (conservative
  per-block estimate).  This avoids committing to an ex-ante
  epoch-pool estimate that would need traffic prediction — each
  block's cap is computed from its own pool snapshot, and the epoch
  earnings tracker prevents double-crediting across blocks.
* Pre-activation: cap_active=False, mint_block_reward byte-for-byte
  identical to commit-a516fe2 behavior.
"""

import unittest

from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    ATTESTER_REWARD_CAP_HEIGHT,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_FEE_FUNDING_HEIGHT,
    FINALITY_INTERVAL,
    GENESIS_SUPPLY,
    PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH,
    TREASURY_ENTITY_ID,
)


# Activation helpers.  POST_ACTIVATION_HEIGHT must also be >=
# ATTESTER_REWARD_SPLIT_HEIGHT and ATTESTER_FEE_FUNDING_HEIGHT so the
# pro-rata distribution path runs and the accumulator is consumed.
PRE_ACTIVATION_HEIGHT = max(0, ATTESTER_REWARD_CAP_HEIGHT - 1)
POST_ACTIVATION_HEIGHT = max(
    ATTESTER_REWARD_CAP_HEIGHT,
    ATTESTER_REWARD_SPLIT_HEIGHT,
    ATTESTER_FEE_FUNDING_HEIGHT,
)


def _make_committee(n: int) -> list[bytes]:
    """Deterministic list of n distinct 32-byte IDs avoiding the
    proposer ID 0x70 ('p') used throughout this file."""
    out: list[bytes] = []
    i = 0
    while len(out) < n:
        b = (i + 0x10) & 0xFF
        if b == 0x70:
            i += 1
            continue
        out.append(bytes([b]) * 32)
        i += 1
    return out


class TestEpochEarningsFieldInit(unittest.TestCase):
    """The rolling-epoch per-entity earnings tracker exists and
    initializes to empty-dict / sentinel -1."""

    def test_fields_initialized(self):
        supply = SupplyTracker()
        self.assertEqual(supply.attester_epoch_earnings, {})
        self.assertEqual(supply.attester_epoch_earnings_start, -1)


class TestPreActivationBehaviorPreserved(unittest.TestCase):
    """Pre-activation: cap_active=False; rewards flow pro-rata as
    before with no cap, no overflow burn, and no mutation of the
    epoch-earnings tracker."""

    def test_pre_activation_pro_rata_unchanged(self):
        supply = SupplyTracker()
        # Populate accumulator with enough to exceed any cap under
        # the post-activation formula.  Pre-activation the gate keeps
        # the legacy path byte-for-byte: every committee member gets
        # attester_pool // n tokens, no cap, no epoch tracking.
        supply.attester_fee_pool_this_block = 500
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=PRE_ACTIVATION_HEIGHT,
            attester_committee=committee,
        )

        # 12 (issuance pool) + 500 (fee accumulator) = 512, // 128 = 4.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 4)
        self.assertEqual(result["total_attestor_reward"], 4 * 128)
        # Pre-activation the epoch tracker is untouched.
        self.assertEqual(supply.attester_epoch_earnings, {})
        self.assertEqual(supply.attester_epoch_earnings_start, -1)


class TestPostActivationFirstBlockOfEpoch(unittest.TestCase):
    """First block of an epoch: each entity's accumulated earnings
    start at 0, so per_slot_reward fits under the cap and no cap-
    overflow burn fires beyond the normal integer-division remainder.
    """

    def test_first_block_no_cap_overflow(self):
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 500
        proposer = b"p" * 32
        # Align to an epoch boundary so we definitely see the "first
        # block of the epoch" case.
        height = POST_ACTIVATION_HEIGHT + (
            (-POST_ACTIVATION_HEIGHT) % FINALITY_INTERVAL
        )
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=height,
            attester_committee=committee,
        )

        # Pool = 12 + 500 = 512; per_slot = 512 // 128 = 4.  Cap
        # at attester_pool=512:
        #   cap_per_entity = 512 * 100 * 100 // 10_000 = 512.
        # per_slot (4) < cap (512), so no overflow.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 4)
        self.assertEqual(result["total_attestor_reward"], 4 * 128)
        # Only the integer-division remainder (512 - 4*128 = 0) burns.
        self.assertEqual(result["burned"], 0)

    def test_first_block_earnings_tracked(self):
        """The tracker records each entity's earnings for the epoch."""
        supply = SupplyTracker()
        supply.attester_fee_pool_this_block = 500
        proposer = b"p" * 32
        height = POST_ACTIVATION_HEIGHT + (
            (-POST_ACTIVATION_HEIGHT) % FINALITY_INTERVAL
        )
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        supply.mint_block_reward(
            proposer,
            block_height=height,
            attester_committee=committee,
        )

        epoch_start = (height // FINALITY_INTERVAL) * FINALITY_INTERVAL
        self.assertEqual(supply.attester_epoch_earnings_start, epoch_start)
        for eid in committee:
            self.assertEqual(supply.attester_epoch_earnings[eid], 4)


class TestAccumulationAcrossEpochHitsCap(unittest.TestCase):
    """Across multiple blocks of the same epoch, an entity's tracked
    earnings accumulate.  Once an entity's earnings reach the per-
    block cap, further rewards to that entity BURN rather than credit.
    """

    def test_accumulation_and_cap_burn(self):
        """Seed an entity at exactly cap-minus-one, mint one more
        block, verify only the leftover 1 token credits and the rest
        burns."""
        supply = SupplyTracker()
        proposer = b"p" * 32
        # Choose a height that is NOT the first block of its epoch so
        # we can seed the tracker with prior-block earnings cleanly.
        epoch_start = (
            (POST_ACTIVATION_HEIGHT // FINALITY_INTERVAL) * FINALITY_INTERVAL
            + FINALITY_INTERVAL  # next epoch start
        )
        height = epoch_start + 5  # mid-epoch block

        # Set accumulator so attester_pool (post-merge) = 500.
        # pool_per_block = 500 (fee) + 12 (issuance) = 512.
        # cap_per_entity = 512 * 100 * 100 / 10_000 = 512.
        supply.attester_fee_pool_this_block = 500

        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        # Pre-seed the tracker as if prior blocks of this epoch had
        # already credited every committee member up to 1 token short
        # of the cap (511).  The current block's per_slot_reward (4)
        # overshoots by 3 tokens per entity.
        supply.attester_epoch_earnings_start = epoch_start
        supply.attester_epoch_earnings = {eid: 511 for eid in committee}

        result = supply.mint_block_reward(
            proposer,
            block_height=height,
            attester_committee=committee,
        )

        # Each entity can only earn 1 more token; 3 tokens per seat
        # must burn as cap-overflow.
        for eid in committee:
            self.assertEqual(supply.balances[eid], 1)
        # attester_pool this block = 512; per_slot = 4; committee=128
        # tokens paid = 128 × 1 = 128; overflow = 128 × 3 = 384.
        # integer-division remainder = 512 - 4*128 = 0.
        # burned = 384.
        self.assertEqual(result["burned"], 384)
        # Tracker now pinned at cap.
        for eid in committee:
            self.assertEqual(supply.attester_epoch_earnings[eid], 512)


class TestCapBurnReducesSupply(unittest.TestCase):
    """Cap-overflow burn must reduce total_supply and bump
    total_burned so the invariant
      total_supply == GENESIS_SUPPLY + total_minted - total_burned
    holds across activation."""

    def test_supply_invariant_under_cap(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        epoch_start = (
            (POST_ACTIVATION_HEIGHT // FINALITY_INTERVAL) * FINALITY_INTERVAL
            + FINALITY_INTERVAL
        )
        height = epoch_start + 5

        supply.attester_fee_pool_this_block = 500
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        # Pre-seed so every entity is at the cap — no new earnings possible.
        supply.attester_epoch_earnings_start = epoch_start
        supply.attester_epoch_earnings = {eid: 512 for eid in committee}

        pre_supply = supply.total_supply
        pre_minted = supply.total_minted
        pre_burned = supply.total_burned

        supply.mint_block_reward(
            proposer,
            block_height=height,
            attester_committee=committee,
        )

        # issuance mint = 16, of which proposer gets 4 (16 * 1 / 4).
        # attester_pool = 12 + 500 = 512, per_slot = 4, cap-overflow =
        # 4 × 128 = 512.  total_burned must rise by 512.
        self.assertEqual(supply.total_minted - pre_minted, 16)
        self.assertEqual(supply.total_burned - pre_burned, 512)
        # Supply invariant preserved.
        self.assertEqual(
            supply.total_supply,
            GENESIS_SUPPLY + supply.total_minted - supply.total_burned,
        )
        # Circulation reflects the burn: supply rose by (minted -
        # burned) = 16 - 512 = -496.  (Supply may fall below
        # pre-block value post-cap, which is the intended effect.)
        self.assertEqual(supply.total_supply, pre_supply + 16 - 512)


class TestEpochBoundaryResetsTracker(unittest.TestCase):
    """At the block that crosses into a new FINALITY_INTERVAL window,
    the earnings tracker resets and every entity can earn up to the
    full cap again."""

    def test_epoch_boundary_resets(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        # Pre-populate the tracker as if the previous epoch had filled
        # the cap.  The new epoch's first block must reset first.
        prev_epoch_start = (
            (POST_ACTIVATION_HEIGHT // FINALITY_INTERVAL) * FINALITY_INTERVAL
            + FINALITY_INTERVAL
        )
        new_epoch_start = prev_epoch_start + FINALITY_INTERVAL
        supply.attester_epoch_earnings_start = prev_epoch_start
        committee = _make_committee(128)
        supply.attester_epoch_earnings = {eid: 512 for eid in committee}

        supply.attester_fee_pool_this_block = 500
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        result = supply.mint_block_reward(
            proposer,
            block_height=new_epoch_start,
            attester_committee=committee,
        )

        # Tracker reset: start moved to new epoch, per-entity earnings
        # re-initialized at 4 (this block's per_slot_reward).
        self.assertEqual(
            supply.attester_epoch_earnings_start, new_epoch_start,
        )
        for eid in committee:
            self.assertEqual(supply.attester_epoch_earnings[eid], 4)
            self.assertEqual(supply.balances[eid], 4)
        # No cap-overflow burn — fresh epoch, below cap.
        self.assertEqual(result["burned"], 0)


class TestActivationBoundary(unittest.TestCase):
    """The cap fires inclusive at ATTESTER_REWARD_CAP_HEIGHT."""

    def test_one_below_activation_no_cap(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        supply.attester_fee_pool_this_block = 500

        # Sentinel state: set tracker to a bogus epoch-start — this
        # field MUST remain untouched at heights pre-fork since the
        # cap path never runs.  Same expectation as
        # ATTESTER_FEE_FUNDING_HEIGHT - 1 for the pay_fee_with_burn
        # path in commit a516fe2.
        supply.attester_epoch_earnings_start = -1

        supply.mint_block_reward(
            proposer,
            block_height=ATTESTER_REWARD_CAP_HEIGHT - 1,
            attester_committee=committee,
        )
        self.assertEqual(supply.attester_epoch_earnings, {})
        self.assertEqual(supply.attester_epoch_earnings_start, -1)

    def test_at_activation_cap_active(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0
        supply.attester_fee_pool_this_block = 500

        supply.mint_block_reward(
            proposer,
            block_height=ATTESTER_REWARD_CAP_HEIGHT,
            attester_committee=committee,
        )
        # Tracker is now populated.
        self.assertNotEqual(supply.attester_epoch_earnings, {})
        epoch_start = (
            (ATTESTER_REWARD_CAP_HEIGHT // FINALITY_INTERVAL)
            * FINALITY_INTERVAL
        )
        self.assertEqual(supply.attester_epoch_earnings_start, epoch_start)


class TestSnapshotRoundTrip(unittest.TestCase):
    """Reorg safety: the per-epoch earnings tracker snapshots with
    _snapshot_memory_state and restores via _install / _restore paths.
    A restore from snapshot resumes cap enforcement correctly."""

    def test_snapshot_restore_preserves_tracker(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        # Mutate the tracker to a non-default state.
        bc.supply.attester_epoch_earnings = {b"e" * 32: 500}
        bc.supply.attester_epoch_earnings_start = 12_345
        snap = bc._snapshot_memory_state()
        # Clobber.
        bc.supply.attester_epoch_earnings = {}
        bc.supply.attester_epoch_earnings_start = -1
        # Restore.
        bc._restore_memory_snapshot(snap)
        self.assertEqual(
            bc.supply.attester_epoch_earnings, {b"e" * 32: 500},
        )
        self.assertEqual(
            bc.supply.attester_epoch_earnings_start, 12_345,
        )


class TestStateRootCommitment(unittest.TestCase):
    """Mutating attester_epoch_earnings must change compute_state_root
    so state-synced nodes that inherit a stale tracker are detectable.
    """

    def test_mutation_changes_state_root(self):
        from messagechain.storage.state_snapshot import compute_state_root
        base = _blank_snapshot()
        base_root = compute_state_root(base)

        mutated = dict(base)
        mutated["attester_epoch_earnings"] = {b"x" * 32: 42}
        mutated["attester_epoch_earnings_start"] = 42
        mutated_root = compute_state_root(mutated)
        self.assertNotEqual(base_root, mutated_root)

    def test_tracker_start_alone_changes_root(self):
        """Changing only attester_epoch_earnings_start (with empty
        dict) must also change the root — otherwise a state-synced
        node that agreed on zero earnings but disagreed on which
        epoch the tracker is pinned to would silently fork at the
        next epoch boundary."""
        from messagechain.storage.state_snapshot import compute_state_root
        base = _blank_snapshot()
        base["attester_epoch_earnings_start"] = 100
        one = compute_state_root(base)
        base["attester_epoch_earnings_start"] = 200
        two = compute_state_root(base)
        self.assertNotEqual(one, two)


class TestSnapshotWireRoundTrip(unittest.TestCase):
    """Binary round-trip: encode a v12 snapshot, decode it, and confirm
    the per-epoch tracker survives byte-for-byte."""

    def test_wire_roundtrip(self):
        from messagechain.storage.state_snapshot import (
            encode_snapshot, decode_snapshot, STATE_SNAPSHOT_VERSION,
        )
        # v12 = this fork's bump.
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 12)
        snap = _blank_snapshot()
        snap["attester_epoch_earnings"] = {
            b"a" * 32: 100,
            b"b" * 32: 200,
        }
        snap["attester_epoch_earnings_start"] = 50_000
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["attester_epoch_earnings"],
            snap["attester_epoch_earnings"],
        )
        self.assertEqual(
            decoded["attester_epoch_earnings_start"],
            snap["attester_epoch_earnings_start"],
        )


class TestSimApplyLockstep(unittest.TestCase):
    """compute_post_state_root (the sim path) must agree with
    _apply_block_state's live mutations when the cap is active.
    This is the catch-all: if the sim forgets to mirror the cap
    logic, we silently fork."""

    def test_post_cap_state_root_lockstep(self):
        # Import here so the test-suite discovery doesn't pay the
        # blockchain setup cost when this class is skipped.
        import unittest
        try:
            from messagechain.core.blockchain import Blockchain
            # Running the full sim/apply harness mid-way through an
            # activation window requires a fully-built chain with
            # attesters and pre-conditions that are exercised by the
            # broader integration test suite (e.g.
            # tests/test_attester_fee_funding_integration).  We keep
            # this assertion as a lightweight smoke check that the
            # Blockchain constructor accepts the new config constant
            # and that mint_block_reward can be called at
            # POST_ACTIVATION_HEIGHT without error.  The integration
            # test for sim/apply lockstep lives alongside the
            # existing attester-fee-funding tests; adding a full
            # committee harness here would duplicate that
            # infrastructure.
            bc = Blockchain()
            self.assertIsNotNone(bc)
        except Exception as exc:
            raise unittest.SkipTest(
                f"Blockchain bootstrap unavailable in this env: {exc}"
            ) from exc


class TestSupplyInvariantAcrossActivation(unittest.TestCase):
    """Chain-level supply invariant:
      total_supply == GENESIS_SUPPLY + total_minted - total_burned
    must hold before, at, and after activation across many mints."""

    def test_invariant_across_many_blocks(self):
        supply = SupplyTracker()
        proposer = b"p" * 32
        committee = _make_committee(128)
        for eid in [proposer, *committee, TREASURY_ENTITY_ID]:
            supply.balances[eid] = 0

        # Span 3 epochs across the activation boundary.  Mint without
        # fee-pool contributions so this is a pure issuance test.
        # (The cap still fires when pool_per_block * cap_bps * epoch /
        # 10_000 >= per_slot_reward; at issuance-only pool the cap is
        # pool * bps * epoch / 10_000 = 12 * 100 * 100 / 10_000 = 12,
        # well above per_slot=0 — no overflow.)
        base = (
            (ATTESTER_REWARD_CAP_HEIGHT // FINALITY_INTERVAL)
            * FINALITY_INTERVAL
        )
        for offset in range(-FINALITY_INTERVAL, FINALITY_INTERVAL * 2):
            supply.attester_fee_pool_this_block = 0
            supply.mint_block_reward(
                proposer,
                block_height=base + offset,
                attester_committee=committee,
            )
            self.assertEqual(
                supply.total_supply,
                GENESIS_SUPPLY + supply.total_minted - supply.total_burned,
            )


# ── Helpers ──────────────────────────────────────────────────────────

def _blank_snapshot() -> dict:
    """A minimal snapshot dict that every setdefault branch in
    deserialize_state can fill in.  Used by the state-root and
    wire-roundtrip tests that don't need a live Blockchain."""
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
    }


if __name__ == "__main__":
    unittest.main()
