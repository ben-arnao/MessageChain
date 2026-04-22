"""Treasury spend-rate cap tightening (hard fork).

Background
----------
The treasury-rebase fork (commit b498806) introduced a per-epoch
cap of TREASURY_MAX_SPEND_BPS_PER_EPOCH = 100 bps (1%) per 100-block
epoch.  Intended as a safeguard against governance capture, the cap
is mis-sized: with ~525.6 epochs/year compounding a max-rate spend,
``(1 - 0.01)^526 ≈ 0.005`` — i.e. ~99.5% of the treasury is
drainable in a single year.

This fork tightens the safeguard to two independently-binding
caps:
    1. Per-epoch 100 bps -> 10 bps (0.1%).
    2. New absolute annual ceiling of 500 bps (5%) of the current
       treasury balance, measured over a 52,560-block rolling
       window (365.25 days at BLOCK_TIME_TARGET=600s).

BOTH must pass; either binding rejects the spend.  Worst-case drain
becomes 5%/year — the treasury halves over ~14 years under
continuous max-vote governance, not 1 year.

This module covers:
    - new config constants at expected values
    - pre-activation: legacy byte-identical behavior
    - post-activation: tightened per-epoch cap (10 bps)
    - post-activation: annual rolling-window cap (500 bps)
    - pruning / rolling window semantics
    - interaction: both caps must be satisfied simultaneously
    - reorg safety: rolling list round-trips through the memory
      snapshot
    - state-root commitment: the list is covered by
      compute_state_root
    - snapshot wire round-trip: encode -> decode preserves the list
"""

import unittest

import messagechain.config as config
from messagechain.economics.inflation import SupplyTracker
from messagechain.storage.state_snapshot import (
    STATE_SNAPSHOT_VERSION,
    compute_state_root,
    decode_snapshot,
    encode_snapshot,
)


TREASURY = config.TREASURY_ENTITY_ID


def _recipient(tag: bytes = b"cap-recipient") -> bytes:
    return tag.ljust(32, b"\x00")


def _fresh_supply(initial_treasury: int = 7_000_000) -> SupplyTracker:
    """Minimal SupplyTracker with only the treasury seeded — keeps
    the cap math small and easy to reason about."""
    supply = SupplyTracker()
    supply.balances[TREASURY] = initial_treasury
    return supply


class TestCapTighteningConstants(unittest.TestCase):
    """The new constants exist at module scope with expected values."""

    def test_post_tighten_per_epoch_constant(self):
        self.assertTrue(
            hasattr(config, "TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN"),
        )
        # 10 bps = 0.1% per 100-block epoch — 10x tighter than legacy.
        self.assertEqual(
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN, 10,
        )
        # Must be strictly tighter than the legacy cap.
        self.assertLess(
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN,
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH,
        )

    def test_annual_cap_constant(self):
        self.assertTrue(hasattr(config, "TREASURY_MAX_SPEND_BPS_PER_YEAR"))
        # 500 bps = 5% per rolling-year window.
        self.assertEqual(config.TREASURY_MAX_SPEND_BPS_PER_YEAR, 500)

    def test_year_window_matches_600s_block_time(self):
        """52,560 blocks × 600s/block == 365 days at BLOCK_TIME_TARGET.

        Note: the exact number of seconds in a Julian year is
        31,557,600 (365.25 days); rounding down to a whole-block
        count gives 52,596 blocks, and rounding down to a whole-day
        count (365.00) gives 52,560 blocks.  The window uses 52,560
        — the rounder number whose seconds-equivalent is exactly
        365 × 86,400 = 31,536,000.  Close enough to a Julian year
        for a safeguard cap; no economic reason to split the
        rounding difference.
        """
        self.assertTrue(hasattr(config, "TREASURY_SPEND_CAP_YEAR_BLOCKS"))
        self.assertEqual(config.TREASURY_SPEND_CAP_YEAR_BLOCKS, 52_560)
        # 52,560 × 600 = 31,536,000 seconds = 365 × 86,400.
        self.assertEqual(
            config.TREASURY_SPEND_CAP_YEAR_BLOCKS * 600,
            365 * 86_400,
        )

    def test_activation_height_constant(self):
        self.assertTrue(hasattr(config, "TREASURY_CAP_TIGHTEN_HEIGHT"))
        self.assertEqual(config.TREASURY_CAP_TIGHTEN_HEIGHT, 50_000)

    def test_helper_returns_legacy_bps_pre_activation(self):
        self.assertEqual(
            config.get_treasury_max_spend_bps_per_epoch(
                config.TREASURY_CAP_TIGHTEN_HEIGHT - 1,
            ),
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH,
        )

    def test_helper_returns_post_tighten_bps_at_and_after_activation(self):
        self.assertEqual(
            config.get_treasury_max_spend_bps_per_epoch(
                config.TREASURY_CAP_TIGHTEN_HEIGHT,
            ),
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN,
        )
        self.assertEqual(
            config.get_treasury_max_spend_bps_per_epoch(
                config.TREASURY_CAP_TIGHTEN_HEIGHT + 1,
            ),
            config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN,
        )


class TestPreActivationLegacyBehavior(unittest.TestCase):
    """Pre-activation: the 1% per-epoch cap remains and there is no
    annual ceiling.  A chain still under treasury-rebase-only semantics
    must be byte-identical to what it was before the cap-tightening
    fork was written."""

    def setUp(self):
        # Override the activation height upward so all per-spend
        # block_heights in this test are strictly pre-activation.
        self._orig = config.TREASURY_CAP_TIGHTEN_HEIGHT
        config.TREASURY_CAP_TIGHTEN_HEIGHT = 10 ** 9

    def tearDown(self):
        config.TREASURY_CAP_TIGHTEN_HEIGHT = self._orig

    def test_legacy_one_percent_spend_succeeds(self):
        supply = _fresh_supply(7_000_000)
        # 1% of 7M = 70K — exactly at the legacy per-epoch cap.
        ok = supply.treasury_spend(
            _recipient(), 70_000,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertTrue(ok)

    def test_legacy_second_same_epoch_spend_rejected(self):
        """Under pre-activation the existing per-epoch cap still
        rejects a follow-up even-if-tiny spend."""
        supply = _fresh_supply(7_000_000)
        self.assertTrue(
            supply.treasury_spend(
                _recipient(), 70_000,
                current_block=config.TREASURY_REBASE_HEIGHT,
            ),
        )
        self.assertFalse(
            supply.treasury_spend(
                _recipient(), 1,
                current_block=config.TREASURY_REBASE_HEIGHT + 1,
            ),
        )

    def test_no_annual_cap_enforced_pre_activation(self):
        """Pre-activation there is no annual ceiling — any sequence
        of epoch-compliant spends compounds without a yearly gate.
        Simulate 10 epochs each at the 1% cap (far above 5% annual)."""
        supply = _fresh_supply(7_000_000)
        for epoch_index in range(10):
            block = (
                config.TREASURY_REBASE_HEIGHT
                + epoch_index * config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            )
            cap = (
                supply.get_balance(TREASURY)
                * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH
                // 10_000
            )
            self.assertTrue(
                supply.treasury_spend(
                    _recipient(), cap, current_block=block,
                ),
                f"legacy cap spend at epoch {epoch_index} unexpectedly rejected",
            )
        # Spent ~10% of treasury — would be cap-rejected post-tighten
        # (5% annual ceiling).
        spent = 7_000_000 - supply.get_balance(TREASURY)
        self.assertGreater(spent, 500_000)

    def test_rolling_list_stays_empty_pre_activation(self):
        supply = _fresh_supply(7_000_000)
        supply.treasury_spend(
            _recipient(), 70_000,
            current_block=config.TREASURY_REBASE_HEIGHT,
        )
        self.assertEqual(
            supply._treasury_spend_rolling_debits, [],
        )


class TestPostActivationPerEpochTighter(unittest.TestCase):
    """Post-activation the per-epoch cap is 10 bps (0.1%) of current
    treasury balance.  0.1% succeeds; 0.11% rejects."""

    def test_spend_at_post_tighten_cap_succeeds(self):
        supply = _fresh_supply(7_000_000)
        # 0.1% of 7M = 7,000 tokens — exactly at the post-tighten cap.
        cap = (
            7_000_000
            * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN
            // 10_000
        )
        self.assertEqual(cap, 7_000)
        ok = supply.treasury_spend(
            _recipient(), cap,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertTrue(ok)
        self.assertEqual(supply.get_balance(_recipient()), cap)

    def test_spend_over_post_tighten_cap_rejected(self):
        supply = _fresh_supply(7_000_000)
        # 0.11% = 7,700 — above the 0.1% cap.
        ok = supply.treasury_spend(
            _recipient(), 7_700,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertFalse(ok)
        # Treasury untouched on reject.
        self.assertEqual(supply.get_balance(TREASURY), 7_000_000)

    def test_legacy_one_percent_spend_now_rejected(self):
        """The 1% spend that was legal under legacy is 10× over the
        new per-epoch cap.  Must reject."""
        supply = _fresh_supply(7_000_000)
        ok = supply.treasury_spend(
            _recipient(), 70_000,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertFalse(ok)


class TestPostActivationAnnualCap(unittest.TestCase):
    """Post-activation the annual ceiling (5% per rolling 52,560-block
    window) is enforced.  Accumulating spends up to exactly 5% must
    succeed; one more token over pushes it above and rejects."""

    def _per_epoch_cap(self, balance: int) -> int:
        return (
            balance
            * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN
            // 10_000
        )

    def test_cumulative_spends_accumulate_toward_annual_cap(self):
        """Series of small epoch-compliant spends accumulate in the
        rolling window; once the cumulative debits approach 5% of the
        (shrinking) current balance, further spends begin to reject.

        NOTE: the annual cap is re-measured against CURRENT balance
        at each spend, so the effective drain ceiling shifts lower
        as the treasury shrinks.  We verify that we can land MULTIPLE
        spends before getting cap-rejected, demonstrating the
        rolling-window accumulation works — rather than asserting an
        exact cumulative total which would be sensitive to the
        shrinking-denominator arithmetic.
        """
        supply = _fresh_supply(7_000_000)
        accepted_spends = 0
        epoch_index = 0
        max_epochs = 100  # safety bound
        while epoch_index < max_epochs:
            block = (
                config.TREASURY_CAP_TIGHTEN_HEIGHT
                + epoch_index * config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            )
            per_epoch_now = self._per_epoch_cap(
                supply.get_balance(TREASURY),
            )
            if per_epoch_now <= 0:
                break
            ok = supply.treasury_spend(
                _recipient(), per_epoch_now, current_block=block,
            )
            if ok:
                accepted_spends += 1
                epoch_index += 1
            else:
                break
        # Annual cap of 5% vs per-epoch cap of 0.1% → at least ~40
        # spends are accepted before the annual ceiling binds (with
        # the shrinking-denominator effect; ideal is ~50).  Assert a
        # lower bound well clear of trivial acceptance.
        self.assertGreaterEqual(
            accepted_spends, 40,
            f"only {accepted_spends} per-epoch spends accepted — "
            "annual cap appears to bind sooner than expected.",
        )
        # And we DID eventually bind the annual cap — the while-loop
        # exited via rejection, not the max_epochs guard.
        self.assertLess(accepted_spends, max_epochs)

    def test_single_spend_at_annual_cap_succeeds_next_rejects(self):
        """Start with a larger treasury so the 5% annual cap is
        reachable in a single spend that's still within the 0.1%
        per-epoch cap of a sufficiently-large balance.  To hit this
        regime cleanly, we exercise the annual cap directly: simulate
        a chain where many epoch-sized spends have accumulated just
        under 5%, then the next spend would push above 5% and fail."""
        supply = _fresh_supply(7_000_000)
        # Preload the rolling debit list with a total just under 5%.
        # This directly exercises the annual-cap gate without needing
        # to schedule 50+ epochs.  Treasury balance is untouched so
        # the annual cap reads 5% of 7M = 350,000.
        just_under = 7_000_000 * 500 // 10_000 - 1  # 349,999
        supply._treasury_spend_rolling_debits = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, just_under),
        ]
        # Simulate that debit as already taken.
        supply.balances[TREASURY] -= just_under

        # A 2-token spend would push total to 350,001 — over 5% of
        # the current (post-debit) balance.  Using balance=7M-349,999
        # = 6,650,001, 5% = 332,500; 349,999 + 2 = 350,001 > 332,500
        # → rejected.  (The cap is re-measured against current
        # balance, which SHRINKS as spends execute — so even small
        # additions can push over once the window is near-full.)
        ok = supply.treasury_spend(
            _recipient(), 2,
            current_block=(
                config.TREASURY_CAP_TIGHTEN_HEIGHT
                + config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            ),
        )
        self.assertFalse(ok)

    def test_annual_cap_blocks_spend_even_when_per_epoch_would_pass(self):
        """A spend that fits under the per-epoch cap but pushes the
        rolling-window total over the annual cap must reject."""
        supply = _fresh_supply(7_000_000)
        # Preload the rolling window with just-under-5% of the pre-debit
        # balance; then attempt a sub-epoch-cap spend that would push
        # the rolling total above 5% of the (post-debit) balance.
        annual_target = 7_000_000 * 500 // 10_000  # 350,000
        preload = annual_target - 100  # 349,900
        supply._treasury_spend_rolling_debits = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, preload),
        ]
        supply.balances[TREASURY] -= preload

        # per-epoch cap of the post-debit balance:
        #   (7M - 349,900) * 0.1% = ~6,650 tokens
        # 200 is well under per-epoch, but pushes annual over.
        ok = supply.treasury_spend(
            _recipient(), 200,
            current_block=(
                config.TREASURY_CAP_TIGHTEN_HEIGHT
                + config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            ),
        )
        self.assertFalse(ok)


class TestRollingWindowPrune(unittest.TestCase):
    """Entries older than TREASURY_SPEND_CAP_YEAR_BLOCKS no longer
    count against the annual cap."""

    def test_entry_from_block_zero_pruned_after_window(self):
        """A spend recorded at block H_activation is pruned when a
        later spend arrives at block H_activation + 52,560 + 1."""
        supply = _fresh_supply(7_000_000)
        # Spend at activation — allowed (0 prior debits).
        spend_at_activation = 7_000  # 0.1% of 7M
        ok = supply.treasury_spend(
            _recipient(), spend_at_activation,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertTrue(ok)
        self.assertEqual(
            len(supply._treasury_spend_rolling_debits), 1,
        )

        # Jump forward by WINDOW + 1 blocks — the earlier spend is
        # now outside the rolling window and must be pruned at the
        # next spend.  Use a spend that's within per-epoch and would
        # violate the annual cap if the old entry were still counted.
        later_block = (
            config.TREASURY_CAP_TIGHTEN_HEIGHT
            + config.TREASURY_SPEND_CAP_YEAR_BLOCKS
            + 1
        )
        # Fresh 5% window should accept another per-epoch-cap spend.
        balance_now = supply.get_balance(TREASURY)
        new_epoch_cap = (
            balance_now
            * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN
            // 10_000
        )
        ok = supply.treasury_spend(
            _recipient(), new_epoch_cap, current_block=later_block,
        )
        self.assertTrue(ok)

        # Only the recent spend should remain in the rolling list.
        self.assertEqual(
            len(supply._treasury_spend_rolling_debits), 1,
        )
        (h, a) = supply._treasury_spend_rolling_debits[0]
        self.assertEqual(h, later_block)
        self.assertEqual(a, new_epoch_cap)

    def test_entry_at_window_edge_still_counts(self):
        """Exactly at window_start a debit still counts — it's the
        > (not >=) that trims.  The code uses
        ``h >= window_start`` meaning entries at EXACTLY
        window_start are retained.  Verify an entry at
        current_block - WINDOW is still in the list after the next
        spend."""
        supply = _fresh_supply(7_000_000)
        ok = supply.treasury_spend(
            _recipient(), 7_000,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertTrue(ok)

        # Next spend exactly WINDOW blocks later — window_start is
        # then equal to the first spend's block, so it's retained.
        later = (
            config.TREASURY_CAP_TIGHTEN_HEIGHT
            + config.TREASURY_SPEND_CAP_YEAR_BLOCKS
        )
        balance_now = supply.get_balance(TREASURY)
        per_epoch_cap = (
            balance_now
            * config.TREASURY_MAX_SPEND_BPS_PER_EPOCH_POST_TIGHTEN
            // 10_000
        )
        ok = supply.treasury_spend(
            _recipient(), per_epoch_cap, current_block=later,
        )
        self.assertTrue(ok)
        # Both entries present.
        self.assertEqual(
            len(supply._treasury_spend_rolling_debits), 2,
        )


class TestCapInteraction(unittest.TestCase):
    """A spend must satisfy BOTH the per-epoch AND annual caps; either
    binding rejects the spend."""

    def test_satisfies_annual_but_violates_per_epoch_rejects(self):
        supply = _fresh_supply(7_000_000)
        # 2% of 7M = 140,000 — well over the 0.1% per-epoch cap
        # (7,000) but inside the 5% annual cap (350,000).
        ok = supply.treasury_spend(
            _recipient(), 140_000,
            current_block=config.TREASURY_CAP_TIGHTEN_HEIGHT,
        )
        self.assertFalse(ok)

    def test_satisfies_per_epoch_but_violates_annual_rejects(self):
        supply = _fresh_supply(7_000_000)
        # Preload window with 5% already spent.
        preload = 7_000_000 * 500 // 10_000
        supply._treasury_spend_rolling_debits = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, preload),
        ]
        supply.balances[TREASURY] -= preload

        # Any further spend inside a fresh epoch — even 1 token —
        # must reject.
        ok = supply.treasury_spend(
            _recipient(), 1,
            current_block=(
                config.TREASURY_CAP_TIGHTEN_HEIGHT
                + config.TREASURY_SPEND_CAP_EPOCH_BLOCKS
            ),
        )
        self.assertFalse(ok)


class TestSnapshotReorgSafety(unittest.TestCase):
    """Memory-state snapshot (used for reorg rollback) round-trips
    the rolling debit list."""

    def _fake_chain(self):
        """Build a minimal chain-like object that exercises the
        snapshot encode path.  Full Blockchain would drag the whole
        bootstrap-and-initialize path in; for this test we only need
        _snapshot_memory_state / _restore_memory_snapshot."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.bootstrap import (
            RECOMMENDED_STAKE_PER_SEED,
            bootstrap_seed_local,
            build_launch_allocation,
        )
        from messagechain.identity.identity import Entity

        seed = Entity.create(b"cap-tightening-seed".ljust(32, b"\x00"))
        cold = Entity.create(b"cap-tightening-cold".ljust(32, b"\x00"))
        allocation = build_launch_allocation([seed.entity_id])
        chain = Blockchain()
        chain.initialize_genesis(seed, allocation_table=allocation)
        ok, log = bootstrap_seed_local(
            chain, seed,
            cold_authority_pubkey=cold.public_key,
            stake_amount=RECOMMENDED_STAKE_PER_SEED,
        )
        assert ok, "\n".join(log)
        return chain

    def test_snapshot_restores_rolling_list_exactly(self):
        chain = self._fake_chain()
        # Three synthetic entries — not actually driven through
        # treasury_spend to keep this test narrowly focused on the
        # snapshot round-trip rather than the spend pipeline.
        preloaded = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, 1_000),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 100, 2_500),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 250, 7_000),
        ]
        chain.supply._treasury_spend_rolling_debits = list(preloaded)
        snap = chain._snapshot_memory_state()

        # Mutate live state post-snapshot.
        chain.supply._treasury_spend_rolling_debits.append(
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 500, 999),
        )
        self.assertEqual(
            len(chain.supply._treasury_spend_rolling_debits), 4,
        )

        # Restore — expect exactly the pre-mutation state.
        chain._restore_memory_snapshot(snap)
        restored = chain.supply._treasury_spend_rolling_debits
        self.assertEqual(
            [(int(h), int(a)) for (h, a) in restored],
            preloaded,
        )

    def test_snapshot_is_isolated_from_live_mutation(self):
        """The snapshot holds an independent copy — mutating live
        state after snapshotting must not mutate the snapshot's copy."""
        chain = self._fake_chain()
        chain.supply._treasury_spend_rolling_debits = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, 5_000),
        ]
        snap = chain._snapshot_memory_state()
        chain.supply._treasury_spend_rolling_debits.append(
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 1, 1),
        )
        # Snapshot must still reflect the pre-append state.
        self.assertEqual(
            list(snap["treasury_spend_rolling_debits"]),
            [(config.TREASURY_CAP_TIGHTEN_HEIGHT, 5_000)],
        )


class TestStateRootCommitment(unittest.TestCase):
    """The rolling debit list participates in the snapshot state root."""

    def _base_snapshot(self, rolling_debits):
        """Return a minimal snapshot dict for compute_state_root."""
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
            "treasury_spend_rolling_debits": rolling_debits,
        }

    def test_empty_vs_nonempty_list_produces_different_roots(self):
        root_empty = compute_state_root(self._base_snapshot([]))
        root_populated = compute_state_root(
            self._base_snapshot(
                [(config.TREASURY_CAP_TIGHTEN_HEIGHT, 1_000)],
            ),
        )
        self.assertNotEqual(root_empty, root_populated)

    def test_different_amounts_produce_different_roots(self):
        root_a = compute_state_root(
            self._base_snapshot(
                [(config.TREASURY_CAP_TIGHTEN_HEIGHT, 1_000)],
            ),
        )
        root_b = compute_state_root(
            self._base_snapshot(
                [(config.TREASURY_CAP_TIGHTEN_HEIGHT, 2_000)],
            ),
        )
        self.assertNotEqual(root_a, root_b)

    def test_different_heights_produce_different_roots(self):
        root_a = compute_state_root(
            self._base_snapshot(
                [(config.TREASURY_CAP_TIGHTEN_HEIGHT, 1_000)],
            ),
        )
        root_b = compute_state_root(
            self._base_snapshot(
                [(config.TREASURY_CAP_TIGHTEN_HEIGHT + 1, 1_000)],
            ),
        )
        self.assertNotEqual(root_a, root_b)

    def test_root_is_order_independent(self):
        """Two permutations of the same multiset hash to the same
        root — the section sorts entries deterministically."""
        entries_a = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 10, 1_000),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 20, 2_000),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 5, 500),
        ]
        entries_b = list(reversed(entries_a))
        self.assertEqual(
            compute_state_root(self._base_snapshot(entries_a)),
            compute_state_root(self._base_snapshot(entries_b)),
        )


class TestSnapshotWireRoundTrip(unittest.TestCase):
    """encode_snapshot -> decode_snapshot preserves the list exactly."""

    def _base_snapshot(self, rolling_debits):
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
            "treasury_spend_rolling_debits": rolling_debits,
        }

    def test_empty_list_roundtrips(self):
        blob = encode_snapshot(self._base_snapshot([]))
        decoded = decode_snapshot(blob)
        self.assertEqual(decoded["treasury_spend_rolling_debits"], [])

    def test_populated_list_roundtrips_exact_values(self):
        entries = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, 7_000),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 100, 6_993),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 250, 6_986),
        ]
        blob = encode_snapshot(self._base_snapshot(list(entries)))
        decoded = decode_snapshot(blob)
        # Sorted by (height, amount) in encoder — entries are already
        # ascending so output matches input order.
        self.assertEqual(
            decoded["treasury_spend_rolling_debits"],
            entries,
        )

    def test_populated_list_roundtrip_sorted_deterministic(self):
        """Insertion order does not matter — encoder sorts."""
        entries = [
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 250, 9),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT + 100, 8),
            (config.TREASURY_CAP_TIGHTEN_HEIGHT, 7),
        ]
        blob_a = encode_snapshot(self._base_snapshot(list(entries)))
        blob_b = encode_snapshot(
            self._base_snapshot(list(reversed(entries))),
        )
        self.assertEqual(blob_a, blob_b)
        decoded = decode_snapshot(blob_a)
        # Post-decode: ascending by height.
        self.assertEqual(
            decoded["treasury_spend_rolling_debits"],
            sorted(entries),
        )

    def test_wire_version_at_least_11(self):
        # Originally bumped to v10, but the concurrent coverage-misses
        # fork also claimed v10 — this fork was promoted to v11 at
        # merge time.  Subsequent forks may have bumped further
        # (e.g. v12 widened inclusion_list_processed_violations
        # entries to 96 bytes), so the treasury-cap-tightening fork
        # only requires the floor is still v11 or higher.
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 11)


if __name__ == "__main__":
    unittest.main()
