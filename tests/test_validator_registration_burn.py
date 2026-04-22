"""Tests for the validator-registration burn hard fork.

Background
----------
The attester-reward-cap fork (commit ``37a2436``) limits per-entity
epoch earnings.  But at MIN_STAKE = 10_000, a 25M-stake founder can
split into ~2,500 sybils, each with its own cap allowance — aggregate
capture exceeds what the founder's main entity would earn uncapped.
The cap is sybil-negative for large stakers: splitting increases
aggregate revenue.

Fix: raise the real cost of spawning validators.  Burn
VALIDATOR_REGISTRATION_BURN tokens when an entity FIRST registers as
a validator (i.e., on first StakeTransaction).  Sybil cost increases
from 10K stake (recoverable on unstake) to 20K (10K stake + 10K
permanently burned).  Infrastructure cost remains the ultimate
limit, but the protocol now charges a meaningful entry fee.

Design choices
--------------
* One-time per entity.  Once registered, always registered — an
  entity that fully unstakes and later re-stakes does NOT pay a
  second burn.  Option A from the design doc: cleaner, avoids
  punishing legitimate operators cycling stake.
* Grandfathering: entities already staked at activation height are
  added to the registered set at that height without paying.  This
  is a one-shot migration guarded by ``grandfather_applied`` for
  reorg safety (mirrors ``treasury_rebase_applied``).
* State: ``SupplyTracker.registered_validators`` is consensus state.
  Snapshotted + committed to the state root + wire-version bumped.
* Pre-activation: set never populated, no burn; byte-for-byte
  legacy behavior.
"""

from __future__ import annotations

import unittest

import messagechain.config as config
from messagechain.economics.inflation import SupplyTracker


PRE_ACTIVATION_HEIGHT = max(
    0, getattr(config, "VALIDATOR_REGISTRATION_BURN_HEIGHT", 70_000) - 1,
)
POST_ACTIVATION_HEIGHT = getattr(
    config, "VALIDATOR_REGISTRATION_BURN_HEIGHT", 70_000,
) + 1


# ── Constants ───────────────────────────────────────────────────────


class TestConstants(unittest.TestCase):
    """Config constants exist with the documented values."""

    def test_burn_amount_constant(self):
        self.assertTrue(hasattr(config, "VALIDATOR_REGISTRATION_BURN"))
        self.assertEqual(config.VALIDATOR_REGISTRATION_BURN, 10_000)

    def test_activation_height_constant(self):
        self.assertTrue(hasattr(config, "VALIDATOR_REGISTRATION_BURN_HEIGHT"))
        self.assertIsInstance(config.VALIDATOR_REGISTRATION_BURN_HEIGHT, int)


# ── SupplyTracker init ───────────────────────────────────────────────


class TestSupplyTrackerInit(unittest.TestCase):
    """SupplyTracker gains ``registered_validators`` set and
    ``grandfather_applied`` flag at default (empty / False)."""

    def test_registered_validators_is_empty_set(self):
        supply = SupplyTracker()
        self.assertTrue(hasattr(supply, "registered_validators"))
        self.assertIsInstance(supply.registered_validators, set)
        self.assertEqual(supply.registered_validators, set())

    def test_grandfather_applied_default_false(self):
        supply = SupplyTracker()
        self.assertTrue(hasattr(supply, "grandfather_applied"))
        self.assertFalse(supply.grandfather_applied)


# ── Blockchain apply path ────────────────────────────────────────────
#
# The burn fires inside the stake-tx apply loop in _apply_block_state.
# We exercise that loop via the helper below so these tests do not
# need to build full blocks.


def _make_chain_with_entity(entity, balance, height):
    """Build a minimal chain with `entity` registered and funded."""
    from messagechain.core.blockchain import Blockchain
    from tests import register_entity_for_test

    chain = Blockchain()
    chain.initialize_genesis(entity)
    register_entity_for_test(chain, entity)
    chain.supply.balances[entity.entity_id] = balance
    return chain


class _StubStakeTx:
    """Minimal stake-tx surrogate for the apply-path helper.

    The helper we call directly only needs entity_id, amount, fee,
    nonce, sender_pubkey, and signature.leaf_index — not the full WOTS+
    surface.  A real StakeTransaction is used in the block-level test."""

    class _Sig:
        def __init__(self, leaf_index=0):
            self.leaf_index = leaf_index

    def __init__(self, entity_id, amount, fee=0, nonce=0, leaf_index=0):
        self.entity_id = entity_id
        self.amount = amount
        self.fee = fee
        self.nonce = nonce
        self.sender_pubkey = b""
        self.signature = _StubStakeTx._Sig(leaf_index=leaf_index)
        self.tx_hash = b"\x00" * 32


class TestChargeOnFirstStake(unittest.TestCase):
    """Post-activation first-stake path: burn charged, entity marked."""

    def test_pre_activation_no_burn(self):
        """Pre-activation: the apply helper must not burn, not populate."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"pre-activation-staker".ljust(32, b"\x00"))
        chain = _make_chain_with_entity(alice, balance=1_000_000, height=0)
        before_supply = chain.supply.total_supply
        before_burned = chain.supply.total_burned

        stx = _StubStakeTx(alice.entity_id, amount=10_000)
        # Call the registration-burn hook directly so we don't require
        # full block-apply machinery.  Pre-activation path must no-op.
        chain._apply_validator_registration_burn(stx, PRE_ACTIVATION_HEIGHT)

        self.assertEqual(chain.supply.total_supply, before_supply)
        self.assertEqual(chain.supply.total_burned, before_burned)
        self.assertNotIn(
            alice.entity_id, chain.supply.registered_validators,
        )

    def test_post_activation_first_stake_burns(self):
        """Post-activation first stake: balance down by burn; total_supply
        down by burn; entity added to registered set."""
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"post-activation-first".ljust(32, b"\x00"))
        chain = _make_chain_with_entity(alice, balance=50_000, height=0)
        before_balance = chain.supply.get_balance(alice.entity_id)
        before_supply = chain.supply.total_supply
        before_burned = chain.supply.total_burned
        burn = config.VALIDATOR_REGISTRATION_BURN

        stx = _StubStakeTx(alice.entity_id, amount=10_000)
        ok = chain._apply_validator_registration_burn(
            stx, POST_ACTIVATION_HEIGHT,
        )
        self.assertTrue(ok, "sufficient-balance first stake must succeed")

        self.assertEqual(
            chain.supply.get_balance(alice.entity_id),
            before_balance - burn,
        )
        self.assertEqual(chain.supply.total_supply, before_supply - burn)
        self.assertEqual(chain.supply.total_burned, before_burned + burn)
        self.assertIn(
            alice.entity_id, chain.supply.registered_validators,
        )


class TestNoReBurnOnSubsequentStakes(unittest.TestCase):
    """Option A: once registered, always registered.  A second stake
    from the same entity does NOT pay another burn."""

    def test_second_stake_no_reburn(self):
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"second-stake-noreburn".ljust(32, b"\x00"))
        chain = _make_chain_with_entity(alice, balance=100_000, height=0)

        stx1 = _StubStakeTx(alice.entity_id, amount=10_000, leaf_index=0)
        chain._apply_validator_registration_burn(
            stx1, POST_ACTIVATION_HEIGHT,
        )

        before_balance = chain.supply.get_balance(alice.entity_id)
        before_supply = chain.supply.total_supply
        before_burned = chain.supply.total_burned

        stx2 = _StubStakeTx(alice.entity_id, amount=5_000, leaf_index=1)
        ok = chain._apply_validator_registration_burn(
            stx2, POST_ACTIVATION_HEIGHT,
        )
        self.assertTrue(ok, "already-registered re-stake must succeed")
        self.assertEqual(chain.supply.get_balance(alice.entity_id), before_balance)
        self.assertEqual(chain.supply.total_supply, before_supply)
        self.assertEqual(chain.supply.total_burned, before_burned)

    def test_fully_unstake_and_restake_no_reburn(self):
        """A validator that fully unstakes and later re-stakes is still
        marked as registered — Option A (cleaner) — so they do NOT pay
        a second burn."""
        from messagechain.identity.identity import Entity

        bob = Entity.create(b"full-unstake-restake".ljust(32, b"\x00"))
        chain = _make_chain_with_entity(bob, balance=100_000, height=0)

        # Register + first stake.
        stx1 = _StubStakeTx(bob.entity_id, amount=10_000, leaf_index=0)
        chain._apply_validator_registration_burn(
            stx1, POST_ACTIVATION_HEIGHT,
        )
        self.assertIn(bob.entity_id, chain.supply.registered_validators)

        # Simulate full unstake — we don't go through the full unstake
        # queue since the registration burn mark persists regardless.
        chain.supply.staked.pop(bob.entity_id, None)

        # Second stake later — no re-burn.
        before_supply = chain.supply.total_supply
        before_burned = chain.supply.total_burned
        stx2 = _StubStakeTx(bob.entity_id, amount=10_000, leaf_index=1)
        ok = chain._apply_validator_registration_burn(
            stx2, POST_ACTIVATION_HEIGHT,
        )
        self.assertTrue(ok)
        self.assertEqual(chain.supply.total_supply, before_supply)
        self.assertEqual(chain.supply.total_burned, before_burned)


class TestInsufficientBalance(unittest.TestCase):
    """Post-activation, a first stake whose (amount + registration
    burn) exceeds the entity's balance is REJECTED.  The entity is
    NOT marked as registered, so a later well-funded attempt retries
    the burn."""

    def test_insufficient_balance_rejects_and_preserves_state(self):
        from messagechain.identity.identity import Entity

        carol = Entity.create(b"insufficient-balance-stk".ljust(32, b"\x00"))
        # 15,000 < 10,000 stake + 10,000 burn = 20,000 required.
        chain = _make_chain_with_entity(carol, balance=15_000, height=0)

        before_balance = chain.supply.get_balance(carol.entity_id)
        before_supply = chain.supply.total_supply
        before_burned = chain.supply.total_burned

        stx = _StubStakeTx(carol.entity_id, amount=10_000)
        ok = chain._apply_validator_registration_burn(
            stx, POST_ACTIVATION_HEIGHT,
        )
        self.assertFalse(ok, "insufficient balance must reject")

        # No balance/supply mutation.
        self.assertEqual(chain.supply.get_balance(carol.entity_id), before_balance)
        self.assertEqual(chain.supply.total_supply, before_supply)
        self.assertEqual(chain.supply.total_burned, before_burned)
        self.assertNotIn(
            carol.entity_id, chain.supply.registered_validators,
            "rejected first-stake must not mark entity as registered",
        )


# ── Grandfather migration ────────────────────────────────────────────


class TestGrandfather(unittest.TestCase):
    """At activation height, every entity with current stake > 0 is
    added to registered_validators without paying the burn.  Guarded
    by ``grandfather_applied`` for reorg safety."""

    def test_grandfather_populates_set(self):
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        # Seed some staked entities pre-activation.
        bc.supply.staked = {
            b"a" * 32: 5_000,
            b"b" * 32: 0,             # zero stake — NOT grandfathered
            b"c" * 32: 1,             # non-zero stake — grandfathered
        }
        self.assertEqual(bc.supply.registered_validators, set())
        self.assertFalse(bc.supply.grandfather_applied)

        bc._apply_registration_grandfather(
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT,
        )
        self.assertEqual(
            bc.supply.registered_validators,
            {b"a" * 32, b"c" * 32},
        )
        self.assertTrue(bc.supply.grandfather_applied)

    def test_grandfather_no_double_apply(self):
        """Re-running at the same height is a no-op once the flag is set.
        (Reorg-safety convention: flag rolls back via snapshot restore.)"""
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        bc.supply.staked = {b"a" * 32: 1_000}
        bc._apply_registration_grandfather(
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT,
        )
        # Mutate registered_validators underneath — a second apply must
        # NOT re-add the entity (flag is sticky).
        bc.supply.registered_validators.clear()
        bc._apply_registration_grandfather(
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT,
        )
        self.assertEqual(bc.supply.registered_validators, set())

    def test_grandfather_other_heights_noop(self):
        """Not-activation-height call is a no-op regardless of flag."""
        from messagechain.core.blockchain import Blockchain
        bc = Blockchain()
        bc.supply.staked = {b"a" * 32: 1_000}
        bc._apply_registration_grandfather(
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT - 1,
        )
        self.assertEqual(bc.supply.registered_validators, set())
        self.assertFalse(bc.supply.grandfather_applied)
        bc._apply_registration_grandfather(
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT + 1,
        )
        self.assertEqual(bc.supply.registered_validators, set())
        self.assertFalse(bc.supply.grandfather_applied)


# ── Reorg / snapshot safety ──────────────────────────────────────────


class TestSnapshotRoundTrip(unittest.TestCase):
    """registered_validators + grandfather_applied must survive the
    snapshot round-trip, or a failed reorg would strand the chain in
    an inconsistent post-rollback state."""

    def test_snapshot_restore_preserves_set_and_flag(self):
        from messagechain.core.blockchain import Blockchain

        bc = Blockchain()
        bc.supply.registered_validators = {b"a" * 32, b"b" * 32}
        bc.supply.grandfather_applied = True
        snap = bc._snapshot_memory_state()
        # Clobber.
        bc.supply.registered_validators = set()
        bc.supply.grandfather_applied = False
        # Restore.
        bc._restore_memory_snapshot(snap)
        self.assertEqual(
            bc.supply.registered_validators,
            {b"a" * 32, b"b" * 32},
        )
        self.assertTrue(bc.supply.grandfather_applied)


# ── State-root commitment ────────────────────────────────────────────


class TestStateRootCommitment(unittest.TestCase):
    """Mutating registered_validators must change compute_state_root
    so state-synced nodes cannot silently disagree on the set."""

    def test_mutation_changes_state_root(self):
        from messagechain.storage.state_snapshot import compute_state_root

        base = _blank_snapshot()
        base_root = compute_state_root(base)

        mutated = dict(base)
        mutated["registered_validators"] = {b"x" * 32}
        mutated_root = compute_state_root(mutated)
        self.assertNotEqual(base_root, mutated_root)


# ── Wire-format bump ─────────────────────────────────────────────────


class TestSnapshotWireRoundTrip(unittest.TestCase):
    """Binary round-trip: encode a post-fork snapshot, decode it, and
    confirm registered_validators survives byte-for-byte."""

    def test_snapshot_version_bumped(self):
        from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
        # v14 was the previous bump; this fork bumps to 15.
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 15)

    def test_wire_roundtrip(self):
        from messagechain.storage.state_snapshot import (
            encode_snapshot, decode_snapshot,
        )
        snap = _blank_snapshot()
        snap["registered_validators"] = {b"r" * 32, b"s" * 32}
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(
            decoded["registered_validators"],
            snap["registered_validators"],
        )


# ── Helpers ──────────────────────────────────────────────────────────


def _blank_snapshot() -> dict:
    """A minimal snapshot dict carrying every section deserialize_state
    populates via setdefault.  Keeps state-root / wire-roundtrip tests
    independent of live Blockchain bootstrap."""
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
        "registered_validators": set(),
    }


if __name__ == "__main__":
    unittest.main()
