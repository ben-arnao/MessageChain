"""Tests for duty-state persistence + reward-path withhold.

Iteration 3b-iii of the validator-duty archive-reward redesign.  This
iteration lands the two remaining pieces:

    * The three duty fields (validator_archive_misses,
      validator_first_active_block, archive_active_snapshot) participate
      in the state snapshot (dict serialize/encode/decode) and in the
      state root so bootstrapping and replaying nodes agree on them.
    * Proposer rewards (and attester rewards, because attesters are
      also validators) are reduced by withhold_pct(miss_count) at mint
      time; withheld tokens route into archive_reward_pool instead of
      being credited to the validator's balance.

STATE_SNAPSHOT_VERSION bumps to 7 (v6 was taken by inclusion-list
processor state) — pre-v7 binary blobs cannot decode because the new
fields are strictly appended after the v6 inclusion-list sections.
"""

from __future__ import annotations

import unittest

import messagechain.config as _cfg
from messagechain.config import (
    ARCHIVE_WITHHOLD_TIERS,
    HASH_ALGO,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.archive_duty import ActiveValidatorSnapshot
from messagechain.storage.state_snapshot import (
    STATE_SNAPSHOT_VERSION,
    compute_state_root,
    decode_snapshot,
    encode_snapshot,
    serialize_state,
)


# Shared test config shrink so integration tests fit the test-profile
# WOTS+ leaf budget.  Same pattern as test_archive_duty_wiring.
_SAVED: dict = {}
_TEST_INTERVAL = 5
_TEST_WINDOW = 2


def setUpModule():
    _SAVED["cfg_interval"] = _cfg.ARCHIVE_CHALLENGE_INTERVAL
    _SAVED["cfg_window"] = _cfg.ARCHIVE_SUBMISSION_WINDOW
    _SAVED["cfg_grace"] = _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS
    grace_epochs = (
        _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS
        // max(_cfg.ARCHIVE_CHALLENGE_INTERVAL, 1)
    )
    _cfg.ARCHIVE_CHALLENGE_INTERVAL = _TEST_INTERVAL
    _cfg.ARCHIVE_SUBMISSION_WINDOW = _TEST_WINDOW
    _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS = grace_epochs * _TEST_INTERVAL
    import messagechain.consensus.archive_challenge as _ac
    _SAVED["ac_interval"] = _ac.ARCHIVE_CHALLENGE_INTERVAL
    _SAVED["ac_window"] = _ac.ARCHIVE_SUBMISSION_WINDOW
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _TEST_INTERVAL
    _ac.ARCHIVE_SUBMISSION_WINDOW = _TEST_WINDOW


def tearDownModule():
    _cfg.ARCHIVE_CHALLENGE_INTERVAL = _SAVED["cfg_interval"]
    _cfg.ARCHIVE_SUBMISSION_WINDOW = _SAVED["cfg_window"]
    _cfg.ARCHIVE_BOOTSTRAP_GRACE_BLOCKS = _SAVED["cfg_grace"]
    import messagechain.consensus.archive_challenge as _ac
    _ac.ARCHIVE_CHALLENGE_INTERVAL = _SAVED["ac_interval"]
    _ac.ARCHIVE_SUBMISSION_WINDOW = _SAVED["ac_window"]


def _eid(byte: int) -> bytes:
    return bytes([byte]) * 32


def _minimal_snap(**overrides) -> dict:
    """Hand-built snapshot dict with all required fields + sensible
    defaults.  Overrides clobber specific keys.
    """
    snap = {
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
        "total_supply": 1000,
        "total_minted": 0,
        "total_fees_collected": 0,
        "total_burned": 0,
        "base_fee": 100,
        "finalized_checkpoints": {},
        "seed_initial_stakes": {},
        "seed_divestment_debt": {},
        "archive_reward_pool": 0,
        "censorship_pending": {},
        "censorship_processed": set(),
        "receipt_subtree_roots": {},
        "bogus_rejection_processed": set(),
        # v6 fields (added by inclusion-list; other test modules can
        # exercise these, we just need them present so encode_snapshot
        # doesn't KeyError):
        "inclusion_list_active": {},
        "inclusion_list_processed_violations": set(),
        # New v7 fields (this iteration):
        "validator_archive_misses": {},
        "validator_first_active_block": {},
        "archive_active_snapshot": None,
    }
    snap.update(overrides)
    return snap


# ---------------------------------------------------------------------------
# 1. Snapshot version bump
# ---------------------------------------------------------------------------


class TestVersionBump(unittest.TestCase):
    def test_version_is_7(self):
        """v7 is the wire format for this iteration — codifies the
        three duty fields (v6 was taken by inclusion-list)."""
        self.assertEqual(STATE_SNAPSHOT_VERSION, 7)


# ---------------------------------------------------------------------------
# 2. Round-trip encoding
# ---------------------------------------------------------------------------


class TestRoundTrip(unittest.TestCase):
    def test_empty_duty_fields_roundtrip(self):
        """Fresh chain — all three duty fields empty.  Round-trip
        preserves them.
        """
        snap = _minimal_snap()
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(decoded["validator_archive_misses"], {})
        self.assertEqual(decoded["validator_first_active_block"], {})
        self.assertIsNone(decoded["archive_active_snapshot"])

    def test_misses_roundtrip(self):
        misses = {_eid(1): 1, _eid(2): 3, _eid(3): 7}
        snap = _minimal_snap(validator_archive_misses=misses)
        decoded = decode_snapshot(encode_snapshot(snap))
        self.assertEqual(decoded["validator_archive_misses"], misses)

    def test_first_active_roundtrip(self):
        first_active = {_eid(1): 100, _eid(2): 250_000}
        snap = _minimal_snap(validator_first_active_block=first_active)
        decoded = decode_snapshot(encode_snapshot(snap))
        self.assertEqual(
            decoded["validator_first_active_block"], first_active,
        )

    def test_open_snapshot_roundtrip(self):
        """An open challenge carries a challenge_block, active_set, and
        K challenge_heights.  All three must survive a binary round
        trip so a restart during the submission window picks up where
        it left off.
        """
        snap_obj = ActiveValidatorSnapshot(
            challenge_block=500,
            active_set=frozenset([_eid(1), _eid(2), _eid(3)]),
            challenge_heights=(100, 200, 300),
        )
        snap = _minimal_snap(archive_active_snapshot=snap_obj)
        decoded = decode_snapshot(encode_snapshot(snap))
        out = decoded["archive_active_snapshot"]
        self.assertIsInstance(out, ActiveValidatorSnapshot)
        self.assertEqual(out.challenge_block, 500)
        self.assertEqual(out.active_set, frozenset([_eid(1), _eid(2), _eid(3)]))
        self.assertEqual(out.challenge_heights, (100, 200, 300))


# ---------------------------------------------------------------------------
# 3. State-root inclusion
# ---------------------------------------------------------------------------


class TestStateRootIncludesDuty(unittest.TestCase):
    def test_miss_counter_affects_state_root(self):
        """A validator with +1 miss must produce a different state
        root than one with 0 misses — otherwise two nodes could agree
        on the snapshot but compute different withhold amounts.
        """
        base = _minimal_snap()
        alt = _minimal_snap(
            validator_archive_misses={_eid(1): 1},
        )
        self.assertNotEqual(
            compute_state_root(base),
            compute_state_root(alt),
        )

    def test_first_active_affects_state_root(self):
        """Bootstrap grace is per-validator and per-join-height, so the
        state root must bind first_active_block.
        """
        base = _minimal_snap()
        alt = _minimal_snap(
            validator_first_active_block={_eid(1): 42},
        )
        self.assertNotEqual(
            compute_state_root(base),
            compute_state_root(alt),
        )

    def test_open_snapshot_affects_state_root(self):
        """Whether an epoch is currently open (and which heights it
        challenges) affects which validators get miss-bumped at epoch
        close — must be bound into the state root.
        """
        base = _minimal_snap()
        alt = _minimal_snap(
            archive_active_snapshot=ActiveValidatorSnapshot(
                challenge_block=5,
                active_set=frozenset([_eid(1)]),
                challenge_heights=(1, 2, 3),
            ),
        )
        self.assertNotEqual(
            compute_state_root(base),
            compute_state_root(alt),
        )

    def test_snapshot_heights_affect_state_root(self):
        """Two open snapshots over the same active set but different
        challenge heights MUST NOT collapse to the same root — else a
        grinding proposer could surreptitiously change which heights
        were challenged.
        """
        common_set = frozenset([_eid(1)])
        a = _minimal_snap(
            archive_active_snapshot=ActiveValidatorSnapshot(
                challenge_block=5, active_set=common_set,
                challenge_heights=(1, 2, 3),
            ),
        )
        b = _minimal_snap(
            archive_active_snapshot=ActiveValidatorSnapshot(
                challenge_block=5, active_set=common_set,
                challenge_heights=(4, 5, 6),
            ),
        )
        self.assertNotEqual(compute_state_root(a), compute_state_root(b))


# ---------------------------------------------------------------------------
# 4. Reward-path withhold (integration)
# ---------------------------------------------------------------------------


def _fresh_chain_with_validators(validator_count: int = 3):
    from messagechain.identity.identity import Entity
    from messagechain.core.blockchain import Blockchain
    from messagechain.consensus.pos import ProofOfStake
    validators = [
        Entity.create(f"duty-persist-v{i}".encode().ljust(32, b"\x00"))
        for i in range(validator_count)
    ]
    chain = Blockchain()
    chain.initialize_genesis(validators[0])
    for v in validators:
        chain.public_keys[v.entity_id] = v.keypair.public_key
        chain.supply.balances[v.entity_id] = 10_000_000
        chain.supply.stake(v.entity_id, VALIDATOR_MIN_STAKE * 10)
    pos = ProofOfStake()
    return chain, validators, pos


def _propose_empty(chain, validators, pos):
    latest = chain.chain[-1]
    selected_id = chain._selected_proposer_for_slot(latest, round_number=0)
    proposer = next(v for v in validators if v.entity_id == selected_id)
    block = chain.propose_block(pos, proposer, transactions=[])
    ok, reason = chain.add_block(block)
    assert ok, f"block rejected: {reason}"
    return block, proposer


class TestRewardWithhold(unittest.TestCase):
    def test_zero_miss_no_withhold(self):
        """Compliant validator (miss=0) receives the full reward; pool
        balance unchanged by withhold (may still change for other
        reasons like fee-burn redirect, but this test runs zero-fee
        blocks, so the pool's delta is strictly from withhold).
        """
        chain, vals, pos = _fresh_chain_with_validators(1)
        pool_before = chain.archive_reward_pool
        _propose_empty(chain, vals, pos)
        # No miss counter set — proposer should receive full reward.
        # Pool shouldn't gain anything from withhold (empty-tx block
        # has no fee burn either, so pool delta == 0).
        self.assertEqual(chain.archive_reward_pool, pool_before)

    def test_withhold_routes_to_archive_pool(self):
        """A validator with miss_count=1 has 25% of their proposer
        reward diverted into the archive pool.  Verify the delta
        matches ARCHIVE_WITHHOLD_TIERS[1].
        """
        chain, vals, pos = _fresh_chain_with_validators(1)
        v = vals[0]
        # Age the validator past bootstrap grace so withhold applies.
        chain.validator_first_active_block[v.entity_id] = -1_000_000
        # Inject a miss count of 1.
        chain.validator_archive_misses[v.entity_id] = 1

        balance_before = chain.supply.balances[v.entity_id]
        pool_before = chain.archive_reward_pool
        _propose_empty(chain, vals, pos)
        balance_delta = chain.supply.balances[v.entity_id] - balance_before
        pool_delta = chain.archive_reward_pool - pool_before

        # The proposer still ends up net positive (gross_reward - withheld),
        # and the pool gained exactly the withheld amount.  Ratios follow
        # the tier table.
        tier_pct = ARCHIVE_WITHHOLD_TIERS[1]  # 25
        # With 1-validator chain, block reward is the full proposer
        # reward (no committee).  Reconstruct gross from pool + net.
        gross = balance_delta + pool_delta
        self.assertGreater(gross, 0)
        expected_pool = gross * tier_pct // 100
        self.assertEqual(pool_delta, expected_pool)

    def test_full_withhold_at_max_miss_tier(self):
        """miss_count saturating the tier table sends 100% of the
        proposer's reward to the archive pool; their balance is
        unchanged by this block's mint.
        """
        chain, vals, pos = _fresh_chain_with_validators(1)
        v = vals[0]
        chain.validator_first_active_block[v.entity_id] = -1_000_000
        chain.validator_archive_misses[v.entity_id] = len(ARCHIVE_WITHHOLD_TIERS)

        balance_before = chain.supply.balances[v.entity_id]
        pool_before = chain.archive_reward_pool
        _propose_empty(chain, vals, pos)
        balance_delta = chain.supply.balances[v.entity_id] - balance_before
        pool_delta = chain.archive_reward_pool - pool_before

        # 100%-tier = proposer receives nothing from this mint; whole
        # gross reward lands in pool.
        self.assertEqual(balance_delta, 0)
        self.assertGreater(pool_delta, 0)

    def test_bootstrap_exempt_validator_no_withhold(self):
        """A validator still in bootstrap grace, even with a fresh
        miss count (shouldn't happen in normal flow but defensively),
        is not withheld from.
        """
        chain, vals, pos = _fresh_chain_with_validators(1)
        v = vals[0]
        # Genesis-age (not aged past grace) — still exempt.
        chain.validator_archive_misses[v.entity_id] = 3
        pool_before = chain.archive_reward_pool
        _propose_empty(chain, vals, pos)
        # Grace-exempt → no withhold → pool unchanged by withhold.
        self.assertEqual(chain.archive_reward_pool, pool_before)


if __name__ == "__main__":
    unittest.main()
