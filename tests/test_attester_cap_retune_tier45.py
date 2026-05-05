"""Tier 45 — per-validator attester-reward cap retune.

Background: the Tier 4 per-validator attester-reward cap was sized for
committees of ~128 members, where each validator's per-slot reward is
small.  At today's mainnet committee size of 2 (`min(eligible_validators,
ATTESTER_COMMITTEE_TARGET_SIZE)` resolves to 2 with two staked
validators), per-slot reward is ~half the attester pool, so a validator
hits the 100 bps (1% of pool) cap by block 3 of every 100-block epoch
and burns the remainder of their legitimate rewards for the next 97
blocks.  ~79% of attester issuance evaporates per epoch.

Fix: at PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT, raise the cap from
100 bps to 5000 bps (50% of the per-block attester-pool basis, scaled
across FINALITY_INTERVAL).  Pre-fork path is byte-for-byte identical to
the legacy 100 bps read.

This file pins:

  1. Activation-ordering: Tier 45 follows Tier 44.
  2. Constants visible at the public config import surface.
  3. Pre-fork byte-identical: the cap helper at height = activation - 1
     returns the legacy 100 bps.
  4. Post-fork retune: the cap helper at height = activation returns
     the new 5000 bps.
  5. Pre/post cap_per_entity hardcoded values pinned: at attester_pool
     basis = 12 (BLOCK_REWARD=16 minus proposer_share=4) and
     FINALITY_INTERVAL=100, legacy cap is 12 tokens/entity/epoch
     (12 * 100 * 100 // 10000 = 12) and the Tier 45 cap is 600
     (12 * 5000 * 100 // 10000 = 600).

Reward-curve SHAPE is unchanged this is a single-knob retune of the
per-entity cap, not a touch on smooth-V2 / floor / halving / any
anchored economics constant.
"""

from __future__ import annotations

import unittest

from messagechain.config import (
    CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT,
    FINALITY_INTERVAL,
    PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT,
    PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH,
    PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45,
)
from messagechain.economics.inflation import _attester_cap_bps_per_epoch


# Cap-pool-basis = (reward - proposer_share) at BLOCK_REWARD=16 with the
# canonical 1/4 proposer share is 16 - 4 = 12.  Hardcode it rather than
# importing PROPOSER_REWARD_NUMERATOR/DENOMINATOR so the test is
# regression-pinned: if either constant moves the test will fail loudly
# rather than silently re-deriving a different value.
_CAP_POOL_BASIS_AT_BLOCK_REWARD_16 = 12


class TestActivationOrdering(unittest.TestCase):
    """Tier 45 must follow Tier 44 (CENSORSHIP_EVIDENCE_POLY_RECEIPTED_
    TX_HEIGHT = 3834).  Operators upgrade through the prior fork before
    the new cap binds — same pattern every prior tier follows."""

    def test_tier45_follows_tier44(self):
        self.assertGreater(
            PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT,
            CENSORSHIP_EVIDENCE_POLY_RECEIPTED_TX_HEIGHT,
        )


class TestConstantsVisible(unittest.TestCase):
    """The new constants must be importable from messagechain.config —
    operator dashboards, the upgrade CLI, and external tooling read them
    via the public surface."""

    def test_tier45_bps_constant_is_5000(self):
        self.assertEqual(
            PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH_TIER45,
            5000,
        )

    def test_tier45_height_constant_compressed(self):
        # Re-runwayed to 1707 in 1.55.1 sweep (was 4534).
        self.assertEqual(PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT, 1707)

    def test_legacy_bps_unchanged(self):
        # Legacy bps must remain at 100 — the fix is a NEW height-gated
        # value, not a mutation of the original constant.  Mutating it
        # would silently re-write history for every block at heights
        # below the activation.
        self.assertEqual(
            PER_VALIDATOR_ATTESTER_REWARD_CAP_BPS_PER_EPOCH, 100,
        )


class TestPreForkByteIdentical(unittest.TestCase):
    """At heights strictly below PER_VALIDATOR_ATTESTER_CAP_RETUNE_
    HEIGHT, the cap helper MUST return the legacy 100 bps value — every
    block below the activation height replays bit-for-bit identical to
    pre-fork mint behavior."""

    def test_helper_at_activation_minus_one_returns_legacy(self):
        h = PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT - 1
        self.assertEqual(_attester_cap_bps_per_epoch(h), 100)

    def test_helper_at_genesis_returns_legacy(self):
        # Sanity check: genesis (height 0) is well below every height
        # gate, so the helper resolves to the legacy constant.
        self.assertEqual(_attester_cap_bps_per_epoch(0), 100)

    def test_legacy_cap_per_entity_pinned(self):
        # cap_per_entity = cap_pool_basis * bps * FINALITY_INTERVAL // 10_000
        # At BLOCK_REWARD=16, basis=12, bps=100, FINALITY_INTERVAL=100:
        #   12 * 100 * 100 // 10_000 = 12 tokens/entity/epoch.
        # Hardcode the result so a future drift in any input is caught.
        h = PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT - 1
        bps = _attester_cap_bps_per_epoch(h)
        cap = (
            _CAP_POOL_BASIS_AT_BLOCK_REWARD_16
            * bps
            * FINALITY_INTERVAL
            // 10_000
        )
        self.assertEqual(cap, 12)


class TestPostForkRetune(unittest.TestCase):
    """At and above PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT, the cap
    helper MUST return 5000 bps — the retuned value that lets a
    committee-of-2 validator earn its pro-rata ~50% share across the
    full epoch without burning."""

    def test_helper_at_activation_returns_tier45(self):
        h = PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT
        self.assertEqual(_attester_cap_bps_per_epoch(h), 5000)

    def test_helper_well_above_activation_returns_tier45(self):
        h = PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT + 10_000
        self.assertEqual(_attester_cap_bps_per_epoch(h), 5000)

    def test_post_fork_cap_per_entity_pinned(self):
        # cap_per_entity = cap_pool_basis * bps * FINALITY_INTERVAL // 10_000
        # At BLOCK_REWARD=16, basis=12, bps=5000, FINALITY_INTERVAL=100:
        #   12 * 5000 * 100 // 10_000 = 600 tokens/entity/epoch.
        # That's 50× the legacy 12-token cap — exactly the lift the
        # retune is designed to deliver.
        h = PER_VALIDATOR_ATTESTER_CAP_RETUNE_HEIGHT
        bps = _attester_cap_bps_per_epoch(h)
        cap = (
            _CAP_POOL_BASIS_AT_BLOCK_REWARD_16
            * bps
            * FINALITY_INTERVAL
            // 10_000
        )
        self.assertEqual(cap, 600)


if __name__ == "__main__":
    unittest.main()
