"""VALIDATOR_MIN_STAKE drop hard fork (Tier 28): 10_000 -> FAUCET_DRIP.

The post-Tier-2 floor of 10_000 (0.007% of supply) made permissionless
validator entry "permissionless on paper, $X capital wall in practice."
Tier 28 drops the floor to exactly one faucet drip so any user who can
solve the faucet PoW can spin up a validator from a single grab.

Trade-off (acknowledged by the operator): sybil cost collapses to ~one
faucet drip + the per-/24 + PoW limits the faucet enforces.  Slashing
still bites, but the absolute burn-on-misbehavior shrinks proportionally.

Activation-gated at MIN_STAKE_FAUCET_DRIP_HEIGHT so historical chain
state pre-fork replays deterministically.

Grandfathering policy
---------------------
Mechanically a no-op vs. Tier 2: every validator currently sitting at or
above the 10k post-raise floor is automatically above the new 300 floor.
The fork only widens admission for fresh stake / partial unstake to the
new lower floor.
"""

from __future__ import annotations

import unittest

import messagechain.config as config
from messagechain.network.faucet import FAUCET_DRIP


class TestMinStakeFaucetDripConstants(unittest.TestCase):

    def test_constant_exists(self):
        self.assertTrue(hasattr(config, "VALIDATOR_MIN_STAKE_FAUCET_DRIP"))

    def test_constant_equals_faucet_drip(self):
        """The whole point of the fork: floor == one faucet grab."""
        self.assertEqual(
            config.VALIDATOR_MIN_STAKE_FAUCET_DRIP, FAUCET_DRIP,
            "VALIDATOR_MIN_STAKE_FAUCET_DRIP must track FAUCET_DRIP "
            "byte-for-byte; if FAUCET_DRIP moves, this constant moves with it",
        )

    def test_activation_height_exists(self):
        self.assertTrue(hasattr(config, "MIN_STAKE_FAUCET_DRIP_HEIGHT"))
        self.assertIsInstance(config.MIN_STAKE_FAUCET_DRIP_HEIGHT, int)

    def test_activation_above_prior_tier(self):
        """Tier 28 must follow Tier 27 (REACT_NO_SELF_MESSAGE_HEIGHT)."""
        self.assertGreater(
            config.MIN_STAKE_FAUCET_DRIP_HEIGHT,
            config.REACT_NO_SELF_MESSAGE_HEIGHT,
        )

    def test_activation_above_min_stake_raise(self):
        """Sanity: this fork strictly post-dates the prior min-stake fork."""
        self.assertGreater(
            config.MIN_STAKE_FAUCET_DRIP_HEIGHT,
            config.MIN_STAKE_RAISE_HEIGHT,
        )


class TestMinStakeFaucetDripGate(unittest.TestCase):
    """get_validator_min_stake returns the new floor at/after activation."""

    def test_pre_activation_returns_10k(self):
        h = config.MIN_STAKE_FAUCET_DRIP_HEIGHT - 1
        self.assertEqual(
            config.get_validator_min_stake(h),
            config.VALIDATOR_MIN_STAKE_POST_RAISE,
            "pre-Tier-28 callers must continue to see the 10k floor for "
            "deterministic replay of pre-fork blocks",
        )

    def test_at_activation_returns_drip(self):
        self.assertEqual(
            config.get_validator_min_stake(config.MIN_STAKE_FAUCET_DRIP_HEIGHT),
            FAUCET_DRIP,
        )

    def test_post_activation_returns_drip(self):
        # Sample inside the Tier 28 era (between Tier 28 activation and
        # Tier 29 activation).  Tier 29 lowers the floor again so a
        # height at "+ 50_000" past Tier 28 would already be in Tier 29
        # territory and return the Tier 29 floor instead.
        h = (
            config.MIN_STAKE_FAUCET_DRIP_HEIGHT
            + (config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT
               - config.MIN_STAKE_FAUCET_DRIP_HEIGHT) // 2
        )
        self.assertEqual(
            config.get_validator_min_stake(h),
            FAUCET_DRIP,
        )

    def test_legacy_path_still_returns_100(self):
        """Pre-Tier-2 callers must continue to see the 100-token legacy floor."""
        self.assertEqual(
            config.get_validator_min_stake(0),
            config.VALIDATOR_MIN_STAKE,
        )


class TestFreshValidatorAtFaucetDrip(unittest.TestCase):
    """Post-Tier-28: a fresh validator at exactly FAUCET_DRIP is accepted."""

    def test_fresh_drip_amount_accepted(self):
        from messagechain.core.staking import (
            create_stake_transaction, verify_stake_transaction,
        )
        from messagechain.core.transaction import calculate_min_fee
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"faucet-drip-validator".ljust(32, b"\x00"))
        tx = create_stake_transaction(
            alice, amount=FAUCET_DRIP, nonce=0,
            fee=calculate_min_fee(b"", signature_bytes=4096),
        )
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT + 1,
            current_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT + 1,
        )
        self.assertTrue(
            ok,
            "fresh stake of exactly one faucet drip must clear the new floor",
        )

    def test_fresh_below_drip_rejected(self):
        from messagechain.core.staking import (
            create_stake_transaction, verify_stake_transaction,
        )
        from messagechain.core.transaction import calculate_min_fee
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"faucet-below-floor".ljust(32, b"\x00"))
        tx = create_stake_transaction(
            alice, amount=FAUCET_DRIP - 1, nonce=0,
            fee=calculate_min_fee(b"", signature_bytes=4096),
        )
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT + 1,
            current_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT + 1,
        )
        self.assertFalse(
            ok,
            "stake of (drip - 1) sits below the floor and must reject",
        )

    def test_pre_activation_still_requires_10k(self):
        """Pre-Tier-28 the 10k floor still applies — drip-sized stake rejects."""
        from messagechain.core.staking import (
            create_stake_transaction, verify_stake_transaction,
        )
        from messagechain.core.transaction import calculate_min_fee
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"pre-tier28-rejecter".ljust(32, b"\x00"))
        tx = create_stake_transaction(
            alice, amount=FAUCET_DRIP, nonce=0,
            fee=calculate_min_fee(b"", signature_bytes=4096),
        )
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT - 1,
            current_height=config.MIN_STAKE_FAUCET_DRIP_HEIGHT - 1,
        )
        self.assertFalse(
            ok,
            "pre-Tier-28: drip-sized stake is below the 10k floor — must reject",
        )


if __name__ == "__main__":
    unittest.main()
