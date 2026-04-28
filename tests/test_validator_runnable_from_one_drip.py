"""Tier 29: a single faucet drip is enough to spin up a validator.

Tier 28 set the stake floor to FAUCET_DRIP=300 and Tier 6's
VALIDATOR_REGISTRATION_BURN=10_000 was still in force, so the
end-to-end first-time-validator cost was still 10_300+fee.
Tier 29 closes both gaps:

    1. ``VALIDATOR_REGISTRATION_BURN`` drops to 0 at activation, so
       first-time registration carries no burn.
    2. ``VALIDATOR_MIN_STAKE`` drops from FAUCET_DRIP to
       FAUCET_DRIP - MIN_FEE, so the user has room to pay the
       per-stake-tx flat fee floor out of the same drip and stake
       what's left.

Net effect: one faucet drip funds (fee + stake + burn) end to end.
"""

from __future__ import annotations

import unittest

import messagechain.config as config
from messagechain.network.faucet import FAUCET_DRIP


class TestTier29Constants(unittest.TestCase):

    def test_height_constant_exists(self):
        self.assertTrue(hasattr(config, "VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT"))

    def test_tier_ordering_above_tier28(self):
        self.assertGreater(
            config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT,
            config.MIN_STAKE_FAUCET_DRIP_HEIGHT,
        )

    def test_min_stake_helper_returns_drip_minus_fee_floor(self):
        h = config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT
        self.assertEqual(
            config.get_validator_min_stake(h),
            FAUCET_DRIP - config.MIN_FEE,
        )

    def test_min_stake_pre_tier29_still_drip(self):
        """Pre-Tier-29 callers continue to see the Tier 28 floor."""
        # Strictly below Tier 29.  Tier 28 activated at MIN_STAKE_FAUCET_DRIP_HEIGHT,
        # so anywhere in [Tier 28, Tier 29) the floor is FAUCET_DRIP.
        h = config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT - 1
        self.assertGreaterEqual(h, config.MIN_STAKE_FAUCET_DRIP_HEIGHT)
        self.assertEqual(
            config.get_validator_min_stake(h),
            FAUCET_DRIP,
            "between Tier 28 and Tier 29 the floor stays pinned to "
            "FAUCET_DRIP for replay determinism",
        )

    def test_registration_burn_helper_exists(self):
        self.assertTrue(hasattr(config, "get_validator_registration_burn"))

    def test_registration_burn_zero_post_tier29(self):
        self.assertEqual(
            config.get_validator_registration_burn(
                config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT,
            ),
            0,
        )

    def test_registration_burn_legacy_pre_tier29(self):
        """Pre-Tier-29: 10_000 burn (Tier 6 era through Tier 28)."""
        h = config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT - 1
        # Sample a height inside the Tier 6 era (post-Tier-6, pre-Tier-29).
        post_tier6 = config.VALIDATOR_REGISTRATION_BURN_HEIGHT + 1
        self.assertEqual(
            config.get_validator_registration_burn(post_tier6),
            config.VALIDATOR_REGISTRATION_BURN,
        )
        self.assertEqual(
            config.get_validator_registration_burn(h),
            config.VALIDATOR_REGISTRATION_BURN,
        )

    def test_registration_burn_zero_pre_tier6(self):
        """Pre-Tier-6: no burn (the burn fork itself hasn't activated)."""
        self.assertEqual(
            config.get_validator_registration_burn(0),
            0,
        )


class TestValidatorRunnableFromOneDrip(unittest.TestCase):
    """End-to-end: 300-drip wallet can stake 200 + fee 100 + burn 0."""

    def test_drip_fully_funds_first_validator(self):
        """A wallet holding exactly FAUCET_DRIP can land a stake tx."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.staking import create_stake_transaction
        from messagechain.identity.identity import Entity
        from tests import register_entity_for_test
        from unittest.mock import patch

        alice = Entity.create(b"drip-only-validator".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)

        chain.supply.balances[alice.entity_id] = FAUCET_DRIP
        chain.supply.staked[alice.entity_id] = 0
        chain.supply.registered_validators.discard(alice.entity_id)

        # Stake everything except the per-stake-tx fee floor (MIN_FEE).
        stake_amount = FAUCET_DRIP - config.MIN_FEE
        tx = create_stake_transaction(
            alice,
            amount=stake_amount,
            nonce=chain.nonces.get(alice.entity_id, 0),
            fee=config.MIN_FEE,
        )

        post_fork_h = config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT + 100
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: post_fork_h),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx,
                pending_nonces={},
                pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(
            ok,
            f"a single drip must fund stake+fee+burn end to end: {reason}",
        )

    def test_pre_tier29_drip_is_insufficient(self):
        """Pre-Tier-29: 300 drip cannot cover the 10k registration burn."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.staking import create_stake_transaction
        from messagechain.identity.identity import Entity
        from tests import register_entity_for_test
        from unittest.mock import patch

        alice = Entity.create(b"drip-pre-tier29".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        register_entity_for_test(chain, alice)

        chain.supply.balances[alice.entity_id] = FAUCET_DRIP
        chain.supply.staked[alice.entity_id] = 0
        chain.supply.registered_validators.discard(alice.entity_id)

        tx = create_stake_transaction(
            alice,
            amount=FAUCET_DRIP - config.MIN_FEE,
            nonce=chain.nonces.get(alice.entity_id, 0),
            fee=config.MIN_FEE,
        )
        # Sit between Tier 28 activation and Tier 29 activation.  The
        # admission path uses ``apply_height = self.height + 1``, so we
        # patch height = activation - 2 to keep apply_height strictly
        # below VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT.
        between = config.VALIDATOR_RUNNABLE_FROM_DRIP_HEIGHT - 2
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: between),
        ):
            ok, _reason = chain._validate_stake_tx_in_block(
                tx,
                pending_nonces={},
                pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertFalse(
            ok,
            "pre-Tier-29 the 10k registration burn dominates and must "
            "reject a wallet holding only one drip",
        )


if __name__ == "__main__":
    unittest.main()
