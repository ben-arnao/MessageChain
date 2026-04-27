"""VALIDATOR_MIN_STAKE raise hard fork: 100 -> 10,000.

Background
----------
When GENESIS_SUPPLY was rebased from 1B to 140M, the legacy
VALIDATOR_MIN_STAKE of 100 tokens dropped to 0.00007% of supply —
sybil-trivial.  Raising to 10,000 (0.007%) keeps validator entry
permissionless but imposes meaningful per-validator capital cost.

Activation-gated at MIN_STAKE_RAISE_HEIGHT (placeholder 50_000) so
historical chain state pre-fork replays deterministically.

Grandfathering policy
---------------------
- Existing validators with stake < new floor KEEP their stake unchanged.
- Post-activation, a StakeTransaction whose (current_stake + tx.amount)
  is below the new floor is REJECTED.
- UnstakeTransaction that drops below the new floor without fully
  exiting is REJECTED post-activation.  Full exit (remaining == 0) is
  always permitted.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import messagechain.config as config
from messagechain.core.transaction import calculate_min_fee
from messagechain.economics.inflation import SupplyTracker


def _fee_for_wots_sig(public_key_len: int = 32) -> int:
    """Fee large enough to cover a typical WOTS+ signature + auth path.

    Post-FEE_INCLUDES_SIGNATURE_HEIGHT (50_000) callers must pay for
    the witness bytes; under-paying fails the fee gate before the
    min-stake check runs, producing false-positive test failures.
    Over-estimate here so sig-size variations across algorithms don't
    break the test — stake-tx fee is not the property under test.
    """
    # Typical WOTS+ sig + auth path ~2.7 KB; budget 4 KB to be safe.
    return calculate_min_fee(b"", signature_bytes=4096)


class TestMinStakeRaiseConstants(unittest.TestCase):
    """Constants + helper function + activation gate."""

    def test_legacy_constant_unchanged(self):
        """Pre-activation value must byte-mirror the current constant."""
        self.assertEqual(config.VALIDATOR_MIN_STAKE, 100)

    def test_post_raise_constant_exists(self):
        self.assertTrue(hasattr(config, "VALIDATOR_MIN_STAKE_POST_RAISE"))
        self.assertEqual(config.VALIDATOR_MIN_STAKE_POST_RAISE, 10_000)

    def test_activation_height_canonical(self):
        self.assertTrue(hasattr(config, "MIN_STAKE_RAISE_HEIGHT"))
        # Compressed in 1.11.0 from 60_000 to 1000; fast-forwarded to 701 in 1.26.0.
        self.assertEqual(config.MIN_STAKE_RAISE_HEIGHT, 701)

    def test_helper_exists(self):
        self.assertTrue(hasattr(config, "get_validator_min_stake"))

    def test_pre_activation_returns_legacy(self):
        self.assertEqual(
            config.get_validator_min_stake(config.MIN_STAKE_RAISE_HEIGHT - 1),
            100,
        )
        self.assertEqual(config.get_validator_min_stake(0), 100)

    def test_at_activation_returns_new(self):
        self.assertEqual(
            config.get_validator_min_stake(config.MIN_STAKE_RAISE_HEIGHT),
            10_000,
        )

    def test_post_activation_returns_new(self):
        self.assertEqual(
            config.get_validator_min_stake(
                config.MIN_STAKE_RAISE_HEIGHT + 10_000,
            ),
            10_000,
        )


class TestVerifyStakeTransactionGate(unittest.TestCase):
    """verify_stake_transaction enforces the fork-gated minimum."""

    def _make_stake_tx(self, amount: int, fee: int | None = None):
        from messagechain.core.staking import create_stake_transaction
        from messagechain.identity.identity import Entity
        alice = Entity.create(b"min-stake-raise-gate".ljust(32, b"\x00"))
        return alice, create_stake_transaction(
            alice, amount=amount, nonce=0,
            fee=fee if fee is not None else _fee_for_wots_sig(),
        )

    def test_pre_activation_accepts_500(self):
        """Pre-fork: amount=500 clears the 100-token floor."""
        from messagechain.core.staking import verify_stake_transaction
        alice, tx = self._make_stake_tx(500, fee=config.MIN_FEE)
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_RAISE_HEIGHT - 1,
            current_height=config.MIN_STAKE_RAISE_HEIGHT - 1,
        )
        self.assertTrue(ok)

    def test_pre_activation_rejects_50(self):
        """Pre-fork: amount=50 is below the 100-token legacy floor."""
        from messagechain.core.staking import verify_stake_transaction
        alice, tx = self._make_stake_tx(50, fee=config.MIN_FEE)
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_RAISE_HEIGHT - 1,
            current_height=config.MIN_STAKE_RAISE_HEIGHT - 1,
        )
        self.assertFalse(ok)

    def test_post_activation_accepts_50000(self):
        """Post-fork: amount=50k clears the 10k floor for a fresh validator.

        Uses a signature-aware fee since post-activation callers also
        cross the FEE_INCLUDES_SIGNATURE_HEIGHT gate (same height).
        """
        from messagechain.core.staking import verify_stake_transaction
        alice, tx = self._make_stake_tx(50_000)
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
            current_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
        )
        self.assertTrue(ok)

    def test_post_activation_rejects_5000(self):
        """Post-fork: amount=5k falls below the 10k floor."""
        from messagechain.core.staking import verify_stake_transaction
        alice, tx = self._make_stake_tx(5_000)
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
            current_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
        )
        self.assertFalse(ok)


class TestGrandfatherTopUp(unittest.TestCase):
    """A legacy sub-floor validator can't top up without clearing the new floor."""

    def _post_fork_chain(self, entity):
        """Build a chain whose `height` property reports post-fork.

        `Blockchain.height` is a read-only property derived from
        `len(self.chain)`.  We swap it out with a PropertyMock that
        returns a post-fork height so the validation path exercises
        the MIN_STAKE_RAISE gate without needing hundreds of dummy
        blocks.
        """
        from messagechain.core.blockchain import Blockchain
        from tests import register_entity_for_test
        chain = Blockchain()
        chain.initialize_genesis(entity)
        register_entity_for_test(chain, entity)
        return chain

    def test_legacy_500_cannot_add_1000(self):
        """500 + 1000 = 1500 still < 10k floor post-activation -> reject."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.staking import create_stake_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"legacy-500-topup".ljust(32, b"\x00"))
        chain = self._post_fork_chain(alice)
        # Fund and manually seed legacy sub-floor stake (500).
        chain.supply.balances[alice.entity_id] = 100_000
        chain.supply.staked[alice.entity_id] = 500
        tx = create_stake_transaction(
            alice, amount=1_000, nonce=chain.nonces.get(alice.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        post_fork_h = config.MIN_STAKE_RAISE_HEIGHT + 100
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: post_fork_h),
        ):
            ok, _reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertFalse(ok, (
            "top-up leaving total stake 1500 below new 10k floor must be "
            "rejected"
        ))

    def test_legacy_500_can_top_up_to_clear_floor(self):
        """500 + 9500 = 10000 clears the floor exactly -> accept."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.staking import create_stake_transaction
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"legacy-500-clear".ljust(32, b"\x00"))
        chain = self._post_fork_chain(alice)
        chain.supply.balances[alice.entity_id] = 100_000
        chain.supply.staked[alice.entity_id] = 500
        tx = create_stake_transaction(
            alice, amount=9_500, nonce=chain.nonces.get(alice.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        post_fork_h = config.MIN_STAKE_RAISE_HEIGHT + 100
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: post_fork_h),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(ok, f"500+9500=10000 must clear the 10k floor: {reason}")


class TestGrandfatherFullExit(unittest.TestCase):
    """Full unstake (remaining == 0) is always permitted, even for legacy sub-floor."""

    def test_legacy_500_can_fully_unstake(self):
        chain_supply = SupplyTracker()
        eid = b"a" * 32
        chain_supply.staked[eid] = 500
        ok = chain_supply.unstake(
            eid, 500,
            current_block=config.MIN_STAKE_RAISE_HEIGHT + 100,
        )
        self.assertTrue(ok, "full exit (remaining == 0) must be allowed")
        self.assertEqual(chain_supply.get_staked(eid), 0)

    def test_legacy_500_cannot_partially_unstake(self):
        """200 of 500 leaves 300, below the new 10k floor and > 0 -> reject."""
        chain_supply = SupplyTracker()
        eid = b"a" * 32
        chain_supply.staked[eid] = 500
        ok = chain_supply.unstake(
            eid, 200,
            current_block=config.MIN_STAKE_RAISE_HEIGHT + 100,
        )
        self.assertFalse(ok, "partial exit leaving 300 < 10k floor must reject")
        # Stake unchanged.
        self.assertEqual(chain_supply.get_staked(eid), 500)


class TestFreshValidatorAtExactFloor(unittest.TestCase):
    """Post-activation: a fresh validator at exactly the new floor is accepted."""

    def test_fresh_10000_accepted(self):
        from messagechain.core.staking import (
            create_stake_transaction, verify_stake_transaction,
        )
        from messagechain.identity.identity import Entity
        alice = Entity.create(b"exact-floor-validator".ljust(32, b"\x00"))
        tx = create_stake_transaction(
            alice, amount=10_000, nonce=0, fee=_fee_for_wots_sig(),
        )
        ok = verify_stake_transaction(
            tx, alice.public_key,
            block_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
            current_height=config.MIN_STAKE_RAISE_HEIGHT + 1,
        )
        self.assertTrue(ok)


class TestLegacyValidatorCanAttest(unittest.TestCase):
    """A legacy 500-stake validator registered pre-fork can still attest post-fork.

    The enforcement site is `Blockchain._selected_proposer_for_slot`, which
    filters the active set to `amt >= min_stake`.  Post-fork, a 500-stake
    legacy validator would be filtered out if we used the new floor for the
    ACTIVE-SET gate — but grandfathering policy says existing stake is kept
    unchanged.  So the active-set filter stays at the LEGACY floor to
    preserve existing validators' participation rights; only *new* stake /
    partial-unstake operations are subject to the new floor.
    """

    def test_legacy_500_stays_in_validator_set(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.identity.identity import Entity

        alice = Entity.create(b"legacy-stayer".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(alice)
        # Legacy 500 stake — grandfathered, must remain addressable.
        chain.supply.staked[alice.entity_id] = 500

        pos = ProofOfStake()
        # sync_consensus_stakes pulls from supply into consensus.stakes;
        # the hook we're adding must honor grandfathering (floor = legacy).
        chain.sync_consensus_stakes(
            pos, block_height=config.MIN_STAKE_RAISE_HEIGHT + 100,
        )
        self.assertIn(
            alice.entity_id, pos.stakes,
            "legacy 500-stake validator must remain in the active set "
            "(grandfathered); otherwise they silently lose attestation "
            "rights at the fork boundary",
        )


if __name__ == "__main__":
    unittest.main()
