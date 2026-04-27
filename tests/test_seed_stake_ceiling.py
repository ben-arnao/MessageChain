"""Seed stake ceiling: permanent cap at SEED_MAX_STAKE_CEILING.

After SEED_DIVESTMENT_END_HEIGHT (block 315,576) the forced-divestment
schedule leaves the founder seed at SEED_DIVESTMENT_RETAIN_FLOOR_
POST_RETUNE (= 20M) staked tokens.  Without a stake-side ceiling the
founder can accumulate tokens externally (purchase, transfer, OTC)
and re-stake them, pushing their effective validator weight back to
pre-divestment levels — silently undoing the whole dilution.

The SEED_STAKE_CEILING_HEIGHT hard fork installs a permanent cap:
at/after activation, any StakeTransaction whose entity_id is in
`seed_entity_ids` is rejected when the resulting stake would exceed
SEED_MAX_STAKE_CEILING.

These tests lock the ceiling invariants via the block-level stake
validation path (_validate_stake_tx_in_block):

  * Post-activation, seed cannot re-stake above 20M.
  * Post-activation, seed staking below 20M is accepted.
  * Non-seed validators are unaffected.
  * Pre-activation there is no ceiling (legacy behavior).
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import create_stake_transaction
from messagechain.core.transaction import calculate_min_fee
from messagechain.identity.identity import Entity


def _fee_for_wots_sig() -> int:
    """Signature-size-aware fee (post-FEE_INCLUDES_SIGNATURE_HEIGHT)."""
    return calculate_min_fee(b"", signature_bytes=4096)


def _post_fork_height() -> int:
    """A height safely past every fork the stake path cares about."""
    return max(
        config.SEED_STAKE_CEILING_HEIGHT,
        config.MIN_STAKE_RAISE_HEIGHT,
        config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
    ) + 100


def _build_chain(entity: Entity, is_seed: bool) -> Blockchain:
    """Build a chain with the given entity optionally in seed_entity_ids."""
    from tests import register_entity_for_test
    chain = Blockchain()
    chain.initialize_genesis(entity)
    register_entity_for_test(chain, entity)
    if is_seed:
        chain.seed_entity_ids = frozenset({entity.entity_id})
    else:
        # Ensure the entity is NOT in the seed set for the non-seed path.
        chain.seed_entity_ids = frozenset()
    return chain


class TestSeedStakeCeilingPostActivation(unittest.TestCase):
    """Post-activation: seed cannot stake above SEED_MAX_STAKE_CEILING."""

    def test_seed_cannot_restake_above_ceiling(self):
        """Post-activation: seed at 9M + 2M (total 11M) must be rejected.

        Simulates the attack: founder unstaked to 0 during divestment,
        bought tokens externally past the floor, attempts to re-stake
        past the ceiling in one shot.  Reject is the expected and
        required behavior.
        """
        seed = Entity.create(b"seed-ceiling-over".ljust(32, b"\x00"))
        chain = _build_chain(seed, is_seed=True)
        # Fund liberally so insufficient-balance is NOT why the tx fails.
        chain.supply.balances[seed.entity_id] = 100_000_000
        # Seed already sits at 9M staked — top-up would land at 11M (above 10M ceiling).
        chain.supply.staked[seed.entity_id] = 9_000_000
        tx = create_stake_transaction(
            seed, amount=2_000_000,
            nonce=chain.nonces.get(seed.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: _post_fork_height()),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertFalse(ok, (
            "seed re-stake pushing total above ceiling must be rejected"
        ))
        self.assertIn("seed", reason.lower())

    def test_seed_exactly_at_ceiling_accepted(self):
        """Post-activation: reaching exactly the ceiling (inclusive) is fine.

        Ceiling is <=, not < — the retention floor from divestment IS
        the ceiling value, so staking up to and including it must
        succeed.  Only strictly above is rejected.
        """
        seed = Entity.create(b"seed-ceiling-exact".ljust(32, b"\x00"))
        chain = _build_chain(seed, is_seed=True)
        chain.supply.balances[seed.entity_id] = 100_000_000
        chain.supply.staked[seed.entity_id] = 0
        tx = create_stake_transaction(
            seed, amount=config.SEED_MAX_STAKE_CEILING,
            nonce=chain.nonces.get(seed.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: _post_fork_height()),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(ok, f"staking exactly to ceiling must succeed: {reason}")

    def test_seed_one_above_ceiling_rejected(self):
        """Boundary test: ceiling + 1 is rejected."""
        seed = Entity.create(b"seed-ceiling-plus1".ljust(32, b"\x00"))
        chain = _build_chain(seed, is_seed=True)
        chain.supply.balances[seed.entity_id] = 100_000_000
        chain.supply.staked[seed.entity_id] = 0
        tx = create_stake_transaction(
            seed, amount=config.SEED_MAX_STAKE_CEILING + 1,
            nonce=chain.nonces.get(seed.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: _post_fork_height()),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertFalse(ok, (
            "staking one token above ceiling must be rejected"
        ))
        self.assertIn("seed", reason.lower())

    def test_seed_below_ceiling_accepted(self):
        """Seed topping up from 5M by 2M (total 7M) must succeed.

        Captures the "seed can still operate normally below the
        ceiling" requirement.
        """
        seed = Entity.create(b"seed-ceiling-under".ljust(32, b"\x00"))
        chain = _build_chain(seed, is_seed=True)
        chain.supply.balances[seed.entity_id] = 100_000_000
        chain.supply.staked[seed.entity_id] = 5_000_000
        tx = create_stake_transaction(
            seed, amount=2_000_000,
            nonce=chain.nonces.get(seed.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: _post_fork_height()),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(ok, f"seed stake below ceiling must succeed: {reason}")

    def test_non_seed_unaffected(self):
        """A non-seed validator can stake well above the seed ceiling."""
        bob = Entity.create(b"non-seed-large".ljust(32, b"\x00"))
        chain = _build_chain(bob, is_seed=False)
        chain.supply.balances[bob.entity_id] = 100_000_000
        chain.supply.staked[bob.entity_id] = 0
        tx = create_stake_transaction(
            bob, amount=config.SEED_MAX_STAKE_CEILING + 5_000_000,
            nonce=chain.nonces.get(bob.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: _post_fork_height()),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(ok, (
            f"non-seed validator must be unaffected by seed ceiling: {reason}"
        ))


class TestSeedStakeCeilingPreActivation(unittest.TestCase):
    """Pre-activation: legacy behavior — no ceiling on seeds."""

    def test_pre_activation_seed_can_exceed_ceiling(self):
        """Pre-fork: legacy byte-for-byte — seed can stake to any amount.

        Exercises the activation gate: at height < SEED_STAKE_CEILING_
        HEIGHT the ceiling check does not run.  We place the test
        AFTER MIN_STAKE_RAISE and FEE_INCLUDES_SIGNATURE (so the
        signature-aware fee applies) but BEFORE
        SEED_STAKE_CEILING_HEIGHT so only the ceiling gate is skipped.
        This requires SEED_STAKE_CEILING_HEIGHT to sit strictly above
        the other two — the placeholder value (70_000 > 50_000) gives
        us that window.
        """
        # Apply-time height (block being built) is `self.height + 1`.
        # For pre-activation we need apply_height < SEED_STAKE_CEILING_
        # HEIGHT, so patch self.height to SEED_STAKE_CEILING_HEIGHT - 2
        # (apply_height = SEED_STAKE_CEILING_HEIGHT - 1, strictly below
        # the gate).  We also want apply_height at or beyond the other
        # forks so they're already-active — isolates the seed ceiling
        # gate as the only thing that changes across the window.
        pre_ceiling_h = config.SEED_STAKE_CEILING_HEIGHT - 2
        apply_h_pre_ceiling = pre_ceiling_h + 1  # = SEED_STAKE_CEILING_HEIGHT - 1
        other_forks_max = max(
            config.MIN_STAKE_RAISE_HEIGHT,
            config.FEE_INCLUDES_SIGNATURE_HEIGHT,
        )
        if apply_h_pre_ceiling < other_forks_max:
            self.skipTest(
                "no pre-ceiling window that's also post-other-forks"
            )
        seed = Entity.create(b"seed-preactivation".ljust(32, b"\x00"))
        chain = _build_chain(seed, is_seed=True)
        chain.supply.balances[seed.entity_id] = 100_000_000
        chain.supply.staked[seed.entity_id] = 0
        tx = create_stake_transaction(
            seed,
            amount=config.SEED_MAX_STAKE_CEILING + 1_000_000,
            nonce=chain.nonces.get(seed.entity_id, 0),
            fee=_fee_for_wots_sig(),
        )
        with patch.object(
            Blockchain, "height",
            new=property(lambda self: pre_ceiling_h),
        ):
            ok, reason = chain._validate_stake_tx_in_block(
                tx, pending_nonces={}, pending_balance_spent={},
                pending_balance_credits={},
                pending_pubkey_installs={},
            )
        self.assertTrue(ok, (
            f"pre-activation seed stake above ceiling must succeed "
            f"(legacy behavior): {reason}"
        ))


if __name__ == "__main__":
    unittest.main()
