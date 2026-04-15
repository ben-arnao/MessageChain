"""Stage 5: min-stake gating as a function of bootstrap_progress.

The chain's validator-registration gate used to consult
`graduated_min_stake(block_height)` — a tiered function of raw height.
That couples the "is bootstrap over?" question to a clock, not to the
actual decentralization metric.

This stage introduces `min_stake_for_progress()` so the gate follows
the single `bootstrap_progress` gradient that drives every other
bootstrap-era behavior (attester committee weighting, seed exclusion,
escrow window).  Registration is free-entry (zero stake allowed) for
the first half of bootstrap, then ramps linearly to the full
VALIDATOR_MIN_STAKE by progress = 1.0.

Also exposes `escrow_blocks_for_progress()` for stage 3 to consume.
"""

import unittest

from messagechain.consensus.bootstrap_gradient import (
    min_stake_for_progress,
    escrow_blocks_for_progress,
)


class TestMinStakeFormula(unittest.TestCase):
    """Pure-function behavior of the min-stake gradient."""

    def test_zero_stake_in_first_half(self):
        """Progress < 0.5 → min_stake = 0 (free-entry window)."""
        self.assertEqual(
            min_stake_for_progress(0.0, full_min_stake=100), 0,
        )
        self.assertEqual(
            min_stake_for_progress(0.25, full_min_stake=100), 0,
        )
        # Just below inflection.
        self.assertEqual(
            min_stake_for_progress(0.499, full_min_stake=100), 0,
        )

    def test_ramp_begins_at_inflection(self):
        """At inflection, min_stake = 0 exactly (curve start)."""
        self.assertEqual(
            min_stake_for_progress(0.5, full_min_stake=100), 0,
        )

    def test_full_min_at_progress_one(self):
        """At progress = 1.0, min_stake = full_min_stake."""
        self.assertEqual(
            min_stake_for_progress(1.0, full_min_stake=100), 100,
        )

    def test_linear_ramp_between_inflection_and_one(self):
        """Second half is a linear ramp.  At progress=0.75, min = 50."""
        self.assertEqual(
            min_stake_for_progress(0.75, full_min_stake=100), 50,
        )

    def test_custom_inflection(self):
        """Inflection is configurable — ramp starts wherever caller wants."""
        # Inflection at 0.8: first 80% is free-entry, last 20% ramps
        self.assertEqual(
            min_stake_for_progress(0.5, full_min_stake=100, inflection=0.8), 0,
        )
        self.assertEqual(
            min_stake_for_progress(0.9, full_min_stake=100, inflection=0.8), 50,
        )

    def test_rejects_out_of_range_progress(self):
        with self.assertRaises(ValueError):
            min_stake_for_progress(-0.1, full_min_stake=100)
        with self.assertRaises(ValueError):
            min_stake_for_progress(1.5, full_min_stake=100)

    def test_rejects_invalid_inflection(self):
        with self.assertRaises(ValueError):
            min_stake_for_progress(0.5, full_min_stake=100, inflection=1.0)
        with self.assertRaises(ValueError):
            min_stake_for_progress(0.5, full_min_stake=100, inflection=-0.1)


class TestEscrowFormula(unittest.TestCase):
    """Pure-function behavior of the escrow-window gradient (for stage 3)."""

    def test_max_escrow_at_progress_zero(self):
        self.assertEqual(
            escrow_blocks_for_progress(0.0, max_escrow_blocks=12_960),
            12_960,
        )

    def test_zero_escrow_at_progress_one(self):
        """Escrow collapses to 0 at end of bootstrap."""
        self.assertEqual(
            escrow_blocks_for_progress(1.0, max_escrow_blocks=12_960),
            0,
        )

    def test_linear_decay(self):
        """Halfway through bootstrap, half the max escrow."""
        self.assertEqual(
            escrow_blocks_for_progress(0.5, max_escrow_blocks=12_960),
            6_480,
        )

    def test_rejects_invalid_inputs(self):
        with self.assertRaises(ValueError):
            escrow_blocks_for_progress(1.5, max_escrow_blocks=12_960)
        with self.assertRaises(ValueError):
            escrow_blocks_for_progress(0.5, max_escrow_blocks=-1)


class TestStakeValidationUsesProgress(unittest.TestCase):
    """Blockchain.validate_stake_transaction_in_block consults the
    bootstrap_progress-derived min_stake, not the height-tier table.

    Concrete behavioral guarantee: during early bootstrap, a stake tx
    of any positive amount is accepted (as long as balance + other
    validation checks pass).  At full bootstrap_progress, the stake
    tx must meet VALIDATOR_MIN_STAKE.
    """

    def _make_entity(self, seed: bytes):
        from messagechain.identity.identity import Entity
        return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=4)

    def test_small_stake_accepted_during_bootstrap(self):
        """With progress low, a 1-token stake is accepted on the min-stake
        check (still subject to other checks — balance, nonce, etc.)."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.staking import create_stake_transaction
        from messagechain.config import TREASURY_ENTITY_ID, MIN_FEE

        chain = Blockchain()
        e = self._make_entity(b"small")
        # Register at genesis so nonce is known and pubkey is on-chain.
        chain.initialize_genesis(e, allocation_table={
            TREASURY_ENTITY_ID: 40_000_000,
            e.entity_id: 10_000,  # enough for fee + 1-token stake
        })
        # Force very early bootstrap: no non-seed stake, low height.
        self.assertLess(chain.bootstrap_progress, 0.01)

        stake_tx = create_stake_transaction(e, amount=1, nonce=0, fee=MIN_FEE)
        ok, reason = chain._validate_stake_tx_in_block(
            stake_tx, pending_nonces={}, pending_balance_spent={},
        )
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
