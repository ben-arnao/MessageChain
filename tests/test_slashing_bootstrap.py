"""Slashing must fire during the bootstrap window (progress == 0.0).

Context:
  During bootstrap the min-stake gate is near-zero (min_stake scales
  linearly with bootstrap_progress), and attester rewards are locked
  in a ~90 day escrow.  A cheap-to-spin-up Sybil validator could
  double-sign with impunity if slashing were gated off until some
  later progress threshold.

  The design intentionally does NOT gate slashing on progress.  This
  test pins that invariant: at height 0 / progress 0.0 a
  freshly-registered validator MUST still be slashable.

  If this test fails, slashing has accidentally been gated and
  attackers have a free-for-all during the bootstrap window.
"""

import time
import unittest

from messagechain.config import (
    SLASH_FINDER_REWARD_PCT,
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


def _make_conflicting_headers(proposer_entity, prev_block):
    """Two different signed block headers at the same height by the same proposer."""
    block_num = prev_block.header.block_number + 1

    header_a = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"A"),
        timestamp=time.time(),
        proposer_id=proposer_entity.entity_id,
    )
    header_a.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_a.signable_data())
    )

    header_b = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"B"),
        timestamp=time.time() + 1,
        proposer_id=proposer_entity.entity_id,
    )
    header_b.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_b.signable_data())
    )

    return header_a, header_b


class TestSlashingDuringBootstrap(unittest.TestCase):
    """Double-signing at bootstrap_progress == 0.0 is still slashable."""

    def setUp(self):
        # Seed entity (alice) gets a genesis allocation so
        # seed_entity_ids is non-empty and bootstrap_progress is
        # well-defined at height 0.
        self.alice = Entity.create(b"alice-boot".ljust(32, b"\x00"))
        # Offender: registers during bootstrap and double-signs.
        self.offender = Entity.create(b"offender-boot".ljust(32, b"\x00"))
        # Finder: submits the evidence.
        self.finder = Entity.create(b"finder-boot".ljust(32, b"\x00"))

        self.chain = Blockchain()
        self.chain.initialize_genesis(
            self.alice,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.alice.entity_id: 1_000_000,
            },
        )
        register_entity_for_test(self.chain, self.offender)
        register_entity_for_test(self.chain, self.finder)

        # Fund the offender & finder so the offender can stake the
        # minimum and the finder can pay the slash-tx fee.
        self.chain.supply.balances[self.offender.entity_id] = 10_000
        self.chain.supply.balances[self.finder.entity_id] = 10_000

    def test_bootstrap_progress_is_near_zero_at_genesis(self):
        """Sanity: right after genesis, bootstrap_progress is at the floor.

        `height` is the chain length (genesis is 1 block), so the raw
        value is 1 / BOOTSTRAP_END_HEIGHT ≈ 1e-5 — effectively zero.
        If this ever changes the other tests below need re-framing —
        their whole point is that slashing works specifically at the
        bottom of the gradient.
        """
        self.assertEqual(self.chain.height, 1)
        # Effectively zero: well under 0.001 (i.e. < 0.1% into bootstrap).
        self.assertLess(self.chain.bootstrap_progress, 1e-3)

    def test_offender_can_stake_minimum_during_bootstrap(self):
        """Non-seed validator can register with the bootstrap min-stake."""
        from messagechain.consensus.bootstrap_gradient import (
            min_stake_for_progress,
        )
        min_stake = min_stake_for_progress(
            self.chain.bootstrap_progress,
            full_min_stake=VALIDATOR_MIN_STAKE,
        )
        # During bootstrap at progress=0.0 the floor is 0.  We still
        # need some positive stake to slash — the attacker can easily
        # put up VALIDATOR_MIN_STAKE (100 tokens) even as a throwaway.
        stake_amount = max(1, min_stake) or VALIDATOR_MIN_STAKE
        self.assertTrue(
            self.chain.supply.stake(self.offender.entity_id, stake_amount)
        )
        self.assertEqual(
            self.chain.supply.get_staked(self.offender.entity_id),
            stake_amount,
        )

    def test_double_sign_during_bootstrap_is_slashed(self):
        """The load-bearing test: double-sign at progress=0.0 MUST slash.

        Simulates a cheap Sybil attacker who registers during the free-
        entry window, stakes the bootstrap minimum, then equivocates.
        After applying the slash transaction the offender's stake must
        be zero, they must be flagged in slashed_validators, and the
        finder must receive their cut.
        """
        # Lock in the bootstrap-era preconditions: we are AT the floor.
        self.assertLess(
            self.chain.bootstrap_progress, 1e-3,
            "Test invalid: progress must be ~0 to prove the bootstrap gate",
        )
        self.assertEqual(self.chain.height, 1)

        # Attacker stakes; 100 tokens is the cheapest viable bootstrap stake.
        attacker_stake = VALIDATOR_MIN_STAKE
        self.assertTrue(
            self.chain.supply.stake(self.offender.entity_id, attacker_stake),
            "stake() should succeed during bootstrap — min-stake floor is 0",
        )
        self.assertEqual(
            self.chain.supply.get_staked(self.offender.entity_id),
            attacker_stake,
        )

        finder_balance_before = self.chain.supply.get_balance(
            self.finder.entity_id,
        )
        total_supply_before = self.chain.supply.total_supply

        # Offender equivocates: two conflicting signed headers at height 1.
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.offender, prev)
        evidence = SlashingEvidence(
            offender_id=self.offender.entity_id,
            header_a=header_a,
            header_b=header_b,
        )

        # Finder files the evidence (pays a fee, earns a reward).
        slash_tx = create_slash_transaction(self.finder, evidence, fee=500)

        # Proposer_id here is alice (the seed).  Any registered validator
        # works for the "proposer_id" argument of apply_slash_transaction —
        # we only need the tip recipient.
        success, msg = self.chain.apply_slash_transaction(
            slash_tx, self.alice.entity_id,
        )

        self.assertTrue(
            success,
            f"Slashing MUST fire at bootstrap_progress=0.0, got: {msg}",
        )

        # Stake destroyed.
        self.assertEqual(
            self.chain.supply.get_staked(self.offender.entity_id), 0,
            "Offender's stake must be zero after slashing during bootstrap",
        )
        # Offender flagged so they can't re-enter.
        self.assertIn(
            self.offender.entity_id, self.chain.slashed_validators,
            "Offender must be in slashed_validators after bootstrap slash",
        )

        # Finder got their cut (minus the fee they paid).
        expected_reward = attacker_stake * SLASH_FINDER_REWARD_PCT // 100
        finder_balance_after = self.chain.supply.get_balance(
            self.finder.entity_id,
        )
        self.assertEqual(
            finder_balance_after,
            finder_balance_before + expected_reward - slash_tx.fee,
            "Finder reward must be paid even during bootstrap",
        )

        # Supply shrank: burned stake + burned base_fee.
        burned_stake = attacker_stake - expected_reward
        self.assertEqual(
            self.chain.supply.total_supply,
            total_supply_before - burned_stake - self.chain.supply.base_fee,
            "Burned stake must reduce total supply during bootstrap slash",
        )


if __name__ == "__main__":
    unittest.main()
