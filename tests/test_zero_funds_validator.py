"""End-to-end test: a user with zero funds can run a validator during bootstrap.

This is a core product requirement: without an initial-stake-free onramp,
nobody can join the network before a secondary market forms, and the chain
never gets off the ground.  The design answer is:

  * Attestation inclusion has NO stake gate — any registered entity can
    sign and broadcast an attestation (see Blockchain._validate_attestations).
  * Attester committee selection is uniform at bootstrap_progress=0 — a
    zero-stake attestor has the same selection probability as a founder
    (see attester_committee.weights_for_progress).
  * Seed exclusion from the committee during progress<0.5 means the
    attester pool is reserved for newcomers.
  * Earned committee rewards sit in the escrow ledger and are slashable
    until the escrow window elapses — good behavior unlocks tokens,
    misbehavior burns them.

These tests exercise that workflow on a real block pipeline, not isolated
unit logic, so a regression in any one of the pieces above will fail here.
"""

from __future__ import annotations

import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import create_attestation
from messagechain.core.bootstrap import (
    build_launch_allocation,
    RECOMMENDED_STAKE_PER_SEED,
)
from tests import register_entity_for_test, pick_selected_proposer


class TestZeroFundsValidator(unittest.TestCase):
    """A zero-funds entity registers, attests, and earns a reward via committee."""

    def _make_chain_with_seeds(self, stake_per_seed: int = 250_000):
        """Build a blockchain with 1 funded + staked seed validator.

        Returns (chain, seeds, consensus).  The seed is funded at genesis,
        registered, and has `stake_per_seed` tokens staked.  The chain is
        ready to accept blocks.
        """
        seeds = [
            Entity.create(b"seed-0".ljust(32, b"\x00")),
        ]
        for s in seeds:
            s.keypair._next_leaf = 0

        chain = Blockchain()
        allocation = build_launch_allocation(
            [s.entity_id for s in seeds],
            stake_per_seed=stake_per_seed,
            fee_buffer=0,
        )
        chain.initialize_genesis(seeds[0], allocation_table=allocation)
        for s in seeds[1:]:
            register_entity_for_test(chain, s)

        for s in seeds:
            chain.supply.stake(s.entity_id, stake_per_seed)

        consensus = ProofOfStake()
        chain.sync_consensus_stakes(consensus)
        return chain, seeds, consensus

    def test_zero_stake_entity_can_attest_and_be_included_in_block(self):
        """A registered entity with 0 balance and 0 stake can attest; the
        block carrying its attestation is accepted by validate_block."""
        chain, seeds, consensus = self._make_chain_with_seeds()

        # Zero-funds validator: just a registered entity, no balance, no stake.
        newcomer = Entity.create(b"newcomer".ljust(32, b"\x00"))
        newcomer.keypair._next_leaf = 0
        register_entity_for_test(chain, newcomer)

        self.assertEqual(chain.supply.get_balance(newcomer.entity_id), 0)
        self.assertEqual(chain.supply.get_staked(newcomer.entity_id), 0)

        # Produce a first block so there's something to attest to.
        proposer = pick_selected_proposer(chain, seeds)
        block1 = chain.propose_block(consensus, proposer, [])
        ok, reason = chain.add_block(block1)
        self.assertTrue(ok, reason)

        # The newcomer signs an attestation for block1 despite holding nothing.
        att = create_attestation(newcomer, block1.block_hash, block1.header.block_number)

        # A seed proposes block 2 carrying the newcomer's attestation.
        proposer = pick_selected_proposer(chain, seeds)
        block2 = chain.propose_block(consensus, proposer, [], attestations=[att])
        ok, reason = chain.add_block(block2)
        self.assertTrue(ok, reason)

    def test_zero_stake_attestor_earns_committee_reward_into_escrow(self):
        """During bootstrap, a zero-stake attestor selected by the uniform
        committee earns a 1-token reward held in escrow (slashable but real)."""
        chain, seeds, consensus = self._make_chain_with_seeds()

        # Bootstrap progress must be low enough for uniform committee
        # selection.  Fresh chain → height=0 → progress≈0 → pure uniform
        # AND seed exclusion (seeds can't steal the attester pool).
        self.assertLess(
            chain.bootstrap_progress, 0.5,
            "Test precondition: bootstrap_progress must be < 0.5 for the "
            "newcomer-only attester pool to apply",
        )

        newcomer = Entity.create(b"newcomer".ljust(32, b"\x00"))
        newcomer.keypair._next_leaf = 0
        register_entity_for_test(chain, newcomer)

        # Block 1: advance the chain so we have a block to attest.
        proposer = pick_selected_proposer(chain, seeds)
        block1 = chain.propose_block(consensus, proposer, [])
        chain.add_block(block1)

        # Newcomer attests block 1.
        att = create_attestation(newcomer, block1.block_hash, block1.header.block_number)

        # Seed proposes block 2 including the newcomer's attestation — no
        # seed attestations, so the committee pool has only the newcomer
        # AND seed exclusion during bootstrap guarantees they get the slot.
        proposer = pick_selected_proposer(chain, seeds)
        block2 = chain.propose_block(
            consensus, proposer, [], attestations=[att],
        )
        ok, reason = chain.add_block(block2)
        self.assertTrue(ok, reason)

        # Newcomer should have earned >= 1 token, but it's locked in escrow
        # (bootstrap slashing window).  Their spendable balance is still 0.
        escrowed = chain.get_escrowed_balance(newcomer.entity_id)
        self.assertGreaterEqual(
            escrowed, 1,
            "Zero-stake attestor should earn ≥1 token of escrowed reward "
            "when selected by the uniform committee during bootstrap",
        )
        self.assertEqual(
            chain.get_spendable_balance(newcomer.entity_id), 0,
            "Reward should be locked in escrow, not spendable yet",
        )


class TestFounderStakeDominance(unittest.TestCase):
    """The recommended founder allocation keeps founder stake at ≥2/3
    of total stake even under a worst-case Sybil accumulation scenario.

    If this property fails, zero-funds validators collectively outweigh
    the founder and can threaten consensus during bootstrap.  The
    RECOMMENDED_STAKE_PER_SEED constant must be sized against the
    bootstrap-era minting envelope so this assertion holds.
    """

    def test_single_seed_holds_supermajority_against_worst_case_sybils(self):
        """The founder seed still holds >=2/3 of stake even if the entire
        bootstrap minting envelope (~1.68M tokens) is captured and staked
        by non-seed validators."""
        from messagechain.consensus.bootstrap_gradient import (
            BOOTSTRAP_END_HEIGHT,
        )
        from messagechain.config import BLOCK_REWARD

        total_founder_stake = RECOMMENDED_STAKE_PER_SEED
        # Upper bound on tokens minted across the whole bootstrap window —
        # assumes reward never halves during the window (pessimistic for
        # attacker; conservative for defender).
        bootstrap_minting_envelope = BOOTSTRAP_END_HEIGHT * BLOCK_REWARD

        # Worst case: every minted token ends up in Sybil stake.
        sybil_stake = bootstrap_minting_envelope
        total_stake = total_founder_stake + sybil_stake
        founder_share_pct = (total_founder_stake * 100) // total_stake

        self.assertGreaterEqual(
            founder_share_pct, 67,
            f"Founder stake share dropped to {founder_share_pct}% under "
            f"worst-case Sybil accumulation — recommended stake per seed "
            f"({RECOMMENDED_STAKE_PER_SEED}) is too small for the bootstrap "
            f"envelope ({bootstrap_minting_envelope}).",
        )


if __name__ == "__main__":
    unittest.main()
