"""End-to-end rehearsal for the recommended 3-seed + shared-payout launch.

This test exercises the exact shape the operator runbook recommends:

  * 3 seed hot entities, each staking RECOMMENDED_STAKE_PER_SEED
    (250,000 tokens in production) with a 1,000-token fee buffer.
  * 3 distinct cold authority keys (off-chain; the chain enforces
    uniqueness across authority bindings).
  * 1 shared payout entity registered POST-genesis via the block
    pipeline, used as the sweep target for block rewards.

Unlike tests/test_bootstrap_rehearsal.py — which exercises the direct-
chain API path at bootstrap time — this test drives the production
block pipeline: the payout entity arrives via a RegistrationTransaction
in a real block, then a reward sweep happens via TransferTransaction.
It is the canonical proof that the recommended launch plan works end-
to-end, including the properties that matter most:

  * Every seed's authority is set to its own cold key and rejects
    unstake attempts signed by the hot key.
  * All three seeds are staked to exactly the target amount.
  * Payout entity, once registered, is visible on chain and can
    receive transfers.
  * A reward sweep from a seed to the shared payout works.
"""

import unittest

from messagechain import config
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.block import Block
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import (
    bootstrap_seed_local,
    build_launch_allocation,
    RECOMMENDED_STAKE_PER_SEED,
    RECOMMENDED_GENESIS_PER_SEED,
)
from messagechain.core.registration import create_registration_transaction
from messagechain.core.staking import (
    create_unstake_transaction, verify_unstake_transaction,
)
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity
from messagechain.config import (
    TREASURY_ENTITY_ID, TREASURY_ALLOCATION, MIN_FEE,
)
from tests import pick_selected_proposer


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


class TestRecommendedLaunchPlan(unittest.TestCase):
    """The full 3-seed + shared-payout launch plan works end-to-end."""

    def setUp(self):
        # Standard test Merkle height (4 = 16 leaves) — plenty for a
        # handful of blocks.  The recommended stake numbers don't
        # depend on tree height; this just keeps keygen fast.
        self.seeds = [
            _entity(b"launch-seed-1"),
            _entity(b"launch-seed-2"),
            _entity(b"launch-seed-3"),
        ]
        self.cold_keys = [
            _entity(b"launch-cold-1"),
            _entity(b"launch-cold-2"),
            _entity(b"launch-cold-3"),
        ]
        self.payout = _entity(b"launch-payout")
        for e in self.seeds + self.cold_keys + [self.payout]:
            e.keypair._next_leaf = 0

    def _build_genesis_chain(self) -> Blockchain:
        allocation = build_launch_allocation(
            [s.entity_id for s in self.seeds],
        )
        chain = Blockchain()
        chain.initialize_genesis(self.seeds[0], allocation_table=allocation)
        return chain

    def _bootstrap_all_seeds(self, chain: Blockchain):
        """Run bootstrap_seed_local for each seed with its own cold key."""
        for seed, cold in zip(self.seeds, self.cold_keys):
            ok, log = bootstrap_seed_local(
                chain, seed,
                cold_authority_pubkey=cold.public_key,
                stake_amount=RECOMMENDED_STAKE_PER_SEED,
            )
            self.assertTrue(
                ok, f"{seed.entity_id.hex()[:12]} bootstrap failed:\n"
                + "\n".join(log),
            )

    def test_allocation_table_matches_recommendation(self):
        """Helper produces the expected per-seed liquid amount + treasury."""
        allocation = build_launch_allocation(
            [s.entity_id for s in self.seeds],
        )
        self.assertEqual(allocation[TREASURY_ENTITY_ID], TREASURY_ALLOCATION)
        for seed in self.seeds:
            self.assertEqual(allocation[seed.entity_id], RECOMMENDED_GENESIS_PER_SEED)
        # Payout deliberately NOT in genesis allocation — it registers
        # via the block pipeline.
        self.assertNotIn(self.payout.entity_id, allocation)

    def test_allocation_rejects_wrong_seed_count(self):
        """Must have exactly 3 seeds — 1 or 2 is a footgun."""
        with self.assertRaises(ValueError):
            build_launch_allocation([self.seeds[0].entity_id])
        with self.assertRaises(ValueError):
            build_launch_allocation([s.entity_id for s in self.seeds * 2])

    def test_all_three_seeds_bootstrap_cleanly(self):
        chain = self._build_genesis_chain()
        self._bootstrap_all_seeds(chain)
        # Post-conditions: every seed has the full stake locked and a
        # cold authority key pointing at its own cold key.
        for seed, cold in zip(self.seeds, self.cold_keys):
            self.assertEqual(
                chain.supply.get_staked(seed.entity_id),
                RECOMMENDED_STAKE_PER_SEED,
            )
            self.assertEqual(
                chain.get_authority_key(seed.entity_id),
                cold.public_key,
            )
            self.assertNotEqual(
                chain.get_authority_key(seed.entity_id),
                seed.public_key,
            )

    def test_hot_key_cannot_unstake_after_bootstrap(self):
        """The defining property of the cold-key split: hot key ≠ authority."""
        chain = self._build_genesis_chain()
        self._bootstrap_all_seeds(chain)

        seed = self.seeds[0]
        cold = self.cold_keys[0]
        # Attacker who compromised the validator server has the hot key.
        nonce = chain.nonces.get(seed.entity_id, 0)
        malicious = create_unstake_transaction(
            seed, amount=RECOMMENDED_STAKE_PER_SEED, nonce=nonce,
        )
        # Under the cold authority: must NOT verify.
        self.assertFalse(verify_unstake_transaction(malicious, cold.public_key))
        # Sanity: the tx is well-formed, so the defense is the key
        # mismatch, not a structural bug.
        self.assertTrue(verify_unstake_transaction(malicious, seed.public_key))

    def test_payout_registers_via_block_and_can_receive_sweep(self):
        """The shared payout: registered post-genesis, receives transfers."""
        chain = self._build_genesis_chain()
        self._bootstrap_all_seeds(chain)
        consensus = ProofOfStake()
        for seed in self.seeds:
            consensus.stakes[seed.entity_id] = RECOMMENDED_STAKE_PER_SEED

        # Payout is not yet on chain.
        self.assertNotIn(self.payout.entity_id, chain.public_keys)

        # Register the payout by broadcasting a RegistrationTransaction.
        # In production, the operator submits this via RPC to any seed;
        # here we inject it into the next proposed block directly.
        reg_tx = create_registration_transaction(self.payout)
        proposer = pick_selected_proposer(chain, self.seeds)
        block = chain.propose_block(
            consensus, proposer, [],
            registration_transactions=[reg_tx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, f"registration block rejected: {reason}")
        self.assertIn(self.payout.entity_id, chain.public_keys)

        # Sweep: seed1 transfers some of its liquid (the ~1,000 leftover
        # from genesis + accumulated block rewards) to the payout.
        seed = self.seeds[0]
        pre_payout = chain.supply.get_balance(self.payout.entity_id)
        sweep_amount = 500
        transfer_nonce = chain.nonces.get(seed.entity_id, 0)
        sweep_tx = create_transfer_transaction(
            seed, self.payout.entity_id, sweep_amount,
            nonce=transfer_nonce, fee=MIN_FEE,
        )
        proposer = pick_selected_proposer(chain, self.seeds)
        block = chain.propose_block(
            consensus, proposer, [],
            transfer_transactions=[sweep_tx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, f"sweep block rejected: {reason}")

        self.assertEqual(
            chain.supply.get_balance(self.payout.entity_id) - pre_payout,
            sweep_amount,
        )

    def test_founder_token_concentration_within_security_and_optics_bounds(self):
        """Founder allocation sits above the security floor and below the
        optics ceiling.

        Security floor (≥5% of supply): the founder must hold enough
        stake to retain a 2/3 supermajority of consensus weight during
        bootstrap, even after zero-funds validators accumulate tokens via
        escrow-era committee rewards.  Below 5%, a modestly funded Sybil
        swarm can outweigh the seeds.

        Optics ceiling (≤15% of supply): hoarding more than this signals
        an extractive genesis distribution and deters outside validators
        from participating.  The treasury (4%) is excluded from this
        calculation — it's governance-controlled and flows via proposals.
        """
        from messagechain.config import GENESIS_SUPPLY
        founder_total = 3 * RECOMMENDED_GENESIS_PER_SEED
        pct = founder_total / GENESIS_SUPPLY
        self.assertGreaterEqual(
            pct, 0.05,
            f"founder concentration is {pct:.4%} — below the 5% security "
            f"floor; zero-funds validators could outweigh the seeds "
            f"during bootstrap",
        )
        self.assertLessEqual(
            pct, 0.15,
            f"founder concentration is {pct:.4%} — above the 15% optics "
            f"ceiling; hoarding at this level looks extractive",
        )


if __name__ == "__main__":
    unittest.main()
