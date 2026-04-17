"""End-to-end rehearsal for the recommended single-seed + shared-payout launch.

This test exercises the exact shape the operator runbook recommends:

  * 1 seed hot entity, staking RECOMMENDED_STAKE_PER_SEED
    (99,000,000 tokens in production) with a 1,000-token fee buffer.
  * 1 cold authority key (off-chain; the chain enforces uniqueness
    across authority bindings).
  * 1 shared payout entity registered POST-genesis via the block
    pipeline, used as the sweep target for block rewards.

Unlike tests/test_bootstrap_rehearsal.py -- which exercises the direct-
chain API path at bootstrap time -- this test drives the production
block pipeline: the payout entity arrives via a RegistrationTransaction
in a real block, then a reward sweep happens via TransferTransaction.
It is the canonical proof that the recommended launch plan works end-
to-end, including the properties that matter most:

  * The seed's authority is set to its cold key and rejects
    unstake attempts signed by the hot key.
  * The seed is staked to exactly the target amount.
  * Payout entity, once registered, is visible on chain and can
    receive transfers.
  * A reward sweep from the seed to the shared payout works.
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
    """The full single-seed + shared-payout launch plan works end-to-end."""

    def setUp(self):
        self.seed = _entity(b"launch-seed-1")
        self.cold_key = _entity(b"launch-cold-1")
        self.payout = _entity(b"launch-payout")
        for e in [self.seed, self.cold_key, self.payout]:
            e.keypair._next_leaf = 0

    def _build_genesis_chain(self) -> Blockchain:
        allocation = build_launch_allocation(
            [self.seed.entity_id],
        )
        chain = Blockchain()
        chain.initialize_genesis(self.seed, allocation_table=allocation)
        return chain

    def _bootstrap_seed(self, chain: Blockchain):
        """Run bootstrap_seed_local for the seed with its cold key."""
        ok, log = bootstrap_seed_local(
            chain, self.seed,
            cold_authority_pubkey=self.cold_key.public_key,
            stake_amount=RECOMMENDED_STAKE_PER_SEED,
        )
        self.assertTrue(
            ok, f"{self.seed.entity_id.hex()[:12]} bootstrap failed:\n"
            + "\n".join(log),
        )

    def test_allocation_table_matches_recommendation(self):
        """Helper produces the expected per-seed liquid amount + treasury."""
        allocation = build_launch_allocation(
            [self.seed.entity_id],
        )
        self.assertEqual(allocation[TREASURY_ENTITY_ID], TREASURY_ALLOCATION)
        self.assertEqual(allocation[self.seed.entity_id], RECOMMENDED_GENESIS_PER_SEED)
        # Payout deliberately NOT in genesis allocation -- it registers
        # via the block pipeline.
        self.assertNotIn(self.payout.entity_id, allocation)

    def test_allocation_rejects_wrong_seed_count(self):
        """Must have exactly 1 seed -- 0 or 3 is rejected."""
        with self.assertRaises(ValueError):
            build_launch_allocation([])
        eids = [bytes([i]) * 32 for i in range(1, 4)]
        with self.assertRaises(ValueError):
            build_launch_allocation(eids)

    def test_seed_bootstraps_cleanly(self):
        chain = self._build_genesis_chain()
        self._bootstrap_seed(chain)
        # Post-conditions: the seed has the full stake locked and a
        # cold authority key.
        self.assertEqual(
            chain.supply.get_staked(self.seed.entity_id),
            RECOMMENDED_STAKE_PER_SEED,
        )
        self.assertEqual(
            chain.get_authority_key(self.seed.entity_id),
            self.cold_key.public_key,
        )
        self.assertNotEqual(
            chain.get_authority_key(self.seed.entity_id),
            self.seed.public_key,
        )

    def test_hot_key_cannot_unstake_after_bootstrap(self):
        """The defining property of the cold-key split: hot key != authority."""
        chain = self._build_genesis_chain()
        self._bootstrap_seed(chain)

        nonce = chain.nonces.get(self.seed.entity_id, 0)
        malicious = create_unstake_transaction(
            self.seed, amount=RECOMMENDED_STAKE_PER_SEED, nonce=nonce,
        )
        # Under the cold authority: must NOT verify.
        self.assertFalse(verify_unstake_transaction(malicious, self.cold_key.public_key))
        # Sanity: the tx is well-formed, so the defense is the key
        # mismatch, not a structural bug.
        self.assertTrue(verify_unstake_transaction(malicious, self.seed.public_key))

    def test_payout_registers_via_receive_to_exist_and_can_receive_sweep(self):
        """Receive-to-exist flow: payout enters state on first incoming transfer."""
        chain = self._build_genesis_chain()
        self._bootstrap_seed(chain)
        consensus = ProofOfStake()
        consensus.stakes[self.seed.entity_id] = RECOMMENDED_STAKE_PER_SEED

        # Payout is not yet on chain — no balance, no pubkey.
        self.assertNotIn(self.payout.entity_id, chain.public_keys)
        self.assertEqual(chain.supply.get_balance(self.payout.entity_id), 0)

        # Sweep: seed sends tokens directly to the payout's entity_id.
        # Under receive-to-exist this creates the payout's balance entry
        # with no pubkey; the pubkey is installed only when the payout
        # itself first spends (not tested here — we care about receive).
        sweep_amount = 500
        transfer_nonce = chain.nonces.get(self.seed.entity_id, 0)
        sweep_tx = create_transfer_transaction(
            self.seed, self.payout.entity_id, sweep_amount,
            nonce=transfer_nonce, fee=MIN_FEE,
        )
        proposer = pick_selected_proposer(chain, [self.seed])
        block = chain.propose_block(
            consensus, proposer, [],
            transfer_transactions=[sweep_tx],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, f"sweep block rejected: {reason}")

        self.assertEqual(
            chain.supply.get_balance(self.payout.entity_id), sweep_amount,
        )
        # The payout is a balance-only entity — no pubkey yet.
        self.assertNotIn(self.payout.entity_id, chain.public_keys)

    def test_founder_token_concentration_within_security_and_optics_bounds(self):
        """Founder allocation sits above the security floor and below the
        optics ceiling.

        Security floor (>=5% of supply): the founder must hold enough
        stake to retain a 2/3 supermajority of consensus weight during
        bootstrap, even after zero-funds validators accumulate tokens via
        escrow-era committee rewards.  Below 5%, a modestly funded Sybil
        swarm can outweigh the seed.

        Optics ceiling (<=15% of supply): hoarding more than this signals
        an extractive genesis distribution and deters outside validators
        from participating.  The treasury (4%) is excluded from this
        calculation -- it's governance-controlled and flows via proposals.
        """
        from messagechain.config import GENESIS_SUPPLY
        founder_total = RECOMMENDED_GENESIS_PER_SEED
        pct = founder_total / GENESIS_SUPPLY
        self.assertGreaterEqual(
            pct, 0.05,
            f"founder concentration is {pct:.4%} -- below the 5% security "
            f"floor; zero-funds validators could outweigh the seed "
            f"during bootstrap",
        )
        self.assertLessEqual(
            pct, 0.15,
            f"founder concentration is {pct:.4%} -- above the 15% optics "
            f"ceiling; hoarding at this level looks extractive",
        )


if __name__ == "__main__":
    unittest.main()
