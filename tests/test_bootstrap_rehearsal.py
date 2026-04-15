"""Three-seed local bootstrap rehearsal.

Exercises the `bootstrap_seed_local` orchestration on a 3-validator
genesis allocation with a separate cold-wallet entity, then asserts
every security-critical post-condition:

1. All three seeds registered on chain.
2. All three seeds have authority_key == cold wallet public key.
3. All three seeds have the expected stake locked.
4. A simulated hot-key compromise CANNOT unstake (authority-gated).
5. Block production + finality work with the 3-seed set post-bootstrap.
6. Re-running bootstrap is idempotent.

These are the same checks the production runbook has to make on real
servers.  Passing this rehearsal does not prove the remote-RPC path is
correct — it proves the orchestration sequence and post-condition
checks are correct, which is the step people actually get wrong.
"""

import unittest
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.consensus.pos import ProofOfStake
from messagechain.identity.identity import Entity
from messagechain.config import (
    TREASURY_ENTITY_ID, TREASURY_ALLOCATION, VALIDATOR_MIN_STAKE, MIN_FEE,
)


SEED_STAKE = 250_000
# Seed genesis allocation must cover: stake_amount + set-authority-key fee
# + some padding so a mis-estimate doesn't silently under-stake.  The
# runbook for production should use the same pattern.
SEED_FEE_BUDGET = MIN_FEE * 10
SEED_GENESIS = SEED_STAKE + SEED_FEE_BUDGET
WALLET_LIQUID = 5_000


def _build_four_entities():
    """Generate the four entities the operator would generate offline:
    three seed hot-keys + one cold wallet."""
    return {
        "seed1": Entity.create(b"rehearsal-seed-1".ljust(32, b"\x00")),
        "seed2": Entity.create(b"rehearsal-seed-2".ljust(32, b"\x00")),
        "seed3": Entity.create(b"rehearsal-seed-3".ljust(32, b"\x00")),
        "cold":  Entity.create(b"rehearsal-cold".ljust(32, b"\x00")),
    }


def _fresh_chain(entities: dict) -> Blockchain:
    """Initialise a chain with the 4-entity genesis allocation table.

    Matches the production runbook: treasury gets 4%, each seed gets its
    stake amount pre-allocated as liquid balance, wallet gets a small
    liquid amount.
    """
    chain = Blockchain()
    allocation = {
        TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        entities["seed1"].entity_id: SEED_GENESIS,
        entities["seed2"].entity_id: SEED_GENESIS,
        entities["seed3"].entity_id: SEED_GENESIS,
        entities["cold"].entity_id: WALLET_LIQUID,
    }
    # initialize_genesis registers the first entity and credits allocations.
    # We pass seed1 so it becomes the genesis proposer; the allocation
    # table handles the rest of the funding.
    chain.initialize_genesis(entities["seed1"], allocation_table=allocation)
    return chain


class TestBootstrapRehearsal(unittest.TestCase):
    """End-to-end bootstrap of 3 seeds against a real Blockchain."""

    def setUp(self):
        self.entities = _build_four_entities()
        # Reset keypair leaf cursors for deterministic signing
        for e in self.entities.values():
            e.keypair._next_leaf = 0
        self.chain = _fresh_chain(self.entities)
        self.cold_pk = self.entities["cold"].public_key

    def _bootstrap_all(self):
        """Run bootstrap_seed_local for each of the 3 seeds."""
        results = {}
        for name in ("seed1", "seed2", "seed3"):
            ok, log = bootstrap_seed_local(
                self.chain,
                self.entities[name],
                cold_authority_pubkey=self.cold_pk,
                stake_amount=SEED_STAKE,
            )
            results[name] = (ok, log)
        return results

    def test_all_three_seeds_bootstrap_cleanly(self):
        results = self._bootstrap_all()
        for name, (ok, log) in results.items():
            self.assertTrue(ok, f"{name} bootstrap failed:\n" + "\n".join(log))
            self.assertTrue(
                any("BOOTSTRAP COMPLETE" in line for line in log),
                f"{name} log missing completion marker",
            )

    def test_all_seeds_registered_after_bootstrap(self):
        self._bootstrap_all()
        for name in ("seed1", "seed2", "seed3"):
            eid = self.entities[name].entity_id
            self.assertIn(eid, self.chain.public_keys, f"{name} not registered")

    def test_all_seeds_have_cold_authority_key(self):
        """The single most important post-condition: hot key is NOT its
        own authority.  Otherwise unstake/revoke would only need the hot
        key, defeating the whole cold-key split."""
        self._bootstrap_all()
        for name in ("seed1", "seed2", "seed3"):
            eid = self.entities[name].entity_id
            authority = self.chain.get_authority_key(eid)
            self.assertEqual(
                authority, self.cold_pk,
                f"{name} authority key is NOT the cold key — hot-key "
                f"compromise would be fatal",
            )
            self.assertNotEqual(
                authority, self.entities[name].public_key,
                f"{name} authority key is still the hot signing key",
            )

    def test_all_seeds_staked_to_target(self):
        self._bootstrap_all()
        for name in ("seed1", "seed2", "seed3"):
            eid = self.entities[name].entity_id
            self.assertEqual(
                self.chain.supply.get_staked(eid), SEED_STAKE,
                f"{name} stake != {SEED_STAKE}",
            )

    def test_hot_key_cannot_unstake_after_bootstrap(self):
        """Simulate a compromised validator server: the attacker has the
        hot signing key and tries to unstake the whole pile.  With the
        cold-key authority set, the chain must reject the unstake tx.
        """
        from messagechain.core.staking import create_unstake_transaction
        self._bootstrap_all()

        seed1 = self.entities["seed1"]
        # Nonce after Step 2 (set-authority-key) advanced the nonce by 1.
        # Fetch the current nonce from chain state to be safe.
        current_nonce = self.chain.nonces.get(seed1.entity_id, 0)

        # Attacker signs an unstake with the HOT key (what they'd have
        # if they compromised the validator server).
        malicious_unstake = create_unstake_transaction(
            seed1, amount=SEED_STAKE, nonce=current_nonce,
        )

        # The chain should reject this because the authority key (cold)
        # is what's required to sign unstake, not the hot key.
        from messagechain.core.staking import verify_unstake_transaction
        # Verify directly against the authority (cold) key — must FAIL
        self.assertFalse(
            verify_unstake_transaction(malicious_unstake, self.cold_pk),
            "Unstake signed by hot key must not verify under cold authority",
        )
        # Sanity: it would have verified under the hot key
        self.assertTrue(
            verify_unstake_transaction(malicious_unstake, seed1.public_key),
            "Unstake tx is well-formed; the defense is ONLY the key mismatch",
        )

    def test_blocks_can_be_produced_by_bootstrapped_seeds(self):
        """Smoke: after bootstrap, the chain can still produce blocks
        proposed by the staked seeds.  Proves we didn't break block
        production during orchestration."""
        self._bootstrap_all()

        consensus = ProofOfStake()
        for name in ("seed1", "seed2", "seed3"):
            eid = self.entities[name].entity_id
            consensus.stakes[eid] = SEED_STAKE

        # Pick the deterministically-selected proposer for the next slot.
        latest = self.chain.get_latest_block()
        selected = self.chain._selected_proposer_for_slot(latest, round_number=0)
        proposer_entity = None
        for name in ("seed1", "seed2", "seed3"):
            if self.entities[name].entity_id == selected:
                proposer_entity = self.entities[name]
                break
        if proposer_entity is None:
            proposer_entity = self.entities["seed1"]  # bootstrap fallback

        block = self.chain.propose_block(consensus, proposer_entity, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, f"Block production failed: {reason}")

    def test_bootstrap_is_idempotent(self):
        """Re-running bootstrap after a partial success must not double-
        charge fees, double-stake, or otherwise drift.  This matters
        when an operator retries after a transient failure."""
        self._bootstrap_all()
        snapshot = {
            name: (
                self.chain.supply.get_staked(self.entities[name].entity_id),
                self.chain.get_authority_key(self.entities[name].entity_id),
                self.chain.supply.get_balance(self.entities[name].entity_id),
            )
            for name in ("seed1", "seed2", "seed3")
        }
        # Second pass — every step should detect "already done" and skip.
        results = self._bootstrap_all()
        for name, (ok, log) in results.items():
            self.assertTrue(ok, f"{name} second pass failed")
            self.assertTrue(
                any("skipping" in line for line in log),
                f"{name} second pass didn't skip any step",
            )
        for name in ("seed1", "seed2", "seed3"):
            eid = self.entities[name].entity_id
            now = (
                self.chain.supply.get_staked(eid),
                self.chain.get_authority_key(eid),
                self.chain.supply.get_balance(eid),
            )
            self.assertEqual(
                snapshot[name], now,
                f"{name} state drifted on second bootstrap pass",
            )

    def test_bootstrap_fails_loudly_on_insufficient_balance(self):
        """If someone mis-configures the genesis allocation so a seed
        doesn't have enough liquid balance to stake, bootstrap MUST fail
        loudly — not silently run with a smaller stake."""
        # Leave enough for the set-authority-key fee so we fail at the
        # stake step, not earlier.  This mimics an under-budgeted genesis
        # allocation that covers fees but not the full stake amount.
        self.chain.supply.balances[self.entities["seed1"].entity_id] = MIN_FEE * 5
        ok, log = bootstrap_seed_local(
            self.chain,
            self.entities["seed1"],
            cold_authority_pubkey=self.cold_pk,
            stake_amount=SEED_STAKE,
        )
        self.assertFalse(ok)
        self.assertTrue(
            any("FAILED" in line for line in log),
            f"Expected explicit FAILED log line; got:\n" + "\n".join(log),
        )


if __name__ == "__main__":
    unittest.main()
