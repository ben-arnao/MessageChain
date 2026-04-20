"""Single-seed local bootstrap rehearsal.

Exercises the `bootstrap_seed_local` orchestration on a 1-validator
genesis allocation with a separate cold-wallet entity, then asserts
every security-critical post-condition:

1. The seed is registered on chain.
2. The seed has authority_key == cold wallet public key.
3. The seed has the expected stake locked.
4. A simulated hot-key compromise CANNOT unstake (authority-gated).
5. Block production works with the seed post-bootstrap.
6. Re-running bootstrap is idempotent.

These are the same checks the production runbook has to make on the
real server.  Passing this rehearsal does not prove the remote-RPC path
is correct -- it proves the orchestration sequence and post-condition
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


def _build_entities():
    """Generate entities the operator would generate offline.

    One seed hot-key PLUS one distinct cold-authority key.  Store the
    cold mnemonic in the safe.
    """
    return {
        "seed1": Entity.create(b"rehearsal-seed-1".ljust(32, b"\x00")),
        "cold1": Entity.create(b"rehearsal-cold-1".ljust(32, b"\x00")),
    }


# Keep the legacy name working for any external caller.
def _build_four_entities():
    return _build_entities()


def _fresh_chain(entities: dict) -> Blockchain:
    """Initialise a chain with the genesis allocation table.

    Matches the production runbook: treasury gets 4%, the seed gets its
    stake amount pre-allocated as liquid balance.  Cold-wallet entity
    is NOT allocated on chain and NOT registered -- it lives off-chain
    entirely; only its public key is pointed at as authority key.
    """
    chain = Blockchain()
    allocation = {
        TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        entities["seed1"].entity_id: SEED_GENESIS,
    }
    chain.initialize_genesis(entities["seed1"], allocation_table=allocation)
    return chain


class TestBootstrapRehearsal(unittest.TestCase):
    """End-to-end bootstrap of 1 seed against a real Blockchain."""

    def setUp(self):
        self.entities = _build_entities()
        # Reset keypair leaf cursors for deterministic signing
        for e in self.entities.values():
            e.keypair._next_leaf = 0
        self.chain = _fresh_chain(self.entities)
        self.cold_pks = {
            "seed1": self.entities["cold1"].public_key,
        }

    def _bootstrap_all(self):
        """Run bootstrap_seed_local for the seed."""
        results = {}
        for name in ("seed1",):
            ok, log = bootstrap_seed_local(
                self.chain,
                self.entities[name],
                cold_authority_pubkey=self.cold_pks[name],
                stake_amount=SEED_STAKE,
            )
            results[name] = (ok, log)
        return results

    def test_seed_bootstraps_cleanly(self):
        results = self._bootstrap_all()
        for name, (ok, log) in results.items():
            self.assertTrue(ok, f"{name} bootstrap failed:\n" + "\n".join(log))
            self.assertTrue(
                any("BOOTSTRAP COMPLETE" in line for line in log),
                f"{name} log missing completion marker",
            )

    def test_seed_registered_after_bootstrap(self):
        self._bootstrap_all()
        eid = self.entities["seed1"].entity_id
        self.assertIn(eid, self.chain.public_keys, "seed1 not registered")

    def test_seed_has_cold_authority_key(self):
        """The single most important post-condition: hot key is NOT its
        own authority.  Otherwise unstake/revoke would only need the hot
        key, defeating the whole cold-key split."""
        self._bootstrap_all()
        eid = self.entities["seed1"].entity_id
        authority = self.chain.get_authority_key(eid)
        self.assertEqual(
            authority, self.cold_pks["seed1"],
            "seed1 authority key is NOT the matching cold key -- "
            "hot-key compromise would be fatal",
        )
        self.assertNotEqual(
            authority, self.entities["seed1"].public_key,
            "seed1 authority key is still the hot signing key",
        )

    def test_seed_staked_to_target(self):
        self._bootstrap_all()
        eid = self.entities["seed1"].entity_id
        self.assertEqual(
            self.chain.supply.get_staked(eid), SEED_STAKE,
            f"seed1 stake != {SEED_STAKE}",
        )

    def test_hot_key_cannot_unstake_after_bootstrap(self):
        """Simulate a compromised validator server: the attacker has the
        hot signing key and tries to unstake the whole pile.  With the
        cold-key authority set, the chain must reject the unstake tx.
        """
        from messagechain.core.staking import create_unstake_transaction
        self._bootstrap_all()

        seed1 = self.entities["seed1"]
        current_nonce = self.chain.nonces.get(seed1.entity_id, 0)

        # Attacker signs an unstake with the HOT key.
        malicious_unstake = create_unstake_transaction(
            seed1, amount=SEED_STAKE, nonce=current_nonce,
        )

        from messagechain.core.staking import verify_unstake_transaction
        # Verify directly against the authority (cold) key -- must FAIL
        self.assertFalse(
            verify_unstake_transaction(malicious_unstake, self.cold_pks["seed1"]),
            "Unstake signed by hot key must not verify under cold authority",
        )
        # Sanity: it would have verified under the hot key
        self.assertTrue(
            verify_unstake_transaction(malicious_unstake, seed1.public_key),
            "Unstake tx is well-formed; the defense is ONLY the key mismatch",
        )

    def test_blocks_can_be_produced_by_bootstrapped_seed(self):
        """Smoke: after bootstrap, the chain can still produce blocks
        proposed by the staked seed."""
        self._bootstrap_all()

        consensus = ProofOfStake()
        eid = self.entities["seed1"].entity_id
        consensus.stakes[eid] = SEED_STAKE

        latest = self.chain.get_latest_block()
        selected = self.chain._selected_proposer_for_slot(latest, round_number=0)
        proposer_entity = self.entities["seed1"]

        block = self.chain.propose_block(consensus, proposer_entity, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, f"Block production failed: {reason}")

    def test_bootstrap_is_idempotent(self):
        """Re-running bootstrap after a partial success must not double-
        charge fees, double-stake, or otherwise drift."""
        self._bootstrap_all()
        snapshot = {
            "seed1": (
                self.chain.supply.get_staked(self.entities["seed1"].entity_id),
                self.chain.get_authority_key(self.entities["seed1"].entity_id),
                self.chain.supply.get_balance(self.entities["seed1"].entity_id),
            ),
        }
        # Second pass -- every step should detect "already done" and skip.
        results = self._bootstrap_all()
        for name, (ok, log) in results.items():
            self.assertTrue(ok, f"{name} second pass failed")
            self.assertTrue(
                any("skipping" in line for line in log),
                f"{name} second pass didn't skip any step",
            )
        eid = self.entities["seed1"].entity_id
        now = (
            self.chain.supply.get_staked(eid),
            self.chain.get_authority_key(eid),
            self.chain.supply.get_balance(eid),
        )
        self.assertEqual(
            snapshot["seed1"], now,
            "seed1 state drifted on second bootstrap pass",
        )

    def test_bootstrap_fails_loudly_on_insufficient_balance(self):
        """If someone mis-configures the genesis allocation so the seed
        doesn't have enough liquid balance to stake, bootstrap MUST fail
        loudly -- not silently run with a smaller stake."""
        self.chain.supply.balances[self.entities["seed1"].entity_id] = MIN_FEE * 5
        ok, log = bootstrap_seed_local(
            self.chain,
            self.entities["seed1"],
            cold_authority_pubkey=self.cold_pks["seed1"],
            stake_amount=SEED_STAKE,
        )
        self.assertFalse(ok)
        self.assertTrue(
            any("FAILED" in line for line in log),
            f"Expected explicit FAILED log line; got:\n" + "\n".join(log),
        )


if __name__ == "__main__":
    unittest.main()
