"""
Tests for hot/cold key separation.

A validator's identity has two keys:
- Signing key (hot) — lives on the running node, signs blocks and
  attestations 24/7. Compromise of the server exposes this key.
- Authority key (cold) — kept offline. Required for stake withdrawal
  and emergency revocation. Compromise of the server does NOT expose
  this key.

On registration the authority key defaults to the signing key (single-key
model, backward-compatible). A SetAuthorityKey transaction — signed by the
current signing key — promotes a separately-generated cold key to the
authority role. After that, any operation flagged as authority-gated
(currently: unstake) must carry a signature from the cold key, not the
hot one.

Rationale: a compromised validator server drains the entire stake when
one key controls both signing and withdrawal. Splitting them turns
"total loss" into "attacker can only produce blocks until we notice."
"""

import os
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    SetAuthorityKeyTransaction,
    create_set_authority_key_transaction,
    verify_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.staking import create_unstake_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class TestAuthorityKeyRegistration(unittest.TestCase):

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        ok, _ = chain.register_entity(entity.entity_id, entity.public_key, proof)
        return ok

    def test_authority_key_defaults_to_signing_key(self):
        """Without explicit setup, authority_key == signing public_key — the
        single-key model remains the default for backward compatibility."""
        chain = Blockchain()
        entity = _entity(b"alice")
        self._register(chain, entity)
        self.assertEqual(
            chain.get_authority_key(entity.entity_id),
            entity.public_key,
        )

    def test_unknown_entity_has_no_authority_key(self):
        chain = Blockchain()
        self.assertIsNone(chain.get_authority_key(b"\x00" * 32))


class TestSetAuthorityKey(unittest.TestCase):

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain.register_entity(entity.entity_id, entity.public_key, proof)

    def test_set_authority_key_promotes_cold_key(self):
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1000

        cold = _entity(b"validator-cold")

        tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        ok, reason = chain.apply_set_authority_key(tx, proposer_id=hot.entity_id)
        self.assertTrue(ok, reason)
        self.assertEqual(chain.get_authority_key(hot.entity_id), cold.public_key)

    def test_set_authority_key_signature_must_verify(self):
        """A tx signed by a different key must be rejected."""
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        imposter = _entity(b"imposter")
        self._register(chain, hot)
        self._register(chain, imposter)
        chain.supply.balances[hot.entity_id] = 1000

        cold = _entity(b"validator-cold")
        # Build a tx claiming to be from hot but signed by imposter
        tx = SetAuthorityKeyTransaction(
            entity_id=hot.entity_id,
            new_authority_key=cold.public_key,
            nonce=0,
            timestamp=__import__("time").time(),
            fee=500,
            signature=imposter.keypair.sign(b"\x00" * 32),  # wrong signature
        )
        ok, reason = chain.validate_set_authority_key(tx)
        self.assertFalse(ok)

    def test_verify_set_authority_key_function(self):
        """Standalone verify function works for mempool / RPC use."""
        hot = _entity(b"hot")
        cold_pk = _entity(b"cold").public_key
        tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        self.assertTrue(verify_set_authority_key_transaction(tx, hot.public_key))

    def test_rejects_authority_key_equal_to_own_signing_key(self):
        """A cold key identical to the hot key is a no-op that looks like
        protection — reject it so users cannot accidentally ship a chain
        state where authority_keys[eid] == public_keys[eid] and believe
        they have defense-in-depth.

        Cross-entity reuse is NOT rejected on purpose: operators running a
        validator cluster legitimately share one cold wallet across all of
        their seeds.  Only the self-reuse case is always a mistake.
        """
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1000

        tx = create_set_authority_key_transaction(
            hot, new_authority_key=hot.public_key, nonce=0, fee=500,
        )
        ok, reason = chain.validate_set_authority_key(tx)
        self.assertFalse(ok)
        self.assertIn("signing key", reason.lower())

    def test_allows_shared_cold_wallet_across_operator_cluster(self):
        """A single operator running multiple validators sets all of them
        to the same cold-wallet public key.  This is the standard cluster
        pattern (see test_bootstrap_rehearsal) and MUST remain allowed."""
        chain = Blockchain()
        seed1 = _entity(b"cluster-seed-1")
        seed2 = _entity(b"cluster-seed-2")
        self._register(chain, seed1)
        self._register(chain, seed2)
        chain.supply.balances[seed1.entity_id] = 1000
        chain.supply.balances[seed2.entity_id] = 1000

        shared_cold = _entity(b"cluster-cold").public_key

        for seed in (seed1, seed2):
            tx = create_set_authority_key_transaction(
                seed, new_authority_key=shared_cold, nonce=0, fee=500,
            )
            ok, reason = chain.apply_set_authority_key(tx, proposer_id=seed.entity_id)
            self.assertTrue(ok, reason)
            self.assertEqual(chain.get_authority_key(seed.entity_id), shared_cold)


class TestUnstakeRequiresAuthorityKey(unittest.TestCase):
    """Once a cold key is promoted, unstake signatures must come from the cold key."""

    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain.register_entity(entity.entity_id, entity.public_key, proof)

    def test_unstake_with_hot_key_rejected_after_cold_key_set(self):
        from messagechain.core.staking import verify_unstake_transaction

        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1000
        chain.supply.staked[hot.entity_id] = 500

        # Promote cold key
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Attempt unstake signed by HOT key
        unstake = create_unstake_transaction(hot, amount=100, nonce=1, fee=500)

        # The hot-key signature verifies under hot.public_key, but the chain
        # requires it to verify under the authority_key (= cold.public_key).
        authority_pk = chain.get_authority_key(hot.entity_id)
        self.assertEqual(authority_pk, cold.public_key)
        self.assertFalse(verify_unstake_transaction(unstake, authority_pk))

    def test_unstake_with_cold_key_accepted(self):
        from messagechain.core.staking import verify_unstake_transaction

        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1000
        chain.supply.staked[hot.entity_id] = 500

        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Build an unstake tx signed by the COLD key, on behalf of the HOT
        # entity. The cold entity is not itself registered — it's purely
        # an authority key, keyed by the hot entity's id.
        import time
        from messagechain.core.staking import UnstakeTransaction
        from messagechain.crypto.keys import Signature

        tx = UnstakeTransaction(
            entity_id=hot.entity_id,
            amount=100,
            nonce=1,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        msg_hash = _hash(tx._signable_data())
        tx.signature = cold.keypair.sign(msg_hash)
        tx.tx_hash = tx._compute_hash()

        authority_pk = chain.get_authority_key(hot.entity_id)
        self.assertTrue(verify_unstake_transaction(tx, authority_pk))


if __name__ == "__main__":
    unittest.main()
