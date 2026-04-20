"""
Tests for emergency revocation of a compromised validator.

Scenario: an attacker has stolen a validator's hot signing key (via server
compromise). Without a kill-switch, they have ~7 days to produce malicious
blocks, vote in governance, and generally abuse the identity before the
slow unbonding period completes and the legitimate operator can react.

A RevokeTransaction — signed by the cold authority key, which the attacker
does NOT have — instantly:

- Flags the entity as revoked, so new block proposals and attestations
  from that entity are rejected by validation.
- Pushes all stake into the normal unbonding queue so the cold-key holder
  can recover their funds after the standard unbonding delay.
- Removes the entity from the consensus stakes set so proposer selection
  ignores them going forward.

The cold key never touches the server, so this tx is safe to keep
pre-signed on paper / in a separate cold environment for rapid response.
"""

import time
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import (
    RevokeTransaction,
    create_revoke_transaction,
    verify_revoke_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


class TestRevokeSignedByColdKey(_Base):

    def test_revoke_signed_by_authority_key_accepted(self):
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000
        chain.supply.staked[hot.entity_id] = 5_000

        # Promote cold key
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Build revoke tx signed by cold key (on behalf of hot entity id).
        # No nonce — revoke is nonce-free so it can be pre-signed offline.
        revoke = RevokeTransaction(
            entity_id=hot.entity_id,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        msg_hash = _hash(revoke._signable_data())
        revoke.signature = cold.keypair.sign(msg_hash)
        revoke.tx_hash = revoke._compute_hash()

        ok, reason = chain.apply_revoke(revoke, proposer_id=hot.entity_id)
        self.assertTrue(ok, reason)

    def test_revoke_signed_by_hot_key_rejected_after_cold_key_set(self):
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000
        chain.supply.staked[hot.entity_id] = 5_000

        # Promote cold key
        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Attacker holds only the hot key and tries to revoke
        revoke = create_revoke_transaction(hot, fee=500)
        ok, reason = chain.apply_revoke(revoke, proposer_id=hot.entity_id)
        self.assertFalse(ok)


class TestRevokeEffects(_Base):

    def _set_up_revoked(self):
        chain = Blockchain()
        hot = _entity(b"validator-hot")
        cold = _entity(b"validator-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000
        chain.supply.staked[hot.entity_id] = 5_000

        set_tx = create_set_authority_key_transaction(
            hot, new_authority_key=cold.public_key, nonce=0, fee=500,
        )
        chain.apply_set_authority_key(set_tx, proposer_id=hot.entity_id)

        # Sign revoke with cold key
        revoke = RevokeTransaction(
            entity_id=hot.entity_id,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        chain.apply_revoke(revoke, proposer_id=hot.entity_id)
        return chain, hot, cold

    def test_revoke_flags_entity_as_revoked(self):
        chain, hot, _ = self._set_up_revoked()
        self.assertTrue(chain.is_revoked(hot.entity_id))

    def test_revoke_zeroes_active_stake(self):
        """Stake moves from staked -> pending unbonding, not immediately spendable."""
        chain, hot, _ = self._set_up_revoked()
        self.assertEqual(chain.supply.get_staked(hot.entity_id), 0)

    def test_revoke_queues_unbonding(self):
        """Funds must flow through the normal 7-day unbonding, not instant release,
        so that any in-flight slashing windows remain effective."""
        chain, hot, _ = self._set_up_revoked()
        pending = chain.supply.pending_unstakes.get(hot.entity_id, [])
        total_pending = sum(amt for amt, _ in pending)
        self.assertEqual(total_pending, 5_000)

    def test_revoke_is_idempotent(self):
        """Revoking an already-revoked entity fails cleanly — no side effects."""
        chain, hot, cold = self._set_up_revoked()

        # Rewind cold keypair to sign again (simulating re-submission)
        cold.keypair._next_leaf = 0
        revoke = RevokeTransaction(
            entity_id=hot.entity_id,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        ok, reason = chain.apply_revoke(revoke, proposer_id=hot.entity_id)
        self.assertFalse(ok)
        self.assertIn("revoked", reason.lower())


class TestVerifyRevokeTransaction(_Base):

    def test_verify_returns_true_for_valid_signature(self):
        cold = _entity(b"cold")
        tx = RevokeTransaction(
            entity_id=b"\x01" * 32,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        tx.signature = cold.keypair.sign(_hash(tx._signable_data()))
        tx.tx_hash = tx._compute_hash()
        self.assertTrue(verify_revoke_transaction(tx, cold.public_key))

    def test_verify_returns_false_for_wrong_key(self):
        cold = _entity(b"cold")
        other = _entity(b"other")
        tx = create_revoke_transaction(cold, fee=500)
        self.assertFalse(verify_revoke_transaction(tx, other.public_key))


if __name__ == "__main__":
    unittest.main()
