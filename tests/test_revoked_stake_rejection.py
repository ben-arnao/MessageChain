"""
Revoked entities must not be able to submit new StakeTransactions.

Revoke is an authoritative kill switch: the cold authority key has
declared this identity retired / compromised.  The existing code
correctly blocks revoked entities from proposing, attesting,
finality-voting, and unstaking — but stake re-acquisition was unguarded.

Without this check, a revoked entity could:

- Silently re-enroll as a staker after the cold-key holder explicitly
  retired the identity.
- Lock new tokens into stake that can't be unstaked (since the unstake
  path IS revocation-checked), turning stake into a soft burn.
- Perturb bootstrap progress counters and validator-slot accounting.

Fix: `_validate_stake_tx_in_block` (and its standalone variant
`_validate_stake_tx`) now reject stake txs from entities in
`self.revoked_entities` with the same error shape as the unstake path.
"""

import time
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.emergency_revoke import RevokeTransaction
from messagechain.core.staking import create_stake_transaction
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

    def _revoke(self, chain, hot_entity, cold_entity):
        """Promote cold key, then revoke hot entity using the cold key."""
        set_tx = create_set_authority_key_transaction(
            hot_entity, new_authority_key=cold_entity.public_key,
            nonce=0, fee=500,
        )
        ok, reason = chain.apply_set_authority_key(
            set_tx, proposer_id=hot_entity.entity_id,
        )
        assert ok, reason

        revoke = RevokeTransaction(
            entity_id=hot_entity.entity_id,
            timestamp=time.time(),
            fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold_entity.keypair.sign(
            _hash(revoke._signable_data()),
        )
        revoke.tx_hash = revoke._compute_hash()
        ok, reason = chain.apply_revoke(
            revoke, proposer_id=hot_entity.entity_id,
        )
        assert ok, reason


class TestRevokedStakeRejection(_Base):

    def test_revoked_entity_stake_rejected_in_block_validation(self):
        """A revoked entity's StakeTransaction must be rejected by the
        cumulative block-level validator."""
        chain = Blockchain()
        hot = _entity(b"revoked-stake-block")
        cold = _entity(b"revoked-stake-block-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1_000_000
        chain.supply.staked[hot.entity_id] = 5_000

        self._revoke(chain, hot, cold)
        self.assertTrue(chain.is_revoked(hot.entity_id))

        # Hot-key's nonce has advanced (set_authority_key used nonce 0).
        current_nonce = chain.nonces[hot.entity_id]
        stx = create_stake_transaction(
            hot, amount=500_000, nonce=current_nonce, fee=500,
        )
        pending_nonces: dict[bytes, int] = {}
        pending_spent: dict[bytes, int] = {}
        pending_pubkeys: dict[bytes, bytes] = {}
        pending_credits: dict[bytes, int] = {}

        ok, reason = chain._validate_stake_tx_in_block(
            stx, pending_nonces, pending_spent,
            pending_pubkeys, pending_credits,
        )
        self.assertFalse(ok)
        self.assertIn("revoked", reason.lower())

    def test_revoked_entity_stake_rejected_in_standalone_validation(self):
        """Same rejection must happen in the standalone (non-cumulative)
        variant used by validate_block_standalone."""
        chain = Blockchain()
        hot = _entity(b"revoked-stake-standalone")
        cold = _entity(b"revoked-stake-standalone-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 1_000_000
        chain.supply.staked[hot.entity_id] = 5_000

        self._revoke(chain, hot, cold)

        current_nonce = chain.nonces[hot.entity_id]
        stx = create_stake_transaction(
            hot, amount=500_000, nonce=current_nonce, fee=500,
        )

        ok, reason = chain._validate_stake_tx(stx)
        self.assertFalse(ok)
        self.assertIn("revoked", reason.lower())

    def test_non_revoked_entity_can_still_stake(self):
        """Regression — the revocation check must not break normal staking."""
        chain = Blockchain()
        alice = _entity(b"non-revoked-stake")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 1_000_000

        stx = create_stake_transaction(
            alice, amount=500_000, nonce=0, fee=500,
        )
        pending_nonces: dict[bytes, int] = {}
        pending_spent: dict[bytes, int] = {}
        pending_pubkeys: dict[bytes, bytes] = {}
        pending_credits: dict[bytes, int] = {}

        ok, reason = chain._validate_stake_tx_in_block(
            stx, pending_nonces, pending_spent,
            pending_pubkeys, pending_credits,
        )
        self.assertTrue(ok, reason)

        # Standalone variant too.
        ok2, reason2 = chain._validate_stake_tx(stx)
        self.assertTrue(ok2, reason2)

    def test_revoked_entity_cannot_restake_after_revoke_unstake(self):
        """Full attack scenario:
        1. Validator is active with balance + stake.
        2. Cold-key holder revokes it (force-unstakes the stake).
        3. Revoked entity attempts to stake again using the hot key.
        4. The re-stake must be rejected — otherwise the attacker traps
           tokens that revocation should have retired.
        """
        chain = Blockchain()
        hot = _entity(b"restake-attack-hot")
        cold = _entity(b"restake-attack-cold")
        self._register(chain, hot)
        chain.supply.balances[hot.entity_id] = 10_000_000
        chain.supply.staked[hot.entity_id] = 5_000_000

        # Before revoke: hot CAN stake.
        stx_before = create_stake_transaction(
            hot, amount=100_000, nonce=0, fee=500,
        )
        # Fresh pending dicts for every call so nonce bookkeeping doesn't
        # leak across attempts (standalone-style validation).
        ok, _ = chain._validate_stake_tx_in_block(
            stx_before, {}, {}, {}, {},
        )
        self.assertTrue(ok)

        # Revoke: cold key retires the hot identity.
        self._revoke(chain, hot, cold)

        # Force-unstake effect: active stake is zero, moved to unbonding.
        self.assertEqual(chain.supply.get_staked(hot.entity_id), 0)
        pending = chain.supply.pending_unstakes.get(hot.entity_id, [])
        self.assertEqual(sum(amt for amt, _ in pending), 5_000_000)

        # Attacker, still holding the hot key, tries to re-stake.
        current_nonce = chain.nonces[hot.entity_id]
        stx_after = create_stake_transaction(
            hot, amount=100_000, nonce=current_nonce, fee=500,
        )
        ok, reason = chain._validate_stake_tx_in_block(
            stx_after, {}, {}, {}, {},
        )
        self.assertFalse(ok)
        self.assertIn("revoked", reason.lower())

        # Standalone validator rejects too.
        ok2, reason2 = chain._validate_stake_tx(stx_after)
        self.assertFalse(ok2)
        self.assertIn("revoked", reason2.lower())


if __name__ == "__main__":
    unittest.main()
