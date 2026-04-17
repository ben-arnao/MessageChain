"""
Tests for the stale pending-tx sweeper.

Without a sweep, a tx whose nonce has been passed (because the entity
nonce moved on via another tx) sits in the pool forever.  Worse, the
pool-eviction policy protects high-fee txs, so stale-but-expensive
junk pushes legitimate new txs out — on a live network this degrades
fairly quickly.

The sweeper drops txs from _pending_stake_txs / _pending_unstake_txs /
_pending_authority_txs / _pending_governance_txs that are:

  - nonce-stale: tx.nonce < chain's current nonce for that entity.
  - revoked-sender: the entity has been emergency-revoked.  Their
    stake is unbonding, their block production is off, and any
    pending txs signed by the compromised hot key must be dropped.
  - timestamp-expired: older than PENDING_TX_TTL seconds.
  - leaf-burned: the tx's signature leaf_index is already below the
    watermark (chain applied a tx at that leaf in a different pool
    or earlier block; this one can never land).

RevokeTransaction has no nonce, so only the revoked-sender,
timestamp, and leaf-burned checks apply to it.
"""

import time
import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.emergency_revoke import RevokeTransaction
from messagechain.core.staking import (
    create_stake_transaction, create_unstake_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server():
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


class TestStaleNonceSweep(_Base):

    def test_nonce_stale_tx_dropped_from_stake_pool(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        # Admit a stake tx with nonce 0
        tx = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        srv._pending_stake_txs = {tx.tx_hash: tx}

        # Chain nonce advances past this tx (as if a different tx from
        # alice already bumped it to 5).
        srv.blockchain.nonces[alice.entity_id] = 5

        srv._sweep_stale_pending_txs()
        self.assertNotIn(
            tx.tx_hash, srv._pending_stake_txs,
            "Stake tx with nonce < chain nonce must be swept.",
        )

    def test_current_nonce_tx_kept(self):
        """A tx whose nonce matches the current chain state is NOT stale."""
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=5, fee=500)
        srv._pending_stake_txs = {tx.tx_hash: tx}
        srv.blockchain.nonces[alice.entity_id] = 5  # matches tx.nonce

        srv._sweep_stale_pending_txs()
        self.assertIn(
            tx.tx_hash, srv._pending_stake_txs,
            "Tx at current nonce must not be swept.",
        )

    def test_future_nonce_tx_kept(self):
        """A tx nonce > chain nonce is out-of-order, not stale — it will
        become valid once earlier-nonce txs apply.  Keep it."""
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=10, fee=500)
        srv._pending_stake_txs = {tx.tx_hash: tx}
        srv.blockchain.nonces[alice.entity_id] = 5  # tx is in the future

        srv._sweep_stale_pending_txs()
        self.assertIn(tx.tx_hash, srv._pending_stake_txs)


class TestRevokedSenderSweep(_Base):

    def test_pending_tx_from_revoked_sender_dropped(self):
        srv = _build_server()
        hot = _entity(b"hot")
        self._register(srv.blockchain, hot)
        srv.blockchain.supply.balances[hot.entity_id] = 10_000_000

        # Pending stake tx from hot
        tx = create_stake_transaction(hot, amount=100, nonce=0, fee=500)
        srv._pending_stake_txs = {tx.tx_hash: tx}

        # Mark hot revoked after the tx was queued
        srv.blockchain.revoked_entities.add(hot.entity_id)

        srv._sweep_stale_pending_txs()
        self.assertNotIn(
            tx.tx_hash, srv._pending_stake_txs,
            "Pending tx from a revoked sender must be swept.",
        )


class TestLeafBurnedSweep(_Base):

    def test_pending_tx_below_watermark_dropped(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        srv._pending_stake_txs = {tx.tx_hash: tx}

        # Watermark bumped past this tx's leaf (another tx at a higher leaf
        # applied in a block).  The pending tx is now doomed — sweep it.
        srv.blockchain.leaf_watermarks[alice.entity_id] = (
            tx.signature.leaf_index + 5
        )

        srv._sweep_stale_pending_txs()
        self.assertNotIn(tx.tx_hash, srv._pending_stake_txs)


class TestTimestampExpirySweep(_Base):

    def test_ancient_pending_tx_dropped(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        # Backdate the tx timestamp well past the TTL.
        tx.timestamp = time.time() - 10_000  # ~2.8 hours old
        srv._pending_stake_txs = {tx.tx_hash: tx}

        srv._sweep_stale_pending_txs()
        self.assertNotIn(
            tx.tx_hash, srv._pending_stake_txs,
            "Pending tx older than PENDING_TX_TTL must be swept.",
        )


class TestRevokeNonceFreeSweep(_Base):
    """RevokeTransaction has no nonce — sweeper must handle it without
    KeyError and only use the non-nonce checks."""

    def test_pending_revoke_for_already_revoked_dropped(self):
        srv = _build_server()
        hot = _entity(b"hot")
        cold = _entity(b"cold")
        self._register(srv.blockchain, hot)
        srv.blockchain.supply.balances[hot.entity_id] = 10_000_000
        srv.blockchain.authority_keys[hot.entity_id] = cold.public_key

        revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        srv._pending_authority_txs = {revoke.tx_hash: revoke}

        # Already revoked — pending revoke is redundant and will fail apply.
        srv.blockchain.revoked_entities.add(hot.entity_id)

        srv._sweep_stale_pending_txs()
        self.assertNotIn(revoke.tx_hash, srv._pending_authority_txs)

    def test_pending_revoke_for_live_entity_kept(self):
        srv = _build_server()
        hot = _entity(b"hot")
        cold = _entity(b"cold")
        self._register(srv.blockchain, hot)
        srv.blockchain.supply.balances[hot.entity_id] = 10_000_000
        srv.blockchain.authority_keys[hot.entity_id] = cold.public_key

        revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        srv._pending_authority_txs = {revoke.tx_hash: revoke}

        srv._sweep_stale_pending_txs()
        self.assertIn(
            revoke.tx_hash, srv._pending_authority_txs,
            "Live-target revoke must not be swept.",
        )


class TestSweepAcrossAllPools(_Base):
    """One call to _sweep_stale_pending_txs should sweep every pool."""

    def test_all_four_pools_swept(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        # Stale in every pool
        stale_stake = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        stale_unstake = create_unstake_transaction(alice, amount=100, nonce=0, fee=500)
        stale_auth = create_set_authority_key_transaction(
            alice, new_authority_key=_entity(b"cold").public_key, nonce=0, fee=500,
        )
        srv._pending_stake_txs = {stale_stake.tx_hash: stale_stake}
        srv._pending_unstake_txs = {stale_unstake.tx_hash: stale_unstake}
        srv._pending_authority_txs = {stale_auth.tx_hash: stale_auth}

        # Chain nonce advances past all three
        srv.blockchain.nonces[alice.entity_id] = 10

        srv._sweep_stale_pending_txs()
        self.assertFalse(srv._pending_stake_txs)
        self.assertFalse(srv._pending_unstake_txs)
        self.assertFalse(srv._pending_authority_txs)


if __name__ == "__main__":
    unittest.main()
