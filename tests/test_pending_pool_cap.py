"""
Tests for per-pool size caps on the non-message-tx pending pools.

Each of _pending_{stake,unstake,authority,governance}_txs is bounded by
PENDING_POOL_MAX_SIZE.  A new tx landing on a full pool is only admitted
if its fee strictly beats the lowest-fee pending tx (which is evicted).
This matches Mempool's fee-based eviction and closes the unbounded-
memory DoS gap that was flagged in the last audit round.
"""

import time
import unittest
from unittest.mock import patch

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.staking import create_stake_transaction
from messagechain.crypto.hash_sig import _hash
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


class TestAdmitToPool(_Base):
    """Direct tests on the _admit_to_pool primitive."""

    def test_admits_when_under_cap(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        self.assertTrue(srv._admit_to_pool("_pending_stake_txs", tx))
        self.assertIn(tx.tx_hash, srv._pending_stake_txs)

    def test_re_admit_same_tx_idempotent(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        tx = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        srv._admit_to_pool("_pending_stake_txs", tx)
        # Second call returns True (idempotent) without doubling up.
        self.assertTrue(srv._admit_to_pool("_pending_stake_txs", tx))
        self.assertEqual(len(srv._pending_stake_txs), 1)

    def test_rejects_low_fee_when_full(self):
        """At capacity, a tx whose fee doesn't beat the minimum is refused."""
        srv = _build_server()
        # Shrink cap so the test runs fast
        with patch("messagechain.config.PENDING_POOL_MAX_SIZE", 3):
            pool_name = "_pending_stake_txs"
            # Fill with 3 entries at rising fees
            alice = _entity(b"alice")
            self._register(srv.blockchain, alice)
            srv.blockchain.supply.balances[alice.entity_id] = 10_000_000
            srv.blockchain.supply.staked[alice.entity_id] = 10_000_000

            existing = []
            for n in range(3):
                tx = create_stake_transaction(
                    alice, amount=100, nonce=n, fee=1000 + n * 100,
                )
                alice.keypair._next_leaf += 1  # unique leaf per tx
                self.assertTrue(srv._admit_to_pool(pool_name, tx))
                existing.append(tx)
            self.assertEqual(len(srv._pending_stake_txs), 3)

            # Low-fee tx → rejected
            bob = _entity(b"bob")
            self._register(srv.blockchain, bob)
            srv.blockchain.supply.balances[bob.entity_id] = 10_000_000
            low = create_stake_transaction(bob, amount=100, nonce=0, fee=500)
            self.assertFalse(srv._admit_to_pool(pool_name, low))
            self.assertNotIn(low.tx_hash, srv._pending_stake_txs)
            # Pool size unchanged
            self.assertEqual(len(srv._pending_stake_txs), 3)

    def test_high_fee_tx_evicts_lowest_when_full(self):
        """At capacity, a tx with fee > min evicts the current min."""
        srv = _build_server()
        with patch("messagechain.config.PENDING_POOL_MAX_SIZE", 3):
            pool_name = "_pending_stake_txs"
            alice = _entity(b"alice")
            self._register(srv.blockchain, alice)
            srv.blockchain.supply.balances[alice.entity_id] = 10_000_000
            srv.blockchain.supply.staked[alice.entity_id] = 10_000_000

            existing = []
            for n in range(3):
                tx = create_stake_transaction(
                    alice, amount=100, nonce=n, fee=1000 + n * 100,
                )
                alice.keypair._next_leaf += 1
                srv._admit_to_pool(pool_name, tx)
                existing.append(tx)
            min_tx = existing[0]  # fee 1000

            bob = _entity(b"bob")
            self._register(srv.blockchain, bob)
            srv.blockchain.supply.balances[bob.entity_id] = 10_000_000
            high = create_stake_transaction(bob, amount=100, nonce=0, fee=5000)
            self.assertTrue(srv._admit_to_pool(pool_name, high))
            self.assertIn(high.tx_hash, srv._pending_stake_txs)
            self.assertNotIn(min_tx.tx_hash, srv._pending_stake_txs)
            self.assertEqual(len(srv._pending_stake_txs), 3)


class TestPoolCapViaRpcPath(_Base):
    """Confirm the cap is enforced at the admission-path level (the
    layer clients actually hit), not just the internal helper."""

    def test_queue_authority_tx_surfaces_pool_full_error(self):
        srv = _build_server()
        user = _entity(b"user")
        cold_pk = _entity(b"user-cold").public_key
        self._register(srv.blockchain, user)
        srv.blockchain.supply.balances[user.entity_id] = 10_000_000

        with patch("messagechain.config.PENDING_POOL_MAX_SIZE", 1):
            # Fill pool
            tx1 = create_set_authority_key_transaction(
                user, new_authority_key=cold_pk, nonce=0, fee=5000,
            )
            ok, _ = srv._queue_authority_tx(
                tx1, validate_fn=srv.blockchain.validate_set_authority_key,
            )
            self.assertTrue(ok)

            # Second tx with lower fee → rejected with pool-full message.
            # Use a different entity to avoid the leaf-dedupe and nonce
            # paths — we're testing the pool cap in isolation.
            user2 = _entity(b"user2")
            self._register(srv.blockchain, user2)
            srv.blockchain.supply.balances[user2.entity_id] = 10_000_000
            tx2 = create_set_authority_key_transaction(
                user2, new_authority_key=cold_pk, nonce=0, fee=500,
            )
            ok, reason = srv._queue_authority_tx(
                tx2, validate_fn=srv.blockchain.validate_set_authority_key,
            )
            self.assertFalse(ok)
            self.assertIn("pool full", reason.lower())


if __name__ == "__main__":
    unittest.main()
