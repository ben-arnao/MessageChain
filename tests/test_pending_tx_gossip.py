"""
Regression tests for non-message-tx gossip and the cross-pool leaf
dedupe that admission paths now perform.

Before gossip, a SetAuthorityKey / Revoke / KeyRotation / stake / unstake
submitted to node A sat in A's per-type pending pool until A happened to
be the proposer.  If the next proposer was a different peer (expected
case with >1 validator) the tx never landed in a block.

The server's admission path now:
  1. Checks cross-pool for an existing pending tx from the same entity
     at the same leaf_index, refusing the second one immediately.
  2. Broadcasts ANNOUNCE_PENDING_TX to all connected peers so any
     proposer can pick the tx up.
Peers receiving the gossip re-validate, dedupe by tx_hash, and queue
into their own pending pool.

We don't spin up a real P2P swarm in unit tests — gossip is exercised by
calling the receiver's handler directly with a serialized payload.
"""

import time
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.emergency_revoke import RevokeTransaction
from messagechain.core.staking import (
    StakeTransaction, UnstakeTransaction, create_stake_transaction,
    create_unstake_transaction,
)
from messagechain.crypto.hash_sig import _hash
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _FakePeer:
    """Bare-bones stand-in for a server.Peer in unit tests."""
    host = "127.0.0.1"
    port = 9333
    address = "127.0.0.1:9333"
    is_connected = True
    writer = None


def _build_server():
    """Construct a Server instance without starting its event loop."""
    from server import Server
    srv = Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)
    return srv


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


class TestCrossPoolLeafDedupe(_Base):
    """Admission path rejects a second tx at the same leaf_index."""

    def test_same_entity_same_leaf_across_pools_rejected(self):
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 100_000
        srv.blockchain.supply.staked[alice.entity_id] = 10_000

        # Stake tx at leaf N lands in _pending_stake_txs
        stake = create_stake_transaction(alice, amount=100, nonce=0, fee=500)
        srv._pending_stake_txs = {stake.tx_hash: stake}

        # An unstake signed by the same entity rewinding to the same leaf
        # must be refused by _check_leaf_across_all_pools.
        alice.keypair._next_leaf = stake.signature.leaf_index
        # Bypass the fee-check by building manually so we exercise the
        # leaf check in isolation.
        utx = UnstakeTransaction(
            entity_id=alice.entity_id, amount=50, nonce=1,
            timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        utx.signature = alice.keypair.sign(_hash(utx._signable_data()))
        utx.tx_hash = utx._compute_hash()

        self.assertFalse(
            srv._check_leaf_across_all_pools(utx),
            "Cross-pool dedupe must reject a second tx at a leaf already "
            "used by a pending tx from the same entity.",
        )

    def test_cold_key_unstake_not_false_positive_against_hot_leaf(self):
        """A cold-signed unstake at leaf N is NOT a collision with a pending
        hot-signed stake at leaf N — they're in different leaf namespaces.

        Before the fix, cross-pool dedupe keyed by entity_id would reject
        this as a false positive.  Correct behavior: the cold key's leaf
        space is independent of the hot key's, so no collision.
        """
        from messagechain.core.authority_key import (
            create_set_authority_key_transaction,
        )
        srv = _build_server()
        hot = _entity(b"hot")
        cold = _entity(b"cold")
        self._register(srv.blockchain, hot)
        srv.blockchain.supply.balances[hot.entity_id] = 100_000
        srv.blockchain.supply.staked[hot.entity_id] = 10_000
        # Cold key promoted
        srv.blockchain.authority_keys[hot.entity_id] = cold.public_key

        # Hot-signed stake tx lands in the pool at some leaf index.
        hot_stake = create_stake_transaction(hot, amount=100, nonce=0, fee=500)
        srv._pending_stake_txs = {hot_stake.tx_hash: hot_stake}

        # Build a cold-signed unstake that happens to sit at THE SAME
        # leaf_index in the COLD tree — different namespace, should pass.
        target_leaf = hot_stake.signature.leaf_index
        cold.keypair._next_leaf = target_leaf
        utx = UnstakeTransaction(
            entity_id=hot.entity_id, amount=50, nonce=1,
            timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        utx.signature = cold.keypair.sign(_hash(utx._signable_data()))
        utx.tx_hash = utx._compute_hash()
        self.assertEqual(utx.signature.leaf_index, target_leaf)

        self.assertTrue(
            srv._check_leaf_across_all_pools(utx),
            "Cold-signed unstake at leaf N must not be flagged as a "
            "collision with a hot-signed tx at leaf N — different keys, "
            "different leaf namespaces.",
        )


class TestPendingTxGossipReceiver(_Base):
    """The gossip receiver validates + queues per-type."""

    def test_gossiped_authority_tx_lands_in_pool(self):
        srv = _build_server()
        user = _entity(b"user")
        cold_pk = _entity(b"cold").public_key
        self._register(srv.blockchain, user)
        srv.blockchain.supply.balances[user.entity_id] = 100_000

        tx = create_set_authority_key_transaction(
            user, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        payload = {"kind": "authority", "tx": tx.serialize()}
        srv._handle_announce_pending_tx(payload, _FakePeer())
        self.assertIn(tx.tx_hash, getattr(srv, "_pending_authority_txs", {}))

    def test_gossiped_revoke_requires_cold_signature(self):
        srv = _build_server()
        hot = _entity(b"hot")
        cold = _entity(b"cold")
        self._register(srv.blockchain, hot)
        srv.blockchain.supply.balances[hot.entity_id] = 100_000
        srv.blockchain.authority_keys[hot.entity_id] = cold.public_key

        # Revoke signed by cold key — should land
        revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        revoke.signature = cold.keypair.sign(_hash(revoke._signable_data()))
        revoke.tx_hash = revoke._compute_hash()
        srv._handle_announce_pending_tx(
            {"kind": "authority", "tx": revoke.serialize()}, _FakePeer(),
        )
        self.assertIn(revoke.tx_hash, getattr(srv, "_pending_authority_txs", {}))

        # Revoke signed by a random key — should NOT land
        srv2 = _build_server()
        self._register(srv2.blockchain, hot)
        srv2.blockchain.supply.balances[hot.entity_id] = 100_000
        srv2.blockchain.authority_keys[hot.entity_id] = cold.public_key
        imposter = _entity(b"imposter")
        bad_revoke = RevokeTransaction(
            entity_id=hot.entity_id, timestamp=time.time(), fee=500,
            signature=Signature([], 0, [], b"", b""),
        )
        bad_revoke.signature = imposter.keypair.sign(_hash(bad_revoke._signable_data()))
        bad_revoke.tx_hash = bad_revoke._compute_hash()
        srv2._handle_announce_pending_tx(
            {"kind": "authority", "tx": bad_revoke.serialize()}, _FakePeer(),
        )
        self.assertNotIn(
            bad_revoke.tx_hash, getattr(srv2, "_pending_authority_txs", {}),
        )

    def test_gossiped_stake_lands_in_stake_pool(self):
        srv = _build_server()
        v = _entity(b"val")
        self._register(srv.blockchain, v)
        srv.blockchain.supply.balances[v.entity_id] = 100_000

        tx = create_stake_transaction(v, amount=200, nonce=0, fee=500)
        srv._handle_announce_pending_tx(
            {"kind": "stake", "tx": tx.serialize()}, _FakePeer(),
        )
        self.assertIn(tx.tx_hash, getattr(srv, "_pending_stake_txs", {}))

    def test_gossiped_unstake_requires_authority_key(self):
        srv = _build_server()
        v = _entity(b"val")
        self._register(srv.blockchain, v)
        srv.blockchain.supply.balances[v.entity_id] = 100_000
        srv.blockchain.supply.staked[v.entity_id] = 10_000

        # Default authority = signing key; tx signed by v should land
        tx = create_unstake_transaction(v, amount=100, nonce=0, fee=500)
        srv._handle_announce_pending_tx(
            {"kind": "unstake", "tx": tx.serialize()}, _FakePeer(),
        )
        self.assertIn(tx.tx_hash, getattr(srv, "_pending_unstake_txs", {}))

    def test_gossip_dedupes_by_tx_hash(self):
        """A tx gossiped twice is only queued once."""
        srv = _build_server()
        v = _entity(b"val")
        self._register(srv.blockchain, v)
        srv.blockchain.supply.balances[v.entity_id] = 100_000

        tx = create_stake_transaction(v, amount=200, nonce=0, fee=500)
        payload = {"kind": "stake", "tx": tx.serialize()}
        srv._handle_announce_pending_tx(payload, _FakePeer())
        srv._handle_announce_pending_tx(payload, _FakePeer())
        self.assertEqual(
            len(getattr(srv, "_pending_stake_txs", {})), 1,
        )

    def test_malformed_gossip_payload_ignored(self):
        """A garbage payload from a peer doesn't crash the handler."""
        srv = _build_server()
        srv._handle_announce_pending_tx({"kind": "bogus"}, _FakePeer())
        srv._handle_announce_pending_tx({"kind": "stake"}, _FakePeer())  # no tx
        srv._handle_announce_pending_tx(
            {"kind": "stake", "tx": {"wrong": "shape"}}, _FakePeer(),
        )
        # No pools created for bad input.
        self.assertFalse(getattr(srv, "_pending_stake_txs", {}))


if __name__ == "__main__":
    unittest.main()
