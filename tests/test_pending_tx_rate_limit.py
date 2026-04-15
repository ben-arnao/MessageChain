"""
Per-peer rate limit on ANNOUNCE_PENDING_TX gossip.

Non-message-tx gossip (stake / unstake / authority / governance) is
expensive to process: each carries a WOTS+ signature that the receiver
must verify before admitting.  Without a per-peer rate cap, a peer
could flood us with validly-signed junk and force unbounded CPU spend.

The fix: every gossip message consumes a token from the peer's
"pending_tx" token bucket (RATE_PENDING_TX = 2/sec, burst 20).  Over-
rate traffic is dropped BEFORE the signature-verify path, and the
peer's ban score increments under OFFENSE_RATE_LIMIT — repeated
flooding earns a disconnect and temporary ban.
"""

import time
import unittest

from messagechain import config
from messagechain.core.staking import create_stake_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity
from messagechain.network.ratelimit import RATE_PENDING_TX


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


def _build_server():
    from server import Server
    return Server(p2p_port=0, rpc_port=0, seed_nodes=[], data_dir=None)


class _FakePeer:
    def __init__(self, addr="10.0.0.1:9333"):
        self.host, _, self.port = addr.partition(":")
        self.port = int(self.port) if self.port else 9333
        self.address = addr
        self.is_connected = True
        self.writer = None


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _register(self, chain, entity):
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain.register_entity(entity.entity_id, entity.public_key, proof)


class TestRateLimitBucketExists(unittest.TestCase):
    """Sanity: the new 'pending_tx' rate bucket is wired."""

    def test_bucket_rate_and_burst(self):
        rate, burst = RATE_PENDING_TX
        self.assertGreater(rate, 0)
        self.assertGreater(burst, 0)

    def test_rate_limiter_allocates_pending_tx_bucket(self):
        from messagechain.network.ratelimit import PeerRateLimiter
        rl = PeerRateLimiter()
        # First call ensures the bucket exists — should return True until
        # burst is exhausted.
        self.assertTrue(rl.check("1.2.3.4:9333", "pending_tx"))


class TestGossipReceiverEnforcesRateLimit(_Base):
    """The gossip handler consumes a token per message and drops/scores
    over-rate peers."""

    def _make_stake_tx(self, chain):
        alice = _entity(b"alice")
        self._register(chain, alice)
        chain.supply.balances[alice.entity_id] = 10_000_000
        return alice, create_stake_transaction(
            alice, amount=100, nonce=0, fee=500,
        )

    def test_first_gossip_accepted(self):
        srv = _build_server()
        _, tx = self._make_stake_tx(srv.blockchain)
        peer = _FakePeer()
        srv._handle_announce_pending_tx(
            {"kind": "stake", "tx": tx.serialize()}, peer,
        )
        self.assertIn(tx.tx_hash, srv._pending_stake_txs)

    def test_over_rate_gossip_dropped_and_scored(self):
        """After the burst is exhausted, subsequent gossip is rejected
        and the peer accumulates ban score."""
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000
        peer = _FakePeer()

        # Drain the bucket — the burst cap is RATE_PENDING_TX[1] (= 20).
        burst = RATE_PENDING_TX[1]
        # Fire burst+5 gossip messages; each needs a unique leaf, so we
        # use distinct nonces to generate distinct txs.
        leaves_bumped = 0
        for n in range(burst + 5):
            alice.keypair._next_leaf = n
            tx = create_stake_transaction(alice, amount=100, nonce=n, fee=500)
            srv._handle_announce_pending_tx(
                {"kind": "stake", "tx": tx.serialize()}, peer,
            )

        # The over-rate arrivals were dropped — ban manager shows at
        # least one offense under OFFENSE_RATE_LIMIT.
        score = srv.ban_manager.get_score(peer.address)
        self.assertGreater(
            score, 0,
            "Over-rate ANNOUNCE_PENDING_TX should increment ban score.",
        )

    def test_malformed_payload_scored_under_protocol_violation(self):
        srv = _build_server()
        peer = _FakePeer(addr="10.0.0.99:9333")
        srv._handle_announce_pending_tx({"kind": "bogus"}, peer)
        score = srv.ban_manager.get_score(peer.address)
        self.assertGreater(score, 0, "Malformed gossip must score the peer.")

    def test_rate_limit_is_per_peer(self):
        """Flooding from one peer doesn't rate-limit a different peer."""
        srv = _build_server()
        alice = _entity(b"alice")
        self._register(srv.blockchain, alice)
        srv.blockchain.supply.balances[alice.entity_id] = 10_000_000

        flooder = _FakePeer(addr="10.0.0.2:9333")
        burst = RATE_PENDING_TX[1]
        for n in range(burst + 10):
            alice.keypair._next_leaf = n
            tx = create_stake_transaction(alice, amount=100, nonce=n, fee=500)
            srv._handle_announce_pending_tx(
                {"kind": "stake", "tx": tx.serialize()}, flooder,
            )

        # A different peer's bucket is still full.
        polite = _FakePeer(addr="10.0.0.3:9333")
        self.assertTrue(
            srv.rate_limiter.check(polite.address, "pending_tx"),
            "A well-behaved peer must not share the flooder's bucket.",
        )


if __name__ == "__main__":
    unittest.main()
