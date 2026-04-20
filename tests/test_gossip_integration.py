"""
End-to-end multi-node integration tests for non-message-tx gossip.

Unit tests elsewhere exercise _handle_announce_pending_tx directly with
a hand-constructed payload dict — that validates the handler's logic but
not the actual wire path.  This suite sets up two real Server instances
wired together through a loopback link that forces every message
through NetworkMessage.serialize / encode_message / decode_message /
NetworkMessage.deserialize — the exact code that runs between peers in
production.  A serialization bug, a missing field, or a wrong message-
type dispatch that unit tests would miss surfaces here.

We avoid real TCP sockets (flaky, slow, OS-dependent) by giving each
peer a _LoopbackWriter whose drain() hands the bytes to the other
server's _handle_p2p_message via the same decode path real peers use.
Everything else — the Server instances, the blockchain, the rate
limiter, the ban manager, the full admission/validate/queue/relay
pipeline — is the production code path.
"""

import asyncio
import struct
import unittest

from messagechain import config
from messagechain.core.authority_key import (
    create_set_authority_key_transaction,
)
from messagechain.core.staking import create_stake_transaction
from messagechain.crypto.hash_sig import _hash
from messagechain.identity.identity import Entity
from messagechain.network.peer import Peer
from messagechain.network.protocol import (
    NetworkMessage, MessageType, decode_message,
)


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _LoopbackWriter:
    """Duck-types the asyncio.StreamWriter interface needed by
    write_message().  Buffers writes; on drain() forwards the decoded
    NetworkMessage to the target server's _handle_p2p_message.

    Deliberately exercises the length-prefix framing + JSON round-trip
    exactly as a real TCP peer would — that's the whole point of the
    integration test.
    """

    def __init__(self, target_server, *, sender_address: str):
        self._buf = bytearray()
        self._target = target_server
        self._sender_address = sender_address

    def write(self, data: bytes) -> None:
        self._buf.extend(data)

    async def drain(self) -> None:
        # Parse length-prefixed frames out of the buffer and deliver
        # each one to the target.  A single gossip may produce one frame;
        # batch up to N frames is fine too.
        while len(self._buf) >= 4:
            length = struct.unpack(">I", bytes(self._buf[:4]))[0]
            if len(self._buf) < 4 + length:
                break
            frame = bytes(self._buf[4:4 + length])
            del self._buf[:4 + length]
            msg = decode_message(frame)
            # Deliver via the receiver's real dispatcher.  Look up the
            # fake "peer" object the target keeps for this sender.
            sender_peer = self._target.peers.get(self._sender_address)
            if sender_peer is None:
                # Hasn't registered the sender as a peer yet — drop.
                continue
            await self._target._handle_p2p_message(msg, sender_peer)

    def close(self) -> None:
        self._buf.clear()


def _wire_peers(server_a, server_b) -> None:
    """Register server_a and server_b as each other's peers, with writers
    that loop back into the other's message handler.  Mimics a completed
    handshake — in production this follows _connect_to_peer + HANDSHAKE
    but we skip those to keep the test focused on gossip."""
    addr_a = "127.0.0.1:10001"
    addr_b = "127.0.0.1:10002"

    a_to_b_writer = _LoopbackWriter(server_b, sender_address=addr_a)
    b_to_a_writer = _LoopbackWriter(server_a, sender_address=addr_b)

    peer_b_on_a = Peer(
        host="127.0.0.1", port=10002, writer=a_to_b_writer, is_connected=True,
    )
    peer_a_on_b = Peer(
        host="127.0.0.1", port=10001, writer=b_to_a_writer, is_connected=True,
    )
    server_a.peers[addr_b] = peer_b_on_a
    server_b.peers[addr_a] = peer_a_on_b


def _new_server(port_base: int):
    from server import Server
    return Server(
        p2p_port=port_base, rpc_port=port_base + 1, seed_nodes=[],
    )


def _register(chain, entity):
    proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
    chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


async def _flush(n: int = 3) -> None:
    """Yield control a few times so queued create_task coroutines run."""
    for _ in range(n):
        await asyncio.sleep(0)


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    async def asyncTearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height


class TestAuthorityTxGossipRoundTrip(_Base):
    """A SetAuthorityKey tx submitted to node A must appear in node B's
    pending pool via the real gossip wire path."""

    async def test_authority_tx_propagates(self):
        srv_a = _new_server(port_base=20000)
        srv_b = _new_server(port_base=20010)

        user = _entity(b"user")
        cold_pk = _entity(b"user-cold").public_key
        for s in (srv_a, srv_b):
            _register(s.blockchain, user)
            s.blockchain.supply.balances[user.entity_id] = 10_000_000

        _wire_peers(srv_a, srv_b)

        tx = create_set_authority_key_transaction(
            user, new_authority_key=cold_pk, nonce=0, fee=500,
        )
        # Admit via the RPC-handler path on node A — this is what
        # cmd_set_authority_key hits.
        result = srv_a._rpc_set_authority_key({"transaction": tx.serialize()})
        self.assertTrue(result.get("ok"), result.get("error"))

        # Let the gossip create_task run and deliver to B.
        await _flush()

        self.assertIn(
            tx.tx_hash,
            getattr(srv_b, "_pending_authority_txs", {}),
            "SetAuthorityKey tx submitted to A should propagate via "
            "ANNOUNCE_PENDING_TX gossip and land in B's authority pool.",
        )


class TestStakeTxGossipRoundTrip(_Base):
    """Stake tx gossip survives the full wire round-trip."""

    async def test_stake_tx_propagates(self):
        srv_a = _new_server(port_base=20020)
        srv_b = _new_server(port_base=20030)

        val = _entity(b"val")
        for s in (srv_a, srv_b):
            _register(s.blockchain, val)
            s.blockchain.supply.balances[val.entity_id] = 10_000_000

        _wire_peers(srv_a, srv_b)

        tx = create_stake_transaction(val, amount=200, nonce=0, fee=500)
        result = srv_a._rpc_stake({"transaction": tx.serialize()})
        self.assertTrue(result.get("ok"), result.get("error"))

        await _flush()

        self.assertIn(
            tx.tx_hash, getattr(srv_b, "_pending_stake_txs", {}),
        )


class TestGossipRelayToThirdPeer(_Base):
    """A → B → C: node B receives the gossip and re-broadcasts it to C.
    Proves the relay path (not just the initial broadcast) works."""

    async def test_three_node_relay(self):
        srv_a = _new_server(port_base=20040)
        srv_b = _new_server(port_base=20050)
        srv_c = _new_server(port_base=20060)

        val = _entity(b"val")
        for s in (srv_a, srv_b, srv_c):
            _register(s.blockchain, val)
            s.blockchain.supply.balances[val.entity_id] = 10_000_000

        # Wire A<->B and B<->C but NOT A<->C. C only learns via B's relay.
        _wire_peers(srv_a, srv_b)
        _wire_peers(srv_b, srv_c)

        tx = create_stake_transaction(val, amount=250, nonce=0, fee=500)
        srv_a._rpc_stake({"transaction": tx.serialize()})

        # Two flushes: first for A → B broadcast, second for B → C relay.
        await _flush(n=5)

        self.assertIn(
            tx.tx_hash, getattr(srv_c, "_pending_stake_txs", {}),
            "C must receive the tx via B's relay, not just A's direct link.",
        )


class TestInvalidGossipDoesNotPoisonReceiver(_Base):
    """A malformed or invalid gossip payload from A must not leave B in
    a broken state; B stays able to receive valid gossip afterwards."""

    async def test_invalid_then_valid(self):
        srv_a = _new_server(port_base=20070)
        srv_b = _new_server(port_base=20080)

        val = _entity(b"val")
        for s in (srv_a, srv_b):
            _register(s.blockchain, val)
            s.blockchain.supply.balances[val.entity_id] = 10_000_000

        _wire_peers(srv_a, srv_b)

        # Directly inject a malformed ANNOUNCE_PENDING_TX to B.  The
        # _wire_peers helper uses the fixed 10001/10002 addresses; pick
        # whichever key ended up there.
        sender_peer = next(iter(srv_b.peers.values()))
        bad_msg = NetworkMessage(
            MessageType.ANNOUNCE_PENDING_TX, {"kind": "nonsense"},
        )
        await srv_b._handle_p2p_message(bad_msg, sender_peer)

        # Now B should still accept a valid gossip afterwards.
        tx = create_stake_transaction(val, amount=300, nonce=0, fee=500)
        srv_a._rpc_stake({"transaction": tx.serialize()})
        await _flush()

        self.assertIn(
            tx.tx_hash, getattr(srv_b, "_pending_stake_txs", {}),
            "B must stay functional after a malformed gossip from A.",
        )


if __name__ == "__main__":
    unittest.main()
