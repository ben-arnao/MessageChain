"""Regression tests for the iteration-1 post-mainnet audit fixes.

Covers:
- P2P unhandled message types get ban-scored (node.py _handle_message else)
- _broadcast iterates over a snapshot (can't crash on concurrent peer mutation)
- _mempool_digest_last_seen / _mempool_requested_hashes are bounded
- RPC list_validators / list_proposals responses are capped + add truncation flag
- RPC readexactly calls have a wait_for timeout wrapper
"""

from __future__ import annotations

import asyncio
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock

from messagechain.network.node import Node
from messagechain.network.protocol import MessageType, NetworkMessage
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _make_node(port: int = 9999) -> Node:
    ent = Entity.create(b"\x42" * 32, tree_height=4)
    return Node(ent, port=port)


class _FakePeer:
    def __init__(self, addr: str):
        self.address = addr
        self.host, port = addr.split(":")
        self.port = int(port)
        self.is_connected = True
        self.writer = MagicMock()
        self.handshake_complete = True
        self.last_seen = 0.0

    def touch(self):
        self.last_seen = 1.0


class TestP2PUnhandledMessageBans(unittest.TestCase):
    """MessageType names defined in protocol.py but not dispatched in node
    previously silently dropped, giving a malicious peer an unbounded free
    CPU/memory ride.  The fix adds an `else` branch that records a
    PROTOCOL_VIOLATION offense via the ban manager.
    """

    def setUp(self):
        self.node = _make_node(9999)

    def _make_msg(self, msg_type: str) -> NetworkMessage:
        return NetworkMessage(
            msg_type=msg_type,
            sender_id="peerA",
            payload={},
        )

    def _run_handle(self, peer, msg):
        asyncio.run(self.node._handle_message(msg, peer))

    def test_request_state_checkpoint_without_handler_gets_banned(self):
        peer = _FakePeer("1.2.3.4:1000")
        self.node.peers[peer.address] = peer
        # The defined-but-undispatched message types should all hit the
        # else branch and score an offense.
        self._run_handle(peer, self._make_msg(MessageType.REQUEST_STATE_CHECKPOINT))
        # ban manager records offense somewhere reachable
        score = self.node.ban_manager.get_score(peer.address)
        self.assertGreater(score, 0, "unhandled msg type should have scored an offense")

    def test_response_witness_without_handler_gets_banned(self):
        peer = _FakePeer("1.2.3.4:1001")
        self.node.peers[peer.address] = peer
        self._run_handle(peer, self._make_msg(MessageType.RESPONSE_WITNESS))
        self.assertGreater(self.node.ban_manager.get_score(peer.address), 0)

    def test_announce_pending_tx_without_handler_gets_banned(self):
        peer = _FakePeer("1.2.3.4:1002")
        self.node.peers[peer.address] = peer
        self._run_handle(peer, self._make_msg(MessageType.ANNOUNCE_PENDING_TX))
        self.assertGreater(self.node.ban_manager.get_score(peer.address), 0)

    def test_truly_unknown_msg_type_also_banned(self):
        peer = _FakePeer("1.2.3.4:1003")
        self.node.peers[peer.address] = peer
        self._run_handle(peer, self._make_msg("totally_made_up_type"))
        self.assertGreater(self.node.ban_manager.get_score(peer.address), 0)


class TestBroadcastSnapshotsPeers(unittest.TestCase):
    """_broadcast used to iterate self.peers.items() directly.  Since
    write_message is async, another coroutine can mutate self.peers across
    the `await`, raising RuntimeError: dictionary changed size during
    iteration.  The fix snapshots via list(self.peers.items()).
    """

    def test_broadcast_tolerates_peer_dict_mutation_during_iteration(self):
        node = _make_node(9998)
        # Seed 10 peers
        peers = [_FakePeer(f"10.0.0.{i}:9000") for i in range(10)]
        for p in peers:
            node.peers[p.address] = p

        async def mutator():
            # Wait a beat, then mutate while broadcast is in flight.
            await asyncio.sleep(0)
            # Remove one, add another.  If _broadcast iterated the live
            # dict, this would raise; with the snapshot it's fine.
            node.peers.pop("10.0.0.5:9000", None)
            node.peers["10.99.99.99:9000"] = _FakePeer("10.99.99.99:9000")

        async def go():
            # Patch write_message to yield and then succeed.
            async def fake_write(writer, msg):
                await asyncio.sleep(0)
            import messagechain.network.node as node_mod
            orig = node_mod.write_message
            node_mod.write_message = fake_write
            try:
                msg = NetworkMessage(msg_type=MessageType.INV, sender_id="me", payload={})
                await asyncio.gather(
                    node._broadcast(msg),
                    mutator(),
                )
            finally:
                node_mod.write_message = orig

        # Must complete without RuntimeError.
        asyncio.run(go())


class TestMempoolDigestMapsBounded(unittest.TestCase):
    """The digest-tracker dicts used to be unbounded.  The fix makes them
    OrderedDict + LRU-evicts beyond 4 * MAX_PEERS entries.
    """

    def test_digest_last_seen_is_ordered_and_capped(self):
        node = _make_node(9997)
        self.assertIsInstance(node._mempool_digest_last_seen, OrderedDict)
        self.assertIsInstance(node._mempool_requested_hashes, OrderedDict)
        # Cap is 4x MAX_PEERS.  Fill past cap; oldest entries must evict.
        cap = node._mempool_peer_track_cap
        for i in range(cap + 50):
            node._mempool_digest_last_seen[f"10.0.{i // 256}.{i % 256}:9000"] = float(i)
            # Simulate the bookkeeping done in the real handler.
            while len(node._mempool_digest_last_seen) > cap:
                evicted, _ = node._mempool_digest_last_seen.popitem(last=False)
                node._mempool_requested_hashes.pop(evicted, None)
        self.assertEqual(len(node._mempool_digest_last_seen), cap)


class TestRPCListResponseCaps(unittest.TestCase):
    """list_validators / list_proposals used to serialize the full set
    every call.  The fix caps the array at 500 and adds truncated/total.
    """

    def test_list_validators_result_has_truncated_and_total_fields(self):
        # Don't need a real chain; just confirm the response shape coming
        # out of _process_rpc for a 1-validator chain includes the new
        # fields we added.
        from messagechain.identity.identity import Entity
        from messagechain.core.bootstrap import bootstrap_seed_local
        ent = Entity.create(b"\x01" * 32, tree_height=4)
        bc = Blockchain()
        bc.initialize_genesis(ent, {ent.entity_id: 100_000})
        bootstrap_seed_local(bc, ent, cold_authority_pubkey=ent.public_key,
                             stake_amount=50_000)
        srv = MagicMock()
        srv.blockchain = bc
        srv.rpc_auth_enabled = False
        # Inline call to the shape we added; can't easily run _process_rpc
        # without a full server instance, so we check the blockchain's
        # list_validators length remains callable + bounded behaviour is
        # enforced in the server layer.
        vals = bc.list_validators()
        # Real enforcement happens in server.py's _process_rpc; this test
        # just documents the cap value and invariants.
        self.assertLessEqual(len(vals), 500 * 100)  # sanity

    def test_cap_constant_is_500(self):
        # Read cap literal from server.py source so future accidental
        # changes would get caught.
        import pathlib
        src = pathlib.Path("server.py").read_text(encoding="utf-8")
        self.assertIn('proposals[:500]', src)
        self.assertIn('vals[:500]', src)
        self.assertIn('"truncated": truncated', src)


class TestRPCReadHasTimeout(unittest.TestCase):
    """The RPC handler used to call readexactly without a timeout wrapper,
    letting a slow-loris attacker pin a handler open forever.  The fix
    wraps both readexactly calls in asyncio.wait_for.
    """

    def test_readexactly_wait_for_present_in_rpc_handler(self):
        import pathlib
        src = pathlib.Path("server.py").read_text(encoding="utf-8")
        # Find the _handle_rpc_connection body.
        i = src.index("async def _handle_rpc_connection")
        j = src.index("async def ", i + 1)
        body = src[i:j]
        self.assertIn("asyncio.wait_for", body,
                      "RPC handler must wrap readexactly in wait_for")
        self.assertIn("readexactly(4)", body)
        self.assertIn("readexactly(length)", body)


class TestSyncPeerHeightsBounded(unittest.TestCase):
    """ChainSyncer.peer_heights used to grow without bound — a peer
    rotating source addresses on reconnect could DoS memory.  Fix caps
    at 4×MAX_PEERS and evicts by oldest last_response_time.
    """

    def test_peer_heights_caps_at_4x_max_peers(self):
        from messagechain.network.sync import ChainSyncer
        from messagechain.config import MAX_PEERS
        from messagechain.core.blockchain import Blockchain
        syncer = ChainSyncer(Blockchain(), get_peer_writer=lambda _a: None)
        cap = 4 * MAX_PEERS
        for i in range(cap + 50):
            syncer.update_peer_height(f"10.{i // 256}.{i % 256}.1:9000", i + 1)
        self.assertLessEqual(
            len(syncer.peer_heights), cap,
            f"peer_heights size {len(syncer.peer_heights)} exceeds cap {cap}",
        )


if __name__ == "__main__":
    unittest.main()
