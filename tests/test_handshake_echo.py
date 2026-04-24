"""Inbound-side HANDSHAKE echo so the dialer's Peer record gets populated.

Before this fix, the node that received a TCP connection read the dialer's
HANDSHAKE, updated its own Peer record (entity, height, version), and then
went silent. The dialer side therefore never received a HANDSHAKE in reply,
and its Peer entry kept `entity_id=""`, `peer_height=0`, `peer_version=""`
forever — visible as `Entity: (none)`, `Height: 0`, `Version: unknown` on
the outbound side of the `messagechain peers` CLI.

Chain sync still worked because sync_peer selection runs off the inbound
side, but the observability gap masked the state of the peer set and made
operational debugging (who's my peer? what version?) much harder.

Fix: after processing an inbound HANDSHAKE, the receiver echoes its own
HANDSHAKE back. A `Peer.handshake_sent` flag guards against double-send
(outbound path sets it when it dials; inbound echo checks it).
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from messagechain.core.block import create_genesis_block
from messagechain.identity.identity import Entity
from messagechain.network.node import Node
from messagechain.network.peer import Peer
from messagechain.network.protocol import MessageType, NetworkMessage


def _make_node(port: int = 9999, *, seed: bytes = b"\x42" * 32) -> Node:
    ent = Entity.create(seed, tree_height=4)
    return Node(ent, port=port)


def _install_genesis(node: Node, seed: bytes = b"\xAA" * 32) -> bytes:
    proposer = Entity.create(seed, tree_height=4)
    genesis = create_genesis_block(proposer)
    node.blockchain.chain.append(genesis)
    return genesis.block_hash


def _valid_handshake(sender_id_hex: str, *, genesis_hex: str = "") -> NetworkMessage:
    return NetworkMessage(
        msg_type=MessageType.HANDSHAKE,
        sender_id=sender_id_hex,
        payload={
            "port": 9333,
            "chain_height": 5,
            "best_block_hash": "ab" * 32,
            "cumulative_weight": 100,
            "genesis_hash": genesis_hex,
            "version": "9.9.9",
        },
    )


def _run(coro):
    return asyncio.run(coro)


class TestNodeHandshakeEcho(unittest.TestCase):
    """messagechain/network/node.py — Node class echoes HANDSHAKE."""

    def setUp(self):
        self.node = _make_node(9200, seed=b"\x01" * 32)
        self.our_genesis = _install_genesis(self.node)
        self.peer_entity = Entity.create(b"\x02" * 32, tree_height=4)

    def _make_inbound_peer(self) -> Peer:
        p = Peer(
            host="10.0.0.1", port=54321,
            reader=MagicMock(), writer=MagicMock(),
            is_connected=True, direction="inbound",
        )
        self.node.peers[p.address] = p
        return p

    def test_inbound_handshake_triggers_echo(self):
        """Inbound side must send a HANDSHAKE reply after processing the peer's."""
        peer = self._make_inbound_peer()
        msg = _valid_handshake(
            self.peer_entity.entity_id_hex,
            genesis_hex=self.our_genesis.hex(),
        )

        writes: list[NetworkMessage] = []

        async def fake_write(writer, m):
            writes.append(m)

        with patch(
            "messagechain.network.node.write_message",
            new=AsyncMock(side_effect=fake_write),
        ):
            _run(self.node._handle_message(msg, peer))

        handshakes = [m for m in writes if m.msg_type == MessageType.HANDSHAKE]
        self.assertEqual(
            len(handshakes), 1,
            f"expected one HANDSHAKE echo, got {len(handshakes)}",
        )
        reply = handshakes[0]
        self.assertEqual(reply.sender_id, self.node.entity.entity_id_hex)
        self.assertEqual(reply.payload["chain_height"], self.node.blockchain.height)
        self.assertEqual(reply.payload["genesis_hash"], self.our_genesis.hex())
        self.assertIn("version", reply.payload)
        self.assertTrue(peer.handshake_sent)

    def test_second_handshake_from_same_peer_does_not_re_echo(self):
        """Idempotent: a peer that sends HANDSHAKE twice doesn't get a second echo."""
        peer = self._make_inbound_peer()
        msg = _valid_handshake(
            self.peer_entity.entity_id_hex,
            genesis_hex=self.our_genesis.hex(),
        )

        writes: list[NetworkMessage] = []

        async def fake_write(writer, m):
            writes.append(m)

        with patch(
            "messagechain.network.node.write_message",
            new=AsyncMock(side_effect=fake_write),
        ):
            _run(self.node._handle_message(msg, peer))
            _run(self.node._handle_message(msg, peer))

        handshakes = [m for m in writes if m.msg_type == MessageType.HANDSHAKE]
        self.assertEqual(
            len(handshakes), 1,
            "echo must fire once per peer, not on every HANDSHAKE received",
        )

    def test_outbound_peer_does_not_echo(self):
        """Outbound peers already sent their HANDSHAKE on dial; don't echo again."""
        peer = Peer(
            host="10.0.0.2", port=9333,
            reader=MagicMock(), writer=MagicMock(),
            is_connected=True, direction="outbound",
            handshake_sent=True,
        )
        self.node.peers[peer.address] = peer
        msg = _valid_handshake(
            self.peer_entity.entity_id_hex,
            genesis_hex=self.our_genesis.hex(),
        )

        writes: list[NetworkMessage] = []

        async def fake_write(writer, m):
            writes.append(m)

        with patch(
            "messagechain.network.node.write_message",
            new=AsyncMock(side_effect=fake_write),
        ):
            _run(self.node._handle_message(msg, peer))

        handshakes = [m for m in writes if m.msg_type == MessageType.HANDSHAKE]
        self.assertEqual(
            len(handshakes), 0,
            "outbound peer's handshake_sent=True must suppress echo",
        )


class TestServerHandshakeEcho(unittest.TestCase):
    """server.py — Server class echoes HANDSHAKE on inbound side."""

    def _make_server(self, td: str):
        import server as server_mod
        return server_mod.Server(
            p2p_port=29870, rpc_port=29871, seed_nodes=[],
            data_dir=td,
        )

    def test_inbound_handshake_triggers_echo(self):
        import tempfile
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = self._make_server(td)

            peer = Peer(
                host="10.0.0.3", port=50001,
                reader=MagicMock(), writer=MagicMock(),
                is_connected=True, direction="inbound",
            )
            s.peers[peer.address] = peer

            peer_entity_id = "bb" * 16

            msg = NetworkMessage(
                msg_type=MessageType.HANDSHAKE,
                sender_id=peer_entity_id,
                payload={
                    "port": 9333,
                    "chain_height": 0,
                    "best_block_hash": "",
                    "cumulative_weight": 0,
                    "version": "9.9.9",
                },
            )

            writes: list[NetworkMessage] = []

            async def fake_write(writer, m):
                writes.append(m)

            with patch(
                "server.write_message",
                new=AsyncMock(side_effect=fake_write),
            ):
                _run(s._handle_p2p_message(msg, peer))

            handshakes = [m for m in writes if m.msg_type == MessageType.HANDSHAKE]
            self.assertEqual(
                len(handshakes), 1,
                f"expected one HANDSHAKE echo, got {len(handshakes)}",
            )
            self.assertIn("version", handshakes[0].payload)
            self.assertTrue(peer.handshake_sent)


if __name__ == "__main__":
    unittest.main()
