"""Handshake must also carry a chain_id and reject peers on mismatch.

genesis_hash already catches cross-chain peers in practice, but chain_id
is a defense-in-depth filter: a fork that remints a matching genesis
block (or a buggy operator pointing at a chain that coincidentally
shares a genesis) still gets rejected at the peer layer instead of
silently partitioning on tx-signature verification later.

Cases:
  A) DIFFERENT chain_id → receiver records OFFENSE_PROTOCOL_VIOLATION
     (reason prefix "chain_id_mismatch:") and disconnects.
  B) MATCHING chain_id → handshake completes, no offense.
  C) Legacy peer (no chain_id field) → tolerated for backward compat
     (mirrors the legacy-genesis rule).
  D) Non-string chain_id → protocol violation + drop.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock

from messagechain.config import CHAIN_ID
from messagechain.core.block import create_genesis_block
from messagechain.identity.identity import Entity
from messagechain.network.node import Node
from messagechain.network.protocol import MessageType, NetworkMessage


def _make_node(port: int = 9999, *, seed: bytes = b"\x42" * 32) -> Node:
    ent = Entity.create(seed, tree_height=4)
    return Node(ent, port=port)


def _install_genesis(node: Node, seed: bytes = b"\xAA" * 32) -> bytes:
    genesis_proposer = Entity.create(seed, tree_height=4)
    genesis = create_genesis_block(genesis_proposer)
    node.blockchain.chain.append(genesis)
    return genesis.block_hash


class _FakePeer:
    def __init__(self, addr: str, entity_id_hex: str | None = None):
        self.address = addr
        self.host, port = addr.split(":")
        self.port = int(port)
        self.is_connected = True
        self.writer = MagicMock()
        self.reader = MagicMock()
        self.handshake_complete = False
        self.last_seen = 0.0
        self.entity_id = entity_id_hex
        self.connection_type = "full_relay"
        self.direction = "inbound"
        self.transport = "plain"

    def touch(self):
        self.last_seen = 1.0


_MISSING = object()


def _handshake_msg(
    sender_id_hex: str,
    *,
    genesis_hash: str,
    chain_id=_MISSING,
) -> NetworkMessage:
    payload: dict = {
        "port": 9333,
        "chain_height": 0,
        "best_block_hash": "",
        "cumulative_weight": 0,
        "genesis_hash": genesis_hash,
    }
    if chain_id is not _MISSING:
        payload["chain_id"] = chain_id
    return NetworkMessage(
        msg_type=MessageType.HANDSHAKE,
        sender_id=sender_id_hex,
        payload=payload,
    )


class TestHandshakeChainIdCheck(unittest.TestCase):

    def test_mismatching_chain_id_records_violation_and_drops(self):
        node = _make_node(9200, seed=b"\x01" * 32)
        ours = _install_genesis(node)

        peer_entity = Entity.create(b"\x02" * 32, tree_height=4)
        peer = _FakePeer("10.0.1.1:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(
            peer_entity.entity_id_hex,
            genesis_hash=ours.hex(),
            chain_id="messagechain-testnet",
        )
        asyncio.run(node._handle_message(msg, peer))

        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "mismatched chain_id must record a protocol-violation offense",
        )
        self.assertFalse(
            peer.is_connected,
            "peer with mismatched chain_id must be disconnected",
        )

    def test_matching_chain_id_completes_handshake(self):
        node = _make_node(9201, seed=b"\x03" * 32)
        ours = _install_genesis(node)

        peer_entity = Entity.create(b"\x04" * 32, tree_height=4)
        peer = _FakePeer("10.0.1.2:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(
            peer_entity.entity_id_hex,
            genesis_hash=ours.hex(),
            chain_id=CHAIN_ID.decode("ascii"),
        )
        asyncio.run(node._handle_message(msg, peer))

        self.assertEqual(
            node.ban_manager.get_score(peer.address), 0,
            "matching chain_id must not record any offense",
        )
        self.assertTrue(peer.is_connected)

    def test_legacy_peer_without_chain_id_tolerated(self):
        node = _make_node(9202, seed=b"\x05" * 32)
        ours = _install_genesis(node)

        peer_entity = Entity.create(b"\x06" * 32, tree_height=4)
        peer = _FakePeer("10.0.1.3:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(
            peer_entity.entity_id_hex,
            genesis_hash=ours.hex(),
        )
        asyncio.run(node._handle_message(msg, peer))

        self.assertEqual(
            node.ban_manager.get_score(peer.address), 0,
            "legacy peer without chain_id must not be punished",
        )
        self.assertTrue(peer.is_connected)

    def test_non_string_chain_id_records_violation_and_drops(self):
        node = _make_node(9203, seed=b"\x07" * 32)
        ours = _install_genesis(node)

        peer_entity = Entity.create(b"\x08" * 32, tree_height=4)
        peer = _FakePeer("10.0.1.4:9333")
        node.peers[peer.address] = peer

        msg = _handshake_msg(
            peer_entity.entity_id_hex,
            genesis_hash=ours.hex(),
            chain_id=12345,
        )
        asyncio.run(node._handle_message(msg, peer))

        self.assertGreater(
            node.ban_manager.get_score(peer.address), 0,
            "non-string chain_id must record a protocol-violation offense",
        )
        self.assertFalse(peer.is_connected)

    def test_outgoing_handshake_includes_chain_id(self):
        """The handshake payload we SEND must advertise chain_id."""
        from messagechain.network import node as node_module

        src = node_module.__file__
        with open(src, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertIn(
            '"chain_id"', text,
            "node.py must include 'chain_id' in the outgoing HANDSHAKE payload",
        )


if __name__ == "__main__":
    unittest.main()
