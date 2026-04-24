"""Raise PEER_READ_TIMEOUT + evict ghost peers on handler exit.

Live-mainnet observation (2026-04-24): v1 accumulated 19 inbound Peer
objects for the same v2 IP, all with is_connected=False.  Root causes:

1. PEER_READ_TIMEOUT = 300s (5 min) killed v1's inbound read loop
   during the 10-min silent gap between v1-produced blocks.  v2's
   maintenance loop redialed 30s later; repeat every 10 min for
   hours.  TCP keepalive (~2 min dead-detection) already handles the
   only job that a short idle read-timeout ever did — detecting dead
   sockets — so the read-timeout's only remaining purpose is slow-
   loris defense, which 30 min satisfies fine.

2. Neither the inbound handler's finally nor the outbound
   _connect_to_peer finally removed the Peer from self.peers on exit.
   The entry just got its is_connected flipped to False and lingered
   forever.  Over N reconnects, self.peers grew unboundedly.

These tests lock in the fixes.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import messagechain.config as cfg


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _mk_server(data_dir: str, seed_nodes=None):
    import server as server_mod
    s = server_mod.Server(
        p2p_port=29890, rpc_port=29891, seed_nodes=seed_nodes or [],
        data_dir=data_dir,
    )
    return s


class TestPeerReadTimeoutSurvivesBlockGap(unittest.TestCase):
    """PEER_READ_TIMEOUT must be long enough that the inbound read
    loop does NOT time out during the silent gap between block
    productions on a small network.  Block cadence is ~10 min
    (BLOCK_TIME); the timeout must comfortably exceed it."""

    def test_peer_read_timeout_exceeds_block_interval(self):
        # BLOCK_TIME default (or derived) should be <= PEER_READ_TIMEOUT.
        # We pick the larger of BLOCK_TIME and 600s as the floor,
        # because block-time constants can shift per fork.
        block_time = int(getattr(cfg, "BLOCK_TIME", 600) or 600)
        self.assertGreaterEqual(
            cfg.PEER_READ_TIMEOUT, block_time * 2,
            f"PEER_READ_TIMEOUT ({cfg.PEER_READ_TIMEOUT}s) must be at "
            f"least 2x the block interval ({block_time}s), otherwise "
            f"the inbound read loop kills the connection every "
            f"~block_interval of silence on small networks",
        )


class TestInboundHandlerEvictsPeerOnExit(unittest.TestCase):
    """When _handle_p2p_connection exits (read loop break, timeout,
    exception), the Peer entry MUST be removed from self.peers.
    Without this, reconnects from the same remote on a fresh
    ephemeral port leave zombie entries — v1 grew to 19 dead entries
    over 4 hours of v2 churn on mainnet."""

    def test_peer_removed_from_self_peers_on_handler_exit(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            # Pre-load self.peers with a sentinel to confirm specific
            # eviction (not a full clear).
            from messagechain.network.peer import Peer, ConnectionType
            keep = Peer(
                host="10.0.0.99", port=19333,
                reader=None, writer=None,
                is_connected=False,
                connection_type=ConnectionType.FULL_RELAY,
                direction="outbound",
                transport="tls",
            )
            s.peers["10.0.0.99:19333"] = keep

            reader = MagicMock()
            # Simulate a handshake followed by a clean close.
            state = {"step": 0}

            async def _read(n):
                raise asyncio.IncompleteReadError(partial=b"", expected=n)

            async def _read_msg(reader):
                state["step"] += 1
                if state["step"] == 1:
                    # Minimal HANDSHAKE-ish to land a peer in self.peers
                    # so we can then observe its eviction.
                    return None
                return None

            writer = MagicMock()
            writer.close = MagicMock()
            writer.get_extra_info = lambda key: {
                "peername": ("10.0.0.50", 42000),
                "socket": MagicMock(),
                "ssl_object": None,
            }.get(key)

            async def drive():
                # Pre-insert the inbound peer keyed by its address, as
                # the HANDSHAKE handler would do on a real run.
                s.peers["10.0.0.50:42000"] = Peer(
                    host="10.0.0.50", port=42000,
                    reader=reader, writer=writer,
                    is_connected=True,
                    connection_type=ConnectionType.FULL_RELAY,
                    direction="inbound",
                    transport="tls",
                )
                with patch("server.read_message",
                           new=AsyncMock(return_value=None)):
                    await s._handle_p2p_connection(reader, writer)

            _run(drive())

            self.assertNotIn(
                "10.0.0.50:42000", s.peers,
                "inbound peer entry must be removed from self.peers "
                "when the handler exits; otherwise reconnects from "
                "the same remote accumulate as zombie entries",
            )
            self.assertIn(
                "10.0.0.99:19333", s.peers,
                "eviction must be targeted — unrelated peer entries "
                "must NOT be cleared",
            )


class TestOutboundConnectEvictsPeerOnExit(unittest.TestCase):
    """Symmetric to the inbound case: when _connect_to_peer's read
    loop exits, the outbound Peer entry must be removed from
    self.peers, not just flipped to is_connected=False."""

    def test_outbound_peer_removed_on_exit(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            async def fake_open_connection(host, port, **kwargs):
                reader = MagicMock()
                writer = MagicMock()
                writer.close = MagicMock()
                writer.get_extra_info = lambda key: None
                writer.write = MagicMock()
                writer.drain = AsyncMock()
                return reader, writer

            async def drive():
                with patch("asyncio.open_connection",
                           side_effect=fake_open_connection), \
                     patch("server.read_message",
                           new=AsyncMock(return_value=None)), \
                     patch("server.write_message",
                           new=AsyncMock()), \
                     patch.object(cfg, "P2P_TLS_ENABLED", False):
                    await s._connect_to_peer("10.0.0.77", 19333)

            _run(drive())

            self.assertNotIn(
                "10.0.0.77:19333", s.peers,
                "outbound peer entry must be removed from self.peers "
                "after the read loop exits",
            )


if __name__ == "__main__":
    unittest.main()
