"""P2P liveness fixes — ghost-peer cleanup, TCP keepalive, maintenance loop.

Motivated by a live mainnet observation (2026-04-24): validator-2's
`get_peers` RPC reported an outbound connection to validator-1 that had
been "connected" for 24 minutes, while `ss` on both hosts showed no
actual TCP socket on port 9333.  Three root causes:

1. `Server._connect_to_peer` has no `finally` block, so when the
   post-handshake read loop exits (via break / timeout / None), the
   Peer object stays in `self.peers` with `is_connected=True` forever.
   This (a) misleads observability and (b) blocks reconnect attempts,
   because the one-shot guard checks `self.peers[addr].is_connected`.

2. Neither inbound nor outbound sockets enable SO_KEEPALIVE, so a GCP
   VPC cross-zone NAT/firewall silently drops idle flows (no RST) and
   both sides happily wait forever on `readexactly`.

3. Seeds are connected once at startup with no maintenance loop, so a
   dropped connection is never retried — a two-node network degrades
   to two solo chains.

These tests lock in the fixes.
"""

from __future__ import annotations

import asyncio
import socket
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
        p2p_port=29870, rpc_port=29871, seed_nodes=seed_nodes or [],
        data_dir=data_dir,
    )
    return s


class TestOutboundConnectMarksDisconnectedOnExit(unittest.TestCase):
    """Ghost-peer fix: when `_connect_to_peer`'s read loop exits, the
    Peer object left in `self.peers` must have `is_connected=False`.
    Observability callers (get_peers RPC) and the seed-reconnect guard
    (`if addr in self.peers and self.peers[addr].is_connected`) both
    depend on this flag being honest."""

    def test_is_connected_cleared_after_read_loop_exit(self):
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
                # read_message returns None on first call -> loop breaks
                # immediately after HANDSHAKE send.  Without the finally
                # block, is_connected stays True.
                with patch("asyncio.open_connection",
                           side_effect=fake_open_connection), \
                     patch("server.read_message",
                           new=AsyncMock(return_value=None)), \
                     patch("server.write_message",
                           new=AsyncMock()), \
                     patch.object(cfg, "P2P_TLS_ENABLED", False):
                    await s._connect_to_peer("10.0.0.99", 19333)

            _run(drive())
            peer = s.peers.get("10.0.0.99:19333")
            self.assertIsNotNone(peer, "peer should linger for churn visibility")
            self.assertFalse(
                peer.is_connected,
                "is_connected must be False after the read loop exits, "
                "otherwise the seed-reconnect guard will never retry and "
                "observability is misleading",
            )


class TestOutboundConnectEnablesTcpKeepalive(unittest.TestCase):
    """Keepalive fix: on outbound connect, SO_KEEPALIVE must be set on
    the underlying socket so the OS detects silent NAT/firewall drops
    and keeps cross-zone GCP VPC flows alive."""

    def test_setsockopt_so_keepalive_called(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            fake_sock = MagicMock()

            async def fake_open_connection(host, port, **kwargs):
                reader = MagicMock()
                writer = MagicMock()
                writer.close = MagicMock()
                writer.get_extra_info = lambda key: (
                    fake_sock if key == "socket" else None
                )
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
                    await s._connect_to_peer("10.0.0.5", 19333)

            _run(drive())

            calls = fake_sock.setsockopt.call_args_list
            self.assertTrue(
                any(
                    c.args[:3] == (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    for c in calls
                ),
                f"expected SO_KEEPALIVE=1 in setsockopt calls, got {calls}",
            )


class TestInboundConnectEnablesTcpKeepalive(unittest.TestCase):
    """Keepalive fix: same for inbound — accepted sockets must also
    have SO_KEEPALIVE enabled or the server is still blind to silent
    drops on half the connections."""

    def test_inbound_setsockopt_so_keepalive_called(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            fake_sock = MagicMock()
            reader = MagicMock()
            writer = MagicMock()
            writer.close = MagicMock()
            writer.get_extra_info = lambda key: {
                "peername": ("10.0.0.6", 40000),
                "socket": fake_sock,
                "ssl_object": None,
            }.get(key)

            async def drive():
                # read_message returns None -> handler exits after the
                # first read; that's enough to prove the keepalive call
                # happened before the loop.
                with patch("server.read_message",
                           new=AsyncMock(return_value=None)):
                    await s._handle_p2p_connection(reader, writer)

            _run(drive())

            calls = fake_sock.setsockopt.call_args_list
            self.assertTrue(
                any(
                    c.args[:3] == (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    for c in calls
                ),
                f"expected SO_KEEPALIVE=1 in setsockopt calls, got {calls}",
            )


class TestPeerMaintenanceLoopReconnectsDeadSeeds(unittest.TestCase):
    """Maintenance fix: `_peer_maintenance_loop` must call
    `_connect_to_peer` for any configured seed whose tracked Peer has
    `is_connected=False` (or is missing entirely).  Without this, a
    dropped seed connection is never retried — a two-node network
    degrades to two solo chains, which is exactly what happened on
    mainnet 2026-04-24."""

    def test_reconnects_seed_with_is_connected_false(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.7", 19333)])

            # Simulate a stale peer left behind by a prior dead connection.
            from messagechain.network.peer import Peer, ConnectionType
            s.peers["10.0.0.7:19333"] = Peer(
                host="10.0.0.7", port=19333,
                reader=None, writer=None,
                is_connected=False,
                connection_type=ConnectionType.FULL_RELAY,
                direction="outbound",
                transport="tls",
            )

            reconnect_targets = []

            async def fake_connect(host, port):
                reconnect_targets.append((host, port))

            async def drive():
                # Run exactly one tick of the maintenance loop.
                with patch.object(s, "_connect_to_peer",
                                  side_effect=fake_connect):
                    await s._peer_maintenance_tick()

            _run(drive())

            self.assertIn(
                ("10.0.0.7", 19333), reconnect_targets,
                "maintenance tick must re-call _connect_to_peer on a "
                "seed whose peer entry is marked is_connected=False",
            )

    def test_does_not_reconnect_seed_that_is_still_live(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td, seed_nodes=[("10.0.0.8", 19333)])

            from messagechain.network.peer import Peer, ConnectionType
            s.peers["10.0.0.8:19333"] = Peer(
                host="10.0.0.8", port=19333,
                reader=None, writer=None,
                is_connected=True,
                connection_type=ConnectionType.FULL_RELAY,
                direction="outbound",
                transport="tls",
            )

            reconnect_targets = []

            async def fake_connect(host, port):
                reconnect_targets.append((host, port))

            async def drive():
                with patch.object(s, "_connect_to_peer",
                                  side_effect=fake_connect):
                    await s._peer_maintenance_tick()

            _run(drive())

            self.assertEqual(
                reconnect_targets, [],
                "maintenance tick must NOT hammer a seed that is already "
                "connected — one outbound per seed is enough",
            )


if __name__ == "__main__":
    unittest.main()
