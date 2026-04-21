"""server.py P2P TLS integration.

Pre-launch audit finding: server.py (the runtime the live validator
actually runs — per the systemd unit) started its P2P listener with
`asyncio.start_server(..., "0.0.0.0", port)` and outbound peers with
plain `asyncio.open_connection(host, port)`.  No `ssl=` kwarg either
way.  Meanwhile config.P2P_TLS_ENABLED is True and
messagechain/network/node.py has full TLS wiring.  The config's
promise of TLS was being silently broken on live mainnet.

This test forces the start_server / open_connection calls to record
whether an SSLContext was passed, without opening real sockets.

Paired fix in server.py mirrors node.py: cert path under data_dir,
lazy self-signed cert gen, create_node_ssl_context / create_client
_ssl_context on the P2P paths, transport="tls" stamped on Peer.
"""

from __future__ import annotations

import asyncio
import os
import ssl
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


def _mk_server(data_dir: str):
    """Construct a Server on a real temp data_dir (cheap — SQLite init)."""
    import server as server_mod
    s = server_mod.Server(
        p2p_port=29840, rpc_port=29841, seed_nodes=[],
        data_dir=data_dir,
    )
    return s


class TestServerP2PListenerUsesTLS(unittest.TestCase):
    """start_server for P2P must be called with an ssl kwarg when
    P2P_TLS_ENABLED is True."""

    def test_p2p_listener_tls_enabled(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)

            captured_ssl = {}

            async def fake_start_server(handler, host, port, **kwargs):
                # start_server is called TWICE (P2P + RPC). Tag by port.
                captured_ssl[port] = kwargs.get("ssl")
                srv = MagicMock()
                async def _close():
                    return None
                srv.close = MagicMock()
                srv.wait_closed = AsyncMock()
                srv.serve_forever = AsyncMock()
                return srv

            async def drive():
                with patch("asyncio.start_server", side_effect=fake_start_server), \
                     patch.object(cfg, "P2P_TLS_ENABLED", True), \
                     patch.object(s, "_sync_validators_from_chain"), \
                     patch.object(s, "_block_production_loop",
                                  new=AsyncMock(return_value=None)), \
                     patch.object(s, "_handle_task_exception"), \
                     patch.object(s, "anchor_store") as anchors:
                    anchors.load_anchors.return_value = []
                    # Short-circuit the seed-loop by emptying it:
                    s.seed_nodes = []
                    await s.start()
                    s._running = False

            _run(drive())
            self.assertIn(s.p2p_port, captured_ssl)
            self.assertIsNotNone(
                captured_ssl[s.p2p_port],
                "P2P listener must be bound with an SSL context when "
                "P2P_TLS_ENABLED=True",
            )
            self.assertIsInstance(captured_ssl[s.p2p_port], ssl.SSLContext)
            # RPC listener stays plain (operator-controlled bind; auth is
            # token-based not TLS-based in today's design).  Only asserting
            # P2P here.

    def test_p2p_listener_tls_disabled(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            captured_ssl = {}

            async def fake_start_server(handler, host, port, **kwargs):
                captured_ssl[port] = kwargs.get("ssl")
                srv = MagicMock()
                srv.close = MagicMock()
                srv.wait_closed = AsyncMock()
                srv.serve_forever = AsyncMock()
                return srv

            async def drive():
                with patch("asyncio.start_server", side_effect=fake_start_server), \
                     patch.object(cfg, "P2P_TLS_ENABLED", False), \
                     patch.object(s, "_sync_validators_from_chain"), \
                     patch.object(s, "_block_production_loop",
                                  new=AsyncMock(return_value=None)), \
                     patch.object(s, "_handle_task_exception"), \
                     patch.object(s, "anchor_store") as anchors:
                    anchors.load_anchors.return_value = []
                    s.seed_nodes = []
                    await s.start()
                    s._running = False

            _run(drive())
            self.assertIn(s.p2p_port, captured_ssl)
            self.assertIsNone(
                captured_ssl[s.p2p_port],
                "P2P listener must be plain TCP when P2P_TLS_ENABLED=False",
            )


class TestServerOutboundConnectUsesTLS(unittest.TestCase):
    """_connect_to_peer must pass an SSL context to open_connection
    when TLS is enabled, and stamp transport='tls' on the Peer."""

    def test_outbound_connect_tls_enabled_sets_transport(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            s = _mk_server(td)
            captured_kwargs = {}

            async def fake_open_connection(host, port, **kwargs):
                captured_kwargs["ssl"] = kwargs.get("ssl")
                # Return (reader, writer) doubles that cleanly exit the
                # post-handshake loop.
                reader = MagicMock()
                reader.read = AsyncMock(return_value=b"")
                writer = MagicMock()
                writer.close = MagicMock()
                # get_extra_info emulates a TLS-wrapped socket when ssl
                # is present, plain otherwise.
                def extra(key):
                    if key == "ssl_object":
                        return MagicMock() if captured_kwargs["ssl"] else None
                    return None
                writer.get_extra_info = extra
                writer.write = MagicMock()
                writer.drain = AsyncMock()
                return reader, writer

            async def drive():
                # Don't patch asyncio.wait_for — it unwraps coroutines
                # fine for real, and the fake returns instantly.
                with patch("asyncio.open_connection",
                           side_effect=fake_open_connection), \
                     patch.object(cfg, "P2P_TLS_ENABLED", True), \
                     patch("server.read_message",
                           new=AsyncMock(return_value=None)), \
                     patch("server.write_message",
                           new=AsyncMock()):
                    await s._connect_to_peer("10.0.0.5", 19333)

            _run(drive())
            self.assertIsNotNone(
                captured_kwargs.get("ssl"),
                "Outbound connection must pass an ssl context when "
                "P2P_TLS_ENABLED=True",
            )
            peer = s.peers.get("10.0.0.5:19333")
            self.assertIsNotNone(peer, "Peer should have been added")
            self.assertEqual(
                getattr(peer, "transport", None), "tls",
                "Peer transport must be 'tls' when TLS is enabled",
            )


if __name__ == "__main__":
    unittest.main()
