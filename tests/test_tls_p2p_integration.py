"""Integration tests for TLS plumbing into the P2P transport.

These tests verify that TLS is actually wrapped around the asyncio
TCP transport — previously the `CertificatePinStore` was wired into
`node.py`'s post-handshake verification but the actual transport
(`asyncio.open_connection`, `asyncio.start_server`) was plain TCP,
so the `ssl_object` used for TOFU verification was always None and
the TOFU fix was dormant.

Covers:
  1. Outbound connections pass an SSL context to open_connection.
  2. Inbound server passes an SSL context to start_server.
  3. The server cert/key files get created on Node startup when missing.
  4. The same cert/key are reused across Node restarts (idempotent gen).
  5. `P2P_TLS_ENABLED = False` disables TLS and reverts to plain TCP.
"""

import asyncio
import os
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import messagechain.config as cfg
import messagechain.network.node as node_mod
from messagechain.identity.identity import Entity
from messagechain.network.node import Node


def _make_entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


def _run(coro):
    """Run an async coroutine under a fresh event loop (unittest sync entry)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestServerCertGeneration(unittest.TestCase):
    """The server cert and key are created on Node construction when missing."""

    def test_server_cert_generated_if_missing(self):
        """Fresh data_dir with no cert files: Node creates them."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"cert-gen-a")
            self.assertFalse(os.path.exists(os.path.join(td, "p2p_cert.pem")))
            self.assertFalse(os.path.exists(os.path.join(td, "p2p_key.pem")))

            with patch.object(cfg, "P2P_TLS_ENABLED", True):
                node = Node(entity, port=19820, data_dir=td)

            # Node must expose the cert/key paths so start() can use them.
            self.assertTrue(hasattr(node, "_server_cert_path"))
            self.assertTrue(hasattr(node, "_server_key_path"))
            self.assertTrue(os.path.exists(node._server_cert_path))
            self.assertTrue(os.path.exists(node._server_key_path))

    def test_server_cert_preserved_across_restarts(self):
        """Two Node instances with the same data_dir reuse the same cert."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"cert-gen-b")

            with patch.object(cfg, "P2P_TLS_ENABLED", True):
                node1 = Node(entity, port=19821, data_dir=td)
                with open(node1._server_cert_path, "rb") as f:
                    cert1_bytes = f.read()
                with open(node1._server_key_path, "rb") as f:
                    key1_bytes = f.read()

                # Rebuild Node — must NOT regenerate.
                node2 = Node(entity, port=19822, data_dir=td)
                with open(node2._server_cert_path, "rb") as f:
                    cert2_bytes = f.read()
                with open(node2._server_key_path, "rb") as f:
                    key2_bytes = f.read()

            self.assertEqual(cert1_bytes, cert2_bytes,
                             "Cert must be reused across restarts")
            self.assertEqual(key1_bytes, key2_bytes,
                             "Key must be reused across restarts")


class TestOutboundConnectionUsesTLS(unittest.TestCase):
    """_connect_to_peer must pass an SSL context to asyncio.open_connection."""

    def test_outbound_connection_uses_tls(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"outbound-tls-a")
            with patch.object(cfg, "P2P_TLS_ENABLED", True):
                node = Node(entity, port=19830, data_dir=td)

                captured = {}

                async def fake_open_connection(host, port, **kwargs):
                    captured["host"] = host
                    captured["port"] = port
                    captured["ssl"] = kwargs.get("ssl")
                    # Simulate a failure after capturing so the coroutine
                    # short-circuits before touching peer state.
                    raise ConnectionRefusedError("stub")

                with patch.object(node_mod.asyncio, "open_connection",
                                  side_effect=fake_open_connection):
                    _run(node._connect_to_peer("10.0.0.50", 9333))

            self.assertIn("ssl", captured,
                          "open_connection must be called with an ssl kwarg")
            self.assertIsNotNone(captured["ssl"],
                                 "ssl kwarg must be a real SSL context when "
                                 "P2P_TLS_ENABLED=True")
            self.assertIsInstance(captured["ssl"], ssl.SSLContext)


class TestInboundServerUsesTLS(unittest.TestCase):
    """start() must pass an SSL context to asyncio.start_server."""

    def test_inbound_server_uses_tls(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"inbound-tls-a")

            with patch.object(cfg, "P2P_TLS_ENABLED", True):
                node = Node(entity, port=19840, data_dir=td)

                captured = {}

                async def fake_start_server(handler, host, port, **kwargs):
                    captured["host"] = host
                    captured["port"] = port
                    captured["ssl"] = kwargs.get("ssl")
                    stub = MagicMock()
                    # wait_closed must be awaitable — return a completed future.
                    f = asyncio.get_event_loop().create_future()
                    f.set_result(None)
                    stub.wait_closed = MagicMock(return_value=f)
                    return stub

                async def run():
                    with patch.object(node_mod.asyncio, "start_server",
                                      side_effect=fake_start_server):
                        # We only care about the start_server call; stop the
                        # node immediately after start() to avoid spinning up
                        # background loops that expect real peers.
                        node._running = False  # keep loops short-circuited
                        # Pre-create a genesis so start() doesn't do chain work
                        try:
                            await node.start()
                        finally:
                            node._running = False
                            if node._server is not None:
                                try:
                                    node._server.close()
                                except Exception:
                                    pass

                _run(run())

            self.assertIn("ssl", captured,
                          "start_server must be called with an ssl kwarg")
            self.assertIsNotNone(captured["ssl"],
                                 "ssl kwarg must be a real SSL context when "
                                 "P2P_TLS_ENABLED=True")
            self.assertIsInstance(captured["ssl"], ssl.SSLContext)


class TestTLSDisabledUsesPlainTCP(unittest.TestCase):
    """P2P_TLS_ENABLED=False must revert to plain TCP (regression guard)."""

    def test_outbound_plain_tcp_when_tls_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"no-tls-out")
            with patch.object(cfg, "P2P_TLS_ENABLED", False):
                node = Node(entity, port=19850, data_dir=td)

                captured = {}

                async def fake_open_connection(host, port, **kwargs):
                    captured["ssl"] = kwargs.get("ssl")
                    raise ConnectionRefusedError("stub")

                with patch.object(node_mod.asyncio, "open_connection",
                                  side_effect=fake_open_connection):
                    _run(node._connect_to_peer("10.0.0.51", 9333))

            # Either no ssl kwarg passed, or explicitly None — both are plain TCP.
            self.assertIsNone(captured.get("ssl"),
                              "With TLS disabled, outbound connections must "
                              "not carry an SSL context")

    def test_inbound_plain_tcp_when_tls_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"no-tls-in")

            with patch.object(cfg, "P2P_TLS_ENABLED", False):
                node = Node(entity, port=19851, data_dir=td)

                captured = {}

                async def fake_start_server(handler, host, port, **kwargs):
                    captured["ssl"] = kwargs.get("ssl")
                    stub = MagicMock()
                    f = asyncio.get_event_loop().create_future()
                    f.set_result(None)
                    stub.wait_closed = MagicMock(return_value=f)
                    return stub

                async def run():
                    with patch.object(node_mod.asyncio, "start_server",
                                      side_effect=fake_start_server):
                        node._running = False
                        try:
                            await node.start()
                        finally:
                            node._running = False
                            if node._server is not None:
                                try:
                                    node._server.close()
                                except Exception:
                                    pass

                _run(run())

            self.assertIsNone(captured.get("ssl"),
                              "With TLS disabled, the listening server must "
                              "not carry an SSL context")


class TestSslObjectReachesVerifyPeerCertificate(unittest.TestCase):
    """When TLS is plumbed, writer.get_extra_info('ssl_object') must be non-None.

    Documents the contract: once the transport is SSL-wrapped, the
    existing `_verify_and_pin_peer_tls` helper — which is already
    wired after the connect in `_connect_to_peer` — will have a real
    ssl_object to inspect (not the dormant None it saw before this
    fix).  We assert the end-to-end shape: when get_extra_info
    returns an ssl_object, the TOFU helper runs and returns True
    (first-seen) / False (mismatch).
    """

    def test_verify_and_pin_runs_when_ssl_object_present(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"ssl-obj-a")
            node = Node(entity, port=19860, data_dir=td)

            der = b"\x30\x82" + b"\x01" * 100
            ssl_obj = MagicMock(spec=ssl.SSLSocket)
            ssl_obj.getpeercert.return_value = der

            writer = MagicMock()
            writer.get_extra_info = MagicMock(return_value=ssl_obj)

            # Sanity: first connection pins the peer.
            self.assertTrue(
                node._verify_and_pin_peer_tls(writer, "10.0.0.60", 9333)
            )
            self.assertIsNotNone(node.pin_store.get("10.0.0.60", 9333))

            # Different cert — must be rejected (we actually saw the ssl_object).
            der2 = b"\x30\x82" + b"\xaa" * 100
            ssl_obj2 = MagicMock(spec=ssl.SSLSocket)
            ssl_obj2.getpeercert.return_value = der2
            writer2 = MagicMock()
            writer2.get_extra_info = MagicMock(return_value=ssl_obj2)
            self.assertFalse(
                node._verify_and_pin_peer_tls(writer2, "10.0.0.60", 9333)
            )


if __name__ == "__main__":
    unittest.main()
