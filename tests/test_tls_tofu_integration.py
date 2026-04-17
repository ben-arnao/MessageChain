"""Integration tests for wiring CertificatePinStore into the P2P node.

These tests verify that the previously-dormant TOFU pin store is
actually initialized on the Node and invoked during outbound P2P
connections so that a MITM presenting a different TLS certificate
on a second connection is detected.
"""

import hashlib
import os
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock

from messagechain.identity.identity import Entity
from messagechain.network.node import Node
from messagechain.network.tls import CertificatePinStore


def _fingerprint(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


def _make_entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


class TestNodePinStoreInitialized(unittest.TestCase):
    """Node must instantiate a CertificatePinStore on construction."""

    def test_pin_store_initialized_with_data_dir(self):
        """Node with data_dir has a pin_store attribute persisted under data_dir."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-a")
            node = Node(entity, port=19801, data_dir=td)
            self.assertTrue(hasattr(node, "pin_store"))
            self.assertIsInstance(node.pin_store, CertificatePinStore)

    def test_pin_store_initialized_without_data_dir(self):
        """Node without data_dir still has an in-memory pin_store."""
        entity = _make_entity(b"pin-store-b")
        node = Node(entity, port=19802)
        self.assertTrue(hasattr(node, "pin_store"))
        self.assertIsInstance(node.pin_store, CertificatePinStore)

    def test_pin_store_path_under_data_dir(self):
        """The on-disk pin store lives under data_dir when one is provided."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-c")
            node = Node(entity, port=19803, data_dir=td)
            # Pin something and save to verify the path is under data_dir
            node.pin_store.pin("1.2.3.4", 9333, "a" * 64)
            node.pin_store.save()
            expected = os.path.join(td, "peer_pins.json")
            self.assertTrue(os.path.exists(expected))


class TestFirstConnectionPinsPeer(unittest.TestCase):
    """First successful TLS handshake with a peer records a pin."""

    def test_first_outbound_connection_pins_peer(self):
        """After verify_and_pin runs once, the peer cert is stored."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-d")
            node = Node(entity, port=19804, data_dir=td)

            der = b"\x30\x82fake_cert_der_bytes_for_peer_x"
            fp = _fingerprint(der)

            ssl_obj = MagicMock(spec=ssl.SSLSocket)
            ssl_obj.getpeercert.return_value = der
            writer = MagicMock()
            writer.get_extra_info = MagicMock(return_value=ssl_obj)

            ok = node._verify_and_pin_peer_tls(writer, "10.0.0.1", 9333)
            self.assertTrue(ok)
            self.assertEqual(node.pin_store.get("10.0.0.1", 9333), fp)

    def test_non_tls_connection_is_accepted(self):
        """If the writer is not SSL-wrapped, verification is a no-op (True)."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-e")
            node = Node(entity, port=19805, data_dir=td)
            writer = MagicMock()
            writer.get_extra_info = MagicMock(return_value=None)
            ok = node._verify_and_pin_peer_tls(writer, "10.0.0.1", 9333)
            self.assertTrue(ok)
            # No pin should be recorded for a plain-TCP connection
            self.assertIsNone(node.pin_store.get("10.0.0.1", 9333))


class TestSecondConnectionWithDifferentCertRejected(unittest.TestCase):
    """A changed peer certificate on reconnect must be rejected (MITM)."""

    def test_second_connection_with_different_cert_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-f")
            node = Node(entity, port=19806, data_dir=td)

            der1 = b"\x30\x82cert_A_bytes" + b"\x00" * 80
            der2 = b"\x30\x82cert_B_bytes" + b"\xff" * 80

            # First connection: pin
            ssl1 = MagicMock(spec=ssl.SSLSocket)
            ssl1.getpeercert.return_value = der1
            w1 = MagicMock()
            w1.get_extra_info = MagicMock(return_value=ssl1)
            self.assertTrue(
                node._verify_and_pin_peer_tls(w1, "10.0.0.1", 9333)
            )

            # Second connection to same host:port with a different cert
            ssl2 = MagicMock(spec=ssl.SSLSocket)
            ssl2.getpeercert.return_value = der2
            w2 = MagicMock()
            w2.get_extra_info = MagicMock(return_value=ssl2)
            self.assertFalse(
                node._verify_and_pin_peer_tls(w2, "10.0.0.1", 9333)
            )

            # Pin must still be the ORIGINAL (never overwritten on mismatch)
            self.assertEqual(
                node.pin_store.get("10.0.0.1", 9333),
                _fingerprint(der1),
            )

    def test_same_cert_on_reconnect_accepted(self):
        """Reconnect with identical cert is accepted."""
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-g")
            node = Node(entity, port=19807, data_dir=td)

            der = b"\x30\x82same_cert_bytes" + b"\x00" * 64
            ssl_obj = MagicMock(spec=ssl.SSLSocket)
            ssl_obj.getpeercert.return_value = der
            w = MagicMock()
            w.get_extra_info = MagicMock(return_value=ssl_obj)

            self.assertTrue(node._verify_and_pin_peer_tls(w, "10.0.0.1", 9333))
            self.assertTrue(node._verify_and_pin_peer_tls(w, "10.0.0.1", 9333))


class TestPinsPersistAcrossRestart(unittest.TestCase):
    """Saved pins are reloaded when a new Node points at the same data_dir."""

    def test_pins_persist_across_restart(self):
        with tempfile.TemporaryDirectory() as td:
            entity = _make_entity(b"pin-store-h")

            # First instance — pin a peer and save
            node1 = Node(entity, port=19808, data_dir=td)
            der = b"\x30\x82persist_cert_bytes" + b"\x00" * 80
            ssl_obj = MagicMock(spec=ssl.SSLSocket)
            ssl_obj.getpeercert.return_value = der
            w = MagicMock()
            w.get_extra_info = MagicMock(return_value=ssl_obj)
            self.assertTrue(
                node1._verify_and_pin_peer_tls(w, "10.0.0.99", 9333)
            )
            # Explicit save is part of the wiring contract.  _verify_and_pin
            # should have saved on first pin; be defensive and check both paths.
            node1.pin_store.save()

            # Second instance — load from disk
            node2 = Node(entity, port=19809, data_dir=td)
            fp = _fingerprint(der)
            self.assertEqual(node2.pin_store.get("10.0.0.99", 9333), fp)


if __name__ == "__main__":
    unittest.main()
