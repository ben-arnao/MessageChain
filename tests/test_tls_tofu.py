"""Tests for TLS TOFU (Trust On First Use) certificate pinning."""

import json
import os
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock

from messagechain.network.tls import (
    CertificatePinStore,
    verify_peer_certificate,
    create_client_ssl_context,
)


class TestCertificatePinStore(unittest.TestCase):
    """Test CertificatePinStore stores and retrieves fingerprints."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pin_path = os.path.join(self.tmpdir, "pins.json")
        self.store = CertificatePinStore(self.pin_path)

    def tearDown(self):
        if os.path.exists(self.pin_path):
            os.remove(self.pin_path)
        os.rmdir(self.tmpdir)

    def test_store_and_retrieve_fingerprint(self):
        """Pin store can store and retrieve a fingerprint for a peer."""
        fp = "abcd1234" * 8  # 64 hex chars = SHA-256
        self.store.pin("10.0.0.1", 9333, fp)
        self.assertEqual(self.store.get("10.0.0.1", 9333), fp)

    def test_unknown_peer_returns_none(self):
        """Getting a fingerprint for an unknown peer returns None."""
        self.assertIsNone(self.store.get("10.0.0.1", 9333))

    def test_first_connection_accepted_and_pinned(self):
        """First connection to unknown peer: pin returns True, stores fp."""
        fp = "abcd1234" * 8
        result = self.store.check_or_pin("10.0.0.1", 9333, fp)
        self.assertTrue(result)
        self.assertEqual(self.store.get("10.0.0.1", 9333), fp)

    def test_same_cert_accepted(self):
        """Subsequent connection with same cert fingerprint is accepted."""
        fp = "abcd1234" * 8
        self.store.pin("10.0.0.1", 9333, fp)
        result = self.store.check_or_pin("10.0.0.1", 9333, fp)
        self.assertTrue(result)

    def test_different_cert_rejected(self):
        """Connection with different cert fingerprint is rejected (MITM)."""
        fp1 = "abcd1234" * 8
        fp2 = "deadbeef" * 8
        self.store.pin("10.0.0.1", 9333, fp1)
        result = self.store.check_or_pin("10.0.0.1", 9333, fp2)
        self.assertFalse(result)

    def test_clear_pin(self):
        """Clearing a pin removes it, allowing a new cert to be pinned."""
        fp1 = "abcd1234" * 8
        fp2 = "deadbeef" * 8
        self.store.pin("10.0.0.1", 9333, fp1)
        self.store.clear_pin("10.0.0.1", 9333)
        self.assertIsNone(self.store.get("10.0.0.1", 9333))
        # New cert can now be pinned
        result = self.store.check_or_pin("10.0.0.1", 9333, fp2)
        self.assertTrue(result)
        self.assertEqual(self.store.get("10.0.0.1", 9333), fp2)

    def test_persistence_save_and_load(self):
        """Pin store persists to JSON file and loads back correctly."""
        fp = "abcd1234" * 8
        self.store.pin("10.0.0.1", 9333, fp)
        self.store.save()

        # Load into a new store instance
        store2 = CertificatePinStore(self.pin_path)
        store2.load()
        self.assertEqual(store2.get("10.0.0.1", 9333), fp)

    def test_persistence_file_missing_loads_empty(self):
        """Loading from a non-existent file results in empty store."""
        store = CertificatePinStore("/nonexistent/path/pins.json")
        store.load()  # should not raise
        self.assertIsNone(store.get("10.0.0.1", 9333))

    def test_multiple_peers(self):
        """Store handles multiple peers independently."""
        fp_a = "aaaa1111" * 8
        fp_b = "bbbb2222" * 8
        self.store.pin("10.0.0.1", 9333, fp_a)
        self.store.pin("10.0.0.2", 9333, fp_b)
        self.assertEqual(self.store.get("10.0.0.1", 9333), fp_a)
        self.assertEqual(self.store.get("10.0.0.2", 9333), fp_b)


class TestVerifyPeerCertificate(unittest.TestCase):
    """Test the verify_peer_certificate helper function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.pin_path = os.path.join(self.tmpdir, "pins.json")
        self.store = CertificatePinStore(self.pin_path)

    def tearDown(self):
        if os.path.exists(self.pin_path):
            os.remove(self.pin_path)
        os.rmdir(self.tmpdir)

    def _make_mock_socket(self, der_bytes: bytes):
        """Create a mock SSL socket that returns the given DER cert."""
        sock = MagicMock(spec=ssl.SSLSocket)
        sock.getpeercert.return_value = der_bytes
        return sock

    def test_first_seen_cert_is_accepted_and_pinned(self):
        """First connection pins the cert and returns True."""
        der = b"\x30\x82" + b"\x00" * 100  # fake DER
        sock = self._make_mock_socket(der)
        result = verify_peer_certificate(sock, "10.0.0.1", 9333, self.store)
        self.assertTrue(result)
        # Fingerprint should now be stored
        self.assertIsNotNone(self.store.get("10.0.0.1", 9333))

    def test_same_cert_accepted(self):
        """Same cert on reconnect returns True."""
        der = b"\x30\x82" + b"\x00" * 100
        sock = self._make_mock_socket(der)
        # First connection
        verify_peer_certificate(sock, "10.0.0.1", 9333, self.store)
        # Second connection with same cert
        result = verify_peer_certificate(sock, "10.0.0.1", 9333, self.store)
        self.assertTrue(result)

    def test_different_cert_rejected(self):
        """Different cert on reconnect returns False (possible MITM)."""
        der1 = b"\x30\x82" + b"\x00" * 100
        der2 = b"\x30\x82" + b"\xff" * 100
        sock1 = self._make_mock_socket(der1)
        sock2 = self._make_mock_socket(der2)
        # First connection
        verify_peer_certificate(sock1, "10.0.0.1", 9333, self.store)
        # Second connection with different cert
        result = verify_peer_certificate(sock2, "10.0.0.1", 9333, self.store)
        self.assertFalse(result)

    def test_no_cert_returns_false(self):
        """If peer provides no certificate, return False."""
        sock = MagicMock(spec=ssl.SSLSocket)
        sock.getpeercert.return_value = None
        result = verify_peer_certificate(sock, "10.0.0.1", 9333, self.store)
        self.assertFalse(result)


class TestExistingClientContext(unittest.TestCase):
    """Ensure the existing create_client_ssl_context still works."""

    def test_client_context_still_works(self):
        """create_client_ssl_context returns a valid SSL context."""
        ctx = create_client_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main()
