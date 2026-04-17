"""
TLS support for MessageChain P2P connections.

Provides encrypted transport using self-signed certificates.  Blockchain
identity is independent of TLS identity — we only use TLS for confidentiality
and integrity of the P2P transport, not for authentication (the handshake
signature handles that).

On first run the node generates a self-signed Ed25519/RSA certificate and
stores it alongside the chain data.  Peers accept any certificate (no CA
verification) because the goal is encryption, not PKI-based trust.
"""

import hashlib
import json
import logging
import os
import ssl
import tempfile

from messagechain.config import P2P_TLS_ENABLED, TLS_CERT_PATH, TLS_KEY_PATH

logger = logging.getLogger(__name__)


class CertificatePinStore:
    """TOFU (Trust On First Use) certificate pin store.

    Stores SHA-256 fingerprints of peer TLS certificates keyed by
    (host, port).  On first connection to a peer, records their
    certificate fingerprint.  On subsequent connections, verifies
    the fingerprint matches — a mismatch signals a possible MITM.

    Pins are persisted to a JSON file so they survive restarts.
    """

    def __init__(self, path: str | None = None):
        self._path = path
        self._pins: dict[str, str] = {}  # "host:port" -> hex fingerprint
        if path and os.path.exists(path):
            self.load()

    @staticmethod
    def _key(host: str, port: int) -> str:
        return f"{host}:{port}"

    def pin(self, host: str, port: int, fingerprint: str) -> None:
        """Store a fingerprint for a peer."""
        self._pins[self._key(host, port)] = fingerprint

    def get(self, host: str, port: int) -> str | None:
        """Retrieve the stored fingerprint for a peer, or None."""
        return self._pins.get(self._key(host, port))

    def check_or_pin(self, host: str, port: int, fingerprint: str) -> bool:
        """Check fingerprint against stored pin, or pin if first-seen.

        Returns True if the peer is trusted (first-seen or matching pin).
        Returns False if the fingerprint differs from the stored pin
        (possible MITM).
        """
        existing = self.get(host, port)
        if existing is None:
            # First connection — trust and pin
            self.pin(host, port, fingerprint)
            return True
        return existing == fingerprint

    def clear_pin(self, host: str, port: int) -> None:
        """Remove a pin (for legitimate certificate rotation)."""
        key = self._key(host, port)
        self._pins.pop(key, None)

    def save(self) -> None:
        """Persist pins to the JSON file."""
        if self._path is None:
            return
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._pins, f)

    def load(self) -> None:
        """Load pins from the JSON file."""
        if self._path is None or not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r") as f:
                self._pins = json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load certificate pin store; starting fresh")
            self._pins = {}


def _cert_fingerprint(der_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of a DER-encoded certificate."""
    return hashlib.sha256(der_bytes).hexdigest()


def verify_peer_certificate(
    ssl_socket: ssl.SSLSocket,
    host: str,
    port: int,
    pin_store: CertificatePinStore,
) -> bool:
    """Verify a peer's TLS certificate against the TOFU pin store.

    Call this after the TLS handshake completes.  Gets the peer's
    DER-encoded certificate, computes its SHA-256 fingerprint, and
    checks it against the pin store.

    Returns True if first-seen (pins it) or if fingerprint matches.
    Returns False if fingerprint changed (possible MITM) or if no
    certificate was presented.
    """
    der_cert = ssl_socket.getpeercert(binary_form=True)
    if der_cert is None:
        return False
    fingerprint = _cert_fingerprint(der_cert)
    return pin_store.check_or_pin(host, port, fingerprint)


def _generate_self_signed_cert(cert_path: str, key_path: str):
    """Generate a self-signed certificate for P2P TLS.

    Uses the cryptography library if available, otherwise falls back to
    a pre-generated ephemeral pair using the ssl module's defaults.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        # M15: Use 4096-bit RSA for the 1000-year design goal
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "messagechain-node"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        # M14: Restrict private key file permissions
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass  # best-effort on platforms that don't support chmod
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Generated self-signed TLS certificate: {cert_path}")
    except ImportError:
        # Fallback: use openssl command if cryptography is not installed
        import subprocess
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_path, "-out", cert_path,
            "-days", "3650", "-nodes",
            "-subj", "/CN=messagechain-node",
        ], check=True, capture_output=True)
        # M14: Restrict private key file permissions
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        logger.info(f"Generated self-signed TLS certificate via openssl: {cert_path}")


def create_node_ssl_context(
    cert_path: str | None = None,
    key_path: str | None = None,
    data_dir: str | None = None,
) -> ssl.SSLContext:
    """Create an SSL context for the P2P server (accept connections).

    If cert/key files don't exist, generates a self-signed pair.
    """
    if cert_path is None:
        base = data_dir or tempfile.gettempdir()
        cert_path = os.path.join(base, "node_cert.pem")
        key_path = os.path.join(base, "node_key.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        _generate_self_signed_cert(cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    # Require TLS 1.2+ for modern security
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def create_client_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for outbound P2P connections.

    Does NOT verify the server certificate — we only use TLS for
    encryption, not PKI-based authentication.  Blockchain-level
    identity verification happens via signed handshakes.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
