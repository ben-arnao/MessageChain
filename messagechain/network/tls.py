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

import logging
import os
import ssl
import tempfile

from messagechain.config import P2P_TLS_ENABLED, TLS_CERT_PATH, TLS_KEY_PATH

logger = logging.getLogger(__name__)


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

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Generated self-signed TLS certificate: {cert_path}")
    except ImportError:
        # Fallback: use openssl command if cryptography is not installed
        import subprocess
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "3650", "-nodes",
            "-subj", "/CN=messagechain-node",
        ], check=True, capture_output=True)
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
