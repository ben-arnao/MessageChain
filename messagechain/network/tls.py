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
    certificate fingerprint AND — when supplied — the blockchain
    entity_id the peer declared in its application-layer handshake.
    On subsequent connections, verifies both the fingerprint AND the
    declared entity_id match the pinned pair — a mismatch on either
    signals possible MITM *or* impersonation (one peer pinning a
    legitimate-looking cert and later using it to impersonate another
    entity at the same address).

    Pins are persisted to a JSON file so they survive restarts.
    """

    def __init__(self, path: str | None = None):
        self._path = path
        # "host:port" -> {"fp": hex_fingerprint, "eid": entity_id_hex_or_None}
        self._pins: dict[str, dict] = {}
        if path and os.path.exists(path):
            self.load()

    @staticmethod
    def _key(host: str, port: int) -> str:
        return f"{host}:{port}"

    def pin(
        self, host: str, port: int, fingerprint: str,
        entity_id: bytes | None = None,
    ) -> None:
        """Store a (fingerprint, entity_id) pair for a peer."""
        entry = {"fp": fingerprint}
        if entity_id is not None:
            entry["eid"] = entity_id.hex()
        self._pins[self._key(host, port)] = entry

    def get(self, host: str, port: int) -> str | None:
        """Retrieve the stored fingerprint for a peer, or None."""
        entry = self._pins.get(self._key(host, port))
        if entry is None:
            return None
        return entry.get("fp")

    def get_entity(self, host: str, port: int) -> bytes | None:
        """Retrieve the stored entity_id bound to the pinned cert, or None."""
        entry = self._pins.get(self._key(host, port))
        if entry is None:
            return None
        eid_hex = entry.get("eid")
        if not eid_hex:
            return None
        try:
            return bytes.fromhex(eid_hex)
        except ValueError:
            return None

    def check_or_pin(
        self, host: str, port: int, fingerprint: str,
        entity_id: bytes | None = None,
    ) -> bool:
        """Check (fingerprint, entity_id) against pin, or pin if first-seen.

        Returns True if the peer is trusted:
          - first-seen (we pin the pair), or
          - fingerprint matches the pin AND either (a) no entity was
            pinned and no entity is being declared, or (b) the declared
            entity matches the pinned entity.

        Returns False when fingerprint differs (MITM) OR when a peer
        presents the pinned cert but declares a DIFFERENT entity_id
        than the one originally pinned against that cert (impersonation).
        """
        entry = self._pins.get(self._key(host, port))
        if entry is None:
            # First connection — trust and pin (with entity if supplied)
            self.pin(host, port, fingerprint, entity_id=entity_id)
            return True
        if entry.get("fp") != fingerprint:
            return False
        pinned_eid_hex = entry.get("eid")
        # If no entity was ever pinned, accept any caller — this
        # preserves backward compatibility with plain (host, port) pins
        # created before the entity-binding change.  The first call
        # that DOES pass an entity_id upgrades the record in place so
        # subsequent connections are bound.
        if not pinned_eid_hex:
            if entity_id is not None:
                entry["eid"] = entity_id.hex()
            return True
        if entity_id is None:
            # Pin carries an entity but caller declined to declare —
            # accept (still defends against cert change) but do not
            # upgrade or downgrade the binding.
            return True
        return pinned_eid_hex == entity_id.hex()

    def clear_pin(self, host: str, port: int) -> None:
        """Remove a pin (for legitimate certificate rotation)."""
        key = self._key(host, port)
        self._pins.pop(key, None)

    def save(self) -> None:
        """Persist pins to the JSON file — atomically.

        Write to a tmp file → fsync → atomic rename → fsync parent dir.
        Without this, a crash between `open("w")` and full `json.dump`
        leaves a truncated JSON file; next start's `load` hits
        JSONDecodeError and resets all pins to empty.  Every previously-
        pinned peer becomes first-seen-again, letting an active MITM
        succeed on reconnect and re-pin the attacker's cert.
        """
        if self._path is None:
            return
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp_path = self._path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(self._pins, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self._path)
        if hasattr(os, "O_DIRECTORY"):
            try:
                dir_fd = os.open(
                    os.path.dirname(os.path.abspath(self._path)) or ".",
                    os.O_RDONLY,
                )
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

    def load(self) -> None:
        """Load pins from the JSON file.

        Tolerates the pre-entity-binding on-disk format (flat str->str
        map) by promoting each legacy entry to the new {fp, eid=None}
        shape.  Operators upgrading keep their pins; the first connection
        to each peer records the bound entity going forward.
        """
        if self._path is None or not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load certificate pin store; starting fresh")
            self._pins = {}
            return
        if not isinstance(raw, dict):
            logger.warning("Certificate pin store malformed (not a dict); starting fresh")
            self._pins = {}
            return
        migrated: dict[str, dict] = {}
        for k, v in raw.items():
            if isinstance(v, str):
                # Legacy flat format: "host:port" -> "fp"
                migrated[k] = {"fp": v}
            elif isinstance(v, dict) and "fp" in v:
                migrated[k] = {"fp": v["fp"]}
                if v.get("eid"):
                    migrated[k]["eid"] = v["eid"]
            # Anything else is silently dropped — a malformed entry
            # would be a failed tampering attempt, not a pin worth
            # trusting.
        self._pins = migrated


def _cert_fingerprint(der_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of a DER-encoded certificate."""
    return hashlib.sha256(der_bytes).hexdigest()


def verify_peer_certificate(
    ssl_socket: ssl.SSLSocket,
    host: str,
    port: int,
    pin_store: CertificatePinStore,
    entity_id: bytes | None = None,
) -> bool:
    """Verify a peer's TLS certificate against the TOFU pin store.

    Call this after the TLS handshake completes.  Gets the peer's
    DER-encoded certificate, computes its SHA-256 fingerprint, and
    checks it against the pin store.

    If ``entity_id`` is supplied (the blockchain identity the peer
    declared in the application-layer handshake), it is bound to the
    pin: a later connection presenting the same cert with a different
    entity_id is rejected as impersonation.

    Returns True if first-seen (pins it) or if both fingerprint and
    entity_id match.  Returns False if fingerprint changed (possible
    MITM), entity_id was swapped under an existing pin, or no
    certificate was presented.
    """
    der_cert = ssl_socket.getpeercert(binary_form=True)
    if der_cert is None:
        return False
    fingerprint = _cert_fingerprint(der_cert)
    return pin_store.check_or_pin(host, port, fingerprint, entity_id=entity_id)


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
