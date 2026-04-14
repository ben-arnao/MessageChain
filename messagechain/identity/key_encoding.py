"""Checksummed private key encoding.

Private keys are displayed and input as hex with an appended checksum
derived from the key itself. A transcription error (single or multiple
character flips) is detected by the decoder, so the user is told
"your backup is wrong" instead of silently deriving a different
identity and losing the funds.

Format:
    <64 hex chars private key><8 hex chars checksum>
    = 72 hex chars total

Checksum:
    first 4 bytes of SHA3-256(b"mc-key-v1" || private_key)

4-byte checksum gives ~1 in 4 billion chance of a random string passing,
which is adequate — we only care about detecting human transcription
errors, not forging keys.
"""

import hashlib

from messagechain.config import HASH_ALGO

_CHECKSUM_BYTES = 4
CHECKSUM_HEX_CHARS = _CHECKSUM_BYTES * 2
_KEY_HEX_CHARS = 64
_TOTAL_HEX_CHARS = _KEY_HEX_CHARS + CHECKSUM_HEX_CHARS
_DOMAIN = b"mc-key-v1"


class InvalidKeyFormatError(ValueError):
    """The encoded string is not a valid length / not hex."""


class InvalidKeyChecksumError(ValueError):
    """The checksum does not match — likely a transcription error."""


def _compute_checksum(private_key: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, _DOMAIN + private_key).digest()[:_CHECKSUM_BYTES]


def encode_private_key(private_key: bytes) -> str:
    """Encode a 32-byte private key as hex with an appended checksum."""
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise InvalidKeyFormatError("Private key must be 32 bytes")
    checksum = _compute_checksum(bytes(private_key))
    return private_key.hex() + checksum.hex()


def decode_private_key(encoded: str) -> bytes:
    """Decode a checksummed key string. Raises on length, hex, or checksum errors."""
    if not isinstance(encoded, str):
        raise InvalidKeyFormatError("Encoded key must be a string")

    encoded = encoded.strip().lower()

    if len(encoded) != _TOTAL_HEX_CHARS:
        raise InvalidKeyFormatError(
            f"Encoded key must be {_TOTAL_HEX_CHARS} hex chars, got {len(encoded)}"
        )

    try:
        raw = bytes.fromhex(encoded)
    except ValueError as e:
        raise InvalidKeyFormatError(f"Not valid hex: {e}")

    key = raw[:32]
    provided_checksum = raw[32:]
    expected_checksum = _compute_checksum(key)

    if provided_checksum != expected_checksum:
        raise InvalidKeyChecksumError(
            "Checksum mismatch — the key appears to be mistyped. "
            "Double-check your backup."
        )

    return key
