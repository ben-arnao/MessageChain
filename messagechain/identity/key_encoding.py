"""Checksummed private key encoding.

Private keys are displayed and input in one of two formats:

1. 24-word BIP-39 mnemonic (preferred for paper backup) — dramatically
   higher transcription fidelity than hex, compatible with existing
   metal-backup products. See messagechain.identity.mnemonic.

2. 72-char checksummed hex (legacy / compact) — 32-byte key + 4-byte
   SHA3-256 checksum. Still supported for tools that want a fixed-
   width single-token representation.

The decoder auto-detects format: 24 whitespace-separated tokens is
treated as a mnemonic, anything else is tried as hex. A transcription
error in either format is detected via its checksum, so the user is
told "your backup is wrong" instead of silently deriving a different
identity and losing the funds.

Hex format:
    <64 hex chars private key><8 hex chars checksum>
    = 72 hex chars total
    checksum = first 4 bytes of SHA3-256(b"mc-key-v1" || private_key)

4-byte checksum gives ~1 in 4 billion chance of a random string passing,
which is adequate — we only care about detecting human transcription
errors, not forging keys.
"""

import hashlib

from messagechain.config import HASH_ALGO
from messagechain.identity.mnemonic import (
    InvalidMnemonicChecksumError,
    InvalidMnemonicFormatError,
    decode_from_mnemonic,
    encode_to_mnemonic,
    looks_like_mnemonic,
)
from messagechain.crypto.hashing import default_hash

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
    return default_hash(_DOMAIN + private_key)[:_CHECKSUM_BYTES]


def encode_private_key(private_key: bytes) -> str:
    """Encode a 32-byte private key as hex with an appended checksum."""
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise InvalidKeyFormatError("Private key must be 32 bytes")
    checksum = _compute_checksum(bytes(private_key))
    return private_key.hex() + checksum.hex()


def decode_private_key(encoded: str) -> bytes:
    """Decode a private key string in either mnemonic or hex-checksum format.

    Auto-detects the format: 24 whitespace-separated tokens is treated as a
    BIP-39 mnemonic; anything else is tried as 72-char checksummed hex.
    Raises InvalidKeyFormatError on structural problems and
    InvalidKeyChecksumError when the format parses but the checksum fails.
    """
    if not isinstance(encoded, str):
        raise InvalidKeyFormatError("Encoded key must be a string")

    # Route to mnemonic decoder first — catches the preferred format.
    if looks_like_mnemonic(encoded):
        try:
            return decode_from_mnemonic(encoded)
        except InvalidMnemonicChecksumError as e:
            raise InvalidKeyChecksumError(str(e))
        except InvalidMnemonicFormatError as e:
            raise InvalidKeyFormatError(str(e))

    encoded = encoded.strip().lower()

    if len(encoded) != _TOTAL_HEX_CHARS:
        raise InvalidKeyFormatError(
            f"Unrecognized key format: expected a 24-word mnemonic or "
            f"{_TOTAL_HEX_CHARS}-char checksummed hex, got {len(encoded)} chars"
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
