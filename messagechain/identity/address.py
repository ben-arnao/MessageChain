"""
Address checksums for typo-resistant entity ID display.

The raw entity_id is 64 hex characters. A single mistyped character by
a user transcribing an address is silent — the typo'd address is still
well-formed, and if it happens to match a different registered entity
the funds go to the wrong wallet. Even with the CLI's "recipient not
registered" pre-check, a typo that lands on another registered address
would still slip through.

This module adds a short (8-char) checksum suffix to the displayed form
of an entity_id. The checksum is deterministic and verifiable offline,
so the CLI can flag a mistyped address BEFORE any chain interaction.

Format:
    mc1<64 hex entity_id><8 hex checksum>

Checksum:
    first 4 bytes of SHA3-256(b"mc-addr-v1" || entity_id), hex-encoded.

The `mc1` prefix is a human-readable signal that the string is a
MessageChain address (like Bitcoin's `bc1` Bech32 prefix). The raw
hex form without the prefix remains accepted for backward compatibility.
"""

import hashlib

from messagechain.config import HASH_ALGO

_PREFIX = "mc1"
_DOMAIN = b"mc-addr-v1"
_CHECKSUM_BYTES = 4
_CHECKSUM_HEX_CHARS = _CHECKSUM_BYTES * 2
_HEX_ENTITY_CHARS = 64
_DISPLAY_LEN = len(_PREFIX) + _HEX_ENTITY_CHARS + _CHECKSUM_HEX_CHARS


class InvalidAddressError(ValueError):
    """Address format / length / hex error."""


class InvalidAddressChecksumError(ValueError):
    """Address parses cleanly but the checksum doesn't match — typo."""


def _compute_checksum(entity_id: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, _DOMAIN + entity_id).digest()[:_CHECKSUM_BYTES]


def encode_address(entity_id: bytes) -> str:
    """Encode a 32-byte entity_id as a checksummed display address.

    Output shape: `mc1<64 hex><8 hex>`, total 75 characters.
    """
    if not isinstance(entity_id, (bytes, bytearray)) or len(entity_id) != 32:
        raise InvalidAddressError("entity_id must be exactly 32 bytes")
    checksum = _compute_checksum(bytes(entity_id))
    return _PREFIX + entity_id.hex() + checksum.hex()


def decode_address(s: str) -> bytes:
    """Decode a displayed address back to its 32-byte entity_id.

    Accepts EITHER the full `mc1...` checksummed form OR the raw 64-char
    hex (backward-compatibility; no typo protection). Raises
    InvalidAddressChecksumError when the checksum fails, which is the
    signal to the CLI to flag a transcription error before any transfer
    proceeds.
    """
    if not isinstance(s, str):
        raise InvalidAddressError("address must be a string")
    s = s.strip().lower()

    # Backward-compat path: raw 64-char hex, no prefix, no checksum.
    if len(s) == _HEX_ENTITY_CHARS and not s.startswith(_PREFIX):
        try:
            return bytes.fromhex(s)
        except ValueError as e:
            raise InvalidAddressError(f"not valid hex: {e}")

    if not s.startswith(_PREFIX):
        raise InvalidAddressError(
            f"expected address to start with {_PREFIX!r} or be a 64-char "
            f"hex entity ID; got {s[:16]!r}..."
        )
    if len(s) != _DISPLAY_LEN:
        raise InvalidAddressError(
            f"address must be {_DISPLAY_LEN} chars, got {len(s)}"
        )
    body = s[len(_PREFIX):]
    try:
        raw = bytes.fromhex(body)
    except ValueError as e:
        raise InvalidAddressError(f"not valid hex after prefix: {e}")
    entity_id = raw[:32]
    provided = raw[32:]
    expected = _compute_checksum(entity_id)
    if provided != expected:
        raise InvalidAddressChecksumError(
            "Address checksum mismatch — this looks like a transcription error. "
            "Re-check the address character by character."
        )
    return entity_id


def is_checksummed(s: str) -> bool:
    """Cheap shape check: does this string start with the mc1 prefix?"""
    return isinstance(s, str) and s.strip().lower().startswith(_PREFIX)
