"""
BIP-39 mnemonic encoding for 256-bit private keys.

Paper backups are hard: 72 hex characters transcribed by hand get
mistyped regularly, even with a checksum. A 24-word mnemonic from the
BIP-39 English wordlist is dramatically easier to copy correctly,
easier to verify visually, and compatible with the metal-backup
products that already exist in the cryptocurrency ecosystem.

Strict BIP-39 compatibility:
- 256 bits of entropy + first 8 bits of SHA-256(entropy) = 264 bits
- 264 / 11 = 24 words, each indexing a 2048-word English list
- Checksum uses SHA-256 (not SHA3-256) to stay interoperable with
  every existing BIP-39 implementation

This module handles only the entropy↔mnemonic mapping. It deliberately
does NOT implement BIP-39's PBKDF2 seed derivation, because we use the
32-byte entropy directly as the MessageChain private key rather than
deriving an HD-wallet seed from it.
"""

import hashlib
from pathlib import Path


class InvalidMnemonicFormatError(ValueError):
    """The input is not a valid 24-word BIP-39 mnemonic (wrong count, unknown word, etc.)."""


class InvalidMnemonicChecksumError(ValueError):
    """The mnemonic parses cleanly but its checksum bits don't match — typically
    a transcription error when copying words from paper."""


def _load_wordlist() -> list[str]:
    path = Path(__file__).with_name("bip39_english.txt")
    with path.open("r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise RuntimeError(
            f"BIP-39 wordlist is corrupt: expected 2048 words, got {len(words)}"
        )
    return words


WORDLIST: list[str] = _load_wordlist()
_WORD_TO_INDEX: dict[str, int] = {w: i for i, w in enumerate(WORDLIST)}

_ENTROPY_BYTES = 32   # 256 bits
_CHECKSUM_BITS = 8    # 256 / 32 per BIP-39 formula
_WORD_COUNT = 24      # (256 + 8) / 11


def _checksum_bits(entropy: bytes) -> int:
    """Return the first 8 bits of SHA-256(entropy) as an int."""
    digest = hashlib.sha256(entropy).digest()
    return digest[0]  # first 8 bits = first byte


def encode_to_mnemonic(entropy: bytes) -> str:
    """Encode 32 bytes of entropy as a 24-word BIP-39 mnemonic."""
    if not isinstance(entropy, (bytes, bytearray)) or len(entropy) != _ENTROPY_BYTES:
        raise InvalidMnemonicFormatError(
            f"Entropy must be exactly {_ENTROPY_BYTES} bytes"
        )

    # Build a 264-bit big-endian integer: entropy || checksum
    bits = int.from_bytes(entropy, "big")
    bits = (bits << _CHECKSUM_BITS) | _checksum_bits(entropy)

    # Split into 24 chunks of 11 bits, high-order first
    words = []
    for i in range(_WORD_COUNT - 1, -1, -1):
        idx = (bits >> (11 * i)) & 0x7FF
        words.append(WORDLIST[idx])
    return " ".join(words)


def decode_from_mnemonic(mnemonic: str) -> bytes:
    """Decode a 24-word BIP-39 mnemonic back to 32 bytes of entropy.

    Case-insensitive, whitespace-tolerant. Raises
    InvalidMnemonicFormatError on structural defects (wrong count,
    unknown word) and InvalidMnemonicChecksumError when the words
    parse cleanly but the checksum fails — almost always a
    transcription error.
    """
    if not isinstance(mnemonic, str):
        raise InvalidMnemonicFormatError("Mnemonic must be a string")

    words = mnemonic.lower().split()
    if len(words) != _WORD_COUNT:
        raise InvalidMnemonicFormatError(
            f"Mnemonic must be {_WORD_COUNT} words, got {len(words)}"
        )

    # Reassemble the 264-bit integer
    bits = 0
    for word in words:
        idx = _WORD_TO_INDEX.get(word)
        if idx is None:
            raise InvalidMnemonicFormatError(f"Unknown word: {word!r}")
        bits = (bits << 11) | idx

    # Split off the checksum (low 8 bits)
    provided_checksum = bits & ((1 << _CHECKSUM_BITS) - 1)
    entropy_int = bits >> _CHECKSUM_BITS
    entropy = entropy_int.to_bytes(_ENTROPY_BYTES, "big")

    expected_checksum = _checksum_bits(entropy)
    if provided_checksum != expected_checksum:
        raise InvalidMnemonicChecksumError(
            "Checksum mismatch — the mnemonic appears to be mistyped. "
            "Double-check your backup word-by-word."
        )

    return entropy


def looks_like_mnemonic(s: str) -> bool:
    """Cheap heuristic: does this input look like a 24-word mnemonic?

    Used by decode_private_key to auto-route between hex and mnemonic
    formats without forcing the user to specify.
    """
    if not isinstance(s, str):
        return False
    tokens = s.lower().split()
    return len(tokens) == _WORD_COUNT
