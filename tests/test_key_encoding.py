"""Tests for checksummed private key encoding.

The on-screen / on-paper format includes a short hash-based checksum
so transcription errors are detected immediately rather than silently
deriving the wrong identity.
"""

import os
import unittest

from messagechain.identity.key_encoding import (
    encode_private_key,
    decode_private_key,
    InvalidKeyChecksumError,
    InvalidKeyFormatError,
    CHECKSUM_HEX_CHARS,
)


class TestKeyEncoding(unittest.TestCase):
    def test_roundtrip(self):
        """encode then decode returns the same key."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        decoded = decode_private_key(encoded)
        self.assertEqual(decoded, key)

    def test_encoded_includes_checksum(self):
        """Encoded form is 64 hex chars (key) + checksum chars."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        self.assertEqual(len(encoded), 64 + CHECKSUM_HEX_CHARS)

    def test_encoded_is_hex(self):
        """Encoded form is pure hex."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        # Must be valid hex
        bytes.fromhex(encoded)

    def test_detects_single_char_flip(self):
        """Flipping any single hex char must produce a checksum failure."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        # Flip the first character
        flipped = ("0" if encoded[0] != "0" else "1") + encoded[1:]
        with self.assertRaises(InvalidKeyChecksumError):
            decode_private_key(flipped)

    def test_detects_checksum_tamper(self):
        """Flipping the checksum must fail."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        tampered = encoded[:-1] + ("0" if encoded[-1] != "0" else "1")
        with self.assertRaises(InvalidKeyChecksumError):
            decode_private_key(tampered)

    def test_rejects_wrong_length(self):
        """Keys that are too short or too long are rejected clearly."""
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key("abcd")
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key("a" * 100)

    def test_rejects_non_hex(self):
        """Non-hex characters are rejected clearly."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        # Replace last char with non-hex
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key(encoded[:-1] + "z")

    def test_accepts_whitespace(self):
        """Leading/trailing whitespace is trimmed (common paste artifact)."""
        key = os.urandom(32)
        encoded = encode_private_key(key)
        self.assertEqual(decode_private_key(f"  {encoded}\n"), key)

    def test_case_insensitive(self):
        """Uppercase hex is accepted (common if hand-copied)."""
        key = os.urandom(32)
        encoded = encode_private_key(key).upper()
        self.assertEqual(decode_private_key(encoded), key)

    def test_deterministic(self):
        """Same key always encodes the same way."""
        key = os.urandom(32)
        self.assertEqual(encode_private_key(key), encode_private_key(key))

    def test_different_keys_different_checksums(self):
        """Different keys produce different checksums (usually)."""
        # Not a strict guarantee but for random keys it's overwhelmingly likely
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        self.assertNotEqual(encode_private_key(k1), encode_private_key(k2))

    def test_rejects_non_string(self):
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key(None)
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key(b"abcd")


if __name__ == "__main__":
    unittest.main()
