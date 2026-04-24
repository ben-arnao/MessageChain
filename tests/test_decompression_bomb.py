"""Tests for decompression bomb mitigation in compression.py.

A malicious actor can craft a tiny compressed payload that decompresses to
gigabytes, causing OOM on every validating node. decode_payload must enforce
a hard cap via zlib.decompressobj with max_length.
"""

import unittest
import zlib

from messagechain.core.compression import (
    COMPRESSED_FLAG,
    RAW_FLAG,
    decode_payload,
    encode_payload,
    MAX_DECOMPRESSED_MESSAGE_SIZE,
)


class TestDecompressionBombRejected(unittest.TestCase):
    """A zlib bomb (small compressed, huge decompressed) must raise ValueError."""

    def test_decompression_bomb_rejected(self):
        """100 KB of zeros compresses to ~100 bytes. decode_payload must refuse."""
        bomb_plaintext = b"\x00" * 100_000
        # Compress at level 9, strip 2-byte header and 4-byte adler32 trailer
        # to match MessageChain's canonical raw-deflate format.
        compressed = zlib.compress(bomb_plaintext, 9)[2:-4]
        # Sanity: the compressed form is tiny relative to the plaintext.
        self.assertLess(len(compressed), 200)
        with self.assertRaises(ValueError) as ctx:
            decode_payload(compressed, COMPRESSED_FLAG)
        self.assertIn("exceeds", str(ctx.exception))

    def test_max_decompressed_size_constant_is_sane(self):
        """MAX_DECOMPRESSED_MESSAGE_SIZE should be >= MAX_MESSAGE_CHARS
        and not absurdly large."""
        from messagechain.config import MAX_MESSAGE_CHARS
        self.assertGreaterEqual(MAX_DECOMPRESSED_MESSAGE_SIZE, MAX_MESSAGE_CHARS)
        self.assertLessEqual(MAX_DECOMPRESSED_MESSAGE_SIZE, 4 * MAX_MESSAGE_CHARS)


class TestNormalRoundtrip(unittest.TestCase):
    """Normal messages must still round-trip through encode/decode."""

    def test_normal_roundtrip(self):
        plaintext = b"Hello world"
        stored, flag = encode_payload(plaintext)
        decoded = decode_payload(stored, flag)
        self.assertEqual(decoded, plaintext)


class TestMaxSizeMessage(unittest.TestCase):
    """A 280-byte message (MAX_MESSAGE_CHARS) must encode and decode cleanly."""

    def test_max_size_message(self):
        plaintext = b"A" * 280
        stored, flag = encode_payload(plaintext)
        decoded = decode_payload(stored, flag)
        self.assertEqual(decoded, plaintext)


class TestRawFlagUnchanged(unittest.TestCase):
    """RAW_FLAG returns stored bytes unmodified — no decompression at all."""

    def test_raw_flag_unchanged(self):
        data = b"arbitrary bytes \x00\xff\x80"
        result = decode_payload(data, RAW_FLAG)
        self.assertEqual(result, data)


if __name__ == "__main__":
    unittest.main()
