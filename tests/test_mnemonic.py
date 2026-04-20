"""
Tests for BIP-39 mnemonic encoding of private keys.

A 256-bit private key encodes as exactly 24 words from the BIP-39 English
wordlist with an 8-bit checksum (standard BIP-39 entropy-to-mnemonic
mapping). This replaces the 72-hex-char paper-backup format with one that
is dramatically easier to transcribe by hand and compatible with existing
metal-backup products.

Conforms to BIP-39:
- Entropy (256 bits) + checksum (first 8 bits of SHA-256 of entropy)
- 264 bits / 11 = 24 words, each indexing the 2048-word English list
"""

import os
import unittest

from messagechain.identity.mnemonic import (
    WORDLIST,
    InvalidMnemonicChecksumError,
    InvalidMnemonicFormatError,
    encode_to_mnemonic,
    decode_from_mnemonic,
)


class TestWordlist(unittest.TestCase):

    def test_wordlist_is_canonical_bip39_shape(self):
        self.assertEqual(len(WORDLIST), 2048)
        self.assertEqual(len(set(WORDLIST)), 2048)
        self.assertEqual(WORDLIST[0], "abandon")
        self.assertEqual(WORDLIST[-1], "zoo")

    def test_wordlist_prefix_uniqueness(self):
        """First-4-char prefixes uniquely identify each word — a BIP-39 invariant
        that makes auto-completion from metal-stamped backups unambiguous."""
        prefixes = {w[:4] for w in WORDLIST}
        self.assertEqual(len(prefixes), 2048)


class TestMnemonicEncoding(unittest.TestCase):

    def test_encode_produces_24_words(self):
        key = os.urandom(32)
        mnemonic = encode_to_mnemonic(key)
        self.assertEqual(len(mnemonic.split()), 24)

    def test_round_trip_random_keys(self):
        for _ in range(100):
            key = os.urandom(32)
            mnemonic = encode_to_mnemonic(key)
            decoded = decode_from_mnemonic(mnemonic)
            self.assertEqual(decoded, key)

    def test_known_bip39_vector_all_zeros(self):
        """BIP-39 test vector: 32 bytes of zeros encodes to a known mnemonic."""
        key = bytes(32)
        expected = (
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon art"
        )
        self.assertEqual(encode_to_mnemonic(key), expected)
        self.assertEqual(decode_from_mnemonic(expected), key)

    def test_known_bip39_vector_all_ones(self):
        """BIP-39 test vector: 32 bytes of 0x7f ... 0x7f."""
        key = bytes([0x7f] * 32)
        mnemonic = encode_to_mnemonic(key)
        self.assertEqual(decode_from_mnemonic(mnemonic), key)
        self.assertEqual(len(mnemonic.split()), 24)

    def test_decode_rejects_bad_word_count(self):
        with self.assertRaises(InvalidMnemonicFormatError):
            decode_from_mnemonic("abandon abandon abandon")

    def test_decode_rejects_unknown_word(self):
        bad = "abandon " * 23 + "notarealword"
        with self.assertRaises(InvalidMnemonicFormatError):
            decode_from_mnemonic(bad)

    def test_decode_rejects_bad_checksum(self):
        """Flip one bit in the checksum → rejected (catches transcription errors)."""
        key = os.urandom(32)
        mnemonic = encode_to_mnemonic(key).split()
        # Swap the last word for a different valid word — checksum will fail
        last_word = mnemonic[-1]
        alt_word = "abandon" if last_word != "abandon" else "ability"
        mnemonic[-1] = alt_word
        with self.assertRaises(InvalidMnemonicChecksumError):
            decode_from_mnemonic(" ".join(mnemonic))

    def test_decode_is_case_insensitive_and_whitespace_tolerant(self):
        key = os.urandom(32)
        mnemonic = encode_to_mnemonic(key)
        # Uppercase + extra whitespace should still decode
        messy = "  " + mnemonic.upper().replace(" ", "   ") + "  "
        self.assertEqual(decode_from_mnemonic(messy), key)

    def test_encode_requires_32_byte_key(self):
        with self.assertRaises(InvalidMnemonicFormatError):
            encode_to_mnemonic(b"tooshort")
        with self.assertRaises(InvalidMnemonicFormatError):
            encode_to_mnemonic(os.urandom(31))
        with self.assertRaises(InvalidMnemonicFormatError):
            encode_to_mnemonic(os.urandom(33))


class TestKeyEncodingAutoDetect(unittest.TestCase):
    """decode_private_key should accept either the 72-hex format or a 24-word mnemonic."""

    def test_hex_format_still_works(self):
        from messagechain.identity.key_encoding import encode_private_key, decode_private_key
        key = os.urandom(32)
        encoded = encode_private_key(key)
        self.assertEqual(decode_private_key(encoded), key)

    def test_mnemonic_format_auto_detected(self):
        from messagechain.identity.key_encoding import decode_private_key
        key = os.urandom(32)
        mnemonic = encode_to_mnemonic(key)
        self.assertEqual(decode_private_key(mnemonic), key)

    def test_garbage_input_rejected(self):
        from messagechain.identity.key_encoding import (
            decode_private_key, InvalidKeyFormatError,
        )
        with self.assertRaises(InvalidKeyFormatError):
            decode_private_key("this is definitely not a key at all")


if __name__ == "__main__":
    unittest.main()
