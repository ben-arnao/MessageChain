"""Tests for ASCII-only message validation.

Messages must contain only printable ASCII characters (bytes 32-126):
letters, digits, punctuation, and space. No emoji, no Unicode, no
control characters. 1 char = 1 byte, so MAX_MESSAGE_BYTES = MAX_MESSAGE_CHARS = 280.
"""

import unittest

from messagechain.config import MAX_MESSAGE_CHARS, MAX_MESSAGE_BYTES
from messagechain.core.transaction import (
    create_transaction,
    verify_transaction,
    _validate_message,
    calculate_min_fee,
)
from messagechain.identity.identity import Entity


class TestASCIIOnlyConstants(unittest.TestCase):
    """Character and byte limits must be equal (1 char = 1 byte for ASCII)."""

    def test_max_bytes_equals_max_chars(self):
        self.assertEqual(MAX_MESSAGE_BYTES, MAX_MESSAGE_CHARS)

    def test_max_chars_is_280(self):
        self.assertEqual(MAX_MESSAGE_CHARS, 280)


class TestASCIIValidation(unittest.TestCase):
    """_validate_message must reject non-ASCII content."""

    def test_plain_english_accepted(self):
        valid, _ = _validate_message("Hello, world!")
        self.assertTrue(valid)

    def test_all_printable_ascii_accepted(self):
        """Every printable ASCII character (32-126) should be accepted."""
        all_printable = "".join(chr(c) for c in range(32, 127))
        valid, _ = _validate_message(all_printable)
        self.assertTrue(valid)

    def test_max_length_accepted(self):
        valid, _ = _validate_message("A" * 280)
        self.assertTrue(valid)

    def test_over_max_length_rejected(self):
        valid, _ = _validate_message("A" * 281)
        self.assertFalse(valid)

    def test_empty_message_accepted(self):
        valid, _ = _validate_message("")
        self.assertTrue(valid)

    def test_emoji_rejected(self):
        valid, _ = _validate_message("Hello world! \U0001f600")
        self.assertFalse(valid)

    def test_unicode_cjk_rejected(self):
        valid, _ = _validate_message("Hello \u4e16\u754c")
        self.assertFalse(valid)

    def test_accented_characters_rejected(self):
        valid, _ = _validate_message("caf\u00e9")
        self.assertFalse(valid)

    def test_tab_rejected(self):
        """Tab (byte 9) is a control character, not printable ASCII."""
        valid, _ = _validate_message("hello\tworld")
        self.assertFalse(valid)

    def test_newline_rejected(self):
        """Newline (byte 10) is a control character."""
        valid, _ = _validate_message("hello\nworld")
        self.assertFalse(valid)

    def test_null_byte_rejected(self):
        valid, _ = _validate_message("hello\x00world")
        self.assertFalse(valid)

    def test_del_rejected(self):
        """DEL (byte 127) is not printable ASCII."""
        valid, _ = _validate_message("hello\x7fworld")
        self.assertFalse(valid)

    def test_high_ascii_rejected(self):
        """Bytes above 127 are not ASCII."""
        valid, _ = _validate_message("hello\x80world")
        self.assertFalse(valid)


class TestASCIITransactionCreation(unittest.TestCase):
    """create_transaction must reject non-ASCII messages."""

    def setUp(self):
        self.alice = Entity.create(b"alice-ascii-test".ljust(32, b"\x00"))

    def test_create_with_ascii_succeeds(self):
        msg = "Hello, this is a test message!"
        fee = calculate_min_fee(msg.encode("ascii"))
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        self.assertEqual(tx.message, msg.encode("ascii"))

    def test_create_with_emoji_raises(self):
        with self.assertRaises(ValueError):
            create_transaction(self.alice, "Hello \U0001f600", fee=1000, nonce=0)

    def test_create_with_unicode_raises(self):
        with self.assertRaises(ValueError):
            create_transaction(self.alice, "\u00e9l\u00e8ve", fee=1000, nonce=0)


class TestASCIITransactionVerification(unittest.TestCase):
    """verify_transaction must reject messages with non-ASCII bytes."""

    def setUp(self):
        self.alice = Entity.create(b"alice-verify-ascii".ljust(32, b"\x00"))

    def test_valid_ascii_message_verifies(self):
        msg = "Standard English text, with punctuation."
        fee = calculate_min_fee(msg.encode("ascii"))
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        self.assertTrue(verify_transaction(tx, self.alice.keypair.public_key))


if __name__ == "__main__":
    unittest.main()
