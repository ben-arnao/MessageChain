"""Tests for block deserialization size validation.

Ensures that oversized hex strings from untrusted peers are rejected
before attempting Block.from_bytes deserialization.
"""

import unittest

from messagechain.config import MAX_BLOCK_HEX_SIZE, validate_block_hex_size


class TestMaxBlockHexSize(unittest.TestCase):
    """Test the MAX_BLOCK_HEX_SIZE constant is reasonable."""

    def test_max_block_hex_size_is_positive(self):
        self.assertGreater(MAX_BLOCK_HEX_SIZE, 0)

    def test_max_block_hex_size_allows_normal_blocks(self):
        """A normal block (well under 1MB) should be under the limit."""
        # A 100KB block hex = 200K hex chars — should be well within limit
        self.assertGreater(MAX_BLOCK_HEX_SIZE, 200_000)


class TestValidateBlockHexSize(unittest.TestCase):
    """Test the validate_block_hex_size guard function."""

    def test_normal_sized_hex_accepted(self):
        """A reasonably sized hex string is accepted."""
        normal_hex = "aa" * 1000  # 2000 hex chars = 1KB
        self.assertTrue(validate_block_hex_size(normal_hex))

    def test_oversized_hex_rejected(self):
        """A hex string exceeding MAX_BLOCK_HEX_SIZE is rejected."""
        oversized_hex = "aa" * (MAX_BLOCK_HEX_SIZE // 2 + 1)
        self.assertFalse(validate_block_hex_size(oversized_hex))

    def test_boundary_at_max(self):
        """Exactly at the limit should be accepted."""
        boundary_hex = "a" * MAX_BLOCK_HEX_SIZE
        self.assertTrue(validate_block_hex_size(boundary_hex))

    def test_boundary_above_max(self):
        """One character above the limit should be rejected."""
        over_boundary_hex = "a" * (MAX_BLOCK_HEX_SIZE + 1)
        self.assertFalse(validate_block_hex_size(over_boundary_hex))

    def test_non_string_rejected(self):
        """Non-string input is rejected."""
        self.assertFalse(validate_block_hex_size(12345))
        self.assertFalse(validate_block_hex_size(None))
        self.assertFalse(validate_block_hex_size(["aa", "bb"]))

    def test_empty_string_accepted(self):
        """Empty string passes size check (will fail at deserialization)."""
        self.assertTrue(validate_block_hex_size(""))


if __name__ == "__main__":
    unittest.main()
