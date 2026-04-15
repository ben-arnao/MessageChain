"""
Tests for the checksummed entity-ID display format.
"""

import os
import unittest

from messagechain.identity.address import (
    InvalidAddressChecksumError,
    InvalidAddressError,
    decode_address,
    encode_address,
    is_checksummed,
)


class TestAddressRoundTrip(unittest.TestCase):

    def test_random_round_trip(self):
        for _ in range(100):
            eid = os.urandom(32)
            addr = encode_address(eid)
            self.assertEqual(decode_address(addr), eid)

    def test_display_shape(self):
        eid = b"\x00" * 32
        addr = encode_address(eid)
        self.assertTrue(addr.startswith("mc1"))
        self.assertEqual(len(addr), 3 + 64 + 8)  # prefix + entity + checksum


class TestTypoDetection(unittest.TestCase):

    def test_single_char_flip_rejected(self):
        """The point of the checksum: flip any one hex char, decoder fails."""
        eid = os.urandom(32)
        addr = encode_address(eid)
        # Flip a char in the entity body (not the mc1 prefix)
        body = list(addr)
        body[10] = "f" if body[10] != "f" else "e"
        mangled = "".join(body)
        with self.assertRaises(InvalidAddressChecksumError):
            decode_address(mangled)

    def test_bit_flip_in_checksum_rejected(self):
        eid = os.urandom(32)
        addr = encode_address(eid)
        # Flip the last char (in the checksum)
        body = list(addr)
        body[-1] = "f" if body[-1] != "f" else "e"
        with self.assertRaises(InvalidAddressChecksumError):
            decode_address("".join(body))


class TestBackwardCompatibility(unittest.TestCase):

    def test_raw_hex_still_accepted(self):
        eid = os.urandom(32)
        self.assertEqual(decode_address(eid.hex()), eid)

    def test_raw_hex_wrong_length_rejected(self):
        with self.assertRaises(InvalidAddressError):
            decode_address("deadbeef")  # too short

    def test_bad_prefix_rejected(self):
        eid = os.urandom(32)
        with self.assertRaises(InvalidAddressError):
            decode_address("xx1" + eid.hex() + "00000000")


class TestIsChecksummed(unittest.TestCase):

    def test_recognizes_prefix(self):
        self.assertTrue(is_checksummed(encode_address(os.urandom(32))))
        self.assertFalse(is_checksummed(os.urandom(32).hex()))


if __name__ == "__main__":
    unittest.main()
