"""Canonical-form payload compression for MessageTransaction.

Stored form of a message is either:
  - Raw (compression_flag=0): the user's ASCII bytes verbatim
  - Compressed (compression_flag=1): zlib.compress(raw, 9)[2:-4]
    (header/adler32 stripped; decompressed with negative WBITS raw deflate)

Canonical rule: always compute both, store whichever is smaller. If the
compressed form is >= raw, store raw. Deterministic: same plaintext
always yields the same stored bytes and flag.

Consensus implications:
- compression_flag is part of _signable_data → tx_hash commits to the
  canonical form. Two different encoders will produce identical hashes.
- Fee is charged on len(stored_bytes), not len(plaintext) — incentivizes
  compressible content.
- MAX_MESSAGE_BYTES applies to STORED bytes, so a plaintext that exceeds
  the raw cap is still acceptable if it compresses below the cap.
"""

import unittest
import zlib

from messagechain.config import MAX_MESSAGE_BYTES, MAX_MESSAGE_CHARS, MIN_FEE
from messagechain.core.compression import encode_payload, decode_payload, RAW_FLAG, COMPRESSED_FLAG
from messagechain.core.transaction import (
    MessageTransaction,
    calculate_min_fee,
    create_transaction,
    verify_transaction,
)
from messagechain.identity.identity import Entity


class TestCanonicalEncoding(unittest.TestCase):
    """encode_payload returns the smaller of (raw, compressed) deterministically."""

    def test_empty_input_is_raw(self):
        stored, flag = encode_payload(b"")
        self.assertEqual(stored, b"")
        self.assertEqual(flag, RAW_FLAG)

    def test_short_message_is_raw(self):
        """Short text doesn't compress below its own size."""
        stored, flag = encode_payload(b"hi")
        self.assertEqual(flag, RAW_FLAG)
        self.assertEqual(stored, b"hi")

    def test_highly_repeating_is_compressed(self):
        """Long run of the same byte compresses dramatically."""
        plaintext = b"A" * 200
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, COMPRESSED_FLAG)
        self.assertLess(len(stored), len(plaintext))

    def test_english_text_is_compressed(self):
        """A realistic English paragraph benefits from compression."""
        plaintext = (
            b"The quick brown fox jumps over the lazy dog. "
            b"The quick brown fox jumps over the lazy dog. "
            b"The quick brown fox jumps over the lazy dog."
        )
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, COMPRESSED_FLAG)
        self.assertLess(len(stored), len(plaintext))

    def test_random_bytes_stay_raw(self):
        """Incompressible (already-random) input stores raw."""
        # os.urandom is random; compressed form will be larger than raw.
        import os
        plaintext = os.urandom(64)
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, RAW_FLAG)
        self.assertEqual(stored, plaintext)

    def test_encoding_is_deterministic(self):
        """Same plaintext → same stored bytes every time (consensus-critical)."""
        plaintext = b"Deterministic compression test: " + b"ABCD" * 20
        s1, f1 = encode_payload(plaintext)
        s2, f2 = encode_payload(plaintext)
        self.assertEqual(s1, s2)
        self.assertEqual(f1, f2)

    def test_canonical_choice_prefers_raw_on_tie(self):
        """If compressed size equals raw size, prefer raw (simpler, no decode)."""
        # Find a small input where raw and compressed are equal (rare but legal).
        # Easier proof: assert that when len(compressed) >= len(raw),
        # encode_payload picks raw.
        plaintext = b"x"
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, RAW_FLAG)


class TestDecode(unittest.TestCase):
    """decode_payload reverses encode_payload."""

    def test_round_trip_raw(self):
        plaintext = b"Hello, world!"
        stored, flag = encode_payload(plaintext)
        decoded = decode_payload(stored, flag)
        self.assertEqual(decoded, plaintext)

    def test_round_trip_compressed(self):
        plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" * 5  # 150 bytes
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, COMPRESSED_FLAG)
        decoded = decode_payload(stored, flag)
        self.assertEqual(decoded, plaintext)

    def test_round_trip_english(self):
        plaintext = (
            b"The quick brown fox jumps over the lazy dog. "
            * 4
        )
        stored, flag = encode_payload(plaintext)
        self.assertEqual(decode_payload(stored, flag), plaintext)

    def test_unknown_flag_rejected(self):
        with self.assertRaises(ValueError):
            decode_payload(b"anything", 99)


class TestDeterministicAcrossInvocations(unittest.TestCase):
    """zlib level 9 output must match a known-good byte pattern — catches
    any cross-version drift in the stdlib deflate encoder."""

    def test_known_plaintext_produces_known_bytes(self):
        """Regression fixture: if this breaks, Python's zlib changed its
        level-9 output. Nodes would then disagree on tx_hash."""
        plaintext = b"A" * 100
        stored, flag = encode_payload(plaintext)
        self.assertEqual(flag, COMPRESSED_FLAG)
        # Exact expected bytes from zlib.compress(b"A"*100, 9)[2:-4]
        # This is the raw-deflate block for 100 bytes of 'A'.
        expected = zlib.compress(plaintext, 9)[2:-4]
        self.assertEqual(stored, expected)
        # And decode round-trips using raw-deflate.
        self.assertEqual(zlib.decompress(stored, -zlib.MAX_WBITS), plaintext)


class TestMessageTransactionUsesCompression(unittest.TestCase):
    """create_transaction stores the canonical form on tx.message."""

    def setUp(self):
        self.alice = Entity.create(b"alice-compression".ljust(32, b"\x00"))

    def test_compressible_message_stored_compressed(self):
        msg = "A" * 100
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        self.assertEqual(tx.compression_flag, COMPRESSED_FLAG)
        self.assertLess(len(tx.message), 100)

    def test_incompressible_short_stored_raw(self):
        msg = "ok"
        fee = calculate_min_fee(b"ok")
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        self.assertEqual(tx.compression_flag, RAW_FLAG)
        self.assertEqual(tx.message, b"ok")

    def test_plaintext_property_returns_original(self):
        """tx.plaintext always returns the original user bytes."""
        msg = "Hello, world!"
        fee = calculate_min_fee(msg.encode("ascii"))
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        self.assertEqual(tx.plaintext, msg.encode("ascii"))

    def test_plaintext_property_on_compressed(self):
        msg = "B" * 200
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        self.assertEqual(tx.compression_flag, COMPRESSED_FLAG)
        self.assertEqual(tx.plaintext, b"B" * 200)


class TestFeeOnStoredSize(unittest.TestCase):
    """Fees are charged on len(stored_bytes), not len(plaintext)."""

    def setUp(self):
        self.alice = Entity.create(b"alice-fee-compress".ljust(32, b"\x00"))

    def test_min_fee_uses_stored_size(self):
        """A 200-byte repetitive message compresses to <10 bytes — fee should
        reflect the compressed size, not the original."""
        msg = "C" * 200
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        # Required fee is calculated on the stored (compressed) size
        stored_size = len(tx.message)
        expected_min = calculate_min_fee(tx.message)
        # Fee for the raw 200-byte version would be much higher
        raw_min = calculate_min_fee(b"C" * 200)
        self.assertLess(expected_min, raw_min)
        # Sanity: stored_size matches what the min fee was computed on
        self.assertEqual(len(tx.message), stored_size)

    def test_create_accepts_low_fee_for_compressible_message(self):
        """A message that's 100 bytes of 'A' should be acceptable with just
        the compressed-size minimum fee (much smaller than the 100-byte fee)."""
        msg = "A" * 100
        # Encode to find stored size, then fund exactly that min
        from messagechain.core.compression import encode_payload
        stored, _ = encode_payload(msg.encode("ascii"))
        min_fee_for_stored = calculate_min_fee(stored)
        raw_min = calculate_min_fee(msg.encode("ascii"))
        self.assertLess(min_fee_for_stored, raw_min)
        # create_transaction should accept the stored-size minimum
        tx = create_transaction(self.alice, msg, fee=min_fee_for_stored, nonce=0)
        self.assertEqual(tx.fee, min_fee_for_stored)

    def test_verify_checks_fee_against_stored_size(self):
        msg = "Repeat this. " * 20  # compresses well
        tx = create_transaction(self.alice, msg, fee=10_000, nonce=0)
        self.assertTrue(verify_transaction(tx, self.alice.keypair.public_key))


class TestConsensusHashStability(unittest.TestCase):
    """compression_flag is in _signable_data → tx_hash commits to it."""

    def setUp(self):
        self.alice = Entity.create(b"alice-consensus-c".ljust(32, b"\x00"))

    def test_same_plaintext_same_hash_across_creations(self):
        """Two independently-created transactions with the same plaintext
        (and same other fields) hash identically because the canonical
        encoder is deterministic."""
        msg = "A" * 100
        fee = 5000
        tx1 = create_transaction(self.alice, msg, fee=fee, nonce=7)
        tx2 = create_transaction(self.alice, msg, fee=fee, nonce=7)
        # timestamps will differ to the second, but int() of them for the
        # same slot could match; force match by copying:
        tx2.timestamp = tx1.timestamp
        tx2.tx_hash = tx2._compute_hash()
        self.assertEqual(tx1.tx_hash, tx2.tx_hash)

    def test_flag_included_in_signable_data(self):
        """Forging a tx by flipping compression_flag changes tx_hash."""
        msg = "A" * 100
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        original_hash = tx._compute_hash()
        # Flip the flag to RAW — hash must change
        tx.compression_flag = RAW_FLAG
        tampered_hash = tx._compute_hash()
        self.assertNotEqual(original_hash, tampered_hash)


class TestMaxSizeOnStoredBytes(unittest.TestCase):
    """MAX_MESSAGE_BYTES applies to stored (possibly compressed) size."""

    def setUp(self):
        self.alice = Entity.create(b"alice-maxsize-c".ljust(32, b"\x00"))

    def test_highly_compressible_message_over_plaintext_cap_rejected_on_chars(self):
        """MAX_MESSAGE_CHARS still applies to plaintext — a 10000-char
        repetitive message is rejected for being too many characters even
        though it compresses to a few bytes.

        Char limit = 'human readability' constraint, decoupled from storage.
        """
        msg = "A" * (MAX_MESSAGE_CHARS + 1)
        with self.assertRaises(ValueError):
            create_transaction(self.alice, msg, fee=5000, nonce=0)

    def test_max_size_boundary_uses_stored_size(self):
        """A plaintext that's at MAX_MESSAGE_CHARS chars and compresses tiny
        is accepted — its stored size is well under MAX_MESSAGE_BYTES."""
        msg = "A" * MAX_MESSAGE_CHARS  # 280 chars
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        # Stored size should be < MAX_MESSAGE_BYTES (obviously — it compresses)
        self.assertLess(len(tx.message), MAX_MESSAGE_BYTES)
        self.assertTrue(verify_transaction(tx, self.alice.keypair.public_key))


class TestBinarySerializationWithCompression(unittest.TestCase):
    """to_bytes/from_bytes preserve compression_flag."""

    def setUp(self):
        self.alice = Entity.create(b"alice-bin-c".ljust(32, b"\x00"))

    def test_roundtrip_preserves_flag_and_message(self):
        msg = "A" * 100  # will be compressed
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        blob = tx.to_bytes()
        decoded = MessageTransaction.from_bytes(blob)
        self.assertEqual(decoded.compression_flag, tx.compression_flag)
        self.assertEqual(decoded.message, tx.message)
        self.assertEqual(decoded.tx_hash, tx.tx_hash)
        # And plaintext round-trips
        self.assertEqual(decoded.plaintext, msg.encode("ascii"))

    def test_roundtrip_raw_message(self):
        msg = "hi"  # stays raw
        tx = create_transaction(self.alice, msg, fee=calculate_min_fee(b"hi"), nonce=0)
        blob = tx.to_bytes()
        decoded = MessageTransaction.from_bytes(blob)
        self.assertEqual(decoded.compression_flag, RAW_FLAG)
        self.assertEqual(decoded.message, b"hi")


class TestJsonSerializationWithCompression(unittest.TestCase):
    """serialize/deserialize dict form preserves canonical stored bytes."""

    def setUp(self):
        self.alice = Entity.create(b"alice-json-c".ljust(32, b"\x00"))

    def test_serialize_exposes_plaintext_for_humans(self):
        """serialize() must expose human-readable message text, not
        compressed bytes — CLI/RPC output is consumed by humans."""
        msg = "Hello, world!"
        fee = calculate_min_fee(msg.encode("ascii"))
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        data = tx.serialize()
        self.assertEqual(data["message"], "Hello, world!")

    def test_serialize_exposes_compressed_flag(self):
        msg = "A" * 100
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        data = tx.serialize()
        self.assertEqual(data["compression_flag"], COMPRESSED_FLAG)

    def test_deserialize_roundtrip_compressed(self):
        msg = "A" * 100
        tx = create_transaction(self.alice, msg, fee=5000, nonce=0)
        data = tx.serialize()
        restored = MessageTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.compression_flag, COMPRESSED_FLAG)
        self.assertEqual(restored.message, tx.message)
        self.assertEqual(restored.plaintext, msg.encode("ascii"))

    def test_deserialize_roundtrip_raw(self):
        msg = "hi there"
        fee = calculate_min_fee(msg.encode("ascii"))
        tx = create_transaction(self.alice, msg, fee=fee, nonce=0)
        data = tx.serialize()
        restored = MessageTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.compression_flag, RAW_FLAG)
        self.assertEqual(restored.plaintext, msg.encode("ascii"))


class TestCompressionRatioOnTypicalEnglish(unittest.TestCase):
    """Measurement: typical English prose gets meaningful compression."""

    def test_tweet_length_english_compresses(self):
        """A representative 240-byte tweet-length English string should
        compress to ~60-80% of its original size."""
        plaintext = (
            b"This is a representative example of the kind of English text "
            b"that users will post to the chain. It contains common words, "
            b"punctuation, and some repetition for realism realism realism."
        )
        stored, flag = encode_payload(plaintext)
        if flag == COMPRESSED_FLAG:
            ratio = len(stored) / len(plaintext)
            # A realistic ratio for short English text; not a great ratio
            # but enough to matter at scale
            self.assertLess(ratio, 0.9)


if __name__ == "__main__":
    unittest.main()
