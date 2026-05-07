"""Tests for the HMAC-tagged state-snapshot envelope (1.59.1).

Audit r29 #1: ``pickle.loads`` on persisted state-snapshot blobs is a
local-RCE primitive on tampered DB / restored backup.  An attacker
who can write a single row in ``chain.db.state_snapshots`` (a
tampered backup tape, a misconfigured-permissions data dir, a
restored-from-untrusted snapshot) gets arbitrary code execution at
validator-process privilege the next time the node cold-boots,
reorgs, or runs a fork-emergency rewind, BEFORE any signature or
state-root check fires.

The fix wraps every persisted snapshot in an HMAC-SHA256 envelope
keyed by a per-node secret stored in chaindb's ``meta`` table.  On
read, the tag is verified in constant time before ``pickle.loads``
is ever called; an envelope that fails verification raises
``SnapshotEnvelopeError`` and the caller falls back to the legacy
field-by-field load.

These tests pin the envelope contract.  The blockchain-integration
side (the three pickle.loads call sites at blockchain.py:1236, 14734,
14929 falling back gracefully on tampered/legacy blobs) is covered
in test_snapshot_envelope_blockchain_integration.py.
"""

from __future__ import annotations

import unittest

from messagechain.storage.state_snapshot_envelope import (
    MAGIC,
    SnapshotEnvelopeError,
    generate_secret,
    is_envelope,
    pack,
    unpack,
)


class TestSnapshotEnvelopeRoundTrip(unittest.TestCase):
    def test_round_trip_returns_original_payload(self):
        secret = generate_secret()
        payload = b"hello world (pickle blob stand-in)"
        blob = pack(payload, secret)
        self.assertEqual(unpack(blob, secret), payload)

    def test_round_trip_with_arbitrary_bytes(self):
        # Real pickle blobs contain control bytes, high bits, NULs.
        secret = generate_secret()
        payload = bytes(range(256)) * 4
        blob = pack(payload, secret)
        self.assertEqual(unpack(blob, secret), payload)

    def test_round_trip_with_empty_payload(self):
        # Edge case: zero-byte payload still authenticates.
        secret = generate_secret()
        blob = pack(b"", secret)
        self.assertEqual(unpack(blob, secret), b"")

    def test_blob_carries_magic_prefix(self):
        secret = generate_secret()
        blob = pack(b"x", secret)
        self.assertEqual(blob[:len(MAGIC)], MAGIC)
        self.assertTrue(is_envelope(blob))


class TestSnapshotEnvelopeRejection(unittest.TestCase):
    """Every flavor of "untrusted blob" must raise -- the security
    contract is that ``unpack`` returns a payload only when the blob
    was packed by THIS node's secret.  Anything else raises and the
    caller MUST NOT call ``pickle.loads`` on the blob."""

    def test_legacy_unprefixed_pickle_blob_rejected(self):
        # A pre-1.59.1 chaindb has raw pickle blobs without the magic
        # prefix.  Those must fail to unpack so ``pickle.loads`` never
        # runs on them after upgrade.  Instead, the caller's
        # try/except falls through to legacy field-by-field load.
        import pickle
        secret = generate_secret()
        legacy_blob = pickle.dumps({"balances": {}, "staked": {}})
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(legacy_blob, secret)

    def test_tampered_payload_byte_flip_rejected(self):
        secret = generate_secret()
        original = pack(b"some-payload-bytes-here-and-here", secret)
        # Flip a single byte in the payload region.
        tampered = bytearray(original)
        tampered[-1] ^= 0xFF
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(bytes(tampered), secret)

    def test_tampered_tag_byte_flip_rejected(self):
        secret = generate_secret()
        original = pack(b"some-payload-bytes-here-and-here", secret)
        tampered = bytearray(original)
        # Flip a byte inside the HMAC tag region.
        tampered[len(MAGIC) + 5] ^= 0x01
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(bytes(tampered), secret)

    def test_truncated_blob_rejected(self):
        secret = generate_secret()
        original = pack(b"some-payload", secret)
        # Truncate inside the tag region.
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(original[:20], secret)
        # Truncate to less than even the magic.
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(b"MC", secret)
        # Empty blob.
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(b"", secret)

    def test_different_secret_rejects_blob(self):
        # Cross-node: a snapshot written under node A's secret must
        # not unpack under node B's secret.  Defends against an
        # attacker copying a snapshot from one validator to another.
        secret_a = generate_secret()
        secret_b = generate_secret()
        self.assertNotEqual(secret_a, secret_b)
        blob = pack(b"node-A-snapshot", secret_a)
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(blob, secret_b)
        # Sanity: A's own secret still unpacks.
        self.assertEqual(unpack(blob, secret_a), b"node-A-snapshot")

    def test_wrong_magic_rejected(self):
        secret = generate_secret()
        # An attacker who knows the format but uses a different magic
        # (e.g. old MCSNAPv0, a typo, or attacker-controlled junk)
        # must be rejected at the magic check before HMAC even runs.
        bad = b"NOTMAGIC" + b"\x00" * 32 + b"payload"
        self.assertEqual(len(bad[:8]), 8)  # parity with MAGIC length
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(bad, secret)

    def test_attacker_forged_envelope_rejected(self):
        # Concrete attacker scenario: the attacker knows the wire
        # format and packs a malicious payload (a pickle blob that,
        # if pickle.loads runs, would execute attacker code).  They
        # do NOT have the defender's per-node secret, so they HMAC
        # under their own secret.  The defender's ``unpack`` must
        # reject before ``pickle.loads`` is ever called.
        secret = generate_secret()
        attacker_secret = generate_secret()
        self.assertNotEqual(secret, attacker_secret)
        # Use raw bytes for the payload -- the test doesn't depend on
        # them being a valid pickle, only on the envelope rejecting
        # them so the caller never reaches ``pickle.loads``.
        evil_payload = b"\x80\x04" + b"<arbitrary attacker-controlled>"
        evil_blob = pack(evil_payload, attacker_secret)
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(evil_blob, secret)


class TestSnapshotEnvelopeIsEnvelope(unittest.TestCase):
    def test_recognizes_packed_blob(self):
        secret = generate_secret()
        self.assertTrue(is_envelope(pack(b"x", secret)))

    def test_rejects_legacy_pickle_blob(self):
        import pickle
        legacy = pickle.dumps({"a": 1})
        self.assertFalse(is_envelope(legacy))

    def test_rejects_short_blob(self):
        self.assertFalse(is_envelope(b""))
        self.assertFalse(is_envelope(b"MC"))

    def test_rejects_non_bytes(self):
        self.assertFalse(is_envelope(None))
        self.assertFalse(is_envelope("MCSNAPv1..."))


class TestSnapshotEnvelopeApiContract(unittest.TestCase):
    def test_pack_rejects_empty_secret(self):
        with self.assertRaises(ValueError):
            pack(b"x", b"")

    def test_pack_rejects_non_bytes_payload(self):
        with self.assertRaises(TypeError):
            pack("not bytes", generate_secret())

    def test_unpack_rejects_empty_secret(self):
        with self.assertRaises(SnapshotEnvelopeError):
            unpack(pack(b"x", generate_secret()), b"")

    def test_generate_secret_is_unique(self):
        # Statistical sanity -- 100 secrets should all differ.
        secrets_seen = {generate_secret() for _ in range(100)}
        self.assertEqual(len(secrets_seen), 100)

    def test_generate_secret_length(self):
        s = generate_secret()
        self.assertEqual(len(s), 32)


if __name__ == "__main__":
    unittest.main()
