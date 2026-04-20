"""Tests for keypair cache file format and authentication.

The cache file format is:

    [4-byte magic = b"MCKC"] [32-byte HMAC-SHA3-256] [JSON payload]

The HMAC is keyed on the validator's private key, so any tampering —
byte flip, wrong key, old pickle blob — fails authentication and the
cache is treated as corrupt (logged, discarded, regenerated).  This
replaces an earlier pickle-based format that turned any local write
into arbitrary code execution as the validator user.
"""

import os
import pickle
import shutil
import tempfile
import unittest

import messagechain.config
from messagechain.identity.identity import Entity

import server


_PICKLE_TRIPWIRE = {"fired": False}


def _pickle_tripwire_callee():
    """Module-level callee so pickle can reference it via REDUCE."""
    _PICKLE_TRIPWIRE["fired"] = True
    return "tripwire-fired"


class _PickleTripwirePayload:
    def __reduce__(self):
        return (_pickle_tripwire_callee, ())


class TestKeypairCacheFormat(unittest.TestCase):
    def setUp(self):
        self.private_key = b"v" * 32
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _cache_path(self):
        return server._keypair_cache_path(
            self.private_key, self.tree_height, self.tmpdir
        )

    def _load_or_create(self):
        return server._load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir
        )

    def _write_file(self, data: bytes) -> None:
        with open(self._cache_path(), "wb") as f:
            f.write(data)

    # ------------------------------------------------------------------
    # Save path
    # ------------------------------------------------------------------

    def test_saved_cache_starts_with_mckc_magic(self):
        """A saved cache file begins with the MCKC magic + 32-byte HMAC."""
        self._load_or_create()
        with open(self._cache_path(), "rb") as f:
            prefix = f.read(4)
        self.assertEqual(prefix, b"MCKC")
        # File must be at least magic + HMAC + 1 byte of payload.
        self.assertGreater(os.path.getsize(self._cache_path()), 4 + 32)

    def test_saved_cache_is_not_pickle(self):
        """Saved cache payload must not be unpickleable — no pickle in the format."""
        self._load_or_create()
        with open(self._cache_path(), "rb") as f:
            blob = f.read()
        # Skip magic + HMAC; what remains must be JSON, not pickle.
        payload = blob[4 + 32:]
        with self.assertRaises(Exception):
            pickle.loads(payload)

    # ------------------------------------------------------------------
    # Load path — happy case
    # ------------------------------------------------------------------

    def test_round_trip_preserves_entity(self):
        """Writing a cache and loading it again yields the same entity."""
        first = self._load_or_create()
        self.assertTrue(os.path.exists(self._cache_path()))
        second = self._load_or_create()
        self.assertEqual(first.entity_id, second.entity_id)
        self.assertEqual(first.keypair.public_key, second.keypair.public_key)

    # ------------------------------------------------------------------
    # Load path — rejection cases
    # ------------------------------------------------------------------

    def test_wrong_magic_regenerates(self):
        """A cache with bad magic is discarded and the entity is rebuilt."""
        self._write_file(b"XXXX" + b"\x00" * 32 + b'{"version":1}')
        entity = self._load_or_create()
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)
        # Cache has been rewritten with the correct magic.
        with open(self._cache_path(), "rb") as f:
            self.assertEqual(f.read(4), b"MCKC")

    def test_bad_hmac_regenerates(self):
        """A cache with correct magic but wrong HMAC is discarded."""
        self._load_or_create()
        path = self._cache_path()
        with open(path, "rb") as f:
            data = bytearray(f.read())
        # Flip a byte inside the HMAC region.
        data[4 + 5] ^= 0xFF
        with open(path, "wb") as f:
            f.write(bytes(data))

        entity = self._load_or_create()
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_planted_pickle_does_not_execute(self):
        """A pickle blob planted in the cache file must not be deserialized.

        This is the critical regression guard against the pre-HMAC format,
        where pickle.load on this file would execute _pickle_tripwire_callee
        (or anything else an attacker named in a REDUCE opcode).
        """
        planted = pickle.dumps(_PickleTripwirePayload())
        # Sanity: the planted blob really does execute on pickle.loads.
        _PICKLE_TRIPWIRE["fired"] = False
        pickle.loads(planted)
        self.assertTrue(
            _PICKLE_TRIPWIRE["fired"],
            "planted payload is not a real pickle tripwire — test is broken",
        )

        _PICKLE_TRIPWIRE["fired"] = False
        self._write_file(planted)
        entity = self._load_or_create()
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)
        self.assertFalse(
            _PICKLE_TRIPWIRE["fired"],
            "planted pickle was unpickled — cache loader still executes pickle",
        )

    def test_truncated_header_regenerates(self):
        """A file shorter than magic + HMAC is handled gracefully."""
        self._write_file(b"MCK")
        entity = self._load_or_create()
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_cache_from_different_private_key_rejected(self):
        """A valid cache written under key A must not authenticate under key B.

        Guards against an attacker copying a cache file between hosts with
        different keys — the HMAC binds the payload to the specific private
        key that produced it.
        """
        a_key = b"A" * 32
        b_key = b"B" * 32
        server._load_or_create_entity(a_key, self.tree_height, self.tmpdir)
        a_path = server._keypair_cache_path(a_key, self.tree_height, self.tmpdir)
        b_path = server._keypair_cache_path(b_key, self.tree_height, self.tmpdir)
        self.assertNotEqual(a_path, b_path)
        with open(a_path, "rb") as f:
            blob = f.read()
        with open(b_path, "wb") as f:
            f.write(blob)

        entity_b = server._load_or_create_entity(b_key, self.tree_height, self.tmpdir)
        fresh_b = Entity.create(b_key, tree_height=self.tree_height)
        self.assertEqual(entity_b.keypair.public_key, fresh_b.keypair.public_key)


if __name__ == "__main__":
    unittest.main()
