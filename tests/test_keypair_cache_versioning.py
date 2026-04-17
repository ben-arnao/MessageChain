"""Tests for keypair cache file versioning.

The cache file format is:

    [4-byte magic = b"MCKP"] [1-byte version] [pickled Entity]

On load, both the magic and version must match, otherwise the cache is
treated as corrupt (logged, discarded, regenerated).  This guards against
silently loading an object pickled by an older/incompatible version of the
code — a real hazard on a 1000-year chain where class layouts can drift.
"""

import os
import pickle
import shutil
import tempfile
import unittest

import messagechain.config
from messagechain.identity.identity import Entity

import server


class TestKeypairCacheVersioning(unittest.TestCase):
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

    # ------------------------------------------------------------------
    # Constants exposed at module level
    # ------------------------------------------------------------------

    def test_module_defines_magic_and_version(self):
        """Module constants are present with expected values."""
        self.assertEqual(server.KEYPAIR_CACHE_MAGIC, b"MCKP")
        self.assertEqual(len(server.KEYPAIR_CACHE_MAGIC), 4)
        self.assertIsInstance(server.KEYPAIR_CACHE_VERSION, int)
        self.assertGreaterEqual(server.KEYPAIR_CACHE_VERSION, 1)
        # Version must fit in a single byte so the header stays 5 bytes.
        self.assertLess(server.KEYPAIR_CACHE_VERSION, 256)

    # ------------------------------------------------------------------
    # Save path
    # ------------------------------------------------------------------

    def test_saved_cache_starts_with_magic_and_version(self):
        """A saved cache file begins with magic + version header."""
        self._load_or_create()  # generates and saves the cache

        path = self._cache_path()
        self.assertTrue(os.path.exists(path))

        with open(path, "rb") as f:
            header = f.read(5)
        self.assertEqual(header[:4], server.KEYPAIR_CACHE_MAGIC)
        self.assertEqual(header[4], server.KEYPAIR_CACHE_VERSION)

    def test_saved_cache_payload_is_pickled_entity(self):
        """The bytes after the 5-byte header unpickle to an Entity."""
        self._load_or_create()
        with open(self._cache_path(), "rb") as f:
            f.read(5)  # skip header
            obj = pickle.load(f)
        self.assertIsInstance(obj, Entity)

    # ------------------------------------------------------------------
    # Load path — happy case
    # ------------------------------------------------------------------

    def test_load_with_correct_header_succeeds(self):
        """Writing a cache and loading it again yields the same entity."""
        first = self._load_or_create()
        # Sanity: cache file exists with the correct header.
        self.assertTrue(os.path.exists(self._cache_path()))

        second = self._load_or_create()
        self.assertEqual(first.entity_id, second.entity_id)
        self.assertEqual(first.keypair.public_key, second.keypair.public_key)

    # ------------------------------------------------------------------
    # Load path — rejection cases
    # ------------------------------------------------------------------

    def _write_file(self, data: bytes) -> None:
        with open(self._cache_path(), "wb") as f:
            f.write(data)

    def test_load_with_wrong_magic_regenerates(self):
        """A cache with bad magic is discarded and the entity is rebuilt."""
        # Write a file that has valid pickle body but wrong magic.
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        bad_magic = b"XXXX"
        self.assertNotEqual(bad_magic, server.KEYPAIR_CACHE_MAGIC)
        payload = bad_magic + bytes([server.KEYPAIR_CACHE_VERSION]) + pickle.dumps(fresh)
        self._write_file(payload)

        # Should NOT raise — should log and regenerate.
        entity = self._load_or_create()
        self.assertEqual(entity.entity_id, fresh.entity_id)

        # After regeneration, the cache on disk is rewritten with a proper
        # header.
        with open(self._cache_path(), "rb") as f:
            header = f.read(5)
        self.assertEqual(header[:4], server.KEYPAIR_CACHE_MAGIC)
        self.assertEqual(header[4], server.KEYPAIR_CACHE_VERSION)

    def test_load_with_wrong_version_regenerates(self):
        """A cache with correct magic but unknown version is discarded."""
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        bad_version = (server.KEYPAIR_CACHE_VERSION + 7) % 256
        self.assertNotEqual(bad_version, server.KEYPAIR_CACHE_VERSION)
        payload = (
            server.KEYPAIR_CACHE_MAGIC
            + bytes([bad_version])
            + pickle.dumps(fresh)
        )
        self._write_file(payload)

        entity = self._load_or_create()
        self.assertEqual(entity.entity_id, fresh.entity_id)

        # Cache has been rewritten with the current version.
        with open(self._cache_path(), "rb") as f:
            header = f.read(5)
        self.assertEqual(header[4], server.KEYPAIR_CACHE_VERSION)

    def test_load_pre_versioning_raw_pickle_regenerates(self):
        """Old-format caches (raw pickle, no magic header) are discarded.

        This is the migration case: a node upgraded from the pre-versioning
        build will have a raw pickle on disk.  The first 5 bytes of a pickle
        stream do NOT start with b"MCKP", so the magic check rejects them
        and the cache is regenerated safely.
        """
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self._write_file(pickle.dumps(fresh))  # no header — legacy format

        entity = self._load_or_create()
        self.assertEqual(entity.entity_id, fresh.entity_id)

        # After the call, the cache file is in the new format.
        with open(self._cache_path(), "rb") as f:
            header = f.read(5)
        self.assertEqual(header[:4], server.KEYPAIR_CACHE_MAGIC)
        self.assertEqual(header[4], server.KEYPAIR_CACHE_VERSION)

    def test_load_truncated_header_regenerates(self):
        """A file shorter than the 5-byte header is handled gracefully."""
        self._write_file(b"MCK")  # only 3 bytes — not even a full magic

        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        entity = self._load_or_create()
        self.assertEqual(entity.entity_id, fresh.entity_id)


if __name__ == "__main__":
    unittest.main()
