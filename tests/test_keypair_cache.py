"""Tests for keypair disk cache in server.py."""

import hashlib
import os
import pickle
import tempfile
import unittest

import messagechain.config
from messagechain.identity.identity import Entity


class TestKeypairCache(unittest.TestCase):
    """Verify that the keypair cache produces identical entities."""

    def setUp(self):
        self.private_key = b"x" * 32  # meets MIN_PRIVATE_KEY_BYTES
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT  # 4 in tests
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        # Clean up cache files
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _cache_path(self):
        """Compute the expected cache file path."""
        from server import _keypair_cache_path
        return _keypair_cache_path(self.private_key, self.tree_height, self.tmpdir)

    def _load_or_create(self, **kwargs):
        from server import _load_or_create_entity
        return _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir, **kwargs
        )

    def test_cache_key_deterministic(self):
        """Cache path is deterministic for the same inputs."""
        from server import _keypair_cache_path
        p1 = _keypair_cache_path(self.private_key, self.tree_height, self.tmpdir)
        p2 = _keypair_cache_path(self.private_key, self.tree_height, self.tmpdir)
        self.assertEqual(p1, p2)

    def test_cache_key_varies_with_key(self):
        """Different private keys produce different cache paths."""
        from server import _keypair_cache_path
        p1 = _keypair_cache_path(b"a" * 32, self.tree_height, self.tmpdir)
        p2 = _keypair_cache_path(b"b" * 32, self.tree_height, self.tmpdir)
        self.assertNotEqual(p1, p2)

    def test_cache_key_varies_with_height(self):
        """Different tree heights produce different cache paths."""
        from server import _keypair_cache_path
        p1 = _keypair_cache_path(self.private_key, 4, self.tmpdir)
        p2 = _keypair_cache_path(self.private_key, 8, self.tmpdir)
        self.assertNotEqual(p1, p2)

    def test_cached_entity_matches_fresh(self):
        """Loading from cache produces same entity_id and public_key as fresh."""
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)

        # First call creates cache
        cached1 = self._load_or_create()
        self.assertEqual(cached1.entity_id, fresh.entity_id)
        self.assertEqual(cached1.keypair.public_key, fresh.keypair.public_key)

        # Verify cache file was created
        self.assertTrue(os.path.exists(self._cache_path()))

        # Second call loads from cache
        cached2 = self._load_or_create()
        self.assertEqual(cached2.entity_id, fresh.entity_id)
        self.assertEqual(cached2.keypair.public_key, fresh.keypair.public_key)

    def test_corrupt_cache_falls_back(self):
        """Corrupt cache file is deleted and entity is recreated."""
        # Create a corrupt cache file
        path = self._cache_path()
        with open(path, "wb") as f:
            f.write(b"corrupt data that is not valid pickle")

        entity = self._load_or_create()
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)

        self.assertEqual(entity.entity_id, fresh.entity_id)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_no_cache_flag(self):
        """When no_cache=True, no cache file is created."""
        entity = self._load_or_create(no_cache=True)
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)

        self.assertEqual(entity.entity_id, fresh.entity_id)
        self.assertFalse(os.path.exists(self._cache_path()))

    def test_cache_without_data_dir(self):
        """When data_dir is None, behaves like no_cache (no crash)."""
        from server import _load_or_create_entity
        entity = _load_or_create_entity(self.private_key, self.tree_height, None)
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.entity_id, fresh.entity_id)


if __name__ == "__main__":
    unittest.main()
