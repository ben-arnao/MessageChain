"""Integration tests for leaf_index_path wiring in production code paths.

The persistence mechanism lives on KeyPair (see test_crypto_security_high.py
and test_leaf_index_hardening.py), but is only load-bearing when
leaf_index_path is actually set by the production validator-launch path.
These tests guard the wiring itself — the single reason a restart-with-
stale-in-memory-counter can corrupt the WOTS+ one-time-key invariant.
"""

import json
import os
import tempfile
import unittest

import messagechain.config
from messagechain.crypto.keys import _hash
from messagechain.identity.identity import Entity
from server import _load_or_create_entity


class TestValidatorStartupSetsLeafIndexPath(unittest.TestCase):
    """Production init path must configure leaf_index_path on the KeyPair."""

    def setUp(self):
        self.private_key = b"integration-test-seed-for-wiring" + b"\x00" * 1
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT  # 4 in tests
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_leaf_index_path_set_when_data_dir_provided(self):
        """With a data_dir, the loaded entity's keypair has leaf_index_path set."""
        entity = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir, no_cache=True,
        )
        self.assertIsNotNone(entity.keypair.leaf_index_path)
        expected = os.path.join(
            self.tmpdir, messagechain.config.LEAF_INDEX_FILENAME,
        )
        self.assertEqual(entity.keypair.leaf_index_path, expected)

    def test_leaf_index_path_set_even_when_loading_from_cache(self):
        """Cached entities must also get leaf_index_path set on reload.

        The keypair-cache pickle was written BEFORE this wiring existed, so
        leaf_index_path inside it is None — the loader must rebind it.
        """
        # Prime the cache
        _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir,
        )
        # Second call hits the cache
        entity = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir,
        )
        self.assertIsNotNone(entity.keypair.leaf_index_path)


class TestLeafIndexPersistsAcrossRestart(unittest.TestCase):
    """Sign -> shutdown -> reconstruct must never let _next_leaf regress."""

    def setUp(self):
        self.private_key = b"restart-integration-seed-padding" + b"\x00" * 1
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_leaf_index_persists_across_restart(self):
        """Signatures before restart must advance the on-disk leaf index,
        and the post-restart KeyPair must pick up where the old one left off."""
        # Startup 1: load, sign twice
        entity1 = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir, no_cache=True,
        )
        entity1.keypair.sign(_hash(b"msg-1"))
        entity1.keypair.sign(_hash(b"msg-2"))
        used_leaves_before_restart = entity1.keypair._next_leaf
        self.assertEqual(used_leaves_before_restart, 2)

        # Verify the index file exists with the right value
        leaf_path = os.path.join(
            self.tmpdir, messagechain.config.LEAF_INDEX_FILENAME,
        )
        self.assertTrue(os.path.exists(leaf_path))
        with open(leaf_path, "r") as f:
            self.assertEqual(json.load(f)["next_leaf"], 2)

        # Startup 2: new process would reload from disk.  We simulate by
        # forcing no_cache so the KeyPair is fully rebuilt from the seed
        # and only the on-disk leaf_index.json can tell it where to resume.
        entity2 = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir, no_cache=True,
        )
        self.assertEqual(entity2.keypair._next_leaf, 2)

        # Third signature must use leaf 2 (not reuse leaf 0 or 1)
        sig = entity2.keypair.sign(_hash(b"msg-3"))
        self.assertEqual(sig.leaf_index, 2)

    def test_leaf_index_never_regresses_when_cache_stale(self):
        """Even if the pickled cache carries a stale _next_leaf (because the
        pickle captured the keypair at tree-generation time, i.e. _next_leaf=0),
        the restored entity must load the on-disk leaf index and resume."""
        # Startup 1: prime cache + sign once
        entity1 = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir,
        )
        entity1.keypair.sign(_hash(b"msg-first"))
        self.assertEqual(entity1.keypair._next_leaf, 1)

        # Note: the pickle cache was written BEFORE that sign(), so the
        # cached pickle still has _next_leaf == 0.  On reload we expect
        # the loader to consult leaf_index.json and bump it back to 1.

        entity2 = _load_or_create_entity(
            self.private_key, self.tree_height, self.tmpdir,
        )
        self.assertGreaterEqual(entity2.keypair._next_leaf, 1)

        # Second sign must not reuse leaf 0
        sig = entity2.keypair.sign(_hash(b"msg-second"))
        self.assertGreaterEqual(sig.leaf_index, 1)


class TestNoLeafIndexPathWhenNoDataDir(unittest.TestCase):
    """Regression: ephemeral mode (no data_dir) keeps leaf_index_path=None."""

    def test_no_data_dir_keeps_leaf_index_path_none(self):
        private_key = b"ephemeral-test-seed-padding-xxxxx" + b"\x00"
        entity = _load_or_create_entity(
            private_key, messagechain.config.MERKLE_TREE_HEIGHT, None,
        )
        self.assertIsNone(entity.keypair.leaf_index_path)

        # Sign still works without persistence
        sig = entity.keypair.sign(_hash(b"no-persist"))
        self.assertEqual(sig.leaf_index, 0)


if __name__ == "__main__":
    unittest.main()
