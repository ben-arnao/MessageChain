"""
Tests for pinned genesis hash.

Without a pinned genesis, two nodes starting `--mine` on empty data dirs
each mint their own genesis, creating permanently incompatible chains.
With PINNED_GENESIS_HASH set in config, only a single bootstrap
initialize_genesis is allowed to exist network-wide; every other node
must sync block 0 from peers and reject any mismatch.
"""

import unittest

from messagechain import config
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


def _entity(seed: bytes, height: int = 6) -> Entity:
    return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=height)


class _Base(unittest.TestCase):
    def setUp(self):
        self._orig_height = config.MERKLE_TREE_HEIGHT
        self._orig_pinned = getattr(config, "PINNED_GENESIS_HASH", None)
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        config.MERKLE_TREE_HEIGHT = self._orig_height
        config.PINNED_GENESIS_HASH = self._orig_pinned


class TestUnpinnedGenesisPreservesOldBehavior(_Base):
    """When PINNED_GENESIS_HASH is None (dev/test), anyone can mint genesis."""

    def test_initialize_genesis_works_without_pin(self):
        config.PINNED_GENESIS_HASH = None
        chain = Blockchain()
        entity = _entity(b"alice")
        genesis = chain.initialize_genesis(entity)
        self.assertIsNotNone(genesis)


class TestPinnedGenesisEnforced(_Base):
    """When PINNED_GENESIS_HASH is set, arbitrary genesis creation is refused."""

    def test_initialize_genesis_rejected_when_hash_mismatches(self):
        """A node starting with empty data and a mismatching pinned hash
        must NOT be allowed to mint its own genesis."""
        config.PINNED_GENESIS_HASH = b"\xff" * 32  # arbitrary, won't match
        chain = Blockchain()
        entity = _entity(b"alice")
        with self.assertRaises(RuntimeError) as ctx:
            chain.initialize_genesis(entity)
        self.assertIn("pinned", str(ctx.exception).lower())

    def test_initialize_genesis_accepted_when_hash_matches(self):
        """The single bootstrap node whose genesis happens to match the pin
        is allowed through."""
        chain = Blockchain()
        entity = _entity(b"bootstrap")
        # Mint once unpinned to discover what its hash would be
        config.PINNED_GENESIS_HASH = None
        genesis = chain.initialize_genesis(entity)
        expected_hash = genesis.block_hash

        # Fresh chain with the hash pinned to that exact value — should work.
        chain2 = Blockchain()
        config.PINNED_GENESIS_HASH = expected_hash
        entity2 = _entity(b"bootstrap")  # same seed = same identity
        g2 = chain2.initialize_genesis(entity2)
        self.assertEqual(g2.block_hash, expected_hash)


if __name__ == "__main__":
    unittest.main()
