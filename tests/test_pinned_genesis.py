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


class TestDevnetGuard(_Base):
    """Non-devnet mode with PINNED_GENESIS_HASH=None must refuse genesis init."""

    def setUp(self):
        super().setUp()
        self._orig_devnet = config.DEVNET

    def tearDown(self):
        config.DEVNET = self._orig_devnet
        super().tearDown()

    def test_non_devnet_none_pin_raises(self):
        """Production mode (DEVNET=False) with no pinned hash must error."""
        config.DEVNET = False
        config.PINNED_GENESIS_HASH = None
        chain = Blockchain()
        entity = _entity(b"alice")
        with self.assertRaises(RuntimeError) as ctx:
            chain.initialize_genesis(entity)
        msg = str(ctx.exception).lower()
        self.assertIn("pinned_genesis_hash", msg)
        self.assertIn("devnet", msg)

    def test_devnet_none_pin_allowed(self):
        """Devnet mode (DEVNET=True) with no pinned hash is allowed."""
        config.DEVNET = True
        config.PINNED_GENESIS_HASH = None
        chain = Blockchain()
        entity = _entity(b"alice")
        genesis = chain.initialize_genesis(entity)
        self.assertIsNotNone(genesis)

    def test_non_devnet_with_pin_works(self):
        """Production mode with a matching pinned hash works normally."""
        from unittest.mock import patch
        config.DEVNET = False
        with patch("messagechain.core.block.time.time", return_value=1_700_000_000.0), \
             patch("messagechain.consensus.pos.time.time", return_value=1_700_000_000.0):
            # First, create genesis in devnet to get the hash
            config.DEVNET = True
            config.PINNED_GENESIS_HASH = None
            chain = Blockchain()
            entity = _entity(b"bootstrap")
            genesis = chain.initialize_genesis(entity)
            expected_hash = genesis.block_hash

            # Now test production mode with correct pin
            config.DEVNET = False
            config.PINNED_GENESIS_HASH = expected_hash
            chain2 = Blockchain()
            entity2 = _entity(b"bootstrap")
            g2 = chain2.initialize_genesis(entity2)
            self.assertEqual(g2.block_hash, expected_hash)


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
        is allowed through.  The genesis block's timestamp comes from
        time.time() inside create_genesis_block, so we pin wall-clock time
        to make the block hash reproducible across the two mints below."""
        from unittest.mock import patch
        with patch("messagechain.core.block.time.time", return_value=1_700_000_000.0), \
             patch("messagechain.consensus.pos.time.time", return_value=1_700_000_000.0):
            chain = Blockchain()
            entity = _entity(b"bootstrap")
            config.PINNED_GENESIS_HASH = None
            genesis = chain.initialize_genesis(entity)
            expected_hash = genesis.block_hash

            chain2 = Blockchain()
            config.PINNED_GENESIS_HASH = expected_hash
            entity2 = _entity(b"bootstrap")  # same seed = same identity
            g2 = chain2.initialize_genesis(entity2)
            self.assertEqual(g2.block_hash, expected_hash)


if __name__ == "__main__":
    unittest.main()
