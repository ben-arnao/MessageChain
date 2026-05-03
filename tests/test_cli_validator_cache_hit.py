"""CLI must hit the validator's on-disk keypair cache when --data-dir is set.

Observed on live mainnet 2026-04-25: ``python3 -m messagechain transfer
--data-dir /var/lib/messagechain --keyfile /dev/shm/mc-key ...`` hung at
``Entity.create`` for several minutes even though the validator daemon
co-resident on the same host had a perfectly good
``keypair_cache_<digest>.bin`` sitting at ``<data_dir>/`` ready to be
reused.

Root cause:

  * ``_load_cached_entity`` reached into the daemon's
    ``_load_or_create_entity`` to do the cache load.  That entry point
    has two side effects the CLI must NEVER trigger:
      1. On any decode failure it ``os.remove``s the cache file --
         which silently destroys the daemon's good cache so the NEXT
         daemon restart also has to regenerate from scratch.
      2. On cache hit it calls ``_attach_merkle_node_cache``, which
         on its own miss calls ``MerkleNodeCache.build_from_seed`` and
         re-derives every leaf -- the multi-minute wedge the operator
         actually saw, even though the keypair_cache load itself was
         fast.

  * ``_load_cached_entity`` also went through
    ``importlib.util.spec_from_file_location("server.py")`` to reach
    those helpers.  The canonical helpers live at
    ``messagechain.identity.keypair_cache``; reaching for ``server.py``
    drags in the full daemon dependency graph and silently falls
    through to ``return None`` on any import-time failure -- which
    then drops the CLI back into ``Entity.create``.

These tests pin the post-fix invariants:

  * A valid keypair cache file under ``<data_dir>/`` is loaded fast
    (no Entity.create, no MerkleNodeCache build).
  * The cache file is not deleted by the CLI as a side effect, no
    matter what.
  * No data_dir means the personal-wallet path runs and the CLI does
    not crash.

A regression that re-introduces the destructive ``_load_or_create_entity``
call path -- or that re-introduces a heavy ``MerkleNodeCache`` rebuild
on the CLI's signing fast-path -- blows up here instead of after the
operator sits through a 20-30 minute hang on a live production wallet.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from messagechain.config import MERKLE_TREE_HEIGHT
from messagechain.identity.identity import Entity
from messagechain.identity.keypair_cache import (
    encode_keypair_cache,
    keypair_cache_path,
)


_PRIVATE_KEY = bytes(range(32))


def _build_cache_in_tmp(data_dir: str, tree_height: int) -> Entity:
    """Create a real Entity and write its cache file under *data_dir*.

    Mirrors what the daemon's ``_load_or_create_entity`` writes on a
    cache miss, so the on-disk shape the CLI sees is byte-for-byte
    what a co-resident validator would have produced.
    """
    entity = Entity.create(_PRIVATE_KEY, tree_height=tree_height)
    blob = encode_keypair_cache(entity, _PRIVATE_KEY, tree_height)
    cache_path = keypair_cache_path(_PRIVATE_KEY, tree_height, data_dir)
    os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(blob)
    return entity


class TestCliValidatorCacheHit(unittest.TestCase):
    """``_resolve_signing_entity`` reads ``<data_dir>/keypair_cache_*.bin``."""

    def test_resolve_signing_entity_with_data_dir_uses_disk_cache(self):
        from messagechain import cli as cli_mod

        with tempfile.TemporaryDirectory(prefix="mc-validator-cache-") as data_dir:
            real_entity = _build_cache_in_tmp(data_dir, MERKLE_TREE_HEIGHT)
            cache_path = keypair_cache_path(
                _PRIVATE_KEY, MERKLE_TREE_HEIGHT, data_dir,
            )
            self.assertTrue(os.path.exists(cache_path), "test setup invariant")

            args = argparse.Namespace(data_dir=data_dir)

            entity_create_called = {"n": 0}
            real_create = Entity.create

            def counting_create(*a, **kw):
                entity_create_called["n"] += 1
                return real_create(*a, **kw)

            with patch.object(Entity, "create", side_effect=counting_create):
                t0 = time.monotonic()
                loaded = cli_mod._resolve_signing_entity(_PRIVATE_KEY, args)
                elapsed = time.monotonic() - t0

            self.assertIsNotNone(loaded, "cache hit must return an Entity")
            self.assertEqual(
                loaded.entity_id, real_entity.entity_id,
                "cache hit must reconstruct the same entity_id as the "
                "originally-cached entity",
            )
            self.assertEqual(
                loaded.keypair.public_key, real_entity.keypair.public_key,
                "cache hit must reconstruct the same public key",
            )
            self.assertEqual(
                entity_create_called["n"], 0,
                "Entity.create must NOT be called on a cache hit -- "
                "every call eats a 2^tree_height WOTS+ keygen and is "
                "the exact wedge this fix exists to prevent.",
            )
            # 1.0s is plenty of headroom for a millisecond cache read +
            # KeyPair._from_trusted_root.  A full Entity.create at
            # tree_height=4 alone is on the order of tens of
            # milliseconds; if this assertion ever starts firing
            # because of cache-read overhead, the CLI is doing real
            # keygen work and the fix has regressed.
            self.assertLess(
                elapsed, 1.0,
                f"cache-hit path must be fast (<1s); took {elapsed:.3f}s "
                f"-- a real regeneration most likely slipped in",
            )
            # Regression guard: the CLI must NOT delete the daemon's
            # cache file as a side effect of loading it.  The previous
            # implementation routed through ``_load_or_create_entity``,
            # which ``os.remove``s the cache on any decode failure --
            # silently destroying the daemon's good cache so the next
            # daemon restart also has to regenerate from scratch.
            self.assertTrue(
                os.path.exists(cache_path),
                "CLI must NOT delete the daemon's cache file as a "
                "side effect of reading it",
            )

    def test_cache_hit_does_not_trigger_merkle_node_cache_build(self):
        """The Merkle node cache build is the actual multi-minute wedge.

        ``_load_or_create_entity`` -> ``_attach_merkle_node_cache`` ->
        ``MerkleNodeCache.build_from_seed`` re-derives every leaf at
        ``tree_height`` whenever the merkle cache file is absent.  At
        ``tree_height=20`` that's ~20-30 min on an e2-small.  The
        CLI's signing fast-path must never trigger that build -- it's
        the daemon's job, not the CLI's, and a missing daemon cache
        is not the operator's problem.
        """
        from messagechain import cli as cli_mod
        from messagechain.crypto import merkle_cache as merkle_cache_mod

        with tempfile.TemporaryDirectory(prefix="mc-validator-cache-") as data_dir:
            _build_cache_in_tmp(data_dir, MERKLE_TREE_HEIGHT)

            args = argparse.Namespace(data_dir=data_dir)

            build_called = {"n": 0}
            real_build = merkle_cache_mod.MerkleNodeCache.build_from_seed

            def counting_build(*a, **kw):
                build_called["n"] += 1
                return real_build(*a, **kw)

            with patch.object(
                merkle_cache_mod.MerkleNodeCache,
                "build_from_seed",
                side_effect=counting_build,
            ):
                loaded = cli_mod._resolve_signing_entity(_PRIVATE_KEY, args)

            self.assertIsNotNone(loaded)
            self.assertEqual(
                build_called["n"], 0,
                "MerkleNodeCache.build_from_seed must NOT be called "
                "from the CLI's cache-hit path -- it derives every "
                "leaf at tree_height and is the actual multi-minute "
                "wedge the operator hit.",
            )

    def test_resolve_signing_entity_without_data_dir_does_not_crash(self):
        """No ``--data-dir`` -> falls through to the personal-wallet flow.

        On a fresh sandboxed HOME (conftest installs one) and no
        keyfile-style cache, this either hits the personal-wallet
        cache (if a prior test populated it) or pays one Entity.create
        at the test-shrunk tree_height=4.  Either way: no crash, no
        TypeError, no AttributeError.
        """
        from messagechain import cli as cli_mod

        args = argparse.Namespace(data_dir=None)
        entity = cli_mod._resolve_signing_entity(_PRIVATE_KEY, args)
        self.assertIsNotNone(entity)
        # The personal-wallet path returns a real Entity with a
        # populated entity_id; pin the invariant so a future refactor
        # can't silently return a half-initialised stand-in.
        self.assertEqual(len(entity.entity_id), 32)


if __name__ == "__main__":
    unittest.main()
