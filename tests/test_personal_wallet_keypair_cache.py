"""Tests for the personal-wallet keypair cache.

The personal wallet (no --data-dir on the CLI) used to regenerate the
WOTS+ Merkle tree from scratch on every signing command, which on the
production tree height takes ~20-30 minutes per send and makes the
README's "send your first message" walkthrough unusable.  These tests
exercise the new ``~/.messagechain/wallet_cache/`` cache that fixes
that — same HMAC-authenticated on-disk format the daemon already uses,
but rooted at the user's home directory instead of a daemon data_dir.
"""

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import messagechain.config
from messagechain.identity.identity import Entity
from messagechain.identity.keypair_cache import (
    encode_keypair_cache,
    decode_keypair_cache,
    keypair_cache_path,
    load_or_create_personal_wallet_entity,
    personal_wallet_cache_dir,
    personal_wallet_cache_path,
)


_PRIV_A = b"a" * 32
_PRIV_B = b"b" * 32


class TestPersonalWalletCacheLayout(unittest.TestCase):
    """The personal-wallet cache lives under ~/.messagechain/wallet_cache/."""

    def setUp(self):
        # conftest already redirects HOME / USERPROFILE to a per-session
        # temp dir.  Use a per-test subdir so we never trip over leftover
        # cache files written by another test.
        self.home = tempfile.mkdtemp(prefix="mc-personal-wallet-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home}
        )
        self._home_patch.start()
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_cache_dir_under_home(self):
        """Cache root is ~/.messagechain/wallet_cache/."""
        d = personal_wallet_cache_dir()
        self.assertEqual(
            Path(d).resolve(),
            (Path(self.home) / ".messagechain" / "wallet_cache").resolve(),
        )

    def test_cache_path_varies_with_key_and_height(self):
        """Different keys and heights produce different paths, like the daemon cache."""
        p1 = personal_wallet_cache_path(_PRIV_A, self.tree_height)
        p2 = personal_wallet_cache_path(_PRIV_B, self.tree_height)
        p3 = personal_wallet_cache_path(_PRIV_A, self.tree_height + 1)
        self.assertNotEqual(p1, p2)
        self.assertNotEqual(p1, p3)
        self.assertNotEqual(p2, p3)


class TestPersonalWalletCacheRoundTrip(unittest.TestCase):
    """Cold + warm + corrupt-rejection round trip for the personal-wallet cache."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="mc-personal-wallet-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home}
        )
        self._home_patch.start()
        self.tree_height = messagechain.config.MERKLE_TREE_HEIGHT
        self.private_key = _PRIV_A

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def _path(self):
        return personal_wallet_cache_path(self.private_key, self.tree_height)

    def test_cold_first_call_writes_cache(self):
        """First call must materialize a cache file under ~/.messagechain/wallet_cache/."""
        self.assertFalse(os.path.exists(self._path()))
        entity = load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        self.assertTrue(os.path.exists(self._path()))

        # File must start with MCKC magic (matches the daemon's cache).
        with open(self._path(), "rb") as f:
            self.assertEqual(f.read(4), b"MCKC")

        # Reconstructed entity must match a fresh keygen byte-for-byte.
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.entity_id, fresh.entity_id)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_warm_call_uses_cache(self):
        """A second call must read from the cache instead of regenerating."""
        # Cold: populate cache.
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        # Warm: monkey-patch Entity.create to fail loudly so any code path
        # that bypasses the cache is caught.
        from messagechain.identity import identity as _id_mod
        with mock.patch.object(
            _id_mod.Entity, "create",
            side_effect=AssertionError(
                "Warm path must not call Entity.create — that's the slow keygen"
            ),
        ):
            entity = load_or_create_personal_wallet_entity(
                self.private_key, tree_height=self.tree_height,
            )
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.entity_id, fresh.entity_id)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_warm_call_is_orders_of_magnitude_faster_than_cold(self):
        """Warm-path wall-clock must be small relative to a fresh Entity.create.

        At test tree_height=4 the cold path is already cheap (microseconds
        of leaf derivation), so this asserts the warm path is at least 5x
        faster than a fresh Entity.create — enough margin to detect a
        regression where the cache is silently bypassed without being so
        tight that scheduling jitter flakes the test.
        """
        # Cold-populate the cache once so subsequent calls hit the warm path.
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )

        # Time a fresh keygen.
        t0 = time.perf_counter()
        Entity.create(self.private_key, tree_height=self.tree_height)
        cold_elapsed = time.perf_counter() - t0

        # Time the warm path.
        t0 = time.perf_counter()
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        warm_elapsed = time.perf_counter() - t0

        # Floor the cold-elapsed measurement to dodge timer-resolution flake
        # at sub-millisecond cold paths (test height is tiny).
        cold_elapsed = max(cold_elapsed, 1e-3)
        self.assertLess(
            warm_elapsed, cold_elapsed / 5,
            f"warm={warm_elapsed*1000:.2f}ms cold={cold_elapsed*1000:.2f}ms "
            f"— cache appears to be regenerating",
        )

    def test_bad_mac_is_rejected(self):
        """A cache file with a tampered HMAC must NOT yield a usable keypair from stolen material."""
        # Cold-write the cache.
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        path = self._path()
        with open(path, "rb") as f:
            data = bytearray(f.read())
        # Flip a byte inside the HMAC region (offset 4..36).
        data[4 + 5] ^= 0xFF
        with open(path, "wb") as f:
            f.write(bytes(data))

        # The decoder must refuse the tampered file and the loader must
        # regenerate from scratch — reaching the same public key but ONLY
        # because the loader has access to the private key.  A reader who
        # only had the cache file and a wrong/forged private key would
        # never authenticate this blob.
        decoded = decode_keypair_cache(
            bytes(data), self.private_key, self.tree_height,
        )
        self.assertIsNone(decoded, "tampered HMAC must fail decode")

        # End-to-end: load_or_create still returns the right entity (by
        # regenerating), so the user never sees a wrong identity from a
        # corrupt cache.
        entity = load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.keypair.public_key, fresh.keypair.public_key)

    def test_stolen_cache_useless_without_seed(self):
        """A cache file alone, without the private key, must not yield a keypair."""
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        with open(self._path(), "rb") as f:
            blob = f.read()
        # Attacker tries to decode with a wrong private key — must fail.
        wrong_key = b"z" * 32
        decoded = decode_keypair_cache(blob, wrong_key, self.tree_height)
        self.assertIsNone(decoded)

    def test_height_separation(self):
        """Cache hits at the same seed but different height must NOT cross-contaminate.

        The cache key embeds (private_key, tree_height) so a request at a
        new height must find the slot empty — never a stale entry from a
        previous height masquerading as the new one.
        """
        # Populate height=4.
        e4 = load_or_create_personal_wallet_entity(
            self.private_key, tree_height=4,
        )
        self.assertTrue(
            os.path.exists(personal_wallet_cache_path(self.private_key, 4))
        )
        # height=5 must NOT see the height=4 cache.
        self.assertFalse(
            os.path.exists(personal_wallet_cache_path(self.private_key, 5))
        )
        e5 = load_or_create_personal_wallet_entity(
            self.private_key, tree_height=5,
        )
        # The two trees produce different public keys (different roots).
        self.assertNotEqual(e4.keypair.public_key, e5.keypair.public_key)
        self.assertNotEqual(e4.entity_id, e5.entity_id)
        # Height=4 cache file remains intact alongside the new height=5 file.
        self.assertTrue(
            os.path.exists(personal_wallet_cache_path(self.private_key, 4))
        )
        self.assertTrue(
            os.path.exists(personal_wallet_cache_path(self.private_key, 5))
        )

    def test_cache_survives_across_invocations(self):
        """Simulate the 'second CLI run' case: file persists, second call is warm."""
        # First "invocation".
        load_or_create_personal_wallet_entity(
            self.private_key, tree_height=self.tree_height,
        )
        # Second "invocation" — make sure the cache file is still there
        # and the warm path is taken.
        self.assertTrue(os.path.exists(self._path()))
        from messagechain.identity import identity as _id_mod
        with mock.patch.object(
            _id_mod.Entity, "create",
            side_effect=AssertionError(
                "Persistent cache file must give a warm path on the second run"
            ),
        ):
            entity = load_or_create_personal_wallet_entity(
                self.private_key, tree_height=self.tree_height,
            )
        fresh = Entity.create(self.private_key, tree_height=self.tree_height)
        self.assertEqual(entity.entity_id, fresh.entity_id)


class TestSharedEncodingWithDaemon(unittest.TestCase):
    """Personal-wallet cache uses the same encode/decode helpers as the daemon."""

    def test_server_helpers_alias_shared_module(self):
        """server.py's _encode/_decode_keypair_cache are the shared module's symbols."""
        import server
        self.assertIs(server._encode_keypair_cache, encode_keypair_cache)
        self.assertIs(server._decode_keypair_cache, decode_keypair_cache)
        self.assertIs(server._keypair_cache_path, keypair_cache_path)

    def test_round_trip_through_shared_helpers(self):
        """encode_keypair_cache + decode_keypair_cache reconstructs a usable Entity."""
        priv = _PRIV_A
        height = messagechain.config.MERKLE_TREE_HEIGHT
        entity = Entity.create(priv, tree_height=height)
        blob = encode_keypair_cache(entity, priv, height)
        decoded = decode_keypair_cache(blob, priv, height)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.entity_id, entity.entity_id)
        self.assertEqual(decoded.keypair.public_key, entity.keypair.public_key)


if __name__ == "__main__":
    unittest.main()
