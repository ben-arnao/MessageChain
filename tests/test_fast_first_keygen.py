"""Tests for fast first-command keygen UX.

Three independent UX wins ship together:

1. Personal-wallet default tree height is strictly lower than the validator
   default — ``WALLET_DEFAULT_TREE_HEIGHT`` (16 in production) instead of
   ``MERKLE_TREE_HEIGHT`` (20).  Per-entity heights are stored on chain so
   different entities at different heights coexist; validators stay at h=20
   to amortize the larger keygen across ~2 years of slot signing.

2. ``cmd_generate_key`` prints the recovery phrase BEFORE running keygen,
   so the user can back up the 24 words while the tree builds in the
   foreground.  Eliminates the 90-min "blank screen" anxiety window.

3. ``_resolve_signing_entity`` falls back to a legacy ``MERKLE_TREE_HEIGHT``
   cache when the new wallet-default cache is missing — so existing wallets
   from before the default change keep their identity instead of silently
   regenerating at the new height (which would produce a different
   public key and bind a different on-chain entity).
"""

import io
import os
import shutil
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

import messagechain.config
from messagechain.identity.identity import Entity
from messagechain.identity.keypair_cache import (
    encode_keypair_cache,
    load_or_create_personal_wallet_entity,
    personal_wallet_cache_path,
    _atomic_write,
)


_PRIV = b"f" * 32


class TestWalletDefaultIsLowerThanValidator(unittest.TestCase):
    """Anchor: WALLET_DEFAULT_TREE_HEIGHT < MERKLE_TREE_HEIGHT.

    Validators amortize keygen across years of slot signing; personal
    wallets do not.  Forcing the same height on both is what produced
    the original 90-minute first-command wedge.
    """

    def test_wallet_default_strictly_lower(self):
        self.assertLess(
            messagechain.config.WALLET_DEFAULT_TREE_HEIGHT,
            messagechain.config.MERKLE_TREE_HEIGHT,
            "Personal-wallet default must be lower than the validator "
            "default; otherwise the 90-min first-command wedge returns.",
        )


class TestPersonalWalletDefaultsToWalletHeight(unittest.TestCase):
    """After ``cmd_generate_key`` writes a cache at the wallet default,
    the resolver must find it on the very next call -- so the README's
    first-flow keygen cost is paid exactly once.

    The resolver itself defaults to ``MERKLE_TREE_HEIGHT`` on cache
    miss (back-compat for wallets that were never created via
    ``generate-key`` -- e.g. validators, faucet, tests that build
    entities with bare ``Entity.create``).  The wallet-default height
    enters the picture exclusively via ``cmd_generate_key``, which
    writes its cache at the lower height; subsequent resolver calls
    for the same key find that file and skip regeneration.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="mc-fast-keygen-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home},
        )
        self._home_patch.start()

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_resolver_finds_wallet_default_cache_after_generate_key(self):
        """End-to-end: simulate cmd_generate_key warming a cache at the
        wallet default; the resolver must find it instead of regenerating
        at MERKLE_TREE_HEIGHT (which would produce a different identity)."""
        wallet_h = messagechain.config.WALLET_DEFAULT_TREE_HEIGHT
        validator_h = messagechain.config.MERKLE_TREE_HEIGHT
        if wallet_h == validator_h:
            self.skipTest("test config collapses wallet/validator height")

        # Simulate cmd_generate_key: build the entity at the wallet
        # default and write the cache.
        wallet_entity = Entity.create(_PRIV, tree_height=wallet_h)
        cache_path = personal_wallet_cache_path(_PRIV, wallet_h)
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        blob = encode_keypair_cache(wallet_entity, _PRIV, wallet_h)
        _atomic_write(cache_path, blob)

        # Resolver call (no explicit height) must hit the wallet-default
        # cache and return the same identity.
        resolved = load_or_create_personal_wallet_entity(_PRIV)
        self.assertEqual(resolved.keypair.height, wallet_h)
        self.assertEqual(
            resolved.keypair.public_key, wallet_entity.keypair.public_key,
        )


class TestResolveSigningEntityHonorsLegacyCache(unittest.TestCase):
    """A pre-existing cache file at the OLD ``MERKLE_TREE_HEIGHT`` must be
    found by the resolver instead of silently regenerating at the new
    wallet default — that would bind a different public key to the same
    seed and effectively orphan the user's existing on-chain identity."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="mc-fast-keygen-legacy-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home},
        )
        self._home_patch.start()

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_legacy_height_cache_is_preferred_over_fresh_keygen(self):
        # Simulate a pre-upgrade wallet at the validator-default height by
        # forcibly writing a cache there.  This must be a height the wallet-
        # default doesn't already match (skip if test config collapses them).
        wallet_h = messagechain.config.WALLET_DEFAULT_TREE_HEIGHT
        legacy_h = messagechain.config.MERKLE_TREE_HEIGHT
        if legacy_h == wallet_h:
            self.skipTest("test config collapses wallet/validator height")

        legacy_entity = Entity.create(_PRIV, tree_height=legacy_h)
        legacy_path = personal_wallet_cache_path(_PRIV, legacy_h)
        os.makedirs(os.path.dirname(legacy_path), exist_ok=True)
        blob = encode_keypair_cache(legacy_entity, _PRIV, legacy_h)
        _atomic_write(legacy_path, blob)

        # Now call the resolver with no explicit height (the post-upgrade
        # path).  It must FIND the legacy cache rather than regenerate at
        # the new wallet default.
        resolved = load_or_create_personal_wallet_entity(_PRIV)
        self.assertEqual(
            resolved.keypair.public_key, legacy_entity.keypair.public_key,
            "Legacy h=20 cache must be honoured when the resolver runs "
            "with no explicit height — silently regenerating at the new "
            "default would orphan the user's on-chain identity.",
        )
        self.assertEqual(resolved.keypair.height, legacy_h)


class TestRecoveryPhrasePrintedBeforeKeygen(unittest.TestCase):
    """``cmd_generate_key`` must print the recovery phrase BEFORE running
    keygen.  The user can then back up the 24 words during the keygen
    wait, eliminating the "blank screen" anxiety window of the original
    flow where the phrase only appeared at the end."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_phrase_appears_before_keygen_runs(self, mock_stdout):
        """Hook Entity.create to assert the phrase is already on stdout
        BEFORE keygen starts.  This is stronger than just checking the
        order of lines in the final output — it proves the user sees
        the phrase before the wait, not after."""
        from messagechain.cli import cmd_generate_key
        from messagechain.identity import identity as _id_mod

        original_create = _id_mod.Entity.create
        observed_during_keygen: dict = {}

        def hooked_create(*args, **kwargs):
            observed_during_keygen["stdout"] = mock_stdout.getvalue()
            return original_create(*args, **kwargs)

        with mock.patch.object(_id_mod.Entity, "create", side_effect=hooked_create):
            cmd_generate_key(None)

        captured = observed_during_keygen.get("stdout", "")
        self.assertIn(
            "Recovery phrase", captured,
            "Recovery phrase must be printed BEFORE Entity.create runs "
            "so the user can back it up during the keygen wait.",
        )


if __name__ == "__main__":
    unittest.main()
