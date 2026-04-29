"""README-quickstart wallet-cache coverage.

The 1.34.0 personal-wallet keypair cache shipped only on the 14
*spending* CLI commands (send, transfer, stake, ...).  The README's
first-touch path — `generate-key` -> `verify-key` -> `balance` —
re-derives the WOTS+ Merkle tree end-to-end on every call (a
~20-30 minute wedge per command at production tree height).

This module covers the missing wiring:

  1. ``cmd_generate_key`` warms the personal-wallet cache so a
     follow-up ``cmd_verify_key`` is a cache hit.
  2. ``cmd_verify_key`` consults the cache via the shared
     ``_resolve_signing_entity`` helper instead of calling
     ``Entity.create`` directly.
  3. ``cmd_balance`` accepts a read-only ``--address`` (or
     ``--entity-id``) flag that skips key resolution entirely so the
     user can check a balance with no keyfile / seed phrase / cache
     present.
  4. ``cmd_key_status`` accepts the same read-only flag.
  5. ``cmd_start --mine`` consults the on-disk cache (the daemon's
     ``_load_or_create_entity`` flow) rather than a bare
     ``Entity.create``.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from messagechain.identity.identity import Entity
from messagechain.identity.address import encode_address
from messagechain.identity.key_encoding import encode_private_key


class _CacheCounter:
    """Counts ``Entity.create`` calls so a test can assert "cache hit
    means no fresh keygen."""

    def __init__(self):
        self.count = 0
        self.original = Entity.create

    def __call__(self, *args, **kwargs):
        self.count += 1
        return self.original(*args, **kwargs)


class TestGenerateKeyWarmsCache(unittest.TestCase):
    """generate-key MUST write the freshly-derived keypair into the
    personal-wallet cache, so the very next CLI command (verify-key,
    balance, ...) hits the cache instead of redoing the keygen."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_generate_key_populates_personal_wallet_cache(self, _stdout):
        from messagechain.cli import cmd_generate_key
        from messagechain.identity.keypair_cache import (
            personal_wallet_cache_path,
        )
        from messagechain.config import MERKLE_TREE_HEIGHT

        private_key = os.urandom(32)
        with patch("os.urandom", return_value=private_key):
            cmd_generate_key(None)

        # Cache file path is a deterministic function of (private_key,
        # tree_height).  The freshly-generated key MUST have a cache
        # file on disk after the command runs.
        cache_path = personal_wallet_cache_path(
            private_key, MERKLE_TREE_HEIGHT,
        )
        self.assertTrue(
            os.path.exists(cache_path),
            f"generate-key did not warm the wallet cache at {cache_path}",
        )


class TestVerifyKeyHitsCache(unittest.TestCase):
    """verify-key MUST go through the shared
    ``_resolve_signing_entity`` so the personal-wallet cache is
    consulted.  After a generate-key warm, verify-key for the same
    private key should be a cache hit."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_verify_key_uses_cache_after_generate(self, _stdout):
        from argparse import Namespace
        from messagechain.cli import cmd_generate_key, cmd_verify_key

        private_key = os.urandom(32)
        # Step 1: warm the cache via generate-key.
        with patch("os.urandom", return_value=private_key):
            cmd_generate_key(None)

        # Step 2: verify-key.  Wrap Entity.create with a counter; the
        # cache hit path uses ``KeyPair._from_trusted_root`` rather
        # than re-deriving leaves, so Entity.create should NOT be
        # called from the keypair_cache module.  A real Namespace is
        # used (not MagicMock) so `getattr(args, "keyfile", None)`
        # returns None instead of a truthy auto-attribute that
        # _resolve_private_key would try to load as a key file.
        args = Namespace(
            data_dir=None, keyfile=None, key_file=None,
            address=None, entity_id=None, server=None,
        )
        with patch(
            "messagechain.identity.keypair_cache.Entity.create",
        ) as mock_create:
            with patch(
                "getpass.getpass",
                return_value=encode_private_key(private_key),
            ):
                cmd_verify_key(args)

        self.assertEqual(
            mock_create.call_count, 0,
            "verify-key fell through to Entity.create — cache miss "
            "indicates the cache is not being consulted",
        )


class TestBalanceReadOnlyAddress(unittest.TestCase):
    """balance --address mc1... MUST work with no key / cache /
    seed-phrase access at all.  The README quickstart explicitly
    suggests checking a balance before having tokens — at that point
    the user cannot afford a 20-minute wait just to look up zero."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_balance_accepts_address_flag_without_private_key(self, mock_stdout):
        from messagechain.cli import cmd_balance

        # Build an address from a freshly-derived entity_id.  We use
        # Entity.create here only because we need a 32-byte entity_id
        # whose pretty mc1... encoding is well-formed; the test
        # below MUST NOT supply a private_key to cmd_balance.
        private_key = os.urandom(32)
        entity = Entity.create(private_key)
        address = encode_address(entity.entity_id)

        # Mock the RPC to return a static info blob.
        fake_resp = {
            "ok": True,
            "result": {
                "entity_id": entity.entity_id_hex,
                "balance": 12345,
                "staked": 0,
                "messages_posted": 0,
                "nonce": 0,
            },
        }

        # Args: no keyfile, no seed; only --address + --server.  The
        # call MUST NOT prompt for a private key (no getpass, no
        # _resolve_private_key).
        args = MagicMock(
            spec=[
                "address", "entity_id", "data_dir", "key_file", "keyfile",
                "server",
            ],
        )
        args.address = address
        args.entity_id = None
        args.data_dir = None
        args.key_file = None
        args.keyfile = None
        args.server = "127.0.0.1:9334"

        with patch("client.rpc_call", return_value=fake_resp) as mock_rpc:
            with patch("getpass.getpass") as mock_getpass:
                cmd_balance(args)

        mock_getpass.assert_not_called()
        # The RPC MUST have been called with the entity_id derived
        # from the address — no fresh keygen / signing entity needed.
        self.assertTrue(mock_rpc.called)
        call_args = mock_rpc.call_args
        self.assertEqual(
            call_args[0][3]["entity_id"], entity.entity_id_hex,
        )

        output = mock_stdout.getvalue()
        self.assertIn("12345", output)


class TestKeyStatusReadOnlyAddress(unittest.TestCase):
    """key-status --address mc1... mirrors balance: a read-only RPC
    that needs no key access on the local side."""

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_key_status_accepts_address_flag_without_private_key(self, _stdout):
        from messagechain.cli import cmd_key_status

        private_key = os.urandom(32)
        entity = Entity.create(private_key)
        address = encode_address(entity.entity_id)

        fake_resp = {
            "ok": True,
            "result": {
                "leaf_watermark": 3,
                "rotation_number": 0,
                "public_key": entity.public_key.hex(),
            },
        }

        args = MagicMock(
            spec=[
                "address", "entity_id", "data_dir", "key_file", "keyfile",
                "server",
            ],
        )
        args.address = address
        args.entity_id = None
        args.data_dir = None
        args.key_file = None
        args.keyfile = None
        args.server = "127.0.0.1:9334"

        with patch("client.rpc_call", return_value=fake_resp):
            with patch("getpass.getpass") as mock_getpass:
                cmd_key_status(args)

        mock_getpass.assert_not_called()


class TestStartMineUsesCache(unittest.TestCase):
    """``messagechain start --mine`` MUST consult the on-disk daemon
    cache rather than do a bare ``Entity.create`` — for a validator
    restarting after a config flip, that's the difference between a
    second-long startup and a 20-minute one.

    We verify the *code path* contains the routed call rather than
    running the full server (which would require networking + a chain
    state directory).  The structural check is sufficient because the
    daemon's ``_load_or_create_entity`` is itself covered by
    ``test_keypair_cache.py``.
    """

    def test_cmd_start_routes_through_load_or_create_entity(self):
        import inspect
        import messagechain.cli as cli_mod
        src = inspect.getsource(cli_mod.cmd_start)
        # The miner branch of cmd_start must consult the daemon's
        # _load_or_create_entity (or the personal-wallet cache helper)
        # rather than fall through to a bare ``Entity.create`` that
        # always pays full keygen cost.  The bare-create line that
        # this test guards against is the one immediately before
        # ``server.set_wallet_entity(entity)`` — historically:
        #     entity = Entity.create(private_key, progress=progress)
        # The fix routes that line through the same cache the
        # daemon uses.
        self.assertNotRegex(
            src,
            r"entity\s*=\s*Entity\.create\(\s*private_key\s*,",
            "cmd_start --mine still calls Entity.create directly; "
            "route through _load_or_create_entity (or the "
            "personal-wallet cache helper) so a validator restart "
            "is a cache hit, not a 20-minute keygen.",
        )
        # Positive structural assertion: the cache helper is called.
        self.assertTrue(
            "_load_or_create_entity" in src
            or "load_or_create_personal_wallet_entity" in src
            or "_resolve_signing_entity" in src,
            "cmd_start --mine does not consult any keypair-cache "
            "helper — a restart pays full keygen cost",
        )


class TestBootstrapSeedVerifyHintUsesNewBalance(unittest.TestCase):
    """The bootstrap-seed flow prints a 'Verify with:' hint.  The old
    line referenced ``messagechain info --entity-id <hex>``, but
    ``info`` does not accept ``--entity-id``.  Once balance has a
    read-only ``--address`` flag, the verify hint should point there."""

    def test_bootstrap_seed_hint_does_not_reference_info_entity_id(self):
        import inspect
        import messagechain.cli as cli_mod
        src = inspect.getsource(cli_mod.cmd_bootstrap_seed)
        self.assertNotIn(
            "info --entity-id",
            src,
            "bootstrap-seed prints a stale 'info --entity-id' hint; "
            "should reference 'balance --address mc1...' once the "
            "read-only flag is wired",
        )
        self.assertIn(
            "balance --address",
            src,
            "bootstrap-seed verify hint should reference the new "
            "read-only `balance --address mc1...` form",
        )


if __name__ == "__main__":
    unittest.main()
