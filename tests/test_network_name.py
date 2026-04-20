"""Tests for the NETWORK_NAME selector that gates PINNED_GENESIS_HASH.

The risk this mechanism protects against: a clone of the repo today
has ``PINNED_GENESIS_HASH`` hardcoded to a testnet hash.  Without a
network selector, cutting mainnet requires editing a raw hex literal
and hoping nobody forgets.  With the selector, going live requires:

  1. Set ``_MAINNET_GENESIS_HASH`` to the real block-0 hash
  2. Flip ``NETWORK_NAME`` to ``"mainnet"``

Doing (2) without (1) must be a hard failure — you cannot ship a
mainnet build with a None pin.
"""

import unittest
from unittest.mock import patch

import messagechain.config as cfg


class TestNetworkNameSelector(unittest.TestCase):
    def test_default_network_is_testnet(self):
        """During the 2026-04-20 hard-reset window, NETWORK_NAME is 'testnet'.

        Pre-launch this was 'testnet'.  At 2026-04-18 launch it flipped to
        'mainnet'.  On 2026-04-20 we hard-reset (state-root-checkpoint
        wire-format change breaks forward-decode of existing block DBs)
        and flipped back to 'testnet' until the new mainnet genesis is
        minted.  After re-mint, this assertion flips back to 'mainnet'.

        Asserted against the source file rather than cfg.NETWORK_NAME so
        this test stays meaningful even when a test harness mutates the
        module-level constant for isolation.
        """
        import re
        import pathlib
        src = pathlib.Path(cfg.__file__).read_text(encoding="utf-8")
        match = re.search(
            r'^NETWORK_NAME\s*=\s*"(mainnet|testnet|devnet)"',
            src,
            re.MULTILINE,
        )
        self.assertIsNotNone(match, "NETWORK_NAME default not found in config.py")
        self.assertEqual(
            match.group(1),
            "testnet",
            "NETWORK_NAME default must be 'testnet' during the hard-reset "
            "re-mint window.  _MAINNET_GENESIS_HASH is None until the new "
            "block 0 is minted; flipping NETWORK_NAME to 'mainnet' before "
            "that point raises at config load.  Flip this assertion back "
            "to 'mainnet' once the new mainnet genesis hash is pinned.",
        )

    def test_testnet_selector_returns_testnet_hash(self):
        """_resolve_pinned_genesis_hash('testnet') returns _TESTNET_GENESIS_HASH.

        During the 2026-04-20 reset window _TESTNET_GENESIS_HASH is None
        (also stale after the wire-format change); the resolver must still
        return that value verbatim rather than raising or substituting.

        Tested via the resolver, not via the module-level
        PINNED_GENESIS_HASH, because the test harness overrides
        the latter for its own isolation.
        """
        self.assertEqual(
            cfg._resolve_pinned_genesis_hash("testnet"),
            cfg._TESTNET_GENESIS_HASH,
        )
        # When the testnet hash is repopulated after re-mint, it must
        # be exactly 32 bytes — the selector never reshapes it.
        if cfg._TESTNET_GENESIS_HASH is not None:
            self.assertEqual(len(cfg._TESTNET_GENESIS_HASH), 32)

    def test_devnet_returns_none(self):
        """Devnet disables the pin entirely (local testing, fresh genesis)."""
        resolved = cfg._resolve_pinned_genesis_hash("devnet")
        self.assertIsNone(resolved)

    def test_unknown_network_raises(self):
        """Typos ('staging', 'mainet') must fail loudly, not silently fall through."""
        with self.assertRaises(RuntimeError) as ctx:
            cfg._resolve_pinned_genesis_hash("staging")
        msg = str(ctx.exception).lower()
        self.assertIn("staging", msg)

    def test_mainnet_without_pin_raises(self):
        """NETWORK_NAME='mainnet' with None mainnet hash is an explicit error.

        This is the protection that makes the whole mechanism worth it:
        an unfilled mainnet slot cannot silently trust the testnet hash,
        and the error message must name the variable that needs to be
        set so the fix is obvious.
        """
        with patch.object(cfg, "_MAINNET_GENESIS_HASH", None):
            with self.assertRaises(RuntimeError) as ctx:
                cfg._resolve_pinned_genesis_hash("mainnet")
            msg = str(ctx.exception)
            self.assertIn("_MAINNET_GENESIS_HASH", msg)
            self.assertIn("mainnet", msg.lower())

    def test_mainnet_with_pin_returns_it(self):
        """When _MAINNET_GENESIS_HASH is set, mainnet returns that value."""
        fake_mainnet_hash = b"\xab" * 32
        with patch.object(cfg, "_MAINNET_GENESIS_HASH", fake_mainnet_hash):
            resolved = cfg._resolve_pinned_genesis_hash("mainnet")
            self.assertEqual(resolved, fake_mainnet_hash)

    def test_mainnet_does_not_leak_testnet_hash(self):
        """Critical invariant: mainnet resolution MUST NOT return the testnet hash.

        If this test ever passes with the testnet hash coming back, it
        means someone short-circuited the selector (e.g. via a fallback
        like `return _MAINNET_GENESIS_HASH or _TESTNET_GENESIS_HASH`) —
        which is exactly the failure mode we designed this to prevent.
        """
        fake_mainnet_hash = b"\xab" * 32
        with patch.object(cfg, "_MAINNET_GENESIS_HASH", fake_mainnet_hash):
            resolved = cfg._resolve_pinned_genesis_hash("mainnet")
            self.assertNotEqual(resolved, cfg._TESTNET_GENESIS_HASH)

    def test_devnet_flag_matches_network_name(self):
        """Legacy DEVNET flag stays in sync with NETWORK_NAME for back-compat.

        Existing call sites (blockchain.py, initialize_genesis, etc.)
        read DEVNET directly. Renaming everything in one pass is
        risky, so we derive DEVNET from NETWORK_NAME and pin that
        relationship here.
        """
        self.assertEqual(cfg.DEVNET, cfg.NETWORK_NAME == "devnet")


if __name__ == "__main__":
    unittest.main()
