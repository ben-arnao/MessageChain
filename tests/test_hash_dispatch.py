"""Tests for the versioned hash dispatcher.

Ensures:
- The dispatcher's _ALGO_BY_VERSION mapping stays in lockstep with
  config.HASH_VERSION_* — the dispatcher duplicates the integer keys
  as literals to keep the module import-cycle-free, and we want
  drift caught immediately, not at the next fork.
- default_hash(data) at HASH_VERSION_CURRENT matches the raw
  hashlib output under HASH_ALGO, so swapping the project's 50+ call
  sites to default_hash is byte-for-byte identical on the happy path.
- Unknown hash_versions raise (no silent fallback, no downgrade
  attack via a stored-but-rejected version).
- Every module that used to call `hashlib.new(HASH_ALGO, …).digest()`
  now routes through the dispatcher.
"""

import hashlib
import unittest
from pathlib import Path

from messagechain import config
from messagechain.crypto import hashing


class TestHashDispatchTable(unittest.TestCase):
    def test_dispatch_table_mirrors_config_constants(self):
        """Every concrete HASH_VERSION_* constant in config must
        appear in _ALGO_BY_VERSION.  Keeps the two locations honest."""
        # HASH_VERSION_CURRENT is the only required key today; future
        # widenings add more rows.
        self.assertIn(
            config.HASH_VERSION_CURRENT, hashing._ALGO_BY_VERSION,
            "HASH_VERSION_CURRENT missing from dispatch table",
        )
        # The current version must dispatch to the same algorithm
        # name config.HASH_ALGO names.
        self.assertEqual(
            hashing._ALGO_BY_VERSION[config.HASH_VERSION_CURRENT],
            config.HASH_ALGO,
        )

    def test_default_hash_matches_raw_hashlib(self):
        """default_hash is byte-for-byte identical to the legacy
        inline expression — so the mass find-replace cannot change
        any existing hash value."""
        for payload in (b"", b"x", b"messagechain-genesis", b"\x00" * 256):
            self.assertEqual(
                hashing.default_hash(payload),
                hashlib.new(config.HASH_ALGO, payload).digest(),
            )

    def test_hash_v_explicit_version(self):
        """hash_v with the current version matches default_hash."""
        data = b"test-payload"
        self.assertEqual(
            hashing.hash_v(data, config.HASH_VERSION_CURRENT),
            hashing.default_hash(data),
        )

    def test_unknown_version_raises(self):
        """Unknown version → ValueError, never a silent fallback."""
        with self.assertRaises(ValueError):
            hashing.hash_v(b"x", 0)          # reserved sentinel
        with self.assertRaises(ValueError):
            hashing.hash_v(b"x", 999)        # future version


class TestNoDirectHashAlgoCalls(unittest.TestCase):
    """Structural guard: every hash in the codebase must now flow
    through the dispatcher.  Directly grep the repo for the legacy
    pattern and allow-list only the files that are intentionally
    carved out (the dispatcher itself; config.py for one genesis
    constant computed at import time; tests).
    """

    _ALLOWED_DIRECT_USES = {
        # The dispatcher IS the place that calls hashlib.new — the
        # "HASH_ALGO" string lookup lives here and nowhere else.
        "messagechain/crypto/hashing.py",
        # TREASURY_ENTITY_ID is a module-level constant computed at
        # config.py import time.  Routing it through default_hash
        # would create a circular import (default_hash lazy-imports
        # config.HASH_VERSION_CURRENT).  The value is a frozen
        # historical ID that the chain has already committed to in
        # genesis, so a future hash migration cannot change it even
        # in principle — keeping the inline expression is correct.
        "messagechain/config.py",
    }

    def test_no_stray_hashlib_new_hash_algo(self):
        repo_root = Path(__file__).resolve().parent.parent
        messagechain = repo_root / "messagechain"
        stray: list[str] = []
        for py in messagechain.rglob("*.py"):
            rel = py.relative_to(repo_root).as_posix()
            if rel in self._ALLOWED_DIRECT_USES:
                continue
            text = py.read_text(encoding="utf-8")
            # Match both `hashlib.new(HASH_ALGO` and
            # `_hashlib.new(HASH_ALGO` (the latter appears in
            # functions that locally aliased hashlib).
            if "hashlib.new(HASH_ALGO" in text:
                stray.append(rel)
        self.assertEqual(
            stray, [],
            f"Direct hashlib.new(HASH_ALGO, ...) still present in: "
            f"{stray}.  Route through messagechain.crypto.hashing."
            f"default_hash so a future hash migration stays a "
            f"one-line dispatch-table edit.",
        )


if __name__ == "__main__":
    unittest.main()
