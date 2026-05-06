"""Audit r26 #3 — every cold-wallet first signing command must show
progress during the one-time WOTS+ keygen.

Pre-fix the personal-wallet flow was silent on cache miss:
``_resolve_signing_entity`` -> ``load_or_create_personal_wallet_entity``
-> ``Entity.create`` ran the multi-minute keygen with no feedback.
``cmd_generate_key`` / ``cmd_init`` / ``cmd_rotate_key`` already
installed ``_make_progress_reporter`` and showed a bar; every other
signing command (``send`` / ``transfer`` / ``stake`` / ``unstake`` /
``react`` / ``propose`` / ``vote`` / ``submit-evidence`` /
``emergency-revoke`` / ``bootstrap-seed``) hit the resolver without
the reporter — the very first ``messagechain send "hello"`` after
``generate-key`` looked frozen for minutes.  CLAUDE.md anchor: the
"newcomer E2E flow" + "smart-defaults coverage" standing focus
items + Principle #3 (Simplicity).

Fix plumbs an optional ``progress`` callback through
``load_or_create_personal_wallet_entity`` ->
``_load_or_create_at_height`` -> ``Entity.create``.  The CLI's
``_resolve_signing_entity`` installs ``_make_progress_reporter`` for
the personal-wallet path so cache-miss keygen shows a bar identical
to ``generate-key``'s.

Tests pin:
  * ``progress`` parameter is accepted at the cache-or-create entry
    point and threaded through to ``Entity.create``.
  * On cache MISS the callback is invoked at least once (proving
    the wiring reaches keygen).
  * On cache HIT the callback is NEVER invoked (proving the
    wiring is gated to the slow path — cache hits stay zero-print).
  * Source-level pin: ``_resolve_signing_entity`` in cli.py wraps
    its call to ``load_or_create_personal_wallet_entity`` with a
    ``_make_progress_reporter`` install and forwards the reporter
    via the ``progress`` kwarg, so a future refactor that drops the
    wiring fails the suite rather than silently regressing the UX.
"""

from __future__ import annotations

import inspect
import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import messagechain.config
from messagechain.identity.keypair_cache import (
    load_or_create_personal_wallet_entity,
)


_PRIV = b"\x42" * 32


class TestProgressKwargAccepted(unittest.TestCase):
    """``load_or_create_personal_wallet_entity`` must accept a
    ``progress`` kwarg — that's the contract the CLI wires against."""

    def test_progress_kwarg_in_signature(self):
        sig = inspect.signature(load_or_create_personal_wallet_entity)
        self.assertIn(
            "progress", sig.parameters,
            "load_or_create_personal_wallet_entity must accept a "
            "`progress` kwarg so the CLI can wire a per-leaf reporter "
            "for the cold-wallet keygen UX.",
        )


class TestProgressFiresOnCacheMiss(unittest.TestCase):
    """Cache miss -> keygen runs -> progress callback fires per leaf."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="mc-r26-progress-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home}
        )
        self._home_patch.start()

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_cache_miss_invokes_progress(self):
        ticks: list[int] = []
        def progress(leaf_index):
            ticks.append(leaf_index)

        # Cache is empty (fresh HOME) -> keygen runs.  Use the
        # conftest-pinned test tree_height (4 -> 16 leaves) so this is
        # cheap; the progress callback is invoked per leaf regardless
        # of whether the production reporter would skip.
        ent = load_or_create_personal_wallet_entity(
            _PRIV,
            tree_height=messagechain.config.MERKLE_TREE_HEIGHT,
            progress=progress,
        )
        self.assertGreater(
            len(ticks), 0,
            "progress callback must be invoked at least once during "
            "cache-miss keygen — that's how the cold-wallet UX shows "
            "feedback to the user.",
        )
        # The entity is real and usable.
        self.assertIsNotNone(ent)
        self.assertEqual(len(ent.entity_id), 32)


class TestProgressNotInvokedOnCacheHit(unittest.TestCase):
    """Cache hit -> no keygen -> progress callback must NOT fire.

    A cache hit is millisecond-fast; printing a "Building wallet keys"
    bar at every signing command would be noisy and confusing.
    """

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="mc-r26-cachehit-")
        self._home_patch = mock.patch.dict(
            os.environ, {"HOME": self.home, "USERPROFILE": self.home}
        )
        self._home_patch.start()
        # Prime the cache.
        load_or_create_personal_wallet_entity(
            _PRIV,
            tree_height=messagechain.config.MERKLE_TREE_HEIGHT,
        )

    def tearDown(self):
        self._home_patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_cache_hit_does_not_invoke_progress(self):
        ticks: list[int] = []
        def progress(leaf_index):
            ticks.append(leaf_index)

        load_or_create_personal_wallet_entity(
            _PRIV,
            tree_height=messagechain.config.MERKLE_TREE_HEIGHT,
            progress=progress,
        )
        self.assertEqual(
            ticks, [],
            "progress callback must not fire on cache hit — keygen "
            "didn't run, the user expects silent fast resolution.",
        )


class TestResolveSigningEntityProgressWiring(unittest.TestCase):
    """Source-level pin: ``_resolve_signing_entity`` in cli.py must
    install a progress reporter and forward it to
    ``load_or_create_personal_wallet_entity`` so every signing command
    that goes through the resolver gets the cold-wallet UX for free.

    This is a source-grep test (not a behavior test) so it survives
    refactors in either direction: any change that drops the
    progress wiring fails this test rather than silently regressing
    the cold-wallet UX on the next release.
    """

    def test_resolver_imports_make_progress_reporter(self):
        cli_path = Path(__file__).parent.parent / "messagechain" / "cli.py"
        body = cli_path.read_text(encoding="utf-8")
        # Grab the _resolve_signing_entity function body.
        start = body.index("def _resolve_signing_entity(")
        # Find the next top-level `def ` after the function head.
        rest = body[start:]
        # Walk forward to the end of the function: the next line
        # starting with `def ` at column 0.
        end_marker = "\ndef "
        end = rest.index(end_marker, 1) if end_marker in rest else len(rest)
        body_slice = rest[:end]
        self.assertIn(
            "_make_progress_reporter",
            body_slice,
            "_resolve_signing_entity must install _make_progress_reporter "
            "for the cold-wallet keygen UX (audit r26 #3); a future "
            "refactor that drops the wiring would silently regress the "
            "newcomer experience to a multi-minute hang.",
        )
        self.assertIn(
            "progress=",
            body_slice,
            "_resolve_signing_entity must forward `progress=` to "
            "load_or_create_personal_wallet_entity.",
        )


if __name__ == "__main__":
    unittest.main()
