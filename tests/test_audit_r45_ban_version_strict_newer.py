"""Audit r45 #1 — ban auto-clear must require a strictly-newer semver,
not any non-equal string.

Pre-fix the auto-clear gate read::

    if ps.peer_version and ps.peer_version == current_version:
        return False
    # else: clear the ban

i.e. ANY non-empty, non-"unknown" string that differed from the stored
``peer_version`` cleared the ban (score reset, lifetime_score reset,
offenses cleared).  Bypass cycle:

    1. attacker earns OFFENSE_INVALID_TX (instant-ban), peer_version="1.46.0"
    2. reconnect with version="x" → clear, peer_version="x"
    3. attacker re-offends → banned again, peer_version="x"
    4. reconnect with version="y" → clear, peer_version="y"
    5. repeat indefinitely

Every banscore-graded defense (gossip flood, invalid-tx flood, invalid-
block flood, protocol-violation flood) collapses to ~zero cost — the
ban subsystem becomes purely advisory.

Post-fix the gate requires::

    release_version_is_strictly_newer(current_version, ps.peer_version)

which (a) rejects any string that doesn't parse as semver, AND (b)
rejects any semver that isn't strictly newer than the stored one.  The
laundering cycle is bounded by the chain's actual release-tag forward
progress, not by the attacker's choice of garbage strings.

The legacy-empty-peer_version path is preserved (pre-1.48 ban entries
that loaded from disk with no ``peer_version`` field still auto-clear
on first reconnect with a VALID semver) — but now requires the reported
version to parse cleanly, so "x" can no longer launder a legacy entry
either.  See existing tests 3 / 8 / 8b in tests/test_ban_decay.py.

CLAUDE.md anchor protected: Security (principle #1).  Adversaries
defended against: validator-collusion + AI-spam flooding (both
banscore-graded), plus the general "honest-operator's network-layer
defense surface."
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.network.ban import (
    PeerBanManager,
    OFFENSE_INVALID_BLOCK,
    OFFENSE_INVALID_TX,
)


class TestBanClearRequiresStrictlyNewerSemver(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "ban_scores.json")
        self.mgr = PeerBanManager(persistence_path=self.path)
        self.addr = "203.0.113.7:9333"

    def tearDown(self):
        self._tmp.cleanup()

    def _ban_at(self, version: str) -> None:
        self.mgr.record_offense(
            self.addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version=version,
        )
        self.assertTrue(self.mgr.is_banned(self.addr))

    # ── Garbage strings cannot launder a ban ────────────────────────
    def test_arbitrary_garbage_string_does_not_clear(self):
        """A peer banned at v1.46.0 cannot reconnect with version='x'
        and have the ban cleared.  This is the headline audit r45 #1
        bypass.
        """
        self._ban_at("1.46.0")
        for garbage in ("x", "y", "z", "garbage", "lol", "foo-bar"):
            cleared = self.mgr.clear_ban_on_version_change(
                self.addr, garbage,
            )
            self.assertFalse(
                cleared,
                f"reported version {garbage!r} must NOT clear a ban "
                f"stamped with a real semver — the gate must require "
                f"strict-newer semver, not just any non-equal string",
            )
            self.assertTrue(self.mgr.is_banned(self.addr))

    def test_non_semver_with_dots_does_not_clear(self):
        """Strings that *look* dot-shaped but don't parse as semver
        (extra parts, non-numeric segments, leading zeros, etc.) must
        not launder a ban either.
        """
        self._ban_at("1.46.0")
        for bad in (
            "1.46.0.0",       # 4 parts
            "1.46",           # 2 parts
            "1.46.0-",        # empty prerelease
            "1.46.x",         # non-numeric patch
            "01.46.0",        # leading zero
            "1.46.0+meta",    # build metadata not supported
            "v1.47.0",        # v-prefix not supported
            " 1.47.0",        # leading whitespace
            "1.47.0 ",        # trailing whitespace
        ):
            cleared = self.mgr.clear_ban_on_version_change(self.addr, bad)
            self.assertFalse(
                cleared,
                f"malformed version {bad!r} must not clear ban",
            )
            self.assertTrue(self.mgr.is_banned(self.addr))

    # ── Same and older semvers cannot clear ─────────────────────────
    def test_same_semver_does_not_clear(self):
        """Belt-and-suspenders: same-version was already pinned by
        test_ban_decay.py::test_same_version_reconnect_still_banned,
        but the strict-newer rule expresses it directly via the
        ``release_version_is_strictly_newer`` semantics — re-pin here
        so a refactor that swaps the implementation keeps the
        invariant.
        """
        self._ban_at("1.46.0")
        cleared = self.mgr.clear_ban_on_version_change(self.addr, "1.46.0")
        self.assertFalse(cleared)
        self.assertTrue(self.mgr.is_banned(self.addr))

    def test_strictly_older_semver_does_not_clear(self):
        """A downgrade-shaped reconnect (claimed older version than the
        one that earned the ban) must not launder the ban.
        Pre-fix this DID clear the ban (any non-equal string worked).
        """
        self._ban_at("1.46.0")
        for older in ("1.45.0", "1.0.0", "0.9.0", "1.45.999"):
            cleared = self.mgr.clear_ban_on_version_change(self.addr, older)
            self.assertFalse(
                cleared,
                f"downgrade to {older!r} must not clear a v1.46.0 ban — "
                f"prior to audit r45 this was a free ban-laundering path",
            )
            self.assertTrue(self.mgr.is_banned(self.addr))

    def test_prerelease_same_core_does_not_clear(self):
        """1.46.0 is strictly NEWER than 1.46.0-rc1 (release > prerelease
        of same core), so reconnecting as "1.46.0-evil" after being
        banned at "1.46.0" must NOT clear.
        """
        self._ban_at("1.46.0")
        cleared = self.mgr.clear_ban_on_version_change(
            self.addr, "1.46.0-evil",
        )
        self.assertFalse(
            cleared,
            "appending a prerelease tag must not be treated as 'newer'",
        )
        self.assertTrue(self.mgr.is_banned(self.addr))

    # ── Strictly-newer semvers do clear (normal path preserved) ─────
    def test_strictly_newer_semver_clears(self):
        """The legitimate upgrade-after-bug recovery path must still
        work — major / minor / patch bumps clear a stale ban.
        """
        for newer in ("1.47.0", "1.46.1", "2.0.0", "1.46.0.dummy"):
            # The last one above intentionally falls through to "not
            # a valid semver" — pop it.
            pass
        for newer in ("1.47.0", "1.46.1", "2.0.0"):
            mgr = PeerBanManager(persistence_path=self.path + f".{newer}")
            mgr.record_offense(
                self.addr, OFFENSE_INVALID_BLOCK, "bad_block",
                peer_version="1.46.0",
            )
            self.assertTrue(mgr.is_banned(self.addr))
            cleared = mgr.clear_ban_on_version_change(self.addr, newer)
            self.assertTrue(
                cleared,
                f"legitimate upgrade to {newer!r} must clear stale ban",
            )
            self.assertFalse(mgr.is_banned(self.addr))

    # ── The laundering cycle is bounded ─────────────────────────────
    def test_offend_clear_offend_clear_cycle_is_bounded(self):
        """The attack: ban → reconnect-with-garbage → unbanned → re-offend
        → ban → reconnect-with-different-garbage → unbanned → ...
        Post-fix, garbage strings produce no clear at all, so the cycle
        terminates at the first ban.  The peer can still recover by
        running a real new release, but they cannot launder by spinning
        the version string.
        """
        self._ban_at("1.46.0")
        # Five rounds of garbage; ban must persist throughout.
        for garbage in ("a", "b", "c", "1.46.0.0", "garbage123"):
            self.mgr.clear_ban_on_version_change(self.addr, garbage)
            self.assertTrue(
                self.mgr.is_banned(self.addr),
                f"after garbage reconnect {garbage!r} ban must hold",
            )
        # Only a real upgrade clears.
        self.assertTrue(
            self.mgr.clear_ban_on_version_change(self.addr, "1.47.0"),
        )
        self.assertFalse(self.mgr.is_banned(self.addr))

    # ── Legacy-empty path still works but requires valid semver ─────
    def test_legacy_empty_clears_only_on_valid_semver(self):
        """Pre-1.48 ban entries (empty peer_version) still legacy-clear
        on first reconnect — but only when the reported version parses
        as semver.  An attacker reconnecting to a legacy entry with
        garbage gets no clear.
        """
        # Offense recorded WITHOUT a peer_version (pre-handshake / pre-1.48).
        self.mgr.record_offense(self.addr, OFFENSE_INVALID_BLOCK, "bad_block")
        self.assertTrue(self.mgr.is_banned(self.addr))

        # Garbage cannot launder the legacy entry either.
        self.assertFalse(
            self.mgr.clear_ban_on_version_change(self.addr, "x"),
        )
        self.assertTrue(self.mgr.is_banned(self.addr))

        # Valid semver still triggers the legacy-clear (back-compat
        # with tests 3 / 8 / 8b in tests/test_ban_decay.py).
        self.assertTrue(
            self.mgr.clear_ban_on_version_change(self.addr, "1.49.0"),
        )
        self.assertFalse(self.mgr.is_banned(self.addr))

    # ── Instant-ban + version-toggle flood scenario ──────────────────
    def test_instant_ban_floor_holds_under_version_toggle_flood(self):
        """The headline scenario from the audit finding: attacker burns
        OFFENSE_INVALID_TX (instant-ban), reconnects with a new garbage
        version, re-offends, repeats.  Pre-fix this was effectively
        free.  Post-fix every reconnect-with-garbage no-ops the
        clear, so the offender stays banned and the rate-limiter does
        its job.
        """
        # Simulate the very first ban via an OFFENSE_INVALID_TX cycle.
        self.mgr.record_offense(
            self.addr, OFFENSE_INVALID_TX, "invalid_tx",
            peer_version="1.46.0",
        )
        self.assertTrue(self.mgr.is_banned(self.addr))

        # Attacker spins through 50 garbage versions; ban must hold.
        for i in range(50):
            cleared = self.mgr.clear_ban_on_version_change(
                self.addr, f"attacker-toggle-{i}",
            )
            self.assertFalse(
                cleared,
                f"iter {i}: garbage version {'attacker-toggle-' + str(i)!r} "
                f"must not clear ban",
            )
            self.assertTrue(self.mgr.is_banned(self.addr))


if __name__ == "__main__":
    unittest.main()
