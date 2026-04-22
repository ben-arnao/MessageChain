"""Tests for PeerBanManager disk persistence.

A peer banned moments before a scheduled restart (OOM kill, maintenance
reboot) used to reconnect fresh on boot because ban state lived only in
memory. These tests pin down the on-disk persistence contract so bans
survive restarts.
"""

import json
import os
import tempfile
import time
import unittest

from messagechain.network.ban import (
    PeerBanManager,
    OFFENSE_INVALID_BLOCK,
    OFFENSE_MINOR,
    BAN_THRESHOLD,
)


class TestBanStatePersistence(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "ban_scores.json")

    def tearDown(self):
        self._tmp.cleanup()

    # Test A: ban survives BanManager teardown & reconstruction ------
    def test_banned_peer_still_banned_after_restart(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        banned = mgr.record_offense(addr, OFFENSE_INVALID_BLOCK, "bad_block")
        self.assertTrue(banned, "peer should be banned after 100-pt offense")
        self.assertTrue(mgr.is_banned(addr))

        # Tear down — drop the reference so anyone holding it fails loudly.
        del mgr

        # New BanManager reads the same file.
        mgr2 = PeerBanManager(persistence_path=self.path)
        self.assertTrue(
            mgr2.is_banned(addr),
            "ban should survive restart via on-disk persistence",
        )

    # Test B: partial score also persists -----------------------------
    def test_partial_score_persists(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.8:9333"
        # A score below BAN_THRESHOLD — not banned, but tracked.
        mgr.record_offense(addr, OFFENSE_MINOR, "minor")
        self.assertFalse(mgr.is_banned(addr))
        self.assertGreater(mgr.get_score(addr), 0)
        saved_score = mgr.get_score(addr)

        # Force a save in case of debounce edge-case, then restart.
        if hasattr(mgr, "save"):
            mgr.save(force=True)
        del mgr

        mgr2 = PeerBanManager(persistence_path=self.path)
        self.assertEqual(
            mgr2.get_score(addr), saved_score,
            "partial (non-banning) score should survive restart",
        )
        self.assertFalse(mgr2.is_banned(addr))

    # Test C: expired bans are dropped at load ------------------------
    def test_expired_ban_dropped_at_load(self):
        addr_ip = "203.0.113.9"
        # Write a fully-formed state file directly with an in-the-past
        # banned_until so we don't have to wait for a real expiry.
        payload = {
            addr_ip: {
                "score": BAN_THRESHOLD,
                "lifetime_score": BAN_THRESHOLD,
                "first_seen": time.time() - 3600,
                "banned_until": time.time() - 10,  # expired 10s ago
            }
        }
        with open(self.path, "w") as f:
            json.dump(payload, f)

        mgr = PeerBanManager(persistence_path=self.path)
        self.assertFalse(
            mgr.is_banned(f"{addr_ip}:9333"),
            "ban that already expired before load should not be in effect",
        )
        # The expired entry should be gone from the in-memory map
        # (tidy + fresh-slate) — get_score returns 0 for unknown peers.
        self.assertEqual(mgr.get_score(f"{addr_ip}:9333"), 0)

    # Test D: unparseable JSON logs a warning & loads empty -----------
    def test_unparseable_file_loads_empty(self):
        with open(self.path, "w") as f:
            f.write("this is not JSON {")

        # Should NOT raise.
        mgr = PeerBanManager(persistence_path=self.path)
        self.assertFalse(mgr.is_banned("192.0.2.1:9333"))

        # Still functional — offenses work normally.
        banned = mgr.record_offense(
            "192.0.2.1:9333", OFFENSE_INVALID_BLOCK, "bad_block",
        )
        self.assertTrue(banned)

    # Test E: no path → no file written -------------------------------
    def test_no_path_no_file_written(self):
        # Pick a path we can check for absence — but don't pass it.
        ghost = os.path.join(self._tmp.name, "should_not_exist.json")
        mgr = PeerBanManager()  # default = no persistence
        mgr.record_offense("192.0.2.2:9333", OFFENSE_INVALID_BLOCK, "bad")
        self.assertFalse(
            os.path.exists(ghost),
            "no persistence path → no file anywhere in the tmpdir",
        )
        # And: nothing in the whole tmpdir.
        self.assertEqual(
            os.listdir(self._tmp.name), [],
            "no persistence path → no files created at all",
        )


if __name__ == "__main__":
    unittest.main()
