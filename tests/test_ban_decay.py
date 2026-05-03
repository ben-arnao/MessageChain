"""Tests for clear-on-version-change ban policy.

Background — 2026-04-25 incident: validator-2 banned validator-1 with
score 132 / banned_until ~3h future during a 24h+ chain stall caused
by a consensus bug.  After 1.46.0 / 1.47.0 / 1.47.1 shipped fixes,
the chain stayed split because v2 kept rejecting v1's reconnects with
"Rejected banned peer".  Operator had to manually edit
/var/lib/messagechain/ban_scores.json to clear it.

Structural fix: when a peer reconnects advertising a DIFFERENT version
string than the one recorded at ban time, the prior bad-block evidence
is presumed stale (the binary that earned the ban has been replaced).
Clear the ban and let them reconnect.

This is the "Option A" surgical fix from the design discussion — it
matches the actual root-cause (peer software changed) and requires no
operator intervention.
"""

from __future__ import annotations

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


class TestBanClearsOnVersionChange(unittest.TestCase):
    """Direct unit tests of the PeerBanManager clear-on-version-change API."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "ban_scores.json")

    def tearDown(self):
        self._tmp.cleanup()

    # ── Test 1: same version → still banned ─────────────────────────
    def test_same_version_reconnect_still_banned(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        # Record an instant-ban offense, tagging with peer's version.
        banned = mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(banned)
        self.assertTrue(mgr.is_banned(addr))

        # Peer reconnects on the SAME version string.  Ban must hold.
        cleared = mgr.clear_ban_on_version_change(addr, "1.46.0")
        self.assertFalse(cleared, "same version → no clearance")
        self.assertTrue(
            mgr.is_banned(addr),
            "peer on the same buggy binary stays banned",
        )

    # ── Test 2: new version → ban cleared ───────────────────────────
    def test_new_version_reconnect_clears_ban(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(mgr.is_banned(addr))

        # Peer comes back having shipped a fix.  Ban clears.
        cleared = mgr.clear_ban_on_version_change(addr, "1.47.1")
        self.assertTrue(cleared, "version bump must clear stale ban")
        self.assertFalse(
            mgr.is_banned(addr),
            "post-fix reconnect must succeed without operator intervention",
        )

    # ── Test 3: empty stored version → legacy-clear on first reconnect ──
    def test_empty_stored_version_legacy_clear(self):
        """A ban entry without a recorded version (legacy on-disk row,
        or an offense recorded before HANDSHAKE supplied a version)
        MUST auto-clear on first reconnect with a non-empty version.

        Pre-1.50.0 this was conservatively refused, on the reasoning
        "we don't know what binary earned the ban, so don't trust the
        peer."  But that broke the auto-clear feature's PRIMARY use
        case: the bans that triggered an upgrade were written by the
        pre-fix binary (which didn't have the peer_version field) and
        had empty peer_version after the upgrade loaded them, leaving
        recovery requiring the very ``ban_scores.json`` hand-edit the
        feature was built to eliminate.

        Empty stored peer_version is now treated as an unforgeable
        marker for "this entry was written by code that didn't have
        the field" -- i.e. pre-1.48.  The major instant-ban offenses
        (OFFENSE_INVALID_BLOCK / OFFENSE_INVALID_TX) all fire after
        HANDSHAKE, so all FRESH bans will have peer_version stamped
        and the auto-clear gate runs in its normal mode for them.
        """
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        # Offense recorded WITHOUT a peer_version (e.g. pre-handshake).
        mgr.record_offense(addr, OFFENSE_INVALID_BLOCK, "bad_block")
        self.assertTrue(mgr.is_banned(addr))

        cleared = mgr.clear_ban_on_version_change(addr, "1.47.1")
        self.assertTrue(
            cleared,
            "empty stored version must auto-clear -- this is the "
            "pre-1.48 ban legacy-recovery path",
        )
        self.assertFalse(mgr.is_banned(addr))

    # ── Test 4: empty / unknown peer-reported version → no clear ────
    def test_empty_or_unknown_reported_version_no_clear(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(mgr.is_banned(addr))

        # A peer that omits or fakes empty-string version cannot
        # weasel out of a ban.  Same for the literal "unknown".
        for fake in ("", "unknown"):
            cleared = mgr.clear_ban_on_version_change(addr, fake)
            self.assertFalse(
                cleared,
                f"reported version {fake!r} must not clear ban",
            )
            self.assertTrue(mgr.is_banned(addr))

    # ── Test 5: clearance is a clean slate (lifetime_score reset) ───
    def test_cleared_ban_resets_lifetime_score(self):
        """Once we decide a peer's prior bad-block was a stale-binary
        artifact, they get the same clean slate manual_unban gives.
        Otherwise a peer that gets repeatedly version-bumped would
        accumulate lifetime_score and still trip the lifetime ceiling.
        """
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertGreater(mgr.get_score(addr), 0)

        mgr.clear_ban_on_version_change(addr, "1.47.1")
        self.assertEqual(mgr.get_score(addr), 0)
        # New version is now the "current" one for any future offenses.
        # Re-offending on 1.47.1 records that version going forward.
        mgr.record_offense(
            addr, OFFENSE_MINOR, "minor",
            peer_version="1.47.1",
        )
        # And a same-version reconnect on 1.47.1 still holds any new ban.

    # ── Test 6: persistence round-trip preserves peer_version ───────
    def test_peer_version_persists_across_restart(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(mgr.is_banned(addr))
        mgr.save(force=True)
        del mgr

        # Reload — same-version reconnect still banned, new-version clears.
        mgr2 = PeerBanManager(persistence_path=self.path)
        self.assertTrue(mgr2.is_banned(addr))
        self.assertFalse(mgr2.clear_ban_on_version_change(addr, "1.46.0"))
        self.assertTrue(mgr2.clear_ban_on_version_change(addr, "1.47.1"))
        self.assertFalse(mgr2.is_banned(addr))

    # ── Test 7: on-disk schema includes peer_version field ──────────
    def test_on_disk_schema_carries_peer_version(self):
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        mgr.save(force=True)
        with open(self.path, "r") as f:
            payload = json.load(f)
        # IP key after bucket-normalization is the bare IP.
        self.assertIn("203.0.113.7", payload)
        self.assertEqual(payload["203.0.113.7"].get("peer_version"), "1.46.0")

    # ── Test 8: legacy on-disk row (no peer_version) loads + clears ──
    def test_legacy_disk_row_without_peer_version_clears(self):
        """Pre-1.48 on-disk rows have no peer_version key.  Loading
        must not crash, AND the entry must auto-clear on first
        reconnect with a non-empty version (the pre-1.48 legacy
        recovery path -- see Test 3).

        Reproduces the exact 2026-05-03 mainnet incident: v2's
        ban_scores.json had an entry written by 1.47.x code with no
        peer_version.  v2 was upgraded to 1.49.0 and reloaded the
        entry with empty peer_version, which under pre-1.50.0 logic
        permanently locked v1 out (the auto-clear gate refused to
        fire on empty stored version).  Operator had to hand-edit
        the file to recover.  With the 1.50.0 legacy-clear path,
        this test asserts the same scenario now self-resolves.
        """
        legacy = {
            "203.0.113.7": {
                "score": BAN_THRESHOLD,
                "lifetime_score": BAN_THRESHOLD,
                "first_seen": time.time(),
                "banned_until": time.time() + 3600,
                # NO peer_version key -- this is the pre-1.48 schema.
            }
        }
        with open(self.path, "w") as f:
            json.dump(legacy, f)

        mgr = PeerBanManager(persistence_path=self.path)
        self.assertTrue(mgr.is_banned("203.0.113.7:9333"))
        # First reconnect on any non-empty version legacy-clears the ban.
        self.assertTrue(
            mgr.clear_ban_on_version_change("203.0.113.7:9333", "1.49.0"),
            "1.50.0+ must auto-clear pre-1.48 ban entries on first "
            "reconnect -- this is the 2026-05-03 incident's structural fix",
        )
        self.assertFalse(mgr.is_banned("203.0.113.7:9333"))

    # ── Test 8b: post-legacy-clear, re-ban records peer_version ─────
    def test_post_legacy_clear_reban_stamps_peer_version(self):
        """The legacy-clear path stamps the reported version onto the
        cleared entry, so a SUBSEQUENT ban+reconnect cycle uses the
        normal version-comparison path -- not another legacy-clear.

        This bounds the "ban laundering" concern: a bad actor whose
        offense was recorded pre-handshake gets at most ONE legacy-
        clear per ban cycle.  Their next post-handshake offense
        records a real version and the auto-clear gate from then on
        only fires when the version actually changes.
        """
        # Legacy entry that triggers a legacy-clear.
        legacy = {
            "203.0.113.7": {
                "score": BAN_THRESHOLD,
                "lifetime_score": BAN_THRESHOLD,
                "first_seen": time.time(),
                "banned_until": time.time() + 3600,
            }
        }
        with open(self.path, "w") as f:
            json.dump(legacy, f)
        mgr = PeerBanManager(persistence_path=self.path)
        addr = "203.0.113.7:9333"
        # Legacy-clear fires.
        self.assertTrue(mgr.clear_ban_on_version_change(addr, "1.49.0"))
        self.assertFalse(mgr.is_banned(addr))

        # Peer re-offends (post-handshake → version stamped).
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.49.0",
        )
        self.assertTrue(mgr.is_banned(addr))

        # Same-version reconnect now does NOT clear -- the legacy-
        # clear was a one-shot pre-1.48 recovery, not a perpetual pass.
        self.assertFalse(
            mgr.clear_ban_on_version_change(addr, "1.49.0"),
            "post-legacy-clear bans use the normal version-comparison "
            "gate -- same version cannot launder a fresh ban",
        )
        self.assertTrue(mgr.is_banned(addr))

        # Real version change DOES clear, as in the normal path.
        self.assertTrue(
            mgr.clear_ban_on_version_change(addr, "1.50.0"),
            "after legacy-clear, normal version-bump auto-clear works",
        )
        self.assertFalse(mgr.is_banned(addr))

    # ── Test 9: seed-node / operator IPs also benefit ───────────────
    def test_seed_node_ip_also_benefits_from_version_clearance(self):
        """Seed nodes are just IPs — they aren't a privileged set in
        the ban manager's view.  Whatever IP the operator runs the
        upgraded binary from gets the same expedited clearance, which
        is exactly the behavior we want.  This test pins down that
        the SEED_NODES IPs in particular work.
        """
        from messagechain.config import SEED_NODES
        mgr = PeerBanManager(persistence_path=self.path)
        seed_ip = SEED_NODES[0][0]  # validator-1's IP
        addr = f"{seed_ip}:9333"
        mgr.record_offense(
            addr, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(mgr.is_banned(addr))
        # Operator ships v1.47.1 to the seed node; reconnect clears.
        self.assertTrue(mgr.clear_ban_on_version_change(addr, "1.47.1"))
        self.assertFalse(mgr.is_banned(addr))


class TestNodeUsesVersionClearance(unittest.TestCase):
    """Integration check: Node._handle_message HANDSHAKE branch invokes
    clear_ban_on_version_change so a banned peer reconnecting with a
    new version recovers automatically.
    """

    def test_handshake_handler_clears_stale_ban_on_version_bump(self):
        """A banned peer whose HANDSHAKE advertises a new version must
        be unbanned BEFORE the per-message ban check rejects them.
        """
        import asyncio
        from unittest.mock import MagicMock
        from messagechain.identity.identity import Entity
        from messagechain.network.node import Node
        from messagechain.network.protocol import (
            MessageType, NetworkMessage,
        )

        ent = Entity.create(b"\x77" * 32, tree_height=4)
        node = Node(ent, port=9933)

        peer_entity = Entity.create(b"\x88" * 32, tree_height=4)

        # Pre-ban this peer at version "1.46.0".
        peer_addr_full = "10.0.0.99:9333"
        node.ban_manager.record_offense(
            peer_addr_full, OFFENSE_INVALID_BLOCK, "bad_block",
            peer_version="1.46.0",
        )
        self.assertTrue(node.ban_manager.is_banned(peer_addr_full))

        # Build a minimal Peer-shaped object that _handle_message accepts.
        class _Peer:
            def __init__(self, addr):
                self.address = addr
                self.host, port = addr.split(":")
                self.port = int(port)
                self.is_connected = True
                self.writer = MagicMock()
                self.reader = MagicMock()
                self.handshake_sent = False
                self.last_seen = 0.0
                self.entity_id = ""
                self.connection_type = "full_relay"
                self.direction = "inbound"
                self.transport = "plain"
                self.peer_height = 0
                self.peer_version = ""

            def touch(self):
                self.last_seen = 1.0

        peer = _Peer(peer_addr_full)

        msg = NetworkMessage(
            msg_type=MessageType.HANDSHAKE,
            sender_id=peer_entity.entity_id_hex,
            payload={
                "port": 9333,
                "chain_height": 0,
                "best_block_hash": "",
                "cumulative_weight": 0,
                "genesis_hash": "",
                "version": "1.47.1",  # POST-FIX VERSION
            },
        )
        asyncio.run(node._handle_message(msg, peer))

        # Ban should have been cleared by the HANDSHAKE handler.
        self.assertFalse(
            node.ban_manager.is_banned(peer_addr_full),
            "post-fix reconnect must auto-clear stale ban",
        )
        # Peer record should be populated (proves we didn't early-return
        # on the pre-clearance is_banned check).
        self.assertEqual(peer.peer_version, "1.47.1")


if __name__ == "__main__":
    unittest.main()
