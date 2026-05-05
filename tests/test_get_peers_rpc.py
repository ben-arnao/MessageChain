"""Observability: get_peers RPC returns metadata about every connected peer.

Closes a gap flagged in the iter 47-56 hardening batch: outside observers
had no way to see the current validator network shape (who's connected,
at what height, for how long, inbound vs outbound, what version).
`messagechain info`, `status`, and `validators` cover chain state; none
cover the p2p topology.

This test exercises the RPC at the Server dispatch layer without spinning
up a real network — it populates `server.peers` with Peer objects and
calls `_rpc_get_peers` directly.
"""

from __future__ import annotations

import time
import unittest

from messagechain.network.peer import Peer, ConnectionType
from messagechain.network.sync import PeerSyncInfo


class _StubSyncer:
    """Minimal stand-in for ChainSyncer — only the attributes _rpc_get_peers
    reads.  Lets the RPC test exercise its height-source logic without
    standing up a real syncer (which would pull in a Blockchain, mempool,
    etc., none of which the operator-facing RPC actually depends on)."""

    def __init__(self):
        self.peer_heights: dict[str, PeerSyncInfo] = {}


class TestGetPeersRPC(unittest.TestCase):

    def setUp(self):
        # Import lazily so a missing server.Server doesn't break collection.
        from server import Server
        self.server = Server.__new__(Server)
        self.server.peers = {}
        self.server.syncer = _StubSyncer()

    def _add_peer(
        self, host: str, port: int, *, direction: str = "outbound",
        height: int = 0, version: str = "", entity_id: str = "",
        connection_type: ConnectionType = ConnectionType.FULL_RELAY,
        connected_at: float | None = None,
        is_connected: bool = True,
    ) -> Peer:
        p = Peer(host=host, port=port)
        p.is_connected = is_connected
        p.direction = direction
        p.peer_height = height
        p.peer_version = version
        p.entity_id = entity_id
        p.connection_type = connection_type
        p.connected_at = connected_at if connected_at is not None else time.time()
        self.server.peers[p.address] = p
        return p

    def test_empty_peer_set(self):
        from server import Server
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result, {"ok": True, "result": {"peers": [], "count": 0}})

    def test_single_inbound_peer(self):
        from server import Server
        self._add_peer(
            "10.0.0.5", 9333, direction="inbound",
            height=142, version="mc/1.0", entity_id="deadbeef" * 8,
            connected_at=time.time() - 30,
        )
        result = Server._rpc_get_peers(self.server)
        self.assertTrue(result["ok"])
        peers = result["result"]["peers"]
        self.assertEqual(len(peers), 1)
        p = peers[0]
        self.assertEqual(p["address"], "10.0.0.5:9333")
        self.assertEqual(p["direction"], "inbound")
        self.assertEqual(p["height"], 142)
        self.assertEqual(p["version"], "mc/1.0")
        self.assertEqual(p["entity_id"], "deadbeef" * 8)
        self.assertEqual(p["connection_type"], "full_relay")
        self.assertEqual(p["connected"], True)
        # seconds_connected is computed from connected_at → now
        self.assertGreaterEqual(p["seconds_connected"], 29)
        self.assertLessEqual(p["seconds_connected"], 60)

    def test_multiple_peers_sorted_by_address(self):
        from server import Server
        self._add_peer("10.0.0.5", 9333)
        self._add_peer("10.0.0.1", 9333)
        self._add_peer("10.0.0.9", 9333)
        result = Server._rpc_get_peers(self.server)
        addrs = [p["address"] for p in result["result"]["peers"]]
        self.assertEqual(addrs, ["10.0.0.1:9333", "10.0.0.5:9333", "10.0.0.9:9333"])
        self.assertEqual(result["result"]["count"], 3)

    def test_disconnected_peer_still_listed_with_flag(self):
        """A peer object can linger in self.peers after the socket dies.
        Surface it so operators can see 'connection recently dropped'."""
        from server import Server
        self._add_peer(
            "10.0.0.5", 9333, is_connected=False,
            connected_at=time.time() - 600,
        )
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(len(result["result"]["peers"]), 1)
        self.assertFalse(result["result"]["peers"][0]["connected"])

    def test_no_entity_id_renders_as_empty(self):
        """Peers that haven't completed the wallet-id handshake have
        entity_id == "" — the RPC must render that cleanly, not crash."""
        from server import Server
        self._add_peer("10.0.0.5", 9333, entity_id="")
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["entity_id"], "")

    def test_transport_defaults_to_plain(self):
        """A Peer constructed without a transport hint is plain TCP.

        Safe default: the only code paths that can upgrade to TLS are
        the ones that actually negotiate it.  If an operator wants to
        assert "my inbound peer X is running TLS" but the Peer was
        built without setting the field, they see 'plain' — honest and
        auditable, not a speculative 'tls' that could be wrong.
        """
        from server import Server
        self._add_peer("10.0.0.5", 9333)
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["transport"], "plain")

    def test_height_uses_live_syncer_value_over_stale_handshake(self):
        """The RPC must surface the syncer's live peer height — what every
        consensus path already uses — not the frozen handshake-time value
        on the Peer object.

        Repro of the bug this test guards against: validators connect at
        height 1508, run for 10 hours, both advance to 1568, but the peers
        table on each shows the other still at 1508 because peer.peer_height
        is set once at handshake and never updated.  The 10s _sync_loop
        keeps syncer.peer_heights current; the RPC now reads from there.
        """
        from server import Server
        self._add_peer("10.0.0.5", 9333, height=1508)
        self.server.syncer.peer_heights["10.0.0.5:9333"] = PeerSyncInfo(
            peer_address="10.0.0.5:9333",
            chain_height=1568,
        )
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["height"], 1568)

    def test_height_falls_back_to_handshake_when_syncer_has_no_entry(self):
        """A peer that just handshook hasn't yet had a chain-height
        round-trip recorded by the syncer (the _sync_loop runs every 10s).
        In that gap the RPC should still surface the handshake value
        rather than reporting 0."""
        from server import Server
        self._add_peer("10.0.0.5", 9333, height=1508)
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["height"], 1508)

    def test_height_zero_in_syncer_falls_back_to_handshake(self):
        """A PeerSyncInfo can exist with chain_height==0 if the syncer was
        populated before the peer responded.  Treat that as 'no live
        evidence yet' and fall back to the handshake value, so the table
        never reports a peer that was at 1508 ten seconds ago as 0."""
        from server import Server
        self._add_peer("10.0.0.5", 9333, height=1508)
        self.server.syncer.peer_heights["10.0.0.5:9333"] = PeerSyncInfo(
            peer_address="10.0.0.5:9333",
            chain_height=0,
        )
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["height"], 1508)

    def test_transport_tls_surfaces(self):
        """When a peer is created over TLS the RPC surfaces it.

        This is the observability hook for "is my outbound peer
        connection actually encrypted, or did TLS silently fall back
        to plaintext?"  An operator who set P2P_TLS_ENABLED=True
        wants to VERIFY that — reading the journal is too slow; a
        single CLI row per peer lets them eyeball the whole fleet.
        """
        from server import Server
        p = self._add_peer("10.0.0.5", 9333)
        p.transport = "tls"
        result = Server._rpc_get_peers(self.server)
        self.assertEqual(result["result"]["peers"][0]["transport"], "tls")


if __name__ == "__main__":
    unittest.main()
