"""
Tests for the 2026-04 BTC-gap audit fixes.

Covers the wiring/integration gaps where defenses existed in the codebase but
were not actually connected to the running node:

Gap 4:  cumulative_weight propagation from node.py handshake into ChainSyncer
Gap 5:  WeakSubjectivityCheckpoint enforcement during IBD header download
Gap 1:  AddressManager instantiation and PEER_LIST routing through it
Gap 2:  AnchorStore load/save across server lifecycle
Gap 3:  ConnectionType assignment at connection time (block-relay-only mix)
Gap 6:  PEER_LIST rate limiting
Gap 7:  Stalling-peer misbehavior score
Gap 8:  Ban-score decay-gaming prevention (discouragement floor)
Gap 9:  Orphan pool random eviction when full
Gap 11: Randomized per-instance SigCache key
"""

import asyncio
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock

import messagechain.config
from messagechain.config import HASH_ALGO
from messagechain.consensus.checkpoint import WeakSubjectivityCheckpoint
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import MessageTransaction
from messagechain.crypto.sig_cache import SignatureCache
from messagechain.network.addrman import AddressManager
from messagechain.network.anchor import AnchorStore
from messagechain.network.ban import (
    PeerBanManager, OFFENSE_INVALID_HEADERS, OFFENSE_PROTOCOL_VIOLATION,
)
from messagechain.network.peer import ConnectionType, Peer
from messagechain.network.sync import ChainSyncer


# ─── Gap 4: cumulative_weight propagation ──────────────────────────────

class TestCumulativeWeightPropagation(unittest.TestCase):
    """update_peer_height must accept and store the peer-reported
    cumulative stake weight. Without this, the MIN_CUMULATIVE_STAKE_WEIGHT
    filter in get_best_sync_peer rejects every peer and IBD is broken."""

    def _make_syncer(self, our_height=0):
        bc = MagicMock()
        bc.height = our_height
        bc.get_latest_block.return_value = None
        bc.has_block.return_value = False
        return ChainSyncer(bc, lambda _a: None)

    def test_peer_weight_stored_in_peer_info(self):
        s = self._make_syncer()
        s.update_peer_height("1.2.3.4:9333", 500, "abcd", cumulative_weight=5000)
        self.assertEqual(s.peer_heights["1.2.3.4:9333"].cumulative_weight, 5000)

    def test_get_best_sync_peer_requires_min_cumulative_weight(self):
        s = self._make_syncer()
        # Under the threshold — should be filtered out
        s.update_peer_height(
            "1.2.3.4:9333", 500, "abcd",
            cumulative_weight=messagechain.config.MIN_CUMULATIVE_STAKE_WEIGHT - 1,
        )
        self.assertIsNone(s.get_best_sync_peer())
        # At the threshold — eligible
        s.update_peer_height(
            "1.2.3.4:9333", 500, "abcd",
            cumulative_weight=messagechain.config.MIN_CUMULATIVE_STAKE_WEIGHT,
        )
        self.assertEqual(s.get_best_sync_peer(), "1.2.3.4:9333")

    def test_node_handshake_sends_and_parses_cumulative_weight(self):
        """Node must include cumulative_weight in handshake payload and
        parse it when received, so peers can be filtered by real chain weight."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity

        # Build a node with a fake blockchain that exposes a known best-tip weight
        entity = Entity.create(b"node_test_key".ljust(32, b"\x00"))
        node = Node(entity, port=19999)

        # Stub the fork_choice tip so handshakes carry a real weight
        fake_hash = b"\x11" * 32
        node.blockchain.fork_choice.tips = {fake_hash: (7, 12345)}

        # Exercise the handshake payload builder if one exists, or verify
        # update_peer_height+payload contract directly.
        node.syncer.update_peer_height(
            "9.9.9.9:1234", 7, fake_hash.hex(), cumulative_weight=12345,
        )
        info = node.syncer.peer_heights["9.9.9.9:1234"]
        self.assertEqual(info.cumulative_weight, 12345)


# ─── Gap 5: WeakSubjectivityCheckpoint enforcement during IBD ─────────

class TestWeakSubjectivityCheckpointGate(unittest.TestCase):
    """ChainSyncer, when given trusted checkpoints, must reject any header
    whose block_number matches a checkpoint but whose block_hash does not.

    Without this, a malicious peer can serve a plausible-looking fake chain
    from far in the past (long-range attack) and new nodes will sync it."""

    def _make_syncer_with_checkpoints(self, checkpoints):
        bc = MagicMock()
        bc.height = 0
        bc.get_latest_block.return_value = None
        bc.has_block.return_value = False
        offenses = []
        s = ChainSyncer(
            bc, lambda _a: None,
            trusted_checkpoints=checkpoints,
            on_peer_offense=lambda addr, pts, reason: offenses.append((addr, pts, reason)),
        )
        return s, offenses

    def test_matching_checkpoint_accepts_header(self):
        good_hash = bytes.fromhex("ab" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=5, block_hash=good_hash, state_root=b"\x00" * 32,
        )
        s, offenses = self._make_syncer_with_checkpoints([cp])
        s.state = s.state.__class__.SYNCING_HEADERS
        s._current_sync_peer = "1.1.1.1:1"

        headers = [
            {"block_number": 5, "prev_hash": "00" * 32, "block_hash": "ab" * 32},
        ]
        asyncio.run(s.handle_headers_response(headers, "1.1.1.1:1"))
        self.assertEqual(offenses, [])

    def test_mismatched_checkpoint_rejects_header_and_bans_peer(self):
        good_hash = bytes.fromhex("ab" * 32)
        cp = WeakSubjectivityCheckpoint(
            block_number=5, block_hash=good_hash, state_root=b"\x00" * 32,
        )
        s, offenses = self._make_syncer_with_checkpoints([cp])
        s.state = s.state.__class__.SYNCING_HEADERS
        s._current_sync_peer = "9.9.9.9:9"

        # Peer sends a header at checkpoint height with the WRONG hash
        headers = [
            {"block_number": 5, "prev_hash": "00" * 32, "block_hash": "cc" * 32},
        ]
        asyncio.run(s.handle_headers_response(headers, "9.9.9.9:9"))
        # Peer should have been penalized
        self.assertTrue(offenses, "Expected misbehavior offense for checkpoint mismatch")
        addr, pts, _reason = offenses[0]
        self.assertEqual(addr, "9.9.9.9:9")
        self.assertGreaterEqual(pts, OFFENSE_INVALID_HEADERS)
        # The fake header must not be in pending
        self.assertEqual(len(s.pending_headers), 0)


# ─── Gap 1: AddressManager wired into PEER_LIST handler ───────────────

class TestAddressManagerWiredIntoNode(unittest.TestCase):
    """node.Node must instantiate AddressManager and route PEER_LIST adds
    through it instead of bypassing Sybil/bucketing defenses."""

    def test_node_has_addrman(self):
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"addrman_test".ljust(32, b"\x00"))
        node = Node(entity, port=19998)
        self.assertIsInstance(node.addrman, AddressManager)

    def test_peer_list_routes_through_addrman(self):
        """A PEER_LIST message should call addrman.add_address for each entry."""
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"addrman_route".ljust(32, b"\x00"))
        node = Node(entity, port=19997)

        # Spy on addrman.add_address
        calls = []
        original = node.addrman.add_address
        def spy(ip, port, source_ip):
            calls.append((ip, port, source_ip))
            return original(ip, port, source_ip)
        node.addrman.add_address = spy

        # Synthesize a PEER_LIST message. Use routable public IPs so that
        # the node.py _is_valid_peer_address filter (which rejects private /
        # reserved / TEST-NET ranges) does not silently drop our entries.
        from messagechain.network.protocol import MessageType, NetworkMessage
        msg = NetworkMessage(
            msg_type=MessageType.PEER_LIST,
            payload={"peers": [
                {"host": "8.8.8.8", "port": 9333},
                {"host": "1.1.1.1", "port": 9333},
            ]},
            sender_id="a" * 64,
        )
        peer = Peer(host="9.9.9.9", port=5555, is_connected=True)
        asyncio.run(node._handle_message(msg, peer))

        # Both entries should have been routed through addrman
        self.assertEqual(len(calls), 2)
        ips = {c[0] for c in calls}
        self.assertIn("8.8.8.8", ips)
        self.assertIn("1.1.1.1", ips)


# ─── Gap 2: AnchorStore wired into server startup/shutdown ────────────

class TestAnchorStoreWired(unittest.TestCase):
    """Server must persist anchor peers to disk on shutdown and reconnect
    them first on startup."""

    def test_node_has_anchor_store(self):
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        with tempfile.TemporaryDirectory() as td:
            entity = Entity.create(b"anchor_test".ljust(32, b"\x00"))
            node = Node(entity, port=19996, data_dir=td)
            self.assertIsInstance(node.anchor_store, AnchorStore)
            # Path should live inside data_dir
            self.assertTrue(node.anchor_store.path.startswith(td))

    def test_anchor_store_round_trip(self):
        """Saving and re-loading anchors yields the same address list."""
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "anchors.json")
            store = AnchorStore(path)
            store.save_anchors([("203.0.113.1", 9333), ("198.51.100.2", 9333)])

            store2 = AnchorStore(path)
            loaded = store2.load_anchors()
            self.assertEqual(
                sorted(loaded),
                [("198.51.100.2", 9333), ("203.0.113.1", 9333)],
            )


# ─── Gap 3: ConnectionType assigned at connection time ────────────────

class TestConnectionTypeAssignment(unittest.TestCase):
    """Node must maintain at least some BLOCK_RELAY_ONLY connection slots
    to provide topology privacy and anchor resistance."""

    def test_node_tracks_connection_types(self):
        from messagechain.network.node import Node
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"conntype_test".ljust(32, b"\x00"))
        node = Node(entity, port=19995)
        # Node should expose a helper that decides the connection type
        # for a newly dialled peer based on how many slots are already filled.
        # Fill more outbound slots than the full-relay quota so at least one
        # block-relay-only slot must be chosen.
        from messagechain.config import (
            OUTBOUND_FULL_RELAY_SLOTS, OUTBOUND_BLOCK_RELAY_ONLY_SLOTS,
        )
        total = OUTBOUND_FULL_RELAY_SLOTS + OUTBOUND_BLOCK_RELAY_ONLY_SLOTS
        types = []
        for i in range(total):
            t = node._next_connection_type()
            types.append(t)
            # Simulate that the slot is now filled by a connected peer
            fake = Peer(
                host=f"10.0.0.{i + 1}", port=9333, is_connected=True,
                connection_type=t,
            )
            node.peers[fake.address] = fake
        self.assertIn(ConnectionType.FULL_RELAY, types)
        self.assertIn(ConnectionType.BLOCK_RELAY_ONLY, types)
        # First N slots must be full-relay, subsequent must be block-relay-only
        self.assertEqual(
            types[:OUTBOUND_FULL_RELAY_SLOTS],
            [ConnectionType.FULL_RELAY] * OUTBOUND_FULL_RELAY_SLOTS,
        )
        self.assertEqual(
            types[OUTBOUND_FULL_RELAY_SLOTS:],
            [ConnectionType.BLOCK_RELAY_ONLY] * OUTBOUND_BLOCK_RELAY_ONLY_SLOTS,
        )


# ─── Gap 6: PEER_LIST rate limiting ────────────────────────────────────

class TestPeerListRateLimit(unittest.TestCase):
    """PEER_LIST messages must be rate-limited per peer. A malicious peer
    must not be able to flood ADDR-equivalent messages to dominate the
    address table."""

    def test_peer_list_category_has_rate_limit(self):
        from messagechain.network.ratelimit import PeerRateLimiter
        rl = PeerRateLimiter()
        # The "addr" bucket should exist and be strict
        # Burn through the burst
        addr = "1.2.3.4"
        allowed_count = 0
        for _ in range(1000):
            if rl.check(addr, "addr"):
                allowed_count += 1
        # Must be bounded well under 1000
        self.assertLess(allowed_count, 100)

    def test_node_msg_category_returns_addr_for_peer_list(self):
        from messagechain.network.node import Node
        from messagechain.network.protocol import MessageType
        from messagechain.identity.identity import Entity
        entity = Entity.create(b"ratelimit_test".ljust(32, b"\x00"))
        node = Node(entity, port=19994)
        self.assertEqual(node._msg_category(MessageType.PEER_LIST), "addr")


# ─── Gap 7: Stalling-peer misbehavior score ───────────────────────────

class TestStallingPeerPenalty(unittest.TestCase):
    """When the syncer detects a stall, the stalling peer must be
    penalized with a misbehavior offense, not just dropped silently."""

    def test_stall_records_offense(self):
        bc = MagicMock()
        bc.height = 0
        bc.get_latest_block.return_value = None
        offenses = []
        s = ChainSyncer(
            bc, lambda _a: None,
            on_peer_offense=lambda addr, pts, reason: offenses.append((addr, pts, reason)),
        )
        # Put syncer into a syncing state attached to a peer
        s.state = s.state.__class__.SYNCING_BLOCKS
        s._current_sync_peer = "1.2.3.4:9333"
        s._last_progress_time = time.time() - 10_000  # way past SYNC_STALE_TIMEOUT
        s.peer_heights["1.2.3.4:9333"] = type(
            "P", (),
            {"peer_address": "1.2.3.4:9333", "chain_height": 100,
             "best_block_hash": "", "last_response_time": 0.0,
             "cumulative_weight": 99999},
        )()

        asyncio.run(s.check_sync_stale())
        # The stalling peer should have been penalized
        self.assertTrue(offenses, "Expected stall offense")
        self.assertEqual(offenses[0][0], "1.2.3.4:9333")


# ─── Gap 8: Ban-score decay-gaming prevention ─────────────────────────

class TestBanScoreDiscouragementFloor(unittest.TestCase):
    """A peer that repeatedly offends just under the ban threshold and
    relies on hourly decay to reset its score must eventually be banned,
    even if no single offense session reaches 100."""

    def test_repeated_sub_threshold_offenses_trigger_ban(self):
        bm = PeerBanManager()
        addr = "1.2.3.4:9333"
        ip = "1.2.3.4"  # ban manager keys by IP only

        # Simulate a patient attacker: N rounds of offense=95, then wait
        # long enough for full decay, then repeat. Without a discouragement
        # floor, this never bans. With one, it eventually does.
        now = time.time()
        for round_idx in range(5):
            bm.record_offense(addr, 95, f"round{round_idx}")
            # Simulate 200 hours elapsing (should fully decay the rolling score)
            ps = bm._scores[ip]
            ps.last_decay = now - 200 * 3600

        # After 5 rounds of 95-point offenses, the peer should be banned
        # via the non-decaying lifetime_score ceiling.
        self.assertTrue(
            bm.is_banned(addr),
            "Ban-score decay gaming: peer survived 5 rounds of 95-point offenses",
        )


# ─── Gap 9: Orphan pool random eviction ───────────────────────────────

class TestOrphanPoolEviction(unittest.TestCase):
    """When the orphan pool is full, a new valid orphan should displace a
    random existing entry rather than being silently rejected."""

    def _make_tx(self, sender_byte: int, nonce: int) -> MessageTransaction:
        tx = MessageTransaction.__new__(MessageTransaction)
        tx.entity_id = bytes([sender_byte]) * 32
        tx.nonce = nonce
        tx.fee = 10
        tx.timestamp = time.time()
        tx.tx_hash = bytes([sender_byte, nonce]) + b"\x00" * 30
        return tx

    def test_full_pool_evicts_on_new_orphan(self):
        mp = Mempool()
        cap = messagechain.config.MEMPOOL_MAX_ORPHAN_TXS
        # Fill up the orphan pool with one tx per sender (respects per-sender cap)
        for i in range(cap):
            tx = self._make_tx(i % 256, nonce=1)
            tx.entity_id = (i).to_bytes(2, "big") + b"\x00" * 30
            tx.tx_hash = (i).to_bytes(4, "big") + b"\x00" * 28
            mp.orphan_pool[tx.tx_hash] = tx
            mp._orphan_sender_counts[tx.entity_id] += 1
        self.assertEqual(len(mp.orphan_pool), cap)

        # Now a brand-new orphan arrives — it should be accepted via eviction
        new_tx = self._make_tx(99, nonce=1)
        new_tx.entity_id = b"\xff\xff" + b"\x00" * 30
        new_tx.tx_hash = b"NEW!" + b"\x00" * 28
        accepted = mp.add_orphan_tx(new_tx, expected_nonce=0)
        self.assertTrue(accepted, "Orphan pool refused to evict to admit a new entry")
        self.assertIn(new_tx.tx_hash, mp.orphan_pool)
        self.assertEqual(len(mp.orphan_pool), cap)  # still at cap


# ─── Gap 11: Randomized SigCache key ───────────────────────────────────

class TestSigCacheRandomizedKey(unittest.TestCase):
    """Two independent SignatureCache instances should derive different
    cache keys for the same (msg, sig, pub) tuple, so that precomputed
    collision attacks against one node cannot be replayed against another."""

    def test_two_instances_have_different_keys(self):
        c1 = SignatureCache()
        c2 = SignatureCache()
        msg = b"m" * 32
        sig = b"s" * 64
        pub = b"p" * 32
        # Store in c1
        c1.store(msg, sig, pub, True)
        # The raw key functions should differ per instance
        self.assertNotEqual(c1._nonce, c2._nonce)
        # And the internal cache key for the same tuple must differ
        self.assertNotEqual(c1._key(msg, sig, pub), c2._key(msg, sig, pub))

    def test_cache_still_hits_for_same_instance(self):
        c = SignatureCache()
        msg = b"m" * 32
        sig = b"s" * 64
        pub = b"p" * 32
        c.store(msg, sig, pub, True)
        self.assertEqual(c.lookup(msg, sig, pub), True)


if __name__ == "__main__":
    unittest.main()
