"""
Tests for Tier 1 network security features:
- Peer misbehavior scoring & banning
- Per-peer rate limiting
- inv/getdata transaction relay
"""

import time
import unittest

from messagechain.network.ban import (
    PeerBanManager, PeerScore, BAN_THRESHOLD, BAN_DURATION,
    OFFENSE_INVALID_BLOCK, OFFENSE_INVALID_TX, OFFENSE_INVALID_HEADERS,
    OFFENSE_UNREQUESTED_DATA, OFFENSE_PROTOCOL_VIOLATION, OFFENSE_RATE_LIMIT,
    OFFENSE_MINOR,
)
from messagechain.network.ratelimit import PeerRateLimiter, TokenBucket
from messagechain.network.peer import Peer, _LRUSet
from messagechain.network.protocol import MessageType


# ══════════════════════════════════════════════════════════════════
# Peer Ban Manager Tests
# ══════════════════════════════════════════════════════════════════

class TestPeerScore(unittest.TestCase):
    def test_initial_state(self):
        ps = PeerScore()
        assert ps.score == 0
        assert ps.banned_until == 0.0
        assert not ps.is_banned
        assert ps.offenses == []

    def test_is_banned_when_banned_until_set(self):
        ps = PeerScore(banned_until=time.time() + 3600)
        assert ps.is_banned

    def test_ban_expires(self):
        ps = PeerScore(score=100, banned_until=time.time() - 1)
        assert not ps.is_banned
        # Score and offenses should be reset after expiry
        assert ps.score == 0
        assert ps.offenses == []


class TestPeerBanManager(unittest.TestCase):
    def test_fresh_peer_not_banned(self):
        mgr = PeerBanManager()
        assert not mgr.is_banned("192.168.1.1:9333")
        assert mgr.get_score("192.168.1.1:9333") == 0

    def test_minor_offense_does_not_ban(self):
        mgr = PeerBanManager()
        banned = mgr.record_offense("192.168.1.1:9333", OFFENSE_MINOR, "minor")
        assert not banned
        assert mgr.get_score("192.168.1.1:9333") == 1
        assert not mgr.is_banned("192.168.1.1:9333")

    def test_invalid_block_instant_ban(self):
        mgr = PeerBanManager()
        banned = mgr.record_offense("10.0.0.1:9333", OFFENSE_INVALID_BLOCK, "bad block")
        assert banned
        assert mgr.is_banned("10.0.0.1:9333")

    def test_invalid_tx_instant_ban(self):
        mgr = PeerBanManager()
        banned = mgr.record_offense("10.0.0.2:9333", OFFENSE_INVALID_TX, "bad tx")
        assert banned
        assert mgr.is_banned("10.0.0.2:9333")

    def test_cumulative_offenses_trigger_ban(self):
        mgr = PeerBanManager()
        addr = "10.0.0.3:9333"

        # 20 rate-limit offenses (5 points each) = 100 total
        for i in range(19):
            result = mgr.record_offense(addr, OFFENSE_RATE_LIMIT, f"rate_limit_{i}")
            assert not result  # not yet banned

        result = mgr.record_offense(addr, OFFENSE_RATE_LIMIT, "rate_limit_final")
        assert result  # now banned
        assert mgr.is_banned(addr)

    def test_ban_uses_ip_not_port(self):
        """Banning should be by IP, so different ports from same IP are also banned."""
        mgr = PeerBanManager()
        mgr.record_offense("10.0.0.5:9333", OFFENSE_INVALID_BLOCK, "bad block")
        # Same IP, different port
        assert mgr.is_banned("10.0.0.5:9334")
        assert mgr.is_banned("10.0.0.5:1234")

    def test_manual_ban(self):
        mgr = PeerBanManager()
        mgr.manual_ban("10.0.0.6:9333", reason="manual test")
        assert mgr.is_banned("10.0.0.6:9333")

    def test_manual_unban(self):
        mgr = PeerBanManager()
        mgr.manual_ban("10.0.0.7:9333")
        assert mgr.is_banned("10.0.0.7:9333")
        mgr.manual_unban("10.0.0.7:9333")
        assert not mgr.is_banned("10.0.0.7:9333")

    def test_get_banned_peers(self):
        mgr = PeerBanManager()
        mgr.manual_ban("10.0.0.8:9333", reason="test1")
        mgr.manual_ban("10.0.0.9:9333", reason="test2")

        banned = mgr.get_banned_peers()
        ips = {b["ip"] for b in banned}
        assert "10.0.0.8" in ips
        assert "10.0.0.9" in ips
        assert len(banned) == 2

    def test_cleanup_expired(self):
        mgr = PeerBanManager()
        # Add a peer with zero score and no offenses
        mgr._scores["10.0.0.10"] = PeerScore(score=0, offenses=[])
        mgr.cleanup_expired()
        assert "10.0.0.10" not in mgr._scores

    def test_offense_history_trimmed(self):
        mgr = PeerBanManager()
        addr = "10.0.0.11:9333"
        # Record 60 minor offenses
        for i in range(60):
            mgr.record_offense(addr, OFFENSE_MINOR, f"offense_{i}")
        ps = mgr._scores["10.0.0.11"]
        assert len(ps.offenses) <= 50

    def test_already_banned_peer_stays_banned(self):
        mgr = PeerBanManager()
        addr = "10.0.0.12:9333"
        mgr.record_offense(addr, OFFENSE_INVALID_BLOCK, "bad block")
        assert mgr.is_banned(addr)
        # More offenses on an already-banned peer
        result = mgr.record_offense(addr, OFFENSE_MINOR, "another one")
        assert result  # still banned

    def test_custom_threshold_and_duration(self):
        mgr = PeerBanManager(ban_threshold=10, ban_duration=60)
        addr = "10.0.0.13:9333"
        mgr.record_offense(addr, 10, "custom")
        assert mgr.is_banned(addr)

    def test_evict_oldest_on_max_tracked(self):
        from messagechain.network.ban import MAX_TRACKED_PEERS
        mgr = PeerBanManager()
        # Simulate many peers
        for i in range(MAX_TRACKED_PEERS):
            mgr._scores[f"10.0.{i // 256}.{i % 256}"] = PeerScore()
        # Adding one more should not crash
        mgr.record_offense("99.99.99.99:9333", OFFENSE_MINOR, "new peer")
        assert len(mgr._scores) <= MAX_TRACKED_PEERS


# ══════════════════════════════════════════════════════════════════
# Rate Limiter Tests
# ══════════════════════════════════════════════════════════════════

class TestTokenBucket(unittest.TestCase):
    def test_initial_full(self):
        bucket = TokenBucket(rate=10, max_tokens=50)
        assert bucket.tokens == 50

    def test_consume_succeeds_when_tokens_available(self):
        bucket = TokenBucket(rate=10, max_tokens=50)
        assert bucket.consume()
        assert bucket.tokens == 49

    def test_consume_fails_when_empty(self):
        bucket = TokenBucket(rate=10, max_tokens=5)
        for _ in range(5):
            assert bucket.consume()
        assert not bucket.consume()

    def test_refill_over_time(self):
        bucket = TokenBucket(rate=100, max_tokens=100)
        # Drain it
        for _ in range(100):
            bucket.consume()
        assert not bucket.consume()
        # Simulate time passing (hack last_refill)
        bucket.last_refill -= 1.0  # 1 second ago
        assert bucket.consume()  # refill should have added 100 tokens

    def test_does_not_exceed_max(self):
        bucket = TokenBucket(rate=100, max_tokens=10)
        bucket.last_refill -= 10.0  # lots of time
        bucket._refill()
        assert bucket.tokens <= 10


class TestPeerRateLimiter(unittest.TestCase):
    def test_fresh_peer_allowed(self):
        rl = PeerRateLimiter()
        assert rl.check("10.0.0.1:9333", "tx")

    def test_rate_limit_after_burst(self):
        rl = PeerRateLimiter()
        addr = "10.0.0.2:9333"
        # Exhaust the tx bucket (burst=50)
        for _ in range(50):
            assert rl.check(addr, "tx")
        # Next one should be rejected
        assert not rl.check(addr, "tx")

    def test_different_categories_independent(self):
        rl = PeerRateLimiter()
        addr = "10.0.0.3:9333"
        # Exhaust tx bucket
        for _ in range(50):
            rl.check(addr, "tx")
        assert not rl.check(addr, "tx")
        # General bucket should still work
        assert rl.check(addr, "general")

    def test_different_peers_independent(self):
        rl = PeerRateLimiter()
        # Exhaust peer1's tx bucket
        for _ in range(50):
            rl.check("10.0.0.4:9333", "tx")
        assert not rl.check("10.0.0.4:9333", "tx")
        # Peer2 should still be fine
        assert rl.check("10.0.0.5:9333", "tx")

    def test_same_ip_different_port_shared(self):
        """Rate limits should be per-IP, not per-port."""
        rl = PeerRateLimiter()
        # Exhaust from port 9333
        for _ in range(50):
            rl.check("10.0.0.6:9333", "tx")
        # Same IP, different port should also be limited
        assert not rl.check("10.0.0.6:9334", "tx")

    def test_unknown_category_allowed(self):
        rl = PeerRateLimiter()
        assert rl.check("10.0.0.7:9333", "unknown_category")

    def test_remove_peer(self):
        rl = PeerRateLimiter()
        rl.check("10.0.0.8:9333", "tx")
        rl.remove_peer("10.0.0.8:9333")
        # After removal, buckets should be recreated fresh
        # Exhaust and check it's fresh (should have full burst again)
        count = 0
        while rl.check("10.0.0.8:9333", "tx"):
            count += 1
            if count > 100:
                break
        assert count == 50  # fresh bucket

    def test_cleanup_stale(self):
        rl = PeerRateLimiter()
        rl.check("10.0.0.9:9333", "tx")
        # Hack: set last_refill to long ago
        for bucket in rl._buckets["10.0.0.9"].values():
            bucket.last_refill -= 1000
        rl.cleanup_stale(max_age=600)
        assert "10.0.0.9" not in rl._buckets

    def test_block_req_rate_limit(self):
        rl = PeerRateLimiter()
        addr = "10.0.0.10:9333"
        # Block request burst is 10
        for _ in range(10):
            assert rl.check(addr, "block_req")
        assert not rl.check(addr, "block_req")


# ══════════════════════════════════════════════════════════════════
# LRU Set Tests (used for peer known_txs tracking)
# ══════════════════════════════════════════════════════════════════

class TestLRUSet(unittest.TestCase):
    def test_add_and_contains(self):
        s = _LRUSet(10)
        s.add("a")
        assert "a" in s
        assert "b" not in s

    def test_evicts_oldest(self):
        s = _LRUSet(3)
        s.add("a")
        s.add("b")
        s.add("c")
        s.add("d")  # should evict "a"
        assert "a" not in s
        assert "b" in s
        assert "d" in s

    def test_access_refreshes(self):
        s = _LRUSet(3)
        s.add("a")
        s.add("b")
        s.add("c")
        s.add("a")  # refresh "a"
        s.add("d")  # should evict "b" (oldest non-refreshed)
        assert "a" in s
        assert "b" not in s
        assert "c" in s
        assert "d" in s

    def test_len(self):
        s = _LRUSet(5)
        s.add("a")
        s.add("b")
        assert len(s) == 2

    def test_maxsize_respected(self):
        s = _LRUSet(3)
        for i in range(100):
            s.add(str(i))
        assert len(s) == 3


# ══════════════════════════════════════════════════════════════════
# inv/getdata Protocol Tests
# ══════════════════════════════════════════════════════════════════

class TestInvGetdataProtocol(unittest.TestCase):
    def test_inv_message_type_exists(self):
        assert MessageType.INV.value == "inv"

    def test_getdata_message_type_exists(self):
        assert MessageType.GETDATA.value == "getdata"

    def test_peer_known_txs_tracking(self):
        peer = Peer(host="10.0.0.1", port=9333)
        assert "abc123" not in peer.known_txs
        peer.known_txs.add("abc123")
        assert "abc123" in peer.known_txs

    def test_peer_known_txs_bounded(self):
        from messagechain.config import SEEN_TX_CACHE_SIZE
        peer = Peer(host="10.0.0.1", port=9333)
        for i in range(SEEN_TX_CACHE_SIZE + 100):
            peer.known_txs.add(f"tx_{i}")
        assert len(peer.known_txs) == SEEN_TX_CACHE_SIZE


# ══════════════════════════════════════════════════════════════════
# Integration: Ban + Rate Limit interaction
# ══════════════════════════════════════════════════════════════════

class TestBanRateLimitIntegration(unittest.TestCase):
    def test_repeated_rate_limits_lead_to_ban(self):
        """If a peer keeps hitting rate limits, they accumulate enough points to get banned."""
        ban_mgr = PeerBanManager()
        rate_limiter = PeerRateLimiter()
        addr = "10.0.0.20:9333"

        # Exhaust rate limit
        while rate_limiter.check(addr, "tx"):
            pass

        # Now each attempt records an offense
        ban_count = 0
        for i in range(100):
            if not rate_limiter.check(addr, "tx"):
                banned = ban_mgr.record_offense(addr, OFFENSE_RATE_LIMIT, "rate_limit:tx")
                if banned:
                    ban_count += 1
                    break

        assert ban_mgr.is_banned(addr)

    def test_banned_peer_score_persists_across_reconnect(self):
        """Banning by IP means reconnecting on a different port doesn't help."""
        ban_mgr = PeerBanManager()
        ban_mgr.record_offense("10.0.0.21:9333", OFFENSE_INVALID_BLOCK, "bad block")
        assert ban_mgr.is_banned("10.0.0.21:9333")
        assert ban_mgr.is_banned("10.0.0.21:9999")
        assert ban_mgr.is_banned("10.0.0.21:1")


# ══════════════════════════════════════════════════════════════════
# Node message category mapping
# ══════════════════════════════════════════════════════════════════

class TestMessageCategoryMapping(unittest.TestCase):
    """Test that the Node._msg_category method correctly maps message types."""

    def test_tx_category(self):
        from messagechain.network.node import Node
        from messagechain.identity.biometrics import Entity
        entity = Entity.create(b"test-dna", b"test-finger", b"test-iris")
        node = Node(entity, port=19333)
        assert node._msg_category(MessageType.ANNOUNCE_TX) == "tx"
        assert node._msg_category(MessageType.INV) == "tx"
        assert node._msg_category(MessageType.GETDATA) == "tx"

    def test_block_req_category(self):
        from messagechain.network.node import Node
        from messagechain.identity.biometrics import Entity
        entity = Entity.create(b"test-dna", b"test-finger", b"test-iris")
        node = Node(entity, port=19334)
        assert node._msg_category(MessageType.REQUEST_BLOCK) == "block_req"
        assert node._msg_category(MessageType.REQUEST_BLOCKS_BATCH) == "block_req"

    def test_headers_req_category(self):
        from messagechain.network.node import Node
        from messagechain.identity.biometrics import Entity
        entity = Entity.create(b"test-dna", b"test-finger", b"test-iris")
        node = Node(entity, port=19335)
        assert node._msg_category(MessageType.REQUEST_HEADERS) == "headers_req"

    def test_general_category(self):
        from messagechain.network.node import Node
        from messagechain.identity.biometrics import Entity
        entity = Entity.create(b"test-dna", b"test-finger", b"test-iris")
        node = Node(entity, port=19336)
        assert node._msg_category(MessageType.HANDSHAKE) == "general"
        assert node._msg_category(MessageType.PEER_LIST) == "general"
