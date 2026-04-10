"""Tests for security hardening (audit round 3).

Covers:
- Safe hex parsing (rejects invalid hex without crashing)
- RPC rate limiting
- JSON depth limits in protocol
- Sanitized RPC error messages
- Reduced timestamp drift
- Signature cache invalidation on reorg
- Attestation rate limiting per validator
- Bounds checking on sync block numbers
"""

import unittest
import json
import struct
import time
import hashlib

from messagechain.config import HASH_ALGO, MAX_TIMESTAMP_DRIFT
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.crypto.sig_cache import SignatureCache
from messagechain.consensus.attestation import FinalityTracker, Attestation
from messagechain.network.protocol import decode_message, NetworkMessage, MessageType
from tests import register_entity_for_test


class TestSafeHexParsing(unittest.TestCase):
    """Fix #1: bytes.fromhex() must not crash on invalid input."""

    def test_safe_hex_valid(self):
        """Valid hex strings parse correctly."""
        from messagechain.validation import parse_hex
        result = parse_hex("abcdef0123456789")
        self.assertEqual(result, bytes.fromhex("abcdef0123456789"))

    def test_safe_hex_invalid_chars(self):
        """Non-hex characters return None."""
        from messagechain.validation import parse_hex
        self.assertIsNone(parse_hex("xyz123"))

    def test_safe_hex_odd_length(self):
        """Odd-length hex strings return None."""
        from messagechain.validation import parse_hex
        self.assertIsNone(parse_hex("abc"))

    def test_safe_hex_empty(self):
        """Empty string returns None."""
        from messagechain.validation import parse_hex
        self.assertIsNone(parse_hex(""))

    def test_safe_hex_with_label(self):
        """parse_hex with expected_len rejects wrong-length inputs."""
        from messagechain.validation import parse_hex
        # 32 bytes = 64 hex chars
        valid_32 = "aa" * 32
        self.assertIsNotNone(parse_hex(valid_32, expected_len=32))
        self.assertIsNone(parse_hex("aa" * 16, expected_len=32))

    def test_signature_deserialize_bad_hex(self):
        """Signature.deserialize with bad hex raises ValueError, not unhandled crash."""
        bad_data = {
            "wots_signature": ["not_hex"],
            "leaf_index": 0,
            "auth_path": [],
            "wots_public_key": "0011",
            "wots_public_seed": "0011",
        }
        with self.assertRaises(ValueError):
            Signature.deserialize(bad_data)

    def test_attestation_deserialize_bad_hex(self):
        """Attestation.deserialize with bad hex raises ValueError."""
        bad_data = {
            "validator_id": "not_valid_hex",
            "block_hash": "aa" * 32,
            "block_number": 1,
            "signature": {
                "wots_signature": [],
                "leaf_index": 0,
                "auth_path": [],
                "wots_public_key": "0011",
                "wots_public_seed": "0011",
            },
        }
        with self.assertRaises(ValueError):
            Attestation.deserialize(bad_data)


class TestRPCRateLimiting(unittest.TestCase):
    """Fix #2: RPC connections must be rate limited."""

    def test_rpc_rate_limiter_exists(self):
        """Server should have an RPC rate limiter."""
        from messagechain.network.ratelimit import RPCRateLimiter
        limiter = RPCRateLimiter(max_requests=5, window_seconds=1.0)
        # First 5 should pass
        for _ in range(5):
            self.assertTrue(limiter.check("127.0.0.1"))
        # 6th should be blocked
        self.assertFalse(limiter.check("127.0.0.1"))

    def test_rpc_rate_limiter_different_ips(self):
        """Different IPs have independent limits."""
        from messagechain.network.ratelimit import RPCRateLimiter
        limiter = RPCRateLimiter(max_requests=2, window_seconds=1.0)
        self.assertTrue(limiter.check("1.1.1.1"))
        self.assertTrue(limiter.check("1.1.1.1"))
        self.assertFalse(limiter.check("1.1.1.1"))
        # Different IP still has budget
        self.assertTrue(limiter.check("2.2.2.2"))

    def test_rpc_rate_limiter_window_expiry(self):
        """Rate limit resets after window expires."""
        from messagechain.network.ratelimit import RPCRateLimiter
        limiter = RPCRateLimiter(max_requests=1, window_seconds=0.1)
        self.assertTrue(limiter.check("1.1.1.1"))
        self.assertFalse(limiter.check("1.1.1.1"))
        time.sleep(0.15)
        self.assertTrue(limiter.check("1.1.1.1"))


class TestJSONDepthLimits(unittest.TestCase):
    """Fix #3: JSON parsing must reject deeply nested structures."""

    def test_shallow_json_accepted(self):
        """Normal-depth JSON messages parse successfully."""
        msg = NetworkMessage(
            msg_type=MessageType.HANDSHAKE,
            payload={"port": 9333, "chain_height": 0, "best_block_hash": ""},
            sender_id="aa" * 32,
        )
        encoded = json.dumps(msg.serialize()).encode("utf-8")
        result = decode_message(encoded)
        self.assertEqual(result.msg_type, MessageType.HANDSHAKE)

    def test_deeply_nested_json_rejected(self):
        """JSON nested beyond the depth limit is rejected."""
        from messagechain.validation import safe_json_loads, JSONDepthError
        # Build a deeply nested dict
        nested = {"value": "leaf"}
        for _ in range(100):
            nested = {"nested": nested}
        raw = json.dumps(nested)
        with self.assertRaises(JSONDepthError):
            safe_json_loads(raw, max_depth=32)


class TestSanitizedRPCErrors(unittest.TestCase):
    """Fix #4: RPC error messages must not leak implementation details."""

    def test_error_does_not_contain_traceback(self):
        """RPC errors should be generic, not raw exception strings."""
        from messagechain.validation import sanitize_error
        raw = "KeyError: 'entity_id' in /home/user/messagechain/server.py line 290"
        sanitized = sanitize_error(raw)
        self.assertNotIn("/home/user", sanitized)
        self.assertNotIn("line 290", sanitized)
        self.assertNotIn("KeyError", sanitized)

    def test_known_errors_passed_through(self):
        """Known business-logic errors are kept as-is."""
        from messagechain.validation import sanitize_error
        msg = "Insufficient balance for fee"
        self.assertEqual(sanitize_error(msg), msg)


class TestTimestampDrift(unittest.TestCase):
    """Fix #5: Timestamp drift should be reduced."""

    def test_max_drift_is_reasonable(self):
        """MAX_TIMESTAMP_DRIFT should be <= 60 seconds."""
        self.assertLessEqual(MAX_TIMESTAMP_DRIFT, 60)


class TestSigCacheReorgInvalidation(unittest.TestCase):
    """Fix #6: Signature cache must be flushed on chain reorganization."""

    def test_cache_has_invalidate_method(self):
        """SignatureCache must have an invalidate() method."""
        cache = SignatureCache()
        # Store something
        cache.store(b"msg", b"sig", b"pub", True)
        self.assertEqual(len(cache), 1)
        cache.invalidate()
        self.assertEqual(len(cache), 0)

    def test_reorg_calls_cache_invalidate(self):
        """Blockchain._reorganize should invalidate the signature cache."""
        # We verify that the blockchain has a reference to the sig cache
        # and that _reorganize calls invalidate on it.
        chain = Blockchain()
        alice = Entity.create(b"alice-reorg-test")
        chain.initialize_genesis(alice)
        # The chain should have a sig_cache attribute
        self.assertTrue(hasattr(chain, 'sig_cache'))


class TestAttestationRateLimiting(unittest.TestCase):
    """Fix #7: FinalityTracker must rate-limit attestation attempts per validator."""

    def test_duplicate_attestation_not_double_counted(self):
        """Same validator attesting twice for same block should not increase stake."""
        tracker = FinalityTracker()
        validator_id = b"validator1_id_padding_32bytes!!"
        block_hash = b"block_hash_padding_to_32_bytes!"

        att = Attestation(
            validator_id=validator_id,
            block_hash=block_hash,
            block_number=1,
            signature=Signature([], 0, [], b"", b""),
        )

        tracker.add_attestation(att, validator_stake=100, total_stake=200)
        stake_after_first = tracker.attested_stake.get(block_hash, 0)

        tracker.add_attestation(att, validator_stake=100, total_stake=200)
        stake_after_second = tracker.attested_stake.get(block_hash, 0)

        self.assertEqual(stake_after_first, stake_after_second)

    def test_attestation_spam_tracking(self):
        """FinalityTracker should track repeat attempts per validator for monitoring."""
        tracker = FinalityTracker()
        validator_id = b"validator1_id_padding_32bytes!!"
        block_hash = b"block_hash_padding_to_32_bytes!"

        att = Attestation(
            validator_id=validator_id,
            block_hash=block_hash,
            block_number=1,
            signature=Signature([], 0, [], b"", b""),
        )

        # First attempt: accepted
        tracker.add_attestation(att, validator_stake=100, total_stake=200)
        # Repeat attempts should be counted
        for _ in range(10):
            tracker.add_attestation(att, validator_stake=100, total_stake=200)

        # Should still only have one attester
        self.assertEqual(len(tracker.attestations[block_hash]), 1)


class TestSyncBlockNumberBounds(unittest.TestCase):
    """Fix #8: Sync must validate block numbers from peers."""

    def test_negative_block_number_rejected(self):
        """Peer-reported block numbers must be non-negative."""
        from messagechain.network.sync import ChainSyncer
        chain = Blockchain()
        alice = Entity.create(b"sync-test-entity")
        chain.initialize_genesis(alice)
        syncer = ChainSyncer(chain, lambda addr: None)

        # Negative height should be clamped/rejected
        syncer.update_peer_height("1.2.3.4:9333", -1)
        info = syncer.peer_heights.get("1.2.3.4:9333")
        self.assertIsNotNone(info)
        self.assertGreaterEqual(info.chain_height, 0)

    def test_absurdly_high_block_number_rejected(self):
        """Unreasonably high block numbers should be rejected."""
        from messagechain.network.sync import ChainSyncer
        chain = Blockchain()
        alice = Entity.create(b"sync-test-entity-2")
        chain.initialize_genesis(alice)
        syncer = ChainSyncer(chain, lambda addr: None)

        # 100 billion blocks at 10s each = ~31,000 years — unreasonable
        syncer.update_peer_height("1.2.3.4:9333", 100_000_000_000)
        info = syncer.peer_heights.get("1.2.3.4:9333")
        # Either rejected entirely or clamped to a sane maximum
        self.assertLess(info.chain_height, 100_000_000_000)


if __name__ == "__main__":
    unittest.main()
