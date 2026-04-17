"""
Tests for external interface security fixes (TDD).

Bug 1: Key file permissions warn-only -> must raise KeyFileError
Bug 2: Stake/unstake nonce uses on-chain instead of pending
Bug 3: estimate_fee no message size validation
Bug 4: Client JSON depth unbounded
Bug 5: Submission server IP reservation DoS (LRU eviction)
"""

import json
import os
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from messagechain.identity.key_encoding import encode_private_key


# ============================================================================
# Bug 1: Key file permissions
# ============================================================================

class TestKeyFilePermissions(unittest.TestCase):
    """Key files with group/world-readable permissions must be rejected."""

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
    def test_key_file_strict_permissions_rejected(self):
        """A key file with 0o644 must raise KeyFileError, not just warn."""
        from messagechain.cli import _load_key_from_file, KeyFileError

        key = os.urandom(32)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            f.write(encode_private_key(key))
            path = f.name
        try:
            os.chmod(path, 0o644)
            with self.assertRaises(KeyFileError) as ctx:
                _load_key_from_file(path)
            self.assertIn("readable by group/others", str(ctx.exception))
        finally:
            os.unlink(path)

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
    def test_key_file_correct_permissions_accepted(self):
        """A key file with 0o600 must load successfully."""
        from messagechain.cli import _load_key_from_file

        key = os.urandom(32)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as f:
            f.write(encode_private_key(key))
            path = f.name
        try:
            os.chmod(path, 0o600)
            loaded = _load_key_from_file(path)
            self.assertEqual(loaded, key)
        finally:
            os.unlink(path)


# ============================================================================
# Bug 2: Stake/unstake nonce uses on-chain instead of pending
# ============================================================================

class TestStakeUnstakePendingNonce(unittest.TestCase):
    """Consecutive stake/unstake txs must use pending nonces, not on-chain."""

    def setUp(self):
        from messagechain import config
        self._orig_height = config.MERKLE_TREE_HEIGHT
        config.MERKLE_TREE_HEIGHT = 6

    def tearDown(self):
        from messagechain import config
        config.MERKLE_TREE_HEIGHT = self._orig_height

    def _make_server(self):
        """Create a minimal Server with a registered, funded entity."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.identity.identity import Entity
        from messagechain.crypto.hash_sig import _hash
        from messagechain.config import MIN_FEE

        entity = Entity.create(b"stake-nonce-test" + b"\x00" * 16, tree_height=6)
        chain = Blockchain()
        chain.initialize_genesis(entity)
        chain.supply.balances[entity.entity_id] = 1_000_000
        mempool = Mempool()

        # Build a mock server with the relevant state
        server = MagicMock()
        server.blockchain = chain
        server.mempool = mempool
        server._pending_stake_txs = {}
        server._pending_unstake_txs = {}
        server._pending_authority_txs = {}
        server._pending_governance_txs = {}

        return server, entity

    def test_consecutive_stake_txs_accepted(self):
        """Two stake txs submitted back-to-back must both be accepted."""
        from messagechain.core.staking import (
            create_stake_transaction, verify_stake_transaction,
        )
        from messagechain.config import MIN_FEE
        import server as server_module

        srv, entity = self._make_server()

        Server = server_module.Server
        rpc_stake = Server._rpc_stake

        # First stake tx at nonce 0
        tx1 = create_stake_transaction(entity, amount=10_000, nonce=0, fee=MIN_FEE)

        # Bind real methods to mock server
        srv._admit_to_pool = lambda pool_attr, tx: (
            getattr(srv, pool_attr).__setitem__(tx.tx_hash, tx) or True
        )
        srv._check_leaf_across_all_pools = lambda tx: True
        srv._schedule_pending_tx_gossip = lambda *a: None
        srv._get_pending_nonce_all_pools = (
            lambda eid: Server._get_pending_nonce_all_pools(srv, eid)
        )

        result1 = rpc_stake(srv, {"transaction": tx1.serialize()})
        self.assertTrue(result1.get("ok"), f"First stake tx failed: {result1}")

        # Second stake tx at nonce 1 — should be accepted via pending nonce
        tx2 = create_stake_transaction(entity, amount=10_000, nonce=1, fee=MIN_FEE)
        result2 = rpc_stake(srv, {"transaction": tx2.serialize()})
        self.assertTrue(result2.get("ok"), f"Second stake tx failed: {result2}")

    def test_consecutive_unstake_txs_accepted(self):
        """Two unstake txs submitted back-to-back must both be accepted."""
        from messagechain.core.staking import (
            create_stake_transaction, create_unstake_transaction,
            verify_unstake_transaction,
        )
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.core.block import Block
        from messagechain.config import MIN_FEE
        import server as server_module

        srv, entity = self._make_server()

        # First, give entity some staked amount by applying a block with a stake tx
        stx = create_stake_transaction(entity, amount=100_000, nonce=0, fee=MIN_FEE)
        consensus = ProofOfStake()
        block = srv.blockchain.propose_block(
            consensus, entity, [], stake_transactions=[stx],
        )
        ok, reason = srv.blockchain.add_block(block)
        self.assertTrue(ok, reason)
        # entity nonce is now 1

        Server = server_module.Server
        rpc_unstake = Server._rpc_unstake

        srv._admit_to_pool = lambda pool_attr, tx: (
            getattr(srv, pool_attr).__setitem__(tx.tx_hash, tx) or True
        )
        srv._check_leaf_across_all_pools = lambda tx: True
        srv._schedule_pending_tx_gossip = lambda *a: None
        srv._get_pending_nonce_all_pools = (
            lambda eid: Server._get_pending_nonce_all_pools(srv, eid)
        )

        # First unstake at nonce 1
        tx1 = create_unstake_transaction(entity, amount=10_000, nonce=1, fee=MIN_FEE)
        result1 = rpc_unstake(srv, {"transaction": tx1.serialize()})
        self.assertTrue(result1.get("ok"), f"First unstake tx failed: {result1}")

        # Second unstake at nonce 2 — should be accepted via pending nonce
        tx2 = create_unstake_transaction(entity, amount=10_000, nonce=2, fee=MIN_FEE)
        result2 = rpc_unstake(srv, {"transaction": tx2.serialize()})
        self.assertTrue(result2.get("ok"), f"Second unstake tx failed: {result2}")


# ============================================================================
# Bug 3: estimate_fee no message size validation
# ============================================================================

class TestEstimateFeeSizeValidation(unittest.TestCase):
    """estimate_fee must reject oversized messages before encoding."""

    def _make_server(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.mempool import Mempool
        from messagechain.identity.identity import Entity

        entity = Entity.create(b"fee-test" + b"\x00" * 24, tree_height=6)
        chain = Blockchain()
        chain.initialize_genesis(entity)
        mempool = Mempool()

        srv = MagicMock()
        srv.blockchain = chain
        srv.mempool = mempool
        return srv

    def test_estimate_fee_rejects_oversized(self):
        """A 10000-char message must be rejected."""
        import server as server_module
        srv = self._make_server()

        result = server_module.Server._rpc_estimate_fee(
            srv, {"kind": "message", "message": "A" * 10_000}
        )
        self.assertFalse(result["ok"])
        self.assertIn("exceeds", result["error"].lower())

    def test_estimate_fee_normal(self):
        """A 280-char message must return a valid fee estimate."""
        import server as server_module
        srv = self._make_server()

        # Need mempool.get_fee_estimate to work
        srv.mempool.get_fee_estimate = lambda: 1

        result = server_module.Server._rpc_estimate_fee(
            srv, {"kind": "message", "message": "A" * 280}
        )
        self.assertTrue(result["ok"], f"Expected ok, got: {result}")
        self.assertIn("min_fee", result["result"])


# ============================================================================
# Bug 4: Client JSON depth unbounded
# ============================================================================

class TestClientJsonDepth(unittest.TestCase):
    """Client must reject deeply nested JSON from rogue servers."""

    def test_client_rejects_deep_json(self):
        """Mock a server response with 100-level nesting; client should reject."""
        from messagechain.validation import safe_json_loads

        # Build deeply nested JSON (100 levels)
        deep_json = '{"a":' * 100 + '1' + '}' * 100
        deep_bytes = deep_json.encode("utf-8")

        # The client should use safe_json_loads which rejects depth > 32
        with self.assertRaises(ValueError) as ctx:
            safe_json_loads(deep_bytes, max_depth=32)
        self.assertIn("depth", str(ctx.exception).lower())

    def test_client_rpc_call_uses_safe_json(self):
        """rpc_call must use safe_json_loads, not bare json.loads."""
        import client

        # Build a deeply nested response
        deep_json = '{"a":' * 100 + '1' + '}' * 100
        response_bytes = deep_json.encode("utf-8")
        length_prefix = struct.pack(">I", len(response_bytes))

        with patch("client.socket") as mock_socket_mod:
            mock_sock = MagicMock()
            mock_socket_mod.socket.return_value = mock_sock
            mock_socket_mod.AF_INET = 2
            mock_socket_mod.SOCK_STREAM = 1

            # recv returns the length prefix then the response body
            recv_data = [length_prefix, response_bytes]
            call_count = [0]

            def fake_recv(n):
                if call_count[0] < len(recv_data):
                    data = recv_data[call_count[0]]
                    call_count[0] += 1
                    return data
                return b""

            mock_sock.recv = fake_recv

            with self.assertRaises((ValueError, Exception)):
                client.rpc_call("127.0.0.1", 9334, "test", {})


# ============================================================================
# Bug 5: Submission server IP reservation DoS (LRU eviction)
# ============================================================================

class TestSubmissionServerLRUEviction(unittest.TestCase):
    """When all IP slots are active, oldest must be evicted (LRU)."""

    def _make_context(self, max_ips=4):
        """Create a _HandlerContext with a small IP cap for testing."""
        from messagechain.network.submission_server import _HandlerContext

        blockchain = MagicMock()
        mempool = MagicMock()
        ctx = _HandlerContext(blockchain, mempool, relay_callback=None)
        ctx._max_tracked_ips = max_ips
        return ctx

    def test_eviction_makes_room_when_all_active(self):
        """Fill all IP slots with active IPs, then a new IP must evict the oldest."""
        ctx = self._make_context(max_ips=4)

        now = time.time()

        # Fill all 4 slots, each consuming a token to stay "active"
        for i in range(4):
            ip = f"10.0.0.{i}"
            ctx.rate_limit_check(ip)

        self.assertEqual(len(ctx._buckets), 4)

        # Drain all buckets so they're "active" (not fully refilled)
        # and set last_refill to now so _refill() won't re-fill them.
        for i, ip in enumerate(["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            ctx._buckets[ip].tokens = 0
            ctx._buckets[ip].last_refill = now

        # Set distinct last_active timestamps so 10.0.0.0 is the oldest
        for i, ip in enumerate(["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            ctx._last_active[ip] = now - (100 - i * 10)

        result = ctx.rate_limit_check("10.0.0.99")
        # The new IP must be admitted
        self.assertTrue(result)
        self.assertIn("10.0.0.99", ctx._buckets)
        # The oldest IP (10.0.0.0) should be evicted
        self.assertNotIn("10.0.0.0", ctx._buckets)
        self.assertEqual(len(ctx._buckets), 4)

    def test_normal_eviction_still_works(self):
        """Inactive (fully-refilled) buckets are still evicted first."""
        ctx = self._make_context(max_ips=4)

        # Fill all 4 slots
        for i in range(4):
            ctx.rate_limit_check(f"10.0.0.{i}")

        # Let slot 0 and 1 refill fully (inactive)
        ctx._buckets["10.0.0.0"].tokens = ctx._buckets["10.0.0.0"].max_tokens
        ctx._buckets["10.0.0.1"].tokens = ctx._buckets["10.0.0.1"].max_tokens

        # Keep slot 2 and 3 partially drained (active)
        ctx._buckets["10.0.0.2"].tokens = 0
        ctx._buckets["10.0.0.3"].tokens = 0

        # New IP should evict inactive ones first
        result = ctx.rate_limit_check("10.0.0.99")
        self.assertTrue(result)
        self.assertIn("10.0.0.99", ctx._buckets)
        # At least one of the inactive ones should be gone
        inactive_gone = (
            "10.0.0.0" not in ctx._buckets or
            "10.0.0.1" not in ctx._buckets
        )
        self.assertTrue(inactive_gone)


if __name__ == "__main__":
    unittest.main()
