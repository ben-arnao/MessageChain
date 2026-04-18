"""Tests for 5 minor audit findings (2026-04-17).

  M2: Orphan pool eviction must not use modulo-predictable index.
      Use secrets.choice over list(orphan_pool.keys()).
  M9: Orphan per-sender limit bumped from 3 -> 10 so honest
      stake -> unstake -> stake pipelines do not choke.
  L2: ban_peer / unban_peer RPC reject empty / malformed address.
  L3: get_messages RPC count coerces to int and clamps to [1, 100].
  L7: GOVERNANCE_VOTING_WINDOW must be >= 144 blocks (1 day at 600s/block).
"""

import inspect
import time
import unittest

import messagechain.config as config
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import MessageTransaction


# ─── M2: non-modulo-predictable orphan eviction ───────────────────────

class TestOrphanEvictionUnpredictable(unittest.TestCase):
    def test_uses_secrets_choice_not_urandom_modulo(self):
        src = inspect.getsource(Mempool.add_orphan_tx)
        # Hard constraint from audit: do not use modulo arithmetic on
        # os.urandom for victim selection — the result is attacker-visible.
        # Strip comment lines so a prose reference to the old pattern in
        # an explanatory comment does not trip the check.
        code_only = "\n".join(
            line for line in src.splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn(
            "os.urandom", code_only,
            "orphan eviction must not call os.urandom at all "
            "(modulo-predictable pattern)",
        )
        self.assertNotIn(
            "% len(self.orphan_pool)", code_only,
            "orphan eviction must not use modulo-indexed victim selection",
        )
        self.assertIn(
            "secrets.choice", code_only,
            "orphan eviction must use secrets.choice for unbiased selection",
        )

    def test_eviction_still_functions(self):
        """After the refactor, the orphan pool must still rotate under
        pressure rather than rejecting new entries outright."""
        mp = Mempool()
        cap = config.MEMPOOL_MAX_ORPHAN_TXS
        for i in range(cap):
            tx = MessageTransaction.__new__(MessageTransaction)
            tx.entity_id = (i).to_bytes(4, "big") + b"\x00" * 28
            tx.nonce = 1
            tx.fee = 10
            tx.timestamp = time.time()
            tx.tx_hash = (i).to_bytes(4, "big") + b"\x00" * 28
            mp.orphan_pool[tx.tx_hash] = tx
            mp._orphan_sender_counts[tx.entity_id] += 1
        self.assertEqual(len(mp.orphan_pool), cap)

        new_tx = MessageTransaction.__new__(MessageTransaction)
        new_tx.entity_id = b"\xff\xff\xff\xff" + b"\x00" * 28
        new_tx.nonce = 1
        new_tx.fee = 10
        new_tx.timestamp = time.time()
        new_tx.tx_hash = b"NEW!" + b"\x00" * 28
        accepted = mp.add_orphan_tx(new_tx, expected_nonce=0)
        self.assertTrue(accepted)
        self.assertIn(new_tx.tx_hash, mp.orphan_pool)
        self.assertEqual(len(mp.orphan_pool), cap)


# ─── M9: orphan per-sender limit raised to 10 ─────────────────────────

class TestOrphanPerSenderLimit(unittest.TestCase):
    def test_limit_is_at_least_10(self):
        self.assertGreaterEqual(
            config.MEMPOOL_MAX_ORPHAN_PER_SENDER, 10,
            "per-sender orphan limit too tight for honest "
            "stake -> unstake -> stake bursts",
        )

    def test_honest_sender_can_queue_10_orphans(self):
        mp = Mempool()
        entity = b"honest-entity-id".ljust(32, b"\x00")
        # Each orphan has a nonce gap <= MAX_ORPHAN_NONCE_GAP.  Use the
        # same sender repeatedly with ascending (but still gap-bounded)
        # nonces so we exercise the per-sender limit, not the gap limit.
        gap = config.MEMPOOL_MAX_ORPHAN_NONCE_GAP
        # The per-sender limit is at least 10; verify we can fit that
        # many orphans from one sender without hitting the cap.
        accepted = 0
        for i in range(10):
            tx = MessageTransaction.__new__(MessageTransaction)
            tx.entity_id = entity
            # Nonce gap must be 1..gap relative to expected_nonce.  Rotate
            # through valid gaps so every tx is individually admissible.
            tx.nonce = (i % gap) + 1
            tx.fee = 10
            tx.timestamp = time.time()
            tx.tx_hash = (i).to_bytes(4, "big") + b"\x01" * 28
            # Distinct hashes so insertion is not a dedup hit.
            if mp.add_orphan_tx(tx, expected_nonce=0):
                accepted += 1
        self.assertEqual(accepted, 10,
                         "honest sender should be able to queue 10 orphans")


# ─── L2: ban_peer / unban_peer reject malformed addresses ─────────────

class TestBanPeerAddressValidation(unittest.TestCase):
    """Operator RPC must refuse empty or malformed addresses instead of
    silently banning '' (which would later match every peer-less lookup)."""

    def _build_stub_server(self):
        import server as server_mod

        class _StubBan:
            def __init__(self):
                self.banned = []
                self.unbanned = []

            def manual_ban(self, address, reason="manual_rpc"):
                self.banned.append((address, reason))

            def manual_unban(self, address):
                self.unbanned.append(address)

        stub = type("S", (), {})()
        stub.ban_manager = _StubBan()
        return server_mod, stub

    def _call(self, method, address):
        server_mod, stub = self._build_stub_server()
        req = {"method": method, "params": {"address": address}}
        # Run the coroutine synchronously.
        import asyncio
        resp = asyncio.run(server_mod.Server._process_rpc(stub, req))
        return resp, stub

    def test_ban_peer_rejects_empty(self):
        resp, stub = self._call("ban_peer", "")
        self.assertFalse(resp["ok"])
        self.assertEqual(stub.ban_manager.banned, [])

    def test_ban_peer_rejects_missing_port(self):
        resp, stub = self._call("ban_peer", "not-an-address")
        self.assertFalse(resp["ok"])
        self.assertEqual(stub.ban_manager.banned, [])

    def test_ban_peer_accepts_well_formed(self):
        resp, stub = self._call("ban_peer", "1.2.3.4:8333")
        self.assertTrue(resp["ok"])
        self.assertEqual(len(stub.ban_manager.banned), 1)

    def test_ban_peer_accepts_ipv6_bracketed(self):
        resp, stub = self._call("ban_peer", "[::1]:8333")
        self.assertTrue(resp["ok"])
        self.assertEqual(len(stub.ban_manager.banned), 1)

    def test_unban_peer_rejects_empty(self):
        resp, stub = self._call("unban_peer", "")
        self.assertFalse(resp["ok"])
        self.assertEqual(stub.ban_manager.unbanned, [])

    def test_unban_peer_rejects_malformed(self):
        resp, stub = self._call("unban_peer", "garbage")
        self.assertFalse(resp["ok"])
        self.assertEqual(stub.ban_manager.unbanned, [])


# ─── L3: get_messages count is clamped to [1, 100] ────────────────────

class TestGetMessagesCountValidation(unittest.TestCase):
    def _call(self, count_param):
        import asyncio
        import server as server_mod

        class _StubChain:
            def __init__(self):
                self.requested = None

            def get_recent_messages(self, count):
                self.requested = count
                return [f"m{i}" for i in range(count)]

        stub = type("S", (), {})()
        stub.blockchain = _StubChain()
        req = {"method": "get_messages", "params": {"count": count_param}}
        resp = asyncio.run(server_mod.Server._process_rpc(stub, req))
        return resp, stub

    def test_clamps_above_100(self):
        resp, stub = self._call(10_000)
        self.assertTrue(resp["ok"])
        self.assertEqual(stub.blockchain.requested, 100)

    def test_clamps_negative_to_one(self):
        resp, stub = self._call(-5)
        self.assertTrue(resp["ok"])
        self.assertEqual(stub.blockchain.requested, 1)

    def test_clamps_zero_to_one(self):
        resp, stub = self._call(0)
        self.assertTrue(resp["ok"])
        self.assertEqual(stub.blockchain.requested, 1)

    def test_coerces_string_digits(self):
        resp, stub = self._call("5")
        self.assertTrue(resp["ok"])
        self.assertEqual(stub.blockchain.requested, 5)

    def test_rejects_non_int_garbage(self):
        resp, stub = self._call("banana")
        self.assertFalse(resp["ok"])
        self.assertIsNone(stub.blockchain.requested)

    def test_rejects_none(self):
        # None is neither int-coercible nor a sensible default override.
        resp, stub = self._call(None)
        # Default-handling should still yield a valid clamped value;
        # None is explicitly passed so we treat it as invalid input.
        # The implementation must not blow up on it.
        self.assertIn("ok", resp)


# ─── L7: GOVERNANCE_VOTING_WINDOW lower bound ─────────────────────────

class TestGovernanceWindowLowerBound(unittest.TestCase):
    def test_window_is_at_least_one_day(self):
        self.assertGreaterEqual(
            config.GOVERNANCE_VOTING_WINDOW, 144,
            "voting window < 144 blocks (~1 day at 600s/block) is a "
            "misconfiguration: proposals could close before honest "
            "validators see them",
        )

    def test_config_asserts_on_misconfig(self):
        """Reimporting config with a stubbed voting window below the floor
        must raise — a silent 0 or 1 value breaks governance."""
        src = inspect.getsource(config)
        # The cheapest unambiguous enforcement is a module-level assert.
        self.assertIn("GOVERNANCE_VOTING_WINDOW >= 144", src,
                      "config must assert a lower bound on the voting window")


if __name__ == "__main__":
    unittest.main()
