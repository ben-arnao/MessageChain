"""Tests for mempool size limits and transaction expiry."""

import time
import unittest
from unittest.mock import patch
from messagechain.identity.identity import Entity
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.config import MIN_FEE, FEE_PER_BYTE

# Static fee policy for tests that aren't testing fee dynamics
_STATIC_FEE = DynamicFeePolicy(base_fee=100, max_fee=100)

# Minimum valid fee for a short test message (accounts for FEE_PER_BYTE)
_TEST_MSG_FEE = MIN_FEE + 20 * FEE_PER_BYTE  # generous for "msg X" style messages


class TestMempoolLimits(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def _make_tx(self, fee: int, nonce: int, ts: float | None = None):
        tx = create_transaction(
            self.alice, f"msg {nonce}", fee=fee, nonce=nonce
        )
        if ts is not None:
            tx.timestamp = ts
        return tx

    def test_mempool_respects_max_size(self):
        """Mempool should not exceed max_size."""
        pool = Mempool(max_size=3, fee_policy=_STATIC_FEE)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=_TEST_MSG_FEE + i, nonce=i))
        self.assertEqual(pool.size, 3)

    def test_low_fee_evicted_when_full(self):
        """Lowest-fee tx is evicted to make room for higher-fee tx."""
        pool = Mempool(max_size=2, fee_policy=_STATIC_FEE)
        tx1 = self._make_tx(fee=_TEST_MSG_FEE, nonce=0)
        tx2 = self._make_tx(fee=_TEST_MSG_FEE + 100, nonce=1)
        pool.add_transaction(tx1)
        pool.add_transaction(tx2)
        self.assertEqual(pool.size, 2)

        # Add higher fee tx — should evict tx1
        tx3 = self._make_tx(fee=_TEST_MSG_FEE + 200, nonce=2)
        accepted = pool.add_transaction(tx3)
        self.assertTrue(accepted)
        self.assertEqual(pool.size, 2)
        self.assertNotIn(tx1.tx_hash, pool.pending)
        self.assertIn(tx3.tx_hash, pool.pending)

    def test_low_fee_rejected_when_full(self):
        """Tx with fee <= worst in pool is rejected when full."""
        pool = Mempool(max_size=2, fee_policy=_STATIC_FEE)
        tx1 = self._make_tx(fee=_TEST_MSG_FEE + 100, nonce=0)
        tx2 = self._make_tx(fee=_TEST_MSG_FEE + 200, nonce=1)
        pool.add_transaction(tx1)
        pool.add_transaction(tx2)

        # Fee too low to displace anything
        tx3 = self._make_tx(fee=_TEST_MSG_FEE, nonce=2)
        accepted = pool.add_transaction(tx3)
        self.assertFalse(accepted)
        self.assertEqual(pool.size, 2)

    def test_duplicate_rejected(self):
        pool = Mempool(fee_policy=_STATIC_FEE)
        tx = self._make_tx(fee=_TEST_MSG_FEE, nonce=0)
        self.assertTrue(pool.add_transaction(tx))
        self.assertFalse(pool.add_transaction(tx))

    def test_expire_old_transactions(self):
        """Transactions older than TTL are pruned."""
        pool = Mempool(tx_ttl=60, fee_policy=_STATIC_FEE)
        old_time = time.time() - 120  # 2 minutes ago
        tx_old = self._make_tx(fee=_TEST_MSG_FEE, nonce=0, ts=old_time)
        tx_new = self._make_tx(fee=_TEST_MSG_FEE + 10, nonce=1)

        # Force-add old tx (bypass arrival check for testing)
        pool.pending[tx_old.tx_hash] = tx_old
        pool.add_transaction(tx_new)

        expired = pool.expire_transactions()
        self.assertEqual(expired, 1)
        self.assertNotIn(tx_old.tx_hash, pool.pending)
        self.assertIn(tx_new.tx_hash, pool.pending)

    def test_expired_tx_rejected_on_arrival(self):
        """Expired transaction is rejected even when pool has room."""
        pool = Mempool(tx_ttl=60, fee_policy=_STATIC_FEE)
        old_time = time.time() - 120
        tx = self._make_tx(fee=_TEST_MSG_FEE, nonce=0, ts=old_time)
        accepted = pool.add_transaction(tx)
        self.assertFalse(accepted)

    def test_fee_estimate_still_works(self):
        pool = Mempool(max_size=10, fee_policy=_STATIC_FEE)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=_TEST_MSG_FEE + (i + 1) * 10, nonce=i))
        estimate = pool.get_fee_estimate()
        self.assertGreater(estimate, 0)

    def test_get_transactions_ordered_by_fee(self):
        pool = Mempool(max_size=10, fee_policy=_STATIC_FEE)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=_TEST_MSG_FEE + (i + 1) * 30, nonce=i))
        txs = pool.get_transactions(5)
        fees = [t.fee for t in txs]
        self.assertEqual(fees, sorted(fees, reverse=True))


if __name__ == "__main__":
    unittest.main()
