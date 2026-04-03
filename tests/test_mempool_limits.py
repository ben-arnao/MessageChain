"""Tests for mempool size limits and transaction expiry."""

import time
import unittest
from unittest.mock import patch
from messagechain.identity.biometrics import Entity
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction


class TestMempoolLimits(unittest.TestCase):
    def setUp(self):
        self.alice = Entity.create(b"alice-private-key")

    def _make_tx(self, fee: int, nonce: int, ts: float | None = None):
        tx = create_transaction(
            self.alice, f"msg {nonce}", fee=fee, nonce=nonce
        )
        if ts is not None:
            tx.timestamp = ts
        return tx

    def test_mempool_respects_max_size(self):
        """Mempool should not exceed max_size."""
        pool = Mempool(max_size=3)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=i + 1, nonce=i))
        self.assertEqual(pool.size, 3)

    def test_low_fee_evicted_when_full(self):
        """Lowest-fee tx is evicted to make room for higher-fee tx."""
        pool = Mempool(max_size=2)
        tx1 = self._make_tx(fee=5, nonce=0)
        tx2 = self._make_tx(fee=10, nonce=1)
        pool.add_transaction(tx1)
        pool.add_transaction(tx2)
        self.assertEqual(pool.size, 2)

        # Add higher fee tx — should evict tx1 (fee=5)
        tx3 = self._make_tx(fee=20, nonce=2)
        accepted = pool.add_transaction(tx3)
        self.assertTrue(accepted)
        self.assertEqual(pool.size, 2)
        self.assertNotIn(tx1.tx_hash, pool.pending)
        self.assertIn(tx3.tx_hash, pool.pending)

    def test_low_fee_rejected_when_full(self):
        """Tx with fee <= worst in pool is rejected when full."""
        pool = Mempool(max_size=2)
        tx1 = self._make_tx(fee=10, nonce=0)
        tx2 = self._make_tx(fee=20, nonce=1)
        pool.add_transaction(tx1)
        pool.add_transaction(tx2)

        # Fee too low to displace anything
        tx3 = self._make_tx(fee=5, nonce=2)
        accepted = pool.add_transaction(tx3)
        self.assertFalse(accepted)
        self.assertEqual(pool.size, 2)

    def test_duplicate_rejected(self):
        pool = Mempool()
        tx = self._make_tx(fee=5, nonce=0)
        self.assertTrue(pool.add_transaction(tx))
        self.assertFalse(pool.add_transaction(tx))

    def test_expire_old_transactions(self):
        """Transactions older than TTL are pruned."""
        pool = Mempool(tx_ttl=60)
        old_time = time.time() - 120  # 2 minutes ago
        tx_old = self._make_tx(fee=5, nonce=0, ts=old_time)
        tx_new = self._make_tx(fee=10, nonce=1)

        # Force-add old tx (bypass arrival check for testing)
        pool.pending[tx_old.tx_hash] = tx_old
        pool.add_transaction(tx_new)

        expired = pool.expire_transactions()
        self.assertEqual(expired, 1)
        self.assertNotIn(tx_old.tx_hash, pool.pending)
        self.assertIn(tx_new.tx_hash, pool.pending)

    def test_expired_tx_rejected_on_arrival(self):
        """Expired transaction is rejected even when pool has room."""
        pool = Mempool(tx_ttl=60)
        old_time = time.time() - 120
        tx = self._make_tx(fee=5, nonce=0, ts=old_time)
        accepted = pool.add_transaction(tx)
        self.assertFalse(accepted)

    def test_fee_estimate_still_works(self):
        pool = Mempool(max_size=10)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=(i + 1) * 10, nonce=i))
        estimate = pool.get_fee_estimate()
        self.assertGreater(estimate, 0)

    def test_get_transactions_ordered_by_fee(self):
        pool = Mempool(max_size=10)
        for i in range(5):
            pool.add_transaction(self._make_tx(fee=(i + 1) * 3, nonce=i))
        txs = pool.get_transactions(5)
        fees = [t.fee for t in txs]
        self.assertEqual(fees, sorted(fees, reverse=True))


if __name__ == "__main__":
    unittest.main()
