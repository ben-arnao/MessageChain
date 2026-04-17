"""Fee estimator + RPC surcharge awareness.

When a user prepares a transfer to a brand-new recipient, the estimator,
the `estimate_fee` RPC, and the CLI must all surface the NEW_ACCOUNT_FEE
surcharge so the caller submits a tx that will actually be accepted.
Without this, users get back MIN_FEE, submit the tx, and the chain
rejects it with "new-account surcharge required; got 100".

Rules covered here:
  * estimate_fee(..., recipient_is_new=True) includes the surcharge.
  * estimate_fee(..., recipient_is_new=False) does NOT include it
    (default behavior preserved for existing callers).
  * RPC `estimate_fee` with a brand-new recipient_id returns a fee
    including the surcharge.
  * RPC `estimate_fee` with an already-registered recipient_id returns
    the regular estimate (no surcharge).
"""

import unittest
from unittest.mock import MagicMock

from messagechain.config import (
    MIN_FEE, NEW_ACCOUNT_FEE, TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
)
from messagechain.economics.fee_estimator import FeeEstimator
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


class TestEstimatorSurchargeFlag(unittest.TestCase):
    """FeeEstimator.estimate_fee accepts a recipient_is_new flag."""

    def test_default_no_surcharge(self):
        est = FeeEstimator()
        # Empty history falls back to MIN_FEE.
        self.assertEqual(est.estimate_fee(), MIN_FEE)

    def test_new_recipient_adds_surcharge(self):
        est = FeeEstimator()
        self.assertEqual(
            est.estimate_fee(recipient_is_new=True),
            MIN_FEE + NEW_ACCOUNT_FEE,
        )

    def test_existing_recipient_no_surcharge(self):
        est = FeeEstimator()
        self.assertEqual(
            est.estimate_fee(recipient_is_new=False),
            MIN_FEE,
        )

    def test_surcharge_stacks_above_history_estimate(self):
        """Surcharge adds to whatever the history-derived base would be."""
        est = FeeEstimator()
        # Record blocks with high fees so the history-derived estimate
        # exceeds MIN_FEE.
        for _ in range(10):
            est.record_block_fees([500] * 10)
        base = est.estimate_fee()  # no surcharge
        with_surcharge = est.estimate_fee(recipient_is_new=True)
        self.assertEqual(with_surcharge, base + NEW_ACCOUNT_FEE)


class TestRpcEstimateFeeSurcharge(unittest.TestCase):
    """`_rpc_estimate_fee` surfaces the surcharge for brand-new recipients."""

    def _make_server(self):
        alice = Entity.create(b"alice-fee-surch" + b"\x00" * 17)
        chain = Blockchain()
        allocation = {
            alice.entity_id: 1_000_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(alice, allocation_table=allocation)

        # Register a second "existing" entity that won't incur surcharge.
        bob = Entity.create(b"bob-fee-surch" + b"\x00" * 19)
        register_entity_for_test(chain, bob)
        chain.supply.balances[bob.entity_id] = 5_000

        srv = MagicMock()
        srv.blockchain = chain
        srv.mempool = Mempool()
        srv.mempool.get_fee_estimate = lambda: 1
        return srv, alice, bob

    def test_rpc_transfer_to_existing_recipient_no_surcharge(self):
        import server as server_module
        srv, alice, bob = self._make_server()

        result = server_module.Server._rpc_estimate_fee(
            srv,
            {"kind": "transfer", "recipient_id": bob.entity_id.hex()},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertEqual(r["min_fee"], MIN_FEE)
        self.assertFalse(r.get("recipient_is_new", False))

    def test_rpc_transfer_to_brand_new_recipient_includes_surcharge(self):
        import server as server_module
        srv, alice, _bob = self._make_server()

        brand_new = b"\x11" * 32
        result = server_module.Server._rpc_estimate_fee(
            srv,
            {"kind": "transfer", "recipient_id": brand_new.hex()},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertEqual(r["min_fee"], MIN_FEE + NEW_ACCOUNT_FEE)
        self.assertGreaterEqual(r["recommended_fee"], MIN_FEE + NEW_ACCOUNT_FEE)
        self.assertTrue(r.get("recipient_is_new"))

    def test_rpc_transfer_without_recipient_id_preserves_old_behavior(self):
        import server as server_module
        srv, _alice, _bob = self._make_server()

        # No recipient_id -> can't tell, so no surcharge (caller beware).
        result = server_module.Server._rpc_estimate_fee(
            srv, {"kind": "transfer"},
        )
        self.assertTrue(result["ok"], result)
        r = result["result"]
        self.assertEqual(r["min_fee"], MIN_FEE)
        self.assertFalse(r.get("recipient_is_new", False))

    def test_rpc_invalid_recipient_id_hex_reports_error(self):
        import server as server_module
        srv, _alice, _bob = self._make_server()

        result = server_module.Server._rpc_estimate_fee(
            srv,
            {"kind": "transfer", "recipient_id": "not-hex-at-all"},
        )
        # Treat invalid hex as if no recipient_id was provided (fall back
        # to non-surcharge estimate) OR return an error — either behavior
        # is acceptable as long as the server doesn't crash.  We only
        # assert that a structured response comes back.
        self.assertIn("ok", result)


if __name__ == "__main__":
    unittest.main()
