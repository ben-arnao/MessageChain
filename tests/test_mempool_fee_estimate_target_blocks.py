"""Audit r25 #3 — `Mempool.get_fee_estimate` accepts `target_blocks` and
applies the percentile ladder, so the auto-fee `urgency` knob actually
binds on the bid.

Pre-fix the picture was:

    server.py:
        try:
            mempool_fee = self.mempool.get_fee_estimate(
                message_bytes=quoting_bytes, target_blocks=target_blocks,
            )
        except TypeError:
            # Older mempool implementations without target_blocks.
            mempool_fee = self.mempool.get_fee_estimate(
                message_bytes=quoting_bytes,
            )

    mempool.py:
        def get_fee_estimate(self, message_bytes: int = 0) -> int:
            ...
            median_density = densities[len(densities) // 2]   # 50th
            estimate = int(median_density * message_bytes)
            return max(MARKET_FEE_FLOOR, estimate)

The signature mismatch fired the ``TypeError`` fallback on every call,
so every CLI auto-fee quote returned the same median-density estimate
regardless of ``low`` / ``normal`` / ``high`` urgency.  The urgency
value was echoed in the result for display (so it *looked* like it
bound) but never reached the bid.  CLAUDE.md anchor:

    "Auto-fee defaults adjust to fit this model.  When the fee model
    shifts, every auto-fee path shifts with it — don't leave a tx
    kind defaulting to a stale flat fee while others auto-bid by
    density."

Today's empty mempool hides the bug (median ≈ floor); the moment real
congestion arrives, every "high"-urgency user silently underbids and
stalls in the queue, and every "low"-urgency user overpays.

Fix: ``Mempool.get_fee_estimate`` now accepts ``target_blocks`` and
applies the percentile ladder shared with ``FeeEstimator``.  The
server-side ``try/except TypeError`` fallback is no longer needed.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from messagechain.config import MARKET_FEE_FLOOR
from messagechain.core.mempool import Mempool
from messagechain.core.transaction import create_transaction
from messagechain.economics.dynamic_fee import DynamicFeePolicy
from messagechain.identity.identity import Entity


def _stuff_mempool(pool, entities, *, density_per_byte_pairs):
    """Inject pending txs whose stored bytes and fees yield the requested
    fee-per-byte densities.  Real signed message txs walk the same
    `_stored_bytes` / `_fee_per_byte` code paths the production
    estimator uses.  Entities rotate so a 16-leaf WOTS+ test tree
    doesn't exhaust under the density spread (each entity signs at
    most one tx here).
    """
    if len(entities) < len(density_per_byte_pairs):
        raise AssertionError(
            f"need at least {len(density_per_byte_pairs)} entities to "
            f"avoid WOTS+ leaf exhaustion under tree_height=4"
        )
    for idx, density in enumerate(density_per_byte_pairs):
        signer = entities[idx]
        tx = create_transaction(
            signer, f"msg {idx}", fee=10_000 + density * 1000, nonce=0,
        )
        pool._stored_bytes[tx.tx_hash] = max(1, tx.fee // max(1, density))
        pool.pending[tx.tx_hash] = tx
        pool.arrival_heights[tx.tx_hash] = 0
        pool._sender_counts[tx.entity_id] += 1


class TestGetFeeEstimateAcceptsTargetBlocks(unittest.TestCase):
    """The new signature accepts target_blocks without raising TypeError."""

    def setUp(self):
        # 12 distinct entities (one signature each) so the test fits
        # inside the conftest 16-leaf WOTS+ tree without exhausting any
        # one signer.  Density spread of 12 points spans 5/12 → 11/12
        # rungs of the percentile ladder, enough to separate the
        # 90th / 75th / 25th rungs cleanly.
        self.entities = [
            Entity.create(f"r25-econ-{i:02d}".encode().ljust(32, b"\x00"))
            for i in range(12)
        ]
        self.pool = Mempool(
            max_size=100,
            fee_policy=DynamicFeePolicy(base_fee=MARKET_FEE_FLOOR, max_fee=100),
        )

    def test_target_blocks_kwarg_accepted(self):
        """Pre-fix: get_fee_estimate(message_bytes=..., target_blocks=...)
        raised TypeError because the param wasn't declared."""
        # Empty mempool → floor regardless of urgency.  The point of
        # this test is the call itself doesn't raise.
        for tb in (1, 3, 10):
            try:
                fee = self.pool.get_fee_estimate(
                    message_bytes=100, target_blocks=tb,
                )
            except TypeError as e:
                self.fail(
                    f"target_blocks={tb} kwarg must be accepted; got "
                    f"TypeError: {e}"
                )
            self.assertEqual(fee, MARKET_FEE_FLOOR)

    def test_high_urgency_bids_above_low_urgency(self):
        """Percentile ladder must bind: target_blocks=1 (high) >
        target_blocks=3 (normal) > target_blocks=10 (low) when the
        mempool has a non-flat density distribution."""
        # 12 distinct densities span the percentile ladder; idx for
        # each rung lands at a distinct value:
        #   90th  → idx min(12*0.90, 11)=10  → density[10]=11
        #   75th  → idx 12*0.75=9            → density[9]=10
        #   25th  → idx 12*0.25=3            → density[3]=4
        densities = list(range(1, 13))  # 12 distinct fee-per-byte points
        _stuff_mempool(
            self.pool, self.entities, density_per_byte_pairs=densities,
        )

        message_bytes = 1000
        high = self.pool.get_fee_estimate(
            message_bytes=message_bytes, target_blocks=1,
        )
        normal = self.pool.get_fee_estimate(
            message_bytes=message_bytes, target_blocks=3,
        )
        low = self.pool.get_fee_estimate(
            message_bytes=message_bytes, target_blocks=10,
        )
        self.assertGreater(
            high, normal,
            f"high urgency must bid above normal: high={high}, normal={normal}",
        )
        self.assertGreater(
            normal, low,
            f"normal urgency must bid above low: normal={normal}, low={low}",
        )

    def test_default_target_blocks_is_normal(self):
        """A caller that omits target_blocks must get the 'normal'
        (target_blocks=3, 75th percentile) bid — matching the
        DEFAULT_URGENCY in auto_fee.py."""
        densities = list(range(1, 13))
        _stuff_mempool(
            self.pool, self.entities, density_per_byte_pairs=densities,
        )

        explicit_normal = self.pool.get_fee_estimate(
            message_bytes=1000, target_blocks=3,
        )
        default = self.pool.get_fee_estimate(message_bytes=1000)
        self.assertEqual(
            default, explicit_normal,
            "default target_blocks must equal the 'normal' rung",
        )


class TestServerSideKwargPassthrough(unittest.TestCase):
    """Source-level pin: server.py no longer needs the
    ``except TypeError`` fallback — the kwarg is now part of the
    signature.  Keeping the dead fallback is a code smell that lets the
    bug recur if a future refactor re-removes the kwarg."""

    def test_server_drops_typeerror_fallback(self):
        import inspect
        import server

        # Pull every line of server.py that mentions get_fee_estimate
        # along with a few lines of context, and assert no
        # ``except TypeError`` block bookends those calls anymore.
        src = inspect.getsource(server)
        # Both call paths must use the typed signature now.  If a future
        # refactor removes target_blocks again, this test forces the
        # author to also re-add the fallback consciously rather than
        # silently breaking the urgency knob.
        self.assertIn(
            "target_blocks=target_blocks", src,
            "server.py auto-fee path must pass target_blocks to "
            "Mempool.get_fee_estimate so the urgency knob binds",
        )
        # The except-TypeError fallback is no longer load-bearing —
        # the kwarg is now part of the signature.  Removing it is the
        # last step that closes the audit r25 #3 silent regression.
        self.assertNotIn(
            "except TypeError",
            src.split("get_fee_estimate", 1)[1].split("get_fee_estimate", 1)[0]
            if "get_fee_estimate" in src else "",
            "server.py must not retain the TypeError fallback around "
            "get_fee_estimate — the kwarg is now declared, the fallback "
            "would mask future regressions",
        )


if __name__ == "__main__":
    unittest.main()
