"""Mempool fee-per-byte ranking must use STORED bytes, not message bytes.

CLAUDE.md anchor: "Selection priority is fee-per-byte, never absolute
fee.  The block byte budget is the binding constraint, so proposers
rank pending txs by `fee / stored_bytes` for inclusion, eviction-on-
full, and RBF.  Selecting on absolute fee silently prefers larger txs
just because they carry a bigger sticker fee, even when smaller txs
offer the network more revenue per stored byte."

Pre-fix the mempool's ``_fee_per_byte`` returned
``tx.fee / max(1, len(getattr(tx, "message", b"")))``.  For non-
message txs (Transfer, Stake, Unstake, Governance, Authority, Slash,
React) the ``getattr`` fallback returns ``b""`` and the denominator
collapses to 1 — ranking degenerates to absolute fee.  Even for
MessageTransaction the `len(message)` denominator omits the WOTS+
witness bytes (which dominate the stored cost), so a bare message
with a tiny payload but a multi-KB witness ranks orders of magnitude
above a reasonably-sized message that pays the same fee.

This test pins the corrected denominator: ``len(tx.to_bytes())`` —
the actual on-disk stored byte count.
"""

from __future__ import annotations

import unittest

from messagechain.config import MIN_FEE
from messagechain.core.mempool import _fee_per_byte
from messagechain.core.transaction import create_transaction
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity


class TestFeePerStoredByte(unittest.TestCase):
    """``_fee_per_byte`` must divide by stored bytes, not message bytes."""

    def test_message_tx_uses_stored_bytes_not_payload_only(self):
        """A MessageTransaction's ranking denominator must equal
        ``len(tx.to_bytes())``, including witness — NOT just
        ``len(tx.message)``.  WOTS+ witness dominates stored cost."""
        alice = Entity.create(b"mp-fpsb-alice".ljust(32, b"\x00"))
        tx = create_transaction(alice, "hi", fee=1000, nonce=0)
        stored_len = len(tx.to_bytes())
        msg_len = len(tx.message)
        # Sanity: the stored encoding is much larger than the payload
        # (witness dominates).  Without this, the test isn't
        # meaningful.
        self.assertGreater(
            stored_len, msg_len * 10,
            "Test pre-condition: stored bytes must dwarf payload "
            "bytes for the ranking to matter.",
        )
        density = _fee_per_byte(tx)
        # Pre-fix: density == fee / msg_len  (over-states by ~50x).
        # Post-fix: density == fee / stored_len.
        self.assertAlmostEqual(
            density, tx.fee / stored_len, places=6,
            msg=f"density={density} expected~{tx.fee/stored_len} "
                f"(stored_len={stored_len}, msg_len={msg_len})",
        )

    def test_transfer_tx_uses_stored_bytes_not_one(self):
        """A TransferTransaction has no ``message`` attribute, so
        pre-fix ``_fee_per_byte`` returns ``fee / 1`` (= absolute
        fee).  Post-fix it must return ``fee / len(tx.to_bytes())``."""
        alice = Entity.create(b"mp-fpsb-xfer-a".ljust(32, b"\x00"))
        bob = Entity.create(b"mp-fpsb-xfer-b".ljust(32, b"\x00"))
        ttx = create_transfer_transaction(
            alice, bob.entity_id, amount=1, fee=1000, nonce=0,
        )
        stored_len = len(ttx.to_bytes())
        self.assertGreater(stored_len, 1)
        density = _fee_per_byte(ttx)
        # Pre-fix this would equal `1000 / 1 = 1000.0`.
        # Post-fix it must equal `1000 / stored_len`.
        self.assertAlmostEqual(
            density, ttx.fee / stored_len, places=6,
            msg=f"density={density} expected~{ttx.fee/stored_len} "
                f"(stored_len={stored_len})",
        )
        # Specifically: density must be FAR below absolute fee for a
        # ~200-byte transfer.
        self.assertLess(
            density, ttx.fee,
            "Transfer density must be < absolute fee — it has stored "
            "bytes > 1.",
        )

    def test_higher_fee_same_kind_ranks_higher(self):
        """Sanity: between two same-kind, same-size txs, the higher-
        fee one ranks higher.  Acts as a guard that the new
        denominator still produces sensible ordering within a kind."""
        alice = Entity.create(b"mp-fpsb-cmp-a".ljust(32, b"\x00"))
        bob = Entity.create(b"mp-fpsb-cmp-b".ljust(32, b"\x00"))
        cheap = create_transfer_transaction(
            alice, bob.entity_id, amount=1, fee=100, nonce=0,
        )
        rich = create_transfer_transaction(
            alice, bob.entity_id, amount=1, fee=10_000, nonce=1,
        )
        self.assertGreater(_fee_per_byte(rich), _fee_per_byte(cheap))


if __name__ == "__main__":
    unittest.main()
