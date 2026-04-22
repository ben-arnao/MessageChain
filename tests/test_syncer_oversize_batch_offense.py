"""
Batch A-4: syncer must record a peer offense when it truncates an
oversized RESPONSE_HEADERS or RESPONSE_BLOCKS_BATCH.

Prior behavior: when a peer sent more than 2× HEADERS_BATCH_SIZE or
2× BLOCKS_BATCH_SIZE entries, sync.py truncated the batch and only
logged a warning. No ban-score penalty was recorded, so a flooding
peer could burn CPU on parse + truncation indefinitely without ever
getting disconnected.

Fixed behavior: when the batch exceeds the 2× threshold, the
ChainSyncer invokes its on_peer_offense callback with
OFFENSE_PROTOCOL_VIOLATION (reason contains "header_batch_oversize"
or "block_batch_oversize"). Repeat offenders accumulate ban-score
and eventually get disconnected.
"""

import asyncio
import unittest
from unittest.mock import MagicMock

from messagechain.network.ban import OFFENSE_PROTOCOL_VIOLATION
from messagechain.network.sync import (
    ChainSyncer,
    SyncState,
    HEADERS_BATCH_SIZE,
    BLOCKS_BATCH_SIZE,
)


def _make_syncer(state: SyncState):
    """Build a ChainSyncer with a blockchain mock and offense capture list."""
    bc = MagicMock()
    bc.height = 0
    bc.get_latest_block.return_value = None
    bc.has_block.return_value = False
    offenses: list[tuple[str, int, str]] = []
    syncer = ChainSyncer(
        blockchain=bc,
        get_peer_writer=lambda _a: None,
        on_peer_offense=lambda addr, pts, reason: offenses.append(
            (addr, pts, reason)
        ),
    )
    syncer.state = state
    return syncer, offenses


class TestHeadersOversizeOffense(unittest.TestCase):
    """handle_headers_response must record OFFENSE_PROTOCOL_VIOLATION when
    the batch is larger than 2 * HEADERS_BATCH_SIZE."""

    def test_A_oversized_headers_batch_records_offense(self):
        syncer, offenses = _make_syncer(SyncState.SYNCING_HEADERS)
        peer = "1.2.3.4:9333"

        # 3× the normal batch — well over the 2× threshold.
        headers = [
            {
                "block_number": i,
                "prev_hash": "00" * 32,
                "block_hash": f"{i:064x}",
            }
            for i in range(HEADERS_BATCH_SIZE * 3)
        ]

        asyncio.run(syncer.handle_headers_response(headers, peer))

        # At least one offense recorded for the oversize violation,
        # attributed to this peer with OFFENSE_PROTOCOL_VIOLATION.
        oversize_offenses = [
            o for o in offenses if "header_batch_oversize" in o[2]
        ]
        self.assertEqual(
            len(oversize_offenses), 1,
            f"expected exactly one header_batch_oversize offense, got {offenses}",
        )
        addr, pts, reason = oversize_offenses[0]
        self.assertEqual(addr, peer)
        self.assertEqual(pts, OFFENSE_PROTOCOL_VIOLATION)
        self.assertIn("header_batch_oversize", reason)

    def test_B_at_cap_headers_batch_no_offense(self):
        """Exactly 2 * HEADERS_BATCH_SIZE is still within bounds — no offense."""
        syncer, offenses = _make_syncer(SyncState.SYNCING_HEADERS)
        peer = "1.2.3.4:9333"

        headers = [
            {
                "block_number": i,
                "prev_hash": "00" * 32,
                "block_hash": f"{i:064x}",
            }
            for i in range(HEADERS_BATCH_SIZE * 2)
        ]

        asyncio.run(syncer.handle_headers_response(headers, peer))

        oversize_offenses = [
            o for o in offenses if "header_batch_oversize" in o[2]
        ]
        self.assertEqual(
            oversize_offenses, [],
            "at-cap batch (2× HEADERS_BATCH_SIZE) must not trigger an offense",
        )

    def test_D_regression_small_headers_batch_no_offense(self):
        """Regression: a normal-sized valid batch must not trigger offenses."""
        syncer, offenses = _make_syncer(SyncState.SYNCING_HEADERS)
        peer = "1.2.3.4:9333"

        headers = [
            {
                "block_number": i,
                "prev_hash": "00" * 32,
                "block_hash": f"{i:064x}",
            }
            for i in range(HEADERS_BATCH_SIZE // 2)
        ]

        asyncio.run(syncer.handle_headers_response(headers, peer))
        oversize_offenses = [
            o for o in offenses if "header_batch_oversize" in o[2]
        ]
        self.assertEqual(oversize_offenses, [])


class TestBlocksOversizeOffense(unittest.TestCase):
    """handle_blocks_response must record OFFENSE_PROTOCOL_VIOLATION when
    the batch is larger than 2 * BLOCKS_BATCH_SIZE."""

    def test_C_oversized_blocks_batch_records_offense(self):
        syncer, offenses = _make_syncer(SyncState.SYNCING_BLOCKS)
        peer = "5.6.7.8:9333"

        # Deserialization of these entries will fail (they are not valid hex
        # block bytes), but that's fine — the oversize check runs BEFORE any
        # per-block deserialization.
        oversize_count = BLOCKS_BATCH_SIZE * 3
        blocks = ["" for _ in range(oversize_count)]

        asyncio.run(syncer.handle_blocks_response(blocks, peer))

        oversize_offenses = [
            o for o in offenses if "block_batch_oversize" in o[2]
        ]
        self.assertEqual(
            len(oversize_offenses), 1,
            f"expected exactly one block_batch_oversize offense, got {offenses}",
        )
        addr, pts, reason = oversize_offenses[0]
        self.assertEqual(addr, peer)
        self.assertEqual(pts, OFFENSE_PROTOCOL_VIOLATION)
        self.assertIn("block_batch_oversize", reason)

    def test_C_at_cap_blocks_batch_no_offense(self):
        """Exactly 2 * BLOCKS_BATCH_SIZE is still within bounds — no offense."""
        syncer, offenses = _make_syncer(SyncState.SYNCING_BLOCKS)
        peer = "5.6.7.8:9333"

        blocks = ["" for _ in range(BLOCKS_BATCH_SIZE * 2)]
        asyncio.run(syncer.handle_blocks_response(blocks, peer))

        oversize_offenses = [
            o for o in offenses if "block_batch_oversize" in o[2]
        ]
        self.assertEqual(
            oversize_offenses, [],
            "at-cap batch (2× BLOCKS_BATCH_SIZE) must not trigger an offense",
        )


if __name__ == "__main__":
    unittest.main()
