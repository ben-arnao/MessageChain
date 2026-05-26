"""Equivocation detection logs must not promise an outcome the
watcher doesn't actually deliver.

Background -- 2026-05-23 → 2026-05-26 v2 self-equivocation alarm.
v1 was down for 3 days after a failed upgrade.  v2 (the only running
validator) re-proposed block #2846 each cycle with slightly different
content (timestamp drift / mempool delta) because no 2/3 finality was
achievable with only 50% of stake online.  The watcher's
``_observe`` correctly identified each retry as same-(validator,
height, round)-different-payload and the audit r41 #3 self-slash
guard in ``_emit_slash`` correctly suppressed slash emission.  But
the detection WARNING fired BEFORE the guard and ended with the
suffix ``-- filing slash evidence``, which was a lie -- nothing was
ever filed.  An operator scanning the journal saw 200+ lines that
*looked* like v2 was broadcasting slash txs against itself; the
followup "Self-equivocation ... skipping slash emission" line was
easy to miss.

The fix: the detection WARNING describes detection only and points
at a follow-up log line for the actual decision; the success path
in ``_emit_slash`` emits a paired "Slash evidence emitted to
mempool" WARNING so every detection has exactly one decision line
next to it.  The CLAUDE.md "honest operators are insured against
accidents" anchor is reinforced by the log clarity -- an operator
reading the journal in isolation can never conclude their node is
self-slashing when it isn't.

These tests pin the log-text contract.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
import unittest

from messagechain.config import (
    TREASURY_ENTITY_ID,
    VALIDATOR_MIN_STAKE,
)
from messagechain.consensus.equivocation_watcher import EquivocationWatcher
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.core.mempool import Mempool
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _make_signed_header(proposer_entity, prev_block, merkle_seed, t_offset=0.0):
    block_num = prev_block.header.block_number + 1
    header = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(merkle_seed),
        timestamp=time.time() + t_offset,
        proposer_id=proposer_entity.entity_id,
    )
    header.proposer_signature = proposer_entity.keypair.sign(
        _hash(header.signable_data())
    )
    return header


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc-watcher-log-")
        self.db_path = os.path.join(self.tmp, "chain.db")
        self.db = ChainDB(self.db_path)
        self.operator = Entity.create(
            b"operator-watcher-log".ljust(32, b"\x00"),
        )
        self.chain = Blockchain(db=self.db)
        self.chain.initialize_genesis(
            self.operator,
            allocation_table={
                TREASURY_ENTITY_ID: 1_000_000,
                self.operator.entity_id: 10_000_000,
            },
        )
        self.chain.supply.stake(
            self.operator.entity_id, VALIDATOR_MIN_STAKE,
        )
        self.mempool = Mempool()
        self.watcher = EquivocationWatcher(
            chaindb=self.db,
            blockchain=self.chain,
            mempool=self.mempool,
            submitter_entity=self.operator,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestDetectionLogDoesNotPromiseFiling(_Fixture):
    """The detection WARNING must not claim "filing slash evidence" --
    the watcher does not file in three of its four outcome paths
    (self-equivocation, already-processed, detect-only, decode-error),
    so the bare detection-event line must describe detection only.
    """

    def test_self_equivocation_log_pair_is_explicit(self):
        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(self.operator, prev, b"A")
        header_b = _make_signed_header(
            self.operator, prev, b"B", t_offset=1.0,
        )
        self.watcher.observe_block_header(header_a)

        with self.assertLogs(
            "messagechain.consensus.equivocation_watcher",
            level="WARNING",
        ) as cm:
            self.watcher.observe_block_header(header_b)

        joined = "\n".join(cm.output)
        # Detection line is present.
        self.assertIn("Equivocation detected", joined)
        # The misleading "filing slash evidence" promise is GONE.
        self.assertNotIn(
            "filing slash evidence", joined,
            "The detection WARNING must not end with '-- filing slash "
            "evidence' because self-equivocation, already-processed, "
            "detect-only, and decode-error outcomes all skip emission. "
            "Lying about the outcome causes operator alarm during "
            "long liveness stalls (2026-05-23 → 2026-05-26 v2 incident).",
        )
        # Detection points at a follow-up so a single-line read isn't
        # misleading.
        self.assertIn("follow-up", joined)
        # The follow-up decision line for self-equivocation is paired
        # with the detection line.
        self.assertIn("Self-equivocation", joined)
        self.assertIn("skipping slash emission", joined)
        # And the slash pool stays empty (the substantive r41 #3
        # invariant is unaffected by the log refactor).
        self.assertEqual(len(self.mempool.slash_pool), 0)

    def test_real_equivocation_log_pair_is_explicit(self):
        """When the watcher does emit a slash tx (different
        validator equivocating), the detection line is paired with
        an explicit emission line.  No silent emissions -- operators
        reading the journal in isolation can always tell the slash
        was broadcast."""
        offender = Entity.create(
            b"offender-watcher-log".ljust(32, b"\x00"),
        )
        register_entity_for_test(self.chain, offender)
        self.chain.supply.balances[offender.entity_id] = 10_000
        self.chain.supply.stake(
            offender.entity_id, VALIDATOR_MIN_STAKE,
        )

        prev = self.chain.get_latest_block()
        header_a = _make_signed_header(offender, prev, b"A")
        header_b = _make_signed_header(
            offender, prev, b"B", t_offset=1.0,
        )
        self.watcher.observe_block_header(header_a)

        with self.assertLogs(
            "messagechain.consensus.equivocation_watcher",
            level="WARNING",
        ) as cm:
            self.watcher.observe_block_header(header_b)

        joined = "\n".join(cm.output)
        self.assertIn("Equivocation detected", joined)
        self.assertNotIn("filing slash evidence", joined)
        # Explicit emission decision line.
        self.assertIn("Slash evidence emitted to mempool", joined)
        # And the slash tx actually landed.
        self.assertEqual(len(self.mempool.slash_pool), 1)


if __name__ == "__main__":
    unittest.main()
