"""ChainDB nested-transaction atomicity.

Blockchain._persist_state opens a begin_transaction scope and inside it
calls helpers like mark_evidence_processed / add_finalized_block.  Those
helpers historically did an unconditional self._conn.commit(), which
prematurely committed the OUTER transaction mid-flight — subsequent
writes in _persist_state then ran as autocommits and a crash between
them left chain.db partially updated, contrary to the docstring
promise that "a crash mid-persist cannot leave the database in a
partially-updated state".

Guard: every ChainDB helper that touches persistent state must go
through _maybe_commit(), not _conn.commit(), so nested scopes compose.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from messagechain.storage.chaindb import ChainDB


class TestChainDBNestedTxnAtomicity(unittest.TestCase):

    def _fresh_db(self, d: str) -> ChainDB:
        return ChainDB(db_path=os.path.join(d, "chain.db"))

    def test_mark_evidence_processed_respects_outer_txn(self):
        """A rollback of the outer begin_transaction must also discard
        writes done by mark_evidence_processed within that scope."""
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 123)
            db.mark_evidence_processed(b"\xbb" * 32, block_number=5)
            db.set_balance(b"\xcc" * 32, 456)
            db.rollback_transaction()

            # Nothing from the aborted scope should have landed.
            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertEqual(db.get_balance(b"\xcc" * 32), 0)
            self.assertFalse(db.is_evidence_processed(b"\xbb" * 32))
            db.close()

    def test_add_finalized_block_respects_outer_txn(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 111)
            db.add_finalized_block(42, b"\x11" * 32)
            db.rollback_transaction()

            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertIsNone(db.get_finalized_block_at_height(42))
            db.close()

    def test_add_seen_signature_respects_outer_txn(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 222)
            db.add_seen_signature(
                validator_id=b"\x01" * 32,
                block_height=7,
                round_number=0,
                message_type="header",
                signed_payload=b"payload",
                signature_bytes=b"sig",
                first_seen_block_height=7,
            )
            db.rollback_transaction()

            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertIsNone(
                db.get_seen_signature(b"\x01" * 32, 7, 0, "header")
            )
            db.close()

    def test_prune_seen_signatures_respects_outer_txn(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            # Seed a row (auto-committed outside any begin scope).
            db.add_seen_signature(
                validator_id=b"\x02" * 32,
                block_height=3,
                round_number=0,
                message_type="header",
                signed_payload=b"p",
                signature_bytes=b"s",
                first_seen_block_height=3,
            )
            self.assertIsNotNone(
                db.get_seen_signature(b"\x02" * 32, 3, 0, "header")
            )

            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 333)
            db.prune_seen_signatures_before(1_000_000)  # would delete everything
            db.rollback_transaction()

            # Rollback must undo both the balance AND the prune.
            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertIsNotNone(
                db.get_seen_signature(b"\x02" * 32, 3, 0, "header"),
                "prune must roll back with the surrounding transaction",
            )
            db.close()

    def test_add_verified_state_checkpoint_respects_outer_txn(self):
        from messagechain.consensus.state_checkpoint import StateCheckpoint

        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            cp = StateCheckpoint(
                block_number=9,
                block_hash=b"\x33" * 32,
                state_root=b"\x44" * 32,
            )
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 444)
            db.add_verified_state_checkpoint(cp, signatures=[])
            db.rollback_transaction()

            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertIsNone(db.get_verified_state_checkpoint(9))
            db.close()

    def test_store_witness_data_respects_outer_txn(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 555)
            db.store_witness_data(b"\x55" * 32, b"witness-bytes")
            db.rollback_transaction()

            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertFalse(db.has_witness_data(b"\x55" * 32))
            db.close()

    def test_set_slashed_respects_outer_txn(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._fresh_db(d)
            db.begin_transaction()
            db.set_balance(b"\xaa" * 32, 666)
            db.set_slashed(b"\x66" * 32, block_number=12)
            db.rollback_transaction()

            self.assertEqual(db.get_balance(b"\xaa" * 32), 0)
            self.assertFalse(db.is_slashed(b"\x66" * 32))
            db.close()

    def test_standalone_helpers_still_autocommit(self):
        """Outside any begin_transaction, the helpers must still persist
        durably — that's what callers without a batching scope rely on.
        """
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.db")
            db = ChainDB(db_path=path)
            db.mark_evidence_processed(b"\x77" * 32, block_number=1)
            db.add_finalized_block(100, b"\x88" * 32)
            db.close()

            # Reopen and verify durability.
            db2 = ChainDB(db_path=path)
            self.assertTrue(db2.is_evidence_processed(b"\x77" * 32))
            self.assertEqual(
                db2.get_finalized_block_at_height(100), b"\x88" * 32,
            )
            db2.close()


if __name__ == "__main__":
    unittest.main()
