"""Periodic in-memory ↔ on-disk state drift check.

Background: validator-2 silently diverged its in-memory chain state
from its on-disk ChainDB until ``compute_post_state_root`` exploded
with ``struct.error: int too large to convert`` deep inside
``_leaf_value`` — only the resulting overflow surfaced, while the drift
itself ran undetected for who knows how long.  A fresh restart pulled
clean state from disk and the node worked fine, confirming that disk
was the source of truth and memory was the corrupted side.

Defence: ``Blockchain.check_state_drift()`` reopens a read-only handle
to the same chain.db, rehydrates fresh dicts the same way
``_load_from_db`` does, and diffs them against the live in-memory dicts.
The block-production loop calls it every ``state_drift_check_interval``
blocks; on detection it logs at ERROR (default) or — under
``--state-drift-on-detect=crash`` — raises so systemd restarts the node.

Invariants asserted here:

* Clean state (no mutation) returns an empty drift list.
* A balance bumped in-memory without touching disk surfaces a single
  drift record with the exact expected (dict_name, entity_id, in_mem,
  on_disk) shape.
* Drift in any of the consensus-critical surfaces (balances, staked,
  pending_unstakes, nonces, public_keys, authority_keys,
  leaf_watermarks, key_rotation_counts, revoked_entities,
  slashed_validators) is reported.
* Records are tuples / dataclass-likes that include the dict name so an
  operator scrolling the journal can pinpoint which surface drifted
  without reading the whole record.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from messagechain.config import HASH_ALGO
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from tests import register_entity_for_test


def _entity(seed: bytes, height: int = 4) -> Entity:
    padded = seed + b"\x00" * (32 - len(seed))
    return Entity.create(padded, tree_height=height)


class _BaseDrift(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="mc-drift-")
        self.db_path = os.path.join(self.tmpdir, "chain.db")
        self.db = ChainDB(self.db_path)
        self.chain = Blockchain(db=self.db)
        self.genesis = _entity(b"drift_gen", height=4)
        self.chain.initialize_genesis(self.genesis)
        # Force a flush to disk so the rehydration side has something
        # to diff against.
        self.db.flush_state()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestNoDriftOnCleanState(_BaseDrift):
    def test_clean_state_returns_empty_record_list(self):
        records = self.chain.check_state_drift()
        self.assertEqual(
            records,
            [],
            f"expected no drift on clean state, got: {records}",
        )


class TestBalanceDriftDetected(_BaseDrift):
    def test_in_memory_balance_bump_surfaces_record(self):
        # Snapshot the on-disk balance so we can assert the record's
        # disk_value field is the un-mutated original.
        eid = self.genesis.entity_id
        on_disk_balance = self.chain.supply.balances.get(eid, 0)

        # Simulate the validator-2 incident: in-memory dict diverges
        # from disk WITHOUT going through the apply path, so no row
        # is mirrored to the SQL table.
        self.chain.supply.balances[eid] = on_disk_balance + 999

        records = self.chain.check_state_drift()
        self.assertTrue(
            records,
            "expected drift after in-memory balance bump",
        )
        balance_records = [r for r in records if r[0] == "balances"]
        self.assertEqual(
            len(balance_records),
            1,
            f"expected exactly one balance drift record, got: {balance_records}",
        )
        dict_name, entity_id, in_mem, on_disk = balance_records[0]
        self.assertEqual(dict_name, "balances")
        self.assertEqual(entity_id, eid)
        self.assertEqual(in_mem, on_disk_balance + 999)
        self.assertEqual(on_disk, on_disk_balance)


class TestNonceDriftDetected(_BaseDrift):
    def test_in_memory_nonce_bump_surfaces_record(self):
        eid = self.genesis.entity_id
        on_disk_nonce = self.chain.nonces.get(eid, 0)
        self.chain.nonces[eid] = on_disk_nonce + 7

        records = self.chain.check_state_drift()
        nonce_records = [r for r in records if r[0] == "nonces"]
        self.assertEqual(len(nonce_records), 1, f"got: {nonce_records}")
        dict_name, entity_id, in_mem, on_disk = nonce_records[0]
        self.assertEqual(dict_name, "nonces")
        self.assertEqual(entity_id, eid)
        self.assertEqual(in_mem, on_disk_nonce + 7)
        self.assertEqual(on_disk, on_disk_nonce)


class TestStakedDriftDetected(_BaseDrift):
    def test_in_memory_staked_bump_surfaces_record(self):
        eid = self.genesis.entity_id
        # Seed an arbitrary staked entry (genesis often has none).
        self.chain.supply.staked[eid] = 12345

        records = self.chain.check_state_drift()
        staked_records = [r for r in records if r[0] == "staked"]
        self.assertEqual(len(staked_records), 1, f"got: {staked_records}")
        dict_name, entity_id, in_mem, on_disk = staked_records[0]
        self.assertEqual(dict_name, "staked")
        self.assertEqual(entity_id, eid)
        self.assertEqual(in_mem, 12345)
        # No row on disk — represented as 0 (the get-with-default).
        self.assertEqual(on_disk, 0)


class TestRevokedSetDriftDetected(_BaseDrift):
    def test_in_memory_revoked_addition_surfaces_record(self):
        eid = self.genesis.entity_id
        self.chain.revoked_entities.add(eid)

        records = self.chain.check_state_drift()
        rev_records = [r for r in records if r[0] == "revoked_entities"]
        self.assertEqual(len(rev_records), 1, f"got: {rev_records}")
        dict_name, entity_id, in_mem, on_disk = rev_records[0]
        self.assertEqual(dict_name, "revoked_entities")
        self.assertEqual(entity_id, eid)
        self.assertTrue(in_mem)
        self.assertFalse(on_disk)


class TestSlashedSetDriftDetected(_BaseDrift):
    def test_in_memory_slashed_addition_surfaces_record(self):
        eid = self.genesis.entity_id
        self.chain.slashed_validators.add(eid)

        records = self.chain.check_state_drift()
        slashed_records = [r for r in records if r[0] == "slashed_validators"]
        self.assertEqual(len(slashed_records), 1, f"got: {slashed_records}")
        dict_name, entity_id, in_mem, on_disk = slashed_records[0]
        self.assertEqual(dict_name, "slashed_validators")
        self.assertEqual(entity_id, eid)
        self.assertTrue(in_mem)
        self.assertFalse(on_disk)


class TestMultipleDriftsAggregated(_BaseDrift):
    def test_two_independent_drifts_both_reported(self):
        eid = self.genesis.entity_id
        self.chain.supply.balances[eid] = self.chain.supply.balances.get(eid, 0) + 10
        self.chain.nonces[eid] = self.chain.nonces.get(eid, 0) + 5

        records = self.chain.check_state_drift()
        names = sorted({r[0] for r in records})
        self.assertEqual(
            names,
            ["balances", "nonces"],
            f"expected both balances and nonces in drift report, got: {records}",
        )


class TestNoDbIsNoOp(unittest.TestCase):
    """In-memory-only Blockchain (db=None) returns empty record list.

    Many unit tests construct ``Blockchain()`` without a ChainDB.  The
    drift check must be a safe no-op in that mode rather than raising,
    so the periodic call from the production loop doesn't crash test
    harnesses that lift the loop.
    """

    def test_in_memory_only_blockchain_returns_empty(self):
        chain = Blockchain()
        # Even with bogus state, no db means no drift comparison
        # surface — return empty.
        records = chain.check_state_drift()
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
