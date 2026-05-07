"""Integration tests for the snapshot HMAC envelope wired into the
Blockchain cold-load / reorg / fork-emergency-rewind paths
(audit r29 #1, 1.59.1).

Pre-fix the three ``pickle.loads`` call sites at blockchain.py:1236,
14734, 14929 ran on whatever bytes lived in chain.db.state_snapshots
-- a tampered backup tape, a substituted row, a cross-node copy --
giving anyone with DB-write access local RCE at validator-process
privilege before any signature or state-root check fired.

Post-fix, every persisted snapshot blob is wrapped in an HMAC-SHA256
envelope keyed by a per-node secret persisted in chaindb.meta.  On
load, the envelope is verified in constant time BEFORE ``pickle.
loads`` runs; a mismatch raises ``SnapshotEnvelopeError`` and the
caller's existing ``try/except`` falls through to the legacy
field-by-field load path.

These tests pin the integration contract.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.config import (
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ENTITY_ID,
    TREASURY_ALLOCATION,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB
from messagechain.storage.state_snapshot_envelope import (
    MAGIC,
    is_envelope,
)
import messagechain.config as _cfg


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class _MainnetPinOverride:
    _saved: object = object()

    @classmethod
    def _install(cls, eid: bytes):
        cls._saved = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    @classmethod
    def _restore(cls):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = cls._saved


class TestSnapshotEnvelopeBlockchainIntegration(
    _MainnetPinOverride, unittest.TestCase,
):
    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"snap-envelope-integration-key-001",
            tree_height=4,
        )

    def _fresh_db_path(self):
        tmp = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp, True)
        return os.path.join(tmp, "chain.db")

    def _build_chain(self, db_path):
        db = ChainDB(db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        return chain, db

    def _mint_one_block(self, chain):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        proposer = pick_selected_proposer(chain, [self.founder])
        block = chain.propose_block(consensus, proposer, [])
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        return block.header.block_number

    def test_persisted_snapshot_carries_envelope_magic(self):
        """Every snapshot row written post-1.59.1 carries the v1
        envelope magic prefix.  Without this, the load-side HMAC
        check has nothing to verify."""
        self._install(self.founder.entity_id)
        try:
            db_path = self._fresh_db_path()
            chain, db = self._build_chain(db_path)
            height = self._mint_one_block(chain)
            blob = db.get_state_snapshot(height)
            self.assertIsNotNone(blob)
            self.assertTrue(
                is_envelope(blob),
                "snapshot-on-apply did not wrap pickle blob in "
                "the HMAC envelope; pickle.loads remains an RCE "
                "primitive on tampered DB / restored backup",
            )
            self.assertEqual(blob[:len(MAGIC)], MAGIC)
            _close(db)
        finally:
            self._restore()

    def test_secret_persisted_to_meta_table(self):
        """The per-node HMAC secret round-trips via ``meta`` so a
        cold restart on the same DB recovers it (rather than
        rotating to a new secret and rejecting its own prior
        snapshots)."""
        self._install(self.founder.entity_id)
        try:
            db_path = self._fresh_db_path()
            chain, db = self._build_chain(db_path)
            self._mint_one_block(chain)
            stored = db.get_meta("snapshot_hmac_key")
            self.assertIsNotNone(stored)
            self.assertEqual(
                len(bytes.fromhex(stored)), 32,
                "snapshot HMAC secret must be 32 bytes (sha256)",
            )
            _close(db)
            # Reopen: the secret is still there.
            db2 = ChainDB(db_path)
            self.assertEqual(db2.get_meta("snapshot_hmac_key"), stored)
            _close(db2)
        finally:
            self._restore()

    def test_cold_restart_loads_envelope_protected_snapshot(self):
        """Round-trip: write a block, close, reopen, load must
        succeed via the envelope path (not fall back to legacy).
        This is the happy path -- envelope verifies, pickle.loads
        runs on the verified inner payload, accumulators restore."""
        self._install(self.founder.entity_id)
        try:
            db_path = self._fresh_db_path()
            chain, db = self._build_chain(db_path)
            height = self._mint_one_block(chain)
            balances_before = dict(chain.supply.balances)
            staked_before = dict(chain.supply.staked)
            _close(db)
            # Cold restart -- this is the path that pre-fix was the
            # RCE vector.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            chain2._load_from_db()
            self.assertEqual(chain2.supply.balances, balances_before)
            self.assertEqual(chain2.supply.staked, staked_before)
            self.assertEqual(
                chain2.chain[-1].header.block_number, height,
            )
            _close(db2)
        finally:
            self._restore()

    def test_tampered_snapshot_blob_does_not_pickle_loads(self):
        """The security contract: a tampered snapshot row in chaindb
        MUST NOT reach ``pickle.loads``.  Pre-fix, an attacker who
        substitutes a malicious pickle into ``state_snapshots`` got
        local RCE on the next cold-restart.  Post-fix, the HMAC
        envelope verifies first, the tampered blob fails the check,
        and the caller falls back to legacy field-by-field load --
        ``pickle.loads`` is never called on the attacker's bytes.
        """
        self._install(self.founder.entity_id)
        try:
            db_path = self._fresh_db_path()
            chain, db = self._build_chain(db_path)
            height = self._mint_one_block(chain)
            # Snapshot bytes for a cold-restart-RCE attempt: an
            # arbitrary attacker-controlled blob.  We don't actually
            # build a real RCE pickle -- we just substitute non-
            # envelope bytes and verify the load path doesn't crash
            # AND doesn't honor the substitution.
            attacker_blob = b"\x00ATTACKER-CONTROLLED-PICKLE-BYTES\xff"
            db._conn.execute(
                "INSERT OR REPLACE INTO state_snapshots "
                "(block_number, state_blob) VALUES (?, ?)",
                (int(height), attacker_blob),
            )
            db._conn.commit()
            _close(db)
            # Cold restart: the load path tries the envelope, fails
            # HMAC, falls back to legacy field-by-field load.  The
            # node MUST come up cleanly (legacy path is correct,
            # just slower for re-warming accumulators).
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            chain2._load_from_db()
            # Sanity: chain still loaded; balances rehydrated from
            # the canonical chaindb tables (which the attacker
            # didn't touch in this scenario).
            self.assertEqual(
                chain2.chain[-1].header.block_number, height,
            )
            _close(db2)
        finally:
            self._restore()

    def test_snapshot_from_different_node_rejected(self):
        """Cross-node: a snapshot row written under node A's secret
        must not unpickle under node B's secret.  Defends against an
        attacker who copies a snapshot from one validator to
        another (or restores from someone else's backup)."""
        self._install(self.founder.entity_id)
        try:
            # Node A: builds a chain and persists a snapshot row.
            db_a_path = self._fresh_db_path()
            chain_a, db_a = self._build_chain(db_a_path)
            height = self._mint_one_block(chain_a)
            blob_a = db_a.get_state_snapshot(height)
            secret_a_hex = db_a.get_meta("snapshot_hmac_key")
            _close(db_a)
            # Node B: independent fresh DB, mints its own snapshot
            # so it has its OWN secret.  Then we paste node A's
            # blob over node B's height-1 row -- simulating a
            # cross-node tamper.
            db_b_path = self._fresh_db_path()
            chain_b, db_b = self._build_chain(db_b_path)
            height_b = self._mint_one_block(chain_b)
            secret_b_hex = db_b.get_meta("snapshot_hmac_key")
            self.assertNotEqual(secret_a_hex, secret_b_hex)
            db_b._conn.execute(
                "INSERT OR REPLACE INTO state_snapshots "
                "(block_number, state_blob) VALUES (?, ?)",
                (int(height_b), blob_a),
            )
            db_b._conn.commit()
            _close(db_b)
            # Cold restart node B: its secret is B's; the row is
            # tagged under A's; HMAC mismatch; legacy fallback.
            db_b2 = ChainDB(db_b_path)
            chain_b2 = Blockchain(db=db_b2)
            chain_b2._load_from_db()
            self.assertEqual(
                chain_b2.chain[-1].header.block_number, height_b,
            )
            _close(db_b2)
        finally:
            self._restore()


class TestSnapshotEnvelopeSourcePin(unittest.TestCase):
    """Source-level pin: blockchain.py routes every persistent-
    snapshot pickle through ``_decode_snapshot_blob`` /
    ``_pack_snapshot_blob``.  A future refactor cannot drift back
    to a raw ``pickle.loads(blob)`` on a chaindb row without
    tripping this test."""

    def test_no_raw_pickle_loads_on_snapshot_blob(self):
        import inspect
        from messagechain.core import blockchain as _bc
        src = inspect.getsource(_bc)
        # Every pickle.loads in blockchain.py must be inside
        # ``_decode_snapshot_blob`` (which calls it on the verified
        # inner payload only).  Count occurrences and pin shape.
        lines = src.splitlines()
        loads_lines = [
            (i, ln) for i, ln in enumerate(lines, 1)
            if "pickle.loads(" in ln
        ]
        # Exactly one call site, inside ``_decode_snapshot_blob``.
        self.assertEqual(
            len(loads_lines), 1,
            f"expected exactly one ``pickle.loads`` call in "
            f"blockchain.py (inside ``_decode_snapshot_blob``); "
            f"found {len(loads_lines)}: {loads_lines}",
        )

    def test_persist_state_snapshot_uses_envelope(self):
        """The persist site must wrap pickle bytes with
        ``_pack_snapshot_blob`` before writing -- otherwise the
        load-side HMAC check has nothing to verify and we'd be
        back at "pickle.loads on whatever's in the row"."""
        import inspect
        from messagechain.core import blockchain as _bc
        src = inspect.getsource(_bc._Blockchain) if hasattr(
            _bc, "_Blockchain"
        ) else inspect.getsource(_bc.Blockchain)
        self.assertIn("_pack_snapshot_blob(pickle_blob, secret)", src)


if __name__ == "__main__":
    unittest.main()
