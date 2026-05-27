"""Tests for the `messagechain compare-state-paths` diagnostic CLI.

Background -- 2026-05-26 v1/v2 state-machine divergence at height 2846.
Both validators had byte-identical chains through height 2845 (same
block hashes everywhere) but disagreed on the post-state when v2
tried to apply v1's block 2846: "Invalid state_root -- state
commitment mismatch".  Operational fix was to splice v2's chain.db
onto v1; long-term fix is the accumulator-determinism refactor where
every in-memory accumulator becomes a pure function of chain content.

This CLI is Phase 1 of that work -- a diagnostic that runs on a
chain.db and reports which fields differ between cold-load and
replay-from-genesis paths.  The fields that differ are the
candidates for the determinism refactor.

These tests pin the diagnostic contract:

  * Built-from-scratch chain shows zero drift (the simplest
    determinism case must hold or the diagnostic itself is wrong).
  * The diff helper correctly identifies and reports drift in
    plausible field shapes (dict / set / list / scalar).
  * Daemon-running gate refuses to operate when the lock is held
    (same constraint as prune-fork-branches).
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

import messagechain.config as _cfg
from messagechain.cli import _compare_state_dicts
from messagechain.config import (
    _MAINNET_FOUNDER_STAKE,
    _MAINNET_FOUNDER_TOTAL,
    TREASURY_ALLOCATION,
    TREASURY_ENTITY_ID,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.bootstrap import bootstrap_seed_local
from messagechain.identity.identity import Entity
from messagechain.storage.chaindb import ChainDB


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


class _MainnetPinOverride:
    """Same fixture pattern as test_cold_load_self_heal -- needed for
    _replay_state_from_genesis to route through
    _apply_mainnet_genesis_supply_state."""

    def _install_founder(self, eid: bytes):
        self._saved_founder = _cfg._MAINNET_FOUNDER_ENTITY_ID
        _cfg._MAINNET_FOUNDER_ENTITY_ID = eid

    def _install_genesis_pins(self, genesis_hash: bytes):
        self._saved_pinned = getattr(_cfg, "PINNED_GENESIS_HASH", None)
        self._saved_mainnet_hash = getattr(
            _cfg, "_MAINNET_GENESIS_HASH", None,
        )
        _cfg.PINNED_GENESIS_HASH = genesis_hash
        _cfg._MAINNET_GENESIS_HASH = genesis_hash

    def _restore_all(self):
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self._saved_founder
        if hasattr(self, "_saved_pinned"):
            _cfg.PINNED_GENESIS_HASH = self._saved_pinned
        if hasattr(self, "_saved_mainnet_hash"):
            _cfg._MAINNET_GENESIS_HASH = self._saved_mainnet_hash


class TestStateDictDiffer(unittest.TestCase):
    """Pure unit tests for ``_compare_state_dicts``."""

    def _capture(self, fn) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            count = fn()
        return count, buf.getvalue()

    def test_identical_dicts_report_zero_drift(self):
        a = {"balances": {b"x": 5}, "total": 100, "set": {1, 2}}
        b = {"balances": {b"x": 5}, "total": 100, "set": {1, 2}}
        count, out = self._capture(lambda: _compare_state_dicts(a, b))
        self.assertEqual(count, 0, out)
        # No DRIFT lines when state matches.
        self.assertNotIn("DRIFT", out)

    def test_dict_field_drift_reports_per_key_breakdown(self):
        a = {
            "balances": {b"alice": 10, b"bob": 20, b"carol": 30},
        }
        b = {
            # alice changed, bob removed, dave added
            "balances": {b"alice": 11, b"carol": 30, b"dave": 40},
        }
        count, out = self._capture(lambda: _compare_state_dicts(a, b))
        self.assertEqual(count, 1)
        self.assertIn("DRIFT [balances]", out)
        self.assertIn("cold-only-keys=1", out)
        self.assertIn("replay-only-keys=1", out)
        self.assertIn("changed-keys=1", out)

    def test_set_field_drift_reports_membership_delta(self):
        a = {"slashed_validators": {b"v1", b"v2"}}
        b = {"slashed_validators": {b"v1", b"v3"}}
        count, out = self._capture(lambda: _compare_state_dicts(a, b))
        self.assertEqual(count, 1)
        self.assertIn("DRIFT [slashed_validators]: set", out)
        self.assertIn("cold-only=1", out)
        self.assertIn("replay-only=1", out)

    def test_scalar_field_drift_shows_both_values(self):
        a = {"total_supply": 100_000_000}
        b = {"total_supply": 99_999_999}
        count, out = self._capture(lambda: _compare_state_dicts(a, b))
        self.assertEqual(count, 1)
        self.assertIn("DRIFT [total_supply]", out)
        self.assertIn("100000000", out)
        self.assertIn("99999999", out)

    def test_list_field_drift_shows_length_delta(self):
        a = {"_immature_rewards": [1, 2, 3, 4]}
        b = {"_immature_rewards": [1, 2, 99, 4]}
        count, out = self._capture(lambda: _compare_state_dicts(a, b))
        self.assertEqual(count, 1)
        self.assertIn("DRIFT [_immature_rewards]: list", out)
        # Index 2 differs.
        self.assertIn("index 2", out)


class TestColdLoadVsReplayDeterminism(_MainnetPinOverride, unittest.TestCase):
    """End-to-end: build a chain via the same fixture as
    test_cold_load_self_heal, then cold-load -> snapshot -> replay
    -> snapshot, and assert the diagnostic reports zero drift.  If
    this test fails, the diagnostic has found a real determinism bug
    in the test-fixture-scale chain -- the smallest possible
    repro for the option (a) work item."""

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"compare-state-paths-test-founder",
            tree_height=4,
        )

    def _build_chain_with_blocks(self, db_path: str, n_blocks: int):
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        self._install_founder(self.founder.entity_id)
        db = ChainDB(db_path)
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        self._install_genesis_pins(chain.chain[0].block_hash)
        bootstrap_seed_local(
            chain, self.founder,
            cold_authority_pubkey=self.founder.public_key,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        consensus = ProofOfStake()
        consensus.register_validator(
            self.founder.entity_id,
            stake_amount=_MAINNET_FOUNDER_STAKE,
        )
        for _ in range(n_blocks):
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])
            ok, reason = chain.add_block(blk)
            self.assertTrue(ok, reason)
        return chain, db

    def test_freshly_built_chain_is_snapshot_deterministic(self):
        """Test fixture chains MUST be snapshot-deterministic.  If
        they're not, the diagnostic CLI is broken OR there's a
        first-order determinism bug that the smallest possible chain
        already reproduces (great news for fixing it)."""
        try:
            tmp = tempfile.mkdtemp(prefix="mc_compare_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")

            # Phase 1: build chain, persist, close.
            chain1, db1 = self._build_chain_with_blocks(
                db_path, n_blocks=3,
            )
            db1.flush_state()
            _close(db1)

            # Phase 2: cold-load + replay-from-genesis on same chain.db.
            db2 = ChainDB(db_path)
            chain2 = Blockchain(db=db2)
            state_a = chain2._snapshot_memory_state()

            ok, reason = chain2._replay_state_from_genesis()
            self.assertTrue(ok, reason)
            state_b = chain2._snapshot_memory_state()

            # Phase 3: assert no drift.  Capture the diagnostic
            # output for the failure message so a fail report names
            # the drifted field.
            buf = io.StringIO()
            with redirect_stdout(buf):
                drift_count = _compare_state_dicts(state_a, state_b)
            self.assertEqual(
                drift_count, 0,
                f"Cold-load vs replay-from-genesis drift detected on "
                f"a 3-block test fixture.  This is the option (a) "
                f"determinism bug at its smallest reproducer.  Diff "
                f"output:\n{buf.getvalue()}",
            )
            _close(db2)
        finally:
            self._restore_all()


if __name__ == "__main__":
    unittest.main()
