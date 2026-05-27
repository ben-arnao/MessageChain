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
        # tree_height=8 gives 256 WOTS+ leaves -- enough for the
        # 50-block fixture's ~100 signature consumption (proposer +
        # attestation each block).  tree_height=4 (16 leaves, the
        # cheapest setting) exhausts at ~10 blocks.
        cls.founder = Entity.create(
            private_key=b"compare-state-paths-test-founder",
            tree_height=8,
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

    def _assert_zero_drift(self, n_blocks: int):
        """Build an N-block chain and assert cold-load == replay-from-
        genesis on every snapshot field.  Used by the parameterized
        scale tests below.  A failure names the drifted field and the
        block count where the bug first triggers -- the bisection
        target for the per-accumulator fix work."""
        tmp = tempfile.mkdtemp(prefix="mc_compare_test_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db_path = os.path.join(tmp, "chain.db")

        chain1, db1 = self._build_chain_with_blocks(
            db_path, n_blocks=n_blocks,
        )
        db1.flush_state()
        _close(db1)

        db2 = ChainDB(db_path)
        chain2 = Blockchain(db=db2)
        state_a = chain2._snapshot_memory_state()

        ok, reason = chain2._replay_state_from_genesis()
        self.assertTrue(ok, reason)
        state_b = chain2._snapshot_memory_state()

        buf = io.StringIO()
        with redirect_stdout(buf):
            drift_count = _compare_state_dicts(state_a, state_b)
        self.assertEqual(
            drift_count, 0,
            f"Cold-load vs replay-from-genesis drift detected on a "
            f"{n_blocks}-block test fixture.  This is the option (a) "
            f"determinism bug -- the drifted field names a "
            f"non-deterministic accumulator update path.  Diff "
            f"output:\n{buf.getvalue()}",
        )
        _close(db2)

    def test_freshly_built_chain_is_snapshot_deterministic(self):
        """3 blocks -- the smallest reproducer.  Must be zero drift
        or even the simplest chain has a determinism bug."""
        try:
            self._assert_zero_drift(n_blocks=3)
        finally:
            self._restore_all()

    def test_zero_drift_at_15_blocks(self):
        """15 blocks -- past the first few attestation cycles, picks
        up any drift triggered by per-block accumulator updates that
        skip the first 1-2 blocks (e.g. accumulator init paths that
        only fire post-genesis-warmup).  Any drift here is a genuine
        determinism bug, not a fork artifact -- the chain is built
        from scratch by this test."""
        try:
            self._assert_zero_drift(n_blocks=15)
        finally:
            self._restore_all()

    def test_replay_preserves_simulated_accumulator_drift(self):
        """1.95.0 contract: ``_replay_state_from_genesis`` restores
        non-state_root accumulators from the pre-replay cold-load
        snapshot rather than computing them from blocks.  This makes
        replay match the chain's actual history on chains that have
        been running across binary versions with apply-path bugs
        (the 2026-05-26 v1/v2 production state).

        Test: build a clean 3-block chain, simulate accumulator
        drift by poisoning a non-state_root accumulator
        (``validator_archive_misses[founder] += 99``), capture the
        drifted state, run replay-from-genesis, assert replay
        preserved the poisoned value (didn't reset it to what
        from-blocks computation would produce).
        """
        try:
            tmp = tempfile.mkdtemp(prefix="mc_compare_test_")
            self.addCleanup(shutil.rmtree, tmp, True)
            db_path = os.path.join(tmp, "chain.db")

            chain1, db1 = self._build_chain_with_blocks(
                db_path, n_blocks=3,
            )

            # Poison a non-state_root accumulator -- simulates the
            # historical-drift class of bug.  validator_archive_misses
            # is per-validator and not contributed to state_root, so
            # mutating it doesn't break header validation but does
            # diverge cold-load from replay-from-blocks.
            poisoned_value = 99
            chain1.validator_archive_misses[
                self.founder.entity_id
            ] = poisoned_value

            cold_snapshot = chain1._snapshot_memory_state()
            self.assertEqual(
                cold_snapshot["validator_archive_misses"].get(
                    self.founder.entity_id, 0,
                ),
                poisoned_value,
                "test setup: cold-load must have the poisoned value",
            )

            ok, reason = chain1._replay_state_from_genesis()
            self.assertTrue(ok, reason)

            # 1.95.0 contract: replay restored the poisoned value
            # from cold snapshot.  Pre-1.95.0 replay would have
            # rebuilt validator_archive_misses from blocks alone,
            # losing the poison.
            replayed_value = chain1.validator_archive_misses.get(
                self.founder.entity_id, 0,
            )
            self.assertEqual(
                replayed_value, poisoned_value,
                "Replay must preserve non-state_root accumulator "
                "values from the pre-replay cold-load snapshot.  "
                "Lost value = pure-from-blocks replay regression "
                "of the 1.95.0 preserve-accumulators mechanism.",
            )
            _close(db1)
        finally:
            self._restore_all()

    @unittest.skipIf(
        os.environ.get("PYTEST_XDIST_WORKER") is not None
        and "MC_RUN_SLOW" not in os.environ,
        "50-block fixture exceeds the default 30s xdist timeout; "
        "runs in CI/serial mode (MC_RUN_SLOW=1) or via -n 0",
    )
    def test_zero_drift_at_50_blocks(self):
        """50 blocks -- enough to cross most periodic-window
        accumulator boundaries (reward maturation queues, archive
        epoch closes, attester-coverage rollovers) at typical small
        window sizes.  Drift here surfaces non-determinism that
        depends on cumulative count rather than per-block apply.

        Build cost: ~30s wall clock due to WOTS+ keygen for 50
        signatures at tree_height=8.  Default xdist timeout is 30s,
        so this test is skipped under parallel runs and only fires
        when MC_RUN_SLOW=1 or under serial (``-n 0``).  The 3- and
        15-block determinism tests above still run under xdist and
        catch the common case."""
        try:
            self._assert_zero_drift(n_blocks=50)
        finally:
            self._restore_all()


if __name__ == "__main__":
    unittest.main()
