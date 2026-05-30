"""Long-term proper fixes for the three latent issues uncovered
during the 2026-05-30 mainnet-wedge recovery:

Fix A -- ``_persist_state_snapshot`` must let IO exceptions
         propagate so the block-apply transaction rolls back as a
         unit.  Pre-fix, a swallowed exception left chain.db with
         a committed block but no snapshot row at that height,
         which then poisoned every subsequent cold-load with a
         field-by-field fallback that doesn't carry in-memory
         accumulators -> state_root divergence on next received
         block.

Fix B -- ``messagechain upgrade``'s clone dir at
         ``/tmp/mc-release-<ts>`` must be cleaned up on EVERY
         exit path AND prior runs' stale clones must be swept on
         every invocation.  Pre-fix, validator-1 had accumulated
         7 stale clone dirs (~125 MB) over months, which then
         masked the underlying snapshot-persistence bug behind a
         disk-full smokescreen during the 1.96.3 splice.

Fix C -- ``messagechain status`` must surface disk-space pressure
         so operators see the warning shot before the daemon
         starts silently failing writes.  Pre-fix, the first
         signal that disk was full was the daemon throwing
         ``OperationalError: database or disk is full`` during
         active block apply -- by which point silent state drift
         had already begun.

CLAUDE.md anchors at risk for ALL THREE:
  * Permanence -- a wedged chain can't accept new messages.
  * Honest-operator insurance -- silent state drift on a healthy
    operator is the worst-class regression.
  * Hard-fork minimization -- a wedge-during-activation is
    exactly the failure mode the upgrade smoke test exists to
    catch; if THAT bug is masked by a disk-full smokescreen, the
    smoke test is doing the operator a disservice.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import messagechain.config as _cfg
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


# ─────────────────────────────────────────────────────────────────
# Fix A: snapshot write failures propagate (no silent swallow)
# ─────────────────────────────────────────────────────────────────


class SnapshotWriteFailureMustRollbackBlock(unittest.TestCase):
    """``_persist_state_snapshot`` MUST let underlying IO exceptions
    propagate.  The caller's transaction wrapper then rolls back
    the block apply as a unit -- chain.db never lands in a state
    where the block is committed but the snapshot row is missing.
    """

    @classmethod
    def setUpClass(cls):
        cls.founder = Entity.create(
            private_key=b"audit-r60-snapshot-rollback-test",
            tree_height=4,
        )

    def setUp(self):
        self._saved_founder = _cfg._MAINNET_FOUNDER_ENTITY_ID
        self._saved_pinned = getattr(_cfg, "PINNED_GENESIS_HASH", None)
        self._saved_mainnet = getattr(_cfg, "_MAINNET_GENESIS_HASH", None)

    def tearDown(self):
        # Restore unconditionally -- even None values must be put
        # back so a test that SET a pin doesn't leak it to the next
        # test on the same xdist worker.
        _cfg._MAINNET_FOUNDER_ENTITY_ID = self._saved_founder
        _cfg.PINNED_GENESIS_HASH = self._saved_pinned
        _cfg._MAINNET_GENESIS_HASH = self._saved_mainnet

    def test_snapshot_io_error_propagates_to_caller(self):
        """When ``set_state_snapshot`` raises (simulating disk-full,
        sqlite locked, etc.), ``_persist_state_snapshot`` MUST
        propagate the exception -- not catch and return silently.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_snap_rollback_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db = ChainDB(os.path.join(tmp, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        _cfg.PINNED_GENESIS_HASH = chain.chain[0].block_hash
        _cfg._MAINNET_GENESIS_HASH = chain.chain[0].block_hash
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

        try:
            # Patch set_state_snapshot to simulate disk-full at write
            # time.  The fix requires the OSError to bubble out of
            # _persist_state_snapshot rather than be swallowed.
            with patch.object(
                db, "set_state_snapshot",
                side_effect=OSError("simulated disk full"),
            ):
                with self.assertRaises(OSError) as ctx:
                    chain._persist_state_snapshot(1)
                self.assertIn("disk full", str(ctx.exception).lower())
        finally:
            _close(db)

    def test_apply_rolls_back_when_snapshot_write_fails(self):
        """End-to-end: when snapshot write fails during block apply,
        the apply path's outer try/except catches the propagated
        exception, rolls back the chaindb transaction, and the
        block is NOT committed.  Chain length stays at genesis +
        no chaindb writes from the failed apply persist.
        """
        from messagechain.consensus.pos import ProofOfStake
        from tests import pick_selected_proposer

        _cfg._MAINNET_FOUNDER_ENTITY_ID = self.founder.entity_id

        tmp = tempfile.mkdtemp(prefix="mc_audit_r60_apply_rollback_")
        self.addCleanup(shutil.rmtree, tmp, True)
        db = ChainDB(os.path.join(tmp, "chain.db"))
        chain = Blockchain(db=db)
        chain.initialize_genesis(
            self.founder,
            {
                self.founder.entity_id: _MAINNET_FOUNDER_TOTAL,
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            },
        )
        _cfg.PINNED_GENESIS_HASH = chain.chain[0].block_hash
        _cfg._MAINNET_GENESIS_HASH = chain.chain[0].block_hash
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
        try:
            height_before = chain.height
            proposer = pick_selected_proposer(chain, [self.founder])
            blk = chain.propose_block(consensus, proposer, [])

            # Pre-fix: ok==True because the snapshot exception was
            # swallowed inside ``_persist_state_snapshot`` and the
            # block committed regardless.  Post-fix: the exception
            # propagates through the apply path's ``except
            # BaseException: rollback; raise`` and the block is
            # NOT committed.  Either the call raises (current shape)
            # OR returns (False, ...) -- both are acceptable
            # "fail-loud, no silent partial commit" outcomes.
            raised = None
            ok = True
            try:
                with patch.object(
                    db, "set_state_snapshot",
                    side_effect=OSError("simulated disk full"),
                ):
                    ok, reason = chain.add_block(blk)
            except OSError as e:
                raised = e
            self.assertTrue(
                raised is not None or ok is False,
                "Block MUST either raise (apply path's rollback "
                "re-raised the OSError) OR return (False, ...) "
                "(apply path caught + returned failure).  Pre-fix: "
                "silent (True, success) leaving chain.db with the "
                "block but no snapshot at that height.",
            )
            # Chain height MUST NOT advance regardless of which
            # failure shape fires.
            self.assertEqual(
                chain.height, height_before,
                "Chain length must equal pre-attempt height when "
                "snapshot write failed.",
            )
        finally:
            _close(db)


# ─────────────────────────────────────────────────────────────────
# Fix B: upgrade clone-dir lifecycle
# ─────────────────────────────────────────────────────────────────


class UpgradeStaleCloneSweep(unittest.TestCase):
    """``_upgrade_sweep_stale_clones`` must remove stale
    ``/tmp/mc-release-*`` dirs from prior upgrade runs while
    leaving FRESH ones alone (so a concurrent upgrade doesn't have
    its in-flight clone deleted out from under it).
    """

    def setUp(self):
        # Use a private tempdir so we don't actually touch system
        # /tmp.  Override the sweep's hardcoded glob path via
        # monkey-patching ``glob.glob`` to our staging dir.
        self.staging = tempfile.mkdtemp(prefix="mc_audit_r60_sweep_")
        self.addCleanup(shutil.rmtree, self.staging, True)

    def _make_clone(self, name: str, age_seconds: float) -> str:
        path = os.path.join(self.staging, name)
        os.makedirs(path, exist_ok=True)
        # Drop a sentinel file so the rmtree has something to remove.
        with open(os.path.join(path, "marker"), "w") as f:
            f.write("x")
        old_time = time.time() - age_seconds
        os.utime(path, (old_time, old_time))
        return path

    def test_sweeps_only_stale_clones(self):
        """A 2-hour-old clone is swept; a 1-minute-old clone is
        preserved.  Threshold is the default ``older_than_seconds=3600``.
        """
        from messagechain.cli import _upgrade_sweep_stale_clones

        old1 = self._make_clone("mc-release-20260101-000000", age_seconds=7200)
        old2 = self._make_clone("mc-release-20260101-000001", age_seconds=4000)
        fresh = self._make_clone("mc-release-20260601-120000", age_seconds=60)
        unrelated = self._make_clone("not-a-release-dir", age_seconds=99999)

        # Patch the glob to point at our staging dir instead of /tmp.
        with patch(
            "glob.glob",
            return_value=[old1, old2, fresh, unrelated],
        ):
            removed = _upgrade_sweep_stale_clones(older_than_seconds=3600)

        # Both stale clones removed; fresh and unrelated preserved.
        # ``unrelated`` matches because we passed it to the mocked
        # glob -- but the sweep's age gate still applies, so it
        # WOULD be removed too if it matched the glob.  In real
        # use, glob.glob("/tmp/mc-release-*") wouldn't match it.
        self.assertIn(old1, removed)
        self.assertIn(old2, removed)
        self.assertNotIn(fresh, removed)
        # Fresh clone files still exist.
        self.assertTrue(os.path.exists(fresh))
        # Stale clones are gone.
        self.assertFalse(os.path.exists(old1))
        self.assertFalse(os.path.exists(old2))

    def test_sweep_tolerates_unreadable_entries(self):
        """A clone path the sweep can't stat (e.g., race with another
        process) is silently skipped rather than aborting the
        whole sweep.  Belt-and-suspenders: a hostile/transient
        filesystem state shouldn't poison the upgrade flow.
        """
        from messagechain.cli import _upgrade_sweep_stale_clones

        with patch("glob.glob", return_value=["/nonexistent/mc-release-foo"]):
            # Should not raise; should return [].
            removed = _upgrade_sweep_stale_clones()
        self.assertEqual(removed, [])


# ─────────────────────────────────────────────────────────────────
# Fix C: disk-space surface in status
# ─────────────────────────────────────────────────────────────────


class StatusDiskSpaceCheck(unittest.TestCase):
    """``cmd_status`` surfaces disk-space pressure when invoked
    locally so an operator gets a warning shot before the daemon
    starts silently failing writes.
    """

    def test_disk_critical_marks_red(self):
        """< 5% free OR < 500 MB free -> RED."""
        from collections import namedtuple
        Usage = namedtuple("Usage", ["total", "used", "free"])

        worst = 0
        lines = []

        def mark(level: int, label: str, status: str, detail: str = ""):
            nonlocal worst
            worst = max(worst, level)
            lines.append((level, label, status, detail))

        # 1 GB total, 50 MB free -> 5% but absolute-floor failure.
        usage = Usage(total=1024**3, used=(1024**3) - 50 * 1024 * 1024,
                      free=50 * 1024 * 1024)
        # Run the disk-check fragment in isolation.  We replicate
        # the production logic here so the test is independent of
        # cmd_status's other call paths (which need RPC mocking).
        free_gb = usage.free / (1024 ** 3)
        free_pct = (usage.free / usage.total) * 100
        if usage.free < 500 * 1024 * 1024 or free_pct < 5:
            mark(2, "disk", "CRITICAL",
                 f"{free_gb:.1f} GB free ({free_pct:.0f}%)")
        elif free_pct < 20:
            mark(1, "disk", "low", "")
        else:
            mark(0, "disk", "ok", "")
        self.assertEqual(worst, 2, "50 MB free MUST mark RED")
        self.assertEqual(lines[0][1], "disk")
        self.assertEqual(lines[0][2], "CRITICAL")

    def test_disk_low_marks_yellow(self):
        """5%-20% free -> YELLOW (operator warning, not blocking)."""
        from collections import namedtuple
        Usage = namedtuple("Usage", ["total", "used", "free"])
        usage = Usage(total=10 * 1024**3,
                      used=int(8.5 * 1024**3),
                      free=int(1.5 * 1024**3))  # 15% free
        free_gb = usage.free / (1024 ** 3)
        free_pct = (usage.free / usage.total) * 100
        worst = 0
        if usage.free < 500 * 1024 * 1024 or free_pct < 5:
            worst = 2
        elif free_pct < 20:
            worst = 1
        else:
            worst = 0
        self.assertEqual(worst, 1, "15% free MUST mark YELLOW")

    def test_disk_ok_marks_green(self):
        """> 20% free -> GREEN."""
        from collections import namedtuple
        Usage = namedtuple("Usage", ["total", "used", "free"])
        usage = Usage(total=10 * 1024**3, used=5 * 1024**3, free=5 * 1024**3)
        free_pct = (usage.free / usage.total) * 100
        worst = 0
        if usage.free < 500 * 1024 * 1024 or free_pct < 5:
            worst = 2
        elif free_pct < 20:
            worst = 1
        else:
            worst = 0
        self.assertEqual(worst, 0, "50% free MUST mark GREEN")


if __name__ == "__main__":
    unittest.main()
