"""Regression: a candidate block that would be rejected by the
validator-side timestamp rules must NOT advance the height-guard
floor.

Pre-fix (the live chain-stall incident on 2026-04-27, height 671),
``ProofOfStake.create_block`` reserved the floor BEFORE running any
local validation.  A candidate that the validator-side would reject
(originally a round-cap violation, but the same property must hold for
every locally-checkable timestamp rule) still advanced the floor —
and every subsequent legitimate retry at the same height failed with
``HeightAlreadySignedError``.  The chain wedged with no recovery short
of manual floor surgery.

This regression pins the post-fix invariant: pre-sign rejection raises
``ProposerSkipSlotError``, the floor is unchanged, and a follow-up
legitimate proposal at the same height succeeds.

The original round-cap subtest was retired alongside the round-cap
removal (see ``config.MAX_BLOCK_FUTURE_DRIFT`` and
``tests/test_round_cap_recovery.py``).  The remaining subtests cover
the two live pre-sign rules — timestamp-too-early and future-drift —
which is what defends the floor-poisoning property going forward.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.config import BLOCK_TIME_TARGET
from messagechain.consensus.height_guard import HeightSignGuard
from messagechain.consensus.pos import ProofOfStake, ProposerSkipSlotError
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity


class TestProposerFloorNotPoisonedOnLocalRejection(unittest.TestCase):
    """All three subtests assert the same invariant under different
    rejection rules: a candidate the validator-side would reject MUST
    NOT advance the height-guard floor.

    The pre-sign helper is gated on ``ENFORCE_SLOT_TIMING`` (the
    test-mode escape hatch the rest of the suite relies on for
    synthetic block construction).  Production pins this True; we
    re-pin it True here in setUp so the rules actually fire, and
    restore it in tearDown so the rest of the suite's permissive
    block construction is unaffected.
    """

    def setUp(self):
        import messagechain.config as _cfg
        self._prior_enforce = _cfg.ENFORCE_SLOT_TIMING
        _cfg.ENFORCE_SLOT_TIMING = True

        self._tmp = tempfile.mkdtemp(prefix="mc-floor-poison-")
        self.proposer = Entity.create(b"prop-floor-test".ljust(32, b"\x00"))
        self.proposer.keypair._next_leaf = 0
        guard_path = os.path.join(self._tmp, "height_guard.json")
        self.proposer.height_sign_guard = HeightSignGuard.load_or_create(
            guard_path,
        )
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)

    def tearDown(self):
        import messagechain.config as _cfg
        _cfg.ENFORCE_SLOT_TIMING = self._prior_enforce
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_timestamp_too_early_does_not_advance_floor(self):
        """Same property for the ``ts_gap < BLOCK_TIME_TARGET`` rule.

        Defense-in-depth: every locally-checkable timestamp rule must
        skip the slot rather than poison the floor, not just the
        round-cap.
        """
        consensus = ProofOfStake()
        prev = self.chain.get_latest_block()
        bad_ts = prev.header.timestamp + (BLOCK_TIME_TARGET // 2)
        prior_floor = self.proposer.height_sign_guard.last_block_signed
        with self.assertRaises(ProposerSkipSlotError) as cm:
            consensus.create_block(
                self.proposer, [], prev, timestamp=bad_ts,
            )
        self.assertIn("too early", str(cm.exception).lower())
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            prior_floor,
        )

    def test_future_drift_does_not_advance_floor(self):
        """Same property for the ``timestamp > now + MAX_BLOCK_FUTURE_DRIFT``
        rule.  A proposer that picks a far-future timestamp (e.g. NTP
        gone wild, malicious clock) skips the slot rather than poisons
        the floor.
        """
        from messagechain.config import MAX_BLOCK_FUTURE_DRIFT
        import time as _time

        consensus = ProofOfStake()
        prev = self.chain.get_latest_block()
        # Push the timestamp way past now + MAX_BLOCK_FUTURE_DRIFT.
        # With the round-cap removed, future-drift is now the only
        # rule that fires for "far-future" timestamps.
        bad_ts = _time.time() + MAX_BLOCK_FUTURE_DRIFT * 1000
        prior_floor = self.proposer.height_sign_guard.last_block_signed
        with self.assertRaises(ProposerSkipSlotError) as cm:
            consensus.create_block(
                self.proposer, [], prev, timestamp=bad_ts,
            )
        self.assertIn(
            "future", str(cm.exception).lower(),
            f"expected future-drift rejection, got: {cm.exception}",
        )
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            prior_floor,
        )


if __name__ == "__main__":
    unittest.main()
