"""Regression: a candidate block that would be rejected by the
validator-side timestamp/round rules must NOT advance the height-guard
floor.

Pre-fix (the live chain-stall incident on 2026-04-27, height 671),
``ProofOfStake.create_block`` reserved the floor BEFORE running any
local validation.  A candidate at ``round_number >
MAX_PROPOSER_FALLBACK_ROUNDS`` (which the validator-side rejects as
"timestamp-skew slot hijacking rejected") still advanced the floor —
and every subsequent legitimate retry at the same height failed with
``HeightAlreadySignedError``.  The chain wedged with no recovery short
of manual floor surgery.

This regression pins the post-fix invariant: pre-sign rejection raises
``ProposerSkipSlotError``, the floor is unchanged, and a follow-up
proposal at the same height with an in-cap timestamp succeeds.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.config import (
    BLOCK_TIME_TARGET,
    MAX_PROPOSER_FALLBACK_ROUNDS,
)
from messagechain.consensus.height_guard import (
    HeightAlreadySignedError,
    HeightSignGuard,
)
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

    def test_round_cap_violation_does_not_advance_floor(self):
        """Round-cap rejection must NOT poison the floor.

        Mirrors the live chain-stall scenario: wall-clock has marched
        far past the parent's timestamp, so a naive
        ``timestamp = time.time()`` choice yields a ``round_number``
        that the validator-side rejects.  Pre-fix the floor was
        advanced anyway; post-fix the slot is skipped and the floor
        is preserved for a future legitimate retry.
        """
        import time as _time

        consensus = ProofOfStake()
        prev = self.chain.get_latest_block()
        new_height = prev.header.block_number + 1

        # Anchor the parent's timestamp far enough in the past that
        # ``bad_ts`` (parent + (cap+2)*BLOCK_TIME_TARGET) falls within
        # the future-drift window, so the round-cap rule — not future-
        # drift — is the binding pre-sign rejection.  This is the
        # scenario that produced the live chain stall: the chain went
        # quiet long enough that a now-aligned proposer's natural
        # timestamp implies round_number > cap relative to the older
        # parent.
        prev.header.timestamp = (
            _time.time()
            - (MAX_PROPOSER_FALLBACK_ROUNDS + 5) * BLOCK_TIME_TARGET
        )

        # Construct a timestamp that implies round_number > cap.
        # Validator-side computes
        #   round_number = int((ts_gap - BLOCK_TIME_TARGET) // BLOCK_TIME_TARGET)
        # so any ``ts_gap >= (cap + 2) * BLOCK_TIME_TARGET`` overshoots.
        bad_ts = (
            prev.header.timestamp
            + (MAX_PROPOSER_FALLBACK_ROUNDS + 2) * BLOCK_TIME_TARGET
        )
        prior_floor = self.proposer.height_sign_guard.last_block_signed
        self.assertEqual(
            prior_floor, -1,
            "fresh guard must start at -1 floor (any height >= 0 accepted)",
        )

        with self.assertRaises(ProposerSkipSlotError) as cm:
            consensus.create_block(
                self.proposer, [], prev, timestamp=bad_ts,
            )
        # Diagnostic must name the cap so an operator looking at the
        # log can correlate with the validator-side rejection message.
        self.assertIn("cap", str(cm.exception).lower())

        # The load-bearing assertion: the floor MUST NOT have advanced.
        # Pre-fix this is where the test would fail (floor would equal
        # ``new_height``).  Post-fix the floor is untouched.
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            prior_floor,
            "ProposerSkipSlotError must NOT advance the height-guard "
            "floor; pre-fix the floor was poisoned to new_height and "
            "the chain wedged with no recovery",
        )

        # And a subsequent legitimate proposal at the SAME height (with
        # an in-cap timestamp) MUST succeed.  This is the property the
        # operator cared about: a transient bad-timestamp slot does not
        # permanently lock out the height.
        good_ts = prev.header.timestamp + BLOCK_TIME_TARGET + 1  # round 0
        try:
            blk = consensus.create_block(
                self.proposer, [], prev, timestamp=good_ts,
            )
        except HeightAlreadySignedError as e:
            self.fail(
                f"Legitimate retry refused — floor was poisoned by the "
                f"earlier rejection: {e}"
            )
        self.assertEqual(blk.header.block_number, new_height)
        # Now the floor SHOULD have advanced (the second attempt actually signed).
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            new_height,
        )

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
        # In-cap on the round formula so future-drift is the binding
        # rule (round_number = 0 if ts_gap is BLOCK_TIME_TARGET).  Then
        # push the timestamp way past now + MAX_BLOCK_FUTURE_DRIFT.
        bad_ts = _time.time() + MAX_BLOCK_FUTURE_DRIFT * 1000
        prior_floor = self.proposer.height_sign_guard.last_block_signed
        with self.assertRaises(ProposerSkipSlotError) as cm:
            consensus.create_block(
                self.proposer, [], prev, timestamp=bad_ts,
            )
        # Either the round-cap or the future-drift rule may fire first
        # depending on exactly how far in the future ``bad_ts`` is.
        # Both are valid pre-sign rejections; assert we got SOME
        # ProposerSkipSlotError and the floor is preserved.
        self.assertTrue(
            "future" in str(cm.exception).lower()
            or "cap" in str(cm.exception).lower(),
            f"expected future-drift or cap rejection, got: {cm.exception}",
        )
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            prior_floor,
        )


if __name__ == "__main__":
    unittest.main()
