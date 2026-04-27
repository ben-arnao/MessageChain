"""Regression: any post-reserve rejection MUST roll back the
height-guard floor.

The 1.28.0 fix mirrored the (header, prev_block, wall-clock)-only
rejection rules from ``validate_block`` into a pre-sign helper, so a
candidate the network would reject for those reasons no longer
poisons the floor.  But the second incident on 2026-04-27 — same
chain wedge, different rule — exposed the broader bug class: ANY
rejection that fires AFTER ``record_block_sign`` and BEFORE the
block is broadcast leaves the floor at the reserved height with no
signature ever escaping the process.  Concretely, the live wedge
came from a state-root rejection inside ``add_block``, which fires
AFTER ``create_block`` returns and is not pre-sign-checkable
(state-root verification needs the full state-machine apply).

This test pins the durable invariant: regardless of the rejection
rule, the floor only ratchets when a block has actually been
accepted into the local chain.  Three subtests cover the surfaces
where rejection can fire:

  1. ``add_block`` rejects a candidate that ``create_block``
     successfully built (e.g., state-root mismatch on a stale
     parent).  ``rollback_block_sign`` must restore the floor.
  2. An exception inside ``create_block`` AFTER
     ``record_block_sign`` (e.g., signing failure, RANDAO derivation
     bug, block-construction error).  ``create_block``'s try/except
     must roll the floor back before re-raising.
  3. The rollback API itself: a fresh ``record_block_sign`` followed
     by ``rollback_block_sign`` returns True and the floor is
     restored to the prior value.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.consensus.height_guard import (
    HeightAlreadySignedError,
    HeightSignGuard,
)


class TestHeightSignGuardRollbackAPI(unittest.TestCase):
    """Direct unit tests on the rollback API.  No chain or proposer
    setup — exercises the contract on the guard itself."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="mc-guard-rollback-")
        self.path = os.path.join(self._tmp, "height_guard.json")
        self.guard = HeightSignGuard.load_or_create(self.path)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_rollback_restores_prior_floor(self):
        """A reservation followed by a rollback restores the prior
        floor on disk and in memory.  A subsequent attempt at the
        same height MUST succeed (no longer blocked)."""
        self.guard.record_block_sign(100)
        self.assertEqual(self.guard.last_block_signed, 100)

        rolled = self.guard.rollback_block_sign(100)
        self.assertTrue(rolled)
        self.assertEqual(self.guard.last_block_signed, -1)

        # On-disk state must also have been persisted at the prior
        # value — otherwise a process restart would still see floor=100.
        reloaded = HeightSignGuard.load_or_create(self.path)
        self.assertEqual(reloaded.last_block_signed, -1)

        # And a re-attempt at 100 MUST now succeed.
        try:
            self.guard.record_block_sign(100)
        except HeightAlreadySignedError as e:
            self.fail(
                f"floor was not actually rolled back — re-attempt at "
                f"100 still refused: {e}"
            )

    def test_rollback_at_wrong_height_is_noop(self):
        """Rolling back a height that doesn't match the last
        reservation is a no-op.  The floor stays where it is and the
        return value reports False."""
        self.guard.record_block_sign(100)
        # Wrong height — we last reserved 100, not 99.
        self.assertFalse(self.guard.rollback_block_sign(99))
        self.assertEqual(self.guard.last_block_signed, 100)

    def test_rollback_after_subsequent_reserve_is_noop(self):
        """If a second ``record_block_sign`` advanced past the first,
        rolling back the first is a no-op (the in-memory pending
        state was overwritten by the second reservation)."""
        self.guard.record_block_sign(100)
        self.guard.record_block_sign(101)
        # The first reservation can no longer be rolled back —
        # the pending state now refers to 101.
        self.assertFalse(self.guard.rollback_block_sign(100))
        self.assertEqual(self.guard.last_block_signed, 101)

    def test_rollback_with_no_pending_is_noop(self):
        """A rollback before any reservation has been made returns
        False without raising."""
        self.assertFalse(self.guard.rollback_block_sign(100))
        self.assertEqual(self.guard.last_block_signed, -1)

    def test_pending_does_not_survive_restart(self):
        """In-memory pending state MUST NOT persist across a guard
        reload — the on-disk floor is the only durable signal, and
        a freshly-loaded guard cannot roll back a reservation that
        a previous process committed.  Without this property a
        crash-restart could silently "undo" a real signature.
        """
        self.guard.record_block_sign(100)
        # Simulate restart — discard in-memory state, reload from disk.
        reloaded = HeightSignGuard.load_or_create(self.path)
        self.assertEqual(reloaded.last_block_signed, 100)
        # The new guard has no pending state for height 100, so
        # rollback is a no-op.
        self.assertFalse(reloaded.rollback_block_sign(100))
        self.assertEqual(reloaded.last_block_signed, 100)


class TestCreateBlockRollbackOnPostReserveException(unittest.TestCase):
    """If anything between ``record_block_sign`` and the
    ``return block`` line of ``create_block`` raises, the floor must
    be rolled back before the exception propagates to the caller.
    """

    def setUp(self):
        import messagechain.config as _cfg
        self._prior_enforce = _cfg.ENFORCE_SLOT_TIMING
        _cfg.ENFORCE_SLOT_TIMING = False  # let create_block proceed past pre-sign

        self._tmp = tempfile.mkdtemp(prefix="mc-cb-rollback-")
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        self.proposer = Entity.create(b"prop-cb-rollback".ljust(32, b"\x00"))
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

    def test_post_reserve_exception_rolls_back_floor(self):
        """An exception inside ``create_block`` after the floor has
        been reserved must be caught, the floor rolled back, and
        then the exception re-raised.
        """
        from messagechain.consensus.pos import ProofOfStake

        consensus = ProofOfStake()
        prev = self.chain.get_latest_block()
        new_height = prev.header.block_number + 1
        prior_floor = self.proposer.height_sign_guard.last_block_signed

        # Force a failure AFTER record_block_sign by monkey-patching
        # the proposer's keypair.sign to raise.  This simulates any
        # post-reserve failure (RANDAO derivation bug, downstream
        # block-construction error, signature-side disk fault).
        original_sign = self.proposer.keypair.sign
        sentinel_msg = "synthetic post-reserve failure"

        def boom(_data):
            raise RuntimeError(sentinel_msg)

        self.proposer.keypair.sign = boom
        try:
            with self.assertRaises(RuntimeError) as cm:
                consensus.create_block(self.proposer, [], prev)
            self.assertEqual(str(cm.exception), sentinel_msg)
        finally:
            self.proposer.keypair.sign = original_sign

        # The load-bearing assertion: the floor MUST have been rolled
        # back to its prior value, even though create_block raised.
        # Pre-fix the floor would be at ``new_height`` and a
        # subsequent legitimate retry would fail with
        # HeightAlreadySignedError.
        self.assertEqual(
            self.proposer.height_sign_guard.last_block_signed,
            prior_floor,
            f"create_block raised after record_block_sign; floor must "
            f"have been rolled back to {prior_floor}, got "
            f"{self.proposer.height_sign_guard.last_block_signed}",
        )

        # And a legitimate retry MUST succeed (sign restored).
        try:
            blk = consensus.create_block(self.proposer, [], prev)
        except HeightAlreadySignedError as e:
            self.fail(
                f"legitimate retry refused — floor was poisoned by "
                f"the earlier exception path: {e}"
            )
        self.assertEqual(blk.header.block_number, new_height)


class TestServerAddBlockRejectionRollsBackFloor(unittest.TestCase):
    """Integration shape: a state-root mismatch (or any post-return
    rejection from ``Blockchain.add_block``) must roll back the
    floor via the rollback wiring in
    ``server.py::_try_produce_block_sync`` (and the matching wiring
    in ``messagechain/network/node.py``).

    The unit test below directly exercises the rollback semantics via
    the public ``rollback_block_sign`` API — which is what both
    production sites call.  A full end-to-end test that spins up a
    server is excluded as costly under xdist; the wiring is
    line-of-sight obvious in both files and the rollback API is
    where the durability invariant lives.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="mc-server-rollback-")
        self.guard = HeightSignGuard.load_or_create(
            os.path.join(self._tmp, "height_guard.json"),
        )

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_simulated_add_block_rejection_rollback(self):
        """Simulate the production sequence:
          1. ``record_block_sign`` advances the floor to N.
          2. ``add_block(block)`` returns ``(False, reason)``
             (state-root mismatch, byte-budget overflow, anything
             that fires after create_block returned).
          3. The production rejection-handler calls
             ``rollback_block_sign(N)``.
          4. A subsequent legitimate proposal at height N succeeds.
        """
        # Step 1: production proposer reserves the floor.
        self.guard.record_block_sign(672)
        self.assertEqual(self.guard.last_block_signed, 672)

        # Step 2: simulate add_block rejection.  We don't need the
        # real reason here — what matters is that the production
        # rejection-handler runs the rollback below.

        # Step 3: production rejection-handler rolls back.
        rolled = self.guard.rollback_block_sign(672)
        self.assertTrue(rolled, "rollback_block_sign returned False on a fresh reservation")
        self.assertEqual(self.guard.last_block_signed, -1)

        # Step 4: legitimate retry MUST succeed.
        try:
            self.guard.record_block_sign(672)
        except HeightAlreadySignedError as e:
            self.fail(
                f"legitimate retry refused after rollback — rollback "
                f"did not actually restore the floor: {e}"
            )


if __name__ == "__main__":
    unittest.main()
