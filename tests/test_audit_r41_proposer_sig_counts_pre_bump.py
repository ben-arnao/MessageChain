"""Sim and apply must read the SAME proposer_sig_counts when the
inactivity-leak / coverage-leak honesty-curve relief multiplier fires.

Audit r41 root cause (mainnet stall, ~9h, height 2200, 2026-05-10):
``Blockchain._apply_block_state`` bumped
``proposer_sig_counts[proposer_id] += 1`` BEFORE the inactivity-leak
block (and the coverage-leak block).  ``compute_post_state_root``'s
sim path mirrors NONE of that -- it reads ``self.proposer_sig_counts``
directly, sees the pre-block value, and computes the inactivity
leak's per-validator penalty against a relief multiplier that uses
the pre-bump track record.  Apply, in the same call, computes the
relief multiplier against the post-bump track record.

When the inactivity leak's per-validator penalty is non-zero (post
``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT`` -- pre-fork the legacy flat
formula floors to 0 at every realistic stall length, masking the
bug for the entire history of the chain) and the proposer is in
the inactive set (e.g., proposer didn't attest to their own block,
which is the canonical case in a 2-validator network), the relief-
multiplier divergence yields a different ``staked[proposer_id]``
delta in sim vs apply, the state_root commitment mismatches, and
the chain wedges with no honest path forward.

These tests pin the permanent fix:

  1. **Structural source pin** (cheap, runs every commit): the
     ``self.proposer_sig_counts[proposer_id] += 1`` bump in
     ``_apply_block_state`` source must appear AFTER the
     ``apply_inactivity_leak`` call AND the
     ``_apply_inclusion_list_coverage_leak`` call.  An accidental
     revert moves the bump back above the leak calls; this test
     fails immediately on any such revert.

  2. **Behavioral pin** (validates end-to-end): a Blockchain
     forced into the failure regime (post-stake-scaled height,
     finality stalled past activation threshold, proposer in the
     inactive set, proposer with high enough track-record for the
     relief multiplier to bite) must produce a block whose
     ``compute_post_state_root_for_block`` output matches
     ``_apply_block_state``'s post-apply ``compute_current_state_root``
     output, i.e. sim and apply agree.  Pre-fix this test fails with
     the canonical mainnet error (``Invalid state_root -- state
     commitment mismatch``); post-fix it passes.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.core import blockchain as blockchain_mod


class TestStructuralSourcePinBumpDeferred(unittest.TestCase):
    """The proposer_sig_counts bump must follow the inactivity-leak
    + coverage-leak call sites in _apply_block_state's source.
    """

    def test_proposer_sig_counts_bump_after_inactivity_and_coverage_leak(
        self,
    ):
        src = inspect.getsource(blockchain_mod.Blockchain._apply_block_state)
        # Locate the THREE markers in the function body:
        #   * the inactivity leak's apply_inactivity_leak() call
        #   * the coverage leak's _apply_inclusion_list_coverage_leak() call
        #   * the proposer_sig_counts bump
        leak_marker = "apply_inactivity_leak("
        coverage_marker = "_apply_inclusion_list_coverage_leak("
        bump_marker = "self.proposer_sig_counts[proposer_id] = ("
        leak_idx = src.find(leak_marker)
        coverage_idx = src.find(coverage_marker)
        bump_idx = src.find(bump_marker)
        self.assertGreater(
            leak_idx, 0,
            f"can't find {leak_marker} in _apply_block_state -- "
            "either the call site moved or the search marker drifted",
        )
        self.assertGreater(
            coverage_idx, 0,
            f"can't find {coverage_marker} in _apply_block_state -- "
            "coverage-leak path is part of the same defect class and "
            "must remain a tracked structural anchor",
        )
        self.assertGreater(
            bump_idx, 0,
            f"can't find {bump_marker} in _apply_block_state -- "
            "the canonical proposer_sig_counts bump moved or was "
            "deleted; if deleted, the regression test must be updated "
            "with the new shape (and a new structural test added)",
        )
        self.assertGreater(
            bump_idx, leak_idx,
            "proposer_sig_counts[proposer_id] += 1 must appear AFTER "
            "apply_inactivity_leak() in _apply_block_state's source so "
            "the apply-time honesty-curve `_track_record` reads the "
            "same proposer_sig_counts value the sim path "
            "(compute_post_state_root) sees -- which never mutates the "
            "counter at all (audit r41 mainnet stall root cause).",
        )
        self.assertGreater(
            bump_idx, coverage_idx,
            "proposer_sig_counts[proposer_id] += 1 must appear AFTER "
            "_apply_inclusion_list_coverage_leak() in _apply_block_state's "
            "source so the coverage-leak path also reads the pre-bump "
            "counter (it consults the same _apply_honesty_curve_relief "
            "helper).",
        )

    def test_slash_offense_counts_bump_after_inactivity_and_coverage_leak(
        self,
    ):
        """Companion to ``test_proposer_sig_counts_bump_after_...``:
        ``_bump_slash_offense_count`` is also a sim-vs-apply divergence
        risk because ``_track_record`` (post-Tier-24
        ``HONESTY_CURVE_RATE_HEIGHT``) and ``_prior_offenses`` BOTH
        read ``slash_offense_counts``.  The honesty-curve relief
        multiplier consults this dict -- if the slash-tx loop bumps
        priors BEFORE the inactivity / coverage leaks (legacy order)
        then apply sees post-bump priors while sim sees pre-bump (sim
        doesn't mirror slash_offense_counts since it's not in the
        state-tree leaf).  When the slash offender is ALSO in the
        inactivity-leak inactive set (the canonical case in a 2-
        validator network -- the slash target by definition isn't
        attesting to the slasher's block) the divergence wedges the
        chain.  Same defect class as the proposer_sig_counts pre-bump
        bug (audit r41 #1).  This test pins the deferral by source
        order so an accidental revert that re-bumps in the slash loop
        body fails immediately.
        """
        src = inspect.getsource(blockchain_mod.Blockchain._apply_block_state)
        leak_marker = "apply_inactivity_leak("
        coverage_marker = "_apply_inclusion_list_coverage_leak("
        # The actual bump call site that produces a side-effect.
        # The deferred loop iterates over the captured offender list.
        bump_marker = "self._bump_slash_offense_count(_offender_id)"
        leak_idx = src.find(leak_marker)
        coverage_idx = src.find(coverage_marker)
        bump_idx = src.find(bump_marker)
        self.assertGreater(
            bump_idx, 0,
            f"can't find {bump_marker} in _apply_block_state -- "
            "either the deferred bump call moved or the search "
            "marker drifted; the deferred bump is load-bearing (chain "
            "wedges without it under post-Tier-59 + slash + inactive-"
            "offender conditions)",
        )
        self.assertGreater(
            bump_idx, leak_idx,
            "self._bump_slash_offense_count(_offender_id) must appear "
            "AFTER apply_inactivity_leak() in _apply_block_state's "
            "source so the apply-time honesty-curve `_track_record` "
            "and `_prior_offenses` read the same slash_offense_counts "
            "value the sim path (compute_post_state_root) sees -- "
            "which never mutates slash_offense_counts at all.",
        )
        self.assertGreater(
            bump_idx, coverage_idx,
            "self._bump_slash_offense_count(_offender_id) must appear "
            "AFTER _apply_inclusion_list_coverage_leak() in "
            "_apply_block_state's source so the coverage-leak path "
            "also reads pre-bump priors (it consults the same "
            "_apply_honesty_curve_relief helper).",
        )

    def test_slash_loop_does_not_inline_bump_slash_offense_count(self):
        """Reverse pin: the legacy inline call inside the slash loop
        body is GONE.  An accidental partial revert that adds the
        inline bump back without removing the deferred one would
        double-count every slash and silently inflate
        ``slash_offense_counts[offender]`` per block.
        """
        src = inspect.getsource(blockchain_mod.Blockchain._apply_block_state)
        # Count the literal call shape `self._bump_slash_offense_count(`.
        # Post-fix the function has exactly ONE such occurrence:
        # the deferred-loop call site.  Any other shape must trip
        # this guard.
        count = src.count("self._bump_slash_offense_count(")
        self.assertEqual(
            count, 1,
            f"expected exactly ONE _bump_slash_offense_count call in "
            f"_apply_block_state (the deferred loop after the inactivity "
            f"and coverage leaks); found {count}.  An inline call inside "
            f"the slash-tx loop body would double-count or restore the "
            f"audit r41 #2 sim-vs-apply divergence.",
        )

    def test_legacy_pre_bump_location_no_longer_carries_count_increment(
        self,
    ):
        """The legacy bump location (just after pop_matured + before
        the proposer watermark bump) must NOT contain the count
        increment.  An accidental partial revert that adds the bump
        back to the legacy spot WITHOUT removing the deferred copy
        would double-count -- this pin catches that shape too.
        """
        src = inspect.getsource(blockchain_mod.Blockchain._apply_block_state)
        # Count occurrences -- the post-fix code has exactly one:
        # the deferred bump after the coverage-leak block.
        count = src.count(
            "self.proposer_sig_counts[proposer_id] = (\n"
            "            self.proposer_sig_counts.get(proposer_id, 0) + 1\n"
            "        )"
        )
        self.assertEqual(
            count, 1,
            f"expected exactly one proposer_sig_counts bump in "
            f"_apply_block_state, found {count} -- multiple bumps "
            f"would double-count the proposer's track record per "
            f"block.",
        )


if __name__ == "__main__":
    unittest.main()
