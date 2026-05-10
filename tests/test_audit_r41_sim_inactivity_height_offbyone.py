"""sim's apply_inactivity_leak call MUST use block_height, not
self.height + 1.

Audit r41 #4 root cause -- the ACTUAL trigger for the 2026-05-10
mainnet stall.  Surfaced after 1.70.2 / 1.70.3 / 1.70.4 / 1.70.5 all
shipped clean but the chain still wedged at block #2199.  In-process
diag4 dump on validator-2 (the proposer for the stuck slot) confirmed
sim_staked[inactive_validator] diverged from apply's
self.supply.staked[inactive_validator] by a small non-zero delta on
an EMPTY block (no txs of any kind, no slash, no committee).

Root cause: ``compute_post_state_root`` builds the sim path's
inactivity-leak call with::

    _ail(sim_staked, sim_blocks_since_fin, _inactive,
         min_stake=VALIDATOR_MIN_STAKE,
         current_height=self.height + 1,    # <-- OFF BY ONE
         blockchain=self)

while apply (``_apply_block_state``) builds it with::

    apply_inactivity_leak(
        self.supply.staked, self.blocks_since_last_finalization,
        inactive,
        min_stake=VALIDATOR_MIN_STAKE,
        current_height=block.header.block_number,
        blockchain=self,
    )

Since the chain has exactly ``self.height`` blocks indexed
0..(height-1) BEFORE the new block is appended, the new block's
number IS ``self.height``, NOT ``self.height + 1``.  Equivalently:
``block.header.block_number == self.height`` at the moment sim or
apply runs.  Sim's ``self.height + 1`` is therefore one greater
than apply's value.

The bug fires EXACTLY at Tier-N activation boundaries.  On a block
proposed at the activation height itself:

  * apply computes ``current_height = block.header.block_number =
    activation - 1`` and takes the pre-fork branch (legacy formula).
  * sim computes ``current_height = self.height + 1 = activation``
    and takes the post-fork branch (new formula).

When the new formula produces a different per-validator penalty
than the legacy formula, sim and apply diverge on
``staked[inactive_validator]`` -> different state-tree leaf hashes
-> ``Invalid state_root -- state commitment mismatch`` rejection ->
chain wedges with no honest path forward.

Concrete bite at h=2199 mainnet:

  * Tier 59 (``INACTIVITY_LEAK_STAKE_SCALED_HEIGHT = 2200``) flips
    the inactivity-leak formula from legacy
    ``BASE * blocks² / QUOTIENT`` (stake-independent, floors to 0
    at every realistic stall length) to stake-scaled
    ``stake * BASE * blocks² / QUOTIENT_STAKE_SCALED`` (non-zero
    even for short stalls).
  * h=2199 block: apply uses ``current_height=2199`` (pre-Tier-59,
    legacy formula, penalty=0, no mutation).  Sim uses
    ``current_height=2200`` (Tier-59 ACTIVE, stake-scaled formula,
    non-zero penalty, mutates ``sim_staked[inactive]``).
  * The proposer of the block is in the inactive set (no
    attestations from the proposer to their OWN block, which is the
    canonical case in any low-attestation network), so the
    divergence bites on every empty/quiet block at the activation
    height.

CLAUDE.md anchor at risk: Mission ("permanent ledger"); honest-
operator insurance.  This is the same defect class the earlier
1.70.3 (proposer_sig_counts deferral) and 1.70.4
(slash_offense_counts deferral) closed -- a sim-vs-apply divergence
on the inactivity-leak path -- but those fixes addressed the
HONESTY-CURVE-RELIEF-MULTIPLIER INPUTS while this fix addresses the
HEIGHT GATE itself.

Fix: change sim's
``current_height=self.height + 1`` to
``current_height=block_height``.  ``block_height`` is already in
scope as the parameter passed to ``compute_post_state_root``.  Same
value apply uses.

These tests pin the invariant.
"""

from __future__ import annotations

import inspect
import unittest

from messagechain.core import blockchain as blockchain_mod


class TestSimInactivityLeakHeightArg(unittest.TestCase):
    """The sim path's apply_inactivity_leak call MUST use
    ``current_height=block_height``, not ``self.height + 1``.
    """

    def test_sim_apply_inactivity_leak_uses_block_height(self):
        src = inspect.getsource(
            blockchain_mod.Blockchain.compute_post_state_root,
        )
        # Find the _ail() / apply_inactivity_leak() call in the sim
        # body and inspect its current_height kwarg.
        # The call shape is:
        #   _ail(sim_staked, sim_blocks_since_fin, _inactive,
        #        min_stake=VALIDATOR_MIN_STAKE,
        #        current_height=block_height,    # <-- this is what we pin
        #        blockchain=self)
        call_idx = src.find("_ail(")
        if call_idx < 0:
            call_idx = src.find("apply_inactivity_leak(")
        self.assertGreater(
            call_idx, 0,
            "can't find apply_inactivity_leak / _ail call in "
            "compute_post_state_root -- either the call site moved "
            "or the alias drifted",
        )
        # Slice out the call args (next ~600 chars from the call
        # site).  This captures the keyword args including
        # current_height.
        call_slice = src[call_idx:call_idx + 600]
        self.assertIn(
            "current_height=block_height",
            call_slice,
            "sim's apply_inactivity_leak call MUST use "
            "current_height=block_height (audit r41 #4).  Pre-fix "
            "this was self.height + 1, which is off by one and "
            "causes sim to take the post-fork branch of "
            "compute_inactivity_penalty at the activation block "
            "while apply correctly takes the pre-fork branch -- "
            "different per-validator penalty, different "
            "sim_staked[inactive], different state_root, chain "
            "wedges.",
        )
        self.assertNotIn(
            "current_height=self.height + 1",
            call_slice,
            "sim's apply_inactivity_leak call MUST NOT use "
            "current_height=self.height + 1 (the legacy buggy "
            "shape).  Use current_height=block_height instead.",
        )

    def test_apply_inactivity_leak_uses_block_header_block_number(self):
        """Companion guard: the apply-side call must continue to use
        ``block.header.block_number`` so sim and apply pass the SAME
        height to the helper.  Any change to apply's height arg here
        must also flip sim's, or the divergence returns.
        """
        src = inspect.getsource(
            blockchain_mod.Blockchain._apply_block_state,
        )
        call_idx = src.find("apply_inactivity_leak(")
        self.assertGreater(
            call_idx, 0,
            "can't find apply_inactivity_leak call in _apply_block_state",
        )
        call_slice = src[call_idx:call_idx + 600]
        self.assertIn(
            "current_height=block.header.block_number",
            call_slice,
            "_apply_block_state's apply_inactivity_leak call MUST "
            "use current_height=block.header.block_number.  If this "
            "changes, sim's call must change in lockstep or audit "
            "r41 #4 regresses.",
        )

    def test_no_offbyone_height_in_compute_post_state_root_leak_path(
        self,
    ):
        """Belt-and-suspenders: the literal string
        ``self.height + 1`` MUST NOT appear in the sim's inactivity-
        leak call block.  Catches partial reverts where someone
        adds ``current_height=self.height + 1`` back without
        removing the corrected version.
        """
        src = inspect.getsource(
            blockchain_mod.Blockchain.compute_post_state_root,
        )
        # Find the inactivity-leak code block (a few hundred chars
        # bracketing the _ail call) and confirm self.height + 1 is
        # not used as a height argument anywhere in it.
        anchor = "is_leak_active"
        idx = src.find(anchor)
        self.assertGreater(idx, 0, "can't find is_leak_active anchor")
        # Window: from is_leak_active to ~1000 chars after (covers
        # the leak block, including the _ail call args and trailing
        # close).
        window = src[idx:idx + 1000]
        # The phrase "self.height + 1 by the time" appears in the
        # explanatory comment on the OLD code path -- we want to
        # ensure the comment is also updated.  Either the legacy
        # phrase is gone OR it appears inside a comment that
        # explicitly references the bug fix.  Simplest pin: the
        # literal current_height=self.height + 1 token sequence
        # must NOT appear in this window.
        self.assertNotIn(
            "current_height=self.height + 1",
            window,
            "sim's inactivity-leak block must NOT use "
            "current_height=self.height + 1 (audit r41 #4 "
            "regression).",
        )


if __name__ == "__main__":
    unittest.main()
