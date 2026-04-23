"""Block-apply ordering invariants (lock current behavior).

Several hard forks share activation height 50_000:
  * FINALITY_REWARD_FROM_ISSUANCE_HEIGHT — finality votes switch from
    treasury draw to direct mint.
  * TREASURY_REBASE_HEIGHT — 33M burned from treasury at activation.
  * ATTESTER_FEE_FUNDING_HEIGHT — attester pool redirect.
  * FEE_INCLUDES_SIGNATURE_HEIGHT — fee min includes signature bytes.

At activation block(s), several apply-side steps run in a specific
order, and a block that crosses multiple thresholds simultaneously
exercises all of them in a single sequence.  Getting the order wrong
leaks supply invariants silently (treasury empties in the wrong order,
finality mint sees a stale balance, etc).

This file locks the shipped ordering so future refactors cannot
silently drift.  Invariants under test:

  1. Treasury rebase runs AFTER seed divestment in the same block.
     A same-block divestment step that routes treasury_share into the
     treasury does so BEFORE the burn, so the burn sees the post-
     divestment treasury balance.
  2. Finality votes: post-FINALITY_REWARD_FROM_ISSUANCE_HEIGHT the
     mint is treasury-independent, so rebase ordering is MOOT with
     respect to finality votes — even if treasury is empty the
     proposer still gets credited.  Locked via direct apply path.
  3. Attester fee-funding: `fee_burn_this_block` is reset at the
     START of every block-apply, and `attester_fee_pool_this_block`
     likewise.  Neither leaks across block boundaries.

We do NOT re-derive the canonical ordering by experiment here; we
inspect the shipped `_apply_block_state` source for the key anchors
(treasury rebase vs seed divestment, reset of per-block accumulators)
and assert the relative sequence via static source inspection PLUS
dynamic behavior where feasible.  Static checks guarantee the file
flips red if a future refactor moves the calls.
"""

from __future__ import annotations

import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import messagechain.config as config
from messagechain.consensus.finality import FinalityVote
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


class TestApplyOrderingStaticAnchors(unittest.TestCase):
    """Lock the relative order of key apply steps via source inspection.

    Inspecting source is load-bearing because the order is a
    correctness property, not a behavior property — two orderings can
    produce byte-identical output today under narrow inputs but diverge
    later when one of the steps grows a dependency on the other.  The
    static check catches refactors immediately rather than waiting for
    a rare input pattern to surface the bug.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = inspect.getsource(Blockchain._apply_block_state)

    def _index_of(self, needle: str) -> int:
        idx = self.source.find(needle)
        if idx < 0:
            raise AssertionError(
                f"Expected anchor not found in _apply_block_state: {needle!r}"
            )
        return idx

    def test_treasury_rebase_after_seed_divestment(self):
        """Invariant #1: _apply_treasury_rebase runs AFTER
        _apply_seed_divestment in the same block.

        Divestment routes treasury_bps share into the treasury.  If
        the rebase ran first, the 33M burn would see the pre-
        divestment balance (40M), burn 33M, leave 7M — then
        divestment would add its share ON TOP, inflating the post-
        rebase treasury beyond the intended 7M.  Running divestment
        first makes the burn see the post-divestment balance, which
        is the documented behavior.
        """
        divest_idx = self._index_of("self._apply_seed_divestment(")
        rebase_idx = self._index_of("self._apply_treasury_rebase(")
        self.assertLess(
            divest_idx, rebase_idx,
            "seed divestment must run BEFORE treasury rebase",
        )

    def test_fee_burn_reset_at_start_of_apply(self):
        """Invariant #3a: `fee_burn_this_block` is reset at the START
        of _apply_block_state (BEFORE any tx-fee burn accumulates).

        If the reset ran AFTER tx-fee payment, the archive-redirect
        path would see a stale previous-block value and misattribute
        burn tokens.
        """
        reset_idx = self._index_of("self.supply.fee_burn_this_block = 0")
        # First mutation after the reset should be tx-fee burns.
        first_tx_loop_idx = self._index_of("for tx in block.transactions:")
        self.assertLess(
            reset_idx, first_tx_loop_idx,
            "fee_burn_this_block must reset BEFORE tx fees accumulate",
        )

    def test_attester_fee_pool_reset_at_start_of_apply(self):
        """Invariant #3b: `attester_fee_pool_this_block` is reset at
        the START of _apply_block_state for the same reason as
        fee_burn_this_block — no cross-block leakage.
        """
        reset_idx = self._index_of(
            "self.supply.attester_fee_pool_this_block = 0",
        )
        first_tx_loop_idx = self._index_of("for tx in block.transactions:")
        self.assertLess(
            reset_idx, first_tx_loop_idx,
            "attester_fee_pool_this_block must reset BEFORE tx fees "
            "accumulate",
        )

    def test_mint_block_reward_after_tx_fees(self):
        """Invariant #3c: mint_block_reward runs AFTER fee accumulation
        so the attester-pool-from-fee redirect captures this block's
        fees before the committee is paid.
        """
        first_tx_loop_idx = self._index_of("for tx in block.transactions:")
        mint_idx = self._index_of("self.supply.mint_block_reward(")
        self.assertLess(
            first_tx_loop_idx, mint_idx,
            "tx-fee accumulation must run BEFORE mint_block_reward so "
            "attester-pool redirect captures this block's fees",
        )

    def test_archive_rewards_after_mint(self):
        """Archive-rewards step runs AFTER mint_block_reward.

        The archive-reward pool captures fee_burn_this_block AFTER
        fees have accumulated AND after the attester redirect has
        consumed its share in mint_block_reward.  Running archive
        rewards first would double-count.
        """
        mint_idx = self._index_of("self.supply.mint_block_reward(")
        archive_idx = self._index_of("self._apply_archive_rewards(")
        self.assertLess(mint_idx, archive_idx)

    def test_finality_votes_after_mint(self):
        """Finality votes apply AFTER mint_block_reward.

        Under the post-FINALITY_REWARD_FROM_ISSUANCE_HEIGHT fork the
        finality mint is independent of treasury balance, but the
        proposer's reward-from-mint lands first; a future refactor
        that folded finality minting INTO mint_block_reward must not
        silently reorder the two.  Lock the current sequence.
        """
        mint_idx = self._index_of("self.supply.mint_block_reward(")
        finality_idx = self._index_of("self._apply_finality_votes(")
        self.assertLess(mint_idx, finality_idx)


class TestFinalityMintIndependentOfTreasury(unittest.TestCase):
    """Dynamic lock: post-activation finality mint ignores treasury state.

    The post-FINALITY_REWARD_FROM_ISSUANCE_HEIGHT fork removed the
    treasury dependency.  Lock this by running the apply path with an
    EMPTY treasury and asserting the proposer still gets credited.
    This is the key guarantee that makes the "rebase vs finality"
    ordering question moot post-activation — whichever runs first,
    the proposer gets paid from direct issuance.
    """

    def setUp(self):
        self.alice = Entity.create(b"order-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"order-bob".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        self.chain.public_keys[self.bob.entity_id] = self.bob.public_key
        # Drain the treasury entirely.  The mint path must not care.
        from messagechain.config import TREASURY_ENTITY_ID
        self.chain.supply.balances[TREASURY_ENTITY_ID] = 0

    def test_empty_treasury_does_not_block_finality_mint(self):
        post_activation_h = config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT + 1
        vote = FinalityVote(
            signer_entity_id=self.bob.entity_id,
            target_block_hash=b"\x22" * 32,
            target_block_number=1,
            signature=Signature([], 0, [], b"", b""),
        )
        fake = SimpleNamespace(
            finality_votes=[vote],
            header=SimpleNamespace(block_number=post_activation_h),
        )
        alice_before = self.chain.supply.balances.get(self.alice.entity_id, 0)
        minted_before = self.chain.supply.total_minted
        self.chain._apply_finality_votes(fake, self.alice.entity_id)
        self.assertEqual(
            self.chain.supply.balances.get(self.alice.entity_id, 0)
            - alice_before,
            config.FINALITY_VOTE_INCLUSION_REWARD,
            "post-activation finality mint must pay proposer even with "
            "empty treasury",
        )
        self.assertEqual(
            self.chain.supply.total_minted - minted_before,
            config.FINALITY_VOTE_INCLUSION_REWARD,
        )


class TestAttesterFeePoolResetBetweenBlocks(unittest.TestCase):
    """Dynamic lock: per-block fee accumulators do not leak.

    Set `fee_burn_this_block` and `attester_fee_pool_this_block` to
    sentinel non-zero values, then invoke the apply-path reset logic
    (which runs at the very top of _apply_block_state).  We can't
    easily drive a full block through the pipeline without considerable
    scaffolding, but we can lock the behavior by checking the
    attribute-reset anchor runs before any tx loop: that's the
    static invariant already covered above.  Here we complement it
    by verifying the SupplyTracker holds the attributes (so a
    refactor that removes them must break this test, not silently
    drop a reset).
    """

    def test_supply_tracker_exposes_per_block_accumulators(self):
        from messagechain.economics.inflation import SupplyTracker
        s = SupplyTracker()
        self.assertTrue(
            hasattr(s, "fee_burn_this_block"),
            "SupplyTracker must expose fee_burn_this_block for "
            "per-block reset to target",
        )
        self.assertTrue(
            hasattr(s, "attester_fee_pool_this_block"),
            "SupplyTracker must expose attester_fee_pool_this_block",
        )
        # Fresh tracker initializes both accumulators to 0.  If a
        # refactor renames or removes them, this test fires first.
        self.assertEqual(s.fee_burn_this_block, 0)
        self.assertEqual(s.attester_fee_pool_this_block, 0)


class TestActivationHeightOrdering(unittest.TestCase):
    """Canonical fork-schedule ordering (see CLAUDE.md fork table).

    Every inter-fork dependency must hold; a drift here means the
    deployed schedule breaks an economic invariant the code relies on.
    """

    def test_finality_cap_activates_before_direct_mint(self):
        """The defensive per-block finality-vote mint cap MUST activate
        BEFORE the direct-mint path goes live — any window where mint
        runs without the cap is an uncapped-issuance failure under
        validation drift (exactly the hazard the cap was created for).
        """
        self.assertLess(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        )

    def test_attester_reward_ordering(self):
        """Cap-fix follows cap; cap follows pro-rata split + fee-funding."""
        self.assertLess(
            config.ATTESTER_REWARD_SPLIT_HEIGHT,
            config.ATTESTER_REWARD_CAP_HEIGHT,
        )
        self.assertLess(
            config.ATTESTER_FEE_FUNDING_HEIGHT,
            config.ATTESTER_REWARD_CAP_HEIGHT,
        )
        self.assertLess(
            config.ATTESTER_REWARD_CAP_HEIGHT,
            config.ATTESTER_CAP_FIX_HEIGHT,
        )

    def test_divestment_ordering(self):
        """REDIST extends RETUNE; ordering is monotonic."""
        self.assertLessEqual(
            config.SEED_DIVESTMENT_RETUNE_HEIGHT,
            config.SEED_DIVESTMENT_REDIST_HEIGHT,
        )

    def test_deflation_floor_v2_supersedes_v1(self):
        self.assertLess(
            config.DEFLATION_FLOOR_HEIGHT,
            config.DEFLATION_FLOOR_V2_HEIGHT,
        )

    def test_registration_burn_follows_min_stake_raise(self):
        self.assertLess(
            config.MIN_STAKE_RAISE_HEIGHT,
            config.VALIDATOR_REGISTRATION_BURN_HEIGHT,
        )

    def test_flat_fee_follows_sig_aware_fee(self):
        self.assertLess(
            config.FEE_INCLUDES_SIGNATURE_HEIGHT,
            config.FLAT_FEE_HEIGHT,
        )


if __name__ == "__main__":
    unittest.main()
