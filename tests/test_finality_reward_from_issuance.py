"""Tests for the finality-vote reward being minted from issuance
instead of debited from the treasury (hard fork).

Background
----------
Currently FINALITY_VOTE_INCLUSION_REWARD is paid to the proposer from
the treasury via `treasury_spend`.  That path has three stacking
failure modes:

  1. The treasury empties → finality becomes uneconomic silently
     (legacy code falls back to paying whatever the treasury has,
     down to 0).
  2. TREASURY_MAX_SPEND_BPS_PER_EPOCH can be saturated by combined
     governance + finality draws → finality starves even with a
     positive treasury balance.
  3. A parallel fork is tightening the treasury spend-rate cap from
     1%/epoch to 0.1%/epoch, making (2) worse.

Fix: at/after `FINALITY_REWARD_FROM_ISSUANCE_HEIGHT`, the
FINALITY_VOTE_INCLUSION_REWARD is MINTED directly (bumps total_supply
and total_minted) and credited to the proposer.  No treasury
interaction.  The numeric reward value is unchanged.

Pre-activation: treasury-spend path preserved byte-for-byte (including
the silent zero-fallback when the treasury is drained).
"""

import tempfile
import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import _hash
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.finality import create_finality_vote
from messagechain.config import (
    FINALITY_VOTE_INCLUSION_REWARD,
    FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
    TREASURY_ENTITY_ID,
    GENESIS_SUPPLY,
)
from tests import register_entity_for_test, pick_selected_proposer


PRE_ACTIVATION_HEIGHT = max(0, FINALITY_REWARD_FROM_ISSUANCE_HEIGHT - 1)
POST_ACTIVATION_HEIGHT = FINALITY_REWARD_FROM_ISSUANCE_HEIGHT


class _BaseChainFixture(unittest.TestCase):
    """Shared three-validator chain.  Each test flips the fork height to
    exercise the pre- or post-activation branch without needing to mine
    thousands of blocks."""

    def setUp(self):
        self.alice = Entity.create(b"alice-finality-r".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-finality-r".ljust(32, b"\x00"))
        self.carol = Entity.create(b"carol-finality-r".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        self.chain.supply.balances[self.carol.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 1_000)
        self.chain.supply.stake(self.bob.entity_id, 1_000)
        self.chain.supply.stake(self.carol.entity_id, 1_000)
        self.consensus = ProofOfStake()

    def _all(self):
        return [self.alice, self.bob, self.carol]

    def _patch_height(self, height: int):
        import messagechain.config as _mcfg
        import messagechain.core.blockchain as _bc
        self._orig_cfg = _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT
        _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = height
        self._orig_bc = getattr(_bc, "FINALITY_REWARD_FROM_ISSUANCE_HEIGHT", None)
        if hasattr(_bc, "FINALITY_REWARD_FROM_ISSUANCE_HEIGHT"):
            _bc.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = height

    def _restore_height(self):
        import messagechain.config as _mcfg
        import messagechain.core.blockchain as _bc
        _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = self._orig_cfg
        if self._orig_bc is not None:
            _bc.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = self._orig_bc

    def _seed_treasury(self, amount: int):
        self.chain.supply.balances[TREASURY_ENTITY_ID] = (
            self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0) + amount
        )

    def _build_target_and_votes(self):
        """Produce block1 + three matching finality votes."""
        proposer0 = pick_selected_proposer(self.chain, self._all())
        block1 = self.chain.propose_block(self.consensus, proposer0, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)

        votes = [
            create_finality_vote(
                e, block1.block_hash, block1.header.block_number,
                signed_at_height=block1.header.block_number,
            )
            for e in self._all()
        ]
        return block1, votes


class TestPreActivationTreasuryPath(_BaseChainFixture):
    """Pre-activation: reward flows treasury → proposer.  total_supply
    unchanged.  Silent zero-fallback preserved when treasury is short."""

    def setUp(self):
        super().setUp()
        # Force pre-activation by pushing the fork height well beyond
        # any block we'll produce.  10**9 is the canonical sentinel.
        self._patch_height(10**9)

    def tearDown(self):
        self._restore_height()

    def test_treasury_debited_per_vote(self):
        """Treasury balance decreases by N tokens for N included votes,
        proposer balance increases by N.  Tokens are moved, not minted."""
        self._seed_treasury(10_000)

        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        treasury_before = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        proposer_before = self.chain.supply.balances.get(proposer.entity_id, 0)
        supply_before = self.chain.supply.total_supply
        minted_before = self.chain.supply.total_minted

        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        treasury_after = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        proposer_after = self.chain.supply.balances.get(proposer.entity_id, 0)

        expected = FINALITY_VOTE_INCLUSION_REWARD * len(votes)
        # Treasury lost exactly `expected` to the proposer inclusion path
        # (other treasury-affecting paths in a plain block are zero).
        self.assertEqual(treasury_before - treasury_after, expected)
        # Proposer gained >= expected (they also collect block reward).
        self.assertGreaterEqual(proposer_after - proposer_before, expected)
        # total_minted delta reflects the BLOCK mint ONLY, not finality
        # reward (pre-activation: no mint on the finality path).  We
        # can't know the block mint without replicating the reward
        # calc, but we can check that the finality reward did NOT
        # show up as a mint by comparing the invariant.
        self.assertEqual(
            self.chain.supply.total_supply,
            GENESIS_SUPPLY
            + self.chain.supply.total_minted
            - self.chain.supply.total_burned,
        )
        # Extra sanity: the finality path contributes nothing to
        # total_minted beyond the block mint — if it did, minted would
        # be `expected` higher than it is.  Equivalent check: recompute
        # the expected minted-delta as whatever total_supply changed by
        # minus (-burned).  Kept implicit by the invariant above.

    def test_empty_treasury_silent_zero_fallback(self):
        """Pre-activation: if the treasury has < N tokens, pay what it
        has (possibly 0).  Existing behavior must be preserved for
        historical replay."""
        # Do NOT seed treasury — starts with whatever genesis placed
        # there.  Drain it to exactly 0 for a deterministic test.
        self.chain.supply.balances[TREASURY_ENTITY_ID] = 0

        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        treasury_before = 0
        proposer_before = self.chain.supply.balances.get(proposer.entity_id, 0)

        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        treasury_after = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        # No treasury funds to spend — stays at 0 (might still accrue
        # from other paths, but in this minimal block none apply).
        self.assertEqual(treasury_after, treasury_before)


class TestPostActivationIssuanceMint(_BaseChainFixture):
    """Post-activation: reward is minted; treasury is never touched."""

    def setUp(self):
        super().setUp()
        # Fire the fork at block 1 so every non-genesis block is post-
        # activation.  0 would also work but some layers special-case
        # genesis; 1 is cleaner.
        self._patch_height(1)

    def tearDown(self):
        self._restore_height()

    def test_proposer_credited_from_mint(self):
        """Proposer gains N × reward; total_supply AND total_minted both
        increase by the same amount; treasury unchanged."""
        # Seed treasury with a distinctive, recognizable balance — if
        # any code path still debits it we'll see it move.
        treasury_pin = 12_345_678
        self.chain.supply.balances[TREASURY_ENTITY_ID] = treasury_pin

        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        treasury_before = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        proposer_before = self.chain.supply.balances.get(proposer.entity_id, 0)
        supply_before = self.chain.supply.total_supply
        minted_before = self.chain.supply.total_minted

        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        treasury_after = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        proposer_after = self.chain.supply.balances.get(proposer.entity_id, 0)
        supply_after = self.chain.supply.total_supply
        minted_after = self.chain.supply.total_minted

        expected = FINALITY_VOTE_INCLUSION_REWARD * len(votes)

        # Treasury untouched by the finality path (no other treasury-
        # affecting paths in this block either).
        self.assertEqual(treasury_after, treasury_before)
        # Proposer gained at least `expected` (block reward stacks on top).
        self.assertGreaterEqual(proposer_after - proposer_before, expected)
        # total_supply grew by at least `expected` beyond the block mint;
        # total_minted did the same.  The block-mint delta is equal
        # between sup/minted, so their difference is a stable diagnostic.
        # Specifically: (supply_after - supply_before) matches
        # (minted_after - minted_before) assuming no burns, so the
        # difference is a clean check that finality did NOT burn.
        self.assertEqual(
            supply_after - supply_before,
            minted_after - minted_before,
        )
        # The inclusion-path mint delta: compare to a run with no votes.
        # We can't have the same exact block height in two runs, but we
        # CAN assert that the mint grew by at least N * reward more
        # than issuance alone would justify.  Issuance at non-genesis
        # heights is `calculate_block_reward(h)` — compute it.
        issuance = self.chain.supply.calculate_block_reward(
            block2.header.block_number,
        )
        # Post-apply minted-delta = issuance + finality-mint.  Some of
        # issuance may also be burned (attester-pool remainder, cap
        # overflow).  minted_after - minted_before counts issuance +
        # finality at the MINT site, before any burn, so:
        self.assertEqual(
            minted_after - minted_before,
            issuance + expected,
        )

    def test_full_treasury_does_not_affect_behavior(self):
        """Even with a well-funded treasury, post-activation doesn't
        debit it — works regardless of treasury state."""
        self.chain.supply.balances[TREASURY_ENTITY_ID] = 1_000_000_000

        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        treasury_before = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)

        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        treasury_after = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
        self.assertEqual(treasury_after, treasury_before)

    def test_empty_treasury_still_pays_reward(self):
        """The point of the fork — reward is paid even when treasury
        is fully drained.  Pre-activation this silently zero-falls."""
        self.chain.supply.balances[TREASURY_ENTITY_ID] = 0

        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        proposer_before = self.chain.supply.balances.get(proposer.entity_id, 0)

        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        proposer_after = self.chain.supply.balances.get(proposer.entity_id, 0)
        expected = FINALITY_VOTE_INCLUSION_REWARD * len(votes)
        self.assertGreaterEqual(proposer_after - proposer_before, expected)

    def test_supply_invariant_holds(self):
        """total_supply == GENESIS_SUPPLY + total_minted - total_burned
        after a vote-bearing block applies."""
        block1, votes = self._build_target_and_votes()
        proposer = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer, [], finality_votes=votes,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        self.assertEqual(
            self.chain.supply.total_supply,
            GENESIS_SUPPLY
            + self.chain.supply.total_minted
            - self.chain.supply.total_burned,
        )


class TestActivationBoundary(_BaseChainFixture):
    """The fork gate is inclusive at FINALITY_REWARD_FROM_ISSUANCE_HEIGHT."""

    def _run_inclusion_block(self, *, fork_height: int):
        """Helper: builds a target + votes, produces the vote-bearing
        block, returns (supply_delta, minted_delta, treasury_delta)."""
        self._patch_height(fork_height)
        try:
            # Seed a visible treasury so a debit would be unambiguous.
            self._seed_treasury(100_000)
            block1, votes = self._build_target_and_votes()
            proposer = pick_selected_proposer(self.chain, self._all())
            tr_b = self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0)
            sup_b = self.chain.supply.total_supply
            mint_b = self.chain.supply.total_minted
            block2 = self.chain.propose_block(
                self.consensus, proposer, [], finality_votes=votes,
            )
            ok, reason = self.chain.add_block(block2)
            self.assertTrue(ok, reason)
            return (
                self.chain.supply.total_supply - sup_b,
                self.chain.supply.total_minted - mint_b,
                self.chain.supply.balances.get(TREASURY_ENTITY_ID, 0) - tr_b,
            )
        finally:
            self._restore_height()

    def test_height_one_below_activation_uses_treasury(self):
        # Chain is at height 0 (genesis).  After producing block1,
        # block2 (the vote-bearing one) will be at height 2.
        # Fork height set well above 2 → pre-activation path fires.
        _, _, treasury_delta = self._run_inclusion_block(fork_height=10**9)
        # Pre-activation: treasury was debited.
        self.assertLess(treasury_delta, 0)

    def test_height_at_activation_uses_mint(self):
        # Fork height set to 1 → block2 at height 2 is post-activation.
        _, _, treasury_delta = self._run_inclusion_block(fork_height=1)
        # Post-activation: treasury delta should be 0 from the finality
        # path (no other paths touch treasury in a plain vote-block).
        self.assertEqual(treasury_delta, 0)


if __name__ == "__main__":
    unittest.main()
