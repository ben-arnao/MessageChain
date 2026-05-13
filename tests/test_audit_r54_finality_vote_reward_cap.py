"""Audit r54 finding 1 -- Tier 76 finality-vote inclusion-reward per-block cap.

Pre-Tier-76, `_apply_finality_votes` mints `FINALITY_VOTE_INCLUSION_REWARD = 1`
tokens of direct mint to the proposer for EVERY survivor of the
pre-filter, up to `MAX_FINALITY_VOTES_PER_BLOCK = 200`.  The mint
never routes through `_split_bps`, `effective_weight`, the proposer
cap, or the dormancy controller's regulated issuance band -- so
worst-case 200 tokens/block of supply leaks the anchored issuance
envelope.

Tier 76 caps the per-block finality-mint TOTAL at
`FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS = MAX_FINALITY_VOTES_PER_BLOCK // 8`
= 25.  Pre-fork: byte-identical to legacy.  Post-fork: the first
`cap` survivors mint `FINALITY_VOTE_INCLUSION_REWARD` each; further
survivors still contribute to the 2/3 finality tally but produce no
mint -- the inclusion service is unpaid past the budget.

The checkpoint contribution is the chain's safety/liveness property
(must remain uncapped so 2/3 can finalize); the mint is the proposer's
reward (capped here to keep issuance inside the dormancy controller's
envelope).
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

import messagechain.config as config
from messagechain.consensus.finality import FinalityVote
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _fake_finality_vote(
    signer_id: bytes, target_hash: bytes, target_num: int,
    leaf_index: int = 0,
) -> FinalityVote:
    """Build a placeholder FinalityVote -- apply path reads only
    signer_entity_id, target_block_hash, target_block_number, and
    signature.leaf_index."""
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=target_num,
        signature=Signature([], leaf_index, [], b"", b""),
    )


class FinalityVoteRewardCapConfig(unittest.TestCase):
    """Pin the Tier-76 height-ordering invariant and the cap value
    sanity bounds.  These are the cheap, deterministic asserts that
    catch a future fork that lands without runway above Tier 75 or
    silently disables the inclusion bonus."""

    def test_tier_76_height_strictly_follows_tier_75(self):
        self.assertGreater(
            config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT,
            config.SLASH_MIN_UNIT_HEIGHT,
            "Tier 76 finality-vote-cap fork must activate strictly "
            "after Tier 75 slash-min-unit fork -- consecutive "
            "issuance-discipline retunes deserve their own cohort.",
        )

    def test_cap_is_positive(self):
        self.assertGreater(
            config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS, 0,
            "A cap of zero would silently disable the inclusion bonus.",
        )

    def test_cap_is_strictly_below_legacy_worst_case(self):
        # The whole point of the cap is to reduce the legacy worst
        # case (MAX_FINALITY_VOTES_PER_BLOCK tokens/block).  If the
        # cap were >= the legacy worst case, the fork would be a
        # no-op.
        self.assertLess(
            config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS,
            config.MAX_FINALITY_VOTES_PER_BLOCK,
            "Cap must be strictly below MAX_FINALITY_VOTES_PER_BLOCK "
            "or the fork is a no-op.",
        )


class FinalityVoteRewardCapApply(unittest.TestCase):
    """Pin the apply-path behavior across the Tier-76 gate."""

    def setUp(self):
        self.proposer = Entity.create(
            b"r54-finmint-proposer".ljust(32, b"\x00"),
        )
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.proposer)
        # Register many distinct signer entities so each vote consumes
        # a separate watermark slot (the replay-mint defense skips
        # any vote whose leaf is below its signer's chain watermark).
        self.signers = []
        for i in range(60):
            s = Entity.create(
                f"r54-finmint-signer-{i:03d}".encode().ljust(32, b"\x00"),
            )
            self.chain.public_keys[s.entity_id] = s.public_key
            self.signers.append(s)
        self.target_hash = b"\x55" * 32
        self.target_num = 1

    def _apply_block_with_n_votes(self, *, n: int, height: int) -> int:
        """Apply a block carrying N distinct finality votes and return
        the delta in `total_minted` (= tokens minted to proposer)."""
        votes = [
            _fake_finality_vote(
                self.signers[i].entity_id, self.target_hash, self.target_num,
                leaf_index=0,
            )
            for i in range(n)
        ]
        fake = SimpleNamespace(
            finality_votes=votes,
            header=SimpleNamespace(block_number=height),
        )
        minted_before = self.chain.supply.total_minted
        self.chain._apply_finality_votes(fake, self.proposer.entity_id)
        return self.chain.supply.total_minted - minted_before

    def test_pre_fork_unbounded_mint_byte_identical_to_legacy(self):
        """At any height strictly below Tier 76 (but above Tier 4's
        FINALITY_REWARD_FROM_ISSUANCE_HEIGHT so direct-mint is on), the
        per-block finality-mint must equal num_survivors *
        FINALITY_VOTE_INCLUSION_REWARD -- the legacy unbounded shape.
        This is what guarantees historical-block replay stays byte-
        identical across the upgrade."""
        pre_h = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT - 1
        self.assertGreaterEqual(
            pre_h, config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
            "test setup: pre-Tier-76 height must be past Tier 4",
        )
        # 50 votes, with FINALITY_VOTE_INCLUSION_REWARD=1, must mint 50.
        n = 50
        minted = self._apply_block_with_n_votes(n=n, height=pre_h)
        self.assertEqual(
            minted, n * config.FINALITY_VOTE_INCLUSION_REWARD,
            f"pre-Tier-76 at height {pre_h}: {n} votes should mint "
            f"{n * config.FINALITY_VOTE_INCLUSION_REWARD} tokens "
            f"(legacy unbounded), got {minted}",
        )

    def test_post_fork_total_mint_clamped_to_cap(self):
        """At/after Tier 76, even when num_survivors greatly exceeds
        the cap, the per-block finality-mint total must NOT exceed
        FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS."""
        post_h = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT
        cap = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS
        # 2*cap votes -- guarantees we exceed the cap.
        n = 2 * cap
        self.assertLessEqual(
            n, len(self.signers),
            "test setup: not enough signers for n=2*cap",
        )
        minted = self._apply_block_with_n_votes(n=n, height=post_h)
        self.assertEqual(
            minted, cap,
            f"post-Tier-76 at height {post_h}: {n} votes (2x cap) "
            f"should mint exactly cap={cap}, got {minted}",
        )

    def test_post_fork_under_cap_full_legacy_mint(self):
        """A block with strictly fewer votes than the cap must still
        mint the full legacy amount -- the cap is a ceiling, not a
        floor.  Honest operators on real chains will sit well below
        the cap, and their reward must be unchanged."""
        post_h = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT
        cap = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS
        n = cap // 2
        self.assertGreater(n, 0, "test setup: cap // 2 must be positive")
        minted = self._apply_block_with_n_votes(n=n, height=post_h)
        self.assertEqual(
            minted, n * config.FINALITY_VOTE_INCLUSION_REWARD,
            f"post-Tier-76 at height {post_h}: {n} votes (< cap) "
            f"should mint full legacy {n} tokens, got {minted}",
        )

    def test_post_fork_supply_invariant_holds(self):
        """The mint MUST bump total_supply and total_minted in
        lockstep so the supply-conservation assertion holds (Pre-fork
        does this too; we re-verify post-fork that the cap path keeps
        the invariant).  Tests for total_minted += per_vote_mint AND
        total_supply += per_vote_mint when post-Tier-4 direct-mint is
        on."""
        post_h = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT
        cap = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS
        n = 2 * cap
        supply_before = self.chain.supply.total_supply
        minted_before = self.chain.supply.total_minted
        self._apply_block_with_n_votes(n=n, height=post_h)
        supply_after = self.chain.supply.total_supply
        minted_after = self.chain.supply.total_minted
        self.assertEqual(
            supply_after - supply_before, minted_after - minted_before,
            "supply delta must equal minted delta -- conservation",
        )
        self.assertEqual(
            minted_after - minted_before, cap,
            "minted delta must equal the cap when survivors exceed it",
        )

    def test_post_fork_proposer_balance_credit_matches_total_mint(self):
        """All minted tokens land in the proposer's balance; the cap
        applies to the TOTAL, not to per-recipient (there's only one
        recipient -- the proposer)."""
        post_h = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_HEIGHT
        cap = config.FINALITY_VOTE_REWARD_PER_BLOCK_CAP_TOKENS
        bal_before = self.chain.supply.balances.get(self.proposer.entity_id, 0)
        n = 2 * cap
        self._apply_block_with_n_votes(n=n, height=post_h)
        bal_after = self.chain.supply.balances.get(self.proposer.entity_id, 0)
        self.assertEqual(
            bal_after - bal_before, cap,
            "proposer's balance must rise by exactly the capped mint",
        )


if __name__ == "__main__":
    unittest.main()
