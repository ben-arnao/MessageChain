"""Finality-vote apply-path clamp (defense-in-depth).

Under the post-FINALITY_REWARD_FROM_ISSUANCE_HEIGHT fork, each
included finality vote mints 1 token directly into the proposer's
balance (bumps total_supply + total_minted).  `_validate_finality_votes`
already rejects blocks whose count exceeds
MAX_FINALITY_VOTES_PER_BLOCK or that contain duplicate
(signer_entity_id, target_block_number) pairs.

This file locks a second-layer guarantee: even if validation is
bypassed or drifts, the APPLY path (`_apply_finality_votes`) must
itself refuse to mint more than MAX_FINALITY_VOTES_PER_BLOCK tokens
in a single block, at/after FINALITY_VOTE_CAP_HEIGHT.

The scenarios below exercise the clamp by constructing a
SimpleNamespace-style fake block with > cap vote entries and calling
the apply function directly — the validation path is not involved,
so this is purely the apply-side hardening under test.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import messagechain.config as config
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.finality import FinalityVote
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


def _fake_vote(
    signer_id: bytes, target_hash: bytes, target_num: int,
    leaf_index: int = 0,
) -> FinalityVote:
    """Build a placeholder FinalityVote for apply-path clamp tests.

    Apply-side logic reads signer_entity_id, target_block_hash,
    target_block_number, and signature.leaf_index only.  No signature
    verification runs here — that's already done at validation time.

    `leaf_index` defaults to 0, but tests that stuff multiple votes
    into a single block MUST pass distinct values: post-2026-04-25
    the apply path enforces chain-historic leaf-watermark dedup
    (closes the FinalityVote replay-mint vulnerability), so two votes
    from the same signer at the same leaf collapse to one mint.
    """
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=target_num,
        signature=Signature([], leaf_index, [], b"", b""),
    )


class TestApplyPathClamp(unittest.TestCase):
    """Post-activation the mint loop stops at MAX_FINALITY_VOTES_PER_BLOCK."""

    def setUp(self):
        self.alice = Entity.create(b"apply-clamp-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"apply-clamp-bob".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        # Register bob as a known entity so leaf-watermark bookkeeping
        # inside _apply_finality_votes finds a home.  We bypass
        # validate_finality_votes entirely, so no signature check runs.
        self.chain.public_keys[self.bob.entity_id] = self.bob.public_key
        # Pretend a past block exists (target for the vote).
        self.target_hash = b"\x11" * 32
        self.target_num = 1

    def _make_fake_block(self, num_votes: int, block_height: int):
        """Build a SimpleNamespace block with `num_votes` votes.

        Each vote uses a DISTINCT leaf_index so the apply path's
        chain-historic leaf-reuse dedup (closes the FinalityVote
        replay-mint vulnerability) doesn't collapse them.  Real
        production proposers always assemble votes from distinct
        signer/leaf pairs; the cap clamp under test is independent
        of the dedup.
        """
        votes = [
            _fake_vote(
                self.bob.entity_id, self.target_hash, self.target_num,
                leaf_index=i,
            )
            for i in range(num_votes)
        ]
        return SimpleNamespace(
            finality_votes=votes,
            header=SimpleNamespace(block_number=block_height),
        )

    def test_post_activation_clamps_over_cap(self):
        """At/after FINALITY_VOTE_CAP_HEIGHT apply path mints AT MOST cap."""
        # Activation height sits at/after FINALITY_REWARD_FROM_ISSUANCE
        # so the post-fork direct-mint path is the one we're exercising.
        height = max(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        ) + 1
        over_cap = config.MAX_FINALITY_VOTES_PER_BLOCK + 50
        fake = self._make_fake_block(over_cap, block_height=height)
        alice_before = self.chain.supply.balances.get(self.alice.entity_id, 0)
        minted_before = self.chain.supply.total_minted
        supply_before = self.chain.supply.total_supply
        self.chain._apply_finality_votes(fake, self.alice.entity_id)
        minted_delta = self.chain.supply.total_minted - minted_before
        supply_delta = self.chain.supply.total_supply - supply_before
        alice_delta = (
            self.chain.supply.balances.get(self.alice.entity_id, 0) - alice_before
        )
        # Every unit of total_minted must correspond to exactly 1 vote
        # credited to the proposer.  Under the clamp, no more than
        # MAX_FINALITY_VOTES_PER_BLOCK tokens are minted regardless of
        # how many votes the block contains.
        self.assertLessEqual(
            minted_delta, config.MAX_FINALITY_VOTES_PER_BLOCK,
            "apply-path clamp must not mint more than cap tokens",
        )
        self.assertEqual(minted_delta, supply_delta)
        self.assertEqual(minted_delta, alice_delta)

    def test_post_activation_at_cap_mints_all(self):
        """Exactly-cap votes all mint; no spurious drop."""
        height = max(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        ) + 1
        fake = self._make_fake_block(
            config.MAX_FINALITY_VOTES_PER_BLOCK, block_height=height,
        )
        minted_before = self.chain.supply.total_minted
        self.chain._apply_finality_votes(fake, self.alice.entity_id)
        minted_delta = self.chain.supply.total_minted - minted_before
        self.assertEqual(minted_delta, config.MAX_FINALITY_VOTES_PER_BLOCK)

    def test_pre_activation_no_apply_clamp(self):
        """Pre-activation the apply path retains its legacy (uncapped)
        loop.  We verify this does NOT silently start clamping before
        activation — that would alter historical replay.  Use pre-
        FINALITY_REWARD_FROM_ISSUANCE_HEIGHT too so the legacy treasury
        path is the mint path under test, and load treasury with enough
        tokens to pay every vote even over cap.
        """
        pre_height = min(
            config.FINALITY_VOTE_CAP_HEIGHT,
            config.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT,
        ) - 1
        if pre_height < 0:
            self.skipTest("activation height too low for pre-fork test")
        # Fund the treasury well above cap so pre-fork behavior pays
        # every vote.  Directly setting the balance skips the supply-
        # invariant pathway, which is fine: we're probing the legacy
        # loop, not the invariant.
        from messagechain.config import TREASURY_ENTITY_ID
        self.chain.supply.balances[TREASURY_ENTITY_ID] = (
            (config.MAX_FINALITY_VOTES_PER_BLOCK + 50)
            * config.FINALITY_VOTE_INCLUSION_REWARD
        )
        over_cap = config.MAX_FINALITY_VOTES_PER_BLOCK + 50
        fake = self._make_fake_block(over_cap, block_height=pre_height)
        proposer_before = self.chain.supply.balances.get(self.alice.entity_id, 0)
        self.chain._apply_finality_votes(fake, self.alice.entity_id)
        proposer_delta = (
            self.chain.supply.balances.get(self.alice.entity_id, 0)
            - proposer_before
        )
        # Pre-activation legacy behavior: treasury pays every vote
        # with no apply-path clamp.  This is byte-for-byte the
        # shipped pre-fork behavior.
        self.assertEqual(
            proposer_delta,
            over_cap * config.FINALITY_VOTE_INCLUSION_REWARD,
        )


class TestValidationStillRejectsOverCap(unittest.TestCase):
    """Validation still the first line of defense.

    The apply-path clamp is DEFENSE-IN-DEPTH.  It does not weaken the
    validation check — a proposer who over-includes is still punished
    by block rejection, not by a silent clamp.  Lock this with a
    direct call to `_validate_finality_votes`.
    """

    def setUp(self):
        self.alice = Entity.create(b"validate-cap-alice".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)

    def test_validation_rejects_over_cap_regardless_of_fork_height(self):
        """Pre- or post-activation of the apply clamp, validation
        still rejects blocks over MAX_FINALITY_VOTES_PER_BLOCK.  The
        apply clamp is belt-and-suspenders, not a replacement.
        """
        votes = [
            _fake_vote(self.alice.entity_id, b"\x11" * 32, 1)
            for _ in range(config.MAX_FINALITY_VOTES_PER_BLOCK + 1)
        ]
        fake = SimpleNamespace(
            finality_votes=votes,
            header=SimpleNamespace(block_number=1),
        )
        ok, reason = self.chain._validate_finality_votes(fake)
        self.assertFalse(ok)
        self.assertIn("too many finality votes", reason.lower())


if __name__ == "__main__":
    unittest.main()
