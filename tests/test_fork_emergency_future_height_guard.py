"""Regression pin: ``observe_finality_vote`` MUST refuse to feed
the fork-emergency detector with votes whose ``target_block_number``
exceeds the local chain tip.

Pre-fix the public observe-hook fell through to ``dict(self.supply.
staked)`` whenever ``_stake_snapshots`` had no pin for the vote's
target height.  Pinned snapshots only exist for blocks that have
been APPENDED to the chain, so any vote at a future height (target
> self.height) bypassed the pinned-snapshot path and was scored
against LIVE stake.  Two operational consequences:

  1. Liveness fragility (the load-bearing concern).  With one
     validator holding the supermajority of live stake (the
     bootstrap configuration, but also any post-bootstrap
     distribution with a 2/3 holder), a single signed FinalityVote
     at any future height for any hash trips the 2/3 threshold
     against live stake and flags an emergency.  Validators
     auto-halt block production + finality voting per the
     fork_emergency module's load-bearing contract.  Honest
     gossip never produces a future-height vote, but a vote-
     scheduler bug, replay of a stale buffered vote at boot, or
     clock-skew misfire IS sufficient to halt the network with no
     adversary at all.

  2. Adversarial: any 2/3-stake holder can publish signed
     FinalityVotes at attacker-chosen future heights and force the
     same auto-halt across honest peers without producing any
     slashable evidence (the votes are well-formed, the signer is
     a known-staked validator, the only thing wrong is the target
     references a block that does not exist locally).

Fix: in ``observe_finality_vote``, refuse to feed the detector with
votes whose ``target_block_number > self.height``.  Honest gossip
references already-appended blocks; a vote outside that window is
either a bug or an attack and the right move is to drop it from
the early-warning path entirely.  Pinned-snapshot resolution and
detector ingestion are unchanged for past- and current-tip votes.
"""

from __future__ import annotations

import unittest

from messagechain.consensus.finality import create_finality_vote
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


class ForkEmergencyFutureHeightGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.whale = Entity.create(b"feh-whale".ljust(32, b"\x00"))
        cls.minnow = Entity.create(b"feh-minnow".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.whale, self.minnow):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.whale)
        register_entity_for_test(self.chain, self.minnow)
        # Whale = supermajority of stake (mirrors today's bootstrap
        # distribution and any post-bootstrap 2/3 concentration).
        self.chain.supply.balances[self.whale.entity_id] = 100_000
        self.chain.supply.balances[self.minnow.entity_id] = 100
        self.chain.supply.stake(self.whale.entity_id, 99_000)
        self.chain.supply.stake(self.minnow.entity_id, 1)
        # Propose one real block so chain.chain[tip] is addressable
        # for the must-not-regress test.
        self.consensus = ProofOfStake()
        proposer = pick_selected_proposer(
            self.chain, [self.whale, self.minnow],
        )
        block = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

    def test_future_height_vote_does_not_trigger_emergency(self):
        """The load-bearing pin.  A signed FinalityVote at
        target_block_number >= self.height (= len(self.chain), i.e.
        the next-to-be-mined slot or beyond) MUST NOT feed the
        fork-emergency detector, regardless of signer stake or
        target hash.  No such target exists on the chain — there is
        no consensus interpretation of "stake at a block that hasn't
        happened," so the only safe behaviour is to drop the vote
        from the early-warning path."""
        future_height = self.chain.height + 5

        divergent = b"\x77" * 32
        v = create_finality_vote(
            self.whale,
            divergent,
            future_height,
            signed_at_height=future_height,
        )

        self.chain.observe_finality_vote(v)

        self.assertFalse(
            self.chain.fork_emergency_detector.is_in_emergency(),
            "future-height vote must not register against live stake "
            "via the no-pinned-snapshot fallback",
        )

    def test_future_height_vote_array_does_not_trigger_emergency(self):
        """Defense in depth: many future-height votes from the same
        supermajority signer at different future heights must each
        be dropped, not summed into the detector under live stake."""
        for offset in (0, 1, 2, 3, 10, 100, 1_000):
            future_height = self.chain.height + offset
            divergent = future_height.to_bytes(4, "big") * 8  # unique 32B
            v = create_finality_vote(
                self.whale,
                divergent,
                future_height,
                signed_at_height=future_height,
            )
            self.chain.observe_finality_vote(v)

        self.assertFalse(
            self.chain.fork_emergency_detector.is_in_emergency(),
            "future-height votes — at any offset — must not feed the "
            "detector",
        )

    def test_current_tip_vote_still_feeds_detector(self):
        """Must-not-regress: the legitimate gossip path is votes
        targeting blocks already on chain.  A divergent-hash vote at
        a height the chain HAS appended must still trigger the
        emergency — that's the whole point of the early-warning
        hook."""
        # self.chain.height == len(self.chain.chain); valid indices
        # are 0..height-1.  Vote against the most-recent appended
        # block's height.
        latest_idx = self.chain.height - 1
        local_hash = self.chain.chain[latest_idx].block_hash
        divergent = b"\x88" * 32
        self.assertNotEqual(divergent, local_hash)

        v = create_finality_vote(
            self.whale,
            divergent,
            latest_idx,
            signed_at_height=latest_idx,
        )
        self.chain.observe_finality_vote(v)

        # Whale = 99_000/99_001 of stake = >>2/3, so the threshold
        # is crossed and the emergency MUST flag for at-tip targets.
        self.assertTrue(
            self.chain.fork_emergency_detector.is_in_emergency(),
            "at-tip divergent-hash vote from supermajority signer "
            "must still trigger the emergency (must-not-regress)",
        )


if __name__ == "__main__":
    unittest.main()
