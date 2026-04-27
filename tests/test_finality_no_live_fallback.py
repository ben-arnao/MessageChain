"""Apply-path defense-in-depth: missing stake snapshot must NOT fall
back to `self.supply.staked` when crediting FinalityVotes against the
2/3 checkpoint denominator.

Background: `_apply_finality_votes` previously read
    pinned = self._stake_snapshots.get(v.target_block_number)
    stake_map = pinned if pinned is not None else dict(self.supply.staked)

The live-state fallback is a divergence trap.  Peers whose pin for the
target block has been pruned (cold restart, snapshot-mirror corruption,
test-harness skip) compute a different denominator than peers that
still hold the pin -- the resulting `crossed` decision is
arrival-order/restart-history-dependent, splitting the persistent
`finalized_hashes` set across the network.  Validation already rejects
votes older than FINALITY_VOTE_MAX_AGE_BLOCKS and the chaindb mirror
keeps a pin for every block in that window, so a validated vote always
finds its pin on the honest path.  This test pins the deterministic
"skip rather than substitute" behavior for the can't-happen case.
"""

import unittest

from messagechain.config import FINALITY_REWARD_FROM_ISSUANCE_HEIGHT
from messagechain.consensus.finality import create_finality_vote
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


import messagechain.config as _mcfg
import messagechain.core.blockchain as _bc_mod

_ORIG_FINALITY_REWARD_ISSUANCE_HEIGHT = None
_ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT = None


def setUpModule():
    global _ORIG_FINALITY_REWARD_ISSUANCE_HEIGHT
    global _ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT
    _ORIG_FINALITY_REWARD_ISSUANCE_HEIGHT = (
        _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT
    )
    _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = 10**9
    if hasattr(_bc_mod, "FINALITY_REWARD_FROM_ISSUANCE_HEIGHT"):
        global _ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT
        _ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT = (
            _bc_mod.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT
        )
        _bc_mod.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = 10**9


def tearDownModule():
    _mcfg.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = (
        _ORIG_FINALITY_REWARD_ISSUANCE_HEIGHT
    )
    if _ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT is not None:
        _bc_mod.FINALITY_REWARD_FROM_ISSUANCE_HEIGHT = (
            _ORIG_BC_FINALITY_REWARD_ISSUANCE_HEIGHT
        )


class TestApplyFinalityVotesNoLiveFallback(unittest.TestCase):
    """Cross-peer determinism: missing pin must not finalize via live state."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))

    def setUp(self):
        from messagechain.config import TREASURY_ENTITY_ID
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        self.chain.supply.balances[self.carol.entity_id] = 10_000
        self.chain.supply.balances.setdefault(TREASURY_ENTITY_ID, 0)
        self.chain.supply.balances[TREASURY_ENTITY_ID] += 10_000
        # Pinned distribution at target: 2000 / 500 / 500 -> 3000 total.
        # Alice's 2000-stake vote alone = 2/3 of pinned, would finalize.
        self.chain.supply.stake(self.alice.entity_id, 2_000)
        self.chain.supply.stake(self.bob.entity_id, 500)
        self.chain.supply.stake(self.carol.entity_id, 500)
        self.consensus = ProofOfStake()

    def _all(self):
        return [self.alice, self.bob, self.carol]

    def test_missing_pin_skips_vote_no_live_fallback(self):
        # Build target block 1 -- pin gets recorded at apply time.
        proposer = pick_selected_proposer(self.chain, self._all())
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)
        self.assertIn(1, self.chain._stake_snapshots)

        # Alice's 2000-stake vote on block1.  Under the pinned 3000
        # denominator this is exactly 2/3 (would finalize via the
        # honest path).
        vote = create_finality_vote(
            self.alice,
            block1.block_hash,
            block1.header.block_number,
            signed_at_height=block1.header.block_number,
        )

        # Simulate the cold-restart-pin-pruned edge: drop the pin for
        # block 1 from BOTH the in-memory map and the chaindb mirror
        # so apply-path lookup fails, exactly as it would on a peer
        # whose snapshot retention diverged from the proposer's.
        del self.chain._stake_snapshots[1]

        proposer2 = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer2, [], finality_votes=[vote],
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        # The defense: with no pin, the vote MUST NOT contribute to
        # the 2/3 tally.  Block 1 is left unfinalized despite a
        # would-finalize vote being included -- the apply path failed
        # closed deterministically rather than substituting live
        # state and producing a peer-divergent `crossed` decision.
        self.assertFalse(
            self.chain.finalized_checkpoints.is_finalized(block1.block_hash),
            "block1 must NOT finalize when its stake-snapshot pin is "
            "missing -- silent live-state fallback would diverge "
            "finality across peers.",
        )
        self.assertNotIn(
            1, self.chain.finalized_checkpoints.finalized_by_height,
            "no entry for height 1 in finalized_by_height when pin missing",
        )

    def test_with_pin_present_vote_still_finalizes(self):
        """Sanity counter-test: with the pin intact, the same vote DOES
        finalize -- proves the previous test's negative result is from
        the missing pin, not from some other reason the vote was
        rejected."""
        proposer = pick_selected_proposer(self.chain, self._all())
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)
        self.assertIn(1, self.chain._stake_snapshots)

        vote = create_finality_vote(
            self.alice,
            block1.block_hash,
            block1.header.block_number,
            signed_at_height=block1.header.block_number,
        )

        # Pin intact -- do NOT drop _stake_snapshots[1].
        proposer2 = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer2, [], finality_votes=[vote],
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        # Alice's 2000-stake vote / 3000 pinned total = exactly 2/3.
        self.assertTrue(
            self.chain.finalized_checkpoints.is_finalized(block1.block_hash),
            "block1 must finalize when pin present and vote crosses "
            "2/3 of pinned stake",
        )


if __name__ == "__main__":
    unittest.main()
