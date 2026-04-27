"""Apply-path defense-in-depth: missing stake snapshot must NOT fall
back to the live `self.supply.staked` map when crediting attestations
against the FinalityTracker 2/3 justification threshold.

Mirrors `test_finality_no_live_fallback` for the attestation layer.
Background: `_process_attestations` previously read

    pinned = self._stake_snapshots.get(target_block)
    stakes_for_att = pinned if pinned is not None else stakes  # live

The live-state fallback is a divergence trap.  Peers whose pin for the
attested target has been pruned (cold restart past mirror window,
snapshot-mirror corruption) compute a different denominator than peers
that still hold the pin -- the resulting `justified` decision is
arrival-order/restart-history-dependent, splitting the persistent
finalized set across the network.  On the honest path the pin always
exists (initialize_genesis pins height 0, every applied block pins its
own height, and attestations only target the immediate parent -- so
the pin for N-1 is always present when N is being applied).  This
test pins the deterministic "skip rather than substitute" behavior
for the can't-happen case.
"""

import unittest

from messagechain.consensus.attestation import create_attestation
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


class TestProcessAttestationsNoLiveFallback(unittest.TestCase):
    """Cross-peer determinism: missing pin must not justify via live state."""

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
        # Pinned distribution at target: 2000/500/500 -> 3000.  Alice's
        # 2000-stake attestation alone is exactly 2/3 of the pinned
        # denominator, so it would justify under the honest path.
        self.chain.supply.stake(self.alice.entity_id, 2_000)
        self.chain.supply.stake(self.bob.entity_id, 500)
        self.chain.supply.stake(self.carol.entity_id, 500)
        self.consensus = ProofOfStake()

    def _all(self):
        return [self.alice, self.bob, self.carol]

    def _build_atts(self, target_block):
        """Three attestations on `target_block`, one per validator,
        which together carry 3000 stake -- exactly 2/3 of the pinned
        denominator."""
        return [
            create_attestation(
                e, target_block.block_hash, target_block.header.block_number,
            )
            for e in self._all()
        ]

    def test_missing_pin_skips_attestation_no_live_fallback(self):
        # Build target block 1.
        proposer = pick_selected_proposer(self.chain, self._all())
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)
        self.assertIn(1, self.chain._stake_snapshots)

        atts = self._build_atts(block1)

        # Drop the pin for block 1, simulating a peer whose snapshot
        # retention diverged from the proposer's (cold-restart past
        # the mirror window).
        del self.chain._stake_snapshots[1]

        # Build block 2 carrying attestations for block 1.  With the
        # pin gone, those attestations must NOT contribute to the
        # FinalityTracker's 2/3 tally.
        proposer2 = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer2, [], attestations=atts,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        # Block 1 must NOT be in the FinalityTracker's `finalized` set
        # -- the attestation-layer justification path failed closed
        # rather than substituting live state and producing peer-
        # divergent `justified` decisions.
        self.assertNotIn(
            block1.block_hash,
            self.chain.finality.finalized,
            "block1 must NOT be justified when its stake-snapshot pin "
            "is missing -- live-state fallback would diverge "
            "justification across peers.",
        )

    def test_with_pin_present_attestation_still_justifies(self):
        """Counter-test: pin intact -> the same attestations justify
        block 1 through the normal path."""
        proposer = pick_selected_proposer(self.chain, self._all())
        block1 = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)
        self.assertIn(1, self.chain._stake_snapshots)

        atts = self._build_atts(block1)

        proposer2 = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer2, [], attestations=atts,
        )
        ok, reason = self.chain.add_block(block2)
        self.assertTrue(ok, reason)

        # With pinned stake intact, attestations from all three
        # validators (3000 stake) on block 1 cross 2/3 of pinned 3000.
        self.assertIn(
            block1.block_hash, self.chain.finality.finalized,
            "block1 must be justified through the FinalityTracker "
            "when the stake-snapshot pin is intact.",
        )


if __name__ == "__main__":
    unittest.main()
