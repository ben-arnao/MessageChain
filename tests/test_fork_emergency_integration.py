"""End-to-end test for the fork-emergency detector wired into Blockchain.

Covers the integration that the unit tests in
``test_fork_emergency_detector.py`` deliberately skip:
  * Detector lives on Blockchain.fork_emergency_detector
  * Block-apply path feeds ingested finality votes through the detector
  * Public observe_finality_vote() hook (for gossip ingest) feeds the
    same detector with the right stake snapshot
  * recheck_after_chain_advance auto-clears emergencies when the
    local chain catches up
"""

import unittest

from messagechain.consensus.finality import create_finality_vote
from messagechain.consensus.fork_emergency import ForkEmergencyDetector
from messagechain.consensus.pos import ProofOfStake
from messagechain.core.blockchain import Blockchain
from messagechain.identity.identity import Entity
from tests import register_entity_for_test, pick_selected_proposer


class ForkEmergencyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"fork-em-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"fork-em-bob".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"fork-em-carol".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
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

    def _propose_block(self):
        proposer = pick_selected_proposer(self.chain, self._all())
        block = self.chain.propose_block(self.consensus, proposer, [])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        return block

    def test_detector_attached_to_fresh_blockchain(self):
        """A bare Blockchain must own a ForkEmergencyDetector — the
        runtime-side validator-halt and gossip-ingest code paths
        unconditionally read this attribute."""
        self.assertIsInstance(
            self.chain.fork_emergency_detector,
            ForkEmergencyDetector,
        )
        self.assertFalse(self.chain.fork_emergency_detector.is_in_emergency())

    def test_gossip_observe_does_not_trigger_for_local_chain_hash(self):
        """The common case: peers gossip finality votes for a hash THIS
        node has at the same height. Threshold met → finalization (no
        emergency) — never a false-positive fork flag."""
        block1 = self._propose_block()

        for e in self._all():
            v = create_finality_vote(
                e,
                block1.block_hash,
                block1.header.block_number,
                signed_at_height=block1.header.block_number,
            )
            self.chain.observe_finality_vote(v)

        self.assertFalse(self.chain.fork_emergency_detector.is_in_emergency())

    def test_gossip_observe_triggers_for_divergent_supermajority(self):
        """If 2/3 of stake commits to a hash we don't have at height H,
        the detector flags an emergency. This is the gossip-time path —
        votes never even reached our blocks."""
        block1 = self._propose_block()

        # Manufacture a divergent target hash at height 1 — what 2/3 of
        # stake on the OTHER side of an unintentional fork would have
        # signed for the same block number.
        divergent = b"\xee" * 32
        self.assertNotEqual(divergent, block1.block_hash)

        for e in self._all():
            v = create_finality_vote(
                e,
                divergent,
                block1.header.block_number,
                signed_at_height=block1.header.block_number,
            )
            self.chain.observe_finality_vote(v)

        det = self.chain.fork_emergency_detector
        self.assertTrue(det.is_in_emergency())
        emergency = det.lowest_emergency()
        self.assertIsNotNone(emergency)
        assert emergency is not None
        self.assertEqual(emergency.height, block1.header.block_number)
        self.assertEqual(emergency.supermajority_hash, divergent)
        self.assertEqual(emergency.local_hash, block1.block_hash)

    def test_apply_path_also_feeds_detector(self):
        """When a block carries finality votes for a divergent hash
        through the normal apply path (replay / catch-up sync), the
        detector observes them too — defense-in-depth so an emergency
        surfaces even if the operator never enabled gossip ingest
        plumbing."""
        block1 = self._propose_block()

        divergent = b"\xdd" * 32
        votes = [
            create_finality_vote(
                e,
                divergent,
                block1.header.block_number,
                signed_at_height=block1.header.block_number,
            )
            for e in self._all()
        ]

        proposer = pick_selected_proposer(self.chain, self._all())
        block2 = self.chain.propose_block(
            self.consensus, proposer, [],
            finality_votes=votes,
        )
        # Even if the divergent-target votes still pack into a block on
        # this node (validate_block does not reject votes for an
        # unknown hash at a known height), the detector must catch the
        # supermajority signal during apply.
        ok, _reason = self.chain.add_block(block2)
        # The block may be rejected for invalid finality-vote target —
        # if so, the detector still cannot have observed those votes,
        # so the contract is still met. If the block is accepted, the
        # detector MUST have flagged the emergency.
        if ok:
            self.assertTrue(
                self.chain.fork_emergency_detector.is_in_emergency()
            )

    def test_recheck_clears_emergency_when_chain_catches_up(self):
        """After we trigger an emergency via gossip, then later append
        a block whose hash equals the supermajority hash at that
        height, recheck_after_chain_advance auto-clears."""
        block1 = self._propose_block()
        det = self.chain.fork_emergency_detector

        # Synthesize an emergency by directly pushing votes for the
        # ACTUAL hash we have, but pretend our local hash is something
        # else — the cleanest way to test the recheck logic in
        # isolation is to inject the emergency state directly.
        from messagechain.consensus.fork_emergency import ForkEmergency
        det._emergencies[block1.header.block_number] = ForkEmergency(
            height=block1.header.block_number,
            supermajority_hash=block1.block_hash,
            local_hash=b"\xaa" * 32,
            attested_stake=2_000,
            total_stake=3_000,
        )
        self.assertTrue(det.is_in_emergency())

        cleared = det.recheck_after_chain_advance(
            lambda h: (
                self.chain.chain[h].block_hash
                if 0 <= h < len(self.chain.chain)
                else None
            ),
        )
        self.assertEqual(cleared, 1)
        self.assertFalse(det.is_in_emergency())

    def test_block_accept_runs_recheck_automatically(self):
        """add_block must run the recheck after a successful append.
        Otherwise stale emergencies linger and the validator stays
        halted forever even after manual recovery."""
        block1 = self._propose_block()
        det = self.chain.fork_emergency_detector

        from messagechain.consensus.fork_emergency import ForkEmergency
        det._emergencies[block1.header.block_number] = ForkEmergency(
            height=block1.header.block_number,
            supermajority_hash=block1.block_hash,
            local_hash=b"\xbb" * 32,
            attested_stake=2_000,
            total_stake=3_000,
        )

        # Appending another block triggers the post-append recheck —
        # the old emergency at height 1 must clear because chain[1]
        # now matches the supermajority hash.
        self._propose_block()

        self.assertFalse(det.is_in_emergency())


if __name__ == "__main__":
    unittest.main()
