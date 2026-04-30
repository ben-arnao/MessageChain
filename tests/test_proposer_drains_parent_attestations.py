"""Regression tests for the proposer-drains-parent-attestations fix.

The 1.45.1 receipt-page fix taught the read path
(`durable_block_finality`) to consult the successor block's
`attestations` list.  But before this fix, no proposer ever flushed
the in-memory `FinalityTracker` onto chain — every produced block
carried zero attestations.  Result: the receipt page on
https://messagechain.org silently downgraded every block produced
before the most recent restart to "0 attesters / awaiting finality"
because the durable source it read from was empty by construction.

These tests pin both halves of the fix:

  1. ``FinalityTracker.attestations_for(block_hash, block_number)``
     returns the correct ``Attestation`` objects from the in-memory
     tracker, deduped by validator.

  2. The proposer drain path — ``attestations_for(...)`` ->
     ``propose_block(attestations=...)`` -> ``add_block`` -> the
     produced block's ``attestations`` list — actually carries the
     attestations onto chain, where ``durable_block_finality`` can
     read them.
"""

import unittest

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import _hash
from messagechain.consensus.attestation import (
    Attestation,
    FinalityTracker,
    create_attestation,
    durable_block_finality,
)
from messagechain.consensus.pos import ProofOfStake
from tests import register_entity_for_test


class TestAttestationsForHelper(unittest.TestCase):
    """Unit tests for the in-memory drain helper."""

    def setUp(self):
        self.tracker = FinalityTracker()

    def test_returns_attestations_for_matching_pair(self):
        bh = _hash(b"target_block")
        att1 = Attestation(b"v1".ljust(32, b"\x00"), bh, 5, None)
        att2 = Attestation(b"v2".ljust(32, b"\x00"), bh, 5, None)
        self.tracker.add_attestation(att1, 100, 300)
        self.tracker.add_attestation(att2, 100, 300)

        out = self.tracker.attestations_for(bh, 5)
        self.assertEqual(len(out), 2)
        self.assertEqual(
            {a.validator_id for a in out},
            {att1.validator_id, att2.validator_id},
        )

    def test_filters_out_other_blocks(self):
        bh_target = _hash(b"target_block")
        bh_other = _hash(b"other_block")
        att_target = Attestation(b"v1".ljust(32, b"\x00"), bh_target, 5, None)
        att_other = Attestation(b"v2".ljust(32, b"\x00"), bh_other, 5, None)
        self.tracker.add_attestation(att_target, 100, 300)
        self.tracker.add_attestation(att_other, 100, 300)

        out = self.tracker.attestations_for(bh_target, 5)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].validator_id, att_target.validator_id)

    def test_filters_out_other_heights(self):
        bh = _hash(b"target_block")
        att_h5 = Attestation(b"v1".ljust(32, b"\x00"), bh, 5, None)
        self.tracker.add_attestation(att_h5, 100, 300)

        self.assertEqual(self.tracker.attestations_for(bh, 6), [])
        self.assertEqual(self.tracker.attestations_for(bh, 4), [])

    def test_returns_empty_when_tracker_empty(self):
        self.assertEqual(
            self.tracker.attestations_for(_hash(b"any"), 0), [],
        )


class TestProposerDrainsParentAttestations(unittest.TestCase):
    """End-to-end pin: attestations gossiped into the tracker land on
    chain when the next block is produced, so durable_block_finality
    can read them on the receipt page after a restart.
    """

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 10000
        self.chain.supply.balances[self.bob.entity_id] = 10000
        self.chain.supply.balances[self.carol.entity_id] = 10000
        self.consensus = ProofOfStake()

    def test_drained_attestations_land_on_chain(self):
        """Simulates the production sequence:
          1. Proposer produces block N (no parent attestations yet).
          2. Two validators attest to block N — gossip lands in
             ``self.chain.finality`` via add_attestation.
          3. Proposer produces block N+1 by draining the tracker via
             ``attestations_for(tip.block_hash, tip.header.block_number)``
             and passing the result as ``attestations=`` —  exactly
             what server.py::_try_produce_block_sync and
             node.py::_try_produce_block now do.
          4. Block N+1's on-chain ``attestations`` list contains both
             attestations, and ``durable_block_finality`` reads them
             back through the chain (not the tracker).
        """
        # Step 1: produce block N.
        block_n = self.chain.propose_block(self.consensus, self.alice, [])
        ok, reason = self.chain.add_block(block_n)
        self.assertTrue(ok, reason)

        # Step 2: gossip-style: two attestations land in the tracker.
        att_bob = create_attestation(
            self.bob, block_n.block_hash, block_n.header.block_number,
        )
        att_carol = create_attestation(
            self.carol, block_n.block_hash, block_n.header.block_number,
        )
        for att in (att_bob, att_carol):
            self.chain.finality.add_attestation(att, 100, 300)

        # Step 3: proposer drains the tracker for the parent (= tip).
        tip = self.chain.chain[-1]
        drained = self.chain.finality.attestations_for(
            tip.block_hash, tip.header.block_number,
        )
        self.assertEqual(len(drained), 2)

        block_np1 = self.chain.propose_block(
            self.consensus, self.alice, [], attestations=drained,
        )
        ok, reason = self.chain.add_block(block_np1)
        self.assertTrue(ok, reason)

        # Step 4a: the produced block actually carries them.
        on_chain_validators = {
            a.validator_id for a in block_np1.attestations
        }
        self.assertEqual(
            on_chain_validators,
            {self.bob.entity_id, self.carol.entity_id},
            "proposer drain must land both attestations on chain",
        )

        # Step 4b: the durable-read path sees them, even with a fresh
        # (empty) FinalityTracker — i.e., simulating a node restart
        # after the block landed.
        self.chain.finality = FinalityTracker()
        attester_set, _attesting_stake, _threshold_met = (
            durable_block_finality(
                self.chain,
                block_n.header.block_number,
                block_n.block_hash,
            )
        )
        self.assertEqual(
            attester_set,
            {self.bob.entity_id, self.carol.entity_id},
            "durable read from successor block must survive restart",
        )


if __name__ == "__main__":
    unittest.main()
