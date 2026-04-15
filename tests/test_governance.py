"""Tests for on-chain voting: proposals, votes, tally.

The governance module is a general-purpose secure voting system.  It
records proposals, votes, and results on-chain.  What happens downstream
of vote results is out of scope.

Model (2026-04-15 redesign — pure stakers-only, no delegation):
  - Only stakers (own_stake > 0 at snapshot) can vote.
  - Voting power = own stake at snapshot.
  - Anyone can propose (pays fee).
  - Treasury spends require 2/3 of total eligible stake (silence = no).
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    ProposalTransaction,
    VoteTransaction,
    ProposalStatus,
    GovernanceTracker,
    create_proposal,
    create_vote,
    verify_proposal,
    verify_vote,
)
from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
)
from messagechain.core.block import _hash


class TestProposalTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_create_and_verify_proposal(self):
        tx = create_proposal(
            self.alice,
            title="Increase block size limit",
            description="Proposal to raise max txs per block from 50 to 100",
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.proposer_id, self.alice.entity_id)
        self.assertNotEqual(tx.tx_hash, b"")

    def test_proposal_with_reference_hash(self):
        ref_hash = _hash(b"external document contents")
        tx = create_proposal(
            self.alice,
            title="Adopt new fee schedule",
            description="See referenced document for details",
            reference_hash=ref_hash,
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.reference_hash, ref_hash)

    def test_wrong_key_fails_verification(self):
        bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        tx = create_proposal(self.alice, "Test proposal", "desc")
        self.assertFalse(verify_proposal(tx, bob.public_key))

    def test_insufficient_fee_rejected(self):
        tx = create_proposal(self.alice, "Test", "desc", fee=0)
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_empty_title_rejected(self):
        tx = create_proposal(self.alice, "", "desc")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_bad_reference_hash_rejected(self):
        tx = create_proposal(self.alice, "Test", "desc", reference_hash=b"short")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        ref_hash = _hash(b"content")
        tx = create_proposal(self.alice, "Test", "A description", reference_hash=ref_hash)
        data = tx.serialize()
        restored = ProposalTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.title, tx.title)
        self.assertEqual(restored.description, tx.description)
        self.assertEqual(restored.reference_hash, tx.reference_hash)


class TestVoteTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.proposal_id = _hash(b"proposal-id")

    def test_create_and_verify_vote(self):
        tx = create_vote(self.alice, self.proposal_id, approve=True)
        self.assertTrue(verify_vote(tx, self.alice.public_key))

    def test_no_vote_passes_verification(self):
        tx = create_vote(self.alice, self.proposal_id, approve=False)
        self.assertTrue(verify_vote(tx, self.alice.public_key))

    def test_wrong_key_fails(self):
        bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        tx = create_vote(self.alice, self.proposal_id, approve=True)
        self.assertFalse(verify_vote(tx, bob.public_key))

    def test_serialization_roundtrip(self):
        tx = create_vote(self.alice, self.proposal_id, approve=True)
        data = tx.serialize()
        restored = VoteTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.approve, True)


class TestStakerOnlyDirectVoting(unittest.TestCase):
    """Only stakers (own_stake > 0 at snapshot) can register a vote."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # Alice stakes, Bob is a pure liquid holder
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 50_000
        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.proposal_tx, block_height=100, supply_tracker=self.supply,
        )

    def test_staker_direct_vote_accepted(self):
        vote = create_vote(self.alice, self.proposal_tx.proposal_id, True)
        self.assertTrue(self.tracker.add_vote(vote, current_block=101))
        yes, no, participating, _eligible = self.tracker.tally(
            self.proposal_tx.proposal_id,
        )
        self.assertEqual(yes, 1000)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 1000)

    def test_non_staker_direct_vote_rejected(self):
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, True)
        self.assertFalse(self.tracker.add_vote(vote, current_block=101))
        # Nothing recorded — Bob's vote is silently dropped from the tally
        yes, no, participating, _eligible = self.tracker.tally(
            self.proposal_tx.proposal_id,
        )
        self.assertEqual(yes, 0)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 0)
        self.assertNotIn(self.bob.entity_id, self.tracker.proposals[
            self.proposal_tx.proposal_id
        ].votes)


class TestGovernanceTrackerBasics(unittest.TestCase):
    """Tests for the voting state machine — opens/closes, duplicates."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))
        cls.dave = Entity.create(b"dave-private-key".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol, self.dave):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.balances[self.carol.entity_id] = 0
        self.supply.balances[self.dave.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 2000
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.staked[self.dave.entity_id] = 4000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(self.bob, "Add feature X", "details")
        self.tracker.add_proposal(
            self.proposal_tx, block_height=100, supply_tracker=self.supply,
        )

    def test_proposal_starts_open(self):
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, current_block=101,
        )
        self.assertEqual(status, ProposalStatus.OPEN)

    def test_proposal_closes_after_voting_window(self):
        vote = create_vote(self.carol, self.proposal_tx.proposal_id, True)
        self.tracker.add_vote(vote, current_block=101)
        expired = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired,
        )
        self.assertEqual(status, ProposalStatus.CLOSED)

    def test_tally_records_majority_yes(self):
        """Linear staker-only tally — Carol (3000) yes, Bob (2000) no."""
        self.tracker.add_vote(
            create_vote(self.carol, self.proposal_tx.proposal_id, True),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.bob, self.proposal_tx.proposal_id, False),
            current_block=101,
        )
        yes, no, participating, eligible = self.tracker.tally(
            self.proposal_tx.proposal_id,
        )
        self.assertEqual(yes, 3000)
        self.assertEqual(no, 2000)
        self.assertEqual(participating, 5000)
        # Eligible is all four validators' stake (alice 1000, bob 2000,
        # carol 3000, dave 4000).  Alice and Dave did not vote — their
        # stake is silent but in the denominator.
        self.assertEqual(eligible, 10_000)

    def test_no_votes_zero_weight(self):
        yes, no, participating, eligible = self.tracker.tally(
            self.proposal_tx.proposal_id,
        )
        self.assertEqual(yes, 0)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 0)
        self.assertEqual(eligible, 10_000)

    def test_proposal_closes_with_no_votes(self):
        expired = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired,
        )
        self.assertEqual(status, ProposalStatus.CLOSED)

    def test_duplicate_vote_rejected(self):
        v1 = create_vote(self.alice, self.proposal_tx.proposal_id, True)
        v2 = create_vote(self.alice, self.proposal_tx.proposal_id, False)
        self.assertTrue(self.tracker.add_vote(v1, current_block=101))
        self.assertFalse(self.tracker.add_vote(v2, current_block=102))

    def test_vote_outside_window_rejected(self):
        v = create_vote(self.bob, self.proposal_tx.proposal_id, True)
        expired = 100 + GOVERNANCE_VOTING_WINDOW + 1
        self.assertFalse(self.tracker.add_vote(v, current_block=expired))


class TestSnapshotFreezing(unittest.TestCase):
    """Tally uses stake snapshot captured at proposal creation."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 3000
        self.supply.staked[self.bob.entity_id] = 1000
        self.tracker = GovernanceTracker()

    def test_tally_uses_snapshot_not_live_stake(self):
        proposal = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(proposal, block_height=100, supply_tracker=self.supply)
        # Alice inflates her stake AFTER proposal
        self.supply.staked[self.alice.entity_id] = 9000
        self.tracker.add_vote(
            create_vote(self.alice, proposal.proposal_id, True),
            current_block=101,
        )
        yes, _no, participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Snapshot-bound: alice=3000 stake, not live 9000.
        self.assertEqual(yes, 3000)
        self.assertEqual(participating, 3000)
        # Eligible: alice 3000 + bob 1000 = 4000 at snapshot.
        self.assertEqual(eligible, 4000)

    def test_late_staker_cannot_vote(self):
        """Entity without snapshot-stake cannot vote, even if they stake later."""
        proposal = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(proposal, block_height=100, supply_tracker=self.supply)
        # Late-bloomer eve stakes after snapshot
        eve = Entity.create(b"eve-private-key".ljust(32, b"\x00"))
        self.supply.staked[eve.entity_id] = 100_000
        vote = create_vote(eve, proposal.proposal_id, True)
        self.assertFalse(self.tracker.add_vote(vote, current_block=101))

    def test_unstaker_keeps_snapshot_weight(self):
        """Entity staked at snapshot keeps their voting right even after
        unstaking.  The snapshot fixes the electorate at proposal
        creation time; later withdrawals don't disenfranchise."""
        proposal = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(proposal, block_height=100, supply_tracker=self.supply)
        # Alice unstakes after snapshot
        self.supply.staked[self.alice.entity_id] = 0
        self.tracker.add_vote(
            create_vote(self.alice, proposal.proposal_id, True),
            current_block=101,
        )
        yes, _no, _participating, _eligible = self.tracker.tally(proposal.proposal_id)
        self.assertEqual(yes, 3000)

    def test_total_eligible_stake_field_populated(self):
        proposal = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(proposal, block_height=100, supply_tracker=self.supply)
        state = self.tracker.proposals[proposal.proposal_id]
        self.assertEqual(state.total_eligible_stake, 4000)


class TestGovernanceInfo(unittest.TestCase):
    """Tests for proposal info/summary shape."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 1000
        self.supply.balances[self.bob.entity_id] = 1000
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 1000
        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(self.bob, "Fix bug", "details")
        self.tracker.add_proposal(
            self.proposal_tx, block_height=10, supply_tracker=self.supply,
        )

    def test_proposal_info_fields(self):
        info = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=20,
        )
        for key in (
            "proposal_id", "title", "description", "status",
            "yes_weight", "no_weight", "total_participating", "total_eligible",
            "participation_pct", "approval_pct_of_participating",
            "approval_pct_of_eligible", "blocks_remaining", "proposer",
            "direct_votes",
        ):
            self.assertIn(key, info)
        self.assertNotIn("total_weight", info)  # old field removed
        self.assertNotIn("balance_snapshot", info)  # old field removed
        self.assertNotIn("delegation_snapshot", info)  # delegation gone
        self.assertEqual(info["title"], "Fix bug")
        self.assertEqual(info["status"], "open")
        self.assertEqual(info["total_eligible"], 2000)

    def test_unknown_proposal_raises(self):
        with self.assertRaises(ValueError):
            self.tracker.get_proposal_status(b"\x00" * 32, 100)

    def test_blocks_remaining_counts_down(self):
        info = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=10,
        )
        self.assertEqual(info["blocks_remaining"], GOVERNANCE_VOTING_WINDOW)
        info2 = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=110,
        )
        self.assertEqual(info2["blocks_remaining"], GOVERNANCE_VOTING_WINDOW - 100)


if __name__ == "__main__":
    unittest.main()
