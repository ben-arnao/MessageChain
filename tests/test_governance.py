"""Tests for on-chain voting: proposals, voting, and delegation.

The governance module is a general-purpose secure voting system.  It
records proposals, votes, and results on-chain.  What happens downstream
of vote results is out of scope.

Model (2026-04-15 redesign):
  - Stakers vote DIRECTLY (own_stake > 0 required).
  - Holders participate via DELEGATION of their liquid balance to 1-3
    validators.  Linear pass-through; no sqrt, no auto-delegation.
  - Delegations must AGE (GOVERNANCE_DELEGATION_AGING_BLOCKS) before
    counting for a given proposal.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    ProposalTransaction,
    VoteTransaction,
    DelegateTransaction,
    ProposalStatus,
    GovernanceTracker,
    create_proposal,
    create_vote,
    create_delegation,
    verify_proposal,
    verify_vote,
    verify_delegation,
)
from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW,
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_DELEGATE_FEE,
    GOVERNANCE_DELEGATION_AGING_BLOCKS,
)
from messagechain.core.block import _hash


# Per-test helper: register a delegation that is already aged enough to
# count at `proposal_block`.  Use this when the test is about tally math
# rather than aging itself.  Aging-specific tests call set_delegation
# directly so they can pin the exact relationship.
AGED_OFFSET = GOVERNANCE_DELEGATION_AGING_BLOCKS


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


class TestDelegateTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def test_create_and_verify_delegation(self):
        tx = create_delegation(self.alice, [(self.bob.entity_id, 100)])
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_revocation(self):
        tx = create_delegation(self.alice, [])
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_self_delegation_rejected(self):
        tx = create_delegation(self.alice, [(self.alice.entity_id, 100)])
        self.assertFalse(verify_delegation(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        tx = create_delegation(self.alice, [(self.bob.entity_id, 100)])
        data = tx.serialize()
        restored = DelegateTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.targets, [(self.bob.entity_id, 100)])


class TestStakerOnlyDirectVoting(unittest.TestCase):
    """Only stakers (own_stake > 0 at snapshot) can register a direct vote."""

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
    """Tally uses stake/delegation snapshot captured at proposal creation."""

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


class TestDelegationBasics(unittest.TestCase):
    """Linear pass-through delegation — no sqrt, no auto."""

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
        self.tracker = GovernanceTracker()

    def _add_proposal_aged(self, proposer, proposal_block=10_000):
        """Create a proposal such that delegations registered at block 0
        are already aged.  Uses block 10_000 to guarantee
        `block_height - 0 >= aging`.
        """
        proposal = create_proposal(proposer, "t", "d")
        self.tracker.add_proposal(
            proposal, block_height=proposal_block, supply_tracker=self.supply,
        )
        return proposal

    def test_aged_delegation_adds_linear_weight(self):
        """Alice delegates her liquid balance to Bob (a staker).  When Bob
        votes, Alice's balance is added linearly to his side."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        # Register delegation at block 0, aged for proposals at 10_000+.
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.bob)
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, no, participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob direct 500 + Alice aged-delegated 1000 = 1500 yes.
        self.assertEqual(yes, 1500)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 1500)
        # Eligible: bob stake 500 + alice aged balance 1000 = 1500.
        self.assertEqual(eligible, 1500)

    def test_delegation_at_exact_aging_boundary_counts(self):
        """A delegation whose age is EXACTLY the aging threshold counts.

        This pins the boundary precisely: age >= threshold ages in.  An
        off-by-one that excluded delegations at the exact threshold
        would let an attacker guarantee their delegation NEVER ages
        (submit at block N, wait N+aging, submit again at N+aging — it
        would always be excluded at the moment of freshness).
        """
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        # Delegation at block 100; proposal at block 100 + aging.  Delta
        # = aging (exactly), which is >= aging → must age in.
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=100,
        )
        proposal = self._add_proposal_aged(
            self.bob, proposal_block=100 + AGED_OFFSET,
        )
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=100 + AGED_OFFSET + 1,
        )
        yes, _no, _participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob direct 500 + alice aged-delegated 1000 = 1500.
        self.assertEqual(yes, 1500)
        self.assertEqual(eligible, 1500)

    def test_delegation_one_block_below_boundary_excluded(self):
        """A delegation one block short of the aging threshold is
        excluded.  Complement to the boundary-inclusive test above."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        # Delegation at block 101; proposal at block 100 + aging.  Delta
        # = aging - 1 (one short) → must be excluded.
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=101,
        )
        proposal = self._add_proposal_aged(
            self.bob, proposal_block=100 + AGED_OFFSET,
        )
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=100 + AGED_OFFSET + 1,
        )
        yes, _no, _participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob direct 500 only; alice's delegation silent.
        self.assertEqual(yes, 500)
        self.assertEqual(eligible, 500)

    def test_non_aged_delegation_ignored(self):
        """A delegation registered too recently is excluded from this
        proposal's snapshot."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        # Delegation registered at block 9_500 — proposal at 10_000 means
        # only 500 blocks of age, well below aging threshold (1008).
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=9_500,
        )
        proposal = self._add_proposal_aged(self.bob)
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, _no, _participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob direct 500, alice's fresh delegation silent.
        self.assertEqual(yes, 500)
        # Eligible: only bob's stake (alice's fresh delegation isn't in
        # the denominator either — silence of non-aged delegators does
        # NOT count against approval).
        self.assertEqual(eligible, 500)

    def test_re_delegation_resets_aging(self):
        """Submitting a new DelegateTransaction resets the age clock."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        # Original delegation at block 0 would be aged for proposal at 10_000...
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        # ...but alice re-delegates at block 9_500 (same targets).  The age
        # clock MUST reset, not carry over.
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=9_500,
        )
        proposal = self._add_proposal_aged(self.bob)  # block 10_000
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, _no, _participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Only bob's stake; alice's re-delegation is now fresh (500 blocks).
        self.assertEqual(yes, 500)
        self.assertEqual(eligible, 500)

    def test_split_delegation_with_mixed_vote(self):
        """Alice delegates 50/50 to Bob and Carol.  Bob votes yes, Carol
        votes no → 500 yes and 500 no from alice's balance."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 700
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id,
            [(self.bob.entity_id, 50), (self.carol.entity_id, 50)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.bob)
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        self.tracker.add_vote(
            create_vote(self.carol, proposal.proposal_id, False),
            current_block=10_001,
        )
        yes, no, participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob 500 + alice 50% = 500 → yes = 1000
        # Carol 700 + alice 50% = 500 → no = 1200
        self.assertEqual(yes, 1000)
        self.assertEqual(no, 1200)
        self.assertEqual(participating, 2200)
        # Eligible: bob 500 + carol 700 + alice 1000 = 2200.
        self.assertEqual(eligible, 2200)

    def test_split_delegation_with_non_voting_slice_silent(self):
        """If one of the split validators doesn't vote, that slice is
        silent but the delegator's full balance stays in total_eligible."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 700
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id,
            [(self.bob.entity_id, 50), (self.carol.entity_id, 50)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.bob)
        # Only Bob votes.
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, no, participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Bob 500 + alice's bob-slice 500 = 1000 yes.
        # Carol's 700 is silent (she didn't vote); alice's carol-slice
        # 500 is silent too.
        self.assertEqual(yes, 1000)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 1000)
        # Eligible: bob 500 + carol 700 + alice's full 1000 = 2200.
        self.assertEqual(eligible, 2200)

    def test_revocation_removes_delegation_and_aging(self):
        """After revocation the delegator has no delegation and no age
        clock.  A later re-delegation starts fresh from that later block."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        # Revoke
        self.tracker.set_delegation(
            self.alice.entity_id, [], current_block=50,
        )
        self.assertNotIn(self.alice.entity_id, self.tracker.delegations)
        self.assertNotIn(self.alice.entity_id, self.tracker.delegation_set_at)
        # Proposal at 10_000 — alice has no delegation, her balance is silent.
        proposal = self._add_proposal_aged(self.bob)
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, _no, _participating, eligible = self.tracker.tally(proposal.proposal_id)
        self.assertEqual(yes, 500)
        # Alice's liquid balance isn't a delegator in this snapshot.
        self.assertEqual(eligible, 500)

    def test_non_voting_delegate_makes_weight_silent(self):
        """If the chosen validator doesn't vote, delegator's weight is
        silent (not counted in participating) but still in eligible."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.carol)
        # Only Carol votes; Bob (Alice's delegate) does not.
        self.tracker.add_vote(
            create_vote(self.carol, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, no, participating, eligible = self.tracker.tally(proposal.proposal_id)
        # Carol 3000 yes.  Alice's delegation to Bob is silent (Bob
        # didn't vote).
        self.assertEqual(yes, 3000)
        self.assertEqual(no, 0)
        self.assertEqual(participating, 3000)
        # Eligible: bob 500 + carol 3000 + alice delegation 1000 = 4500.
        self.assertEqual(eligible, 4500)

    def test_delegator_direct_vote_fails_if_not_staker(self):
        """Delegator who holds liquid but hasn't staked cannot override
        delegation with a direct vote (because non-stakers can't vote
        directly)."""
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.bob)
        # Alice tries to vote directly — rejected, she's not a staker
        alice_vote = create_vote(self.alice, proposal.proposal_id, False)
        self.assertFalse(self.tracker.add_vote(alice_vote, current_block=10_001))
        # Bob votes yes; Alice's delegation flows to him normally
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),
            current_block=10_001,
        )
        yes, _no, _participating, _eligible = self.tracker.tally(proposal.proposal_id)
        # Bob 500 + alice delegation 1000 = 1500.
        self.assertEqual(yes, 1500)

    def test_validator_self_direct_vote_ignores_own_delegation(self):
        """A staking validator who also delegated (unusual) votes
        directly — the direct vote is all that matters for them."""
        self.supply.staked[self.alice.entity_id] = 2000
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.balances[self.alice.entity_id] = 1000
        self.tracker.set_delegation(
            self.alice.entity_id, [(self.bob.entity_id, 100)],
            current_block=0,
        )
        proposal = self._add_proposal_aged(self.alice)
        self.tracker.add_vote(
            create_vote(self.alice, proposal.proposal_id, False),  # direct NO
            current_block=10_001,
        )
        self.tracker.add_vote(
            create_vote(self.bob, proposal.proposal_id, True),  # Bob YES
            current_block=10_001,
        )
        yes, no, _participating, _eligible = self.tracker.tally(proposal.proposal_id)
        # Alice's own stake 2000 goes no.  Alice's delegation of her
        # liquid balance still flows to Bob (who voted yes).  The
        # redesign spec notes: "a direct vote always overrides
        # delegation from the same entity for that proposal" — but here
        # the delegation is of a DIFFERENT pool (liquid balance) from
        # the direct vote (own stake), and both flow through.  Bob's
        # yes = 500 (own) + 1000 (alice's delegation) = 1500.
        self.assertEqual(yes, 1500)
        self.assertEqual(no, 2000)


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
        ):
            self.assertIn(key, info)
        self.assertNotIn("total_weight", info)  # old field removed
        self.assertNotIn("balance_snapshot", info)  # old field removed
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
