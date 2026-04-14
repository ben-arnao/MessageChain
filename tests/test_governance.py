"""Tests for on-chain voting: proposals, voting, and delegation.

The governance module is a general-purpose secure voting system.
It records proposals, votes, and results on-chain. What happens
downstream of the vote results is out of scope.
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
)
from messagechain.core.block import _hash


class TestProposalTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_create_and_verify_proposal(self):
        """Signed proposal passes verification."""
        tx = create_proposal(
            self.alice,
            title="Increase block size limit",
            description="Proposal to increase max transactions per block from 50 to 100",
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.proposer_id, self.alice.entity_id)
        self.assertNotEqual(tx.tx_hash, b"")

    def test_proposal_with_reference_hash(self):
        """Proposal can include optional reference hash for external content."""
        ref_hash = _hash(b"external document contents")
        tx = create_proposal(
            self.alice,
            title="Adopt new fee schedule",
            description="See referenced document for details",
            reference_hash=ref_hash,
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.reference_hash, ref_hash)

    def test_proposal_without_reference_hash(self):
        """Proposal without reference hash is valid (hash defaults to empty)."""
        tx = create_proposal(
            self.alice,
            title="Simple vote",
            description="No external reference needed",
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.reference_hash, b"")

    def test_wrong_key_fails_verification(self):
        """Proposal verified against wrong key is rejected."""
        bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        tx = create_proposal(self.alice, "Test proposal", "desc")
        self.assertFalse(verify_proposal(tx, bob.public_key))

    def test_insufficient_fee_rejected(self):
        """Proposal with fee below minimum is rejected."""
        tx = create_proposal(self.alice, "Test", "desc", fee=0)
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_empty_title_rejected(self):
        """Proposal with empty title is rejected."""
        tx = create_proposal(self.alice, "", "desc")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_bad_reference_hash_rejected(self):
        """Proposal with wrong-length reference hash is rejected."""
        tx = create_proposal(self.alice, "Test", "desc", reference_hash=b"short")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        """Proposal survives serialization/deserialization."""
        ref_hash = _hash(b"content")
        tx = create_proposal(self.alice, "Test proposal", "A description", reference_hash=ref_hash)
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
        """Signed vote passes verification."""
        tx = create_vote(self.alice, self.proposal_id, approve=True)
        self.assertTrue(verify_vote(tx, self.alice.public_key))

    def test_no_vote_passes_verification(self):
        """A 'no' vote is also valid."""
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
        """Signed delegation passes verification."""
        tx = create_delegation(self.alice, [(self.bob.entity_id, 100)])
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_revocation(self):
        """Delegation with empty targets is a revocation."""
        tx = create_delegation(self.alice, [])
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_self_delegation_rejected(self):
        """Cannot delegate to yourself."""
        tx = create_delegation(self.alice, [(self.alice.entity_id, 100)])
        self.assertFalse(verify_delegation(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        tx = create_delegation(self.alice, [(self.bob.entity_id, 100)])
        data = tx.serialize()
        restored = DelegateTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.targets, [(self.bob.entity_id, 100)])


class TestGovernanceTracker(unittest.TestCase):
    """Tests for the voting state machine."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))
        cls.dave = Entity.create(b"dave-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.dave.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Set balances to 0 so voting power = stake (no sqrt-balance component).
        # This keeps expected tally math simple.
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.balances[self.carol.entity_id] = 0
        self.supply.balances[self.dave.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 2000
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.staked[self.dave.entity_id] = 4000

        self.tracker = GovernanceTracker()

        self.proposal_tx = create_proposal(
            self.bob, "Add feature X", "Detailed description of feature X",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100, supply_tracker=self.supply)

    def test_proposal_starts_open(self):
        """New proposal is in OPEN status."""
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, current_block=101,
        )
        self.assertEqual(status, ProposalStatus.OPEN)

    def test_proposal_closes_after_voting_window(self):
        """Proposal becomes CLOSED after voting window expires."""
        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block,
        )
        self.assertEqual(status, ProposalStatus.CLOSED)

    def test_tally_records_majority_yes(self):
        """Tally correctly records when majority of stake voted yes."""
        vote_yes = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.bob, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes, current_block=101)
        self.tracker.add_vote(vote_no, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Direct: carol(3000) yes, bob(2000) no.
        # Passive auto-delegation: alice(1000) and dave(4000) split across
        # voting validators weighted by sqrt(stake):
        #   sqrt(carol=3000)=54, sqrt(bob=2000)=44, total=98
        # alice(1000): carol-share = 1000*54//98 = 551,
        #              bob-share   = 1000*44//98 = 448
        # dave(4000):  carol-share = 4000*54//98 = 2204,
        #              bob-share   = 4000*44//98 = 1795
        # yes = 3000 + 551 + 2204 = 5755
        # no  = 2000 + 448 + 1795 = 4243
        self.assertEqual(yes_weight, 5755)
        self.assertEqual(total_weight, 5755 + 4243)

    def test_tally_records_majority_no(self):
        """Tally correctly records when majority of stake voted no."""
        vote_yes = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes, current_block=101)
        self.tracker.add_vote(vote_no, current_block=101)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Direct: bob(2000) yes, carol(3000) no.
        # Passive auto-delegation of alice(1000) and dave(4000) via sqrt weights
        # sqrt(carol=3000)=54, sqrt(bob=2000)=44, total=98:
        # yes (bob side) = 2000 + 1000*44//98 + 4000*44//98 = 2000 + 448 + 1795 = 4243
        # no  (carol)    = 3000 + 1000*54//98 + 4000*54//98 = 3000 + 551 + 2204 = 5755
        self.assertEqual(yes_weight, 4243)
        self.assertEqual(total_weight, 4243 + 5755)

    def test_no_votes_zero_weight(self):
        """Proposal with no votes has zero total weight."""
        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        self.assertEqual(yes_weight, 0)
        self.assertEqual(total_weight, 0)

    def test_proposal_closes_with_no_votes(self):
        """Proposal with no votes still closes after window."""
        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block,
        )
        self.assertEqual(status, ProposalStatus.CLOSED)


class TestStakeSnapshot(unittest.TestCase):
    """Tally uses stake snapshot from proposal creation, not live state."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Balances set to 0 so voting power = stake (simpler math).
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 3000
        self.supply.staked[self.bob.entity_id] = 1000

        self.tracker = GovernanceTracker()

    def test_tally_uses_snapshot_not_live_stake(self):
        """Stake changes after proposal creation do not affect tally."""
        proposal_tx = create_proposal(self.alice, "Snapshot test", "desc")
        self.tracker.add_proposal(proposal_tx, block_height=100, supply_tracker=self.supply)

        # Alice stakes more AFTER proposal creation
        self.supply.staked[self.alice.entity_id] = 9000

        vote = create_vote(self.alice, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Snapshot-bound: alice=3000 stake (not live 9000), bob=1000 stake.
        # Alice direct yes (3000).  Bob passive auto-delegates to voting
        # validators: only alice voted, so all 1000 of bob's vp flows to alice.
        # yes = 3000 + 1000 = 4000, total = 4000.
        self.assertEqual(yes_weight, 4000)
        self.assertEqual(total_weight, 4000)

    def test_late_staker_cannot_swing_vote(self):
        """Entity that stakes after proposal creation has zero voting power."""
        # Bob has 1000 staked at proposal creation
        proposal_tx = create_proposal(self.alice, "Late staker test", "desc")
        self.tracker.add_proposal(proposal_tx, block_height=100, supply_tracker=self.supply)

        # Bob massively increases stake after proposal
        self.supply.staked[self.bob.entity_id] = 100_000

        vote = create_vote(self.bob, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        yes_weight, _ = self.tracker.tally(proposal_tx.proposal_id)
        # Snapshot values only: bob=1000 (not the inflated 100_000), alice=3000.
        # Bob voted yes directly (1000).  Alice is passive → auto-delegates.
        # Only bob voted, so alice's 3000 flows entirely to bob.
        # yes = 1000 + 3000 = 4000.
        self.assertEqual(yes_weight, 4000)

    def test_unstaker_keeps_snapshot_weight(self):
        """Entity that unstakes after proposal creation keeps snapshot voting power."""
        proposal_tx = create_proposal(self.alice, "Unstaker test", "desc")
        self.tracker.add_proposal(proposal_tx, block_height=100, supply_tracker=self.supply)

        # Alice unstakes everything after proposal
        self.supply.staked[self.alice.entity_id] = 0

        vote = create_vote(self.alice, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=101)

        yes_weight, _ = self.tracker.tally(proposal_tx.proposal_id)
        # Snapshot value retained: alice=3000 (not live 0), bob=1000.
        # Alice direct yes (3000).  Bob passive auto-delegates → alice.
        # yes = 3000 + 1000 = 4000.
        self.assertEqual(yes_weight, 4000)

    def test_snapshot_captures_total_eligible_stake(self):
        """Proposal info includes total eligible stake from snapshot."""
        proposal_tx = create_proposal(self.alice, "Eligible stake test", "desc")
        self.tracker.add_proposal(proposal_tx, block_height=100, supply_tracker=self.supply)

        info = self.tracker.get_proposal_info(proposal_tx.proposal_id, current_block=101)
        # Alice (3000) + Bob (1000) = 4000
        self.assertEqual(info["total_eligible_stake"], 4000)


class TestVoteWindowEnforcement(unittest.TestCase):
    """Votes on closed proposals are rejected."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 1000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(self.alice, "Window test", "desc")
        self.tracker.add_proposal(self.proposal_tx, block_height=100, supply_tracker=self.supply)

    def test_vote_during_window_accepted(self):
        """Vote during open window is accepted."""
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        accepted = self.tracker.add_vote(vote, current_block=101)
        self.assertTrue(accepted)

        yes_weight, _ = self.tracker.tally(self.proposal_tx.proposal_id)
        # bob direct = 1000 yes.  Alice (stake=1000, no balance) is passive and
        # auto-delegates to voting validators — only bob voted, so alice's
        # full 1000 vp flows to bob.  yes = 1000 + 1000 = 2000.
        self.assertEqual(yes_weight, 2000)

    def test_vote_after_window_rejected(self):
        """Vote after window closes is rejected."""
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        accepted = self.tracker.add_vote(vote, current_block=expired_block)
        self.assertFalse(accepted)

        # Vote should not be recorded
        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        self.assertEqual(yes_weight, 0)
        self.assertEqual(total_weight, 0)

    def test_vote_at_window_boundary_accepted(self):
        """Vote at exactly the last block of the window is accepted."""
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        last_block = 100 + GOVERNANCE_VOTING_WINDOW
        accepted = self.tracker.add_vote(vote, current_block=last_block)
        self.assertTrue(accepted)


class TestVoteImmutability(unittest.TestCase):
    """Once cast, votes cannot be changed."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.staked[self.alice.entity_id] = 5000
        self.supply.staked[self.bob.entity_id] = 1000

        self.tracker = GovernanceTracker()
        self.proposal_tx = create_proposal(self.alice, "Immutability test", "desc")
        self.tracker.add_proposal(self.proposal_tx, block_height=100, supply_tracker=self.supply)

    def test_duplicate_vote_rejected(self):
        """Second vote from same entity on same proposal is rejected."""
        vote1 = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        vote2 = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)

        accepted1 = self.tracker.add_vote(vote1, current_block=101)
        accepted2 = self.tracker.add_vote(vote2, current_block=102)

        self.assertTrue(accepted1)
        self.assertFalse(accepted2)

    def test_first_vote_preserved(self):
        """After rejected duplicate, original vote is preserved in tally."""
        vote1 = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        vote2 = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)

        self.tracker.add_vote(vote1, current_block=101)
        self.tracker.add_vote(vote2, current_block=102)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        # Original yes vote preserved, not overwritten to no.
        # Alice direct = 5000 yes.  Bob passive auto-delegates to only voting
        # validator (alice): bob vp=1000 → all 1000 to alice (yes).
        # yes = 5000 + 1000 = 6000, total = 6000.
        self.assertEqual(yes_weight, 6000)
        self.assertEqual(total_weight, 6000)

    def test_different_entities_can_vote(self):
        """Different entities can still vote independently."""
        vote1 = create_vote(self.alice, self.proposal_tx.proposal_id, approve=True)
        vote2 = create_vote(self.bob, self.proposal_tx.proposal_id, approve=False)

        accepted1 = self.tracker.add_vote(vote1, current_block=101)
        accepted2 = self.tracker.add_vote(vote2, current_block=101)

        self.assertTrue(accepted1)
        self.assertTrue(accepted2)

        yes_weight, total_weight = self.tracker.tally(self.proposal_tx.proposal_id)
        self.assertEqual(yes_weight, 5000)
        self.assertEqual(total_weight, 6000)


class TestDelegation(unittest.TestCase):
    """Tests for vote delegation mechanics."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-private-key".ljust(32, b"\x00"))
        cls.dave = Entity.create(b"dave-private-key".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.dave.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        # Balances at 0 so voting power = stake only (keeps expected
        # values readable).  Individual tests set the stakes they care
        # about and leave others at 0 (i.e. not validators at all), so
        # there are no passive validators to muddle the arithmetic.
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.balances[self.carol.entity_id] = 0
        self.supply.balances[self.dave.entity_id] = 0

        self.tracker = GovernanceTracker()

    def _make_proposal(self):
        """Helper: create a proposal after per-test stakes are set."""
        proposal_tx = create_proposal(
            self.alice, "Test proposal", "Test delegation mechanics",
        )
        self.tracker.add_proposal(
            proposal_tx, block_height=50, supply_tracker=self.supply,
        )
        return proposal_tx

    def test_delegated_vote_adds_weight(self):
        """Delegate's vote carries delegator's stake too."""
        # Only alice and bob are validators — no passive stakes to auto-delegate.
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])

        vote = create_vote(self.bob, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Bob direct(500) yes + alice explicit delegation→bob(1000) yes.
        self.assertEqual(yes_weight, 1500)
        self.assertEqual(total_weight, 1500)

    def test_direct_vote_overrides_delegation(self):
        """If delegator votes directly, their delegation is ignored."""
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])

        vote_bob = create_vote(self.bob, proposal_tx.proposal_id, approve=True)
        vote_alice = create_vote(self.alice, proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_bob, current_block=51)
        self.tracker.add_vote(vote_alice, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Bob(500) yes + Alice(1000) no (direct overrides delegation).
        self.assertEqual(yes_weight, 500)
        self.assertEqual(total_weight, 1500)

    def test_single_hop_only(self):
        """Delegation does NOT chain: A->B->C, A's weight only goes to B."""
        # alice, bob, carol are validators; dave stays out.
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 3000
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])
        self.tracker.set_delegation(self.bob.entity_id, [(self.carol.entity_id, 100)])

        vote = create_vote(self.carol, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Carol(3000) direct + bob's explicit delegation to carol(500).
        # Alice's explicit delegation is to bob — bob didn't vote, so alice's
        # weight is NOT redistributed (single-hop only, no chain to carol).
        # Alice is NOT passive (she has an explicit delegation) so no auto
        # fallback.
        self.assertEqual(yes_weight, 3500)
        self.assertEqual(total_weight, 3500)

    def test_delegation_revocation(self):
        """Revoking delegation removes the delegator's weight from delegate."""
        # Only bob is a validator here — after revocation, alice has no stake
        # so she can't contribute passive auto-delegation either.
        self.supply.staked[self.bob.entity_id] = 500
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])
        self.tracker.set_delegation(self.alice.entity_id, [])

        vote = create_vote(self.bob, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Only Bob(500) direct vote counts — alice has no vp and no delegation.
        self.assertEqual(yes_weight, 500)
        self.assertEqual(total_weight, 500)

    def test_multiple_delegators_to_same_delegate(self):
        """Multiple entities can delegate to the same person."""
        # All four are validators; alice and dave explicitly delegate to carol.
        # bob is the only passive entity, so his vp auto-delegates to carol
        # (only voting validator).
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.staked[self.dave.entity_id] = 200
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.carol.entity_id, 100)])
        self.tracker.set_delegation(self.dave.entity_id, [(self.carol.entity_id, 100)])

        vote = create_vote(self.carol, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Carol(3000) direct + alice→carol(1000) + dave→carol(200).
        # Bob is passive with vp=500 → auto-delegates to only voting validator
        # (carol): share = 500 * isqrt(3000)/isqrt(3000) = 500.
        # yes = 3000 + 1000 + 200 + 500 = 4700.
        self.assertEqual(yes_weight, 4700)
        self.assertEqual(total_weight, 4700)

    def test_delegator_not_counted_if_delegate_didnt_vote(self):
        """If delegate doesn't vote, delegator's weight is not counted."""
        # alice explicitly delegates to bob (who doesn't vote).  Alice's
        # explicit delegation means she does NOT fall back to auto — her
        # weight is lost.  carol votes.
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 3000
        proposal_tx = self._make_proposal()

        self.tracker.set_delegation(self.alice.entity_id, [(self.bob.entity_id, 100)])

        vote = create_vote(self.carol, proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote, current_block=51)

        yes_weight, total_weight = self.tracker.tally(proposal_tx.proposal_id)
        # Carol(3000) direct.  Alice explicit→bob (bob didn't vote → lost).
        # Bob is passive (no direct vote, no explicit delegation) → auto to
        # carol (only voting validator): bob's vp=500 flows entirely to carol.
        # yes = 3000 + 500 = 3500.
        self.assertEqual(yes_weight, 3500)
        self.assertEqual(total_weight, 3500)


class TestGovernanceInfo(unittest.TestCase):
    """Tests for proposal info/summary."""

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

        self.proposal_tx = create_proposal(
            self.bob, "Fix bug in consensus", "Details about the bug fix",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=10, supply_tracker=self.supply)

    def test_proposal_info_fields(self):
        """Proposal info contains all expected fields."""
        info = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=20,
        )
        self.assertIn("proposal_id", info)
        self.assertIn("title", info)
        self.assertIn("description", info)
        self.assertIn("status", info)
        self.assertIn("yes_weight", info)
        self.assertIn("total_weight", info)
        self.assertIn("total_eligible_stake", info)
        self.assertIn("approval_pct", info)
        self.assertIn("blocks_remaining", info)
        self.assertIn("direct_votes", info)
        # Enforcement fields should NOT be present
        self.assertNotIn("can_merge", info)
        self.assertNotIn("owner_approved", info)
        self.assertEqual(info["title"], "Fix bug in consensus")
        self.assertEqual(info["status"], "open")
        self.assertEqual(info["total_eligible_stake"], 2000)

    def test_unknown_proposal_raises(self):
        """Querying unknown proposal raises ValueError."""
        with self.assertRaises(ValueError):
            self.tracker.get_proposal_status(b"\x00" * 32, 100)

    def test_blocks_remaining_counts_down(self):
        """Blocks remaining decreases as chain advances."""
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
