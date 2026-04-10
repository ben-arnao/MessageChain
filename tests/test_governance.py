"""Tests for on-chain governance: proposals, voting, and delegation."""

import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
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
        cls.alice = Entity.create(b"alice-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_create_and_verify_proposal(self):
        """Signed proposal passes verification."""
        content_hash = _hash(b"diff contents of PR")
        tx = create_proposal(
            self.alice,
            pr_url="https://github.com/user/repo/pull/1",
            content_hash=content_hash,
            description="Add governance module",
        )
        self.assertTrue(verify_proposal(tx, self.alice.public_key))
        self.assertEqual(tx.proposer_id, self.alice.entity_id)
        self.assertNotEqual(tx.tx_hash, b"")

    def test_wrong_key_fails_verification(self):
        """Proposal verified against wrong key is rejected."""
        bob = Entity.create(b"bob-private-key")
        content_hash = _hash(b"diff")
        tx = create_proposal(self.alice, "https://example.com/pr/1", content_hash, "desc")
        self.assertFalse(verify_proposal(tx, bob.public_key))

    def test_insufficient_fee_rejected(self):
        """Proposal with fee below minimum is rejected."""
        content_hash = _hash(b"diff")
        tx = create_proposal(self.alice, "https://example.com/pr/1", content_hash, "desc", fee=0)
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_empty_url_rejected(self):
        """Proposal with empty PR URL is rejected."""
        content_hash = _hash(b"diff")
        tx = create_proposal(self.alice, "", content_hash, "desc")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_bad_content_hash_rejected(self):
        """Proposal with wrong-length content hash is rejected."""
        tx = create_proposal(self.alice, "https://example.com/pr/1", b"short", "desc")
        self.assertFalse(verify_proposal(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        """Proposal survives serialization/deserialization."""
        content_hash = _hash(b"diff")
        tx = create_proposal(self.alice, "https://example.com/pr/1", content_hash, "desc")
        data = tx.serialize()
        restored = ProposalTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.pr_url, tx.pr_url)
        self.assertEqual(restored.content_hash, tx.content_hash)


class TestVoteTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")

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
        bob = Entity.create(b"bob-private-key")
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
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

    def test_create_and_verify_delegation(self):
        """Signed delegation passes verification."""
        tx = create_delegation(self.alice, self.bob.entity_id)
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_revocation(self):
        """Delegation with empty delegate_id is a revocation."""
        tx = create_delegation(self.alice, b"")
        self.assertTrue(verify_delegation(tx, self.alice.public_key))

    def test_self_delegation_rejected(self):
        """Cannot delegate to yourself."""
        tx = create_delegation(self.alice, self.alice.entity_id)
        self.assertFalse(verify_delegation(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        tx = create_delegation(self.alice, self.bob.entity_id)
        data = tx.serialize()
        restored = DelegateTransaction.deserialize(data)
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.delegate_id, self.bob.entity_id)


class TestGovernanceTracker(unittest.TestCase):
    """Tests for the governance state machine."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")
        cls.carol = Entity.create(b"carol-private-key")
        cls.dave = Entity.create(b"dave-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.dave.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 1000
        self.supply.balances[self.bob.entity_id] = 2000
        self.supply.balances[self.carol.entity_id] = 3000
        self.supply.balances[self.dave.entity_id] = 4000
        # Voting power is stake-weighted — set staked amounts to match balances
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 2000
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.staked[self.dave.entity_id] = 4000

        self.owner = self.alice
        self.tracker = GovernanceTracker(owner_id=self.alice.entity_id)

        content_hash = _hash(b"diff contents")
        self.proposal_tx = create_proposal(
            self.bob, "https://github.com/user/repo/pull/42",
            content_hash, "Add feature X",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=100)

    def test_proposal_starts_active(self):
        """New proposal is in ACTIVE status."""
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, current_block=101, supply_tracker=self.supply,
        )
        self.assertEqual(status, ProposalStatus.ACTIVE)

    def test_simple_majority_approves(self):
        """Proposal with >50% yes weight can merge."""
        # Carol (3000) votes yes, Bob (2000) votes no
        vote_yes = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.bob, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes)
        self.tracker.add_vote(vote_no)

        # 3000 / 5000 = 60% > 50%
        self.assertTrue(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_simple_majority_rejects(self):
        """Proposal with <=50% yes weight cannot merge."""
        # Bob (2000) votes yes, Carol (3000) votes no
        vote_yes = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_yes)
        self.tracker.add_vote(vote_no)

        # 2000 / 5000 = 40% < 50%
        self.assertFalse(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_no_votes_cannot_merge(self):
        """Proposal with no votes cannot merge."""
        self.assertFalse(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_owner_can_approve_unilaterally(self):
        """Owner approval bypasses consensus requirement."""
        self.tracker.owner_approve(self.proposal_tx.proposal_id)
        self.assertTrue(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_owner_approval_overrides_rejection(self):
        """Owner can approve even when consensus voted no."""
        # Everyone votes no
        vote_no1 = create_vote(self.bob, self.proposal_tx.proposal_id, approve=False)
        vote_no2 = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        vote_no3 = create_vote(self.dave, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_no1)
        self.tracker.add_vote(vote_no2)
        self.tracker.add_vote(vote_no3)

        # Without owner: cannot merge
        self.assertFalse(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

        # Owner overrides
        self.tracker.owner_approve(self.proposal_tx.proposal_id)
        self.assertTrue(
            self.tracker.can_merge(self.proposal_tx.proposal_id, 150, self.supply)
        )

    def test_proposal_expires(self):
        """Proposal without consensus expires after voting window."""
        # Only one small vote, not enough
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        # Bob alone = 2000, Carol voted no = 3000. But Carol didn't vote.
        # Actually only Bob voted yes (2000/2000 = 100%). That passes.
        # Let's make Bob vote no instead so it fails.
        self.tracker.proposals[self.proposal_tx.proposal_id].votes.clear()
        vote_no = create_vote(self.carol, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_no)

        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block, self.supply,
        )
        self.assertEqual(status, ProposalStatus.EXPIRED)

    def test_proposal_approved_after_window_with_consensus(self):
        """Proposal with majority approval is APPROVED even after window closes."""
        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)
        # Only carol voted yes (3000/3000 = 100%)

        expired_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        status = self.tracker.get_proposal_status(
            self.proposal_tx.proposal_id, expired_block, self.supply,
        )
        self.assertEqual(status, ProposalStatus.APPROVED)


class TestDelegation(unittest.TestCase):
    """Tests for vote delegation mechanics."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")
        cls.carol = Entity.create(b"carol-private-key")
        cls.dave = Entity.create(b"dave-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0
        self.dave.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 1000
        self.supply.balances[self.bob.entity_id] = 500
        self.supply.balances[self.carol.entity_id] = 3000
        self.supply.balances[self.dave.entity_id] = 200
        # Voting power is stake-weighted — set staked amounts to match balances
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 500
        self.supply.staked[self.carol.entity_id] = 3000
        self.supply.staked[self.dave.entity_id] = 200

        self.tracker = GovernanceTracker()

        content_hash = _hash(b"diff")
        self.proposal_tx = create_proposal(
            self.alice, "https://github.com/user/repo/pull/1",
            content_hash, "Test proposal",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=50)

    def test_delegated_vote_adds_weight(self):
        """Delegate's vote carries delegator's balance too."""
        # Alice (1000) delegates to Bob (500)
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)

        # Bob votes yes — should carry 500 (own) + 1000 (Alice's) = 1500
        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        self.assertEqual(yes_weight, 1500)
        self.assertEqual(total_weight, 1500)

    def test_direct_vote_overrides_delegation(self):
        """If delegator votes directly, their delegation is ignored."""
        # Alice (1000) delegates to Bob (500)
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)

        # Bob votes yes, Alice votes no directly
        vote_bob = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        vote_alice = create_vote(self.alice, self.proposal_tx.proposal_id, approve=False)
        self.tracker.add_vote(vote_bob)
        self.tracker.add_vote(vote_alice)

        # Bob: 500 yes. Alice: 1000 no (direct override). Total: 1500.
        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        self.assertEqual(yes_weight, 500)
        self.assertEqual(total_weight, 1500)

    def test_single_hop_only(self):
        """Delegation does NOT chain: A->B->C, A's weight only goes to B."""
        # Alice delegates to Bob, Bob delegates to Carol
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)
        self.tracker.set_delegation(self.bob.entity_id, self.carol.entity_id)

        # Carol votes yes — gets only Bob's weight (500), not Alice's (1000)
        # because Alice delegated to Bob, not Carol
        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Carol (3000) + Bob (500, delegated to Carol) = 3500
        # Alice's 1000 is delegated to Bob, but Bob didn't vote, so it doesn't count
        self.assertEqual(yes_weight, 3500)
        self.assertEqual(total_weight, 3500)

    def test_delegation_revocation(self):
        """Revoking delegation removes the delegator's weight from delegate."""
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)
        # Revoke
        self.tracker.set_delegation(self.alice.entity_id, b"")

        vote = create_vote(self.bob, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Only Bob's own balance
        self.assertEqual(yes_weight, 500)
        self.assertEqual(total_weight, 500)

    def test_multiple_delegators_to_same_delegate(self):
        """Multiple entities can delegate to the same person."""
        # Alice (1000) and Dave (200) both delegate to Carol (3000)
        self.tracker.set_delegation(self.alice.entity_id, self.carol.entity_id)
        self.tracker.set_delegation(self.dave.entity_id, self.carol.entity_id)

        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Carol (3000) + Alice (1000) + Dave (200) = 4200
        self.assertEqual(yes_weight, 4200)
        self.assertEqual(total_weight, 4200)

    def test_delegator_not_counted_if_delegate_didnt_vote(self):
        """If delegate doesn't vote, delegator's weight is not counted."""
        self.tracker.set_delegation(self.alice.entity_id, self.bob.entity_id)

        # Only Carol votes (Bob, Alice's delegate, does not vote)
        vote = create_vote(self.carol, self.proposal_tx.proposal_id, approve=True)
        self.tracker.add_vote(vote)

        yes_weight, total_weight = self.tracker.tally(
            self.proposal_tx.proposal_id, self.supply,
        )
        # Only Carol's own balance
        self.assertEqual(yes_weight, 3000)
        self.assertEqual(total_weight, 3000)


class TestGovernanceInfo(unittest.TestCase):
    """Tests for proposal info/summary."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-private-key")
        cls.bob = Entity.create(b"bob-private-key")

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0

        self.supply = SupplyTracker()
        self.supply.balances[self.alice.entity_id] = 1000
        self.supply.balances[self.bob.entity_id] = 1000
        # Voting power is stake-weighted
        self.supply.staked[self.alice.entity_id] = 1000
        self.supply.staked[self.bob.entity_id] = 1000

        self.tracker = GovernanceTracker(owner_id=self.alice.entity_id)

        content_hash = _hash(b"diff")
        self.proposal_tx = create_proposal(
            self.bob, "https://github.com/user/repo/pull/99",
            content_hash, "Fix bug",
        )
        self.tracker.add_proposal(self.proposal_tx, block_height=10)

    def test_proposal_info_fields(self):
        """Proposal info contains all expected fields."""
        info = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=20, supply_tracker=self.supply,
        )
        self.assertIn("proposal_id", info)
        self.assertIn("pr_url", info)
        self.assertIn("status", info)
        self.assertIn("yes_weight", info)
        self.assertIn("total_weight", info)
        self.assertIn("can_merge", info)
        self.assertIn("blocks_remaining", info)
        self.assertEqual(info["pr_url"], "https://github.com/user/repo/pull/99")
        self.assertEqual(info["status"], "active")

    def test_unknown_proposal_raises(self):
        """Querying unknown proposal raises ValueError."""
        with self.assertRaises(ValueError):
            self.tracker.get_proposal_status(b"\x00" * 32, 100, self.supply)

    def test_blocks_remaining_counts_down(self):
        """Blocks remaining decreases as chain advances."""
        info = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=10, supply_tracker=self.supply,
        )
        self.assertEqual(info["blocks_remaining"], GOVERNANCE_VOTING_WINDOW)

        info2 = self.tracker.get_proposal_info(
            self.proposal_tx.proposal_id, current_block=110, supply_tracker=self.supply,
        )
        self.assertEqual(info2["blocks_remaining"], GOVERNANCE_VOTING_WINDOW - 100)


if __name__ == "__main__":
    unittest.main()
