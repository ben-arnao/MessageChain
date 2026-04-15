"""Integration tests for the block-level governance dispatcher.

The dispatcher (`Blockchain._apply_governance_block`) is the bridge
between block processing and the GovernanceTracker.  It:

1. Registers proposals / votes / delegations from each block's governance_txs
2. Pays the fee via the normal burn-and-tip path
3. Auto-executes binding proposals (treasury spends) whose voting
   window has closed as of the current block height
4. Prunes expired proposals to bound tracker memory

These tests exercise the dispatcher directly with crafted mock-blocks,
so they don't depend on state-root simulation for governance txs (which
is a separate future wire-up for the propose_block path).
"""

import unittest
from unittest.mock import MagicMock
from messagechain.core.blockchain import Blockchain
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    create_proposal, create_vote, create_delegation,
    create_treasury_spend_proposal,
    VoteTransaction,
)
from messagechain.identity.identity import Entity
from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW, GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE, TREASURY_ENTITY_ID,
)


def _make_block(block_number: int, proposer_id: bytes, governance_txs: list):
    """Build a minimal mock block carrying only the bits the dispatcher reads."""
    block = MagicMock()
    block.header.block_number = block_number
    block.header.proposer_id = proposer_id
    block.governance_txs = governance_txs
    return block


class TestGovernancePipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"pipe-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"pipe-bob".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"pipe-carol".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        # Give each entity enough liquid balance to pay fees
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.balances[e.entity_id] = 1_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
        # Stake all three so they have governance voting power
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.staked[e.entity_id] = 10_000

    def test_proposal_and_vote_flow_registers_state(self):
        proposal = create_proposal(
            self.alice, "Protocol change", "Rationale",
        )
        block1 = _make_block(1, self.alice.entity_id, [proposal])
        self.chain._apply_governance_block(block1)
        self.assertIn(proposal.proposal_id, self.chain.governance.proposals)

        vote = create_vote(self.bob, proposal.proposal_id, True)
        block2 = _make_block(2, self.alice.entity_id, [vote])
        self.chain._apply_governance_block(block2)
        state = self.chain.governance.proposals[proposal.proposal_id]
        self.assertIn(self.bob.entity_id, state.votes)
        self.assertTrue(state.votes[self.bob.entity_id])

    def test_delegation_applied_from_block(self):
        delegation = create_delegation(
            self.bob, [(self.alice.entity_id, 100)],
        )
        block = _make_block(1, self.alice.entity_id, [delegation])
        self.chain._apply_governance_block(block)
        self.assertIn(self.bob.entity_id, self.chain.governance.delegations)

    def test_treasury_spend_auto_executes_after_window(self):
        # Seed treasury
        self.chain.supply.balances[TREASURY_ENTITY_ID] = 100_000

        spend = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5_000,
            "Fund work", "Bob did good work",
        )
        proposal_block = 5
        b1 = _make_block(proposal_block, self.alice.entity_id, [spend])
        self.chain._apply_governance_block(b1)

        # Votes — binding rule requires > 2/3 of eligible (30k stake),
        # so all three must vote yes (exactly 2/3 fails under strict >)
        for voter in (self.alice, self.bob, self.carol):
            vote = create_vote(voter, spend.proposal_id, True)
            b = _make_block(proposal_block + 1, self.alice.entity_id, [vote])
            self.chain._apply_governance_block(b)

        # Advance to just past voting window — auto-execute fires
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        b_close = _make_block(closed_block, self.alice.entity_id, [])
        bob_before = self.chain.supply.balances.get(self.bob.entity_id, 0)
        self.chain._apply_governance_block(b_close)
        bob_after = self.chain.supply.balances.get(self.bob.entity_id, 0)

        self.assertEqual(bob_after - bob_before, 5_000)
        # Audit log records the spend
        self.assertEqual(len(self.chain.governance.treasury_spend_log), 1)

    def test_closed_proposals_pruned(self):
        proposal = create_proposal(
            self.alice, "Something", "Details",
        )
        proposal_block = 5
        b1 = _make_block(proposal_block, self.alice.entity_id, [proposal])
        self.chain._apply_governance_block(b1)
        self.assertIn(proposal.proposal_id, self.chain.governance.proposals)

        # Far past voting window, pruning removes the proposal
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 2
        self.chain._apply_governance_block(
            _make_block(closed_block, self.alice.entity_id, [])
        )
        self.assertNotIn(proposal.proposal_id, self.chain.governance.proposals)


if __name__ == "__main__":
    unittest.main()
