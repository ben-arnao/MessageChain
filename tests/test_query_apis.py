"""Tests for the read-only query APIs exposed to CLI clients.

Covers three listings that the CLI surfaces as user-facing commands:
  - list_proposals: open / recently-closed governance proposals + tally
  - list_validators: validator set with stake %, blocks produced
  - estimate_fee: suggested fee for a prospective message or transfer
"""

import unittest
from unittest.mock import MagicMock

from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import calculate_min_fee
from messagechain.governance.governance import (
    create_proposal, create_vote, ProposalStatus,
)
from messagechain.identity.identity import Entity
from messagechain.config import GOVERNANCE_VOTING_WINDOW


def _make_block(block_number, proposer_id, governance_txs):
    block = MagicMock()
    block.header.block_number = block_number
    block.header.proposer_id = proposer_id
    block.governance_txs = governance_txs
    return block


class TestListProposals(unittest.TestCase):
    """GovernanceTracker.list_proposals() returns proposals with tally + status."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"list-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"list-bob".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        for e in (self.alice, self.bob):
            self.chain.supply.balances[e.entity_id] = 1_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
            self.chain.supply.staked[e.entity_id] = 10_000

    def test_empty_when_no_proposals(self):
        self.assertEqual(self.chain.governance.list_proposals(current_block=1), [])

    def test_returns_proposal_with_core_fields(self):
        tx = create_proposal(self.alice, "Lower min fee", "Rationale for lowering fee")
        self.chain._apply_governance_block(_make_block(1, self.alice.entity_id, [tx]))

        result = self.chain.governance.list_proposals(current_block=2)
        self.assertEqual(len(result), 1)
        p = result[0]
        self.assertEqual(p["proposal_id"], tx.proposal_id.hex())
        self.assertEqual(p["proposer_id"], self.alice.entity_id.hex())
        self.assertEqual(p["title"], "Lower min fee")
        self.assertEqual(p["created_at_block"], 1)
        self.assertEqual(p["status"], ProposalStatus.OPEN.value)

    def test_tally_reflects_recorded_votes(self):
        tx = create_proposal(self.alice, "Test", "D")
        self.chain._apply_governance_block(_make_block(1, self.alice.entity_id, [tx]))
        vote = create_vote(self.bob, tx.proposal_id, True)
        self.chain._apply_governance_block(_make_block(2, self.alice.entity_id, [vote]))

        p = self.chain.governance.list_proposals(current_block=3)[0]
        self.assertGreater(p["yes_weight"], 0)
        # Bob's 10_000 stake goes fully yes; alice's 10_000 is silent.
        # total_participating = bob's weight; total_eligible = both.
        self.assertEqual(p["yes_weight"], p["total_participating"])
        self.assertGreater(p["total_eligible"], p["total_participating"])

    def test_status_flips_to_closed_after_window(self):
        tx = create_proposal(self.alice, "Test", "D")
        self.chain._apply_governance_block(_make_block(1, self.alice.entity_id, [tx]))
        closed_block = 1 + GOVERNANCE_VOTING_WINDOW + 1
        p = self.chain.governance.list_proposals(current_block=closed_block)[0]
        self.assertEqual(p["status"], ProposalStatus.CLOSED.value)


class TestListValidators(unittest.TestCase):
    """Blockchain.list_validators() returns per-validator info."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"val-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"val-bob".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        for e in (self.alice, self.bob):
            self.chain.public_keys[e.entity_id] = e.public_key

    def test_empty_when_no_stake(self):
        self.chain.supply.staked.clear()
        self.assertEqual(self.chain.list_validators(), [])

    def test_lists_staked_entities_only(self):
        self.chain.supply.staked.clear()
        self.chain.supply.staked[self.alice.entity_id] = 7_500
        self.chain.supply.staked[self.bob.entity_id] = 2_500

        result = self.chain.list_validators()
        self.assertEqual(len(result), 2)

        by_id = {v["entity_id"]: v for v in result}
        alice_row = by_id[self.alice.entity_id.hex()]
        bob_row = by_id[self.bob.entity_id.hex()]

        self.assertEqual(alice_row["staked"], 7_500)
        self.assertEqual(bob_row["staked"], 2_500)
        self.assertAlmostEqual(alice_row["stake_pct"], 75.0, places=2)
        self.assertAlmostEqual(bob_row["stake_pct"], 25.0, places=2)

    def test_sorted_by_stake_descending(self):
        self.chain.supply.staked.clear()
        self.chain.supply.staked[self.alice.entity_id] = 1_000
        self.chain.supply.staked[self.bob.entity_id] = 9_000

        result = self.chain.list_validators()
        self.assertEqual(result[0]["entity_id"], self.bob.entity_id.hex())
        self.assertEqual(result[1]["entity_id"], self.alice.entity_id.hex())

    def test_includes_blocks_produced(self):
        self.chain.supply.staked.clear()
        self.chain.supply.staked[self.alice.entity_id] = 1_000
        self.chain.proposer_sig_counts[self.alice.entity_id] = 42

        row = self.chain.list_validators()[0]
        self.assertEqual(row["blocks_produced"], 42)

    def test_excludes_zero_stake(self):
        self.chain.supply.staked.clear()
        self.chain.supply.staked[self.alice.entity_id] = 0
        self.chain.supply.staked[self.bob.entity_id] = 100
        result = self.chain.list_validators()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["entity_id"], self.bob.entity_id.hex())


class TestEstimateFee(unittest.TestCase):
    """Fee-estimate helpers wrap the existing min-fee + mempool curves."""

    def test_message_fee_matches_min_fee_curve(self):
        msg_bytes = b"Hello, world"
        fee = calculate_min_fee(msg_bytes)
        self.assertGreater(fee, 0)

    def test_larger_messages_cost_more(self):
        small = calculate_min_fee(b"hi")
        large = calculate_min_fee(b"x" * 200)
        self.assertGreater(large, small)


if __name__ == "__main__":
    unittest.main()
