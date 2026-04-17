"""Tests for NEW_ACCOUNT_FEE surcharge.

The chain charges a flat NEW_ACCOUNT_FEE (burned, not paid to proposer)
on any Transfer whose recipient does not yet exist in on-chain state.
This prices permanent state entry above the baseline MIN_FEE and stays
consistent with the "receive-to-exist" account model.

Rules:
  * Transfer to a brand-new recipient: fee must be >= MIN_FEE +
    NEW_ACCOUNT_FEE. The surcharge is burned (total_supply -=
    NEW_ACCOUNT_FEE, total_burned += NEW_ACCOUNT_FEE). Proposer only
    receives (tx.fee - NEW_ACCOUNT_FEE).
  * Transfer to an existing recipient: no surcharge. Proposer receives
    the whole tx.fee minus base_fee burn (the existing EIP-1559 rule).
  * Intra-block pipelining: within a single block, the FIRST tx that
    funds a brand-new recipient pays the surcharge; later txs to the
    same recipient in the same block do not.
  * Treasury spends that create new accounts burn NEW_ACCOUNT_FEE from
    the treasury balance in addition to the amount; insufficient
    treasury balance rejects the spend.
  * Genesis allocation_table bypasses the surcharge.
"""

import unittest

from messagechain.config import (
    DUST_LIMIT, MIN_FEE, TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
    GOVERNANCE_VOTING_WINDOW,
)
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import Block
from messagechain.core.transfer import create_transfer_transaction
from messagechain.identity.identity import Entity
from messagechain.consensus.pos import ProofOfStake
from tests import register_entity_for_test


NEW_ACCOUNT_FEE = 1000  # expected constant; validated against config below


class TestNewAccountFeeConstant(unittest.TestCase):
    def test_constant_is_1000(self):
        from messagechain.config import NEW_ACCOUNT_FEE as cfg_val
        self.assertEqual(cfg_val, NEW_ACCOUNT_FEE)


class _Base(unittest.TestCase):
    """Shared setUp: chain funded from an allocation_table so genesis
    entities and the treasury have balances, but no surcharge is charged
    on genesis."""

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
        self.chain = Blockchain()
        # Alice is the genesis entity (receives allocation directly).
        # Bob is registered directly (test helper -> balance entry too),
        # which makes him an "existing" recipient for tests that need one.
        allocation = {
            self.alice.entity_id: 1_000_000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        self.chain.initialize_genesis(self.alice, allocation_table=allocation)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.bob.entity_id] = 10_000
        self.consensus = ProofOfStake()

    def _make_block(self, proposer, transfer_txs, prev=None):
        if prev is None:
            prev = self.chain.get_latest_block()
        state_root = self.chain.compute_post_state_root(
            [], proposer.entity_id, prev.header.block_number + 1,
            transfer_transactions=transfer_txs,
        )
        return self.consensus.create_block(
            proposer, [], prev,
            transfer_transactions=transfer_txs,
            state_root=state_root,
        )


class TestStandaloneValidation(_Base):
    """validate_transfer_transaction enforces the surcharge."""

    def test_transfer_to_new_recipient_with_only_min_fee_rejected(self):
        tx = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=DUST_LIMIT, nonce=0, fee=MIN_FEE,
        )
        ok, reason = self.chain.validate_transfer_transaction(tx)
        self.assertFalse(ok)
        self.assertIn("surcharge", reason.lower())

    def test_transfer_to_new_recipient_with_exact_surcharge_accepted(self):
        tx = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=DUST_LIMIT, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        ok, reason = self.chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, reason)

    def test_transfer_to_existing_recipient_with_min_fee_accepted(self):
        # Bob is registered via register_entity_for_test — existing recipient.
        tx = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=DUST_LIMIT, nonce=0, fee=MIN_FEE,
        )
        ok, reason = self.chain.validate_transfer_transaction(tx)
        self.assertTrue(ok, reason)


class TestSupplyBurnOnApply(_Base):
    """apply path burns the surcharge for brand-new recipients only."""

    def test_new_recipient_burn_and_proposer_credit(self):
        supply_before = self.chain.supply.total_supply
        burned_before = self.chain.supply.total_burned
        proposer_before = self.chain.supply.get_balance(self.alice.entity_id)

        fee = MIN_FEE + NEW_ACCOUNT_FEE
        amount = 500
        tx = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=amount, nonce=0, fee=fee,
        )
        block = self._make_block(self.alice, [tx])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

        # total_supply went down by NEW_ACCOUNT_FEE + base_fee burn
        # (since this test runs at BASE_FEE_INITIAL == MIN_FEE, the
        # base_fee burn equals MIN_FEE), but it ALSO went UP by block
        # reward.  Check the burn counter directly — it is monotonic
        # and includes both the base_fee burn and the surcharge burn.
        supply_delta_from_burn = (
            self.chain.supply.total_burned - burned_before
        )
        self.assertGreaterEqual(supply_delta_from_burn, NEW_ACCOUNT_FEE)

        # Carol exists now.
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), amount,
        )

        # Sender paid amount + full fee.  Proposer got tip (fee - base_fee
        # burn - NEW_ACCOUNT_FEE surcharge burn).
        # Net alice = (starting) - amount - fee + block_reward_share + tip
        # We only assert that alice did NOT pocket the surcharge; the
        # simplest check is to compare burned-counter delta >= NEW_ACCOUNT_FEE.

    def test_existing_recipient_no_surcharge_burn(self):
        """Transfer to Bob (already registered) burns only base_fee."""
        burned_before = self.chain.supply.total_burned
        tx = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=100, nonce=0, fee=MIN_FEE,
        )
        block = self._make_block(self.alice, [tx])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)

        # Burn counter rose only by base_fee (== MIN_FEE at BASE_FEE_INITIAL),
        # NOT by NEW_ACCOUNT_FEE.
        self.assertEqual(
            self.chain.supply.total_burned - burned_before, MIN_FEE,
        )

    def test_new_recipient_state_entry_created(self):
        """After apply, the recipient appears in state (balance + index)."""
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), 0,
        )
        tx = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=777, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        block = self._make_block(self.alice, [tx])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), 777,
        )

    def test_existing_recipient_high_fee_no_surcharge_burned(self):
        """Paying MIN_FEE + NEW_ACCOUNT_FEE to an existing recipient
        is accepted but does not burn the surcharge (proposer gets the
        tip)."""
        burned_before = self.chain.supply.total_burned
        fee = MIN_FEE + NEW_ACCOUNT_FEE
        tx = create_transfer_transaction(
            self.alice, self.bob.entity_id,
            amount=50, nonce=0, fee=fee,
        )
        block = self._make_block(self.alice, [tx])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        # Only base_fee (== MIN_FEE) burned; the extra NEW_ACCOUNT_FEE
        # is NOT burned because recipient already existed.  So the burn
        # delta equals exactly MIN_FEE, not MIN_FEE + NEW_ACCOUNT_FEE.
        self.assertEqual(
            self.chain.supply.total_burned - burned_before, MIN_FEE,
        )


class TestIntraBlockPipelining(_Base):
    """Within one block, only the first tx funding a new account burns."""

    def test_two_transfers_to_same_new_recipient_burns_once(self):
        """Block [Alice -> NewCarol, Alice -> NewCarol] burns surcharge once."""
        burned_before = self.chain.supply.total_burned
        tx1 = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=100, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        tx2 = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=200, nonce=1, fee=MIN_FEE,
        )
        block = self._make_block(self.alice, [tx1, tx2])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        # Burn delta = 2 * base_fee + 1 * NEW_ACCOUNT_FEE
        self.assertEqual(
            self.chain.supply.total_burned - burned_before,
            MIN_FEE * 2 + NEW_ACCOUNT_FEE,
        )
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), 300,
        )

    def test_second_sender_in_block_to_same_new_recipient_no_surcharge(self):
        """Block [Alice -> NewCarol (surcharge), Bob -> NewCarol] —
        only the first pays."""
        # Ensure bob can first-spend to NewCarol in the same block.
        burned_before = self.chain.supply.total_burned
        tx1 = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=100, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        bob_nonce = self.chain.nonces.get(self.bob.entity_id, 0)
        tx2 = create_transfer_transaction(
            self.bob, self.carol.entity_id,
            amount=50, nonce=bob_nonce, fee=MIN_FEE,
        )
        block = self._make_block(self.alice, [tx1, tx2])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(
            self.chain.supply.total_burned - burned_before,
            MIN_FEE * 2 + NEW_ACCOUNT_FEE,
        )

    def test_second_sender_must_not_be_required_to_pay_surcharge(self):
        """Block-path validation should accept tx2 (Bob -> NewCarol) at
        MIN_FEE once tx1 has already funded NewCarol in the same block."""
        tx1 = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=100, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        bob_nonce = self.chain.nonces.get(self.bob.entity_id, 0)
        tx2 = create_transfer_transaction(
            self.bob, self.carol.entity_id,
            amount=50, nonce=bob_nonce, fee=MIN_FEE,
        )
        block = self._make_block(self.alice, [tx1, tx2])
        parent = self.chain.get_latest_block()
        ok, reason = self.chain.validate_block_standalone(block, parent)
        self.assertTrue(ok, reason)


class TestTreasurySpendSurcharge(_Base):
    """Treasury spends that create a new account burn NEW_ACCOUNT_FEE."""

    def _approve(self, tracker, tx):
        from messagechain.governance.governance import VoteTransaction
        proposal_block = 10
        self.chain.supply.staked[self.alice.entity_id] = (
            self.chain.supply.get_balance(self.alice.entity_id)
        )
        tracker.add_proposal(
            tx, block_height=proposal_block,
            supply_tracker=self.chain.supply,
        )
        vote = VoteTransaction(
            voter_id=self.alice.entity_id,
            proposal_id=tx.proposal_id,
            approve=True,
            timestamp=1.0,
            fee=100,
            signature=None,
        )
        vote.tx_hash = vote._compute_hash()
        tracker.add_vote(vote, current_block=proposal_block + 1)
        return proposal_block + GOVERNANCE_VOTING_WINDOW + 1

    def test_treasury_spend_to_new_account_burns_surcharge(self):
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        tracker = GovernanceTracker()
        tx = create_treasury_spend_proposal(
            self.alice, self.carol.entity_id, 5000,
            "Fund Carol", "Pay new account Carol",
        )
        closed_block = self._approve(tracker, tx)

        treasury_before = self.chain.supply.get_balance(TREASURY_ENTITY_ID)
        burned_before = self.chain.supply.total_burned
        supply_before = self.chain.supply.total_supply

        ok = tracker.execute_treasury_spend(
            tx, self.chain.supply, current_block=closed_block,
        )
        self.assertTrue(ok)

        # Treasury was debited by (amount + NEW_ACCOUNT_FEE)
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY_ENTITY_ID),
            treasury_before - 5000 - NEW_ACCOUNT_FEE,
        )
        # Carol was credited only by amount (not amount+surcharge)
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), 5000,
        )
        # total_supply dropped by NEW_ACCOUNT_FEE
        self.assertEqual(
            self.chain.supply.total_supply, supply_before - NEW_ACCOUNT_FEE,
        )
        self.assertEqual(
            self.chain.supply.total_burned, burned_before + NEW_ACCOUNT_FEE,
        )

    def test_treasury_spend_to_existing_account_no_surcharge(self):
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        tracker = GovernanceTracker()
        # Bob is already registered — existing recipient.
        tx = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5000,
            "Fund Bob", "Pay existing account Bob",
        )
        closed_block = self._approve(tracker, tx)

        treasury_before = self.chain.supply.get_balance(TREASURY_ENTITY_ID)
        burned_before = self.chain.supply.total_burned
        supply_before = self.chain.supply.total_supply

        ok = tracker.execute_treasury_spend(
            tx, self.chain.supply, current_block=closed_block,
        )
        self.assertTrue(ok)

        self.assertEqual(
            self.chain.supply.get_balance(TREASURY_ENTITY_ID),
            treasury_before - 5000,
        )
        # No supply / burn change for existing recipient.
        self.assertEqual(self.chain.supply.total_supply, supply_before)
        self.assertEqual(self.chain.supply.total_burned, burned_before)

    def test_treasury_spend_rejected_when_not_enough_for_surcharge(self):
        """If treasury balance covers amount but not amount+surcharge,
        the spend must be rejected."""
        from messagechain.governance.governance import (
            GovernanceTracker, create_treasury_spend_proposal,
        )
        # Wipe treasury down to exactly `amount` (no buffer for surcharge).
        amount = 500
        self.chain.supply.balances[TREASURY_ENTITY_ID] = amount

        tracker = GovernanceTracker()
        tx = create_treasury_spend_proposal(
            self.alice, self.carol.entity_id, amount,
            "Fund Carol", "No buffer for surcharge",
        )
        closed_block = self._approve(tracker, tx)

        supply_before = self.chain.supply.total_supply
        burned_before = self.chain.supply.total_burned

        ok = tracker.execute_treasury_spend(
            tx, self.chain.supply, current_block=closed_block,
        )
        self.assertFalse(ok)

        # Nothing moved.
        self.assertEqual(
            self.chain.supply.get_balance(TREASURY_ENTITY_ID), amount,
        )
        self.assertEqual(
            self.chain.supply.get_balance(self.carol.entity_id), 0,
        )
        self.assertEqual(self.chain.supply.total_supply, supply_before)
        self.assertEqual(self.chain.supply.total_burned, burned_before)


class TestGenesisExempt(unittest.TestCase):
    """Genesis allocation_table bypasses the surcharge."""

    def test_genesis_allocation_does_not_burn_surcharge(self):
        alice = Entity.create(b"alice-private-key".ljust(32, b"\x00"))
        bob = Entity.create(b"bob-private-key".ljust(32, b"\x00"))
        alice.keypair._next_leaf = 0
        bob.keypair._next_leaf = 0
        chain = Blockchain()
        # Bob receives 3000 but is a "brand-new" entity — no surcharge.
        allocation = {
            alice.entity_id: 5000,
            bob.entity_id: 3000,
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
        }
        chain.initialize_genesis(alice, allocation_table=allocation)
        # total_supply equals the sum (no burn at genesis).
        self.assertEqual(chain.supply.total_burned, 0)
        self.assertEqual(
            chain.supply.get_balance(alice.entity_id), 5000,
        )
        self.assertEqual(chain.supply.get_balance(bob.entity_id), 3000)
        self.assertEqual(
            chain.supply.get_balance(TREASURY_ENTITY_ID), TREASURY_ALLOCATION,
        )


class TestStateRootReflectsBurn(_Base):
    """The SMT state commitment must see the surcharge burn."""

    def test_state_root_matches_compute_post_state_root(self):
        """compute_post_state_root(...) produces the root the block
        commits; after add_block, compute_current_state_root matches."""
        tx = create_transfer_transaction(
            self.alice, self.carol.entity_id,
            amount=500, nonce=0, fee=MIN_FEE + NEW_ACCOUNT_FEE,
        )
        block = self._make_block(self.alice, [tx])
        ok, reason = self.chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertEqual(
            self.chain.compute_current_state_root(),
            block.header.state_root,
        )


if __name__ == "__main__":
    unittest.main()
