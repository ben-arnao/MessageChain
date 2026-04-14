"""Tests for governance-driven validator ejection.

Holders (validators and liquid holders alike) can vote to eject a misbehaving
validator. On passing a 2/3 supermajority after the standard voting window,
the target's stake is moved to the unbonding queue and the validator is
removed from the active set. Ejection is the penalty; no extra slashing.

This is the on-chain lever that lets non-validator holders influence "which
nodes the network trusts" — the only governance-legitimate way to reshape
the validator set without introducing bonded delegation / DPoS.
"""

import unittest
from messagechain.governance.governance import (
    GovernanceTracker,
    ValidatorEjectionProposal,
    VoteTransaction,
    create_validator_ejection_proposal,
    verify_validator_ejection,
)
from messagechain.consensus.pos import ProofOfStake
from messagechain.economics.inflation import SupplyTracker
from messagechain.identity.identity import Entity
from messagechain.config import (
    GOVERNANCE_PROPOSAL_FEE,
    GOVERNANCE_VOTE_FEE,
    GOVERNANCE_VOTING_WINDOW,
    UNBONDING_PERIOD,
    VALIDATOR_MIN_STAKE,
)


def _cast_vote(tracker, voter_id, proposal_id, approve, current_block):
    """Build and record an unsigned vote (tests bypass signature checks)."""
    vote = VoteTransaction(
        voter_id=voter_id,
        proposal_id=proposal_id,
        approve=approve,
        timestamp=1.0,
        fee=GOVERNANCE_VOTE_FEE,
        signature=None,
    )
    vote.tx_hash = vote._compute_hash()
    return tracker.add_vote(vote, current_block=current_block)


class TestValidatorEjectionProposalTx(unittest.TestCase):
    """Ejection proposal transaction: signing, verification, serialization."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-eject-tests".ljust(32, b"\x00"))
        cls.bad_validator = Entity.create(b"bad-validator".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_create_and_verify(self):
        tx = create_validator_ejection_proposal(
            self.alice,
            self.bad_validator.entity_id,
            "Eject BadValidator",
            "Has been double-signing blocks per off-chain evidence ABC",
        )
        self.assertTrue(verify_validator_ejection(tx, self.alice.public_key))
        self.assertEqual(tx.target_validator_id, self.bad_validator.entity_id)

    def test_fee_below_minimum_rejected(self):
        tx = create_validator_ejection_proposal(
            self.alice, self.bad_validator.entity_id, "E", "d",
            fee=GOVERNANCE_PROPOSAL_FEE - 1,
        )
        self.assertFalse(verify_validator_ejection(tx, self.alice.public_key))

    def test_empty_title_rejected(self):
        tx = create_validator_ejection_proposal(
            self.alice, self.bad_validator.entity_id, "", "no title",
        )
        self.assertFalse(verify_validator_ejection(tx, self.alice.public_key))

    def test_missing_target_rejected(self):
        tx = create_validator_ejection_proposal(
            self.alice, b"", "Eject", "no target",
        )
        self.assertFalse(verify_validator_ejection(tx, self.alice.public_key))

    def test_serialization_roundtrip(self):
        tx = create_validator_ejection_proposal(
            self.alice, self.bad_validator.entity_id,
            "Eject BadValidator", "Extensive justification here",
        )
        restored = ValidatorEjectionProposal.deserialize(tx.serialize())
        self.assertEqual(restored.tx_hash, tx.tx_hash)
        self.assertEqual(restored.target_validator_id, tx.target_validator_id)
        self.assertEqual(restored.title, tx.title)
        self.assertEqual(restored.proposal_id, tx.proposal_id)
        self.assertTrue(verify_validator_ejection(restored, self.alice.public_key))

    def test_tamper_detected(self):
        """Any field change invalidates the signature."""
        tx = create_validator_ejection_proposal(
            self.alice, self.bad_validator.entity_id, "Eject", "why",
        )
        data = tx.serialize()
        data["target_validator_id"] = (b"\x99" * 32).hex()
        with self.assertRaises(ValueError):
            ValidatorEjectionProposal.deserialize(data)


class TestValidatorEjectionExecution(unittest.TestCase):
    """End-to-end: propose → vote → close window → execute → side effects."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-exec-tests".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-exec-tests".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-exec-tests".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0
        self.bob.keypair._next_leaf = 0
        self.carol.keypair._next_leaf = 0

        self.tracker = GovernanceTracker()
        self.supply = SupplyTracker()
        self.pos = ProofOfStake()

        # Alice and Carol are honest validators. Bob is the target.
        # Give each enough stake that removing any one doesn't kill the floor
        # if MIN_TOTAL_STAKE is in effect.
        self.alice_stake = 10_000
        self.bob_stake = 10_000
        self.carol_stake = 10_000
        self.supply.staked[self.alice.entity_id] = self.alice_stake
        self.supply.staked[self.bob.entity_id] = self.bob_stake
        self.supply.staked[self.carol.entity_id] = self.carol_stake
        self.pos.register_validator(self.alice.entity_id, self.alice_stake)
        self.pos.register_validator(self.bob.entity_id, self.bob_stake)
        self.pos.register_validator(self.carol.entity_id, self.carol_stake)

    def _submit_proposal(self, proposal_block=10):
        tx = create_validator_ejection_proposal(
            self.alice, self.bob.entity_id,
            "Eject Bob", "Bob is misbehaving",
        )
        self.tracker.add_proposal(
            tx, block_height=proposal_block, supply_tracker=self.supply,
        )
        return tx, proposal_block

    def test_execution_before_window_closes_rejected(self):
        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        # Window still open
        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=proposal_block + 1,
        )
        self.assertFalse(result)
        self.assertIn(self.bob.entity_id, self.pos.stakes)

    def test_execution_below_supermajority_rejected(self):
        """Yes share below 2/3 of participating weight → rejected."""
        tx, proposal_block = self._submit_proposal()
        # Alice yes, Carol no — yes = 10k / total = 20k = 50%, below 2/3
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, False, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        self.assertFalse(result)
        self.assertIn(self.bob.entity_id, self.pos.stakes)
        self.assertEqual(self.supply.get_staked(self.bob.entity_id), self.bob_stake)

    def test_execution_removes_validator_and_unbonds_stake(self):
        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1

        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        self.assertTrue(result)

        # Validator removed from active set
        self.assertNotIn(self.bob.entity_id, self.pos.stakes)
        # Stake immediately moved out of staked balance
        self.assertEqual(self.supply.get_staked(self.bob.entity_id), 0)
        # Full stake now pending unbonding
        self.assertEqual(self.supply.get_pending_unstake(self.bob.entity_id), self.bob_stake)
        # Not yet in liquid balance — unbonding period must pass
        self.assertEqual(self.supply.get_balance(self.bob.entity_id), 0)

    def test_ejected_stake_releases_after_unbonding_period(self):
        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        # Before release
        self.supply.process_pending_unstakes(current_block=closed_block + UNBONDING_PERIOD - 1)
        self.assertEqual(self.supply.get_balance(self.bob.entity_id), 0)
        # After release
        self.supply.process_pending_unstakes(current_block=closed_block + UNBONDING_PERIOD)
        self.assertEqual(self.supply.get_balance(self.bob.entity_id), self.bob_stake)

    def test_execution_replay_rejected(self):
        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        self.assertTrue(self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        ))
        # Second execution must fail — target already ejected
        self.assertFalse(self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        ))

    def test_execution_without_proposal_on_chain_rejected(self):
        """Execute must fail if the proposal was never registered."""
        tx = create_validator_ejection_proposal(
            self.alice, self.bob.entity_id, "Eject Bob", "no proposal registered",
        )
        # Note: did NOT call add_proposal
        closed_block = GOVERNANCE_VOTING_WINDOW + 100
        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        self.assertFalse(result)

    def test_execution_revokes_delegations_to_ejected_validator(self):
        """Delegators pointing at the ejected validator are cleared."""
        delegator = b"\xAA" * 32
        other_delegator = b"\xBB" * 32
        self.tracker.set_delegation(delegator, [(self.bob.entity_id, 100)])
        self.tracker.set_delegation(other_delegator, [(self.carol.entity_id, 100)])

        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )

        self.assertNotIn(delegator, self.tracker.delegations)
        # Unrelated delegation preserved
        self.assertIn(other_delegator, self.tracker.delegations)

    def test_target_vote_is_excluded(self):
        """Target cannot vote in their own ejection — their vote is ignored."""
        tx, proposal_block = self._submit_proposal()
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        # Bob (the target) tries to vote no to block the ejection
        _cast_vote(self.tracker, self.bob.entity_id, tx.proposal_id, False, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        # Target's no vote is excluded — alice + carol = 100% yes among eligible voters
        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        self.assertTrue(result)
        self.assertNotIn(self.bob.entity_id, self.pos.stakes)

    def test_auto_delegation_capture_prevented(self):
        """A lone voter cannot eject peers by harvesting passive stake.

        Under the general governance tally, passive holders' stake auto-
        delegates to whichever validators actually voted — meaning a single
        motivated validator could eject peers by themselves, amplified by
        everyone else's silence.  Ejection must require active engagement,
        so its custom tally disables auto-delegation entirely.
        """
        tx, proposal_block = self._submit_proposal()
        # Only alice votes; carol and bob stay silent (passive stake should
        # NOT flow to alice under the ejection-specific tally).
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        result = self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        )
        self.assertFalse(result)
        self.assertIn(self.bob.entity_id, self.pos.stakes)


class TestEjectionAboveExactSupermajority(unittest.TestCase):
    """A clear supermajority (>2/3) passes the ejection."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-clear".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-clear".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-clear".ljust(32, b"\x00"))
        cls.dave = Entity.create(b"dave-clear".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol, self.dave):
            e.keypair._next_leaf = 0

        self.tracker = GovernanceTracker()
        self.supply = SupplyTracker()
        self.pos = ProofOfStake()
        # 4 validators, ejecting bob. Alice + Carol + Dave = 30k vs Bob = 10k
        # → 30k/40k = 75% > 2/3
        for e, amt in (
            (self.alice, 10_000), (self.bob, 10_000),
            (self.carol, 10_000), (self.dave, 10_000),
        ):
            self.supply.staked[e.entity_id] = amt
            self.pos.register_validator(e.entity_id, amt)

    def test_clear_supermajority_ejects(self):
        tx = create_validator_ejection_proposal(
            self.alice, self.bob.entity_id, "Eject Bob", "Justified",
        )
        proposal_block = 5
        self.tracker.add_proposal(
            tx, block_height=proposal_block, supply_tracker=self.supply,
        )
        _cast_vote(self.tracker, self.alice.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.carol.entity_id, tx.proposal_id, True, proposal_block + 1)
        _cast_vote(self.tracker, self.dave.entity_id, tx.proposal_id, True, proposal_block + 1)
        closed_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1

        self.assertTrue(self.tracker.execute_validator_ejection(
            tx, self.supply, self.pos, current_block=closed_block,
        ))
        self.assertNotIn(self.bob.entity_id, self.pos.stakes)


if __name__ == "__main__":
    unittest.main()
