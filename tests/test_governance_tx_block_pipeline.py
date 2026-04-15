"""
Governance transactions must flow through the block pipeline with their
state_root commitment correctly predicted by compute_post_state_root.

Prior to this, `compute_post_state_root` simulated message/transfer/
authority/stake/unstake but NOT governance.  A block containing any
governance tx (or triggering an auto-executed treasury-spend or
validator-ejection) hit a state_root mismatch and was rejected — even
by its own proposer.  Governance was effectively library-only despite
the rest of the plumbing being there.

These tests prove the end-to-end block pipeline:
1. A block carrying a ProposalTransaction commits to the right state_root
2. A block carrying a VoteTransaction commits to the right state_root
3. A block whose block_height closes a binding proposal's window auto-
   executes the treasury spend and the state_root matches.
4. Same for ValidatorEjectionProposal auto-execution.
"""

import unittest
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.governance.governance import (
    create_proposal, create_vote,
    create_treasury_spend_proposal, create_validator_ejection_proposal,
)
from messagechain.identity.identity import Entity
from messagechain.config import (
    TREASURY_ENTITY_ID, TREASURY_ALLOCATION,
    GOVERNANCE_PROPOSAL_FEE, GOVERNANCE_VOTE_FEE, MIN_FEE,
)

# Overridden in _Base.setUp for fast tests — read from config at call time.
def _window():
    from messagechain import config
    return config.GOVERNANCE_VOTING_WINDOW
from tests import pick_selected_proposer


def _entity(seed: bytes) -> Entity:
    return Entity.create(seed.ljust(32, b"\x00"))


class _Base(unittest.TestCase):
    def setUp(self):
        from messagechain import config
        from messagechain.governance import governance as gov_mod
        self._orig_height = config.MERKLE_TREE_HEIGHT
        self._orig_window_cfg = config.GOVERNANCE_VOTING_WINDOW
        self._orig_window_gov = gov_mod.GOVERNANCE_VOTING_WINDOW
        # Short window keeps the per-test block count small enough to fit
        # in the default test Merkle tree without exhausting leaves.
        config.MERKLE_TREE_HEIGHT = 6
        config.GOVERNANCE_VOTING_WINDOW = 5
        gov_mod.GOVERNANCE_VOTING_WINDOW = 5

    def tearDown(self):
        from messagechain import config
        from messagechain.governance import governance as gov_mod
        config.MERKLE_TREE_HEIGHT = self._orig_height
        config.GOVERNANCE_VOTING_WINDOW = self._orig_window_cfg
        gov_mod.GOVERNANCE_VOTING_WINDOW = self._orig_window_gov

    def _register(self, chain, entity):
        from messagechain.crypto.hash_sig import _hash
        proof = entity.keypair.sign(_hash(b"register" + entity.entity_id))
        chain.register_entity(entity.entity_id, entity.public_key, proof)


class TestGovernanceTxInBlock(_Base):
    """A block carrying governance txs must round-trip + apply cleanly."""

    def _make_chain(self):
        alice = _entity(b"gov-block-alice")
        alice.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(
            alice,
            allocation_table={
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                alice.entity_id: 1_000_000,
            },
        )
        # Stake alice so votes have weight
        chain.supply.staked[alice.entity_id] = 10_000
        return chain, alice

    def test_proposal_block_applies_cleanly(self):
        chain, alice = self._make_chain()
        proposal = create_proposal(alice, "Protocol change", "Rationale")

        consensus = ProofOfStake()
        block = chain.propose_block(
            consensus, alice, [],
            governance_txs=[proposal],
        )
        ok, reason = chain.add_block(block)
        self.assertTrue(ok, reason)
        self.assertIn(proposal.proposal_id, chain.governance.proposals)

    def test_vote_block_applies_cleanly(self):
        chain, alice = self._make_chain()
        proposal = create_proposal(alice, "Change", "Details")
        proposal_block = 1
        consensus = ProofOfStake()
        b1 = chain.propose_block(
            consensus, alice, [],
            governance_txs=[proposal],
        )
        self.assertTrue(chain.add_block(b1)[0])

        vote = create_vote(alice, proposal.proposal_id, True)
        b2 = chain.propose_block(
            consensus, alice, [],
            governance_txs=[vote],
        )
        ok, reason = chain.add_block(b2)
        self.assertTrue(ok, reason)
        state = chain.governance.proposals[proposal.proposal_id]
        self.assertIn(alice.entity_id, state.votes)


class TestAutoExecuteThroughBlock(_Base):
    """State_root must correctly predict auto-executed binding outcomes."""

    def _make_three_validator_chain(self):
        """Three staked validators so a 2/3-of-eligible vote can pass."""
        alice = _entity(b"gov-auto-alice")
        bob = _entity(b"gov-auto-bob")
        carol = _entity(b"gov-auto-carol")
        for e in (alice, bob, carol):
            e.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(
            alice,
            allocation_table={
                TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
                alice.entity_id: 1_000_000,
                bob.entity_id: 1_000_000,
                carol.entity_id: 1_000_000,
            },
        )
        self._register(chain, bob)
        self._register(chain, carol)
        for e in (alice, bob, carol):
            chain.supply.staked[e.entity_id] = 10_000
        return chain, alice, bob, carol

    def _advance(self, chain, consensus, candidates, count: int):
        """Produce `count` empty blocks — each by its correct proposer."""
        for _ in range(count):
            p = pick_selected_proposer(chain, candidates)
            block = chain.propose_block(consensus, p, [])
            ok, reason = chain.add_block(block)
            self.assertTrue(ok, reason)

    def test_treasury_spend_auto_executes_through_block_pipeline(self):
        chain, alice, bob, carol = self._make_three_validator_chain()
        consensus = ProofOfStake()
        candidates = [alice, bob, carol]

        spend = create_treasury_spend_proposal(
            alice, bob.entity_id, 5_000,
            "Fund work", "Pay Bob",
        )
        p1 = pick_selected_proposer(chain, candidates)
        b1 = chain.propose_block(consensus, p1, [], governance_txs=[spend])
        ok, reason = chain.add_block(b1)
        self.assertTrue(ok, f"b1 rejected: {reason}")

        # Block 2: all three vote yes (binding tally needs > 2/3 of
        # total eligible stake)
        votes = [
            create_vote(alice, spend.proposal_id, True),
            create_vote(bob, spend.proposal_id, True),
            create_vote(carol, spend.proposal_id, True),
        ]
        p2 = pick_selected_proposer(chain, candidates)
        b2 = chain.propose_block(consensus, p2, [], governance_txs=votes)
        ok, reason = chain.add_block(b2)
        self.assertTrue(ok, reason)

        # Advance past the voting window.  The block that crosses the
        # threshold is where auto-execute fires — state_root must predict it.
        # We assert on the treasury_spend_log (immune to block reward
        # deltas that also occur in this window) rather than absolute
        # balance changes.
        self._advance(chain, consensus, candidates, _window() + 1)
        self.assertEqual(len(chain.governance.treasury_spend_log), 1)
        entry = chain.governance.treasury_spend_log[0]
        self.assertEqual(entry["recipient_id"], bob.entity_id.hex())
        self.assertEqual(entry["amount"], 5_000)

    def test_ejection_auto_executes_through_block_pipeline(self):
        chain, alice, bob, carol = self._make_three_validator_chain()
        consensus = ProofOfStake()
        candidates = [alice, bob, carol]

        ejection = create_validator_ejection_proposal(
            alice, bob.entity_id,
            "Eject Bob", "Bob misbehaved",
        )
        p1 = pick_selected_proposer(chain, candidates)
        b1 = chain.propose_block(consensus, p1, [], governance_txs=[ejection])
        ok, reason = chain.add_block(b1)
        self.assertTrue(ok, f"b1 rejected: {reason}")

        # Only alice + carol vote yes (bob excluded from tally as target)
        votes = [
            create_vote(alice, ejection.proposal_id, True),
            create_vote(carol, ejection.proposal_id, True),
        ]
        p2 = pick_selected_proposer(chain, candidates)
        b2 = chain.propose_block(consensus, p2, [], governance_txs=votes)
        ok, reason = chain.add_block(b2)
        self.assertTrue(ok, f"b2 rejected: {reason}")

        # Advance past voting window — ejection auto-executes, state_root
        # must predict bob's staked -> 0.
        self._advance(chain, consensus, candidates, _window() + 1)
        self.assertEqual(chain.supply.get_staked(bob.entity_id), 0)
        self.assertEqual(len(chain.governance.ejection_log), 1)


if __name__ == "__main__":
    unittest.main()
