"""
Governance transactions must flow through the block pipeline with their
state_root commitment correctly predicted by compute_post_state_root.

Prior to this, `compute_post_state_root` simulated message/transfer/
authority/stake/unstake but NOT governance.  A block containing any
governance tx (or triggering an auto-executed treasury-spend) hit a
state_root mismatch and was rejected — even by its own proposer.
Governance was effectively library-only despite the rest of the plumbing
being there.

These tests prove the end-to-end block pipeline:
1. A block carrying a ProposalTransaction commits to the right state_root
2. A block carrying a VoteTransaction commits to the right state_root
3. A block whose block_height closes a binding proposal's window auto-
   executes the treasury spend and the state_root matches.
"""

import unittest
from messagechain.core.blockchain import Blockchain
from messagechain.consensus.pos import ProofOfStake
from messagechain.governance.governance import (
    create_proposal, create_vote,
    create_treasury_spend_proposal,
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
        chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)


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

class TestGovernanceLeafReuseRejection(_Base):
    """Governance txs MUST enforce the same WOTS+ leaf-reuse gate as
    every other signed tx type.  A leaf reused across tx types (e.g.
    a message tx at leaf N followed by a governance tx at the same
    leaf N) exposes enough of the one-time secret to forge signatures
    at that leaf — Transfer, SetAuthorityKey, etc.  The validation
    layer must reject the second-use regardless of direction.
    """

    def test_governance_tx_rejected_after_hot_key_leaf_consumed(self):
        """A message tx consumes leaf N.  A governance tx signed at
        the same leaf N must be rejected by per-tx validation (the
        second-block route) — not silently accepted and only bumped
        at apply-time."""
        from messagechain.core.transaction import create_transaction
        from messagechain.config import MIN_FEE
        chain, alice = _make_single_chain()
        consensus = ProofOfStake()

        # Burn leaf 0 via a message tx.
        msg = create_transaction(
            alice, "hi", MIN_FEE + 100, nonce=0,
            current_height=chain.height + 1,
        )
        b1 = chain.propose_block(consensus, alice, [msg])
        ok, reason = chain.add_block(b1)
        self.assertTrue(ok, reason)
        burned_leaf = msg.signature.leaf_index
        self.assertGreater(
            chain.leaf_watermarks[alice.entity_id], burned_leaf,
        )

        # Build a governance proposal at the SAME leaf that message tx
        # burned.  Manually rewind the keypair's next_leaf to force
        # the collision (simulating a signer with stale state — the
        # realistic attack model).
        alice.keypair._next_leaf = burned_leaf
        proposal = create_proposal(alice, "Rewind", "Details")
        self.assertEqual(
            proposal.signature.leaf_index, burned_leaf,
        )

        # Per-tx validation must now reject the governance tx on the
        # watermark rule alone — without this gate, the block-level
        # dedupe only catches same-block collisions.
        ok, reason = chain._validate_governance_tx(proposal)
        self.assertFalse(ok)
        self.assertIn("leaf", reason.lower())

    def test_governance_leaf_collision_within_same_block_rejected(self):
        """Two governance txs from the same entity at the same
        leaf_index in ONE block must be rejected by the block-level
        _check_leaf loop — mirrors the gate for message/transfer/
        attestation/finality-vote."""
        chain, alice = _make_single_chain()
        p1 = create_proposal(alice, "First", "Details")
        # Force second proposal to reuse the same leaf.
        alice.keypair._next_leaf = p1.signature.leaf_index
        p2 = create_proposal(alice, "Second", "OtherDetails")
        self.assertEqual(
            p1.signature.leaf_index, p2.signature.leaf_index,
        )
        self.assertNotEqual(p1.proposal_id, p2.proposal_id)

        consensus = ProofOfStake()
        # propose_block normally filters the second as invalid, so
        # construct the block directly via the underlying path and
        # let validate_block catch the dup.
        block = chain.propose_block(
            consensus, alice, [], governance_txs=[p1, p2],
        )
        # If propose_block filtered p2 out of the final block, the
        # dedupe loop never sees a collision.  Force the collision by
        # injecting p2 manually.
        if p2 not in block.governance_txs:
            block.governance_txs = list(block.governance_txs) + [p2]
        ok, reason = chain.validate_block(block)
        self.assertFalse(ok)
        self.assertIn("leaf", reason.lower())


def _make_single_chain():
    alice = _entity(b"leaf-reuse-alice")
    alice.keypair._next_leaf = 0
    chain = Blockchain()
    chain.initialize_genesis(
        alice,
        allocation_table={
            TREASURY_ENTITY_ID: TREASURY_ALLOCATION,
            alice.entity_id: 1_000_000,
        },
    )
    chain.supply.staked[alice.entity_id] = 10_000
    return chain, alice


if __name__ == "__main__":
    unittest.main()
