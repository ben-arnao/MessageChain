"""Tests for governance audit findings H6 and M5.

H6: Slashed voter's prior vote still counts at pre-slash weight in
    binding tallies.  Fix: re-evaluate voter weights against CURRENT
    stake state in execute_treasury_spend (and anywhere else a BINDING
    tally is computed).  Slashed voters contribute 0.  A voter whose
    stake changed between vote-cast and tally gets their CURRENT stake
    weight.

M5: Two TreasurySpendTransactions closing in the same block can race
    past the balance check — both see the same pre-debit treasury
    balance and both debit, allowing overdraft (the second returns
    False but ordering is non-deterministic).  Fix: process
    treasury spends in the same block in deterministic hex-sorted
    proposal_id order so each re-checks balance AFTER prior debits in
    the block have landed, and losers lose predictably.
"""

import unittest
from unittest.mock import MagicMock

from messagechain.core.blockchain import Blockchain
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_treasury_spend_proposal,
    create_vote,
)
from messagechain.identity.identity import Entity
from messagechain.config import (
    GOVERNANCE_VOTING_WINDOW,
    TREASURY_ENTITY_ID,
)
from messagechain import config as _config


_BYPASSED_HEIGHTS = (
    "TREASURY_CAP_TIGHTEN_HEIGHT",
    "TREASURY_REBASE_HEIGHT",
    "DEFLATION_FLOOR_HEIGHT",
    "DEFLATION_FLOOR_V2_HEIGHT",
    "PROPOSAL_FEE_TIER19_HEIGHT",
    "VOTER_REWARD_HEIGHT",
)


class _TreasuryCapBypass:
    """Pin every non-bootstrap fork height far in the future for the
    test's duration.  Post-1.26.0 fork sweep these activations cluster
    at 700-720 and fire on the close block of the test's voting
    window, perturbing balances the test pre-seeds.  The original
    schedule put the close block well before any of these forks; we
    restore that property for the test only."""

    def __enter__(self):
        self._orig = {
            n: getattr(_config, n) for n in _BYPASSED_HEIGHTS
        }
        for n in _BYPASSED_HEIGHTS:
            setattr(_config, n, 10_000_000)
        return self

    def __exit__(self, *exc):
        for n, v in self._orig.items():
            setattr(_config, n, v)
        return False


def _make_block(block_number: int, proposer_id: bytes, governance_txs: list):
    block = MagicMock()
    block.header.block_number = block_number
    block.header.proposer_id = proposer_id
    block.governance_txs = governance_txs
    return block


class TestH6SlashedVoterWeightZeroedInBindingTally(unittest.TestCase):
    """A voter slashed mid-voting-window must contribute 0 to the final
    binding tally — even if their vote is already in state.votes."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"h6-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"h6-bob".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"h6-carol".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self._cap_bypass = _TreasuryCapBypass().__enter__()
        self.supply = SupplyTracker()
        # Attack scenario: Bob holds a huge malicious stake, Alice and
        # Carol are honest.  Bob alone exceeds 2/3 — so if his pre-slash
        # vote still counts, he carries any treasury spend single-handed.
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0
        self.supply.balances[self.carol.entity_id] = 0
        self.supply.staked[self.alice.entity_id] = 5_000
        self.supply.staked[self.bob.entity_id] = 100_000
        self.supply.staked[self.carol.entity_id] = 5_000
        # Treasury has 100k.
        self.supply.balances[TREASURY_ENTITY_ID] = 100_000
        self.tracker = GovernanceTracker()

    def tearDown(self):
        self._cap_bypass.__exit__(None, None, None)

    def test_slashed_voter_contributes_zero_to_binding_tally(self):
        """A treasury spend needs >2/3 of eligible to pass.  If a malicious
        whale casts YES and is then slashed mid-window, their pre-slash
        stake weight must NOT carry the proposal."""
        # Bob is a whale with 100k stake who tries to drain the treasury
        # to himself.  Alice+Carol (5k each) vote NO.  Bob votes YES.
        # Pre-bugfix: yes=100k, no=10k, eligible=110k. 100*3=300>110*2=220
        # PASSES.
        # Bob is slashed for equivocation before window closes.
        # Post-bugfix (current stake): yes=0 (bob slashed), no=10k,
        # eligible=10k.  0*3=0 NOT > 10*2=20 → REJECTED.
        spend = create_treasury_spend_proposal(
            self.bob, self.bob.entity_id, 50_000, "bad", "whale self-deal",
        )
        self.tracker.add_proposal(spend, block_height=100, supply_tracker=self.supply)

        self.tracker.add_vote(
            create_vote(self.bob, spend.proposal_id, True), current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.alice, spend.proposal_id, False), current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.carol, spend.proposal_id, False), current_block=101,
        )

        treasury_before = self.supply.balances[TREASURY_ENTITY_ID]

        # Bob is slashed (entire stake burned).
        self.supply.slash_validator(self.bob.entity_id, self.alice.entity_id)
        self.assertEqual(self.supply.get_staked(self.bob.entity_id), 0)

        closed_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        ok = self.tracker.execute_treasury_spend(
            spend, self.supply, current_block=closed_block,
        )
        self.assertFalse(
            ok,
            "slashed Bob's YES must not carry the proposal past 2/3",
        )
        treasury_after = self.supply.balances[TREASURY_ENTITY_ID]
        self.assertEqual(
            treasury_after, treasury_before,
            "treasury must NOT spend when slashed vote is correctly zeroed",
        )

    def test_unchanged_stake_binding_tally_still_passes(self):
        """Sanity: when no slashing occurs, binding execution works
        unchanged."""
        spend = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5_000, "ok", "normal proposal",
        )
        self.tracker.add_proposal(spend, block_height=100, supply_tracker=self.supply)
        for voter in (self.alice, self.bob, self.carol):
            self.tracker.add_vote(
                create_vote(voter, spend.proposal_id, True), current_block=101,
            )
        closed_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        ok = self.tracker.execute_treasury_spend(
            spend, self.supply, current_block=closed_block,
        )
        self.assertTrue(ok)
        self.assertEqual(self.supply.balances[self.bob.entity_id], 5_000)

    def test_partial_unstake_reduces_weight_in_binding_tally(self):
        """A voter whose stake shrinks between vote-cast and binding
        execution should only count at their CURRENT stake weight."""
        # With alice=10k, bob=10k, carol=10k (total 30k):
        # If alice (YES) drops to 1k and carol (NO) drops to 1k, bob (YES)
        # still 10k → yes = 11k, no = 1k, eligible = 12k.
        # 11*3=33 > 12*2=24 — passes.
        spend = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, 5_000, "half", "partial unstake test",
        )
        self.tracker.add_proposal(spend, block_height=100, supply_tracker=self.supply)
        self.tracker.add_vote(
            create_vote(self.alice, spend.proposal_id, True), current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.bob, spend.proposal_id, True), current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.carol, spend.proposal_id, False), current_block=101,
        )
        # Alice and Carol both reduce stake.
        self.supply.staked[self.alice.entity_id] = 1_000
        self.supply.staked[self.carol.entity_id] = 1_000

        closed_block = 100 + GOVERNANCE_VOTING_WINDOW + 1
        ok = self.tracker.execute_treasury_spend(
            spend, self.supply, current_block=closed_block,
        )
        self.assertTrue(ok, "should pass: yes=11k no=1k eligible=12k, 11*3=33>24")


class TestM5SameBlockTreasurySpendOrdering(unittest.TestCase):
    """Two treasury spends that close in the same block must be
    processed in a deterministic order (hex-sorted proposal_id) and each
    must re-check balance AFTER prior in-block debits have landed."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"m5-alice".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"m5-bob".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"m5-carol".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self._cap_bypass = _TreasuryCapBypass().__enter__()
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.balances[e.entity_id] = 1_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
            self.chain.supply.staked[e.entity_id] = 10_000

    def tearDown(self):
        self._cap_bypass.__exit__(None, None, None)

    def _both_spends_close_same_block(self, treasury_budget: int, each: int):
        """Set up two distinct treasury-spend proposals created at the
        same block, each asking for `each` tokens from a treasury sized
        `treasury_budget`.  Returns the two spend txs and the block
        where they close."""
        self.chain.supply.balances[TREASURY_ENTITY_ID] = treasury_budget
        # Two spends with identical timestamp paths would collide on
        # tx_hash, so we rely on different recipients to make them
        # distinct.
        spend_a = create_treasury_spend_proposal(
            self.alice, self.bob.entity_id, each, "A", "first",
        )
        spend_b = create_treasury_spend_proposal(
            self.alice, self.carol.entity_id, each, "B", "second",
        )
        proposal_block = 5
        # Both registered in the same block.
        b1 = _make_block(proposal_block, self.alice.entity_id,
                         [spend_a, spend_b])
        self.chain._apply_governance_block(b1)

        # All 3 stakers vote yes on both, spread across separate blocks
        # just for signature leaf index hygiene.
        votes_block = proposal_block + 1
        txs = []
        for voter in (self.alice, self.bob, self.carol):
            txs.append(create_vote(voter, spend_a.proposal_id, True))
            txs.append(create_vote(voter, spend_b.proposal_id, True))
        b_votes = _make_block(votes_block, self.alice.entity_id, txs)
        self.chain._apply_governance_block(b_votes)

        close_block = proposal_block + GOVERNANCE_VOTING_WINDOW + 1
        return spend_a, spend_b, close_block

    def test_insufficient_treasury_only_first_in_order_debits(self):
        """Treasury can cover exactly ONE spend. With hex-sorted-by-id
        ordering, the lower-sorted spend wins; the other MUST be
        rejected (balance check re-runs after the first debit)."""
        spend_a, spend_b, close_block = self._both_spends_close_same_block(
            treasury_budget=6_000, each=5_000,
        )
        treasury_before = self.chain.supply.balances[TREASURY_ENTITY_ID]
        bob_before = self.chain.supply.balances.get(self.bob.entity_id, 0)
        carol_before = self.chain.supply.balances.get(self.carol.entity_id, 0)

        b_close = _make_block(close_block, self.alice.entity_id, [])
        self.chain._apply_governance_block(b_close)

        treasury_after = self.chain.supply.balances[TREASURY_ENTITY_ID]
        bob_after = self.chain.supply.balances.get(self.bob.entity_id, 0)
        carol_after = self.chain.supply.balances.get(self.carol.entity_id, 0)

        # Exactly one spend must execute — treasury has 6k, each asks
        # 5k, so second overdrafts.
        total_paid_out = (bob_after - bob_before) + (carol_after - carol_before)
        self.assertEqual(total_paid_out, 5_000,
                         "only one spend may debit the treasury")
        self.assertEqual(treasury_before - treasury_after, 5_000,
                         "treasury debit must match exactly one spend")
        # Exactly one log entry — the winner.
        self.assertEqual(len(self.chain.governance.treasury_spend_log), 1)

        # Deterministic winner: hex-sorted proposal_id comes first.
        winner = min(spend_a.proposal_id, spend_b.proposal_id)
        if winner == spend_a.proposal_id:
            self.assertEqual(bob_after - bob_before, 5_000)
            self.assertEqual(carol_after, carol_before)
        else:
            self.assertEqual(carol_after - carol_before, 5_000)
            self.assertEqual(bob_after, bob_before)

    def test_sufficient_treasury_both_execute_in_order(self):
        """When the treasury covers both, both must execute.  Regression
        guard: ordering must not reject solvent spends."""
        spend_a, spend_b, close_block = self._both_spends_close_same_block(
            treasury_budget=20_000, each=5_000,
        )
        b_close = _make_block(close_block, self.alice.entity_id, [])
        self.chain._apply_governance_block(b_close)
        self.assertEqual(len(self.chain.governance.treasury_spend_log), 2)
        # Bob and Carol both got their 5k.
        self.assertGreaterEqual(
            self.chain.supply.balances[self.bob.entity_id], 5_000,
        )
        self.assertGreaterEqual(
            self.chain.supply.balances[self.carol.entity_id], 5_000,
        )


if __name__ == "__main__":
    unittest.main()
