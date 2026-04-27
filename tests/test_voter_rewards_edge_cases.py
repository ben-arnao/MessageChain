"""Voter-rewards (Tier 22) edge-case tests.

The main voter-reward suite covers the happy paths (proposal passes,
voters paid pro-rata).  This file pins the edge cases:

  * Cap excess burns (per-voter > VOTER_REWARD_MAX_SHARE_BPS).
  * Pool dust burns (integer-division remainder).
  * Zero-yes-weight passed-supermajority is unreachable (defensive).
  * Pool == 0 (pre-fork) is a clean no-op.
  * Repeated finalize is idempotent (pool zeroed on first call).
  * Burned + distributed == pool exactly (supply invariant).
  * Voter slashed mid-window contributes 0 stake → drops out of
    the winners set (eroded relief, not just lower share).
"""

import unittest

from messagechain.config import (
    GOVERNANCE_APPROVAL_THRESHOLD_NUMERATOR,
    GOVERNANCE_APPROVAL_THRESHOLD_DENOMINATOR,
    VOTER_REWARD_MAX_SHARE_BPS,
)
from messagechain.core.blockchain import Blockchain
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
)
from messagechain.identity.identity import Entity


def _eid(tag: bytes) -> Entity:
    return Entity.create(tag.ljust(32, b"\x00"))


class _Setup:
    """Reusable harness — fresh tracker + supply_tracker + few entities."""

    def __init__(self, num_voters: int = 3):
        self.entities = [
            _eid(f"vr-{i}".encode()) for i in range(num_voters)
        ]
        for e in self.entities:
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        # The first entity is the genesis-funded proposer; the rest
        # are funded + staked manually.
        self.chain.initialize_genesis(self.entities[0])
        for e in self.entities:
            self.chain.supply.balances[e.entity_id] = 10_000_000
            self.chain.public_keys[e.entity_id] = e.public_key
            self.chain.supply.staked[e.entity_id] = 1_000_000

    def make_proposal(self, gt: GovernanceTracker, pool: int = 100_000):
        proposer = self.entities[0]
        tx = create_proposal(proposer, "edge", "edge case test")
        gt.add_proposal(
            tx, block_height=1, supply_tracker=self.chain.supply,
        )
        # Manually escrow the voter-reward pool — this mirrors what
        # the chain-side _apply_governance_block does post-Tier-22
        # via the proposal-fee surcharge debit.
        state = gt.proposals[tx.proposal_id]
        state.voter_reward_pool = pool
        # Pool tokens come from supply but are not in any balance.
        # The chain accounting represents the surcharge burn that
        # funds the pool; tests can simulate by pre-debiting.
        self.chain.supply.total_supply += pool  # tokens enter pool
        return tx


class TestPoolZero(unittest.TestCase):
    """Pre-fork or already-finalized pool=0 is a clean no-op."""

    def test_pool_zero_returns_clean(self):
        s = _Setup()
        gt = GovernanceTracker()
        tx = create_proposal(s.entities[0], "no-pool", "d")
        gt.add_proposal(tx, 1, s.chain.supply)
        # voter_reward_pool defaults to 0 — pre-fork shape.
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=2,
        )
        self.assertEqual(
            result, {"passed": False, "payouts": {}, "burned": 0},
        )

    def test_idempotent_after_first_finalize(self):
        s = _Setup()
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=10_000)
        # Make the proposal fail (no yes-votes) so the burn path runs.
        result1 = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=2,
        )
        self.assertFalse(result1["passed"])
        self.assertEqual(result1["burned"], 10_000)
        # Second call is a no-op (pool was reset to 0).
        result2 = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        self.assertEqual(
            result2, {"passed": False, "payouts": {}, "burned": 0},
        )


class TestFailedProposalBurnsPool(unittest.TestCase):
    """A proposal that fails (yes-weight ≤ 2/3) burns the entire pool."""

    def test_failed_proposal_burns_full_pool(self):
        s = _Setup(num_voters=3)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=50_000)
        # No votes → fails → full burn.
        supply_before = s.chain.supply.total_supply
        burned_before = s.chain.supply.total_burned
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=2,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["payouts"], {})
        self.assertEqual(result["burned"], 50_000)
        self.assertEqual(
            s.chain.supply.total_supply, supply_before - 50_000,
        )
        self.assertEqual(
            s.chain.supply.total_burned, burned_before + 50_000,
        )


class TestPassedProposalDistributes(unittest.TestCase):
    """A passed proposal pays yes-voters pro-rata-by-live-stake."""

    def test_uniform_stake_yields_equal_shares(self):
        # Use 5 voters so each voter's pro-rata share (20%) is under
        # the 25% per-voter cap — exercises the no-cap path cleanly.
        s = _Setup(num_voters=5)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=30_000)
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        balances_before = {
            e.entity_id: s.chain.supply.balances[e.entity_id]
            for e in s.entities
        }
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["payouts"]), 5)
        # Each voter: 30_000 * 1M // 5M = 6_000, well under cap 7_500.
        for e in s.entities:
            self.assertEqual(result["payouts"][e.entity_id], 6_000)
            self.assertEqual(
                s.chain.supply.balances[e.entity_id],
                balances_before[e.entity_id] + 6_000,
            )
        self.assertEqual(result["burned"], 0)


class TestCapExcessBurns(unittest.TestCase):
    """A single voter's share above the per-voter cap burns."""

    def test_single_dominant_voter_capped_at_max_share_bps(self):
        s = _Setup(num_voters=4)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=100_000)
        # Voter 0 has 10× the stake of the others — uncapped pro-rata
        # would give them ≈ 77% of the pool; cap (default 25%) means
        # they get 25_000 and the excess burns.
        s.chain.supply.staked[s.entities[0].entity_id] = 10_000_000
        # Other 3 voters with 1M each.  All four vote yes.
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        self.assertTrue(result["passed"])
        # Cap = pool * 2500 / 10000 = 25_000.
        cap = 100_000 * VOTER_REWARD_MAX_SHARE_BPS // 10_000
        # Voter 0 hits the cap exactly.
        self.assertEqual(result["payouts"][s.entities[0].entity_id], cap)
        # Other voters get their pro-rata share unchanged.  Their
        # combined stake is 3M of 13M total → 3/13 of pool ≈ 23_076
        # split three ways, each ≈ 7_692.
        for e in s.entities[1:]:
            self.assertLess(result["payouts"][e.entity_id], cap)
            self.assertGreater(result["payouts"][e.entity_id], 0)
        # Burn = pool - sum(payouts).  Equals the cap-excess +
        # integer-division dust.
        total_paid = sum(result["payouts"].values())
        self.assertEqual(result["burned"], 100_000 - total_paid)
        self.assertGreater(result["burned"], 0)


class TestDustBurns(unittest.TestCase):
    """Integer-division remainder burns deterministically."""

    def test_dust_from_uneven_division_burns(self):
        # 7 voters → pro-rata 14.28% each, well under 25% cap.
        # Pool=100_003 chosen to be coprime with 7M total stake so
        # per-voter division has remainder.
        s = _Setup(num_voters=7)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=100_003)
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        self.assertTrue(result["passed"])
        # Each voter paid 100_003 * 1M // 7M = 14_286.  Sum = 100_002.
        # Dust = 100_003 - 100_002 = 1.
        per_voter = 100_003 * 1_000_000 // 7_000_000
        for e in s.entities:
            self.assertEqual(result["payouts"][e.entity_id], per_voter)
        self.assertEqual(result["burned"], 100_003 - 7 * per_voter)
        self.assertGreater(result["burned"], 0)


class TestSlashedVoterDropsOut(unittest.TestCase):
    """A voter whose stake was slashed mid-window contributes 0."""

    def test_slashed_voter_excluded_from_winners(self):
        s = _Setup(num_voters=3)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=30_000)
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        # Slash voter 1 — set live stake to 0 between vote-cast and
        # finalize.  Live-weight mode means they drop out of the
        # winners set entirely.
        s.chain.supply.staked[s.entities[1].entity_id] = 0
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        # 2 winners share the pool; the slashed voter gets 0.
        self.assertNotIn(s.entities[1].entity_id, result["payouts"])
        self.assertEqual(len(result["payouts"]), 2)
        self.assertEqual(
            result["payouts"][s.entities[0].entity_id],
            result["payouts"][s.entities[2].entity_id],
        )


class TestSupplyInvariantPreserved(unittest.TestCase):
    """payout + burn == pool exactly, regardless of branch."""

    def test_invariant_holds_on_failed_proposal(self):
        s = _Setup()
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=12_345)
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=2,
        )
        total_paid = sum(result["payouts"].values())
        self.assertEqual(total_paid + result["burned"], 12_345)

    def test_invariant_holds_on_passed_proposal(self):
        s = _Setup(num_voters=3)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=99_997)  # prime → guaranteed dust
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        total_paid = sum(result["payouts"].values())
        self.assertEqual(total_paid + result["burned"], 99_997)

    def test_invariant_holds_on_capped_proposal(self):
        s = _Setup(num_voters=4)
        gt = GovernanceTracker()
        tx = s.make_proposal(gt, pool=80_000)
        s.chain.supply.staked[s.entities[0].entity_id] = 10_000_000
        for e in s.entities:
            gt.add_vote(create_vote(e, tx.proposal_id, True), 2)
        result = gt.finalize_voter_rewards(
            tx.proposal_id, s.chain.supply, current_block=3,
        )
        total_paid = sum(result["payouts"].values())
        self.assertEqual(total_paid + result["burned"], 80_000)


if __name__ == "__main__":
    unittest.main()
