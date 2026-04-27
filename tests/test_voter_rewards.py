"""Voter rewards on passed proposals (Tier 22, VOTER_REWARD_HEIGHT).

Design (see CHANGELOG / config.py "Tier 22"):

  - At proposal apply, post-fork, the proposer pays VOTER_REWARD_SURCHARGE
    on top of the regular tx fee.  The surcharge is held in a per-
    proposal escrow on ProposalState.voter_reward_pool.
  - At proposal close: if the supermajority test passes (yes_weight × 3
    > total_eligible × 2 evaluated in live-weight mode), the pool is
    distributed pro-rata-by-live-stake to YES voters whose stake is
    still > 0; otherwise the entire pool burns.
  - Whale cap: a single voter's share is capped at
    VOTER_REWARD_MAX_SHARE_BPS / 10_000 of the pool.  Excess from the
    cap burns.
  - Integer-division dust burns (deterministic).

These tests pin the tracker-level surface — surcharge plumbing through
the chain's _apply_governance_block is covered by the integration test
class at the bottom.
"""

import unittest

from messagechain.identity.identity import Entity
from messagechain.economics.inflation import SupplyTracker
from messagechain.governance.governance import (
    GovernanceTracker,
    create_proposal,
    create_vote,
)
from messagechain.config import (
    GENESIS_SUPPLY,
    GOVERNANCE_VOTING_WINDOW,
    VOTER_REWARD_HEIGHT,
    VOTER_REWARD_SURCHARGE,
    VOTER_REWARD_MAX_SHARE_BPS,
)


def _net_inflation_invariant(supply: SupplyTracker) -> int:
    """Signed gap of the chain-level invariant.  0 when held."""
    return (
        supply.total_supply
        - GENESIS_SUPPLY
        - supply.total_minted
        + supply.total_burned
    )


class TestVoterRewardPoolField(unittest.TestCase):
    """ProposalState carries a voter_reward_pool field that defaults to
    0 and can be set by the apply path (matches the surcharge debited
    from the proposer)."""

    def setUp(self):
        self.alice = Entity.create(b"vr-pool-alice".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.alice.entity_id] = 10_000

    def test_default_pool_is_zero(self):
        """Pre-fork / no-surcharge path: pool is 0."""
        tracker = GovernanceTracker()
        prop = create_proposal(self.alice, "t", "d")
        tracker.add_proposal(prop, block_height=100, supply_tracker=self.supply)
        state = tracker.proposals[prop.proposal_id]
        self.assertEqual(state.voter_reward_pool, 0)

    def test_pool_set_via_keyword(self):
        """Apply path passes the surcharge through the keyword arg."""
        tracker = GovernanceTracker()
        prop = create_proposal(self.alice, "t", "d")
        tracker.add_proposal(
            prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=VOTER_REWARD_SURCHARGE,
        )
        state = tracker.proposals[prop.proposal_id]
        self.assertEqual(state.voter_reward_pool, VOTER_REWARD_SURCHARGE)


class TestVoterRewardDistributionOnPass(unittest.TestCase):
    """Pool distributes pro-rata to live-stake YES voters when the
    proposal clears the 2/3 supermajority threshold."""

    def setUp(self):
        self.alice = Entity.create(b"vr-pass-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-pass-bob".ljust(32, b"\x00"))
        self.carol = Entity.create(b"vr-pass-carol".ljust(32, b"\x00"))
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # Three equal stakers — each is 1/3 of the electorate.
        self.supply.staked[self.alice.entity_id] = 1_000
        self.supply.staked[self.bob.entity_id] = 1_000
        self.supply.staked[self.carol.entity_id] = 1_000
        for e in (self.alice, self.bob, self.carol):
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        # 99 splits cleanly 33/33/33 for the equal-stake winners (no
        # dust burn) and 99/2 ≈ 49 for the two-winner case below.
        # Using a small pool keeps payout arithmetic obvious in the
        # asserts.  Cap is 25% of 99 = 24, well under any per-voter
        # share in the equal-stake case (33).
        self.pool = 99
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def _close_block(self):
        return 100 + GOVERNANCE_VOTING_WINDOW + 1

    def test_unanimous_yes_distributes_pro_rata(self):
        """With the cap raised out of the way, three equal yes-stake
        voters each collect 1/3 of the pool, integer-rounded down."""
        # Override the cap for this test only — equal-stake means each
        # voter would naturally get 33/99 ≈ 33% which exceeds the
        # default 25% cap.  Lift it to 100% so we can verify the
        # natural pro-rata split.
        import messagechain.config as _cfg
        orig = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            for v in (self.alice, self.bob, self.carol):
                self.tracker.add_vote(
                    create_vote(v, self.prop.proposal_id, True),
                    current_block=101,
                )
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=self._close_block(),
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig

        self.assertTrue(result["passed"])
        # 99 // 3 = 33 each, no dust.
        for v in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[v.entity_id], 33)
        self.assertEqual(result["burned"], 0)

    def test_pool_zeroed_after_finalize(self):
        """Defensive: re-running finalize must be a no-op."""
        self.tracker.add_vote(
            create_vote(self.alice, self.prop.proposal_id, True),
            current_block=101,
        )
        self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=self._close_block(),
        )
        self.assertEqual(
            self.tracker.proposals[self.prop.proposal_id].voter_reward_pool, 0,
        )
        # Second call: no further mutation.
        balance_snapshot = dict(self.supply.balances)
        burned_snapshot = self.supply.total_burned
        self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=self._close_block(),
        )
        self.assertEqual(self.supply.balances, balance_snapshot)
        self.assertEqual(self.supply.total_burned, burned_snapshot)


class TestVoterRewardBurnOnFail(unittest.TestCase):
    """A proposal that fails the 2/3 supermajority test burns the
    entire pool — failed proposals never release voter rewards."""

    def setUp(self):
        self.alice = Entity.create(b"vr-fail-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-fail-bob".ljust(32, b"\x00"))
        self.carol = Entity.create(b"vr-fail-carol".ljust(32, b"\x00"))
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
            self.alice.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        for e in (self.alice, self.bob, self.carol):
            self.supply.staked[e.entity_id] = 1_000
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def test_majority_no_burns_pool(self):
        """Two of three vote NO — yes×3 = 1000×3 = 3000, total = 3000,
        eligible × 2 = 6000.  3000 < 6000 → fails.  Pool burns."""
        self.tracker.add_vote(
            create_vote(self.alice, self.prop.proposal_id, True),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.bob, self.prop.proposal_id, False),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.carol, self.prop.proposal_id, False),
            current_block=101,
        )
        burned_before = self.supply.total_burned
        supply_before = self.supply.total_supply

        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
        )

        self.assertFalse(result["passed"])
        self.assertEqual(result["burned"], self.pool)
        self.assertEqual(self.supply.total_burned, burned_before + self.pool)
        self.assertEqual(self.supply.total_supply, supply_before - self.pool)
        # No yes-voter received a credit.
        self.assertEqual(self.supply.balances[self.alice.entity_id], 0)

    def test_silent_electorate_burns_pool(self):
        """No votes at all — supermajority cannot be reached.  Pool burns."""
        burned_before = self.supply.total_burned

        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
        )

        self.assertFalse(result["passed"])
        self.assertEqual(result["burned"], self.pool)
        self.assertEqual(self.supply.total_burned, burned_before + self.pool)


class TestVoterRewardSlashedYesVoter(unittest.TestCase):
    """A yes-voter who is slashed (or fully unstaked) before close gets
    nothing — their pre-slash weight is zeroed by live-weight tally,
    matching the H6 binding-execution invariant."""

    def setUp(self):
        self.alice = Entity.create(b"vr-slashed-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-slashed-bob".ljust(32, b"\x00"))
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # Both stake equally; both vote yes.  Bob slashed before close.
        self.supply.staked[self.alice.entity_id] = 1_000
        self.supply.staked[self.bob.entity_id] = 1_000
        self.supply.balances[self.alice.entity_id] = 0
        self.supply.balances[self.bob.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 100
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def test_slashed_yes_voter_gets_nothing_alice_gets_full_pool(self):
        # Both vote yes.
        self.tracker.add_vote(
            create_vote(self.alice, self.prop.proposal_id, True),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.bob, self.prop.proposal_id, True),
            current_block=101,
        )
        # Bob is slashed before close.  slash_validator may credit a
        # whistleblower reward to the reporter (alice here), so capture
        # alice's balance AFTER the slash to isolate the voter-reward
        # payout.
        self.supply.slash_validator(self.bob.entity_id, self.alice.entity_id)
        self.assertEqual(self.supply.get_staked(self.bob.entity_id), 0)
        alice_balance_after_slash = self.supply.balances[self.alice.entity_id]

        # Lift the cap so the surviving yes-voter (Alice, alone) can
        # collect 100% of the pool — otherwise this test would be
        # entangled with the whale-cap path.
        import messagechain.config as _cfg
        orig = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000
        try:
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig

        self.assertTrue(result["passed"])  # alice's 1000 vs eligible 1000 → 3>2
        # Bob is slashed, so eligible = alice's 1000 only.  Alice
        # collects the entire pool — measured as a delta over her
        # post-slash balance to ignore any whistleblower credit from
        # slash_validator.
        self.assertEqual(
            self.supply.balances[self.alice.entity_id]
            - alice_balance_after_slash,
            self.pool,
        )
        self.assertEqual(self.supply.balances[self.bob.entity_id], 0)
        self.assertEqual(result["burned"], 0)


class TestVoterRewardWhaleCap(unittest.TestCase):
    """A voter holding the majority of yes-stake cannot collect more
    than VOTER_REWARD_MAX_SHARE_BPS of the pool.  Excess from the cap
    burns deterministically."""

    def setUp(self):
        self.whale = Entity.create(b"vr-cap-whale".ljust(32, b"\x00"))
        self.shrimp = Entity.create(b"vr-cap-shrimp".ljust(32, b"\x00"))
        self.no_voter = Entity.create(b"vr-cap-no".ljust(32, b"\x00"))
        for e in (self.whale, self.shrimp, self.no_voter):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # Whale = 99k, shrimp = 1k, no_voter = 1k.  Whale + shrimp vote yes,
        # no_voter votes no.  Yes = 100k, no = 1k, eligible = 101k.
        # 100k * 3 = 300k > 101k * 2 = 202k → passes.
        self.supply.staked[self.whale.entity_id] = 99_000
        self.supply.staked[self.shrimp.entity_id] = 1_000
        self.supply.staked[self.no_voter.entity_id] = 1_000
        for e in (self.whale, self.shrimp, self.no_voter):
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        # Pool = 1000 — easy to reason about with bps math.
        self.pool = 1_000
        self.prop = create_proposal(self.whale, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def test_whale_capped_excess_burns(self):
        """At 25% cap (default), whale collects min(990, 250) = 250
        and the excess goes to burn (not to the shrimp — the cap is
        per-voter, not 'redistribute')."""
        # Sanity: this test assumes the default cap.
        self.assertEqual(VOTER_REWARD_MAX_SHARE_BPS, 2_500)

        self.tracker.add_vote(
            create_vote(self.whale, self.prop.proposal_id, True),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.shrimp, self.prop.proposal_id, True),
            current_block=101,
        )
        self.tracker.add_vote(
            create_vote(self.no_voter, self.prop.proposal_id, False),
            current_block=101,
        )

        burned_before = self.supply.total_burned
        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
        )

        self.assertTrue(result["passed"])
        # Cap = 1000 * 2500 / 10_000 = 250.
        cap = self.pool * VOTER_REWARD_MAX_SHARE_BPS // 10_000
        # Natural pro-rata: whale = 99k/100k * 1000 = 990, shrimp =
        # 1k/100k * 1000 = 10.  After cap, whale = min(990, 250) = 250,
        # shrimp's natural 10 is well under the cap so unchanged.
        self.assertEqual(
            self.supply.balances[self.whale.entity_id], cap,
        )
        self.assertEqual(self.supply.balances[self.shrimp.entity_id], 10)
        # Burn = pool - whale_capped - shrimp = 1000 - 250 - 10 = 740.
        burned_excess = self.pool - cap - 10
        self.assertEqual(result["burned"], burned_excess)
        self.assertEqual(
            self.supply.total_burned, burned_before + burned_excess,
        )


class TestVoterRewardDustBurns(unittest.TestCase):
    """Integer-division dust at distribution must burn deterministically
    so all nodes agree byte-for-byte on post-distribution state."""

    def setUp(self):
        self.alice = Entity.create(b"vr-dust-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-dust-bob".ljust(32, b"\x00"))
        self.carol = Entity.create(b"vr-dust-carol".ljust(32, b"\x00"))
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        for e in (self.alice, self.bob, self.carol):
            self.supply.staked[e.entity_id] = 1_000
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        # Pool = 100, three equal yes-stake winners → 100/3 = 33r1.
        # Each gets 33; the 1-token remainder burns.
        self.pool = 100
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def test_dust_burns_not_to_lucky_voter(self):
        for v in (self.alice, self.bob, self.carol):
            self.tracker.add_vote(
                create_vote(v, self.prop.proposal_id, True),
                current_block=101,
            )

        import messagechain.config as _cfg
        orig = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000  # lift the cap
        try:
            burned_before = self.supply.total_burned
            result = self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig

        self.assertTrue(result["passed"])
        # Each voter gets exactly 33, not 33/33/34.
        for v in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[v.entity_id], 33)
        # 1-token dust burns.
        self.assertEqual(result["burned"], 1)
        self.assertEqual(self.supply.total_burned, burned_before + 1)


class TestVoterRewardZeroPoolPreFork(unittest.TestCase):
    """Pre-fork proposals (no surcharge debited) carry voter_reward_pool
    == 0.  Calling finalize on a zero-pool proposal must be a no-op —
    no payouts, no burns, no balance/supply mutation."""

    def setUp(self):
        self.alice = Entity.create(b"vr-prefork-alice".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        self.supply.staked[self.alice.entity_id] = 1_000
        self.supply.balances[self.alice.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.prop = create_proposal(self.alice, "t", "d")
        # No voter_reward_pool kwarg → defaults to 0.
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
        )

    def test_finalize_with_zero_pool_is_noop(self):
        self.tracker.add_vote(
            create_vote(self.alice, self.prop.proposal_id, True),
            current_block=101,
        )
        balance_before = self.supply.balances[self.alice.entity_id]
        burned_before = self.supply.total_burned
        supply_before = self.supply.total_supply

        result = self.tracker.finalize_voter_rewards(
            self.prop.proposal_id, self.supply,
            current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
        )

        self.assertEqual(result["burned"], 0)
        self.assertEqual(result["payouts"], {})
        self.assertEqual(self.supply.balances[self.alice.entity_id], balance_before)
        self.assertEqual(self.supply.total_burned, burned_before)
        self.assertEqual(self.supply.total_supply, supply_before)


class TestVoterRewardOnlyYesVotersPaid(unittest.TestCase):
    """No-voters on a passed proposal get nothing — payout is yes-only.
    This pins the design choice: pay-on-pass is one-sided to avoid the
    'easy bet' of voting against every proposal at the floor."""

    def setUp(self):
        self.alice = Entity.create(b"vr-yesonly-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-yesonly-bob".ljust(32, b"\x00"))
        self.carol = Entity.create(b"vr-yesonly-carol".ljust(32, b"\x00"))
        self.dave = Entity.create(b"vr-yesonly-dave".ljust(32, b"\x00"))
        for e in (self.alice, self.bob, self.carol, self.dave):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # 4 stakers: 3 yes (passes 2/3), 1 no.
        for e in (self.alice, self.bob, self.carol, self.dave):
            self.supply.staked[e.entity_id] = 1_000
            self.supply.balances[e.entity_id] = 0

        self.tracker = GovernanceTracker()
        self.pool = 90  # 90 / 3 yes-voters = 30 each, no remainder.
        self.prop = create_proposal(self.alice, "t", "d")
        self.tracker.add_proposal(
            self.prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=self.pool,
        )

    def test_no_voter_gets_nothing(self):
        for v in (self.alice, self.bob, self.carol):
            self.tracker.add_vote(
                create_vote(v, self.prop.proposal_id, True),
                current_block=101,
            )
        self.tracker.add_vote(
            create_vote(self.dave, self.prop.proposal_id, False),
            current_block=101,
        )

        import messagechain.config as _cfg
        orig = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000  # lift cap
        try:
            self.tracker.finalize_voter_rewards(
                self.prop.proposal_id, self.supply,
                current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
            )
        finally:
            _cfg.VOTER_REWARD_MAX_SHARE_BPS = orig

        # Dave (no-voter) gets nothing.
        self.assertEqual(self.supply.balances[self.dave.entity_id], 0)
        # Three yes-voters split 90 evenly.
        for v in (self.alice, self.bob, self.carol):
            self.assertEqual(self.supply.balances[v.entity_id], 30)


class TestVoterRewardInvariantHolds(unittest.TestCase):
    """The chain-level net-inflation invariant
    (total_supply == GENESIS_SUPPLY + total_minted - total_burned)
    must be preserved across the full lifecycle: escrow at apply,
    distribute or burn at close."""

    def setUp(self):
        self.alice = Entity.create(b"vr-inv-alice".ljust(32, b"\x00"))
        self.bob = Entity.create(b"vr-inv-bob".ljust(32, b"\x00"))
        for e in (self.alice, self.bob):
            e.keypair._next_leaf = 0
        self.supply = SupplyTracker()
        # Seed both with stake and a proposer balance to fund the surcharge.
        self.supply.staked[self.alice.entity_id] = 1_000
        self.supply.staked[self.bob.entity_id] = 1_000
        self.supply.balances[self.alice.entity_id] = VOTER_REWARD_SURCHARGE * 2
        self.supply.balances[self.bob.entity_id] = 0
        # Whale-cap doesn't bind here; lift it.
        import messagechain.config as _cfg
        self._orig_cap = _cfg.VOTER_REWARD_MAX_SHARE_BPS
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = 10_000

    def tearDown(self):
        import messagechain.config as _cfg
        _cfg.VOTER_REWARD_MAX_SHARE_BPS = self._orig_cap

    def _simulate_escrow_and_finalize(self, *, pass_proposal: bool):
        """Mimic what the chain apply path does: debit the proposer's
        balance by VOTER_REWARD_SURCHARGE, then later finalize."""
        tracker = GovernanceTracker()
        prop = create_proposal(self.alice, "t", "d")

        # Escrow step (chain apply path debits proposer balance directly,
        # passing the surcharge to add_proposal).
        self.supply.balances[self.alice.entity_id] -= VOTER_REWARD_SURCHARGE
        tracker.add_proposal(
            prop, block_height=100, supply_tracker=self.supply,
            voter_reward_pool=VOTER_REWARD_SURCHARGE,
        )

        # Vote yes — count needed to satisfy the supermajority depends on
        # whether we want it to pass.
        if pass_proposal:
            for v in (self.alice, self.bob):
                tracker.add_vote(
                    create_vote(v, prop.proposal_id, True),
                    current_block=101,
                )
        else:
            tracker.add_vote(
                create_vote(self.alice, prop.proposal_id, False),
                current_block=101,
            )

        tracker.finalize_voter_rewards(
            prop.proposal_id, self.supply,
            current_block=100 + GOVERNANCE_VOTING_WINDOW + 1,
        )

    def test_invariant_holds_through_pass(self):
        """No mint/burn on the pass path → net inflation unchanged."""
        before = _net_inflation_invariant(self.supply)
        self._simulate_escrow_and_finalize(pass_proposal=True)
        self.assertEqual(_net_inflation_invariant(self.supply), before)

    def test_invariant_holds_through_burn(self):
        """Pool burn must decrement total_supply AND increment
        total_burned by the same amount → net inflation unchanged."""
        before = _net_inflation_invariant(self.supply)
        self._simulate_escrow_and_finalize(pass_proposal=False)
        self.assertEqual(_net_inflation_invariant(self.supply), before)


class TestVoterRewardChainApplyPathPostFork(unittest.TestCase):
    """Integration: when a ProposalTransaction is applied at a height
    >= VOTER_REWARD_HEIGHT, the chain's _apply_governance_block debits
    VOTER_REWARD_SURCHARGE from the proposer and escrows it on the
    proposal state."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"vr-chain-alice".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def _setup_chain_with_distinct_block_proposer(self):
        """Build a chain where alice is the proposal-tx author but
        bob is the block proposer.  Keeps the fee-flow off alice's
        balance — a chain proposer receives tip back, so co-locating
        muddies the surcharge-only delta we want to measure."""
        from messagechain.core.blockchain import Blockchain
        bob = Entity.create(b"vr-chain-bob".ljust(32, b"\x00"))
        bob.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(self.alice)
        chain.supply.balances[self.alice.entity_id] = 10_000_000
        chain.supply.balances[bob.entity_id] = 0
        chain.public_keys[self.alice.entity_id] = self.alice.public_key
        chain.public_keys[bob.entity_id] = bob.public_key
        return chain, bob

    def test_post_fork_proposal_debits_surcharge(self):
        """At height >= VOTER_REWARD_HEIGHT, the post-apply state has a
        non-zero voter_reward_pool matching VOTER_REWARD_SURCHARGE,
        and the proposer's balance has been debited an additional
        VOTER_REWARD_SURCHARGE on top of the regular fee flow."""
        from unittest.mock import MagicMock
        chain, bob = self._setup_chain_with_distinct_block_proposer()

        prop = create_proposal(
            self.alice, "title", "desc",
            current_height=VOTER_REWARD_HEIGHT,
        )
        block = MagicMock()
        block.header.block_number = VOTER_REWARD_HEIGHT
        block.header.proposer_id = bob.entity_id
        block.governance_txs = [prop]

        balance_before = chain.supply.balances[self.alice.entity_id]
        chain._apply_governance_block(block)

        state = chain.governance.proposals[prop.proposal_id]
        self.assertEqual(state.voter_reward_pool, VOTER_REWARD_SURCHARGE)
        # Alice (proposal author) paid fee + surcharge; bob (block
        # proposer) received tip = fee - base_fee.  Net change to
        # alice's balance is exactly -(fee + surcharge).
        self.assertEqual(
            chain.supply.balances[self.alice.entity_id],
            balance_before - prop.fee - VOTER_REWARD_SURCHARGE,
        )

    def test_pre_fork_proposal_no_surcharge(self):
        """At height < VOTER_REWARD_HEIGHT, the surcharge is NOT
        debited — pool stays 0, proposer pays fee only."""
        from unittest.mock import MagicMock
        chain, bob = self._setup_chain_with_distinct_block_proposer()

        pre_fork_height = VOTER_REWARD_HEIGHT - 1
        prop = create_proposal(
            self.alice, "title", "desc",
            current_height=pre_fork_height,
        )
        block = MagicMock()
        block.header.block_number = pre_fork_height
        block.header.proposer_id = bob.entity_id
        block.governance_txs = [prop]

        balance_before = chain.supply.balances[self.alice.entity_id]
        chain._apply_governance_block(block)

        state = chain.governance.proposals[prop.proposal_id]
        self.assertEqual(state.voter_reward_pool, 0)
        # Alice paid fee only — no surcharge debited.
        self.assertEqual(
            chain.supply.balances[self.alice.entity_id],
            balance_before - prop.fee,
        )


if __name__ == "__main__":
    unittest.main()
