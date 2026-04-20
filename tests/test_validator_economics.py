"""Tests for long-term validator economics: attestation rewards, higher reward
floor, and EIP-1559-style base fee with fee burning.

These features ensure that transaction validation remains a lucrative
proposition for years into the future.
"""

import unittest
from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.transaction import create_transaction
from messagechain.consensus.pos import ProofOfStake
from messagechain.consensus.attestation import create_attestation
from messagechain.economics.inflation import SupplyTracker
from messagechain.config import (
    BLOCK_REWARD, BLOCK_REWARD_FLOOR, HALVING_INTERVAL,
    PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR,
    BASE_FEE_INITIAL, BASE_FEE_MAX_CHANGE_DENOMINATOR,
    TARGET_BLOCK_SIZE, MIN_FEE, MIN_TIP, MAX_TXS_PER_BLOCK,
)
from tests import register_entity_for_test, pick_selected_proposer


class TestBlockRewardFloor(unittest.TestCase):
    """Block reward never drops below BLOCK_REWARD_FLOOR."""

    def test_floor_is_higher_than_one(self):
        """The floor must be meaningfully above 1."""
        self.assertGreaterEqual(BLOCK_REWARD_FLOOR, 2)

    def test_reward_never_below_floor(self):
        """After all halvings, reward stays at BLOCK_REWARD_FLOOR."""
        tracker = SupplyTracker()
        # After enough halvings, BLOCK_REWARD >> halvings < BLOCK_REWARD_FLOOR
        # At that point the floor should kick in.
        very_late_block = HALVING_INTERVAL * 100  # way past all halvings
        reward = tracker.calculate_block_reward(very_late_block)
        self.assertEqual(reward, BLOCK_REWARD_FLOOR)

    def test_halving_schedule_reaches_floor(self):
        """Walk the halving schedule and verify floor engagement."""
        tracker = SupplyTracker()
        rewards = []
        for i in range(10):
            height = i * HALVING_INTERVAL
            reward = tracker.calculate_block_reward(height)
            rewards.append(reward)

        # First reward is BLOCK_REWARD
        self.assertEqual(rewards[0], BLOCK_REWARD)
        # Rewards decrease
        for j in range(1, len(rewards)):
            self.assertLessEqual(rewards[j], rewards[j - 1])
        # All rewards >= floor
        for r in rewards:
            self.assertGreaterEqual(r, BLOCK_REWARD_FLOOR)

    def test_floor_applies_at_exact_boundary(self):
        """When halving would drop below floor, floor is used instead."""
        tracker = SupplyTracker()
        # Find the halving epoch where naive reward < floor
        epoch = 0
        while (BLOCK_REWARD >> epoch) >= BLOCK_REWARD_FLOOR:
            epoch += 1
        # At this epoch, naive reward < floor but actual reward = floor
        height = epoch * HALVING_INTERVAL
        self.assertEqual(tracker.calculate_block_reward(height), BLOCK_REWARD_FLOOR)


class TestAttestationRewards(unittest.TestCase):
    """Block reward is split between proposer and attester committee.

    Reward distribution is committee-based: each committee slot pays
    ATTESTER_REWARD_PER_SLOT (1 token), independent of stake.  See
    messagechain/consensus/attester_committee.py for selection.
    """

    def test_config_split_is_valid(self):
        """Proposer share must be < 100% (leaving room for attestors)."""
        self.assertLess(PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR)

    def test_no_committee_proposer_gets_full_reward(self):
        """No committee → proposer gets full reward.  Cap exists only
        to protect a multi-validator committee from mega-staker capture;
        with no committee there is no capture to guard against.  Any
        excess used to flow to the treasury, which was unintended
        governance-fund inflation."""
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        reward = tracker.calculate_block_reward(1)
        distributed = tracker.mint_block_reward(proposer, 1, attester_committee=[])
        self.assertEqual(distributed["proposer_reward"], reward)
        self.assertEqual(distributed["total_attestor_reward"], 0)
        self.assertEqual(distributed["treasury_excess"], 0)
        self.assertEqual(tracker.get_balance(proposer), reward)

    def test_reward_split_with_committee(self):
        """Proposer gets 1/4; each committee slot pays 1 token."""
        from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_a = b"\x02" * 32
        att_b = b"\x03" * 32

        reward = tracker.calculate_block_reward(1)
        result = tracker.mint_block_reward(
            proposer, 1, attester_committee=[att_a, att_b],
        )

        proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        self.assertEqual(result["proposer_reward"], proposer_share)
        self.assertEqual(
            result["total_attestor_reward"], 2 * ATTESTER_REWARD_PER_SLOT,
        )

    def test_committee_rewards_are_flat_per_slot(self):
        """Every committee member earns the same flat per-slot reward.

        Under the committee model, stake matters for *selection probability*
        (handled upstream by select_attester_committee), not for the
        payout size.  Once selected, everyone gets the same slot reward.
        """
        from messagechain.consensus.attester_committee import ATTESTER_REWARD_PER_SLOT
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_big = b"\x02" * 32
        att_small = b"\x03" * 32

        tracker.mint_block_reward(
            proposer, 1, attester_committee=[att_big, att_small],
        )

        self.assertEqual(tracker.get_balance(att_big), ATTESTER_REWARD_PER_SLOT)
        self.assertEqual(tracker.get_balance(att_small), ATTESTER_REWARD_PER_SLOT)

    def test_total_minted_equals_paid_plus_burned(self):
        """Reward = proposer_share + attester_pool_paid + burned.

        Conservation under the new burn-not-treasury policy: whatever
        isn't paid to an active validator is BURNED (supply reduction),
        not credited to the treasury.
        """
        from messagechain.config import TREASURY_ENTITY_ID
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_a = b"\x02" * 32
        att_b = b"\x03" * 32

        initial_supply = tracker.total_supply
        initial_burned = tracker.total_burned
        reward = tracker.calculate_block_reward(1)
        result = tracker.mint_block_reward(
            proposer, 1, attester_committee=[att_a, att_b],
        )

        # Proposer + attesters + burned == reward.
        burned = result["burned"]
        total_paid = (
            tracker.get_balance(proposer)
            + tracker.get_balance(att_a)
            + tracker.get_balance(att_b)
        )
        self.assertEqual(total_paid + burned, reward)
        # Supply netted by: +reward (mint) - burned (cap/unfilled overflow).
        self.assertEqual(tracker.total_supply, initial_supply + reward - burned)
        self.assertEqual(tracker.total_burned, initial_burned + burned)
        # Treasury untouched by the reward pipeline.
        self.assertEqual(tracker.get_balance(TREASURY_ENTITY_ID), 0)

    def test_proposer_on_committee_is_capped(self):
        """Proposer-share + committee-slot combined respects the cap.
        Cap overflow now BURNS (previously went to treasury)."""
        from messagechain.config import PROPOSER_REWARD_CAP, TREASURY_ENTITY_ID
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        other = b"\x02" * 32

        reward = tracker.calculate_block_reward(1)
        result = tracker.mint_block_reward(
            proposer, 1, attester_committee=[proposer, other],
        )

        proposer_balance = tracker.get_balance(proposer)
        other_balance = tracker.get_balance(other)
        treasury_balance = tracker.get_balance(TREASURY_ENTITY_ID)
        burned = result["burned"]
        self.assertLessEqual(proposer_balance, PROPOSER_REWARD_CAP)
        self.assertGreater(other_balance, 0)
        # Treasury stays empty — no auto-crediting from reward flow.
        self.assertEqual(treasury_balance, 0)
        # Conservation: paid + burned == reward.
        self.assertEqual(proposer_balance + other_balance + burned, reward)


class TestBaseFee(unittest.TestCase):
    """EIP-1559-style dynamic base fee with fee burning."""

    def test_initial_base_fee(self):
        """Base fee starts at BASE_FEE_INITIAL."""
        tracker = SupplyTracker()
        self.assertEqual(tracker.base_fee, BASE_FEE_INITIAL)

    def test_base_fee_increases_when_blocks_full(self):
        """Base fee rises when parent block had more txs than target."""
        tracker = SupplyTracker()
        initial_fee = tracker.base_fee
        # Simulate a full block (MAX_TXS_PER_BLOCK txs)
        tracker.update_base_fee(MAX_TXS_PER_BLOCK)
        self.assertGreater(tracker.base_fee, initial_fee)

    def test_base_fee_decreases_when_blocks_empty(self):
        """Base fee falls when parent block had fewer txs than target."""
        tracker = SupplyTracker()
        # Start with elevated base fee
        tracker.base_fee = 200
        tracker.update_base_fee(0)  # empty block
        self.assertLess(tracker.base_fee, 200)

    def test_base_fee_stable_at_target(self):
        """Base fee stays constant when block is exactly at target."""
        tracker = SupplyTracker()
        initial_fee = tracker.base_fee
        tracker.update_base_fee(TARGET_BLOCK_SIZE)
        self.assertEqual(tracker.base_fee, initial_fee)

    def test_base_fee_never_below_min_fee(self):
        """Base fee never drops below MIN_FEE floor."""
        tracker = SupplyTracker()
        # Force many empty blocks
        for _ in range(100):
            tracker.update_base_fee(0)
        self.assertGreaterEqual(tracker.base_fee, MIN_FEE)

    def test_base_fee_max_change_rate(self):
        """Base fee changes by at most 1/BASE_FEE_MAX_CHANGE_DENOMINATOR per block."""
        tracker = SupplyTracker()
        tracker.base_fee = 800
        initial = tracker.base_fee
        # Full block — max upward pressure
        tracker.update_base_fee(MAX_TXS_PER_BLOCK)
        max_increase = initial // BASE_FEE_MAX_CHANGE_DENOMINATOR
        self.assertLessEqual(tracker.base_fee - initial, max_increase + 1)

    def test_fee_burn_reduces_supply(self):
        """The base fee portion of each tx fee is burned (removed from supply)."""
        tracker = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        tracker.balances[sender] = 10000

        initial_supply = tracker.total_supply
        base_fee = tracker.base_fee  # 100
        total_fee = base_fee + 50  # 50 tip

        tracker.pay_fee_with_burn(sender, proposer, total_fee, base_fee)

        # Supply decreased by base_fee (burned)
        self.assertEqual(tracker.total_supply, initial_supply - base_fee)
        # Proposer got the tip (total_fee - base_fee)
        self.assertEqual(tracker.get_balance(proposer), total_fee - base_fee)
        # Sender paid the full fee
        self.assertEqual(tracker.get_balance(sender), 10000 - total_fee)

    def test_fee_burn_tracked(self):
        """Total burned tokens are tracked."""
        tracker = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        tracker.balances[sender] = 10000

        base_fee = tracker.base_fee
        tracker.pay_fee_with_burn(sender, proposer, base_fee + 10, base_fee)
        self.assertEqual(tracker.total_burned, base_fee)

        tracker.pay_fee_with_burn(sender, proposer, base_fee + 20, base_fee)
        self.assertEqual(tracker.total_burned, base_fee * 2)

    def test_tx_rejected_if_fee_below_base_fee(self):
        """Transactions with fee < base_fee are invalid at block inclusion."""
        tracker = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        tracker.balances[sender] = 10000

        base_fee = tracker.base_fee  # 100
        result = tracker.pay_fee_with_burn(sender, proposer, base_fee - 1, base_fee)
        self.assertFalse(result)

    def test_tip_goes_entirely_to_proposer(self):
        """The tip (fee minus base_fee) goes entirely to the block proposer."""
        tracker = SupplyTracker()
        sender = b"\x01" * 32
        proposer = b"\x02" * 32
        tracker.balances[sender] = 10000

        base_fee = tracker.base_fee
        tip = 500
        tracker.pay_fee_with_burn(sender, proposer, base_fee + tip, base_fee)
        self.assertEqual(tracker.get_balance(proposer), tip)


class TestBaseFeeBlockchainIntegration(unittest.TestCase):
    """Base fee integrated into block production and validation."""

    def setUp(self):
        self.alice = Entity.create(b"alice-economics-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-economics-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        self.consensus = ProofOfStake()

    def _make_block(self, proposer, txs, prev=None, attestations=None):
        if prev is None:
            prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = self.chain.compute_post_state_root(
            txs, proposer.entity_id, block_height,
        )
        return self.consensus.create_block(
            proposer, txs, prev, state_root=state_root,
            attestations=attestations,
        )

    def test_base_fee_tracked_across_blocks(self):
        """Chain tracks the current base fee as blocks are added."""
        initial_base_fee = self.chain.base_fee
        self.assertEqual(initial_base_fee, BASE_FEE_INITIAL)

    def test_fee_burned_on_block_add(self):
        """When a block is added, the base fee portion of tx fees is burned.

        Post proof-of-custody archive rewards: the archive-reward pool
        captures ARCHIVE_BURN_REDIRECT_PCT of what would have burned
        (those tokens re-enter total_supply as pool balance rather
        than being destroyed).  The remaining portion still burns.
        """
        from messagechain.config import ARCHIVE_BURN_REDIRECT_PCT
        initial_supply = self.chain.supply.total_supply
        nonce = self.chain.nonces.get(self.bob.entity_id, 0)
        fee = max(self.chain.base_fee + 50, 1500)  # must exceed identity creation fee
        tx = create_transaction(self.bob, "Hello", fee=fee, nonce=nonce)
        block = self._make_block(self.alice, [tx])
        success, _ = self.chain.add_block(block)
        self.assertTrue(success)

        # Supply increased by block reward but decreased by the
        # burned-and-not-redirected portion of the base fee.
        reward = self.chain.supply.calculate_block_reward(1)
        # base_fee was BASE_FEE_INITIAL when the block was applied.
        pool_add = BASE_FEE_INITIAL * ARCHIVE_BURN_REDIRECT_PCT // 100
        net_burn = BASE_FEE_INITIAL - pool_add
        expected_supply = initial_supply + reward - net_burn
        self.assertEqual(self.chain.supply.total_supply, expected_supply)
        # And the archive reward pool captured exactly the redirected portion.
        self.assertEqual(self.chain.archive_reward_pool, pool_add)

    def test_empty_blocks_decrease_base_fee(self):
        """Empty blocks cause the base fee to decrease over time."""
        initial_base_fee = self.chain.base_fee
        for _ in range(5):
            block = self._make_block(self.alice, [])  # empty blocks
            self.chain.add_block(block)
        # Base fee should have decreased (or stayed at MIN_FEE floor)
        self.assertLessEqual(self.chain.base_fee, initial_base_fee)


class TestAttestationRewardsIntegration(unittest.TestCase):
    """Attestation rewards work end-to-end in the blockchain."""

    def setUp(self):
        self.alice = Entity.create(b"alice-att-econ-key".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-att-econ-key".ljust(32, b"\x00"))
        self.carol = Entity.create(b"carol-att-econ-key".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice)
        register_entity_for_test(self.chain, self.bob)
        register_entity_for_test(self.chain, self.carol)
        self.chain.supply.balances[self.alice.entity_id] = 1_000_000
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        self.chain.supply.balances[self.carol.entity_id] = 1_000_000
        self.consensus = ProofOfStake()
        # Stake validators
        self.chain.supply.stake(self.bob.entity_id, 300)
        self.consensus.register_validator(self.bob.entity_id, 300)
        self.chain.supply.stake(self.carol.entity_id, 100)
        self.consensus.register_validator(self.carol.entity_id, 100)

    def _make_block(self, proposer, txs, prev=None, attestations=None):
        if prev is None:
            prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1
        state_root = self.chain.compute_post_state_root(
            txs, proposer.entity_id, block_height,
            attestations=attestations,
        )
        return self.consensus.create_block(
            proposer, txs, prev, state_root=state_root,
            attestations=attestations,
        )

    def test_attestors_receive_rewards(self):
        """Both attesters receive flat per-slot rewards via the committee.

        Under the committee reward model, every committee member earns
        ATTESTER_REWARD_PER_SLOT (flat 1 token) — stake affects selection
        probability, not payout size.  With only two candidates (Bob,
        Carol) and committee_size >= 2, both are selected every block,
        so both earn the slot reward.  The old "pro-rata by stake"
        invariant no longer applies.
        """
        from messagechain.consensus.attester_committee import (
            ATTESTER_REWARD_PER_SLOT,
        )
        candidates = [self.alice, self.bob, self.carol]

        proposer1 = pick_selected_proposer(self.chain, candidates)
        block1 = self._make_block(proposer1, [])
        ok, reason = self.chain.add_block(block1)
        self.assertTrue(ok, reason)

        bob_before = self.chain.supply.get_balance(self.bob.entity_id)
        carol_before = self.chain.supply.get_balance(self.carol.entity_id)

        att_bob = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att_carol = create_attestation(self.carol, block1.block_hash, block1.header.block_number)

        proposer2 = pick_selected_proposer(self.chain, candidates)
        block2 = self._make_block(proposer2, [], attestations=[att_bob, att_carol])
        success, reason = self.chain.add_block(block2)
        self.assertTrue(success, reason)

        bob_after = self.chain.supply.get_balance(self.bob.entity_id)
        carol_after = self.chain.supply.get_balance(self.carol.entity_id)

        # Whichever of {bob, carol} is NOT the proposer2 must have
        # gained exactly ATTESTER_REWARD_PER_SLOT from the committee.
        # The one who IS the proposer gained proposer_share +
        # committee slot (capped by PROPOSER_REWARD_CAP).
        if proposer2.entity_id == self.bob.entity_id:
            # Carol is pure committee member
            self.assertEqual(
                carol_after - carol_before, ATTESTER_REWARD_PER_SLOT,
            )
            # Bob got proposer share too — strictly more than Carol
            self.assertGreater(bob_after - bob_before, carol_after - carol_before)
        elif proposer2.entity_id == self.carol.entity_id:
            self.assertEqual(
                bob_after - bob_before, ATTESTER_REWARD_PER_SLOT,
            )
            self.assertGreater(carol_after - carol_before, bob_after - bob_before)
        else:
            # Alice proposed; both Bob and Carol are pure committee members
            self.assertEqual(bob_after - bob_before, ATTESTER_REWARD_PER_SLOT)
            self.assertEqual(carol_after - carol_before, ATTESTER_REWARD_PER_SLOT)


class TestLongTermEconomics(unittest.TestCase):
    """Verify the economic model sustains validator incentives over time."""

    def test_reward_floor_provides_meaningful_income(self):
        """At the reward floor, annual minting is still non-trivial."""
        tracker = SupplyTracker()
        # Simulate far-future block
        far_future = HALVING_INTERVAL * 50
        reward = tracker.calculate_block_reward(far_future)
        self.assertEqual(reward, BLOCK_REWARD_FLOOR)

        # ~263K blocks/year at 120s blocks
        annual_minting = reward * 263_000
        # Should be at least 0.05% of genesis supply
        min_annual = tracker.total_supply * 5 // 10_000
        self.assertGreaterEqual(annual_minting, min_annual)

    def test_burn_creates_deflationary_pressure(self):
        """Over many blocks, base fee burn creates meaningful deflation."""
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        # Simulate 100 blocks with 10 txs each, all paying base_fee + small tip
        total_burned = 0
        for _ in range(100):
            for _ in range(10):
                sender = b"\x99" * 32
                tracker.balances[sender] = tracker.balances.get(sender, 0) + 10000
                base_fee = tracker.base_fee
                tracker.pay_fee_with_burn(sender, proposer, base_fee + MIN_TIP, base_fee)
                total_burned += base_fee
            tracker.update_base_fee(10)  # at target, base fee stays stable

        self.assertEqual(tracker.total_burned, total_burned)
        self.assertGreater(tracker.total_burned, 0)

    def test_high_demand_benefits_validators(self):
        """When blocks are full, validators earn more from higher tips."""
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        sender = b"\x02" * 32
        tracker.balances[sender] = 10_000_000

        # Simulate 20 full blocks to drive up base fee
        for _ in range(20):
            tracker.update_base_fee(MAX_TXS_PER_BLOCK)

        elevated_fee = tracker.base_fee
        self.assertGreater(elevated_fee, BASE_FEE_INITIAL)

        # Even at high base fee, the tip to proposer grows with demand
        tip = 100
        tracker.pay_fee_with_burn(sender, proposer, elevated_fee + tip, elevated_fee)
        self.assertEqual(tracker.get_balance(proposer), tip)


if __name__ == "__main__":
    unittest.main()
