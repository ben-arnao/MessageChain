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
from tests import register_entity_for_test


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
    """Block reward is split between proposer and attestors."""

    def test_config_split_is_valid(self):
        """Proposer share must be < 100% (leaving room for attestors)."""
        self.assertLess(PROPOSER_REWARD_NUMERATOR, PROPOSER_REWARD_DENOMINATOR)

    def test_no_attestors_proposer_gets_capped_reward(self):
        """When no attestors are present, proposer gets reward up to cap."""
        from messagechain.config import PROPOSER_REWARD_CAP
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        reward = tracker.calculate_block_reward(1)
        distributed = tracker.mint_block_reward(proposer, 1, attestor_stakes={})
        expected = min(reward, PROPOSER_REWARD_CAP)
        self.assertEqual(distributed["proposer_reward"], expected)
        self.assertEqual(distributed["total_attestor_reward"], 0)
        self.assertEqual(tracker.get_balance(proposer), expected)

    def test_reward_split_with_attestors(self):
        """Proposer gets 1/4, attestors share 3/4."""
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_a = b"\x02" * 32
        att_b = b"\x03" * 32
        attestor_stakes = {att_a: 300, att_b: 100}

        reward = tracker.calculate_block_reward(1)
        result = tracker.mint_block_reward(proposer, 1, attestor_stakes=attestor_stakes)

        proposer_share = reward * PROPOSER_REWARD_NUMERATOR // PROPOSER_REWARD_DENOMINATOR
        attestor_pool = reward - proposer_share

        self.assertEqual(result["proposer_reward"], proposer_share)
        self.assertEqual(result["total_attestor_reward"], attestor_pool)
        self.assertGreater(result["total_attestor_reward"], result["proposer_reward"])

    def test_attestor_rewards_proportional_to_stake(self):
        """Attestors with more stake get proportionally more reward."""
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_big = b"\x02" * 32
        att_small = b"\x03" * 32
        # 3:1 stake ratio
        attestor_stakes = {att_big: 300, att_small: 100}

        tracker.mint_block_reward(proposer, 1, attestor_stakes=attestor_stakes)

        big_balance = tracker.get_balance(att_big)
        small_balance = tracker.get_balance(att_small)
        # big should get ~3x more than small (integer math may cause slight rounding)
        self.assertGreater(big_balance, small_balance)
        # Within rounding tolerance: big/small should be close to 3
        if small_balance > 0:
            ratio = big_balance / small_balance
            self.assertAlmostEqual(ratio, 3.0, delta=0.5)

    def test_total_minted_equals_reward(self):
        """Total tokens distributed = block reward (no tokens created or lost)."""
        from messagechain.config import TREASURY_ENTITY_ID
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        att_a = b"\x02" * 32
        att_b = b"\x03" * 32
        attestor_stakes = {att_a: 200, att_b: 200}

        initial_supply = tracker.total_supply
        reward = tracker.calculate_block_reward(1)
        tracker.mint_block_reward(proposer, 1, attestor_stakes=attestor_stakes)

        # Supply increased by exactly the reward
        self.assertEqual(tracker.total_supply, initial_supply + reward)
        # All minted tokens are accounted for in balances (including treasury)
        total_distributed = (
            tracker.get_balance(proposer)
            + tracker.get_balance(att_a)
            + tracker.get_balance(att_b)
            + tracker.get_balance(TREASURY_ENTITY_ID)
        )
        self.assertEqual(total_distributed, reward)

    def test_proposer_who_is_also_attestor_is_capped(self):
        """If proposer is also an attestor, their total is capped."""
        from messagechain.config import PROPOSER_REWARD_CAP, TREASURY_ENTITY_ID
        tracker = SupplyTracker()
        proposer = b"\x01" * 32
        other_att = b"\x02" * 32
        attestor_stakes = {proposer: 100, other_att: 100}

        reward = tracker.calculate_block_reward(1)
        tracker.mint_block_reward(proposer, 1, attestor_stakes=attestor_stakes)

        proposer_balance = tracker.get_balance(proposer)
        other_balance = tracker.get_balance(other_att)
        treasury_balance = tracker.get_balance(TREASURY_ENTITY_ID)
        # Proposer's total (proposer share + attestor share) is capped
        self.assertLessEqual(proposer_balance, PROPOSER_REWARD_CAP)
        # Other attestor gets their full share (not affected by cap)
        self.assertGreater(other_balance, 0)
        # All tokens accounted for (proposer + other + treasury = reward)
        self.assertEqual(proposer_balance + other_balance + treasury_balance, reward)


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
        self.alice = Entity.create(b"alice-economics-key")
        self.bob = Entity.create(b"bob-economics-key")
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
        """When a block is added, the base fee portion of tx fees is burned."""
        initial_supply = self.chain.supply.total_supply
        nonce = self.chain.nonces.get(self.bob.entity_id, 0)
        fee = max(self.chain.base_fee + 50, 1500)  # must exceed identity creation fee
        tx = create_transaction(self.bob, "Hello", fee=fee, nonce=nonce)
        block = self._make_block(self.alice, [tx])
        success, _ = self.chain.add_block(block)
        self.assertTrue(success)

        # Supply increased by block reward but decreased by base_fee burn
        reward = self.chain.supply.calculate_block_reward(1)
        # base_fee was BASE_FEE_INITIAL when the block was applied
        expected_supply = initial_supply + reward - BASE_FEE_INITIAL
        self.assertEqual(self.chain.supply.total_supply, expected_supply)

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
        self.alice = Entity.create(b"alice-att-econ-key")
        self.bob = Entity.create(b"bob-att-econ-key")
        self.carol = Entity.create(b"carol-att-econ-key")
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
        """Attestors receive a share of the block reward."""
        # First block (no attestations possible yet)
        block1 = self._make_block(self.alice, [])
        self.chain.add_block(block1)

        bob_before = self.chain.supply.get_balance(self.bob.entity_id)
        carol_before = self.chain.supply.get_balance(self.carol.entity_id)

        # Create attestations for block1
        att_bob = create_attestation(self.bob, block1.block_hash, block1.header.block_number)
        att_carol = create_attestation(self.carol, block1.block_hash, block1.header.block_number)

        # Block2 includes attestations — attestors should earn rewards
        block2 = self._make_block(self.alice, [], attestations=[att_bob, att_carol])
        success, _ = self.chain.add_block(block2)
        self.assertTrue(success)

        bob_after = self.chain.supply.get_balance(self.bob.entity_id)
        carol_after = self.chain.supply.get_balance(self.carol.entity_id)

        # Both attestors gained tokens
        self.assertGreater(bob_after, bob_before)
        self.assertGreater(carol_after, carol_before)

        # Bob staked 3x more, should get ~3x more attestation reward
        bob_gain = bob_after - bob_before
        carol_gain = carol_after - carol_before
        if carol_gain > 0:
            ratio = bob_gain / carol_gain
            self.assertAlmostEqual(ratio, 3.0, delta=1.0)


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
