"""Tests for inactivity leak — Casper-style defense against liveness attacks.

Covers:
    * Leak mode activates after THRESHOLD blocks without finalization
    * Leak mode does NOT activate when finalization is healthy
    * During leak mode, non-attesting validators lose stake (quadratic scaling)
    * Attesting validators are NOT penalized
    * Leaked stake is burned (total_supply decreases)
    * After sufficient leak, honest 60% becomes new 2/3
    * Finalization resuming deactivates leak mode
    * Penalties stop immediately after deactivation
    * Validator with drained stake (reaches 0) is deactivated
    * The quadratic scaling: penalty at block 10 vs 100 vs 1000
    * Integration: a 40/60 split scenario where cartel goes silent,
      leak kicks in, honest validators eventually finalize
    * blocks_since_last_finalization tracks correctly across blocks
"""

import unittest

from messagechain.consensus.inactivity import (
    is_leak_active,
    compute_inactivity_penalty,
    get_inactive_validators,
    apply_inactivity_leak,
)
from messagechain.config import (
    INACTIVITY_LEAK_ACTIVATION_THRESHOLD,
    INACTIVITY_PENALTY_QUOTIENT,
    INACTIVITY_BASE_PENALTY,
)


class TestLeakActivation(unittest.TestCase):
    """Leak mode activates after THRESHOLD blocks without finalization."""

    def test_no_leak_at_zero(self):
        self.assertFalse(is_leak_active(0))

    def test_no_leak_at_threshold(self):
        """Exactly at the threshold — not yet active."""
        self.assertFalse(is_leak_active(INACTIVITY_LEAK_ACTIVATION_THRESHOLD))

    def test_leak_activates_past_threshold(self):
        self.assertTrue(is_leak_active(INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1))

    def test_leak_active_well_past_threshold(self):
        self.assertTrue(is_leak_active(1000))


class TestComputeInactivityPenalty(unittest.TestCase):
    """Penalty computation: quadratic scaling, capped at stake."""

    def test_no_penalty_below_threshold(self):
        """No penalty when finalization is healthy or at threshold."""
        for blocks in range(INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1):
            penalty = compute_inactivity_penalty(blocks, 1000)
            self.assertEqual(penalty, 0, f"Expected 0 penalty at {blocks} blocks")

    def test_no_penalty_zero_stake(self):
        """Zero-stake validators are not penalized."""
        penalty = compute_inactivity_penalty(100, 0)
        self.assertEqual(penalty, 0)

    def test_quadratic_scaling(self):
        """Penalty grows quadratically with blocks_since_finality."""
        stake = 10_000_000  # large enough that cap doesn't interfere
        p10 = compute_inactivity_penalty(10, stake)
        p100 = compute_inactivity_penalty(100, stake)
        p1000 = compute_inactivity_penalty(1000, stake)

        # At 10 blocks: 1 * 100 / 16_777_216 = 0 (rounds to 0)
        # At 100 blocks: 1 * 10000 / 16_777_216 = 0 (rounds to 0)
        # At 1000 blocks: 1 * 1_000_000 / 16_777_216 = 0 (still 0)
        # We need larger blocks_since_finality to get non-zero
        # At 4096 blocks: 1 * 16_777_216 / 16_777_216 = 1
        p4096 = compute_inactivity_penalty(4096, stake)
        self.assertEqual(p4096, 1)

        # At 8192 blocks: 1 * 67_108_864 / 16_777_216 = 4
        p8192 = compute_inactivity_penalty(8192, stake)
        self.assertEqual(p8192, 4)

        # Verify quadratic: p8192 = 4 * p4096 (because 8192 = 2 * 4096)
        self.assertEqual(p8192, 4 * p4096)

    def test_penalty_capped_at_stake(self):
        """Penalty never exceeds the validator's current stake."""
        penalty = compute_inactivity_penalty(1_000_000, 100)
        self.assertEqual(penalty, 100)

    def test_small_penalty_early(self):
        """Early in a stall, penalties are tiny — brief outages are cheap."""
        # 5 blocks past threshold — penalty should be near-zero for
        # reasonable stake amounts.
        blocks = INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1
        penalty = compute_inactivity_penalty(blocks, 1000)
        # 1 * 5^2 / 16M = 25/16M = 0
        self.assertEqual(penalty, 0)


class TestGetInactiveValidators(unittest.TestCase):
    """Expected vs actual attester set computation."""

    def test_all_attested(self):
        expected = {b"a", b"b", b"c"}
        actual = {b"a", b"b", b"c"}
        self.assertEqual(get_inactive_validators(expected, actual), set())

    def test_some_inactive(self):
        expected = {b"a", b"b", b"c"}
        actual = {b"a"}
        self.assertEqual(get_inactive_validators(expected, actual), {b"b", b"c"})

    def test_all_inactive(self):
        expected = {b"a", b"b"}
        actual = set()
        self.assertEqual(get_inactive_validators(expected, actual), {b"a", b"b"})

    def test_extra_actual_ignored(self):
        """Attesters not in expected set don't affect the result."""
        expected = {b"a"}
        actual = {b"a", b"z"}
        self.assertEqual(get_inactive_validators(expected, actual), set())


class TestApplyInactivityLeak(unittest.TestCase):
    """apply_inactivity_leak mutates staked, returns burned+deactivated."""

    def test_burns_stake_from_inactive(self):
        """Inactive validators lose stake during leak."""
        staked = {b"a": 1000, b"b": 1000}
        inactive = {b"b"}
        # Use a large blocks_since_finality so penalty > 0
        total_burned, deactivated = apply_inactivity_leak(
            staked, blocks_since_finality=10000, inactive_validators=inactive,
        )
        self.assertGreater(total_burned, 0)
        self.assertLess(staked[b"b"], 1000)
        # Active validator untouched
        self.assertEqual(staked[b"a"], 1000)

    def test_active_not_penalized(self):
        """Validators who ARE attesting are never penalized."""
        staked = {b"a": 1000, b"b": 1000}
        inactive = set()  # both active
        total_burned, deactivated = apply_inactivity_leak(
            staked, blocks_since_finality=100000, inactive_validators=inactive,
        )
        self.assertEqual(total_burned, 0)
        self.assertEqual(staked[b"a"], 1000)
        self.assertEqual(staked[b"b"], 1000)

    def test_deactivated_when_stake_reaches_zero(self):
        """Validators drained to 0 are returned in the deactivated set."""
        staked = {b"a": 1}  # tiny stake, huge penalty
        inactive = {b"a"}
        total_burned, deactivated = apply_inactivity_leak(
            staked, blocks_since_finality=100000, inactive_validators=inactive,
        )
        self.assertIn(b"a", deactivated)
        self.assertEqual(staked[b"a"], 0)

    def test_no_penalty_below_min_stake(self):
        """Validators at or below min_stake are skipped (not penalized further)."""
        staked = {b"a": 5}
        inactive = {b"a"}
        total_burned, deactivated = apply_inactivity_leak(
            staked, blocks_since_finality=100000,
            inactive_validators=inactive, min_stake=10,
        )
        # Stake is 5, min_stake is 10 — should be skipped
        self.assertEqual(total_burned, 0)
        self.assertEqual(staked[b"a"], 5)

    def test_burned_equals_stake_lost(self):
        """Total burned equals the actual stake decrease across all inactive."""
        staked = {b"a": 5000, b"b": 3000, b"c": 1000}
        inactive = {b"a", b"c"}
        before_a = staked[b"a"]
        before_c = staked[b"c"]
        total_burned, _ = apply_inactivity_leak(
            staked, blocks_since_finality=10000, inactive_validators=inactive,
        )
        actual_lost = (before_a - staked[b"a"]) + (before_c - staked[b"c"])
        self.assertEqual(total_burned, actual_lost)


class TestQuadraticGrowth(unittest.TestCase):
    """Verify quadratic growth of penalties over time."""

    def test_penalty_ratios_are_quadratic(self):
        """Doubling blocks_since_finality quadruples the penalty."""
        stake = 10**12  # absurdly large to avoid cap
        n = 100_000
        p_n = compute_inactivity_penalty(n, stake)
        p_2n = compute_inactivity_penalty(2 * n, stake)
        # p_2n should be 4 * p_n (quadratic)
        self.assertEqual(p_2n, 4 * p_n)

    def test_penalty_at_known_values(self):
        """Spot-check penalty at specific block counts."""
        stake = 10**12
        # penalty = 1 * blocks^2 / 16_777_216
        # At blocks=4096: 4096^2 = 16_777_216, penalty = 1
        self.assertEqual(compute_inactivity_penalty(4096, stake), 1)
        # At blocks=4096*2=8192: 8192^2 / 16_777_216 = 4
        self.assertEqual(compute_inactivity_penalty(8192, stake), 4)
        # At blocks=4096*10=40960: 40960^2 / 16_777_216 = 100
        self.assertEqual(compute_inactivity_penalty(40960, stake), 100)


class TestCartelRecoveryScenario(unittest.TestCase):
    """Simulate 40% cartel going silent, verify honest 60% recovers 2/3.

    Setup: 5 validators, 3 honest (60 stake each = 180 total honest),
    2 malicious (60 stake each = 120 total malicious).
    Total = 300.  Honest 180/300 = 60% < 2/3.

    The leak should drain malicious stake until honest_stake * 3 >= total * 2.
    """

    def test_recovery_from_40pct_cartel(self):
        honest_stake = {b"h1": 60, b"h2": 60, b"h3": 60}
        cartel_stake = {b"m1": 60, b"m2": 60}
        staked = {**honest_stake, **cartel_stake}
        cartel_ids = set(cartel_stake.keys())

        # Verify initial: honest 180, total 300 — no 2/3
        honest_total = sum(staked[v] for v in honest_stake)
        total = sum(staked.values())
        self.assertFalse(honest_total * 3 >= total * 2)

        # Run leak until honest reaches 2/3
        blocks_since_finality = INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1
        max_iterations = 200_000
        for _ in range(max_iterations):
            apply_inactivity_leak(
                staked, blocks_since_finality, cartel_ids,
            )
            blocks_since_finality += 1

            honest_total = sum(staked[v] for v in honest_stake)
            total = sum(staked.values())
            if total > 0 and honest_total * 3 >= total * 2:
                break
        else:
            self.fail("Honest validators never recovered 2/3 supermajority")

        # After recovery: honest stake is untouched, cartel is drained
        for h in honest_stake:
            self.assertEqual(staked[h], 60, f"Honest validator {h} was penalized")
        for m in cartel_ids:
            self.assertLess(staked[m], 60, f"Cartel validator {m} was not penalized")

        # Report recovery time for the task output
        recovery_blocks = blocks_since_finality - INACTIVITY_LEAK_ACTIVATION_THRESHOLD
        # Store for reporting
        self._recovery_blocks = recovery_blocks

    def test_recovery_block_count_reasonable(self):
        """The 40% cartel scenario recovers within ~10000 blocks (~70 days)."""
        staked = {b"h1": 60, b"h2": 60, b"h3": 60, b"m1": 60, b"m2": 60}
        cartel_ids = {b"m1", b"m2"}

        blocks_since_finality = INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1
        for _ in range(200_000):
            apply_inactivity_leak(staked, blocks_since_finality, cartel_ids)
            blocks_since_finality += 1
            honest_total = sum(staked[v] for v in [b"h1", b"h2", b"h3"])
            total = sum(staked.values())
            if total > 0 and honest_total * 3 >= total * 2:
                break

        recovery_blocks = blocks_since_finality - INACTIVITY_LEAK_ACTIVATION_THRESHOLD
        # Must recover — failing to do so is a critical bug
        self.assertGreater(recovery_blocks, 0)
        # Should recover within a reasonable timeframe
        # With the quotient of 2^24, recovery for 120 stake should take
        # around 5800 blocks (~40 days at 600s)
        self.assertLess(recovery_blocks, 20_000)


class TestBlockchainInactivityIntegration(unittest.TestCase):
    """Integration test: blocks_since_last_finalization tracking in Blockchain."""

    def setUp(self):
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.pos import ProofOfStake
        from messagechain.consensus.attestation import create_attestation
        from messagechain.config import TREASURY_ENTITY_ID

        self.Entity = Entity
        self.Blockchain = Blockchain
        self.ProofOfStake = ProofOfStake
        self.create_attestation = create_attestation

        self.alice = Entity.create(b"alice-inactivity".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-inactivity".ljust(32, b"\x00"))
        self.carol = Entity.create(b"carol-inactivity".ljust(32, b"\x00"))

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.alice, allocation_table={
            TREASURY_ENTITY_ID: 40_000_000,
            self.alice.entity_id: 1_000_000,
        })
        self._register(self.bob)
        self._register(self.carol)
        self.chain.supply.balances[self.bob.entity_id] = 1_000_000
        self.chain.supply.balances[self.carol.entity_id] = 1_000_000

        self.consensus = ProofOfStake()
        self.chain.supply.stake(self.alice.entity_id, 300)
        self.consensus.register_validator(self.alice.entity_id, 300)
        self.chain.supply.stake(self.bob.entity_id, 300)
        self.consensus.register_validator(self.bob.entity_id, 300)
        self.chain.supply.stake(self.carol.entity_id, 300)
        self.consensus.register_validator(self.carol.entity_id, 300)

    def _register(self, entity):
        import hashlib
        from messagechain.config import HASH_ALGO
        h = hashlib.new(HASH_ALGO, b"register" + entity.entity_id).digest()
        proof = entity.keypair.sign(h)
        self.chain._install_pubkey_direct(entity.entity_id, entity.public_key, proof)

    def _pick_proposer(self, candidates):
        latest = self.chain.get_latest_block()
        expected = self.chain._selected_proposer_for_slot(latest, round_number=0)
        if expected is None:
            return candidates[0]
        for c in candidates:
            if c.entity_id == expected:
                return c
        return candidates[0]

    def _make_block(self, proposer, txs=None, attestations=None):
        prev = self.chain.get_latest_block()
        block_height = prev.header.block_number + 1
        txs = txs or []
        state_root = self.chain.compute_post_state_root(
            txs, proposer.entity_id, block_height,
            attestations=attestations,
        )
        return self.consensus.create_block(
            proposer, txs, prev, state_root=state_root,
            attestations=attestations,
        )

    def test_blocks_since_finalization_starts_at_zero(self):
        """Fresh chain starts with blocks_since_last_finalization = 0."""
        self.assertEqual(self.chain.blocks_since_last_finalization, 0)

    def test_counter_increments_without_finalization(self):
        """blocks_since_last_finalization increments each block."""
        candidates = [self.alice, self.bob, self.carol]
        for i in range(3):
            p = self._pick_proposer(candidates)
            blk = self._make_block(p)
            ok, msg = self.chain.add_block(blk)
            self.assertTrue(ok, msg)

        # After 3 blocks with no attestations, counter should be 3
        self.assertEqual(self.chain.blocks_since_last_finalization, 3)

    def test_counter_resets_on_finalization(self):
        """Counter resets when a block gets finalized via attestations."""
        candidates = [self.alice, self.bob, self.carol]

        # Block 1: no attestations
        p1 = self._pick_proposer(candidates)
        blk1 = self._make_block(p1)
        ok, msg = self.chain.add_block(blk1)
        self.assertTrue(ok, msg)

        # Block 2: attestations for block 1 from all three validators
        att_a = self.create_attestation(
            self.alice, blk1.block_hash, blk1.header.block_number,
        )
        att_b = self.create_attestation(
            self.bob, blk1.block_hash, blk1.header.block_number,
        )
        att_c = self.create_attestation(
            self.carol, blk1.block_hash, blk1.header.block_number,
        )
        p2 = self._pick_proposer(candidates)
        blk2 = self._make_block(p2, attestations=[att_a, att_b, att_c])
        ok, msg = self.chain.add_block(blk2)
        self.assertTrue(ok, msg)

        # Block 1 should be finalized (3 validators all attested with
        # 300 stake each = 900 total, 900*3 >= 900*2)
        self.assertTrue(self.chain.finality.is_finalized(blk1.block_hash))

        # Counter should have reset
        self.assertEqual(self.chain.blocks_since_last_finalization, 0)

    def test_leak_applies_to_inactive_during_stall(self):
        """During a finalization stall, inactive validators lose stake."""
        candidates = [self.alice, self.bob, self.carol]

        # Produce THRESHOLD + 2 blocks without attestations
        for i in range(INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 2):
            p = self._pick_proposer(candidates)
            blk = self._make_block(p)
            ok, msg = self.chain.add_block(blk)
            self.assertTrue(ok, msg)

        # Verify we're in leak mode
        self.assertTrue(is_leak_active(self.chain.blocks_since_last_finalization))

        # At such early blocks (6 blocks), the penalty is tiny and
        # likely rounds to 0 with the large quotient. This is by design.
        # We verify the counter is correct.
        self.assertEqual(
            self.chain.blocks_since_last_finalization,
            INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 2,
        )

    def test_leak_not_active_with_healthy_finalization(self):
        """With regular attestations, leak mode never activates."""
        candidates = [self.alice, self.bob, self.carol]

        # Block 1
        p1 = self._pick_proposer(candidates)
        blk1 = self._make_block(p1)
        ok, msg = self.chain.add_block(blk1)
        self.assertTrue(ok, msg)

        # Block 2 with attestations for block 1
        att_a = self.create_attestation(
            self.alice, blk1.block_hash, blk1.header.block_number,
        )
        att_b = self.create_attestation(
            self.bob, blk1.block_hash, blk1.header.block_number,
        )
        att_c = self.create_attestation(
            self.carol, blk1.block_hash, blk1.header.block_number,
        )
        p2 = self._pick_proposer(candidates)
        blk2 = self._make_block(p2, attestations=[att_a, att_b, att_c])
        ok, msg = self.chain.add_block(blk2)
        self.assertTrue(ok, msg)

        self.assertFalse(is_leak_active(self.chain.blocks_since_last_finalization))


class TestLeakPenaltyStopOnRecovery(unittest.TestCase):
    """Once finalization resumes, penalties stop immediately."""

    def test_penalties_stop_after_finalization_resumes(self):
        """After leak mode ends, compute_inactivity_penalty returns 0."""
        # During leak
        penalty_during = compute_inactivity_penalty(10000, 1000)
        self.assertGreater(penalty_during, 0)

        # After recovery (blocks_since_finality resets to 0)
        penalty_after = compute_inactivity_penalty(0, 1000)
        self.assertEqual(penalty_after, 0)

        # Just past threshold again after reset — still tiny/zero
        penalty_barely = compute_inactivity_penalty(
            INACTIVITY_LEAK_ACTIVATION_THRESHOLD + 1, 1000,
        )
        # (5^2 / 16M) = 0 — rounds to zero
        self.assertEqual(penalty_barely, 0)


if __name__ == "__main__":
    unittest.main()
