"""Tier 19 — soft equivocation slash (operator-mistake survivability).

Pre-fork (height < SOFT_SLASH_HEIGHT) the equivocation penalty is a
full 100% stake + escrow burn plus permanent removal from the
validator set.  That penalty matched a deliberate Byzantine attack
but was catastrophic for the most common honest-operator failure mode:
running two nodes under the same key (failover misconfig, restored
backup with the old node still running, restart race).  One accidental
dual-sign wiped the operator's entire bond.

Post-fork the penalty is partial — SOFT_SLASH_PCT (5%) of stake +
the same fraction of bootstrap escrow + the same fraction of any
pending unstakes (so an offender cannot escape by unstaking faster
than evidence can be submitted).  The offender stays in the set with
reduced stake; only `_processed_evidence` is updated, so the SAME
piece of evidence cannot be applied twice but new evidence against
the same offender lands at a new partial slash.

Repeat-offender economics fall out without escalation logic: each new
slash burns 5% of what's left, so a stuck dual-node operator with N
mistakes decays geometrically as (1-0.05)^N → 10 mistakes ≈ 40%
loss, 50 mistakes ≈ 92% loss.  Sustained misbehavior still
approaches total stake loss; a single accident does not.
"""

import unittest
import time
from unittest.mock import patch

from messagechain.identity.identity import Entity
from messagechain.core.blockchain import Blockchain
from messagechain.core.block import BlockHeader, _hash
from messagechain.consensus.slashing import (
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.config import (
    SLASH_PENALTY_PCT,
    SLASH_FINDER_REWARD_PCT,
    SOFT_SLASH_HEIGHT,
    SOFT_SLASH_PCT,
    TIER_18_HEIGHT,
)
from tests import register_entity_for_test


def _make_conflicting_headers(proposer_entity, prev_block):
    """Two distinct signed headers at the same height — equivocation."""
    block_num = prev_block.header.block_number + 1
    header_a = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"empty"),
        timestamp=time.time(),
        proposer_id=proposer_entity.entity_id,
    )
    header_a.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_a.signable_data()),
    )
    header_b = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"different"),
        timestamp=time.time() + 1,
        proposer_id=proposer_entity.entity_id,
    )
    header_b.proposer_signature = proposer_entity.keypair.sign(
        _hash(header_b.signable_data()),
    )
    return header_a, header_b


def _slash_at_height(chain, alice, bob, carol_id, prev_block, fork_active: bool):
    """Build evidence + apply slash. If fork_active, force post-fork height
    by patching SOFT_SLASH_HEIGHT to 0; otherwise keep default (13000)."""
    header_a, header_b = _make_conflicting_headers(alice, prev_block)
    evidence = SlashingEvidence(
        offender_id=alice.entity_id,
        header_a=header_a,
        header_b=header_b,
    )
    slash_tx = create_slash_transaction(bob, evidence, fee=1500)
    if fork_active:
        with patch("messagechain.config.SOFT_SLASH_HEIGHT", 0):
            return chain.apply_slash_transaction(slash_tx, carol_id)
    return chain.apply_slash_transaction(slash_tx, carol_id)


class TestTier19ForkConstants(unittest.TestCase):
    def test_fork_height_above_tier_18(self):
        """SOFT_SLASH_HEIGHT must follow TIER_18_HEIGHT — Tier 19 rides above."""
        self.assertGreater(SOFT_SLASH_HEIGHT, TIER_18_HEIGHT)

    def test_soft_slash_pct_is_partial(self):
        """The whole point of the fork is a partial slash; equality with the
        pre-fork 100% would make the fork a no-op."""
        self.assertGreater(SOFT_SLASH_PCT, 0)
        self.assertLess(SOFT_SLASH_PCT, SLASH_PENALTY_PCT)


class TestPreForkBehaviorPreserved(unittest.TestCase):
    """Below SOFT_SLASH_HEIGHT the slash semantics must be byte-identical
    to today: 100% stake burn + permanent ban via `slashed_validators`."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-pre-fork".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-pre-fork".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-pre-fork".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.balances[e.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 1_000)

    def test_pre_fork_full_slash_burns_all_stake(self):
        prev = self.chain.get_latest_block()
        ok, msg = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev,
            fork_active=False,
        )
        self.assertTrue(ok, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)
        self.assertIn(self.alice.entity_id, self.chain.slashed_validators)


class TestPostForkPartialSlash(unittest.TestCase):
    """At/after SOFT_SLASH_HEIGHT the equivocation slash is partial and
    the offender stays in the validator set."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-post-fork".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-post-fork".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-post-fork".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.balances[e.entity_id] = 1_000_000
        self.chain.supply.stake(self.alice.entity_id, 100_000)

    def test_post_fork_partial_stake_burn(self):
        """5% of stake is burned, not 100%."""
        prev = self.chain.get_latest_block()
        ok, msg = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev,
            fork_active=True,
        )
        self.assertTrue(ok, msg)
        expected_remaining = 100_000 - (100_000 * SOFT_SLASH_PCT // 100)
        self.assertEqual(
            self.chain.supply.get_staked(self.alice.entity_id),
            expected_remaining,
            f"expected ~95k stake remaining post-fork, got "
            f"{self.chain.supply.get_staked(self.alice.entity_id)}",
        )

    def test_post_fork_no_permaban(self):
        """Offender stays out of slashed_validators set so they can keep
        operating with reduced stake."""
        prev = self.chain.get_latest_block()
        ok, _ = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev,
            fork_active=True,
        )
        self.assertTrue(ok)
        self.assertNotIn(self.alice.entity_id, self.chain.slashed_validators)

    def test_post_fork_repeat_evidence_compounds(self):
        """A second piece of distinct evidence against the same offender
        slashes another 5% of the (already-reduced) stake."""
        # First offense
        prev1 = self.chain.get_latest_block()
        ok1, _ = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev1,
            fork_active=True,
        )
        self.assertTrue(ok1)
        after_first = self.chain.supply.get_staked(self.alice.entity_id)
        self.assertEqual(after_first, 95_000)

        # Second offense — different evidence (different timestamps in the
        # conflicting headers), same offender.  Pre-fork this would be
        # rejected as "already slashed"; post-fork it must land.
        prev2 = self.chain.get_latest_block()
        header_c, header_d = _make_conflicting_headers(self.alice, prev2)
        # Force fresh evidence: shift timestamps so evidence_hash differs
        header_c.timestamp = time.time() + 100
        header_c.proposer_signature = self.alice.keypair.sign(
            _hash(header_c.signable_data()),
        )
        header_d.timestamp = time.time() + 101
        header_d.proposer_signature = self.alice.keypair.sign(
            _hash(header_d.signable_data()),
        )
        evidence2 = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_c,
            header_b=header_d,
        )
        slash_tx2 = create_slash_transaction(self.bob, evidence2, fee=1500)
        with patch("messagechain.config.SOFT_SLASH_HEIGHT", 0):
            ok2, msg2 = self.chain.apply_slash_transaction(
                slash_tx2, self.carol.entity_id,
            )
        self.assertTrue(ok2, msg2)
        # Second slash burns 5% of remaining 95_000 = 4_750 → 90_250 left
        expected_after_second = after_first - (after_first * SOFT_SLASH_PCT // 100)
        self.assertEqual(
            self.chain.supply.get_staked(self.alice.entity_id),
            expected_after_second,
        )

    def test_post_fork_same_evidence_still_dedupes(self):
        """Even though the offender isn't permabanned, the SAME piece of
        evidence (same evidence_hash) cannot be applied twice — that
        would let the finder claim the reward repeatedly off one report."""
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_conflicting_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a,
            header_b=header_b,
        )
        slash_tx_1 = create_slash_transaction(self.bob, evidence, fee=1500)
        slash_tx_2 = create_slash_transaction(self.bob, evidence, fee=1500)
        with patch("messagechain.config.SOFT_SLASH_HEIGHT", 0):
            ok1, _ = self.chain.apply_slash_transaction(
                slash_tx_1, self.carol.entity_id,
            )
            ok2, msg2 = self.chain.apply_slash_transaction(
                slash_tx_2, self.carol.entity_id,
            )
        self.assertTrue(ok1)
        self.assertFalse(ok2, "same evidence must not slash twice")
        self.assertIn("already submitted", msg2.lower())

    def test_post_fork_finder_reward_scales(self):
        """Finder reward = 10% of the (now-smaller) slashed amount."""
        bob_balance_before = self.chain.supply.get_balance(self.bob.entity_id)
        prev = self.chain.get_latest_block()
        ok, _ = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev,
            fork_active=True,
        )
        self.assertTrue(ok)
        slashed = 100_000 * SOFT_SLASH_PCT // 100  # 5_000
        expected_reward = slashed * SLASH_FINDER_REWARD_PCT // 100  # 500
        bob_balance_after = self.chain.supply.get_balance(self.bob.entity_id)
        # Bob earned reward, paid 1500 fee
        self.assertEqual(
            bob_balance_after,
            bob_balance_before + expected_reward - 1500,
        )

    def test_post_fork_pending_unstakes_partially_slashed(self):
        """Pending unstakes are slashed at the same partial percent, not
        zeroed.  An offender cannot escape by unstaking — but they don't
        lose 100% of unbonding tokens either."""
        # Move some stake into pending_unstakes
        self.chain.supply.unstake(self.alice.entity_id, 20_000, current_block=1)
        pending_before = self.chain.supply.get_pending_unstake(self.alice.entity_id)
        staked_before = self.chain.supply.get_staked(self.alice.entity_id)
        self.assertEqual(pending_before, 20_000)
        self.assertEqual(staked_before, 80_000)

        prev = self.chain.get_latest_block()
        ok, _ = _slash_at_height(
            self.chain, self.alice, self.bob, self.carol.entity_id, prev,
            fork_active=True,
        )
        self.assertTrue(ok)

        # 5% of pending should be burned, leaving 95% (= 19_000)
        pending_after = self.chain.supply.get_pending_unstake(self.alice.entity_id)
        self.assertEqual(
            pending_after,
            pending_before - (pending_before * SOFT_SLASH_PCT // 100),
            f"expected pending unstakes scaled by 95%, got {pending_after}",
        )
        # 5% of stake should be burned, leaving 95% (= 76_000)
        staked_after = self.chain.supply.get_staked(self.alice.entity_id)
        self.assertEqual(
            staked_after,
            staked_before - (staked_before * SOFT_SLASH_PCT // 100),
        )


if __name__ == "__main__":
    unittest.main()
