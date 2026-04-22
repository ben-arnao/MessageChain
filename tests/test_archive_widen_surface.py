"""Tests for iteration 3e: widen the paid-archivist surface.

Recommendation 1 from the post-3d audit.  Closes the mission-layer
gap where only ~10 fastest-connection archivists per epoch were paid
by the FCFS mechanism — which concentrated paid custody far too
narrowly for the permanence-via-distribution promise.

Two changes:

    1. Cap bump: ARCHIVE_PROOFS_PER_CHALLENGE 10 → 100.  More paid
       archivists per epoch.

    2. Reward split: ARCHIVE_REWARD 1000 → 100.  Preserves total
       per-epoch pool drain at 10,000 tokens/epoch; 10× more winners
       each earning 1/10 as much.  The economic model showed the
       old reward was wildly over-generous relative to storage cost
       (5,000-500,000×), so splitting it finer costs nothing.

    3. Selection change: strict-FCFS-over-proposer-listed-order
       replaced with a DETERMINISTIC UNIFORM SHUFFLE over valid
       proofs.  The proposer still picks WHICH proofs to include,
       but within the included set, every valid submitter has equal
       chance of making the cap.  Shuffle seed = parent block's
       randao mix (consensus-deterministic, tamper-resistant).  A
       slow-connection hobbyist who merely gets their proof INCLUDED
       in ANY block of the window now has equal odds as a
       fast-connection industrial operator.

The selection change is the load-bearing distributional fix — cap +
reward tuning alone wouldn't help if FCFS kept preselecting the same
fast operators.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import (
    ARCHIVE_PROOFS_PER_CHALLENGE,
    ARCHIVE_REWARD,
    HASH_ALGO,
)
from messagechain.consensus.archive_challenge import (
    ArchiveRewardPool,
    apply_archive_rewards,
    build_custody_proof,
)


def _h(b: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, b).digest()


def _mini_block(txs, block_number=1):
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": _h(header_bytes),
    }


def _make_proof(prover_byte, block):
    return build_custody_proof(
        prover_id=bytes([prover_byte]) * 32,
        target_height=block["block_number"],
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=0,
        tx_bytes=block["tx_bytes_list"][0],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. Config bumps
# ---------------------------------------------------------------------------


class TestConfigWidened(unittest.TestCase):
    def test_cap_raised_to_100(self):
        """Paid-archivist cap bumped 10×."""
        self.assertEqual(ARCHIVE_PROOFS_PER_CHALLENGE, 100)

    def test_per_payout_dropped_to_100(self):
        """Per-payout reward dropped 10× so total pool drain is flat."""
        self.assertEqual(ARCHIVE_REWARD, 100)

    def test_total_pool_drain_preserved(self):
        """cap × reward = 10,000 tokens/epoch, same as pre-3e (10 × 1000).
        Wider distribution without inflating the reward stream."""
        self.assertEqual(ARCHIVE_PROOFS_PER_CHALLENGE * ARCHIVE_REWARD, 10_000)


# ---------------------------------------------------------------------------
# 2. Deterministic lottery replaces strict FCFS
# ---------------------------------------------------------------------------


class TestDeterministicLottery(unittest.TestCase):
    def setUp(self):
        self.block = _mini_block(
            [f"tx-{i}".encode() * 10 for i in range(2)], 7,
        )
        # 30 valid proofs from 30 distinct provers — more than the
        # cap we'll exercise, so selection actually matters.
        self.proofs = [
            _make_proof(i + 1, self.block) for i in range(30)
        ]

    def test_selection_is_deterministic_for_same_seed(self):
        """Given the same seed, two independent calls select the same
        N winners.  Consensus-critical — every node must agree on who
        got paid."""
        pool1 = ArchiveRewardPool(); pool1.fund(1_000_000)
        pool2 = ArchiveRewardPool(); pool2.fund(1_000_000)
        seed = _h(b"test-seed")
        result_1 = apply_archive_rewards(
            proofs=self.proofs,
            pool=pool1,
            expected_block_hash=self.block["block_hash"],
            selection_seed=seed,
            max_payouts=10,
        )
        result_2 = apply_archive_rewards(
            proofs=self.proofs,
            pool=pool2,
            expected_block_hash=self.block["block_hash"],
            selection_seed=seed,
            max_payouts=10,
        )
        self.assertEqual(
            [p.prover_id for p in result_1.payouts],
            [p.prover_id for p in result_2.payouts],
        )

    def test_different_seeds_produce_different_winners(self):
        """Different randomness → different winners, proving the
        selection is actually using the seed (and not just FCFS in
        disguise)."""
        pool_a = ArchiveRewardPool(); pool_a.fund(1_000_000)
        pool_b = ArchiveRewardPool(); pool_b.fund(1_000_000)
        result_a = apply_archive_rewards(
            proofs=self.proofs, pool=pool_a,
            expected_block_hash=self.block["block_hash"],
            selection_seed=_h(b"seed-A"), max_payouts=10,
        )
        result_b = apply_archive_rewards(
            proofs=self.proofs, pool=pool_b,
            expected_block_hash=self.block["block_hash"],
            selection_seed=_h(b"seed-B"), max_payouts=10,
        )
        self.assertNotEqual(
            [p.prover_id for p in result_a.payouts],
            [p.prover_id for p in result_b.payouts],
        )

    def test_selection_is_not_submission_order_fcfs(self):
        """The STRONGEST test: with 30 submitters and cap=10, strict
        FCFS would always pick provers 1-10 (first 10 in the list).
        Deterministic lottery should almost never pick exactly that
        set.  Run a few different seeds and assert at least one seed
        produces a different winner set than the fast-connection
        bias.
        """
        fcfs_winners = {bytes([i + 1]) * 32 for i in range(10)}
        seen_non_fcfs = False
        for i in range(5):
            pool = ArchiveRewardPool(); pool.fund(1_000_000)
            result = apply_archive_rewards(
                proofs=self.proofs, pool=pool,
                expected_block_hash=self.block["block_hash"],
                selection_seed=_h(f"seed-{i}".encode()),
                max_payouts=10,
            )
            winners = {p.prover_id for p in result.payouts}
            if winners != fcfs_winners:
                seen_non_fcfs = True
                break
        self.assertTrue(
            seen_non_fcfs,
            "lottery is indistinguishable from FCFS — the fast-"
            "connection bias is not broken",
        )


# ---------------------------------------------------------------------------
# 3. Fairness: over many seeds, provers win proportionally
# ---------------------------------------------------------------------------


class TestLotteryFairness(unittest.TestCase):
    def test_every_valid_submitter_wins_sometimes_across_seeds(self):
        """Across many randomness draws, every valid submitter should
        eventually appear as a winner.  This is what "widened
        distribution" actually means — not that each seed picks
        everyone, but that no submitter is permanently excluded by
        their position in the proposer's list.
        """
        block = _mini_block(
            [f"tx-{i}".encode() * 10 for i in range(2)], 7,
        )
        # 20 valid provers; pick 5 per round; many rounds.
        proofs = [_make_proof(i + 1, block) for i in range(20)]
        ever_won: set[bytes] = set()
        for i in range(200):
            pool = ArchiveRewardPool(); pool.fund(1_000_000)
            result = apply_archive_rewards(
                proofs=proofs, pool=pool,
                expected_block_hash=block["block_hash"],
                selection_seed=_h(f"round-{i}".encode()),
                max_payouts=5,
            )
            for p in result.payouts:
                ever_won.add(p.prover_id)
        # After 200 × 5 = 1000 slot-draws over 20 provers at uniform
        # probability, it is astronomically unlikely that any prover
        # never wins.  (1 - 5/20)^200 ≈ 10^-25.
        self.assertEqual(
            len(ever_won), 20,
            f"only {len(ever_won)}/20 provers ever won across 200 "
            f"rounds — lottery is not uniformly covering the field",
        )


# ---------------------------------------------------------------------------
# 4. Economic-model margin at new parameters
# ---------------------------------------------------------------------------


class TestNewEconomicMargin(unittest.TestCase):
    """The economic model from 3d asserted the archive reward covered
    storage cost by large multiples.  Under 3e's reduced reward, the
    margin is narrower but still comfortable.
    """

    def test_archive_reward_still_covers_storage_at_year_100(self):
        """Per-slot per-epoch reward = 100 tokens.  Winning 1 slot/epoch
        (plausible for a dedicated hobbyist among ~100 competitors) =
        100 × 525 epochs/yr × $0.10/token = $5,250/yr.  Year-100
        storage cost ≈ $9.79.  Still 500× margin — plenty."""
        from tests.test_archive_economic_model import (
            annual_storage_cost_usd,
        )
        epochs_per_year = 525
        token_price = 0.10
        reward_per_slot = ARCHIVE_REWARD
        annual_earnings = reward_per_slot * epochs_per_year * token_price
        annual_cost = annual_storage_cost_usd(100)
        self.assertGreater(
            annual_earnings, annual_cost * 100,
            f"after 3e's reward reduction, a 1-slot-per-epoch "
            f"archivist earns ${annual_earnings:.2f}/yr vs storage "
            f"cost ${annual_cost:.2f}/yr; margin must stay above 100×",
        )


if __name__ == "__main__":
    unittest.main()
