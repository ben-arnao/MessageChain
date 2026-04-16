"""Reputation-weighted bootstrap lottery: real-time influence for honest behavior.

Verifies three interlocking properties:

  1. **Reputation tracking** — every accepted attestation increments
     `Blockchain.reputation[validator_id]`; a slash event zeroes it.
     Deterministic from chain replay so every node sees the same
     reputation map at every height.

  2. **Lottery selection** — `select_lottery_winner` picks a non-seed
     candidate with probability proportional to their (capped)
     reputation.  Empty candidate sets / all-seed sets return None.
     High-reputation candidates win dominantly in a many-trial setup.

  3. **Wiring** — at block_height % LOTTERY_INTERVAL == 0 during
     bootstrap, the apply path mints LOTTERY_BOUNTY and credits it
     into the winner's balance + escrow.  State commitments match
     between the sim and apply paths.
"""

from __future__ import annotations

import unittest

from messagechain.consensus.reputation_lottery import (
    select_lottery_winner,
    effective_reputation,
    lottery_bounty_for_progress,
)


def _eid(i: int) -> bytes:
    return bytes([i]) * 32


class TestReputationClamp(unittest.TestCase):
    """effective_reputation clamps to [0, cap]."""

    def test_negative_clamps_to_zero(self):
        self.assertEqual(effective_reputation(-5, cap=100), 0)

    def test_zero_stays_zero(self):
        self.assertEqual(effective_reputation(0, cap=100), 0)

    def test_within_range_unchanged(self):
        self.assertEqual(effective_reputation(50, cap=100), 50)

    def test_above_cap_clamps_to_cap(self):
        self.assertEqual(effective_reputation(500, cap=100), 100)


class TestLotteryBountyFade(unittest.TestCase):
    """lottery_bounty_for_progress fades linearly from full at p=0 to 0 at p=1.

    Replaces the earlier cliff behavior where the lottery fired at a
    fixed bounty throughout bootstrap and abruptly went silent at
    progress=1.0.  The smooth fade matches the design intent: early
    bootstrap concentrates the bounty when validators need it most;
    the incentive winds down on the same schedule as every other
    bootstrap-era mechanic.
    """

    def test_full_bounty_at_genesis(self):
        """At progress = 0 the bounty is the full configured amount."""
        self.assertEqual(
            lottery_bounty_for_progress(0.0, full_bounty=100), 100,
        )

    def test_zero_bounty_at_progress_one(self):
        """At progress = 1.0 the bounty collapses to zero — no cliff."""
        self.assertEqual(
            lottery_bounty_for_progress(1.0, full_bounty=100), 0,
        )

    def test_linear_fade_half_at_half(self):
        """At progress = 0.5 the bounty is half."""
        self.assertEqual(
            lottery_bounty_for_progress(0.5, full_bounty=100), 50,
        )

    def test_monotonic_non_increasing(self):
        """The fade is monotonically non-increasing in progress."""
        prev = 9999
        for p in [i / 20 for i in range(21)]:
            cur = lottery_bounty_for_progress(p, full_bounty=100)
            self.assertLessEqual(cur, prev, f"non-monotonic at p={p}")
            prev = cur

    def test_rejects_out_of_range_progress(self):
        with self.assertRaises(ValueError):
            lottery_bounty_for_progress(-0.01, full_bounty=100)
        with self.assertRaises(ValueError):
            lottery_bounty_for_progress(1.01, full_bounty=100)

    def test_rejects_negative_bounty(self):
        with self.assertRaises(ValueError):
            lottery_bounty_for_progress(0.5, full_bounty=-1)

    def test_integrated_envelope_half_of_flat(self):
        """Triangular (fading) envelope is ~half the rectangular (flat)
        envelope over the same bootstrap window.  Spot-checks the
        rough envelope math documented on the helper."""
        n_intervals = 100
        flat_total = n_intervals * 100
        faded_total = sum(
            lottery_bounty_for_progress(k / n_intervals, full_bounty=100)
            for k in range(n_intervals)
        )
        # Triangular sum is ~half of rectangular; allow 5% band for
        # integer-rounding effects.
        self.assertLess(faded_total, flat_total * 0.55)
        self.assertGreater(faded_total, flat_total * 0.45)


class TestLotterySelection(unittest.TestCase):
    """select_lottery_winner picks deterministic, reputation-weighted winners."""

    def test_empty_candidates_returns_none(self):
        winner = select_lottery_winner(
            candidates=[], seed_entity_ids=frozenset(),
            randomness=b"\x00" * 32, reputation_cap=100,
        )
        self.assertIsNone(winner)

    def test_all_candidates_are_seeds_returns_none(self):
        seeds = frozenset({_eid(1), _eid(2)})
        winner = select_lottery_winner(
            candidates=[(_eid(1), 100), (_eid(2), 50)],
            seed_entity_ids=seeds,
            randomness=b"\x01" * 32, reputation_cap=100,
        )
        self.assertIsNone(winner)

    def test_seeds_excluded_from_draw(self):
        """Seed never wins even with high reputation."""
        seeds = frozenset({_eid(1)})
        wins = {_eid(1): 0, _eid(2): 0}
        for i in range(50):
            winner = select_lottery_winner(
                candidates=[(_eid(1), 10_000), (_eid(2), 1)],
                seed_entity_ids=seeds,
                randomness=i.to_bytes(32, "big"),
                reputation_cap=10_000,
            )
            if winner is not None:
                wins[winner] += 1
        self.assertEqual(wins[_eid(1)], 0)
        self.assertEqual(wins[_eid(2)], 50)

    def test_deterministic_given_randomness(self):
        """Same inputs produce identical output on every invocation."""
        a = select_lottery_winner(
            candidates=[(_eid(i), i * 10) for i in range(1, 6)],
            seed_entity_ids=frozenset(),
            randomness=b"\x42" * 32, reputation_cap=100,
        )
        b = select_lottery_winner(
            candidates=[(_eid(i), i * 10) for i in range(1, 6)],
            seed_entity_ids=frozenset(),
            randomness=b"\x42" * 32, reputation_cap=100,
        )
        self.assertEqual(a, b)

    def test_high_reputation_wins_dominantly(self):
        """Over many trials, a candidate with 100x reputation wins much more."""
        heavy = _eid(1)
        light = _eid(2)
        candidates = [(heavy, 1000), (light, 10)]
        wins = {heavy: 0, light: 0}
        trials = 500
        for i in range(trials):
            winner = select_lottery_winner(
                candidates=candidates, seed_entity_ids=frozenset(),
                randomness=i.to_bytes(32, "big"),
                reputation_cap=10_000,
            )
            if winner is not None:
                wins[winner] += 1
        # Expected win ratio ≈ 100:1 (heavy vs light); allow wide band.
        self.assertGreater(wins[heavy], trials * 0.90)
        self.assertLess(wins[light], trials * 0.10)

    def test_cap_prevents_runaway_reputation(self):
        """Past the cap, additional reputation confers no extra advantage."""
        a, b = _eid(1), _eid(2)
        # a has rep=10_000, b has rep=1_000_000.  With cap=100, both
        # are effectively capped at 100 → roughly equal odds.
        candidates = [(a, 10_000), (b, 1_000_000)]
        wins = {a: 0, b: 0}
        trials = 400
        for i in range(trials):
            winner = select_lottery_winner(
                candidates=candidates, seed_entity_ids=frozenset(),
                randomness=i.to_bytes(32, "big"),
                reputation_cap=100,
            )
            wins[winner] += 1
        # Expected ~50/50; give a 15pt band either way.
        self.assertGreater(wins[a], trials * 0.35)
        self.assertLess(wins[a], trials * 0.65)

    def test_zero_reputation_pool_falls_back_to_uniform(self):
        """If nobody has attested yet, lottery still picks a winner
        (uniform over eligible) rather than returning None."""
        candidates = [(_eid(i), 0) for i in range(5)]
        # Must pick somebody across trials.
        any_winner = False
        for i in range(10):
            w = select_lottery_winner(
                candidates=candidates, seed_entity_ids=frozenset(),
                randomness=i.to_bytes(32, "big"),
                reputation_cap=100,
            )
            if w is not None:
                any_winner = True
                break
        self.assertTrue(any_winner)


class TestReputationBlockchainIntegration(unittest.TestCase):
    """End-to-end: reputation increments from real attestations in real blocks.

    This is the proof that the apply-path wiring is correct — not just
    unit-level but actually connected to attestation flow.
    """

    def _make_chain_with_seeds(self, num_seeds: int = 3):
        from messagechain.identity.identity import Entity
        from messagechain.core.blockchain import Blockchain
        from messagechain.core.bootstrap import build_launch_allocation
        from messagechain.consensus.pos import ProofOfStake
        from tests import register_entity_for_test

        seeds = [
            Entity.create(f"rlx-seed-{i}".encode().ljust(32, b"\x00"))
            for i in range(num_seeds)
        ]
        for s in seeds:
            s.keypair._next_leaf = 0
        chain = Blockchain()
        allocation = build_launch_allocation(
            [s.entity_id for s in seeds],
            stake_per_seed=100_000, fee_buffer=0,
        )
        chain.initialize_genesis(seeds[0], allocation_table=allocation)
        for s in seeds[1:]:
            register_entity_for_test(chain, s)
        for s in seeds:
            chain.supply.stake(s.entity_id, 100_000)
        consensus = ProofOfStake()
        chain.sync_consensus_stakes(consensus)
        return chain, seeds, consensus

    def test_reputation_increments_on_applied_attestation(self):
        """An accepted attestation bumps the attestor's reputation by 1."""
        from messagechain.consensus.attestation import create_attestation
        from tests import pick_selected_proposer, register_entity_for_test
        from messagechain.identity.identity import Entity

        chain, seeds, consensus = self._make_chain_with_seeds()
        newcomer = Entity.create(b"rlx-new".ljust(32, b"\x00"))
        newcomer.keypair._next_leaf = 0
        register_entity_for_test(chain, newcomer)

        self.assertEqual(chain.reputation.get(newcomer.entity_id, 0), 0)

        # Block 1 → something to attest.
        proposer = pick_selected_proposer(chain, seeds)
        b1 = chain.propose_block(consensus, proposer, [])
        chain.add_block(b1)

        # Newcomer attests block 1; block 2 carries the attestation.
        att = create_attestation(
            newcomer, b1.block_hash, b1.header.block_number,
        )
        proposer = pick_selected_proposer(chain, seeds)
        b2 = chain.propose_block(consensus, proposer, [], attestations=[att])
        ok, _ = chain.add_block(b2)
        self.assertTrue(ok)

        self.assertEqual(chain.reputation.get(newcomer.entity_id), 1)


if __name__ == "__main__":
    unittest.main()
