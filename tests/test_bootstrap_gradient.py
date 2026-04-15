"""Bootstrap gradient: single monotonic parameter driving the free-entry phase.

The protocol's bootstrap phase is a *gradient*, not a binary mode.  As the
chain matures — both in block height and in how stake has diversified
away from the genesis seeds — parameters transition smoothly:

  * min_stake_required (0 → MIN_STAKE_PRODUCTION)
  * attester selection (uniform → stake-weighted)
  * escrow window      (90 days → 0 days)
  * seed exclusion     (TRUE → FALSE) from the attester committee

All four are driven by a single value in [0, 1]:

    bootstrap_progress = max(
        height / BOOTSTRAP_END_HEIGHT,            # time-based floor
        observed_max(non_seed_stake / total_stake)  # decentralization-driven
    )

This stage is pure scaffolding: the gradient is computed and exposed,
but nothing consumes it yet.  Later stages wire it into attester
rewards, min-stake gates, etc.

Ratcheting: the stake component is MONOTONIC — once observed, it
cannot regress.  Prevents an attack where seeds briefly unstake /
restake to resurrect a "more bootstrap-friendly" parameter set and
grief new validators (e.g. forcing min_stake back to 0 after it had
already ramped up).  Height naturally monotonic since chain.height
only grows.
"""

import unittest

from messagechain.consensus.bootstrap_gradient import (
    BOOTSTRAP_END_HEIGHT,
    compute_bootstrap_progress,
    RatchetState,
)


class TestPureFormula(unittest.TestCase):
    """compute_bootstrap_progress is a pure function of inputs."""

    def test_genesis_is_zero(self):
        """Height 0, no external stake → progress 0.0."""
        p = compute_bootstrap_progress(
            height=0, seed_stake=750_000, non_seed_stake=0,
        )
        self.assertEqual(p, 0.0)

    def test_height_alone_drives_progress(self):
        """No external stake; progress tracks height / BOOTSTRAP_END_HEIGHT."""
        # Halfway in time, no stake diversification:
        p = compute_bootstrap_progress(
            height=BOOTSTRAP_END_HEIGHT // 2,
            seed_stake=750_000, non_seed_stake=0,
        )
        self.assertAlmostEqual(p, 0.5, places=4)

    def test_height_capped_at_one(self):
        """Past BOOTSTRAP_END_HEIGHT, progress never exceeds 1.0."""
        p = compute_bootstrap_progress(
            height=BOOTSTRAP_END_HEIGHT * 5,
            seed_stake=750_000, non_seed_stake=0,
        )
        self.assertEqual(p, 1.0)

    def test_stake_ratio_drives_progress_when_height_low(self):
        """Early in time but stake already decentralized → progress tracks stake."""
        # Height = 10% of end, but 80% of stake is non-seed:
        p = compute_bootstrap_progress(
            height=BOOTSTRAP_END_HEIGHT // 10,
            seed_stake=200_000, non_seed_stake=800_000,
        )
        # height component = 0.1, stake component = 0.8, max = 0.8
        self.assertAlmostEqual(p, 0.8, places=4)

    def test_max_of_two_components(self):
        """Whichever component is larger wins."""
        # Case A: height dominates
        pa = compute_bootstrap_progress(
            height=BOOTSTRAP_END_HEIGHT * 3 // 4,
            seed_stake=1_000_000, non_seed_stake=100_000,
        )
        # height = 0.75, stake = 100/1100 ≈ 0.091, max = 0.75
        self.assertAlmostEqual(pa, 0.75, places=4)

        # Case B: stake dominates
        pb = compute_bootstrap_progress(
            height=BOOTSTRAP_END_HEIGHT // 10,
            seed_stake=100_000, non_seed_stake=900_000,
        )
        # height = 0.1, stake = 0.9, max = 0.9
        self.assertAlmostEqual(pb, 0.9, places=4)

    def test_zero_total_stake_is_zero_progress(self):
        """Edge case: zero stake on both sides.  Stake component is 0."""
        p = compute_bootstrap_progress(
            height=0, seed_stake=0, non_seed_stake=0,
        )
        self.assertEqual(p, 0.0)

    def test_all_non_seed_stake_is_full_progress(self):
        """All stake held by non-seed validators → stake component = 1.0."""
        p = compute_bootstrap_progress(
            height=0, seed_stake=0, non_seed_stake=1_000_000,
        )
        self.assertEqual(p, 1.0)


class TestRatchet(unittest.TestCase):
    """RatchetState stores the max bootstrap_progress ever observed.

    The stake-derived component can fluctuate (seeds could unstake, or
    external validators could unstake).  Without a ratchet, an attacker
    could nudge the parameter set backwards to trigger bootstrap-phase
    behavior in a chain that had already progressed past it.

    The ratchet is in-memory; on restart it is seeded from current chain
    state + height.  A more complete ratchet (persisted through the
    state root) is future work — for now, this is a defense-in-depth
    layer on top of the height floor, which is always monotonic.
    """

    def test_initial_value_is_zero(self):
        r = RatchetState()
        self.assertEqual(r.max_progress, 0.0)

    def test_observing_higher_value_moves_forward(self):
        r = RatchetState()
        r.observe(0.3)
        self.assertEqual(r.max_progress, 0.3)
        r.observe(0.7)
        self.assertEqual(r.max_progress, 0.7)

    def test_observing_lower_value_does_not_regress(self):
        r = RatchetState()
        r.observe(0.7)
        r.observe(0.4)
        self.assertEqual(r.max_progress, 0.7)  # held at peak

    def test_values_outside_0_1_are_rejected(self):
        r = RatchetState()
        with self.assertRaises(ValueError):
            r.observe(-0.1)
        with self.assertRaises(ValueError):
            r.observe(1.5)

    def test_repeated_observations_idempotent(self):
        r = RatchetState()
        r.observe(0.5)
        r.observe(0.5)
        r.observe(0.5)
        self.assertEqual(r.max_progress, 0.5)


class TestBlockchainIntegration(unittest.TestCase):
    """Blockchain exposes seed_entity_ids and bootstrap_progress.

    seed_entity_ids is pinned at genesis from the allocation table
    (minus the treasury).  It is a frozenset so it cannot be mutated
    post-launch — the "who is a seed" question has exactly one answer
    for the life of the chain.
    """

    def _make_entity(self, seed: bytes):
        from messagechain.identity.identity import Entity
        return Entity.create(seed + b"\x00" * (32 - len(seed)), tree_height=4)

    def test_seeds_empty_without_allocation_table(self):
        """Backward-compat path: no allocation_table → no seeds pinned."""
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        genesis = self._make_entity(b"g")
        chain.initialize_genesis(genesis)
        self.assertEqual(chain.seed_entity_ids, frozenset())

    def test_seeds_from_allocation_table_exclude_treasury(self):
        """seed_entity_ids = allocation_table keys minus TREASURY_ENTITY_ID."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.config import TREASURY_ENTITY_ID
        chain = Blockchain()
        s1 = self._make_entity(b"s1")
        s2 = self._make_entity(b"s2")
        s3 = self._make_entity(b"s3")
        allocation = {
            TREASURY_ENTITY_ID: 40_000_000,
            s1.entity_id: 251_000,
            s2.entity_id: 251_000,
            s3.entity_id: 251_000,
        }
        chain.initialize_genesis(s1, allocation_table=allocation)
        self.assertEqual(
            chain.seed_entity_ids,
            frozenset({s1.entity_id, s2.entity_id, s3.entity_id}),
        )

    def test_seeds_is_frozenset(self):
        """Can't be mutated after genesis."""
        from messagechain.core.blockchain import Blockchain
        from messagechain.config import TREASURY_ENTITY_ID
        chain = Blockchain()
        s = self._make_entity(b"s")
        chain.initialize_genesis(s, allocation_table={
            TREASURY_ENTITY_ID: 1_000,
            s.entity_id: 1_000,
        })
        self.assertIsInstance(chain.seed_entity_ids, frozenset)
        # Python frozensets have no .add, so any mutation attempt is
        # syntactically rejected.  This assertion is mostly for doc.
        self.assertFalse(hasattr(chain.seed_entity_ids, "add"))

    def test_bootstrap_progress_at_genesis(self):
        """Just after genesis, with only seed stake: progress ≈ 0.

        Genesis appends block 0, so height = 1 right after
        initialize_genesis — progress = 1/BOOTSTRAP_END_HEIGHT ≈ 1e-5,
        effectively zero.  Stake component is also zero since no
        non-seed stake exists yet.
        """
        from messagechain.core.blockchain import Blockchain
        from messagechain.config import TREASURY_ENTITY_ID
        chain = Blockchain()
        s = self._make_entity(b"s")
        chain.initialize_genesis(s, allocation_table={
            TREASURY_ENTITY_ID: 40_000_000,
            s.entity_id: 251_000,
        })
        # Genesis liquid balance is 251_000 but staked = 0 (stake must
        # be explicitly locked via a stake tx).  Both components are
        # effectively zero.
        self.assertLess(chain.bootstrap_progress, 0.001)

    def test_bootstrap_progress_ratchets_on_query(self):
        """Repeated reads never regress below a previously-observed peak.

        This is the whole point of the ratchet: a query today and a
        query tomorrow must produce non-decreasing values, even if
        stake re-concentrates between them.
        """
        from messagechain.core.blockchain import Blockchain
        from messagechain.config import TREASURY_ENTITY_ID
        chain = Blockchain()
        s = self._make_entity(b"s")
        chain.initialize_genesis(s, allocation_table={
            TREASURY_ENTITY_ID: 1_000_000,
            s.entity_id: 1_000_000,
        })
        # Manually push the ratchet up by simulating an observation.
        chain._bootstrap_ratchet.observe(0.6)
        self.assertAlmostEqual(chain.bootstrap_progress, 0.6, places=4)
        # Even if we recompute fresh with no external stake, the ratchet
        # holds the peak:
        p2 = chain.bootstrap_progress
        self.assertAlmostEqual(p2, 0.6, places=4)


if __name__ == "__main__":
    unittest.main()
