"""Audit r38 #2 -- Tier 67 attester-committee Decimal end-to-end.

Closes the cross-platform consensus-split risk in attester-committee
selection.  Pre-fix `_deterministic_weighted_sample` (in
`messagechain.consensus.attester_committee`) computed the per-candidate
priority as a Decimal but immediately collapsed back to ``float``
before the sort:

    pri = float(u.ln() / Decimal(w))

Decimal.ln IS deterministic (good — Tier 62 lesson learned for the
lottery), but the cast back to float at the sort key reintroduces an
IEEE-754-rounding hazard.  Two near-equal log-keys can rank-flip on
different libc / different CPython versions, producing different
attester sets on different platforms — a chain-wide partition class.

Today's homogeneous-Linux-glibc mainnet hides it; the moment a third
validator joins on different libc / arch / Python build, partition
risk goes live.  Committee selection is consensus-critical (rewards
land in `mint_block_reward` and are committed in `state_root`), so
divergent committees mean divergent state-roots — instant network
partition.

Same bug class as Tier 62 (`LOTTERY_DETERMINISTIC_HEIGHT`) -- the
fix mirrors the Decimal end-to-end pattern already shipped for
``select_lottery_winner``.

Tier 67 (``ATTESTER_COMMITTEE_DECIMAL_HEIGHT``) hard-fork-gates the
new Decimal-end-to-end path.  Pre-fork the legacy float-cast branch
runs unchanged so historical blocks replay byte-identically; post-
fork the deterministic Decimal branch is the consensus rule.

Tests:
  1. Activation constant ordering (Tier 67 sits 50 above Tier 66).
  2. Pre-fork legacy byte-identity: the legacy float-cast branch's
     output exactly matches what the pre-Tier-67 code returns.
  3. Post-fork repeatability: the Decimal branch produces a stable
     output for any fixed (randomness, candidates, weights) input.
  4. Post-fork helper does NOT reference ``float(...)`` on the sort
     key path (regression pin -- the float cast is the bug).
  5. Weighted-probability shape preserved post-fork (heavy items
     still win proportionally more often than light items).
  6. Edge cases: empty candidates, all-seeds, all-zero-weight,
     committee_size >= len(candidates).
  7. Both consensus call sites in ``core/blockchain.py``
     (``compute_post_state_root`` sim path + ``_apply_block_state``
     apply path) pass ``block_height=`` so the gate activates.
"""

from __future__ import annotations

import inspect
import unittest
from decimal import Decimal

from messagechain.config import (
    ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
    LOTTERY_DETERMINISTIC_HEIGHT,
    VOTER_REWARD_ADAPTIVE_CAP_HEIGHT,
)
from messagechain.consensus.attester_committee import (
    _deterministic_weighted_sample_decimal,
    _deterministic_weighted_sample_legacy_float,
    select_attester_committee,
)


# ─────────────────────────────────────────────────────────────────────
# Activation-constant ordering
# ─────────────────────────────────────────────────────────────────────


class TestActivationConstantOrdering(unittest.TestCase):
    """The Tier 67 activation height must sit AFTER Tier 66 (the
    most recent prior tier) with the standard 50-block cohort gap so
    the validator-upgrade window does not collapse."""

    def test_tier67_follows_tier66(self):
        self.assertGreater(
            ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
            VOTER_REWARD_ADAPTIVE_CAP_HEIGHT,
            "Tier 67 must follow Tier 66; consecutive consensus-rule "
            "activations need cohort spacing.",
        )

    def test_tier67_follows_tier62_lottery(self):
        # Tier 67 mirrors Tier 62's pattern; both must be active before
        # any future tier that combines them.  Sanity-check ordering.
        self.assertGreater(
            ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
            LOTTERY_DETERMINISTIC_HEIGHT,
        )

    def test_tier67_gap_is_50_blocks(self):
        # Match the Tier 49-66 cohort spacing pattern.
        self.assertEqual(
            ATTESTER_COMMITTEE_DECIMAL_HEIGHT - VOTER_REWARD_ADAPTIVE_CAP_HEIGHT,
            50,
            "Tier 67 should sit exactly 50 blocks above Tier 66 to "
            "match the Tier 49-66 cohort spacing.",
        )


# ─────────────────────────────────────────────────────────────────────
# Pre-fork legacy byte-identity
# ─────────────────────────────────────────────────────────────────────


class TestLegacyFloatBranchByteIdentity(unittest.TestCase):
    """Pre-fork (height < activation) the legacy float-cast branch
    MUST run unchanged so historical blocks replay byte-identically.

    The "ground truth" we compare against is the literal pre-fix
    implementation: hash → log-key (float cast) → sort → top-k.
    """

    def _ground_truth_legacy(self, items, weights, k, randomness):
        """Reference implementation of the pre-fix float-cast path.
        Mirrors `_deterministic_weighted_sample_legacy_float` byte-
        for-byte; if either drifts the test fires."""
        from decimal import localcontext
        from messagechain.crypto.hashing import default_hash

        if k >= len(items):
            return sorted(items)
        priorities: list[tuple[float, bytes]] = []
        with localcontext() as ctx:
            ctx.prec = 40
            for item, w in zip(items, weights):
                h = default_hash(randomness + item)
                hash_int = int.from_bytes(h[:8], "big") + 1
                if w <= 0:
                    pri = float("-inf")
                else:
                    u = Decimal(hash_int) / Decimal(2**64)
                    pri = float(u.ln() / Decimal(w))
                priorities.append((pri, item))
        priorities.sort(key=lambda p: (-p[0], p[1]))
        return [item for _, item in priorities[:k]]

    def test_legacy_branch_matches_ground_truth(self):
        items = [bytes([i]) * 32 for i in range(20)]
        weights = [float(i + 1) for i in range(20)]
        randomness = b"\xAB" * 32
        for k in (1, 3, 5, 10, 19):
            with self.subTest(k=k):
                expected = self._ground_truth_legacy(
                    items, weights, k, randomness,
                )
                actual = _deterministic_weighted_sample_legacy_float(
                    items, weights, k, randomness,
                )
                self.assertEqual(
                    actual, expected,
                    f"Legacy float branch must match pre-fix "
                    f"behaviour byte-for-byte (k={k}).",
                )

    def test_legacy_branch_handles_zero_weight_items(self):
        items = [b"\xAA" * 32, b"\xBB" * 32, b"\xCC" * 32, b"\xDD" * 32]
        weights = [10.0, 0.0, 5.0, 0.0]
        randomness = b"\x42" * 32
        out = _deterministic_weighted_sample_legacy_float(
            items, weights, 2, randomness,
        )
        # Both positive-weight items must be in the top-2.
        self.assertEqual(set(out), {items[0], items[2]})


# ─────────────────────────────────────────────────────────────────────
# Post-fork Decimal branch
# ─────────────────────────────────────────────────────────────────────


class TestDecimalBranchDeterministic(unittest.TestCase):
    """The Tier 67 Decimal branch keeps the priority as Decimal end-
    to-end; sort comparisons are exact, eliminating IEEE-754 ULP
    rank-flip risk."""

    def test_repeatable_for_same_inputs(self):
        items = [bytes([i]) * 32 for i in range(20)]
        weights = [float(i + 1) for i in range(20)]
        randomness = b"\x77" * 32
        first = _deterministic_weighted_sample_decimal(
            items, weights, 5, randomness,
        )
        second = _deterministic_weighted_sample_decimal(
            items, weights, 5, randomness,
        )
        self.assertEqual(first, second, "Decimal branch must be repeatable.")

    def test_decimal_branch_does_not_call_float_on_sort_key(self):
        """Regression pin: the entire bug is the ``float()`` cast
        before the sort.  The Tier 67 branch's source MUST NOT
        contain ``float(`` -- if it does, we've reintroduced the
        cross-platform hazard."""
        src = inspect.getsource(_deterministic_weighted_sample_decimal)
        self.assertNotIn(
            "float(", src,
            "Tier 67 Decimal branch must not cast Decimal to float "
            "anywhere on the sort-key path -- that's the exact "
            "cross-platform consensus-split hazard the fix closes.",
        )

    def test_zero_weight_items_go_last(self):
        items = [b"\xAA" * 32, b"\xBB" * 32, b"\xCC" * 32, b"\xDD" * 32]
        weights = [10.0, 0.0, 5.0, 0.0]
        randomness = b"\x33" * 32
        # k=2 must pick the two positive-weight items.
        out = _deterministic_weighted_sample_decimal(
            items, weights, 2, randomness,
        )
        self.assertEqual(set(out), {items[0], items[2]})

    def test_weighted_probability_shape_preserved(self):
        """Heavy items should win disproportionately often.  Run
        the sampler over many randomness seeds and confirm the
        heaviest item wins more often than the lightest."""
        items = [bytes([i]) * 32 for i in range(8)]
        # Skewed: item 0 gets weight 100, item 7 gets weight 1.
        weights = [100.0, 50.0, 25.0, 10.0, 5.0, 2.5, 1.0, 1.0]
        wins = {it: 0 for it in items}
        for seed in range(100):
            r = bytes([seed]) * 32
            picked = _deterministic_weighted_sample_decimal(
                items, weights, 1, r,
            )
            wins[picked[0]] += 1
        # Heaviest item should win meaningfully more often than the
        # lightest.  Sample size is small so use a loose bar.
        self.assertGreater(
            wins[items[0]], wins[items[7]],
            f"Heaviest item should win more often than lightest. "
            f"Wins: heavy={wins[items[0]]}, light={wins[items[7]]}",
        )

    def test_returns_full_set_when_k_geq_n(self):
        items = [bytes([i]) * 32 for i in range(5)]
        weights = [1.0] * 5
        out = _deterministic_weighted_sample_decimal(
            items, weights, 5, b"\x00" * 32,
        )
        self.assertEqual(out, sorted(items))
        out = _deterministic_weighted_sample_decimal(
            items, weights, 10, b"\x00" * 32,
        )
        self.assertEqual(out, sorted(items))


# ─────────────────────────────────────────────────────────────────────
# select_attester_committee height-gate dispatch
# ─────────────────────────────────────────────────────────────────────


class TestSelectAttesterCommitteeHeightGate(unittest.TestCase):
    """`select_attester_committee` must accept ``block_height`` and
    dispatch to the legacy branch pre-fork or the Decimal branch
    post-fork.  Backwards-compat: ``None``/missing routes to legacy."""

    def _candidates(self, n=10):
        return [(bytes([i]) * 32, (i + 1) * 100) for i in range(n)]

    def test_pre_fork_height_routes_to_legacy_float(self):
        out_pre = select_attester_committee(
            candidates=self._candidates(),
            seed_entity_ids=frozenset(),
            bootstrap_progress=1.0,
            randomness=b"\x55" * 32,
            committee_size=3,
            block_height=ATTESTER_COMMITTEE_DECIMAL_HEIGHT - 1,
        )
        out_legacy = select_attester_committee(
            candidates=self._candidates(),
            seed_entity_ids=frozenset(),
            bootstrap_progress=1.0,
            randomness=b"\x55" * 32,
            committee_size=3,
            block_height=None,  # legacy default
        )
        self.assertEqual(
            out_pre, out_legacy,
            "Pre-fork height MUST route to the legacy float branch "
            "byte-for-byte to keep historical blocks replaying "
            "identically.",
        )

    def test_post_fork_height_routes_to_decimal(self):
        candidates = self._candidates()
        randomness = b"\x99" * 32
        out_post = select_attester_committee(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            bootstrap_progress=1.0,
            randomness=randomness,
            committee_size=3,
            block_height=ATTESTER_COMMITTEE_DECIMAL_HEIGHT,
        )
        # Round-trip: calling _deterministic_weighted_sample_decimal
        # with the same inputs should reproduce the same committee.
        items = [eid for eid, _ in candidates]
        stakes = [stake for _, stake in candidates]
        from messagechain.consensus.attester_committee import (
            weights_for_progress,
        )
        weights = weights_for_progress(stakes, 1.0)
        expected = sorted(_deterministic_weighted_sample_decimal(
            items, weights, 3, randomness,
        ))
        self.assertEqual(out_post, expected)

    def test_block_height_kwarg_optional_for_back_compat(self):
        # Existing tests may not pass block_height.  Default behaviour
        # should be the legacy branch, matching pre-fork.
        out = select_attester_committee(
            candidates=self._candidates(),
            seed_entity_ids=frozenset(),
            bootstrap_progress=1.0,
            randomness=b"\x11" * 32,
            committee_size=3,
        )
        self.assertEqual(len(out), 3)


# ─────────────────────────────────────────────────────────────────────
# Both consensus call sites pass block_height=
# ─────────────────────────────────────────────────────────────────────


class TestConsensusCallSitesPassBlockHeight(unittest.TestCase):
    """Both `select_attester_committee` call sites in
    `core/blockchain.py` (sim path in `compute_post_state_root` and
    apply path in `_apply_block_state`) MUST pass `block_height=`
    so the Tier 67 gate actually activates.

    Without this thread, the height-gate is wired but inert -- a
    bug class the lottery fix (Tier 62) had to belt-and-braces with
    the same assertion.
    """

    def test_blockchain_passes_block_height_to_committee_selector(self):
        import re
        from pathlib import Path
        src_path = Path(__file__).parent.parent / "messagechain" / "core" / "blockchain.py"
        src = src_path.read_text(encoding="utf-8")
        # Find every select_attester_committee( call and assert
        # block_height= appears within the call's argument span.
        # Simple heuristic: count the call-opens and confirm at
        # least as many block_height= occurrences within
        # select_attester_committee( ... ) blocks.
        call_pattern = re.compile(
            r"select_attester_committee\s*\((?P<args>.*?)\)",
            re.DOTALL,
        )
        matches = list(call_pattern.finditer(src))
        # We expect both consensus call sites to be present.
        self.assertGreaterEqual(
            len(matches), 2,
            "Expected at least two select_attester_committee( ... ) "
            "call sites in core/blockchain.py.",
        )
        for i, m in enumerate(matches):
            with self.subTest(call_index=i):
                self.assertIn(
                    "block_height=", m.group("args"),
                    f"select_attester_committee call #{i} in "
                    f"core/blockchain.py must pass block_height= so "
                    f"the Tier 67 gate activates at the configured "
                    f"height.  Without it, the fix is wired but "
                    f"inert.",
                )


if __name__ == "__main__":
    unittest.main()
