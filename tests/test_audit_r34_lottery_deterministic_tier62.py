"""Tier 62 — `select_lottery_winner` post-fork uses platform-deterministic
math instead of `math.log` (which delegates to a libm whose ULP-level
rounding is not portable across glibc / musl / MSVC libm / macOS libm).

Pre-fix the lottery winner could differ between heterogeneous-libc
validators on the same chain — a silent state-root divergence on every
lottery firing.  Tier 62 mirrors the same fix `attester_committee.py`
already received: drop into `decimal.Decimal.ln()` at fixed precision
inside a `localcontext()`, which is byte-identical everywhere CPython
runs.

This is a hard fork at ``LOTTERY_DETERMINISTIC_HEIGHT``: pre-fork blocks
replay byte-identically through the legacy float path; post-fork blocks
must use the deterministic path.
"""

from __future__ import annotations

import unittest

from messagechain.config import LOTTERY_DETERMINISTIC_HEIGHT
from messagechain.consensus.reputation_lottery import (
    select_lottery_winner,
)


def _eid(i: int) -> bytes:
    return bytes([i]) * 32


class TestActivationConstantOrdering(unittest.TestCase):
    """Tier 62 activates above the most-recent prior tier."""

    def test_height_above_tier_61(self):
        from messagechain.config import (
            INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT,
        )
        self.assertGreater(
            LOTTERY_DETERMINISTIC_HEIGHT,
            INACTIVITY_LEAK_FRACTIONAL_DEBT_HEIGHT,
        )


class TestPreForkLegacyByteIdentical(unittest.TestCase):
    """Pre-fork heights must continue to use the legacy float path so
    every historical lottery-firing block replays byte-identically."""

    def test_pre_fork_matches_no_height_default(self):
        """`block_height` below activation is indistinguishable from
        the back-compat `block_height=None` legacy default — both
        route through the legacy float math."""
        candidates = [(_eid(i), 100 * (i + 1)) for i in range(8)]
        randomness = b"\xab" * 32
        legacy_default = select_lottery_winner(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            randomness=randomness,
            reputation_cap=10_000,
        )
        legacy_pre_fork = select_lottery_winner(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            randomness=randomness,
            reputation_cap=10_000,
            block_height=LOTTERY_DETERMINISTIC_HEIGHT - 1,
        )
        self.assertEqual(legacy_default, legacy_pre_fork)


class TestPostForkDeterministic(unittest.TestCase):
    """Post-fork the deterministic path must produce the same winner on
    every call for the same inputs — the property that pre-fix could
    drift across libcs."""

    def test_post_fork_repeatable(self):
        candidates = [(_eid(i), 100 * (i + 1)) for i in range(8)]
        randomness = b"\xab" * 32
        a = select_lottery_winner(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            randomness=randomness,
            reputation_cap=10_000,
            block_height=LOTTERY_DETERMINISTIC_HEIGHT,
        )
        b = select_lottery_winner(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            randomness=randomness,
            reputation_cap=10_000,
            block_height=LOTTERY_DETERMINISTIC_HEIGHT + 50_000,
        )
        self.assertEqual(a, b)
        self.assertIsNotNone(a)

    def test_post_fork_uses_no_libm_math_log(self):
        """Defensive: the post-fork code path must not call `math.log`.

        We assert the symbol on the public-facing function source.  A
        future regression that re-introduces `math.log` on the post-
        fork branch trips this immediately.
        """
        import inspect
        from messagechain.consensus import reputation_lottery as _rl
        src = inspect.getsource(_rl)
        # Acceptable: `math.log` referenced inside the legacy helper
        # (gated behind the height check).  Unacceptable: the post-
        # fork helper or the public dispatcher call site referencing
        # math.log.
        # The post-fork helper is named with `_decimal` per the
        # attester_committee.py precedent — verify it does NOT
        # contain math.log.
        # Locate the deterministic helper body and assert no math.log.
        det_func = getattr(_rl, "_select_lottery_winner_decimal", None)
        self.assertIsNotNone(
            det_func,
            "Tier 62 must add `_select_lottery_winner_decimal` helper",
        )
        det_src = inspect.getsource(det_func)
        self.assertNotIn("math.log", det_src)


class TestPostForkRespectsWeights(unittest.TestCase):
    """The deterministic path must preserve the weighted-probability
    shape: high-reputation candidates win dominantly across many
    seeds."""

    def test_heavy_reputation_dominates(self):
        heavy = (_eid(0), 10_000)
        light = [(_eid(i), 100) for i in range(1, 12)]
        candidates = [heavy] + light
        heavy_count = 0
        # 80 trials puts P(heavy never wins) under ~10^-9 at the
        # implied weighted-pick probability; well under the
        # cheapest-tree-height test budget while bounding flake.
        trials = 80
        for i in range(trials):
            picked = select_lottery_winner(
                candidates=candidates,
                seed_entity_ids=frozenset(),
                randomness=i.to_bytes(32, "big"),
                reputation_cap=10_000,
                block_height=LOTTERY_DETERMINISTIC_HEIGHT,
            )
            if picked == _eid(0):
                heavy_count += 1
        # 10_000 / (10_000 + 11 * 100) ≈ 90% expected win rate.
        self.assertGreater(heavy_count, trials * 0.6)


class TestSeedExclusionPreservedPostFork(unittest.TestCase):
    """The post-fork helper must continue to honor seed exclusion —
    a seed entity_id passed through `seed_entity_ids` never wins."""

    def test_seed_never_wins_post_fork(self):
        seed_id = _eid(0)
        candidates = [(seed_id, 100_000)] + [
            (_eid(i), 100) for i in range(1, 5)
        ]
        for i in range(40):
            picked = select_lottery_winner(
                candidates=candidates,
                seed_entity_ids=frozenset({seed_id}),
                randomness=i.to_bytes(32, "big"),
                reputation_cap=100_000,
                block_height=LOTTERY_DETERMINISTIC_HEIGHT,
            )
            self.assertNotEqual(picked, seed_id)


class TestEmptyAndAllSeedReturnNone(unittest.TestCase):
    """Edge cases: empty candidate set or all-seed candidates → None,
    matching legacy behavior, on the post-fork path."""

    def test_empty_candidates_returns_none_post_fork(self):
        self.assertIsNone(
            select_lottery_winner(
                candidates=[],
                seed_entity_ids=frozenset(),
                randomness=b"\x00" * 32,
                reputation_cap=100,
                block_height=LOTTERY_DETERMINISTIC_HEIGHT,
            )
        )

    def test_all_seed_returns_none_post_fork(self):
        a, b = _eid(0), _eid(1)
        self.assertIsNone(
            select_lottery_winner(
                candidates=[(a, 100), (b, 200)],
                seed_entity_ids=frozenset({a, b}),
                randomness=b"\x07" * 32,
                reputation_cap=100,
                block_height=LOTTERY_DETERMINISTIC_HEIGHT,
            )
        )


class TestZeroReputationFallbackPostFork(unittest.TestCase):
    """Degenerate "nobody has attested yet" case: all reputations zero
    → uniform draw on the post-fork path, matching legacy."""

    def test_all_zero_reputations_picks_someone(self):
        candidates = [(_eid(i), 0) for i in range(5)]
        picked = select_lottery_winner(
            candidates=candidates,
            seed_entity_ids=frozenset(),
            randomness=b"\x21" * 32,
            reputation_cap=100,
            block_height=LOTTERY_DETERMINISTIC_HEIGHT,
        )
        self.assertIsNotNone(picked)


class TestBlockchainCallSitesPassHeight(unittest.TestCase):
    """The two consensus call sites in `core/blockchain.py` must pass
    `block_height` through to `select_lottery_winner` — without it
    the post-fork branch never activates and the chain stays on the
    legacy float path forever.
    """

    def test_call_sites_pass_block_height_kwarg(self):
        import inspect
        from messagechain.core import blockchain as _bc
        src = inspect.getsource(_bc)
        lines = src.splitlines()
        # Walk every line that contains `select_lottery_winner(` and
        # is NOT a comment / NOT an import line.  Each such line is
        # the start of a real call invocation; assert the next ~30
        # lines (the kwarg block) carry `block_height=`.
        misses = []
        kept = 0
        for i, line in enumerate(lines):
            if "select_lottery_winner(" not in line:
                continue
            stripped = line.lstrip()
            # Skip comment lines (the "see select_lottery_winner(...)"
            # style annotation appears in the apply path).
            if stripped.startswith("#"):
                continue
            # Skip import lines (single-line; no paren-call follows).
            if stripped.startswith("from ") or stripped.startswith("import "):
                continue
            kept += 1
            block = "\n".join(lines[i : i + 30])
            if "block_height=" not in block:
                misses.append(i + 1)  # 1-indexed line number
        self.assertGreaterEqual(
            kept, 2,
            "Expected at least 2 real call sites in blockchain.py "
            "(sim path + apply path).",
        )
        self.assertEqual(
            misses, [],
            f"select_lottery_winner call site(s) at line(s) {misses} "
            f"do not pass block_height=; the post-fork branch will "
            f"never activate without this kwarg.",
        )


if __name__ == "__main__":
    unittest.main()
