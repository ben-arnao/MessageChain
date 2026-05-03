"""Cross-reference test: every scalar pool that holds tokens AND
moves with ``total_supply`` MUST be summed by
``Blockchain.check_supply_conservation``.

Background -- 2026-05-03 incident: 1.49.0 added the per-block supply-
conservation invariant but its initial sum only counted balances +
treasury + staked + pending_unstakes.  Two scalar pools that genuinely
hold tokens (and that ``total_supply`` was bumped to track) were
missed: ``Blockchain.archive_reward_pool`` and
``Supply.lottery_prize_pool``.  When fee-burn redirects accumulated
into the archive pool, ``actual`` (sum of buckets) drifted below
``expected`` (= ``total_supply``) and the invariant fired a
false-positive supply violation every block thereafter.  Worse, the
real symptom -- the pre-existing 47.5M phantom from the 1.26.0
phantom-supply migration's incomplete repair -- was masked in the
noise because operators couldn't tell which deltas were the bug and
which were the false positive.

This test pins the contract structurally:

  1. Every ``Blockchain`` / ``Supply`` attribute matching the heuristic
     "scalar int that holds tokens" (named ``*_pool``) MUST appear in
     the breakdown returned by ``check_supply_conservation``.

  2. Every source line in ``messagechain/`` that mutates
     ``self.supply.total_supply`` or ``self.total_supply`` (the two
     idiomatic spellings used in the codebase) must live in a file
     that ALSO mutates a counted bucket -- a heuristic but useful
     signal that the +/- to ``total_supply`` is paired with a bucket
     credit/debit, not orphaned into an uncounted pool.

If a future change adds a new pool or a new mint/burn site without
updating ``check_supply_conservation``, this test fails BEFORE the
chain accumulates an undetected residual.  Tighter than waiting for
the per-block invariant to fire under load.

The two checks are intentionally fuzzy at the AST level -- a tighter
walker would have to model the whole apply path.  The heuristics here
catch the actual class of bug that bit the 2026-05-03 incident
without requiring a full static analyzer.
"""

from __future__ import annotations

import inspect
import re
import unittest
from pathlib import Path

from messagechain.core.blockchain import Blockchain
from messagechain.economics.inflation import SupplyTracker  # noqa: F401


# All breakdown keys that ``check_supply_conservation`` surfaces.  A
# pool that fails to land here will trigger TestPoolsAreInBreakdown.
_EXPECTED_BREAKDOWN_KEYS = {
    "balances_sum",
    "staked_sum",
    "pending_unstakes_sum",
    "treasury",
    "archive_reward_pool",
    "lottery_prize_pool",
}

# Pool attributes that DO hold tokens AND DO move with total_supply.
# Each entry: (object-getter, attribute-name, breakdown-key-name).
# The object-getter is a function of (chain) so a test can verify the
# breakdown's reported value matches the live attribute value.
_POOLS_TO_VERIFY: list[tuple[str, str, str]] = [
    # archive_reward_pool: Blockchain instance attribute.  Funded by
    # fee-burn redirects (split_burn_for_pool) and validator-coverage
    # withholds.  Drained by archive-custody payouts.
    ("blockchain", "archive_reward_pool", "archive_reward_pool"),
    # lottery_prize_pool: Supply attribute.  Accumulates seed-divestment
    # share redistribution and is drained at LOTTERY_INTERVAL firings.
    ("supply", "lottery_prize_pool", "lottery_prize_pool"),
]

# Per-block accumulators that DO mutate during apply but are reset to
# zero before the conservation check fires.  These are explicitly
# allowed to be absent from the breakdown -- documenting them here is
# the audit trail.  If a developer adds a new accumulator that ISN'T
# zero by check time, they must either (a) flush it into a counted
# bucket before check, or (b) add it to the breakdown.
_ALLOWED_ZEROED_ACCUMULATORS = {
    # pay_fee_with_burn redirects fees away from burn into this
    # accumulator; mint_block_reward drains it into the attester
    # committee's balances at block-end and resets to 0.
    "attester_fee_pool_this_block",
    # Per-block fee-burn ticker; reset at block-end after split into
    # archive_reward_pool + actual burn.
    "fee_burn_this_block",
}


# ─── Helpers ─────────────────────────────────────────────────────────


def _messagechain_python_files() -> list[Path]:
    """All .py files under messagechain/ -- the production code paths
    we want to cross-reference against the conservation check."""
    root = (
        Path(__file__).resolve().parent.parent / "messagechain"
    )
    return sorted(p for p in root.rglob("*.py") if p.is_file())


def _grep_lines(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return out
    for ln, line in enumerate(text.splitlines(), 1):
        if pattern.search(line):
            out.append((ln, line.strip()))
    return out


# ─── Tests ───────────────────────────────────────────────────────────


class TestBreakdownIncludesAllPools(unittest.TestCase):
    """Every named pool we know about must appear in the breakdown."""

    def test_every_known_pool_is_in_breakdown(self):
        from messagechain.identity.identity import Entity

        ent = Entity.create(b"pool_cov_t1".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        _exp, _act, breakdown = chain.check_supply_conservation()

        for owner, attr, key in _POOLS_TO_VERIFY:
            self.assertIn(
                key, breakdown,
                f"Pool '{attr}' (on {owner}) is not surfaced in the "
                f"conservation breakdown.  If it holds tokens that are "
                f"counted in total_supply, add it to "
                f"check_supply_conservation()'s actual_total sum and "
                f"breakdown dict.",
            )

    def test_breakdown_pool_values_match_live_attributes(self):
        """The breakdown's reported value for each pool must equal the
        live attribute on the object that owns it.  Pins the read path
        so a typo in the conservation method (e.g. reading from the
        wrong object) gets caught immediately."""
        from messagechain.identity.identity import Entity

        ent = Entity.create(b"pool_cov_t2".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)

        # Force non-zero values so a "always-zero" read can't masquerade
        # as a correct read.
        chain._set_archive_reward_pool(12_345)
        chain.supply.lottery_prize_pool = 67_890

        _exp, _act, breakdown = chain.check_supply_conservation()
        self.assertEqual(breakdown["archive_reward_pool"], 12_345)
        self.assertEqual(breakdown["lottery_prize_pool"], 67_890)

    def test_breakdown_keys_match_documented_set(self):
        """Adding a new key to the breakdown without updating the
        documented set ``_EXPECTED_BREAKDOWN_KEYS`` here means future
        readers won't know what the new key is for.  Pin it so the
        next addition forces an explicit doc update in this test."""
        from messagechain.identity.identity import Entity

        ent = Entity.create(b"pool_cov_t3".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        _e, _a, breakdown = chain.check_supply_conservation()
        self.assertEqual(set(breakdown.keys()), _EXPECTED_BREAKDOWN_KEYS)


class TestPoolDiscoveryHeuristic(unittest.TestCase):
    """Find every Blockchain / Supply attribute matching ``*_pool`` and
    flag any that look like they hold tokens but aren't in the
    breakdown.  This is the structural guard for "developer adds a new
    pool but forgets to update the conservation check."

    Heuristic-based because a precise check would need full static
    analysis of every mutation site -- the heuristic catches the actual
    class of bug (named-pool attribute that mutates with total_supply)
    without requiring that machinery.
    """

    def _named_pool_attributes_on(self, obj) -> list[str]:
        """Attributes whose name ends with ``_pool`` and whose live
        value is an int (scalar pool, not a dict / list / object).
        Excludes per-block accumulators that we know are reset before
        the conservation check fires."""
        out: list[str] = []
        for name in dir(obj):
            if not name.endswith("_pool"):
                continue
            if name.startswith("_"):  # private impl detail
                continue
            try:
                v = getattr(obj, name)
            except Exception:
                continue
            if not isinstance(v, int):
                continue
            out.append(name)
        return out

    def test_no_orphan_named_pools(self):
        """Every public ``*_pool`` int attribute on Blockchain or
        Supply must either (a) appear in the breakdown, or (b) be
        explicitly listed in ``_ALLOWED_ZEROED_ACCUMULATORS`` with a
        documented reason it doesn't need to be summed."""
        from messagechain.identity.identity import Entity

        ent = Entity.create(b"pool_cov_t4".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)

        breakdown_keys = set(_EXPECTED_BREAKDOWN_KEYS)
        allowed = _ALLOWED_ZEROED_ACCUMULATORS

        chain_pools = self._named_pool_attributes_on(chain)
        supply_pools = self._named_pool_attributes_on(chain.supply)

        for attr in chain_pools + supply_pools:
            in_breakdown = attr in breakdown_keys
            in_allowed = attr in allowed
            self.assertTrue(
                in_breakdown or in_allowed,
                f"Pool attribute '{attr}' is not in the conservation "
                f"breakdown AND not in the documented "
                f"_ALLOWED_ZEROED_ACCUMULATORS list.  If it holds "
                f"tokens that are counted in total_supply, add it to "
                f"check_supply_conservation().  If it is a per-block "
                f"accumulator that is zeroed before the check fires, "
                f"add it to _ALLOWED_ZEROED_ACCUMULATORS in this test "
                f"with a comment explaining why.",
            )


class TestSupplyMutationSitesAreCovered(unittest.TestCase):
    """Every file that mutates ``total_supply`` should also mutate at
    least one counted bucket -- a heuristic check that the +/- to the
    counter is paired with a bucket credit/debit and not orphaned into
    a freshly-introduced uncounted pool.

    This is the catch-all for the bug shape: a developer adds a new
    code path that does ``self.supply.total_supply += X`` to mint into
    some new accumulator without crediting any of the counted buckets.
    Per-block, this would silently inflate ``expected`` above
    ``actual`` and the conservation invariant would fire false
    positives until the new accumulator drains.

    Files exempted by the bucket-mutation pattern check below are the
    ones where the cross-reference is genuinely not applicable -- e.g.
    pure scalar adjustments inside the supply tracker itself.
    """

    # Lines like ``self.supply.total_supply += X``,
    # ``self.total_supply -= Y``.  Captures both the Blockchain-side and
    # Supply-side spellings.
    _SUPPLY_MUTATION_RE = re.compile(
        r"\b(self\.supply\.total_supply|self\.total_supply)\s*[+\-]=\s*",
    )

    # Bucket mutation patterns: anything that touches one of the
    # counted-buckets attributes.  Tolerant of attribute access spellings
    # used in the codebase (``self.supply.balances[...]``, indexed via
    # ``[entity_id]``, ``.get(...)`` reads paired with assignments, etc.)
    _BUCKET_MUTATION_RE = re.compile(
        r"\b(self\.supply\.balances|self\.supply\.staked|"
        r"self\.balances|self\.staked|"
        r"self\.supply\.pending_unstakes|self\.pending_unstakes|"
        r"self\.archive_reward_pool|self\.supply\.lottery_prize_pool|"
        r"_set_archive_reward_pool|_set_lottery_prize_pool|"
        r"burn_from_treasury|burn_slash_proportional|"
        r"slash_validator|process_pending_unstakes)",
    )

    # Files where the heuristic doesn't apply (pure-counter helpers,
    # tests, tool-side code).  Keep this list short and explicit.
    _EXEMPT_PATHS = {
        # Test fixtures: not production paths.
        # (Tests live in tests/ and aren't scanned anyway, listed
        # here for documentation.)
    }

    def test_total_supply_mutations_pair_with_bucket_mutations(self):
        offenders: list[str] = []
        for path in _messagechain_python_files():
            rel = path.relative_to(path.parent.parent.parent)
            if str(rel) in self._EXEMPT_PATHS:
                continue
            mut_lines = _grep_lines(path, self._SUPPLY_MUTATION_RE)
            if not mut_lines:
                continue
            bucket_lines = _grep_lines(path, self._BUCKET_MUTATION_RE)
            if not bucket_lines:
                offenders.append(
                    f"{rel} has {len(mut_lines)} total_supply "
                    f"mutation(s) but NO bucket mutation -- the +/- "
                    f"may be orphaned into an uncounted pool.  First "
                    f"mutation: line {mut_lines[0][0]}: "
                    f"{mut_lines[0][1]!r}.  Either add the paired "
                    f"bucket update or, if this is a legitimate pure-"
                    f"counter file (e.g. supply tracker internals), "
                    f"add it to _EXEMPT_PATHS in this test with a "
                    f"comment.",
                )
        self.assertEqual(
            offenders, [],
            "\n".join(offenders),
        )


class TestConservationCheckMethodSignature(unittest.TestCase):
    """The conservation check's signature is part of the contract --
    callers (e.g. _enforce_supply_conservation, the diagnostic RPC)
    rely on the (expected, actual, breakdown) triple shape.  Pin it so
    a future refactor that drops the breakdown dict gets caught here."""

    def test_returns_three_tuple(self):
        sig = inspect.signature(Blockchain.check_supply_conservation)
        # Docstring asserts the return type; runtime check that a
        # call returns a triple.
        from messagechain.identity.identity import Entity

        ent = Entity.create(b"pool_cov_t5".ljust(32, b"\x00"))
        chain = Blockchain()
        chain.initialize_genesis(ent)
        result = chain.check_supply_conservation()
        self.assertEqual(len(result), 3)
        expected, actual, breakdown = result
        self.assertIsInstance(expected, int)
        self.assertIsInstance(actual, int)
        self.assertIsInstance(breakdown, dict)


if __name__ == "__main__":
    unittest.main()
