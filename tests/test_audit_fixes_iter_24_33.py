"""Regression tests for the iter 24-33 audit pass fixes.

Three shipped fixes from this batch:
1. pyproject.toml: adds [project]/[build-system] so `pip install .` works
   and exposes the `messagechain` CLI entry point.
2. Seed-divestment debt accounting: subtracts the ACTUALLY-drained amount
   from the debt accumulator instead of the would-have-been amount, so
   slashing mid-window doesn't strand tokens.
3. Tx timestamp upper bound: enforces tx.timestamp <= block.timestamp
   so a proposer can't forward-date messages inside a block stamped
   earlier.
"""

from __future__ import annotations

import unittest

import messagechain.config as _config
from messagechain.core.blockchain import Blockchain


# Legacy-schedule coverage: the divestment debt-clamp test in this file
# simulates the pre-retune schedule.  Push the retune AND
# redistribution heights past its simulated range so pre-retune params
# apply throughout (no lottery share of divestment).
_ORIG_RETUNE_HEIGHT = _config.SEED_DIVESTMENT_RETUNE_HEIGHT
_ORIG_REDIST_HEIGHT = _config.SEED_DIVESTMENT_REDIST_HEIGHT


def setUpModule():
    _config.SEED_DIVESTMENT_RETUNE_HEIGHT = 10 ** 9
    _config.SEED_DIVESTMENT_REDIST_HEIGHT = 10 ** 9


def tearDownModule():
    _config.SEED_DIVESTMENT_RETUNE_HEIGHT = _ORIG_RETUNE_HEIGHT
    _config.SEED_DIVESTMENT_REDIST_HEIGHT = _ORIG_REDIST_HEIGHT


class TestPyprojectHasCLIEntry(unittest.TestCase):
    """pip install . previously silently produced no CLI command.  Fix
    adds [project]/[project.scripts] so `messagechain` resolves."""

    def test_pyproject_has_project_table(self):
        import pathlib
        src = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project]", src)
        self.assertIn('name = "messagechain"', src)
        self.assertIn("[project.scripts]", src)
        self.assertIn("messagechain.cli:main", src)

    def test_pyproject_declares_no_runtime_deps(self):
        """stdlib-only is a project invariant (security + 1000-yr stability)."""
        import pathlib
        src = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", src)


class TestDivestmentDebtConservedUnderSlashClamp(unittest.TestCase):
    """When the floor-clamp on divestment forces `divest < whole`, the
    undrained whole tokens MUST roll over to the next block via the
    debt accumulator.  Pre-fix used `whole * SCALE`, which stranded
    `whole - divest` tokens every time the clamp fired."""

    def _make_chain_with_seed(self, initial_stake: int, current_stake: int):
        bc = Blockchain()
        seed_id = b"\xa5" * 32
        bc.seed_entity_ids = frozenset({seed_id})
        bc.seed_initial_stakes = {seed_id: initial_stake}
        bc.supply.balances[seed_id] = 0
        bc.supply.staked[seed_id] = current_stake
        return bc, seed_id

    def test_debt_not_cleared_when_divest_clamped_by_floor(self):
        from messagechain.config import (
            SEED_DIVESTMENT_RETAIN_FLOOR as FLOOR,
            SEED_DIVESTMENT_START_HEIGHT as START,
            SEED_DIVESTMENT_END_HEIGHT as END,
        )
        # Simulate a seed post-slash: current_stake only 1 token above
        # the floor, so the floor-clamp will force divest=1 even though
        # several whole tokens have accumulated.
        bc, seed_id = self._make_chain_with_seed(
            initial_stake=95_000_000, current_stake=FLOOR + 1,
        )

        # Pre-seed a fat debt so multiple whole tokens are ready.
        SCALE = 10**9
        bc.seed_divestment_debt[seed_id] = 10 * SCALE  # 10 whole tokens

        # Run one divestment apply cycle at a height safely inside the
        # window.  We only need this one call to observe the debt math.
        height = START + (END - START) // 2
        bc._apply_seed_divestment(height)

        # Stake dropped by exactly 1 (clamped by floor).
        self.assertEqual(bc.supply.staked[seed_id], FLOOR)

        # Debt should retain ~9 whole tokens (plus one per-block fractional
        # contribution).  Pre-fix: debt was reset to a tiny fractional
        # remainder.  Post-fix: debt >= 9 * SCALE.
        remaining_whole = bc.seed_divestment_debt[seed_id] // SCALE
        self.assertGreaterEqual(
            remaining_whole, 9,
            f"Debt stranded {10 - remaining_whole} whole tokens on "
            f"floor-clamp — divestment arithmetic broken.",
        )


class TestTxTimestampBoundedByBlockTimestamp(unittest.TestCase):
    """validate_block now enforces tx.timestamp <= block.header.timestamp,
    protecting the chain's role as a trusted-timestamp service."""

    def test_source_enforces_tx_timestamp_upper_bound(self):
        import pathlib
        src = pathlib.Path(
            "messagechain/core/blockchain.py"
        ).read_text(encoding="utf-8")
        # The check lives in validate_block's per-tx loop.
        self.assertIn(
            "tx.timestamp > block.header.timestamp", src,
            "validate_block must enforce tx.timestamp <= block.timestamp",
        )


if __name__ == "__main__":
    unittest.main()
