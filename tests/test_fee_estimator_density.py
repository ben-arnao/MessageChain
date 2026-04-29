"""Fee estimator must percentile over fee-per-byte DENSITIES, not absolute fees.

Audit finding (verbatim):

    `FeeEstimator.estimate_fee` and `mempool_percentile_estimate` return
    absolute-fee percentiles, not fee-per-byte — directly violates the
    anchored auto-fee model.

CLAUDE.md anchors:

    "Selection priority is fee-per-byte, never absolute fee."
    "Any wallet/CLI helper that picks a fee for the user computes a
     target fee-per-byte from current mempool conditions and multiplies
     by the tx's stored byte count."

Worked example used as the headline density-vs-absolute regression:

    Mempool has one 5_000-byte tx @ fee 5_000 (1/B) and ten 50-byte txs
    @ fee 100 (2/B).  True 75th-pct fee-per-byte = 2/B.  Quoting a
    100-byte tx must return ~200 (= 2 fpb × 100 bytes).  Buggy code
    returns either 100 (the modal absolute fee) or 5000 (the high
    outlier) depending on the `stored_size`-cancel artifact — never
    the density-correct 200.
"""

import unittest

from messagechain.economics.auto_fee import mempool_percentile_estimate
from messagechain.economics.fee_estimator import FeeEstimator
from messagechain.config import MIN_FEE


# ── Worked example shared by both helpers ───────────────────────────


def _worked_example_pairs() -> list[tuple[int, int]]:
    """One 5000-byte tx @ fee 5000, ten 50-byte txs @ fee 100.

    Densities: 1/B (×1) and 2/B (×10).  All-percentiles >= 25th =
    2/B; 90th and 75th and 50th and 25th all return 2/B.  10th returns
    1/B.  This shape was chosen so the absolute-fee bug can't
    accidentally land on the right answer.
    """
    pairs: list[tuple[int, int]] = [(5_000, 5_000)]
    pairs.extend([(100, 50)] * 10)
    return pairs


# ── A. mempool_percentile_estimate operates on densities ────────────


class TestMempoolPercentileOperatesOnDensities(unittest.TestCase):
    """The (fee, stored_size)-pair API ranks by density, not absolute fee."""

    def test_worked_example_quotes_density_times_stored_size(self):
        """75th-pct density × 100B quote → ~200, not 100 or 5000."""
        pairs = _worked_example_pairs()
        # New API: pass (fee, stored_size) pairs grouped per block.
        # The estimator ranks by `fee / stored_size` density.
        quote = mempool_percentile_estimate(
            [pairs],  # one block of pairs
            target_blocks=3,
            stored_size=100,
        )
        # 75th percentile of densities = 2/B; quoting 100B → 200.
        self.assertEqual(quote, 200)

    def test_quote_scales_linearly_with_stored_size(self):
        """Doubling stored_size doubles the quote (density × bytes)."""
        pairs = _worked_example_pairs()
        small = mempool_percentile_estimate(
            [pairs], target_blocks=3, stored_size=100,
        )
        big = mempool_percentile_estimate(
            [pairs], target_blocks=3, stored_size=200,
        )
        self.assertEqual(big, 2 * small)

    def test_low_urgency_picks_low_density_rung(self):
        """target_blocks=>10 → 25th-pct in the existing ladder; 10th otherwise.

        With one tx at 1/B and ten at 2/B, the 10th-pct of densities is
        1/B (the single low outlier), and 25th-pct is 2/B.  Either
        answer is acceptable so long as the helper is operating on
        densities; we assert the quote is one of those two density values
        × stored_size, NOT the absolute-fee artifact (5000 or 100).
        """
        pairs = _worked_example_pairs()
        # target_blocks=20 → 10th percentile in the ladder.
        quote = mempool_percentile_estimate(
            [pairs], target_blocks=20, stored_size=100,
        )
        # Acceptable: 1/B * 100 = 100 (10th-pct density rung).  Not
        # acceptable: the absolute-fee artifact 5000 (the 1-tx outlier
        # picked by absolute-fee ranking at the same percentile).
        self.assertIn(quote, (100, 200))
        self.assertNotEqual(quote, 5_000)

    def test_high_urgency_does_not_chase_absolute_outlier(self):
        """High urgency must still rank densities, not absolute fees.

        With one 5000-fee tx and ten 100-fee txs, an absolute-fee
        90th-pct chases the 5000 outlier.  Density-90th is 2/B → 200
        for a 100B quote.  Confirms the divide+remultiply bug is gone.
        """
        pairs = _worked_example_pairs()
        quote = mempool_percentile_estimate(
            [pairs], target_blocks=1, stored_size=100,
        )
        self.assertEqual(quote, 200)

    def test_zero_stored_size_returns_zero(self):
        """Defensive: stored_size<=0 means no useful quote."""
        pairs = _worked_example_pairs()
        self.assertEqual(
            mempool_percentile_estimate(
                [pairs], target_blocks=3, stored_size=0,
            ),
            0,
        )


# ── B. FeeEstimator percentiles over densities, not absolute fees ───


class TestFeeEstimatorOperatesOnDensities(unittest.TestCase):
    """`record_block_fees` accepts (fee, stored_size) pairs; the percentile
    is computed in fee-per-byte and the quote is density × quoting-bytes."""

    def test_record_pairs_and_quote_density_times_stored_size(self):
        est = FeeEstimator()
        # New API: record fee+size pairs per block.  Same worked example.
        est.record_block_fees(_worked_example_pairs())
        quote = est.estimate_fee(target_blocks=3, stored_size=100)
        # 75th-pct density = 2/B; 100B quote → 200.
        self.assertEqual(quote, 200)

    def test_quote_scales_with_quoting_stored_size(self):
        est = FeeEstimator()
        est.record_block_fees(_worked_example_pairs())
        small = est.estimate_fee(target_blocks=3, stored_size=100)
        big = est.estimate_fee(target_blocks=3, stored_size=200)
        self.assertEqual(big, 2 * small)

    def test_high_urgency_does_not_chase_absolute_fee_outlier(self):
        est = FeeEstimator()
        est.record_block_fees(_worked_example_pairs())
        quote = est.estimate_fee(target_blocks=1, stored_size=100)
        # Density 90th-pct = 2/B → 200.  Buggy absolute-fee 90th-pct
        # would chase the 5000 outlier.
        self.assertEqual(quote, 200)

    def test_quote_never_below_min_fee(self):
        """Floor still binds; density × bytes < MIN_FEE → MIN_FEE."""
        est = FeeEstimator()
        # Tiny densities so the floor binds.
        est.record_block_fees([(1, 1000)] * 10)  # density = 0.001/B
        quote = est.estimate_fee(target_blocks=3, stored_size=10)
        # 0.001 * 10 = 0.01 → flooring to MIN_FEE.
        self.assertGreaterEqual(quote, MIN_FEE)


if __name__ == "__main__":
    unittest.main()
