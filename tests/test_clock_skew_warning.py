"""
Tests for clock-skew warning when a locally proposed block fails
timing validation. The warning helps operators diagnose miscalibrated
system clocks — a silent degradation that only hurts the affected node.
"""

import unittest
from messagechain.consensus.block_producer import is_clock_skew_reason


class TestClockSkewDetection(unittest.TestCase):
    """is_clock_skew_reason must return True for timing-related rejection
    reasons from add_block, and False for everything else."""

    def test_detects_timestamp_too_early(self):
        reason = "Block timestamp too early: gap 300s < BLOCK_TIME_TARGET 600s"
        self.assertTrue(is_clock_skew_reason(reason))

    def test_detects_timestamp_too_far_in_future(self):
        reason = "Block timestamp 1700000000 too far in the future"
        self.assertTrue(is_clock_skew_reason(reason))

    def test_detects_timestamp_below_mtp(self):
        reason = "Block timestamp 1700000000 must exceed median time past 1700000100"
        self.assertTrue(is_clock_skew_reason(reason))

    def test_ignores_wrong_proposer(self):
        self.assertFalse(is_clock_skew_reason("Wrong proposer for slot"))

    def test_ignores_invalid_block_number(self):
        self.assertFalse(is_clock_skew_reason("Invalid block number"))

    def test_ignores_too_many_transactions(self):
        self.assertFalse(is_clock_skew_reason("Too many transactions"))

    def test_ignores_randao_mismatch(self):
        self.assertFalse(is_clock_skew_reason("randao mismatch"))
