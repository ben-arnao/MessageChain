"""Tests for the progress callback in KeyPair generation."""

import io
import os
import re
import sys
import unittest
from contextlib import redirect_stderr

from messagechain.crypto.keys import KeyPair


class TestKeygenProgress(unittest.TestCase):
    def test_progress_called_once_per_leaf(self):
        """The callback is invoked exactly num_leaves times."""
        seed = os.urandom(32)
        count = [0]

        def cb(_leaf_index):
            count[0] += 1

        kp = KeyPair.generate(seed, height=3, progress=cb)
        self.assertEqual(count[0], 1 << 3)

    def test_progress_sees_all_leaf_indices(self):
        """Every leaf index from 0 to num_leaves-1 is reported."""
        seed = os.urandom(32)
        seen = []

        def cb(leaf_index):
            seen.append(leaf_index)

        KeyPair.generate(seed, height=3, progress=cb)
        self.assertEqual(sorted(seen), list(range(1 << 3)))

    def test_no_progress_works_normally(self):
        """Omitting the callback must not change behavior."""
        seed = os.urandom(32)
        kp1 = KeyPair.generate(seed, height=3)
        kp2 = KeyPair.generate(seed, height=3, progress=None)
        self.assertEqual(kp1.public_key, kp2.public_key)

    def test_progress_does_not_affect_public_key(self):
        """Providing a callback must not change the derived public key."""
        seed = os.urandom(32)
        kp1 = KeyPair.generate(seed, height=3)
        kp2 = KeyPair.generate(seed, height=3, progress=lambda _i: None)
        self.assertEqual(kp1.public_key, kp2.public_key)


class TestCliProgressReporter(unittest.TestCase):
    """CLI-layer reporter built by ``_make_progress_reporter``.
    Wraps the callback above for the ``messagechain init`` /
    ``generate-key`` / ``rotate-key`` paths where keygen at
    production MERKLE_TREE_HEIGHT=20 takes 90+ min.  Without
    rate + ETA the operator cannot tell whether their VM is
    sized right for the job.
    """

    def test_small_tree_returns_none(self):
        """Sub-4096-leaf trees (tests, prototype profile) skip the
        reporter -- printing overhead would dwarf keygen itself."""
        from messagechain.cli import _make_progress_reporter
        self.assertIsNone(_make_progress_reporter(16))
        self.assertIsNone(_make_progress_reporter(4095))

    def test_reporter_exists_for_production_tree(self):
        from messagechain.cli import _make_progress_reporter
        self.assertIsNotNone(_make_progress_reporter(4096))
        self.assertIsNotNone(_make_progress_reporter(1 << 20))

    def test_first_tick_arrives_at_leaf_one(self):
        """Anxiety-reducer: the operator must see motion within a
        second or two of keygen starting, not at the first 5%
        checkpoint (which on a weak VM is several minutes in)."""
        from messagechain.cli import _make_progress_reporter
        report = _make_progress_reporter(100_000, label="Keygen")
        buf = io.StringIO()
        with redirect_stderr(buf):
            report(0)   # leaf 0 -> done=1
        output = buf.getvalue()
        self.assertIn("Keygen:", output)
        # The first tick should be at ~0.0% (done=1 of 100k).
        self.assertIn("0.0%", output)

    def test_reporter_includes_rate_and_eta(self):
        """Rate (leaves/sec) and ETA are the two pieces of
        information that let an operator gauge 'is this really
        going to take 2 hours?' -- both must be in every update."""
        from messagechain.cli import _make_progress_reporter
        report = _make_progress_reporter(10_000, label="Keygen")
        buf = io.StringIO()
        with redirect_stderr(buf):
            for i in range(200):  # drive past the first tick + 1%
                report(i)
        output = buf.getvalue()
        # Rate as '<N>/s', ETA as '<...>' from _format_eta_seconds.
        self.assertRegex(output, r"\[\d+/s, ETA ")

    def test_final_tick_includes_newline(self):
        """After the last leaf the reporter must emit a newline so
        subsequent stderr output doesn't overwrite the progress
        line.  Regression anchor for the self-overwrite pattern."""
        from messagechain.cli import _make_progress_reporter
        n = 5000
        report = _make_progress_reporter(n, label="Keygen")
        buf = io.StringIO()
        with redirect_stderr(buf):
            for i in range(n):
                report(i)
        output = buf.getvalue()
        # 100.0% must appear and be followed by a newline.
        self.assertIn("100.0%", output)
        # The trailing newline is printed after the final carriage-
        # return frame -- the last character of output must be \n.
        self.assertTrue(output.endswith("\n"))

    def test_early_cadence_is_denser_than_steady(self):
        """First 5% uses 1% increments; afterwards 5% increments.
        Protects against future refactors that silently drop the
        early-dense regime (regression anchor for the anxiety-
        reducing startup feedback).
        """
        from messagechain.cli import _make_progress_reporter
        n = 10_000
        report = _make_progress_reporter(n, label="Keygen")
        buf = io.StringIO()
        with redirect_stderr(buf):
            for i in range(n):
                report(i)
        output = buf.getvalue()
        # Each tick writes one '\r' frame. Count frames in the
        # first 5% of leaves (~500) vs. the remainder (~9500).
        # Early regime: 1% cadence -> ~5 ticks in first 5%.
        # Steady regime: 5% cadence -> ~19 ticks in remaining 95%.
        # Look for early-percent frames (0.0%..4.x%) vs. later.
        early_frames = len(re.findall(
            r"\r[^\r]* [0-4]\.\d%", output,
        ))
        # The key invariant: at least 3 frames in the early window
        # (validates 1%-ish cadence, not just one frame at 0% and
        # another at 5%).
        self.assertGreaterEqual(
            early_frames, 3,
            f"Expected >=3 early frames (<5%) for dense startup "
            f"feedback, saw {early_frames}. Output snippet:\n"
            f"{output[:300]!r}",
        )


class TestFormatEtaSeconds(unittest.TestCase):
    """Small but worth locking down -- the reporter rewrites its
    line every tick, so a longer-then-shorter ETA transition
    ('1h02m' -> '8s') relies on consistent formatting width and
    the trailing-spaces pad in the reporter."""

    def test_seconds_under_minute(self):
        from messagechain.cli import _format_eta_seconds
        self.assertEqual(_format_eta_seconds(0.5), "?")  # non-positive
        self.assertEqual(_format_eta_seconds(1), "1s")
        self.assertEqual(_format_eta_seconds(59), "59s")

    def test_minutes_with_zero_padded_seconds(self):
        from messagechain.cli import _format_eta_seconds
        self.assertEqual(_format_eta_seconds(60), "1m00s")
        self.assertEqual(_format_eta_seconds(125), "2m05s")
        self.assertEqual(_format_eta_seconds(3599), "59m59s")

    def test_hours_with_zero_padded_minutes(self):
        from messagechain.cli import _format_eta_seconds
        self.assertEqual(_format_eta_seconds(3600), "1h00m")
        self.assertEqual(_format_eta_seconds(3600 + 120), "1h02m")
        self.assertEqual(_format_eta_seconds(2 * 3600 + 59 * 60), "2h59m")

    def test_non_positive_and_infinite_return_placeholder(self):
        from messagechain.cli import _format_eta_seconds
        self.assertEqual(_format_eta_seconds(0), "?")
        self.assertEqual(_format_eta_seconds(-10), "?")
        self.assertEqual(_format_eta_seconds(float("inf")), "?")
        self.assertEqual(_format_eta_seconds(float("nan")), "?")


if __name__ == "__main__":
    unittest.main()
