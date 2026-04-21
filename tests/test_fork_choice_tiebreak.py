"""
Tests for fork-choice tie-breaking.

Security invariant: when two forks have identical cumulative stake weight,
the winner MUST be chosen by tip-block-hash, not by greater height. A
height-based tiebreak lets a minority validator produce a longer-but-
equal-weight fork and force a reorg; a hash-based tiebreak costs a full
proposer signature per grind attempt, making manipulation uneconomic.
"""

import unittest

from messagechain.consensus.fork_choice import ForkChoice


class TestForkChoiceTiebreak(unittest.TestCase):
    def test_equal_weight_taller_fork_does_not_win(self):
        """A longer-height fork with equal weight must NOT beat the shorter one."""
        fc = ForkChoice()
        # Shorter chain with a lexicographically-small tip hash
        low_hash = b"\x01" * 32
        fc.add_tip(low_hash, 5, 100)
        # Longer chain with equal weight but lexicographically-larger hash
        high_hash = b"\xff" * 32
        fc.add_tip(high_hash, 9, 100)

        best = fc.get_best_tip()
        # The longer-height fork must NOT win on height alone.
        self.assertNotEqual(
            best[0], high_hash,
            "Height-based tiebreak allows minority reorg — must use hash",
        )
        # With lex-smaller-wins, the low-hash tip is the canonical winner.
        self.assertEqual(best[0], low_hash)

    def test_equal_weight_hash_tiebreak_is_deterministic(self):
        """Hash tiebreak must be deterministic regardless of insertion order."""
        low_hash = b"\x00" + b"\xaa" * 31
        high_hash = b"\xfe" + b"\xaa" * 31

        fc1 = ForkChoice()
        fc1.add_tip(high_hash, 5, 100)
        fc1.add_tip(low_hash, 5, 100)

        fc2 = ForkChoice()
        fc2.add_tip(low_hash, 5, 100)
        fc2.add_tip(high_hash, 5, 100)

        self.assertEqual(fc1.get_best_tip()[0], fc2.get_best_tip()[0])
        self.assertEqual(fc1.get_best_tip()[0], low_hash)

    def test_is_better_chain_rejects_equal_weight_taller_fork(self):
        """is_better_chain must NOT accept an equal-weight chain just because it is taller."""
        fc = ForkChoice()
        cur_hash = b"\x05" * 32
        fc.add_tip(cur_hash, 5, 100)

        # Taller fork, equal weight, lex-larger hash — must be rejected.
        taller_larger_hash = b"\xee" * 32
        self.assertFalse(
            fc.is_better_chain(100, 20, taller_larger_hash),
            "Equal-weight taller fork must not win — height must not be a tiebreak",
        )

    def test_is_better_chain_accepts_equal_weight_smaller_hash(self):
        """A tip with equal weight and lex-smaller hash wins the tiebreak."""
        fc = ForkChoice()
        cur_hash = b"\x55" * 32
        fc.add_tip(cur_hash, 10, 100)

        smaller_hash = b"\x11" * 32
        self.assertTrue(fc.is_better_chain(100, 3, smaller_hash))

    def test_is_better_chain_heavier_still_wins(self):
        """Weight remains the primary criterion; any hash wins if heavier."""
        fc = ForkChoice()
        fc.add_tip(b"\x01" * 32, 5, 100)
        # Heavier chain with lex-larger hash still wins.
        self.assertTrue(fc.is_better_chain(200, 3, b"\xff" * 32))

    def test_is_better_chain_lighter_still_loses(self):
        fc = ForkChoice()
        fc.add_tip(b"\xff" * 32, 5, 100)
        # Lighter chain with lex-smaller hash still loses.
        self.assertFalse(fc.is_better_chain(50, 99, b"\x00" * 32))


if __name__ == "__main__":
    unittest.main()
