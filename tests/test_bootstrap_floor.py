"""Tests for the post-bootstrap validator-count floor on finality.

Bootstrap exit is intentionally one-way — we do not want a validator to
leave briefly and re-enter relaxed rules at will.  But the original design
left a vulnerability: if validators drop below MIN_VALIDATORS_TO_EXIT_BOOTSTRAP
AFTER exit, a single remaining validator trivially controls 100% of total
stake and can finalize blocks unilaterally.

The fix: finalization (not block acceptance) requires a minimum number of
distinct attesters.  When the active set is too thin, finality simply halts
until more validators join.  Blocks can still be produced — they just stay
reversible.  This is the right failure mode: degraded liveness beats
compromised finality.
"""

import unittest
from messagechain.consensus.attestation import (
    Attestation, FinalityTracker,
)


class TestBootstrapFinalityFloor(unittest.TestCase):
    """Finality halts if active validator count is below the floor."""

    def setUp(self):
        self.tracker = FinalityTracker()
        self.block_hash = b"\xAB" * 32
        self.block_number = 10

    def _make_att(self, vid: bytes) -> Attestation:
        # Tests bypass signature verification by passing public_keys=None.
        return Attestation(
            validator_id=vid,
            block_hash=self.block_hash,
            block_number=self.block_number,
            signature=None,
        )

    def test_finalizes_when_above_floor(self):
        """With enough distinct attesters, 2/3 stake finalizes."""
        validators = [b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32]
        total_stake = 4000
        results = []
        for vid in validators:
            justified = self.tracker.add_attestation(
                self._make_att(vid),
                validator_stake=1000,
                total_stake=total_stake,
                min_validator_count=4,
            )
            results.append(justified)
        self.assertIn(True, results)
        self.assertIn(self.block_hash, self.tracker.finalized)

    def test_halts_below_floor_even_with_full_stake(self):
        """One validator controlling 100% of stake must NOT finalize alone."""
        validators = [b"\x01" * 32]
        total_stake = 1000
        for vid in validators:
            justified = self.tracker.add_attestation(
                self._make_att(vid),
                validator_stake=1000,
                total_stake=total_stake,
                min_validator_count=4,
            )
            self.assertFalse(justified)
        self.assertNotIn(self.block_hash, self.tracker.finalized)

    def test_halts_below_floor_with_partial_set(self):
        """3 validators cannot finalize when floor is 4."""
        validators = [b"\x01" * 32, b"\x02" * 32, b"\x03" * 32]
        total_stake = 3000
        for vid in validators:
            justified = self.tracker.add_attestation(
                self._make_att(vid),
                validator_stake=1000,
                total_stake=total_stake,
                min_validator_count=4,
            )
            self.assertFalse(justified)
        self.assertNotIn(self.block_hash, self.tracker.finalized)

    def test_default_floor_zero_preserves_backward_compat(self):
        """Omitting min_validator_count disables the floor (legacy callers)."""
        validators = [b"\x01" * 32]
        total_stake = 1000
        justified = self.tracker.add_attestation(
            self._make_att(validators[0]),
            validator_stake=1000,
            total_stake=total_stake,
        )
        self.assertTrue(justified)
        self.assertIn(self.block_hash, self.tracker.finalized)


if __name__ == "__main__":
    unittest.main()
