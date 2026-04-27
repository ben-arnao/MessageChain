"""
Unit tests for the ForkEmergencyDetector.

These exercise the detector in isolation — no Blockchain, no network.
Signature verification is the caller's responsibility (gossip ingest
already verifies once), so tests construct FinalityVotes with
placeholder signatures.
"""

import unittest

from messagechain.consensus.finality import FinalityVote
from messagechain.consensus.fork_emergency import (
    FORK_EMERGENCY_MAX_TRACKED_HEIGHTS,
    ForkEmergency,
    ForkEmergencyDetector,
)
from messagechain.crypto.keys import Signature


def _vote(signer_id: bytes, height: int, target_hash: bytes) -> FinalityVote:
    """Build a placeholder FinalityVote — signature not used by detector."""
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=height,
        signed_at_height=height,
        signature=Signature([], 0, [], b"", b""),
    )


def _sid(label: int) -> bytes:
    return bytes([label]) * 32


def _hash(label: int) -> bytes:
    return bytes([label]) * 32


class ForkEmergencyDetectorTests(unittest.TestCase):
    def test_below_threshold_returns_none(self):
        det = ForkEmergencyDetector()
        # 1/3 of total stake is well below the 2/3 threshold.
        emergency = det.observe_vote(
            _vote(_sid(1), height=100, target_hash=_hash(0xAA)),
            signer_stake=10,
            total_stake_at_target=100,
            local_hash_at_height=_hash(0xBB),
        )
        self.assertIsNone(emergency)
        self.assertFalse(det.is_in_emergency())

    def test_supermajority_matching_local_no_emergency(self):
        """If 2/3 sign the same hash this node already has, no emergency."""
        det = ForkEmergencyDetector()
        good_hash = _hash(0xAA)
        # Two signers each contributing 40% — exceeds 2/3.
        det.observe_vote(
            _vote(_sid(1), 100, good_hash),
            signer_stake=40,
            total_stake_at_target=100,
            local_hash_at_height=good_hash,
        )
        emergency = det.observe_vote(
            _vote(_sid(2), 100, good_hash),
            signer_stake=40,
            total_stake_at_target=100,
            local_hash_at_height=good_hash,
        )
        self.assertIsNone(emergency)
        self.assertFalse(det.is_in_emergency())

    def test_supermajority_disagreement_triggers_emergency(self):
        """2/3 sign hash X, but local chain has hash Y at this height."""
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        # First vote — well below threshold.
        first = det.observe_vote(
            _vote(_sid(1), 100, super_hash),
            signer_stake=30,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertIsNone(first)
        self.assertFalse(det.is_in_emergency())

        # Second vote pushes accumulated to 70 — crosses 2/3.
        second = det.observe_vote(
            _vote(_sid(2), 100, super_hash),
            signer_stake=40,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertIsNotNone(second)
        assert second is not None  # for type checker
        self.assertEqual(second.height, 100)
        self.assertEqual(second.supermajority_hash, super_hash)
        self.assertEqual(second.local_hash, local_hash)
        self.assertEqual(second.attested_stake, 70)
        self.assertEqual(second.total_stake, 100)
        self.assertTrue(det.is_in_emergency())

    def test_local_hash_unknown_still_triggers_emergency(self):
        """If we don't have any block at the height yet, supermajority
        disagreement still flags — we're behind on a chain we don't
        recognize."""
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)

        det.observe_vote(
            _vote(_sid(1), 200, super_hash),
            signer_stake=50,
            total_stake_at_target=100,
            local_hash_at_height=None,
        )
        emergency = det.observe_vote(
            _vote(_sid(2), 200, super_hash),
            signer_stake=20,
            total_stake_at_target=100,
            local_hash_at_height=None,
        )
        self.assertIsNotNone(emergency)
        assert emergency is not None
        self.assertIsNone(emergency.local_hash)
        self.assertTrue(det.is_in_emergency())

    def test_idempotent_same_signer_hash_does_not_double_count(self):
        """Re-observing the exact same vote contributes nothing."""
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        for _ in range(5):
            det.observe_vote(
                _vote(_sid(1), 300, super_hash),
                signer_stake=60,
                total_stake_at_target=100,
                local_hash_at_height=local_hash,
            )
        # 60% of total stake from the single signer never crosses 2/3
        # no matter how many times we re-observe the same vote.
        self.assertFalse(det.is_in_emergency())
        self.assertEqual(det.attested_stake(300, super_hash), 60)

    def test_equivocator_second_vote_ignored(self):
        """A signer voting for two hashes at one height contributes
        only their first observed hash. The second is the slashable
        double-vote and the detector deliberately mirrors
        FinalityCheckpoints.add_vote in skipping it."""
        det = ForkEmergencyDetector()
        hash_a = _hash(0xAA)
        hash_b = _hash(0xBB)

        det.observe_vote(
            _vote(_sid(1), 400, hash_a),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=hash_a,
        )
        # Same signer now flips to hash_b — must NOT count toward
        # hash_b's tally. Without this rule a single equivocator could
        # single-handedly push BOTH hashes to apparent supermajority.
        det.observe_vote(
            _vote(_sid(1), 400, hash_b),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=hash_a,
        )
        self.assertEqual(det.attested_stake(400, hash_b), 0)
        self.assertFalse(det.is_in_emergency())

    def test_emergencies_are_per_height(self):
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        # Trigger at height 100.
        det.observe_vote(
            _vote(_sid(1), 100, super_hash),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertTrue(det.is_in_emergency())

        # A perfectly normal supermajority at height 200 (matches
        # local) does NOT clear the height-100 emergency.
        det.observe_vote(
            _vote(_sid(1), 200, super_hash),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=super_hash,
        )
        self.assertTrue(det.is_in_emergency())
        self.assertEqual(len(det.current_emergencies()), 1)
        lowest = det.lowest_emergency()
        self.assertIsNotNone(lowest)
        assert lowest is not None
        self.assertEqual(lowest.height, 100)

    def test_clear_emergency_only_clears_explicit_height(self):
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        det.observe_vote(
            _vote(_sid(1), 100, super_hash),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        det.observe_vote(
            _vote(_sid(1), 200, super_hash),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertEqual(len(det.current_emergencies()), 2)

        cleared = det.clear_emergency(100)
        self.assertTrue(cleared)
        self.assertEqual(len(det.current_emergencies()), 1)
        self.assertEqual(det.current_emergencies()[0].height, 200)

        # Clearing a non-existent height is a no-op.
        self.assertFalse(det.clear_emergency(999))

    def test_clear_all_returns_count(self):
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        for h in (100, 200, 300):
            det.observe_vote(
                _vote(_sid(1), h, super_hash),
                signer_stake=70,
                total_stake_at_target=100,
                local_hash_at_height=local_hash,
            )
        self.assertEqual(det.clear_all(), 3)
        self.assertFalse(det.is_in_emergency())

    def test_zero_stake_vote_ignored(self):
        """A signer with zero stake has no voting weight."""
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)
        emergency = det.observe_vote(
            _vote(_sid(1), 100, super_hash),
            signer_stake=0,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertIsNone(emergency)
        self.assertEqual(det.attested_stake(100, super_hash), 0)

    def test_zero_total_stake_ignored(self):
        """A height with no recorded stake snapshot cannot trigger."""
        det = ForkEmergencyDetector()
        emergency = det.observe_vote(
            _vote(_sid(1), 100, _hash(0xAA)),
            signer_stake=10,
            total_stake_at_target=0,
            local_hash_at_height=None,
        )
        self.assertIsNone(emergency)

    def test_lru_eviction_caps_memory(self):
        """Pathological flood of distinct heights does not grow memory
        without bound — oldest heights are evicted."""
        det = ForkEmergencyDetector(max_tracked_heights=4)
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        # Trigger emergencies at heights 100..103.
        for h in range(100, 104):
            det.observe_vote(
                _vote(_sid(1), h, super_hash),
                signer_stake=70,
                total_stake_at_target=100,
                local_hash_at_height=local_hash,
            )
        self.assertEqual(len(det.current_emergencies()), 4)

        # Touching a new height must evict the oldest emergency too —
        # acting on a flag whose supporting votes have been GC'd would
        # be unsafe.
        det.observe_vote(
            _vote(_sid(1), 104, super_hash),
            signer_stake=70,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        heights = [e.height for e in det.current_emergencies()]
        self.assertNotIn(100, heights)
        self.assertIn(104, heights)
        self.assertEqual(len(heights), 4)

    def test_re_flag_same_height_same_hash_is_noop(self):
        """Once an emergency is recorded at (height, hash), additional
        votes that re-confirm the same supermajority hash do not
        re-emit the emergency."""
        det = ForkEmergencyDetector()
        super_hash = _hash(0xAA)
        local_hash = _hash(0xBB)

        first = None
        # 7 signers each at 10 stake — first crosses 2/3 at vote #7
        # since 7*10 = 70 >= 67.
        for i in range(1, 8):
            r = det.observe_vote(
                _vote(_sid(i), 500, super_hash),
                signer_stake=10,
                total_stake_at_target=100,
                local_hash_at_height=local_hash,
            )
            if r is not None and first is None:
                first = r

        self.assertIsNotNone(first)
        # Adding another signer beyond the threshold returns None
        # (already-flagged), but the emergency record is unchanged.
        extra = det.observe_vote(
            _vote(_sid(8), 500, super_hash),
            signer_stake=10,
            total_stake_at_target=100,
            local_hash_at_height=local_hash,
        )
        self.assertIsNone(extra)
        self.assertEqual(len(det.current_emergencies()), 1)

    def test_default_cap_constant_is_reasonable(self):
        # Sanity: the default cap is large enough for ~30 days of
        # 100-validator-network signing at FINALITY_INTERVAL=100
        # blocks (~86 distinct heights at chain-typical cadence) with
        # plenty of headroom for spam.
        self.assertGreaterEqual(FORK_EMERGENCY_MAX_TRACKED_HEIGHTS, 256)


class ForkEmergencyDataclassTests(unittest.TestCase):
    def test_short_repr_includes_key_fields(self):
        emergency = ForkEmergency(
            height=42,
            supermajority_hash=_hash(0xAA),
            local_hash=_hash(0xBB),
            attested_stake=70,
            total_stake=100,
        )
        s = emergency.short()
        self.assertIn("height=42", s)
        self.assertIn("70/100", s)
        self.assertIn("supermajority=", s)

    def test_short_repr_handles_missing_local(self):
        emergency = ForkEmergency(
            height=7,
            supermajority_hash=_hash(0xAA),
            local_hash=None,
            attested_stake=70,
            total_stake=100,
        )
        self.assertIn("local=<missing>", emergency.short())


if __name__ == "__main__":
    unittest.main()
