"""Tests for reorg state machine correctness.

Three critical bugs where _reset_state() mishandles fields during reorg:
1. slashed_validators cleared but _processed_evidence kept (slash evasion)
2. reputation dict not reset (stale counts after reorg)
3. FinalityTracker not reset (stale finality data after reorg)
Plus a regression test for revoked_entities (already correct).
"""

import unittest

from messagechain.core.blockchain import Blockchain


class TestSlashedValidatorRatchet(unittest.TestCase):
    """Bug 1: slashed_validators must be a security ratchet — never cleared."""

    def test_slashed_validator_stays_slashed_after_reorg(self):
        """Once an entity is slashed on any fork, the punishment is permanent.
        _reset_state() must NOT clear slashed_validators."""
        chain = Blockchain()

        entity_id = b"equivocator"
        evidence_hash = b"evidence-hash-001"

        # Simulate slash state from a block on the old fork
        chain.slashed_validators.add(entity_id)
        chain._processed_evidence.add(evidence_hash)

        # Trigger _reset_state (called during reorg replay)
        chain._reset_state()

        # slashed_validators must survive (security ratchet)
        self.assertIn(
            entity_id,
            chain.slashed_validators,
            "slashed_validators must not be cleared by _reset_state — "
            "slash evasion via reorg",
        )

        # _processed_evidence must also survive (already correct, regression check)
        self.assertIn(
            evidence_hash,
            chain._processed_evidence,
            "_processed_evidence must not be cleared by _reset_state",
        )

    def test_processed_evidence_consistent_with_slashed(self):
        """After _reset_state, both _processed_evidence and slashed_validators
        must be preserved so there is no inconsistency."""
        chain = Blockchain()

        chain.slashed_validators.add(b"v1")
        chain.slashed_validators.add(b"v2")
        chain._processed_evidence.add(b"ev1")
        chain._processed_evidence.add(b"ev2")

        chain._reset_state()

        self.assertEqual(chain.slashed_validators, {b"v1", b"v2"})
        self.assertEqual(chain._processed_evidence, {b"ev1", b"ev2"})


class TestReputationResetOnReorg(unittest.TestCase):
    """Bug 2: reputation dict must be reset so replay rebuilds it from scratch."""

    def test_reputation_reset_on_reorg(self):
        """Stale reputation from old fork must not persist after _reset_state."""
        chain = Blockchain()

        # Simulate reputation accumulated from old-fork attestations
        chain.reputation[b"validator-a"] = 42
        chain.reputation[b"validator-b"] = 17

        chain._reset_state()

        # reputation must be empty — replay will rebuild it
        self.assertEqual(
            chain.reputation,
            {},
            "reputation dict must be cleared by _reset_state to avoid "
            "stale counts diverging lottery selection across nodes",
        )


class TestFinalityTrackerResetOnReorg(unittest.TestCase):
    """Bug 3: FinalityTracker (in-memory attestation finality) must be reset."""

    def test_finality_tracker_reset_on_reorg(self):
        """Old-fork finality data must not persist after _reset_state."""
        chain = Blockchain()

        # Simulate finality state from old fork by directly adding to
        # the FinalityTracker's internal finalized set
        fake_block_hash = b"\x01" * 32
        chain.finality.finalized.add(fake_block_hash)
        self.assertTrue(chain.finality.is_finalized(fake_block_hash))

        chain._reset_state()

        # After reset, the tracker should be fresh — no stale finalized blocks
        self.assertFalse(
            chain.finality.is_finalized(fake_block_hash),
            "FinalityTracker must be reset by _reset_state — stale finality "
            "from old fork should not persist",
        )

    def test_finalized_checkpoints_not_reset(self):
        """FinalityCheckpoints (persistent, long-range-attack defense) must NOT
        be cleared by _reset_state — finalized blocks stay finalized."""
        chain = Blockchain()

        fake_hash = b"\x02" * 32
        chain.finalized_checkpoints.mark_finalized(fake_hash, block_number=10)

        chain._reset_state()

        self.assertTrue(
            chain.finalized_checkpoints.is_finalized(fake_hash),
            "finalized_checkpoints must NOT be cleared — persistent finality "
            "survives reorgs for long-range-attack defense",
        )


class TestRevokedEntitiesPreservedOnReorg(unittest.TestCase):
    """Regression: revoked_entities is already NOT cleared (correct). Verify."""

    def test_revoked_entities_preserved_on_reorg(self):
        chain = Blockchain()
        chain.revoked_entities.add(b"compromised-entity")

        chain._reset_state()

        self.assertIn(
            b"compromised-entity",
            chain.revoked_entities,
            "revoked_entities must not be cleared by _reset_state — "
            "emergency revocation is a permanent security ratchet",
        )


if __name__ == "__main__":
    unittest.main()
