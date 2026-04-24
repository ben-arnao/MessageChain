"""R5-D defense-in-depth: FinalityCheckpoints.finalized_by_height must
never silently overwrite an existing hash at a given height.

The equivocation gate in add_vote already prevents a single signer from
pushing two different hashes to 2/3 at the same height on the honest
path.  These tests lock in the defense-in-depth guard for the two
paths that write finalized_by_height:

    1. add_vote: if, for any reason, a SECOND hash reaches 2/3 at an
       already-finalized height (corruption, unforeseen attack), the
       write must NOT silently overwrite B1 with B2.
    2. mark_finalized: cold-load from persistent storage — if chaindb
       is corrupted and presents two different hashes at the same
       height, the node must refuse to start rather than silently
       pick the last-loaded one.  Same hash twice (idempotent reload)
       is fine.
"""

import unittest

from messagechain.consensus.finality import (
    FinalityVote,
    FinalityCheckpoints,
)
from messagechain.core.block import _hash
from messagechain.crypto.keys import Signature


def _make_vote(signer_id: bytes, target_hash: bytes, target_num: int) -> FinalityVote:
    # None-signature fixture matches test_finality.py; these tests
    # exercise counter/guard logic, not signature crypto.
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=target_num,
        signature=Signature([], 0, [], b"", b""),
    )


class TestAddVoteConflictingFinalizationGuard(unittest.TestCase):
    """Test A: defence-in-depth in add_vote's write to finalized_by_height."""

    def test_second_block_reaching_threshold_does_not_overwrite(self):
        """Force a synthetic scenario where two DIFFERENT blocks both
        reach 2/3 at the same height via DISJOINT signer sets — so the
        per-signer equivocation gate does NOT fire.  The second
        finalization attempt must either raise a clear exception, or
        return False + leave finalized_by_height[H] unchanged at B1.
        """
        cp = FinalityCheckpoints()
        height = 42
        block_a = _hash(b"block_A")
        block_b = _hash(b"block_B")

        # Two disjoint signers → 2/3 for B1 at height H
        sa1 = b"sa1".ljust(32, b"\x00")
        sa2 = b"sa2".ljust(32, b"\x00")
        self.assertFalse(cp.add_vote(_make_vote(sa1, block_a, height), 100, 300))
        self.assertTrue(cp.add_vote(_make_vote(sa2, block_a, height), 100, 300))
        self.assertEqual(cp.finalized_by_height[height], block_a)

        # Now two DIFFERENT signers push B2 to 2/3 at the same height.
        # The equivocation gate won't fire because these signer IDs are
        # disjoint from sa1/sa2 — so without a uniqueness guard the
        # second write would silently overwrite.
        sb1 = b"sb1".ljust(32, b"\x00")
        sb2 = b"sb2".ljust(32, b"\x00")
        cp.add_vote(_make_vote(sb1, block_b, height), 100, 300)
        try:
            result = cp.add_vote(_make_vote(sb2, block_b, height), 100, 300)
        except Exception:
            # Raised loudly — acceptable.
            self.assertEqual(cp.finalized_by_height[height], block_a)
            return
        # Didn't raise → must have refused (returned False-ish) and
        # preserved B1 at height H.
        self.assertFalse(result)
        self.assertEqual(cp.finalized_by_height[height], block_a)


class TestMarkFinalizedUniquenessGuard(unittest.TestCase):
    """Tests B and C: mark_finalized cold-load guard."""

    def test_conflicting_cold_load_raises(self):
        """Test B: two different hashes for the same block_number →
        cold-load must hard-fail rather than silently pick last-loaded.
        """
        cp = FinalityCheckpoints()
        b1 = _hash(b"B1")
        b2 = _hash(b"B2")
        cp.mark_finalized(b1, 42)
        with self.assertRaises(Exception):
            cp.mark_finalized(b2, 42)
        # First-loaded value must be preserved.
        self.assertEqual(cp.finalized_by_height[42], b1)

    def test_idempotent_same_hash_same_height(self):
        """Test C: calling mark_finalized twice with the SAME hash at
        the SAME height must be idempotent — no raise, no state change.
        """
        cp = FinalityCheckpoints()
        b1 = _hash(b"B1")
        cp.mark_finalized(b1, 42)
        # Second call with identical args must not raise.
        cp.mark_finalized(b1, 42)
        self.assertEqual(cp.finalized_by_height[42], b1)
        self.assertIn(b1, cp.finalized_hashes)


if __name__ == "__main__":
    unittest.main()
