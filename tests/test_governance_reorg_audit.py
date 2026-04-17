"""Tests for governance state correctness across reorg snapshot/restore.

Bug under test: `_snapshot_memory_state` captured only a shallow
(votes, created_at_block) tuple for each proposal, and
`_restore_memory_snapshot` NEVER wrote `gov_proposals` back onto
`self.governance.proposals`.  On a failed reorg, proposals ended up
in a mix of old + new state:

- Votes cast on the aborted fork leaked into the restored state.
- `stake_snapshot` (and the full ProposalState payload) was never
  carried in the snapshot at all, so even if the restore path ran it
  could not have reconstructed the pre-reorg tracker.

The fix uses `copy.deepcopy` on the entire `gov.proposals` dict in both
snapshot and restore so nested mutation on the new fork cannot leak
across the rollback boundary.
"""

import copy
import unittest

from messagechain.core.blockchain import Blockchain
from messagechain.governance.governance import (
    ProposalState,
    ProposalTransaction,
)
from messagechain.crypto.keys import Signature


def _fake_proposal(tag: bytes) -> ProposalTransaction:
    """Build a ProposalTransaction without signing — we only need .tx_hash
    to flow through the tracker in these state-machine tests."""
    return ProposalTransaction(
        proposer_id=b"proposer-" + tag,
        title="title-" + tag.decode("ascii", errors="replace"),
        description="desc-" + tag.decode("ascii", errors="replace"),
        timestamp=0.0,
        fee=0,
        signature=Signature([], 0, [], b"", b""),
        reference_hash=b"",
    )


def _install_proposal(chain: Blockchain, tag: bytes,
                      stake_snapshot: dict, created_at_block: int = 1,
                      votes: dict | None = None) -> bytes:
    """Register a proposal directly into the tracker, bypassing the block
    pipeline.  Returns the proposal_id."""
    tx = _fake_proposal(tag)
    pid = tx.proposal_id
    chain.governance.proposals[pid] = ProposalState(
        proposal=tx,
        created_at_block=created_at_block,
        stake_snapshot=dict(stake_snapshot),
        total_eligible_stake=sum(stake_snapshot.values()),
        votes=dict(votes) if votes else {},
    )
    return pid


class TestGovProposalsRestoredOnFailedReorg(unittest.TestCase):
    """The full ProposalState (proposal tx, stake_snapshot, votes, block)
    must be restored verbatim when a reorg aborts."""

    def test_gov_proposals_restored_on_failed_reorg(self):
        chain = Blockchain()

        stake = {b"val-a": 1000, b"val-b": 500, b"val-c": 250}
        pid = _install_proposal(
            chain, b"p1", stake_snapshot=stake, created_at_block=3,
            votes={b"val-a": True, b"val-b": False},
        )

        # Capture expected values from the pre-snapshot state
        expected_state = chain.governance.proposals[pid]
        expected_votes = dict(expected_state.votes)
        expected_stake = dict(expected_state.stake_snapshot)
        expected_eligible = expected_state.total_eligible_stake
        expected_block = expected_state.created_at_block

        # Snapshot (what _reorganize captures before rolling back)
        snapshot = chain._snapshot_memory_state()

        # Simulate what happens during the failed-reorg window: new fork
        # mutates governance state.
        chain.governance.proposals[pid].votes[b"val-c"] = True  # new vote
        chain.governance.proposals[pid].votes[b"val-a"] = False  # flipped!
        chain.governance.proposals.pop(pid, None)  # and even drops it
        # add a spurious proposal from the aborted fork
        spurious_pid = _install_proposal(
            chain, b"spurious", stake_snapshot={b"x": 1}, created_at_block=9,
        )

        # Restore (what _reorganize runs on abort)
        chain._restore_memory_snapshot(snapshot)

        # Original proposal must be back, with original votes & snapshot
        self.assertIn(pid, chain.governance.proposals,
                      "Original proposal must be restored on rollback")
        restored = chain.governance.proposals[pid]
        self.assertEqual(restored.votes, expected_votes,
                         "Votes must match pre-reorg state exactly")
        self.assertEqual(restored.stake_snapshot, expected_stake,
                         "stake_snapshot must match pre-reorg state exactly")
        self.assertEqual(restored.total_eligible_stake, expected_eligible)
        self.assertEqual(restored.created_at_block, expected_block)

        # Proposal introduced during the aborted fork must be gone
        self.assertNotIn(
            spurious_pid, chain.governance.proposals,
            "Proposals introduced on the aborted fork must not leak through",
        )


class TestGovProposalsIsolatedSnapshots(unittest.TestCase):
    """Mutations to governance.proposals after snapshotting must not
    bleed into the snapshot itself (deepcopy isolation)."""

    def test_post_snapshot_mutations_do_not_leak_into_snapshot(self):
        chain = Blockchain()
        pid = _install_proposal(
            chain, b"iso", stake_snapshot={b"v": 100}, created_at_block=2,
            votes={b"v": True},
        )

        snapshot = chain._snapshot_memory_state()

        # Mutate live state after snapshot
        chain.governance.proposals[pid].votes[b"v"] = False
        chain.governance.proposals[pid].votes[b"w"] = True
        chain.governance.proposals[pid].stake_snapshot[b"v"] = 99999
        # Add a whole new proposal
        _install_proposal(
            chain, b"later", stake_snapshot={b"q": 1}, created_at_block=5,
        )

        # Restore from the earlier snapshot
        chain._restore_memory_snapshot(snapshot)

        # The restored state must reflect the pre-mutation values
        restored = chain.governance.proposals[pid]
        self.assertEqual(
            restored.votes, {b"v": True},
            "Post-snapshot vote mutations must not appear after restore",
        )
        self.assertEqual(
            restored.stake_snapshot, {b"v": 100},
            "Post-snapshot stake_snapshot mutations must not appear after restore",
        )
        # Exactly one proposal — the one captured at snapshot time
        self.assertEqual(
            set(chain.governance.proposals.keys()), {pid},
            "Proposals added after snapshot must be removed on restore",
        )

    def test_mutating_restored_state_does_not_corrupt_snapshot(self):
        """The snapshot itself must be independent from the restored live
        state (deepcopy on both sides), so a second restore still works."""
        chain = Blockchain()
        pid = _install_proposal(
            chain, b"twice", stake_snapshot={b"v": 10}, created_at_block=1,
            votes={b"v": True},
        )
        snapshot = chain._snapshot_memory_state()

        # First restore, then mutate the restored state
        chain._restore_memory_snapshot(snapshot)
        chain.governance.proposals[pid].votes[b"v"] = False

        # Second restore from the same snapshot must still yield original
        chain._restore_memory_snapshot(snapshot)
        self.assertEqual(
            chain.governance.proposals[pid].votes, {b"v": True},
            "Snapshot dict must not be mutated by operations on restored state",
        )


class TestExecutedTreasurySpendsRegression(unittest.TestCase):
    """Existing executed-treasury-spends restore behavior must still work."""

    def test_gov_executed_treasury_spends_still_restored(self):
        chain = Blockchain()

        chain.governance._executed_treasury_spends.add(b"spend-1")
        chain.governance._executed_treasury_spends.add(b"spend-2")

        snapshot = chain._snapshot_memory_state()

        # Mutate live state
        chain.governance._executed_treasury_spends.add(b"spend-3")
        chain.governance._executed_treasury_spends.discard(b"spend-1")

        chain._restore_memory_snapshot(snapshot)
        self.assertEqual(
            chain.governance._executed_treasury_spends,
            {b"spend-1", b"spend-2"},
        )


class TestGovVoteTamperingRevertedOnRestore(unittest.TestCase):
    """Direct vote tampering after snapshot must be fully reverted."""

    def test_gov_vote_tampering_reverted_on_restore(self):
        chain = Blockchain()
        pid = _install_proposal(
            chain, b"tamp",
            stake_snapshot={b"A": 500, b"B": 500},
            created_at_block=4,
            votes={b"A": True},
        )

        snapshot = chain._snapshot_memory_state()

        # Tamper: flip A's vote
        chain.governance.proposals[pid].votes[b"A"] = False
        self.assertEqual(
            chain.governance.proposals[pid].votes[b"A"], False,
        )

        chain._restore_memory_snapshot(snapshot)

        self.assertEqual(
            chain.governance.proposals[pid].votes[b"A"], True,
            "Vote must be restored to its pre-snapshot value",
        )


if __name__ == "__main__":
    unittest.main()
