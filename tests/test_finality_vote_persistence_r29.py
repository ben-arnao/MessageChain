"""Regression tests for audit r29 #3 (1.59.1):
``FinalityCheckpoints._vote_by_signer_height`` is now persisted to
``chain.db.finality_votes_seen`` so a validator cannot evade local
equivocation detection by timing the second of two conflicting
finality votes to a network-wide restart window.

Pre-fix the map was in-memory only.  An attacker scenario:
  1. Validator V signs FinalityVote A for (target_height H, hash H1)
  2. V (or the operator) restarts the local node, deliberately or
     coincidentally with a release roll / OS update window.
  3. V signs FinalityVote B for (target_height H, hash H2 ≠ H1).
  4. Local equivocation detection has nothing to compare against
     because the restart flushed ``_vote_by_signer_height`` -- the
     second vote is recorded as a first observation.

Honest peers that saw both votes still detect, but in a network-
wide restart window every node loses its local evidence
simultaneously.  Auto-slash deterrent silently amnestied.

Post-fix every observation is persisted to chaindb on add, and
``rehydrate_from_chaindb`` warms the cache on cold-restart so the
gate fires on the first post-restart conflict.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from messagechain.consensus.finality import (
    FinalityCheckpoints,
    FinalityDoubleVoteEvidence,
    FinalityVote,
)
from messagechain.crypto.keys import Signature
from messagechain.storage.chaindb import ChainDB


def _close(db: ChainDB) -> None:
    try:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
    except Exception:
        pass


def _make_vote(
    signer_id: bytes,
    target_hash: bytes,
    target_num: int,
    signed_at_height: int = 0,
) -> FinalityVote:
    """Produce a FinalityVote with a stub signature.  These tests
    only exercise the equivocation map; the signature is not
    verified by ``add_vote`` (verification is the caller's job).
    Stub shape mirrors test_finality_uniqueness_guard.py."""
    return FinalityVote(
        signer_entity_id=signer_id,
        target_block_hash=target_hash,
        target_block_number=target_num,
        signed_at_height=signed_at_height or target_num,
        signature=Signature([], 0, [], b"", b""),
    )


class _FreshDBMixin:
    def _fresh_db(self) -> ChainDB:
        tmp = tempfile.mkdtemp(prefix="mc_test_")
        self.addCleanup(shutil.rmtree, tmp, True)
        return ChainDB(os.path.join(tmp, "chain.db"))


class TestFinalityVotesSeenChaindbAccessors(
    _FreshDBMixin, unittest.TestCase,
):
    """Round-trip pins for the chaindb accessors themselves."""

    def test_round_trip_single_observation(self):
        db = self._fresh_db()
        signer = b"S" * 32
        h_target = 100
        h_hash = b"H" * 32
        payload = b"\x01\x02\x03"
        inserted = db.add_finality_vote_seen(
            signer, h_target, h_hash, payload,
            first_seen_block_height=99,
        )
        self.assertTrue(inserted)
        got = db.get_finality_vote_seen(signer, h_target)
        self.assertIsNotNone(got)
        h, p, fs = got
        self.assertEqual(h, h_hash)
        self.assertEqual(p, payload)
        self.assertEqual(fs, 99)
        _close(db)

    def test_idempotent_insert(self):
        db = self._fresh_db()
        signer = b"S" * 32
        first = db.add_finality_vote_seen(
            signer, 50, b"A" * 32, b"X", first_seen_block_height=49,
        )
        again = db.add_finality_vote_seen(
            signer, 50, b"B" * 32, b"Y", first_seen_block_height=51,
        )
        self.assertTrue(first)
        self.assertFalse(
            again,
            "second insert at the same (signer, height) must be "
            "ignored -- the equivocation gate compares against the "
            "FIRST observation, not the latest",
        )
        # The first row pins.  Second insert with different hash is
        # ignored at this layer (caller built evidence higher up).
        h, p, _ = db.get_finality_vote_seen(signer, 50)
        self.assertEqual(h, b"A" * 32)
        self.assertEqual(p, b"X")
        _close(db)

    def test_get_all_returns_every_row(self):
        db = self._fresh_db()
        for i in range(5):
            db.add_finality_vote_seen(
                signer_id=bytes([i]) * 32,
                target_block_number=100 + i,
                target_block_hash=bytes([i + 64]) * 32,
                vote_payload=bytes([i]),
                first_seen_block_height=99 + i,
            )
        rows = db.get_all_finality_votes_seen()
        self.assertEqual(len(rows), 5)
        # Every entry round-trips.
        seen = {(r[0], r[1]) for r in rows}
        for i in range(5):
            self.assertIn((bytes([i]) * 32, 100 + i), seen)
        _close(db)

    def test_prune_drops_old_rows(self):
        db = self._fresh_db()
        db.add_finality_vote_seen(
            b"X" * 32, 100, b"H" * 32, b"P",
            first_seen_block_height=10,
        )
        db.add_finality_vote_seen(
            b"X" * 32, 200, b"H" * 32, b"P",
            first_seen_block_height=150,
        )
        db.add_finality_vote_seen(
            b"X" * 32, 300, b"H" * 32, b"P",
            first_seen_block_height=300,
        )
        deleted = db.prune_finality_votes_before(200)
        self.assertEqual(deleted, 2)
        self.assertEqual(db.count_finality_votes_seen(), 1)
        # The surviving row is the height-300 one.
        self.assertIsNotNone(db.get_finality_vote_seen(b"X" * 32, 300))
        self.assertIsNone(db.get_finality_vote_seen(b"X" * 32, 100))
        _close(db)


class TestRestartWindowEquivocationDetected(
    _FreshDBMixin, unittest.TestCase,
):
    """The defect class the fix closes: A validator who signs
    conflicting finality votes ACROSS a node restart must still be
    detected on the first post-restart conflicting observation."""

    def test_restart_between_conflicting_votes_still_slashes(self):
        db = self._fresh_db()
        signer = b"V" * 32
        # Pre-restart: validator signs A.
        fc1 = FinalityCheckpoints(chaindb=db)
        vote_a = _make_vote(signer, b"A" * 32, 100)
        fc1.add_vote(vote_a, signer_stake=10, total_stake_at_target=30)
        self.assertEqual(
            len(fc1.pending_slashing_evidence), 0,
            "first observation must not produce evidence",
        )
        # Restart simulation: drop the in-memory FinalityCheckpoints,
        # rebuild a fresh one bound to the same chaindb (the row
        # the first instance persisted is still there).
        fc2 = FinalityCheckpoints(chaindb=db)
        loaded = fc2.rehydrate_from_chaindb()
        self.assertEqual(loaded, 1)
        # Post-restart: validator signs B (conflicting).
        vote_b = _make_vote(signer, b"B" * 32, 100)
        crossed = fc2.add_vote(
            vote_b, signer_stake=10, total_stake_at_target=30,
        )
        self.assertFalse(crossed)
        self.assertEqual(
            len(fc2.pending_slashing_evidence), 1,
            "post-restart conflicting vote must produce equivocation "
            "evidence -- this is the entire point of the fix",
        )
        ev = fc2.pending_slashing_evidence[0]
        self.assertIsInstance(ev, FinalityDoubleVoteEvidence)
        self.assertEqual(ev.offender_id, signer)
        # Evidence carries BOTH original signed votes for slashing.
        self.assertEqual(ev.vote_a.target_block_hash, b"A" * 32)
        self.assertEqual(ev.vote_b.target_block_hash, b"B" * 32)
        _close(db)

    def test_restart_with_no_prior_vote_is_clean_observation(self):
        # Sanity: a fresh node booting with no chaindb history
        # (no prior observations) handles the first vote as a fresh
        # observation, no spurious evidence.
        db = self._fresh_db()
        fc = FinalityCheckpoints(chaindb=db)
        loaded = fc.rehydrate_from_chaindb()
        self.assertEqual(loaded, 0)
        signer = b"V" * 32
        vote = _make_vote(signer, b"H" * 32, 100)
        fc.add_vote(vote, signer_stake=10, total_stake_at_target=30)
        self.assertEqual(len(fc.pending_slashing_evidence), 0)
        _close(db)

    def test_chaindb_unbound_falls_back_to_legacy_in_memory_path(self):
        # Legacy / in-memory test fixtures construct
        # FinalityCheckpoints with no chaindb.  Pre-fix behavior must
        # be preserved exactly: same-process equivocation detected,
        # cross-restart equivocation NOT detected (which is the
        # known limitation the fix closes only when chaindb is
        # bound).
        fc = FinalityCheckpoints()
        signer = b"V" * 32
        vote_a = _make_vote(signer, b"A" * 32, 100)
        vote_b = _make_vote(signer, b"B" * 32, 100)
        fc.add_vote(vote_a, signer_stake=10, total_stake_at_target=30)
        fc.add_vote(vote_b, signer_stake=10, total_stake_at_target=30)
        self.assertEqual(
            len(fc.pending_slashing_evidence), 1,
            "in-memory equivocation gate must still work without a "
            "chaindb -- the persistent path is additive, not a "
            "replacement",
        )

    def test_persisted_payload_round_trips_to_real_finalityvote(self):
        # Defensive check: a row written by add_vote round-trips
        # through FinalityVote.from_bytes cleanly -- because
        # rehydrate_from_chaindb relies on this.
        db = self._fresh_db()
        fc = FinalityCheckpoints(chaindb=db)
        signer = b"V" * 32
        vote = _make_vote(
            signer, b"H" * 32, 100, signed_at_height=99,
        )
        fc.add_vote(vote, signer_stake=10, total_stake_at_target=30)
        rows = db.get_all_finality_votes_seen()
        self.assertEqual(len(rows), 1)
        _, _, _, payload, _ = rows[0]
        rehydrated = FinalityVote.from_bytes(payload)
        self.assertEqual(rehydrated.signer_entity_id, signer)
        self.assertEqual(rehydrated.target_block_hash, b"H" * 32)
        self.assertEqual(rehydrated.target_block_number, 100)
        self.assertEqual(rehydrated.signed_at_height, 99)
        _close(db)


class TestPersistenceFailureDoesNotBreakConsensus(
    unittest.TestCase,
):
    """If chaindb writes fail (disk full, sqlite locked, etc.), the
    in-memory cache MUST still record the vote so the local gate
    works for the rest of the process lifetime.  Only across-restart
    evidence is at risk; consensus is not."""

    def test_db_write_failure_does_not_propagate(self):
        # Use a stub chaindb whose add_finality_vote_seen raises.
        class _FailingDB:
            def get_finality_vote_seen(self, *a, **k): return None

            def add_finality_vote_seen(self, *a, **k):
                raise RuntimeError("simulated disk full")

            def get_all_finality_votes_seen(self): return []

        fc = FinalityCheckpoints(chaindb=_FailingDB())
        signer = b"V" * 32
        vote = _make_vote(signer, b"H" * 32, 100)
        # Must not raise.  The vote IS recorded in the in-memory
        # cache so subsequent same-process equivocation still
        # detects.
        fc.add_vote(vote, signer_stake=10, total_stake_at_target=30)
        # Same-process equivocation detection still works:
        bad = _make_vote(signer, b"X" * 32, 100)
        fc.add_vote(bad, signer_stake=10, total_stake_at_target=30)
        self.assertEqual(len(fc.pending_slashing_evidence), 1)


if __name__ == "__main__":
    unittest.main()
