"""Tests for iteration 3c: sample strength + decay sanity +
age-skewed challenge sampling.

This iteration closes three gaps identified in the fresh-pass audit:

    1. Miss-counter decay was too kind to attackers.  A validator that
       failed 3 epochs (100% withhold) could fully recover with just
       1 successful epoch.  Replaced with a streak-based rule: a miss
       only decrements after ARCHIVE_MISS_DECAY_STREAK consecutive
       successful epochs, so operators who cycle between pruning and
       serving cannot cheaply wash out their reputation.

    2. Challenge count per epoch (K) bumped from 3 to 5.  Weak-point
       evasion probability at p=0.5 drops from ~12% to ~3%.

    3. compute_challenges now produces age-skewed heights — half the
       K challenges sample uniformly across all history, half sample
       from the oldest ARCHIVE_AGE_SKEW_FRACTION of history.  Prevents
       a validator from passing by retaining only recent blocks.

Scope:
    * New state field: validator_archive_success_streak (bytes→int).
    * New config: ARCHIVE_MISS_DECAY_STREAK = 3,
                  ARCHIVE_AGE_SKEW_FRACTION = 0.1,
                  ARCHIVE_CHALLENGE_K bumps to 5.
    * State snapshot v7 → v8 (streak counter persisted).
"""

from __future__ import annotations

import hashlib
import unittest

from messagechain.config import (
    ARCHIVE_AGE_SKEW_FRACTION,
    ARCHIVE_CHALLENGE_K,
    ARCHIVE_MISS_DECAY_STREAK,
    HASH_ALGO,
)
from messagechain.consensus.archive_challenge import (
    ArchiveProofBundle,
    build_custody_proof,
    compute_challenges,
)
from messagechain.consensus.archive_duty import (
    ActiveValidatorSnapshot,
    compute_miss_updates,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _eid(byte: int) -> bytes:
    return bytes([byte]) * 32


def _mini_block(txs, block_number):
    import struct
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": _h(header_bytes),
    }


def _proof_for(entity_id, target_height):
    block = _mini_block(
        [f"tx-{i}".encode() * 10 for i in range(3)], target_height,
    )
    return build_custody_proof(
        prover_id=entity_id,
        target_height=target_height,
        target_block_hash=block["block_hash"],
        header_bytes=block["header_bytes"],
        merkle_root=block["merkle_root"],
        tx_index=0,
        tx_bytes=block["tx_bytes_list"][0],
        all_tx_hashes=block["tx_hashes"],
    )


# ---------------------------------------------------------------------------
# 1. K bumped to 5
# ---------------------------------------------------------------------------


class TestKBump(unittest.TestCase):
    def test_archive_challenge_k_is_5(self):
        """K is bumped from 3 to 5 in this iteration — evasion math at
        p=0.5 drops from 12% to 3%."""
        self.assertEqual(ARCHIVE_CHALLENGE_K, 5)

    def test_compute_challenges_default_returns_5(self):
        """Default-K compute_challenges yields 5 deterministic
        challenges."""
        challenges = compute_challenges(_h(b"block-x"), 10_000)
        self.assertEqual(len(challenges), 5)


# ---------------------------------------------------------------------------
# 2. Age-skewed sampling
# ---------------------------------------------------------------------------


class TestAgeSkewedSampling(unittest.TestCase):
    def test_second_half_of_challenges_lands_in_oldest_fraction(self):
        """With K=5 and B large enough, challenges at indices
        (K+1)//2 .. K-1 must target the oldest
        ARCHIVE_AGE_SKEW_FRACTION of history.  A pruner keeping only
        the newest (1 - fraction) slice fails these challenges
        deterministically.
        """
        B = 10_000
        age_cutoff = int(B * ARCHIVE_AGE_SKEW_FRACTION)
        k = 5
        uniform_count = (k + 1) // 2  # 3 uniform, 2 age-skewed
        # Sample across many block hashes to avoid cherry-pick; the
        # skewed half should ALWAYS land in [0, age_cutoff).
        for i in range(30):
            block_hash = _h(f"block-{i}".encode())
            challenges = compute_challenges(block_hash, B, k=k)
            for j in range(uniform_count, len(challenges)):
                self.assertLess(
                    challenges[j].target_height, age_cutoff,
                    f"challenge {j} (block_hash[:8]={block_hash[:8].hex()}) "
                    f"landed at height {challenges[j].target_height}, "
                    f"expected < {age_cutoff}",
                )

    def test_first_half_samples_across_all_history(self):
        """Uniformly-sampled challenges (first half of K) should spread
        across the whole chain, not cluster in any one tenth.  Loose
        sanity check — not uniformity-grade, just coverage.
        """
        B = 10_000
        k = 5
        uniform_count = (k + 1) // 2
        uniform_heights: set[int] = set()
        for i in range(200):
            block_hash = _h(f"cover-{i}".encode())
            challenges = compute_challenges(block_hash, B, k=k)
            for j in range(uniform_count):
                uniform_heights.add(challenges[j].target_height)
        # With 200×(K//2)=400 samples spread uniformly over [0, B), we
        # expect tails populated.  Specifically require samples in the
        # NEWER half that age-skew never reaches, so this test actually
        # distinguishes from an all-age-skewed regression.
        age_cutoff = int(B * ARCHIVE_AGE_SKEW_FRACTION)
        newer_half_hits = {
            h for h in uniform_heights if h >= B // 2
        }
        self.assertGreater(
            len(newer_half_hits), 10,
            "uniform-sampled half must reach the newer chain too",
        )
        # And confirm the uniform half is not accidentally confined to
        # the age-skew range — that would indicate both halves skew old.
        only_old = all(h < age_cutoff for h in uniform_heights)
        self.assertFalse(
            only_old, "uniform half must not be age-skewed"
        )

    def test_age_skew_degrades_gracefully_on_small_B(self):
        """When B is too small for a meaningful 10% slice (B < 10),
        age-skewed challenges fall back to full-range sampling rather
        than raising or looping forever.  This is the bootstrap-era
        case (chain has very few blocks).
        """
        # B=5 means fraction 0.1 × 5 = 0.5, which floors to 0 — need to
        # widen to at least 1 so mod is valid.
        challenges = compute_challenges(_h(b"small"), 5, k=5)
        self.assertEqual(len(challenges), 5)
        for c in challenges:
            self.assertGreaterEqual(c.target_height, 0)
            self.assertLess(c.target_height, 5)


# ---------------------------------------------------------------------------
# 3. Streak-based decay
# ---------------------------------------------------------------------------


class TestStreakDecay(unittest.TestCase):
    def setUp(self):
        self.v = _eid(1)
        self.snap = ActiveValidatorSnapshot(
            challenge_block=100,
            active_set=frozenset([self.v]),
            challenge_heights=(10, 20, 30, 40, 50),
        )
        # Age past bootstrap grace (default 1000 blocks) so duty
        # actually applies at current_block=150.
        self.first_active = {self.v: -1_000_000}

    def _bundle_covering_all(self):
        proofs = [
            _proof_for(self.v, h) for h in self.snap.challenge_heights
        ]
        return [ArchiveProofBundle.from_proofs(proofs)]

    def _empty_bundle(self):
        return [ArchiveProofBundle.from_proofs([])]

    def test_one_success_does_not_decrement_from_nonzero_miss(self):
        """A validator with miss=3 who submits once gets no decrement.
        Decay only fires after ARCHIVE_MISS_DECAY_STREAK consecutive
        successes.
        """
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._bundle_covering_all(),
            current_misses={self.v: 3},
            current_streaks={},
            current_block=150,
            validator_first_active_block=self.first_active,
        )
        # Miss count unchanged after just one success.
        self.assertEqual(new_misses.get(self.v, 0), 3)
        # Streak starts accumulating.
        self.assertEqual(new_streaks.get(self.v, 0), 1)

    def test_decay_fires_after_streak_threshold(self):
        """After ARCHIVE_MISS_DECAY_STREAK successful epochs in a row,
        miss counter decrements by 1 and streak resets to 0.
        """
        # Simulate being at streak = ARCHIVE_MISS_DECAY_STREAK - 1; next
        # successful epoch is the decay trigger.
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._bundle_covering_all(),
            current_misses={self.v: 3},
            current_streaks={self.v: ARCHIVE_MISS_DECAY_STREAK - 1},
            current_block=150,
            validator_first_active_block=self.first_active,
        )
        self.assertEqual(new_misses[self.v], 2)
        # Streak reset to 0 on decay.
        self.assertEqual(new_streaks.get(self.v, 0), 0)

    def test_any_miss_resets_streak(self):
        """A single miss breaks the consecutive streak — even if the
        validator was one success away from a decay trigger.
        """
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._empty_bundle(),  # miss
            current_misses={self.v: 1},
            current_streaks={self.v: ARCHIVE_MISS_DECAY_STREAK - 1},
            current_block=150,
            validator_first_active_block=self.first_active,
        )
        # Miss incremented, streak reset.
        self.assertEqual(new_misses[self.v], 2)
        self.assertEqual(new_streaks.get(self.v, 0), 0)

    def test_streak_caps_or_continues_harmlessly(self):
        """Once miss hits 0 via decay, further successful epochs should
        not push the counter negative, and streak behavior past that
        point is an implementation detail (may continue accumulating
        or reset — either is fine, as long as miss stays at 0).
        """
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._bundle_covering_all(),
            current_misses={},
            current_streaks={self.v: 50},  # arbitrarily large
            current_block=150,
            validator_first_active_block=self.first_active,
        )
        # miss stays at 0 (no key means 0 under state-lean invariant).
        self.assertEqual(new_misses.get(self.v, 0), 0)

    def test_bootstrap_exempt_passes_through_streak_too(self):
        """Grace-exempt validators' streak state passes through
        unchanged — they haven't completed an eligible epoch, so the
        streak can't accumulate.
        """
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._bundle_covering_all(),
            current_misses={self.v: 0},
            current_streaks={self.v: 2},
            current_block=150,
            # Grace: very recent first-active.
            validator_first_active_block={self.v: 149},
        )
        # Streak must be preserved unchanged.
        self.assertEqual(new_streaks.get(self.v, 0), 2)

    def test_streak_zero_entries_omitted_from_returned_dict(self):
        """State-lean invariant for streaks: value 0 is not stored."""
        new_misses, new_streaks = compute_miss_updates(
            snapshot=self.snap,
            bundles_in_window=self._empty_bundle(),
            current_misses={},
            current_streaks={self.v: 2},
            current_block=150,
            validator_first_active_block=self.first_active,
        )
        # Streak reset to 0 by the miss — must not be stored.
        self.assertNotIn(self.v, new_streaks)


# ---------------------------------------------------------------------------
# 4. State snapshot v8 persists streak counter
# ---------------------------------------------------------------------------


class TestStreakPersistence(unittest.TestCase):
    def test_streak_roundtrips_through_snapshot(self):
        from messagechain.storage.state_snapshot import (
            STATE_SNAPSHOT_VERSION,
            compute_state_root,
            decode_snapshot,
            encode_snapshot,
        )
        self.assertGreaterEqual(STATE_SNAPSHOT_VERSION, 8)
        streaks = {_eid(1): 2, _eid(2): 1}
        snap = _minimal_snap(validator_archive_success_streak=streaks)
        blob = encode_snapshot(snap)
        decoded = decode_snapshot(blob)
        self.assertEqual(decoded["validator_archive_success_streak"], streaks)

    def test_streak_affects_state_root(self):
        """Two otherwise-identical snapshots differing only in streak
        values must produce different state roots — else a grinder
        could silently manipulate one validator's decay timing."""
        from messagechain.storage.state_snapshot import compute_state_root
        base = _minimal_snap()
        alt = _minimal_snap(
            validator_archive_success_streak={_eid(1): 2},
        )
        self.assertNotEqual(compute_state_root(base), compute_state_root(alt))


def _minimal_snap(**overrides) -> dict:
    from messagechain.storage.state_snapshot import STATE_SNAPSHOT_VERSION
    snap = {
        "version": STATE_SNAPSHOT_VERSION,
        "balances": {}, "nonces": {}, "staked": {},
        "public_keys": {}, "authority_keys": {},
        "leaf_watermarks": {}, "key_rotation_counts": {},
        "revoked_entities": set(), "slashed_validators": set(),
        "entity_id_to_index": {}, "next_entity_index": 1,
        "total_supply": 1000, "total_minted": 0,
        "total_fees_collected": 0, "total_burned": 0,
        "base_fee": 100, "finalized_checkpoints": {},
        "seed_initial_stakes": {}, "seed_divestment_debt": {},
        "archive_reward_pool": 0,
        "censorship_pending": {}, "censorship_processed": set(),
        "receipt_subtree_roots": {},
        "bogus_rejection_processed": set(),
        "inclusion_list_active": {},
        "inclusion_list_processed_violations": set(),
        "validator_archive_misses": {},
        "validator_first_active_block": {},
        "archive_active_snapshot": None,
        "validator_archive_success_streak": {},
    }
    snap.update(overrides)
    return snap


if __name__ == "__main__":
    unittest.main()
