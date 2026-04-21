"""Tests for archive-duty primitives.

Iteration 3b-i of the validator-duty archive-reward redesign.  Pure
primitives — no block-state wiring, no reward-path integration.  The
primitives are deterministic functions over in-memory data structures
so the state machine that consumes them (iteration 3b-ii) can be
wired against known-good behavior.

Primitives covered:
    * ActiveValidatorSnapshot: frozen active-set at a challenge block.
    * compute_miss_updates(): given snapshot + bundles-in-window + K
      challenge heights + current duty state, return the new miss
      counts.
    * withhold_pct(miss_count): graduated reward-withhold tier.
    * is_bootstrap_exempt(): true iff validator is younger than the
      bootstrap grace window.

Design contract:
    * Miss increments by 1 when validator was active but did not
      submit all K proofs (all-or-nothing credit).
    * Miss decrements by 1 (floor 0) on successful full submission.
    * Miss is capped at ARCHIVE_MAX_MISS_COUNT for tier selection; the
      raw counter can exceed the cap but tier clips.
    * Bootstrap grace: validator_first_active_block must be tracked
      per-validator; exemption = (current_block - first_active_block
      < ARCHIVE_BOOTSTRAP_GRACE_BLOCKS).
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from messagechain.config import (
    ARCHIVE_BOOTSTRAP_GRACE_BLOCKS,
    ARCHIVE_CHALLENGE_INTERVAL,
    ARCHIVE_MAX_MISS_COUNT,
    ARCHIVE_WITHHOLD_TIERS,
    HASH_ALGO,
)
from messagechain.consensus.archive_challenge import (
    ArchiveProofBundle,
    build_custody_proof,
)
from messagechain.consensus.archive_duty import (
    ActiveValidatorSnapshot,
    compute_miss_updates,
    is_bootstrap_exempt,
    withhold_pct,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _eid(byte: int) -> bytes:
    return bytes([byte]) * 32


def _mini_block(txs: list[bytes], block_number: int) -> dict:
    from messagechain.core.block import compute_merkle_root
    tx_hashes = [_h(t) for t in txs]
    merkle_root = compute_merkle_root(tx_hashes) if tx_hashes else _h(b"empty")
    header_bytes = struct.pack(">Q", block_number) + merkle_root
    block_hash = _h(header_bytes)
    return {
        "block_number": block_number,
        "header_bytes": header_bytes,
        "merkle_root": merkle_root,
        "tx_bytes_list": list(txs),
        "tx_hashes": tx_hashes,
        "block_hash": block_hash,
    }


def _proof_for(entity_id: bytes, target_height: int):
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


def _bundle_for(participant_heights: dict[bytes, list[int]]):
    """Convenience: build an ArchiveProofBundle covering the given
    (validator → list-of-heights) map.  Heights can be empty to mean
    "this validator didn't submit."
    """
    proofs = []
    for eid, heights in participant_heights.items():
        for h in heights:
            proofs.append(_proof_for(eid, h))
    return ArchiveProofBundle.from_proofs(proofs)


# ---------------------------------------------------------------------------
# 1. withhold_pct: graduated reward-withhold tier
# ---------------------------------------------------------------------------


class TestWithholdPct(unittest.TestCase):
    def test_zero_misses_no_withhold(self):
        """A compliant validator loses none of their reward."""
        self.assertEqual(withhold_pct(0), 0)

    def test_graduated_tiers_match_config(self):
        """Tiers read from ARCHIVE_WITHHOLD_TIERS — no hardcoding."""
        for i, expected in enumerate(ARCHIVE_WITHHOLD_TIERS):
            self.assertEqual(withhold_pct(i), expected)

    def test_miss_count_above_cap_saturates_at_100(self):
        """Once you're past the last tier you stay at 100%; no
        overflow, no negative, no wraparound.
        """
        self.assertEqual(withhold_pct(ARCHIVE_MAX_MISS_COUNT + 5), 100)
        self.assertEqual(withhold_pct(1000), 100)

    def test_negative_miss_count_rejected(self):
        """Miss counter should never go negative — if a caller tries
        to pass one in, fail loud rather than silently mapping to 0.
        """
        with self.assertRaises(ValueError):
            withhold_pct(-1)


# ---------------------------------------------------------------------------
# 2. is_bootstrap_exempt: new-validator grace window
# ---------------------------------------------------------------------------


class TestBootstrapExempt(unittest.TestCase):
    def test_brand_new_validator_exempt(self):
        """Validator that joined this block is exempt — they couldn't
        possibly have downloaded full history yet.
        """
        first_active = {_eid(1): 100}
        self.assertTrue(
            is_bootstrap_exempt(
                entity_id=_eid(1),
                current_block=100,
                validator_first_active_block=first_active,
            ),
        )

    def test_just_before_grace_expires_still_exempt(self):
        """One block shy of the grace window end = still exempt."""
        first_active = {_eid(1): 100}
        current = 100 + ARCHIVE_BOOTSTRAP_GRACE_BLOCKS - 1
        self.assertTrue(
            is_bootstrap_exempt(
                entity_id=_eid(1),
                current_block=current,
                validator_first_active_block=first_active,
            ),
        )

    def test_at_grace_expiry_no_longer_exempt(self):
        """Exactly `grace` blocks later = duty applies — the grace
        window is half-open `[first_active, first_active + grace)`.
        """
        first_active = {_eid(1): 100}
        current = 100 + ARCHIVE_BOOTSTRAP_GRACE_BLOCKS
        self.assertFalse(
            is_bootstrap_exempt(
                entity_id=_eid(1),
                current_block=current,
                validator_first_active_block=first_active,
            ),
        )

    def test_unknown_validator_treated_as_new(self):
        """A validator with no first_active entry is implicitly
        brand-new — exempt until they're registered.  Conservative
        bias: never penalize an entity the state machine doesn't
        recognize yet.
        """
        self.assertTrue(
            is_bootstrap_exempt(
                entity_id=_eid(99),
                current_block=50_000,
                validator_first_active_block={},
            ),
        )

    def test_long_tenured_validator_not_exempt(self):
        """Validators active for many epochs past the grace window
        are fully on the hook.
        """
        first_active = {_eid(1): 0}
        self.assertFalse(
            is_bootstrap_exempt(
                entity_id=_eid(1),
                current_block=1_000_000,
                validator_first_active_block=first_active,
            ),
        )


# ---------------------------------------------------------------------------
# 3. ActiveValidatorSnapshot: frozen set at challenge block
# ---------------------------------------------------------------------------


class TestActiveSnapshot(unittest.TestCase):
    def test_snapshot_carries_block_number_and_heights(self):
        """Snapshot is identified by the challenge block that spawned
        it + the K heights it challenged.  Both travel together so
        epoch-close processing has everything it needs.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([_eid(1), _eid(2)]),
            challenge_heights=(100, 200, 300),
        )
        self.assertEqual(snap.challenge_block, 1000)
        self.assertEqual(len(snap.active_set), 2)
        self.assertEqual(snap.challenge_heights, (100, 200, 300))

    def test_snapshot_is_immutable(self):
        """Once captured, the snapshot must not mutate — consensus
        nodes computing epoch-close outcomes later must see the same
        bytes they saw at capture time.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([_eid(1)]),
            challenge_heights=(100,),
        )
        # frozenset + tuple — both immutable
        self.assertIsInstance(snap.active_set, frozenset)
        self.assertIsInstance(snap.challenge_heights, tuple)


# ---------------------------------------------------------------------------
# 4. compute_miss_updates: the core state-transition function
# ---------------------------------------------------------------------------


class TestComputeMissUpdates(unittest.TestCase):
    def setUp(self):
        self.heights = (100, 200, 300)  # K=3 challenge heights
        self.v1 = _eid(1)
        self.v2 = _eid(2)
        self.v3 = _eid(3)

    def test_full_submission_all_heights_decrements_miss(self):
        """Validator submits valid proofs for ALL K heights → miss
        counter decrements (floor 0).
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        bundles = [_bundle_for({self.v1: list(self.heights)})]
        old_misses = {self.v1: 2}
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses=old_misses,
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0},
        )
        self.assertEqual(new_misses[self.v1], 1)

    def test_partial_submission_missing_one_height_increments(self):
        """Partial credit is no credit: missing one of K heights
        counts as a full miss.  This is the all-or-nothing duty.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        # Submit only 2 of 3 heights
        bundles = [_bundle_for({self.v1: [100, 200]})]
        old_misses = {self.v1: 0}
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses=old_misses,
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0},
        )
        self.assertEqual(new_misses[self.v1], 1)

    def test_no_submission_increments(self):
        """Validator in the active set who submitted nothing: miss++."""
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1, self.v2]),
            challenge_heights=self.heights,
        )
        # v1 submits, v2 doesn't.
        bundles = [_bundle_for({self.v1: list(self.heights)})]
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses={},
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0, self.v2: 0},
        )
        self.assertEqual(new_misses.get(self.v1, 0), 0)  # clean: still 0
        self.assertEqual(new_misses[self.v2], 1)

    def test_miss_decrement_floors_at_zero(self):
        """A validator at miss=0 who submits cleanly stays at 0;
        compute_miss_updates must not emit negatives.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        bundles = [_bundle_for({self.v1: list(self.heights)})]
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses={self.v1: 0},
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0},
        )
        self.assertGreaterEqual(new_misses.get(self.v1, 0), 0)
        # Canonical: entry stays at 0 (or is omitted), not negative
        self.assertIn(new_misses.get(self.v1, 0), (0,))

    def test_bootstrap_exempt_validator_never_missed(self):
        """A validator inside the bootstrap grace window never
        accrues misses, even if they submitted nothing — they haven't
        had time to sync full history yet.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        bundles = []  # no one submitted
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses={},
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 999},  # joined last block
        )
        self.assertEqual(new_misses.get(self.v1, 0), 0)

    def test_bundles_across_multiple_window_blocks_aggregated(self):
        """Submission window spans many blocks; proofs may arrive in
        any of them.  compute_miss_updates must union all bundles
        over the window before scoring.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        # v1's proofs arrive spread across three blocks in the window
        bundles = [
            _bundle_for({self.v1: [100]}),
            _bundle_for({self.v1: [200]}),
            _bundle_for({self.v1: [300]}),
        ]
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses={self.v1: 1},
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0},
        )
        # v1 covered all K heights via multiple bundles → decrement.
        # state-lean invariant: 0 entries are omitted, so use .get.
        self.assertEqual(new_misses.get(self.v1, 0), 0)

    def test_non_active_submitters_do_not_affect_misses(self):
        """A non-validator who happens to submit a proof bundle is
        fine — we don't penalize non-participants, we just don't
        reward/score them.  Duty only applies to the active set.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1]),
            challenge_heights=self.heights,
        )
        non_active = _eid(99)
        bundles = [_bundle_for({
            self.v1: list(self.heights),
            non_active: list(self.heights),
        })]
        new_misses = compute_miss_updates(
            snapshot=snap,
            bundles_in_window=bundles,
            current_misses={},
            current_block=1000 + 50,
            validator_first_active_block={self.v1: 0},
        )
        # non_active is not in the snapshot → no entry in new_misses.
        self.assertNotIn(non_active, new_misses)

    def test_deterministic_across_input_orderings(self):
        """Same inputs, different orderings of bundles_in_window or
        active_set iteration order = same output.  Consensus critical.
        """
        snap = ActiveValidatorSnapshot(
            challenge_block=1000,
            active_set=frozenset([self.v1, self.v2, self.v3]),
            challenge_heights=self.heights,
        )
        first_active = {self.v1: 0, self.v2: 0, self.v3: 0}
        bundles_a = [
            _bundle_for({self.v1: [100, 200]}),  # partial — miss
            _bundle_for({self.v2: list(self.heights)}),
            _bundle_for({self.v3: []}),
        ]
        bundles_b = list(reversed(bundles_a))

        out_a = compute_miss_updates(
            snapshot=snap, bundles_in_window=bundles_a,
            current_misses={}, current_block=1000 + 50,
            validator_first_active_block=first_active,
        )
        out_b = compute_miss_updates(
            snapshot=snap, bundles_in_window=bundles_b,
            current_misses={}, current_block=1000 + 50,
            validator_first_active_block=first_active,
        )
        self.assertEqual(out_a, out_b)


if __name__ == "__main__":
    unittest.main()
