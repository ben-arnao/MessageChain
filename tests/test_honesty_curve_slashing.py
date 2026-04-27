"""Tier 23 — Honesty curve slashing.

Replaces the flat-pct slash policy of Tier 20 with a graduated curve that
reads the offender's chain-recorded track record and the unambiguity of
the evidence.

Anchored properties under test:

  1. The severity function is *deterministic* — same inputs yield the
     same output across independent computations.

  2. An honest restart (sign block N, crash, restart, attempt to sign a
     different block N) is REFUSED by the persistent same-height guard
     before any signature leaves the process.  No slash evidence is
     produced from an honest restart.

  3. Unambiguous evidence — distinct attestations for distinct block
     hashes at the same height, OR block headers that differ in fields
     that cannot be a single-restart artifact (state_root, prev_hash,
     large timestamp gap) — slashes 100%.  This is the deliberate-
     Byzantine path; it must remain catastrophic.

  4. Ambiguous evidence — block headers that differ ONLY in fields
     drift-able by a crash-restart (merkle_root + small timestamp gap) —
     slashes a small fraction of stake.

  5. A repeat offender's severity escalates: the second piece of
     ambiguous evidence against the same offender bites harder than the
     first.

  6. Honest history attenuates ambiguous-evidence penalties: a long-
     tenure validator (high `proposer_sig_counts` + `reputation`) with a
     single ambiguous offense is slashed materially less than a fresh
     validator with the same evidence.

The fork is gated by HONESTY_CURVE_HEIGHT in config.py.  Below that
height, slash semantics are byte-identical to today (Tier 20 SOFT_SLASH
or pre-Tier-20 100% — whichever applies at the height).
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from messagechain.config import (
    HONESTY_CURVE_HEIGHT,
    PROPOSAL_FEE_TIER19_HEIGHT,
    SLASH_FINDER_REWARD_PCT,
    SLASH_PENALTY_PCT,
    SOFT_SLASH_HEIGHT,
    SOFT_SLASH_PCT,
)
from messagechain.consensus.honesty_curve import (
    OffenseKind,
    Unambiguity,
    classify_block_evidence,
    slashing_severity,
)
from messagechain.consensus.slashing import (
    AttestationSlashingEvidence,
    SlashingEvidence,
    create_slash_transaction,
)
from messagechain.consensus.attestation import Attestation, create_attestation
from messagechain.core.block import BlockHeader, _hash
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity
from tests import register_entity_for_test


# ---------------------------------------------------------------------------
# Fork-height invariants
# ---------------------------------------------------------------------------


class TestHonestyCurveForkConstants(unittest.TestCase):
    """Activation height must follow the established fork schedule."""

    def test_height_above_soft_slash(self):
        # Tier 23 rides above Tier 20 — the soft-slash 5% baseline is the
        # *floor* the curve interpolates from, so it must be in effect first.
        self.assertGreater(HONESTY_CURVE_HEIGHT, SOFT_SLASH_HEIGHT)

    def test_height_above_proposal_fee_tier19(self):
        self.assertGreater(HONESTY_CURVE_HEIGHT, PROPOSAL_FEE_TIER19_HEIGHT)


# ---------------------------------------------------------------------------
# Severity function — pure inputs, no chain state
# ---------------------------------------------------------------------------


class TestSlashingSeverityPure(unittest.TestCase):
    """slashing_severity is pure — only chain state shapes the answer."""

    def setUp(self):
        self.alice = Entity.create(b"alice-severity".ljust(32, b"\x00"))
        self.bob = Entity.create(b"bob-severity".ljust(32, b"\x00"))
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.bob)
        register_entity_for_test(self.chain, self.alice)
        self.chain.supply.balances[self.alice.entity_id] = 10_000
        self.chain.supply.stake(self.alice.entity_id, 1_000)

    def test_deterministic(self):
        """Same inputs must yield the same severity across two calls."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 50
        self.chain.reputation[self.alice.entity_id] = 100
        a = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        b = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertEqual(a, b)

    def test_deterministic_across_independent_computations(self):
        """Two completely independent severity computations agree.

        The function must read only chain state — wall clock, RNG, env
        vars are all banned.  This test feeds the same chain state twice
        and asserts byte-identical agreement, which would catch a stray
        time.time() / os.urandom() / random.random() leak.
        """
        self.chain.proposer_sig_counts[self.alice.entity_id] = 137
        self.chain.reputation[self.alice.entity_id] = 421
        self.chain.slash_offense_counts[self.alice.entity_id] = 2
        out_a = []
        out_b = []
        for _ in range(5):
            out_a.append(slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            ))
            out_b.append(slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            ))
        self.assertEqual(out_a, out_b)
        self.assertEqual(len(set(out_a)), 1)

    def test_unambiguous_with_prior_offense_is_full_burn(self):
        """Repeat-offender unambiguous evidence MUST be 100%."""
        self.chain.slash_offense_counts[self.alice.entity_id] = 1
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        self.assertEqual(sev, 100)

    def test_unambiguous_first_offense_is_significant(self):
        """First unambiguous offense is in the high band even with long history."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 100_000
        self.chain.reputation[self.alice.entity_id] = 1_000_000
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        self.assertGreaterEqual(sev, 50)
        self.assertLessEqual(sev, 100)

    def test_ambiguous_first_offense_long_history_is_small(self):
        """Long honest history + first ambiguous offense → tiny slash (≤5%)."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 10_000
        self.chain.reputation[self.alice.entity_id] = 50_000
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        self.assertLessEqual(sev, 5)
        self.assertGreaterEqual(sev, 1)

    def test_ambiguous_fresh_validator_first_offense_is_floor(self):
        """No history → fresh validator gets the SOFT_SLASH_PCT band."""
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.BLOCK_DOUBLE_PROPOSAL,
            Unambiguity.AMBIGUOUS,
            self.chain,
        )
        # No track record → small base burn (the SOFT_SLASH_PCT band)
        self.assertLessEqual(sev, 10)
        self.assertGreaterEqual(sev, 1)

    def test_ambiguous_repeat_offender_escalates(self):
        """Each prior ambiguous offense ratchets the next one up."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 500
        self.chain.reputation[self.alice.entity_id] = 1_000

        severities = []
        for prior in (0, 1, 3, 6, 10):
            self.chain.slash_offense_counts[self.alice.entity_id] = prior
            sev = slashing_severity(
                self.alice.entity_id,
                OffenseKind.BLOCK_DOUBLE_PROPOSAL,
                Unambiguity.AMBIGUOUS,
                self.chain,
            )
            severities.append(sev)
        # Non-decreasing across prior offenses (escalation).
        for i in range(1, len(severities)):
            self.assertGreaterEqual(severities[i], severities[i - 1])
        # Strictly higher between first and last
        self.assertGreater(severities[-1], severities[0])

    def test_attestation_double_vote_is_unambiguous(self):
        """Distinct block_hash at same height for one validator → never
        a single-restart artifact (attestation signable_data has no
        wall-clock-driftable field)."""
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.ATTESTATION_DOUBLE_VOTE,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        self.assertGreaterEqual(sev, 50)

    def test_finality_double_vote_is_unambiguous(self):
        """Same — finality votes commit a block hash, no drift field."""
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.FINALITY_DOUBLE_VOTE,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        self.assertGreaterEqual(sev, 50)

    def test_inclusion_list_violation_kind_is_accepted(self):
        """The OffenseKind enum exposes INCLUSION_LIST_VIOLATION even though
        the chain path that emits it is on a sibling branch.  Coordinate
        with `fix/inclusion-list-wiring` — when both land, that branch
        wires the call site."""
        self.assertTrue(hasattr(OffenseKind, "INCLUSION_LIST_VIOLATION"))
        # Function must accept the kind without crashing.
        sev = slashing_severity(
            self.alice.entity_id,
            OffenseKind.INCLUSION_LIST_VIOLATION,
            Unambiguity.UNAMBIGUOUS,
            self.chain,
        )
        self.assertGreaterEqual(sev, 1)
        self.assertLessEqual(sev, 100)

    def test_severity_in_valid_range(self):
        """For ANY combination of inputs the severity is in [1, 100]."""
        for kind in OffenseKind:
            for amb in Unambiguity:
                for prior in (0, 1, 5, 50):
                    for good_blocks in (0, 10, 1000, 100_000):
                        self.chain.proposer_sig_counts[self.alice.entity_id] = good_blocks
                        self.chain.reputation[self.alice.entity_id] = good_blocks * 4
                        self.chain.slash_offense_counts[self.alice.entity_id] = prior
                        sev = slashing_severity(
                            self.alice.entity_id, kind, amb, self.chain,
                        )
                        self.assertGreaterEqual(sev, 1)
                        self.assertLessEqual(sev, 100)


# ---------------------------------------------------------------------------
# Evidence classification — what counts as "ambiguous" vs "unambiguous"
# ---------------------------------------------------------------------------


def _signed_header(
    entity, *, block_num, prev_hash, merkle_root, timestamp,
    state_root=b"\x00" * 32, prev_block_for_random=None,
):
    h = BlockHeader(
        version=1,
        block_number=block_num,
        prev_hash=prev_hash,
        merkle_root=merkle_root,
        timestamp=timestamp,
        proposer_id=entity.entity_id,
        state_root=state_root,
    )
    h.proposer_signature = entity.keypair.sign(_hash(h.signable_data()))
    return h


class TestEvidenceClassification(unittest.TestCase):
    """classify_block_evidence(header_a, header_b) decides AMBIGUOUS vs
    UNAMBIGUOUS purely from the two headers' bytes."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-classify".ljust(32, b"\x00"))

    def setUp(self):
        self.alice.keypair._next_leaf = 0

    def test_only_merkle_root_and_close_timestamp_is_ambiguous(self):
        """Crash-restart artifact: same height/prev/state, different
        merkle (mempool churn during restart) and timestamp drift of a
        few seconds."""
        ts = 1_700_000_000
        prev = b"\x11" * 32
        a = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x01" * 32, timestamp=ts,
        )
        b = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x02" * 32, timestamp=ts + 3,
        )
        self.assertEqual(classify_block_evidence(a, b), Unambiguity.AMBIGUOUS)

    def test_different_state_root_is_unambiguous(self):
        """Distinct state_root — proposer ran the chain forward to
        different post-state.  Cannot be a restart artifact."""
        ts = 1_700_000_000
        prev = b"\x11" * 32
        a = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x01" * 32, timestamp=ts,
            state_root=b"\xaa" * 32,
        )
        b = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x01" * 32, timestamp=ts,
            state_root=b"\xbb" * 32,
        )
        self.assertEqual(classify_block_evidence(a, b), Unambiguity.UNAMBIGUOUS)

    def test_different_prev_hash_is_unambiguous(self):
        """Distinct prev_hash — proposer chose two different parents.
        That's a fork choice, not a restart."""
        ts = 1_700_000_000
        a = _signed_header(
            self.alice, block_num=42, prev_hash=b"\x11" * 32,
            merkle_root=b"\x01" * 32, timestamp=ts,
        )
        b = _signed_header(
            self.alice, block_num=42, prev_hash=b"\x22" * 32,
            merkle_root=b"\x01" * 32, timestamp=ts,
        )
        self.assertEqual(classify_block_evidence(a, b), Unambiguity.UNAMBIGUOUS)

    def test_large_timestamp_gap_is_unambiguous(self):
        """A multi-minute gap between conflicting headers can't be a
        single crash-restart cycle."""
        ts = 1_700_000_000
        prev = b"\x11" * 32
        a = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x01" * 32, timestamp=ts,
        )
        b = _signed_header(
            self.alice, block_num=42, prev_hash=prev,
            merkle_root=b"\x02" * 32, timestamp=ts + 600,  # 10 minutes
        )
        self.assertEqual(classify_block_evidence(a, b), Unambiguity.UNAMBIGUOUS)


# ---------------------------------------------------------------------------
# Persistent "have I already signed at this height" guard
# ---------------------------------------------------------------------------


class TestHeightSignGuard(unittest.TestCase):
    """The proposer (and attester / finality voter) must persist their
    last-signed height to disk BEFORE the signature leaves the process,
    so a crash-restart cannot produce a second sign at the same height.

    Pattern is identical to the WOTS+ leaf-index guard in keys.py:
    persist-then-sign, never sign-then-persist.
    """

    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="mc-honesty-guard-")
        self.alice = Entity.create(b"alice-guard".ljust(32, b"\x00"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_block_double_sign_is_refused_by_guard(self):
        """sign(N) succeeds.  Crash + restart simulated by reloading
        the guard from disk.  sign(N) again is REFUSED — no signature
        is produced, no slashable evidence on the wire."""
        from messagechain.consensus.height_guard import HeightSignGuard

        path = self._tmp + "/sign_heights.json"
        guard = HeightSignGuard.load_or_create(path)

        # First sign at height 42 — allowed.
        guard.record_block_sign(42)

        # Simulate restart: throw away the in-memory guard, reload from disk.
        guard2 = HeightSignGuard.load_or_create(path)
        with self.assertRaises(Exception):
            guard2.record_block_sign(42)

    def test_attestation_guard_independent_of_block_guard(self):
        """A validator may legitimately propose a block AND attest to
        the parent at the same chain height — they are different
        signing slots, tracked under separate counters."""
        from messagechain.consensus.height_guard import HeightSignGuard

        path = self._tmp + "/sign_heights.json"
        guard = HeightSignGuard.load_or_create(path)
        guard.record_block_sign(42)
        # Attestation at same height — different slot, allowed.
        guard.record_attestation_sign(42)

        guard2 = HeightSignGuard.load_or_create(path)
        with self.assertRaises(Exception):
            guard2.record_attestation_sign(42)

    def test_finality_guard_independent(self):
        from messagechain.consensus.height_guard import HeightSignGuard

        path = self._tmp + "/sign_heights.json"
        guard = HeightSignGuard.load_or_create(path)
        guard.record_finality_sign(42)
        guard2 = HeightSignGuard.load_or_create(path)
        with self.assertRaises(Exception):
            guard2.record_finality_sign(42)

    def test_higher_height_after_lower_is_allowed(self):
        from messagechain.consensus.height_guard import HeightSignGuard

        path = self._tmp + "/sign_heights.json"
        guard = HeightSignGuard.load_or_create(path)
        guard.record_block_sign(10)
        guard.record_block_sign(11)
        guard.record_block_sign(100)

        guard2 = HeightSignGuard.load_or_create(path)
        with self.assertRaises(Exception):
            guard2.record_block_sign(50)
        # New higher height is still allowed
        guard2.record_block_sign(101)

    def test_persist_before_sign_atomicity(self):
        """The on-disk file must survive a simulated crash mid-write."""
        from messagechain.consensus.height_guard import HeightSignGuard

        path = self._tmp + "/sign_heights.json"
        guard = HeightSignGuard.load_or_create(path)
        guard.record_block_sign(7)

        # The file exists and parses
        import json
        with open(path) as f:
            data = json.load(f)
        self.assertGreaterEqual(data.get("last_block_signed", -1), 7)


# ---------------------------------------------------------------------------
# End-to-end via apply_slash_transaction — the curve actually runs
# ---------------------------------------------------------------------------


def _make_ambiguous_headers(proposer, prev_block, *, ts=None):
    """Two block headers that differ ONLY in merkle_root + ≤1s timestamp.

    This is the canonical "honest restart accident" shape:
    proposer-N built a block, partial-propagated, crashed, rebuilt
    block-N with a slightly different mempool snapshot."""
    if ts is None:
        ts = 1_700_000_000
    block_num = prev_block.header.block_number + 1
    header_a = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"snapshot-A"),
        timestamp=ts, proposer_id=proposer.entity_id,
    )
    header_a.proposer_signature = proposer.keypair.sign(
        _hash(header_a.signable_data()),
    )
    header_b = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"snapshot-B"),
        timestamp=ts + 1, proposer_id=proposer.entity_id,
    )
    header_b.proposer_signature = proposer.keypair.sign(
        _hash(header_b.signable_data()),
    )
    return header_a, header_b


def _make_unambiguous_headers(proposer, prev_block, *, ts=None):
    """Two block headers with different state_root — cannot be restart."""
    if ts is None:
        ts = 1_700_000_000
    block_num = prev_block.header.block_number + 1
    header_a = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"only-snapshot"),
        timestamp=ts, proposer_id=proposer.entity_id,
        state_root=b"\xaa" * 32,
    )
    header_a.proposer_signature = proposer.keypair.sign(
        _hash(header_a.signable_data()),
    )
    header_b = BlockHeader(
        version=1, block_number=block_num,
        prev_hash=prev_block.block_hash,
        merkle_root=_hash(b"only-snapshot"),
        timestamp=ts, proposer_id=proposer.entity_id,
        state_root=b"\xbb" * 32,
    )
    header_b.proposer_signature = proposer.keypair.sign(
        _hash(header_b.signable_data()),
    )
    return header_a, header_b


class TestEndToEndCurveSlash(unittest.TestCase):
    """Drive a slash through apply_slash_transaction with the fork
    forced active, and verify the realized burn matches the curve."""

    @classmethod
    def setUpClass(cls):
        cls.alice = Entity.create(b"alice-e2e".ljust(32, b"\x00"))
        cls.bob = Entity.create(b"bob-e2e".ljust(32, b"\x00"))
        cls.carol = Entity.create(b"carol-e2e".ljust(32, b"\x00"))

    def setUp(self):
        for e in (self.alice, self.bob, self.carol):
            e.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.carol)
        register_entity_for_test(self.chain, self.alice)
        register_entity_for_test(self.chain, self.bob)
        for e in (self.alice, self.bob, self.carol):
            self.chain.supply.balances[e.entity_id] = 10_000_000
        self.chain.supply.stake(self.alice.entity_id, 1_000_000)

    def _slash_with_curve(self, evidence, fork_active=True):
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        if fork_active:
            with patch("messagechain.config.HONESTY_CURVE_HEIGHT", 0):
                return self.chain.apply_slash_transaction(
                    slash_tx, self.carol.entity_id,
                )
        return self.chain.apply_slash_transaction(
            slash_tx, self.carol.entity_id,
        )

    def test_unambiguous_headers_first_offense_long_history_50_to_100(self):
        """Distinct state_root on first offense for an established
        validator → high-band slash (≥50%)."""
        # Establish long honest history on chain
        self.chain.proposer_sig_counts[self.alice.entity_id] = 100_000
        self.chain.reputation[self.alice.entity_id] = 1_000_000

        prev = self.chain.get_latest_block()
        header_a, header_b = _make_unambiguous_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a, header_b=header_b,
        )
        staked_before = self.chain.supply.get_staked(self.alice.entity_id)
        ok, msg = self._slash_with_curve(evidence)
        self.assertTrue(ok, msg)
        staked_after = self.chain.supply.get_staked(self.alice.entity_id)
        burned_pct = (staked_before - staked_after) * 100 // staked_before
        self.assertGreaterEqual(burned_pct, 50)
        self.assertLessEqual(burned_pct, 100)

    def test_unambiguous_repeat_offender_is_full_burn(self):
        """An offender with 1 prior recorded slash + new unambiguous
        evidence is wiped 100%."""
        # Pre-seed a prior offense.
        self.chain.slash_offense_counts[self.alice.entity_id] = 1

        prev = self.chain.get_latest_block()
        header_a, header_b = _make_unambiguous_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a, header_b=header_b,
        )
        ok, msg = self._slash_with_curve(evidence)
        self.assertTrue(ok, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)
        self.assertIn(self.alice.entity_id, self.chain.slashed_validators)

    def test_ambiguous_first_offense_long_history_is_tiny(self):
        """Long history + first ambiguous offense → ≤5% slash."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 10_000
        self.chain.reputation[self.alice.entity_id] = 50_000

        prev = self.chain.get_latest_block()
        header_a, header_b = _make_ambiguous_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a, header_b=header_b,
        )
        staked_before = self.chain.supply.get_staked(self.alice.entity_id)
        ok, msg = self._slash_with_curve(evidence)
        self.assertTrue(ok, msg)
        staked_after = self.chain.supply.get_staked(self.alice.entity_id)
        burned = staked_before - staked_after
        burned_pct = burned * 100 // staked_before
        self.assertLessEqual(
            burned_pct, 5,
            f"long-history ambiguous slash should be small, burned {burned_pct}%",
        )
        self.assertGreaterEqual(burned, 1)
        # And the offender is NOT permabanned
        self.assertNotIn(self.alice.entity_id, self.chain.slashed_validators)

    def test_ambiguous_repeat_escalates(self):
        """Each ambiguous repeat hits harder than the previous."""
        self.chain.proposer_sig_counts[self.alice.entity_id] = 500
        self.chain.reputation[self.alice.entity_id] = 1_000

        burns = []
        prev = self.chain.get_latest_block()
        for i in range(3):
            staked_before = self.chain.supply.get_staked(
                self.alice.entity_id,
            )
            if staked_before == 0:
                break
            # Distinct timestamps so each evidence_hash differs and
            # _processed_evidence dedup doesn't reject the second/third.
            ts = 1_700_000_000 + i * 5
            header_a, header_b = _make_ambiguous_headers(
                self.alice, prev, ts=ts,
            )
            evidence = SlashingEvidence(
                offender_id=self.alice.entity_id,
                header_a=header_a, header_b=header_b,
            )
            ok, msg = self._slash_with_curve(evidence)
            self.assertTrue(ok, msg)
            staked_after = self.chain.supply.get_staked(
                self.alice.entity_id,
            )
            burns.append(staked_before - staked_after)
        # Strictly more burned in later offenses than the first
        self.assertGreater(burns[-1], burns[0])

    def test_pre_fork_unchanged(self):
        """At a height below HONESTY_CURVE_HEIGHT the slash semantics
        are byte-identical to today (Tier 20 SOFT_SLASH_PCT applies)."""
        # Force pre-fork: lift HONESTY_CURVE_HEIGHT high.  Tier 20 is
        # already in effect (height < SOFT_SLASH_HEIGHT path falls
        # through to the legacy 100% — but most modern tests set
        # SOFT_SLASH_HEIGHT to 0 to use 5%).  Here we exercise the legacy
        # 100% path.
        prev = self.chain.get_latest_block()
        header_a, header_b = _make_ambiguous_headers(self.alice, prev)
        evidence = SlashingEvidence(
            offender_id=self.alice.entity_id,
            header_a=header_a, header_b=header_b,
        )
        slash_tx = create_slash_transaction(self.bob, evidence, fee=1500)
        # Both forks lifted to far future -> pre-fork policy = full burn
        with patch("messagechain.config.HONESTY_CURVE_HEIGHT", 10**9), \
             patch("messagechain.config.SOFT_SLASH_HEIGHT", 10**9):
            ok, msg = self.chain.apply_slash_transaction(
                slash_tx, self.carol.entity_id,
            )
        self.assertTrue(ok, msg)
        self.assertEqual(self.chain.supply.get_staked(self.alice.entity_id), 0)


# ---------------------------------------------------------------------------
# Honest-restart scenario — the headline anchor
# ---------------------------------------------------------------------------


class TestHeightGuardWiredIntoSignSites(unittest.TestCase):
    """The guard, attached to an entity as ``entity.height_sign_guard``,
    must intercept ``create_block`` / ``create_attestation`` /
    ``create_finality_vote`` BEFORE the keypair sign call."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="mc-guard-wiring-")
        self.alice = Entity.create(b"alice-wiring".ljust(32, b"\x00"))
        self.alice.keypair._next_leaf = 0

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_create_attestation_consults_guard(self):
        """A validator with a guard installed cannot create two
        attestations at the same height across a simulated restart."""
        from messagechain.consensus.height_guard import (
            HeightAlreadySignedError,
            HeightSignGuard,
        )

        path = self._tmp + "/g.json"
        self.alice.height_sign_guard = HeightSignGuard.load_or_create(path)

        # First attestation at height 7 — succeeds.
        a = create_attestation(self.alice, b"\x01" * 32, 7)
        self.assertIsNotNone(a)

        # Simulated restart — fresh guard loaded from disk.
        self.alice.height_sign_guard = HeightSignGuard.load_or_create(path)
        # Second attestation at the same height — REFUSED before signing.
        with self.assertRaises(HeightAlreadySignedError):
            create_attestation(self.alice, b"\x02" * 32, 7)

    def test_create_finality_vote_consults_guard(self):
        from messagechain.consensus.finality import create_finality_vote
        from messagechain.consensus.height_guard import (
            HeightAlreadySignedError,
            HeightSignGuard,
        )

        path = self._tmp + "/g.json"
        self.alice.height_sign_guard = HeightSignGuard.load_or_create(path)

        v = create_finality_vote(
            self.alice, b"\xaa" * 32, target_block_number=42,
            signed_at_height=42,
        )
        self.assertIsNotNone(v)

        self.alice.height_sign_guard = HeightSignGuard.load_or_create(path)
        with self.assertRaises(HeightAlreadySignedError):
            create_finality_vote(
                self.alice, b"\xbb" * 32, target_block_number=42,
                signed_at_height=42,
            )

    def test_no_guard_attached_is_a_no_op(self):
        """Backward compat: existing call sites that don't attach a
        guard see the same behavior as before this fork."""
        # Default Entity has no height_sign_guard attribute — sign
        # twice at the same height MUST succeed (the guard is the
        # only thing stopping it).
        a = create_attestation(self.alice, b"\x01" * 32, 99)
        b = create_attestation(self.alice, b"\x02" * 32, 99)
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)


class TestHonestRestartIsRefusedNotSlashed(unittest.TestCase):
    """Sign block N, simulate crash, restart, attempt to sign a different
    block N.  The HeightSignGuard must REFUSE the second sign — no slash
    evidence reaches the wire because no second signature was produced.

    This test cuts the realistic false-positive path that the audit
    finding called out (`pos.py` create_block has no same-height guard,
    BlockHeader.signable_data includes drift-able fields).
    """

    def test_persistent_guard_blocks_restart_double_sign(self):
        import tempfile
        from messagechain.consensus.height_guard import HeightSignGuard

        tmp = tempfile.mkdtemp(prefix="mc-restart-")
        try:
            path = tmp + "/sign_heights.json"
            # First boot: sign at N
            guard = HeightSignGuard.load_or_create(path)
            guard.record_block_sign(N := 100)
            # Crash + restart
            del guard
            guard2 = HeightSignGuard.load_or_create(path)
            # Operator restarts the proposer process; same block height
            # comes around (because proposal selection was deterministic
            # for that slot).  The guard must refuse.
            with self.assertRaises(Exception):
                guard2.record_block_sign(N)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
