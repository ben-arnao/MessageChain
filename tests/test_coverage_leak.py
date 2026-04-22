"""Tests for the coverage-divergence inactivity leak.

Threat model
============

Inclusion lists require >=2/3 of attester stake to have observed a tx
in the mempool for INCLUSION_LIST_WAIT_BLOCKS before a tx becomes
list-eligible.  A coordinated 1/3 minority can defeat this defense by
*selectively withholding* their `AttesterMempoolReport` for targeted
txs — the chain still finalizes (so the existing finalization-based
inactivity leak doesn't trigger) and no inclusion list ever forms for
the censored txs.

The coverage-divergence leak punishes selective withholding.  When
ANY inclusion list does form (proving 2/3+ saw the listed txs), every
active-set attester whose mempool reports lacked any listed tx — i.e.
who claims not to have seen something the supermajority did see — has
their per-attester `coverage_misses` counter incremented.  An attester
whose reports DID cover all listed txs resets to zero.

Penalties scale quadratically in `consecutive_misses` and only fire
once `consecutive_misses > COVERAGE_LEAK_ACTIVATION_MISSES` so honest
mempool divergence (a few isolated misses) never bleeds stake.
"""

from __future__ import annotations

import hashlib
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_LIST_WINDOW,
    COVERAGE_LEAK_BASE_PENALTY,
    COVERAGE_LEAK_QUOTIENT,
    COVERAGE_LEAK_ACTIVATION_MISSES,
    COVERAGE_LEAK_WINDOW_BLOCKS,
)
from messagechain.identity.identity import Entity
from messagechain.consensus.inactivity import (
    compute_coverage_penalty,
    apply_coverage_leak,
    get_coverage_misses,
)
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    aggregate_inclusion_list,
    build_attester_mempool_report,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"cov") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    return {v.entity_id: per for v in validators}


def _make_unsigned_report(
    reporter_id: bytes,
    report_height: int,
    tx_hashes: list[bytes],
) -> AttesterMempoolReport:
    """Build a fake AttesterMempoolReport without burning a one-time key.

    The coverage-leak path inspects only `reporter_id` + `tx_hashes`;
    it does NOT verify signatures (the inclusion-list quorum-verification
    pass that DOES verify lives in
    `verify_inclusion_list_quorum`, which the leak path doesn't call).
    Tests can therefore stitch together hundreds of "reports" cheaply.
    """
    from messagechain.crypto.keys import Signature
    placeholder = Signature([], 0, [], b"", b"")
    return AttesterMempoolReport(
        reporter_id=reporter_id,
        report_height=report_height,
        tx_hashes=list(tx_hashes),
        signature=placeholder,
    )


def _build_list_with_reports(
    validators: list[Entity],
    publish_height: int,
    tx_hashes: list[bytes],
    *,
    omitting: set[bytes] | None = None,
) -> InclusionList:
    """Build an inclusion list where every validator "reports" `tx_hashes`
    at height publish_height-1 *unless* their entity_id is in `omitting`,
    in which case they don't gossip a report at all.

    Uses unsigned reports so the test can spin up hundreds of cycles
    without exhausting a validator's one-time WOTS+ keys.
    """
    omitting = omitting or set()
    stakes = _stakes(validators)
    reports = [
        _make_unsigned_report(
            v.entity_id,
            report_height=publish_height - 1,
            tx_hashes=list(tx_hashes),
        )
        for v in validators
        if v.entity_id not in omitting
    ]
    return aggregate_inclusion_list(
        reports=reports, stakes=stakes,
        publish_height=publish_height,
    )


# ─────────────────────────────────────────────────────────────────────
# Pure-function: compute_coverage_penalty
# ─────────────────────────────────────────────────────────────────────

class TestComputeCoveragePenalty(unittest.TestCase):
    """The arithmetic shape — quadratic in consecutive_misses, capped."""

    def test_zero_below_activation(self):
        for misses in range(COVERAGE_LEAK_ACTIVATION_MISSES + 1):
            self.assertEqual(
                compute_coverage_penalty(1_000_000, misses),
                0,
                f"Expected 0 penalty at {misses} misses",
            )

    def test_zero_stake_zero_penalty(self):
        self.assertEqual(
            compute_coverage_penalty(0, COVERAGE_LEAK_ACTIVATION_MISSES + 5),
            0,
        )

    def test_quadratic_scaling(self):
        """penalty(2k) = 4 * penalty(k) when both are above the floor.

        Use a stake large enough that the cap never fires.
        """
        stake = 10**18
        m1 = COVERAGE_LEAK_ACTIVATION_MISSES + 16
        m2 = 2 * m1
        p1 = compute_coverage_penalty(stake, m1)
        p2 = compute_coverage_penalty(stake, m2)
        # Both must be non-trivial.
        self.assertGreater(p1, 0)
        self.assertGreater(p2, 0)
        # Quadratic: doubling misses quadruples the penalty (within
        # integer-divide truncation).
        self.assertAlmostEqual(p2, 4 * p1, delta=4)

    def test_capped_at_stake(self):
        """An attester with tiny stake can't be penalised below 0."""
        tiny_stake = 1
        # An astronomically high miss count would overflow stake without
        # the cap.
        self.assertEqual(
            compute_coverage_penalty(tiny_stake, 10_000_000),
            tiny_stake,
        )

    def test_negative_inputs_yield_zero(self):
        self.assertEqual(compute_coverage_penalty(-1, 100), 0)
        self.assertEqual(compute_coverage_penalty(1000, -1), 0)


# ─────────────────────────────────────────────────────────────────────
# Pure-function: get_coverage_misses
# ─────────────────────────────────────────────────────────────────────

class TestGetCoverageMisses(unittest.TestCase):
    """Compute the set of attesters who failed to cover at least one
    list entry, given the active set and the inclusion list itself.
    """

    def test_full_coverage_no_misses(self):
        validators = _make_validators(3, b"full")
        tx_h = _h(b"tx-full")
        lst = _build_list_with_reports(
            validators, publish_height=11, tx_hashes=[tx_h],
        )
        active = {v.entity_id for v in validators}
        self.assertEqual(get_coverage_misses(active, lst), set())

    def test_missing_reporter_is_a_miss(self):
        validators = _make_validators(4, b"miss")
        tx_h = _h(b"tx-miss")
        # 3 of 4 report; 4th withholds and so doesn't appear in the
        # list's quorum_attestation at all.  The list still forms because
        # 3/4 >= 2/3.  The 4th attester is "missing".
        lst = _build_list_with_reports(
            validators, publish_height=11, tx_hashes=[tx_h],
            omitting={validators[3].entity_id},
        )
        active = {v.entity_id for v in validators}
        misses = get_coverage_misses(active, lst)
        self.assertEqual(misses, {validators[3].entity_id})

    def test_partial_report_is_a_miss(self):
        """A reporter that included SOME but not ALL listed txs misses."""
        # Use 4 validators so 3/4 = 75% > 2/3 quorum is unambiguously
        # over the QUORUM_BPS threshold without integer-math drift.
        validators = _make_validators(4, b"part")
        tx_a, tx_b = _h(b"tx-a"), _h(b"tx-b")
        stakes = _stakes(validators)
        reports = [
            build_attester_mempool_report(
                validators[0], report_height=10, tx_hashes=[tx_a, tx_b],
            ),
            build_attester_mempool_report(
                validators[1], report_height=10, tx_hashes=[tx_a, tx_b],
            ),
            build_attester_mempool_report(
                validators[2], report_height=10, tx_hashes=[tx_a, tx_b],
            ),
            # validator[3] reports only tx_a — misses tx_b.
            build_attester_mempool_report(
                validators[3], report_height=10, tx_hashes=[tx_a],
            ),
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        # Sanity: list contains BOTH txs.  tx_a at 4/4, tx_b at 3/4.
        list_hashes = {e.tx_hash for e in lst.entries}
        self.assertIn(tx_a, list_hashes)
        self.assertIn(tx_b, list_hashes)
        active = {v.entity_id for v in validators}
        misses = get_coverage_misses(active, lst)
        # validator[3] missed tx_b.
        self.assertEqual(misses, {validators[3].entity_id})

    def test_non_active_attesters_ignored(self):
        """Validators outside the active set are never in the miss set —
        they aren't expected to attest at all."""
        validators = _make_validators(4, b"out")
        tx_h = _h(b"tx-out")
        # Build the list using only 3 of 4 validators.
        lst = _build_list_with_reports(
            validators[:3], publish_height=11, tx_hashes=[tx_h],
        )
        # Active set excludes validators[3].
        active = {v.entity_id for v in validators[:3]}
        misses = get_coverage_misses(active, lst)
        self.assertEqual(misses, set())

    def test_empty_list_no_misses(self):
        """A list with no entries can't generate any misses — there's
        nothing for an attester to fail to cover."""
        validators = _make_validators(3, b"empty")
        # Aggregate with no reports → empty list.
        lst = aggregate_inclusion_list(
            reports=[], stakes=_stakes(validators), publish_height=11,
        )
        self.assertEqual(lst.entries, [])
        active = {v.entity_id for v in validators}
        self.assertEqual(get_coverage_misses(active, lst), set())


# ─────────────────────────────────────────────────────────────────────
# State mutator: apply_coverage_leak
# ─────────────────────────────────────────────────────────────────────

class TestApplyCoverageLeak(unittest.TestCase):
    """Counter increment/reset semantics + stake burn arithmetic."""

    def setUp(self):
        self.validators = _make_validators(4, b"app")
        self.active = {v.entity_id for v in self.validators}
        self.staked = {v.entity_id: 10**12 for v in self.validators}
        self.misses_counter: dict[bytes, int] = {}

    def _step(self, lst: InclusionList) -> tuple[int, set[bytes]]:
        return apply_coverage_leak(
            staked=self.staked,
            misses_counter=self.misses_counter,
            active_attesters=self.active,
            inclusion_list=lst,
        )

    def test_happy_path_no_penalty(self):
        tx_h = _h(b"hp-tx")
        lst = _build_list_with_reports(
            self.validators, publish_height=11, tx_hashes=[tx_h],
        )
        burned, _ = self._step(lst)
        self.assertEqual(burned, 0)
        for vid in self.active:
            self.assertEqual(self.misses_counter.get(vid, 0), 0)

    def test_one_block_honest_miss_no_penalty(self):
        tx_h = _h(b"oh-tx")
        lst = _build_list_with_reports(
            self.validators, publish_height=11, tx_hashes=[tx_h],
            omitting={self.validators[3].entity_id},
        )
        burned, _ = self._step(lst)
        self.assertEqual(burned, 0)
        self.assertEqual(self.misses_counter[self.validators[3].entity_id], 1)
        # Other validators stay at 0.
        for v in self.validators[:3]:
            self.assertEqual(self.misses_counter.get(v.entity_id, 0), 0)

    def test_below_activation_threshold_no_penalty(self):
        """3 consecutive misses → counter 3, still no penalty."""
        tx_h = _h(b"bat-tx")
        offender = self.validators[3].entity_id
        for h in range(3):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"bat-" + str(h).encode())],
                omitting={offender},
            )
            burned, _ = self._step(lst)
            self.assertEqual(burned, 0)
        self.assertEqual(self.misses_counter[offender], 3)
        # Sanity: 3 should be < activation threshold.
        self.assertLess(3, COVERAGE_LEAK_ACTIVATION_MISSES + 1)

    def test_activation_at_five_misses(self):
        """Past the activation threshold → small but non-zero penalty."""
        offender = self.validators[3].entity_id
        stake_before = self.staked[offender]
        # Drive offender's counter to 5 consecutive misses.
        for h in range(5):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"act-" + str(h).encode())],
                omitting={offender},
            )
            self._step(lst)
        # 5 > COVERAGE_LEAK_ACTIVATION_MISSES (=4) by spec.
        self.assertGreater(
            self.misses_counter[offender],
            COVERAGE_LEAK_ACTIVATION_MISSES,
        )
        # Some stake should have been burned by now (small).
        self.assertLess(self.staked[offender], stake_before)

    def test_recovery_resets_counter(self):
        """A successful coverage report after misses resets the counter."""
        offender = self.validators[3].entity_id
        for h in range(10):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"rec-" + str(h).encode())],
                omitting={offender},
            )
            self._step(lst)
        self.assertEqual(self.misses_counter[offender], 10)

        # Now offender reports adequately — counter resets.
        good_lst = _build_list_with_reports(
            self.validators, publish_height=21,
            tx_hashes=[_h(b"good-tx")],
        )
        self._step(good_lst)
        self.assertEqual(self.misses_counter.get(offender, 0), 0)

        # A subsequent miss restarts at 1, not 11.
        miss_lst = _build_list_with_reports(
            self.validators, publish_height=22,
            tx_hashes=[_h(b"after-rec")],
            omitting={offender},
        )
        self._step(miss_lst)
        self.assertEqual(self.misses_counter[offender], 1)

    def test_cap_at_stake(self):
        """Even with massive miss counts, stake never goes negative."""
        offender = self.validators[3].entity_id
        # Tiny stake so the cap fires almost immediately past activation.
        self.staked[offender] = 100
        # Drive misses well past activation.
        for h in range(50):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"cap-" + str(h).encode())],
                omitting={offender},
            )
            self._step(lst)
        # Stake bottoms out at 0, never below.
        self.assertGreaterEqual(self.staked[offender], 0)

    def test_no_list_no_change(self):
        """An empty inclusion list (no entries) does not increment any
        counter — only cycles where a list actually forms count."""
        # First create real misses for the offender.
        offender = self.validators[3].entity_id
        miss_lst = _build_list_with_reports(
            self.validators, publish_height=11,
            tx_hashes=[_h(b"prior-miss")],
            omitting={offender},
        )
        self._step(miss_lst)
        self.assertEqual(self.misses_counter[offender], 1)

        # Now apply an empty list: counters must NOT change (neither
        # increment for the omitter nor reset for the others).
        empty = aggregate_inclusion_list(
            reports=[], stakes=self.staked, publish_height=12,
        )
        self.assertEqual(empty.entries, [])
        before = dict(self.misses_counter)
        burned, _ = self._step(empty)
        self.assertEqual(burned, 0)
        self.assertEqual(self.misses_counter, before)

    def test_persistent_withholding_drains_minority(self):
        """Per the design target: 32 cycles → ~5% stake leak."""
        offender = self.validators[3].entity_id
        stake_initial = self.staked[offender]
        for h in range(32):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"persist-" + str(h).encode())],
                omitting={offender},
            )
            self._step(lst)
        drained = stake_initial - self.staked[offender]
        # Design target: cumulative ~5% drain after 32 cycles.  Loose
        # bounds so calibration tweaks don't break the test, tight
        # enough to catch wrong-by-an-order-of-magnitude calibration.
        drained_pct = drained * 100 / stake_initial
        self.assertGreater(
            drained_pct, 1.0,
            f"32-cycle drain {drained_pct:.2f}% — should be ~5%",
        )
        self.assertLess(
            drained_pct, 25.0,
            f"32-cycle drain {drained_pct:.2f}% — should be ~5%, not blow up",
        )

    def test_long_horizon_drains_majority(self):
        """128 cycles → ~50% stake leak: the cartel falls below the
        minority threshold required for their withholding to matter.
        """
        offender = self.validators[3].entity_id
        stake_initial = self.staked[offender]
        for h in range(128):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"long-" + str(h).encode())],
                omitting={offender},
            )
            self._step(lst)
        drained = stake_initial - self.staked[offender]
        drained_pct = drained * 100 / stake_initial
        # Design target: ~50%.  Loose bounds again, but require at
        # least a meaningful fraction.
        self.assertGreater(
            drained_pct, 20.0,
            f"128-cycle drain {drained_pct:.2f}% — should be ~50%",
        )

    def test_determinism_two_replays_match(self):
        """Two replays of identical inputs produce identical outputs."""
        offender = self.validators[3].entity_id
        steps = []
        for h in range(20):
            lst = _build_list_with_reports(
                self.validators, publish_height=11 + h,
                tx_hashes=[_h(b"det-" + str(h).encode())],
                omitting={offender} if h % 2 == 0 else set(),
            )
            steps.append(lst)

        # Replay A.
        staked_a = {v.entity_id: 10**12 for v in self.validators}
        misses_a: dict[bytes, int] = {}
        burns_a: list[int] = []
        for lst in steps:
            burned, _ = apply_coverage_leak(
                staked=staked_a, misses_counter=misses_a,
                active_attesters=self.active, inclusion_list=lst,
            )
            burns_a.append(burned)

        # Replay B (independent state).
        staked_b = {v.entity_id: 10**12 for v in self.validators}
        misses_b: dict[bytes, int] = {}
        burns_b: list[int] = []
        for lst in steps:
            burned, _ = apply_coverage_leak(
                staked=staked_b, misses_counter=misses_b,
                active_attesters=self.active, inclusion_list=lst,
            )
            burns_b.append(burned)

        self.assertEqual(burns_a, burns_b)
        self.assertEqual(staked_a, staked_b)
        self.assertEqual(misses_a, misses_b)


# ─────────────────────────────────────────────────────────────────────
# Snapshot round-trip: counter survives serialize/decode/install
# ─────────────────────────────────────────────────────────────────────

class TestSnapshotRoundtrip(unittest.TestCase):

    def test_counter_survives_snapshot(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
        )

        founder = Entity.create(b"snap-founder".ljust(32, b"\x00"))
        founder.keypair._next_leaf = 0
        chain = Blockchain()
        chain.initialize_genesis(founder)

        # Seed the counter directly — exercising the snapshot field, not
        # the apply path (apply path is exercised by the integration
        # test below).
        offender = b"\xaa" * 32
        bystander = b"\xbb" * 32
        chain.attester_coverage_misses = {
            offender: 17,
            bystander: 0,
        }

        snap = serialize_state(chain)
        # Field present in the dict.
        self.assertIn("attester_coverage_misses", snap)
        self.assertEqual(snap["attester_coverage_misses"][offender], 17)

        # Binary round-trip.
        blob = encode_snapshot(snap)
        restored = decode_snapshot(blob)
        self.assertEqual(
            restored["attester_coverage_misses"][offender], 17,
        )

        # Install into a fresh chain.
        chain2 = Blockchain()
        chain2._install_state_snapshot(restored)
        self.assertEqual(
            chain2.attester_coverage_misses.get(offender), 17,
        )


# ─────────────────────────────────────────────────────────────────────
# Block-apply integration: wiring through _apply_block_state
# ─────────────────────────────────────────────────────────────────────

class TestBlockApplyIntegration(unittest.TestCase):
    """Verify _apply_block_state correctly increments / leaks based on
    the block's inclusion_list.

    The tests construct a chain and synthesise blocks by directly
    invoking the apply hook with a hand-built inclusion list — this
    avoids the proposer-selection / attestation plumbing and isolates
    the coverage-leak path.
    """

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.founder = Entity.create(b"int-founder".ljust(32, b"\x00"))
        self.founder.keypair._next_leaf = 0
        self.chain = Blockchain()
        self.chain.initialize_genesis(self.founder)
        self.validators = _make_validators(4, b"int")
        for v in self.validators:
            register_entity_for_test(self.chain, v)
            self.chain.supply.staked[v.entity_id] = 10**10

    def test_apply_increments_and_resets(self):
        """A block with an inclusion list updates attester_coverage_misses
        for every active attester."""
        offender = self.validators[3].entity_id
        lst = _build_list_with_reports(
            self.validators, publish_height=1,
            tx_hashes=[_h(b"int-tx-1")],
            omitting={offender},
        )
        # Drive the apply-time hook directly.
        self.chain._apply_inclusion_list_coverage_leak(lst)
        self.assertEqual(
            self.chain.attester_coverage_misses[offender], 1,
        )

        # A subsequent good cycle resets the offender to 0.
        good = _build_list_with_reports(
            self.validators, publish_height=2,
            tx_hashes=[_h(b"int-tx-2")],
        )
        self.chain._apply_inclusion_list_coverage_leak(good)
        self.assertEqual(
            self.chain.attester_coverage_misses.get(offender, 0), 0,
        )

    def test_block_validity_consensus_on_burn(self):
        """Two chains replaying the same sequence of inclusion-list
        cycles agree on the burned amount and stake state — the
        fundamental consensus-on-coverage-leak invariant."""
        offender = self.validators[3].entity_id

        # Replay sequence on a *second* chain initialised the same way.
        from messagechain.core.blockchain import Blockchain
        founder2 = Entity.create(b"int-founder".ljust(32, b"\x00"))
        founder2.keypair._next_leaf = 0
        chain2 = Blockchain()
        chain2.initialize_genesis(founder2)
        for v in self.validators:
            register_entity_for_test(chain2, v)
            chain2.supply.staked[v.entity_id] = 10**10

        for h in range(40):
            lst = _build_list_with_reports(
                self.validators, publish_height=1 + h,
                tx_hashes=[_h(b"consensus-" + str(h).encode())],
                omitting={offender},
            )
            self.chain._apply_inclusion_list_coverage_leak(lst)
            chain2._apply_inclusion_list_coverage_leak(lst)

        # Stake outcomes match bit-for-bit.
        self.assertEqual(
            self.chain.supply.staked[offender],
            chain2.supply.staked[offender],
        )
        # Counter outcomes match bit-for-bit.
        self.assertEqual(
            dict(self.chain.attester_coverage_misses),
            dict(chain2.attester_coverage_misses),
        )

    def test_independence_from_inactivity_leak(self):
        """Coverage leak operates on inclusion-list cycles only; it
        does not care whether the chain is in finalization-stall (the
        existing inactivity leak's domain) and vice versa.

        Concretely: applying a coverage leak does not touch
        blocks_since_last_finalization, and changing
        blocks_since_last_finalization does not change coverage state.
        """
        offender = self.validators[3].entity_id
        before_stall = self.chain.blocks_since_last_finalization
        lst = _build_list_with_reports(
            self.validators, publish_height=1,
            tx_hashes=[_h(b"indep-tx")],
            omitting={offender},
        )
        self.chain._apply_inclusion_list_coverage_leak(lst)
        # Stall counter untouched.
        self.assertEqual(
            self.chain.blocks_since_last_finalization, before_stall,
        )
        # Coverage counter advanced.
        self.assertEqual(
            self.chain.attester_coverage_misses[offender], 1,
        )

        # Now bump the stall counter manually — coverage state must
        # not change.
        self.chain.blocks_since_last_finalization = 100
        coverage_before = dict(self.chain.attester_coverage_misses)
        self.assertEqual(
            self.chain.attester_coverage_misses, coverage_before,
        )


if __name__ == "__main__":
    unittest.main()
