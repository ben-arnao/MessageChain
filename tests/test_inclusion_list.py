"""Tests for quorum-signed inclusion lists.

The InclusionList sits between forced_inclusion (attester-subjective,
slashing-free) and InclusionListViolationEvidenceTx (consensus-objective,
slashing-bearing).  This test module covers the data type itself —
construction, canonical bytes, hashing, validation against the quorum
attestation, processor lifecycle.

Slashing wiring is in test_inclusion_list_violation.py.

Pipeline (Option A — chosen and documented in the module docstring):

  1. Each attester gossips an AttesterMempoolReport committing to the
     tx_hashes its mempool has held for >= INCLUSION_LIST_WAIT_BLOCKS.
  2. The proposer of block N collects reports valid for heights
     [N-INCLUSION_LIST_WAIT_BLOCKS, N-1], intersects them stake-weighted,
     and any tx_hash with >= INCLUSION_LIST_QUORUM_BPS of stake support
     enters an InclusionList published in block N.
  3. The list applies forward to blocks N+1..N+INCLUSION_LIST_WINDOW.
  4. After expiry, any list entry that didn't land yields an
     InclusionListViolationEvidenceTx slashable against the proposers.
"""

import hashlib
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_LIST_WINDOW,
    INCLUSION_LIST_QUORUM_BPS,
    MAX_INCLUSION_LIST_ENTRIES,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    InclusionListProcessor,
    InclusionViolation,
    build_attester_mempool_report,
    verify_attester_mempool_report,
    aggregate_inclusion_list,
    verify_inclusion_list_quorum,
    INCLUSION_LIST_DOMAIN_TAG,
    ATTESTER_MEMPOOL_REPORT_DOMAIN_TAG,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"il") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    """Return an equal-stake distribution keyed by entity_id."""
    return {v.entity_id: per for v in validators}


# ─────────────────────────────────────────────────────────────────────
# AttesterMempoolReport — wire round-trip + signature verification
# ─────────────────────────────────────────────────────────────────────

class TestAttesterMempoolReport(unittest.TestCase):

    def test_build_and_verify(self):
        v = _make_validators(1, b"build")[0]
        tx_hashes = [_h(b"tx-a"), _h(b"tx-b")]
        report = build_attester_mempool_report(
            v, report_height=10, tx_hashes=tx_hashes,
        )
        self.assertEqual(report.reporter_id, v.entity_id)
        self.assertEqual(report.report_height, 10)
        self.assertEqual(set(report.tx_hashes), set(tx_hashes))
        self.assertTrue(verify_attester_mempool_report(report, v.public_key))

    def test_canonical_ordering_in_signed_bytes(self):
        """tx_hashes must be sorted before signing — same SET of hashes
        in different insertion order must produce the SAME report bytes
        and thus the SAME signature input."""
        v = _make_validators(1, b"canon")[0]
        h1, h2, h3 = _h(b"a"), _h(b"b"), _h(b"c")
        r_in_order = build_attester_mempool_report(
            v, report_height=5, tx_hashes=[h1, h2, h3],
        )
        # Reset the keypair leaf so we can re-sign from a clean slate.
        v_again = Entity.create(b"canon-v0".ljust(32, b"\x00"))
        # Pass same hashes but unordered — canonical form must sort them.
        r_unordered = build_attester_mempool_report(
            v_again, report_height=5, tx_hashes=[h3, h1, h2],
        )
        # The signable_data is what matters for canonical commitment;
        # both reports' signable_data must match byte-for-byte.
        self.assertEqual(
            r_in_order._signable_data(), r_unordered._signable_data(),
        )

    def test_dict_roundtrip(self):
        v = _make_validators(1, b"dr")[0]
        tx_hashes = [_h(b"a"), _h(b"b")]
        report = build_attester_mempool_report(
            v, report_height=7, tx_hashes=tx_hashes,
        )
        rt = AttesterMempoolReport.deserialize(report.serialize())
        self.assertEqual(rt.reporter_id, report.reporter_id)
        self.assertEqual(rt.report_height, report.report_height)
        self.assertEqual(rt.tx_hashes, report.tx_hashes)
        self.assertTrue(verify_attester_mempool_report(rt, v.public_key))

    def test_binary_roundtrip(self):
        v = _make_validators(1, b"br")[0]
        tx_hashes = [_h(b"x"), _h(b"y"), _h(b"z")]
        report = build_attester_mempool_report(
            v, report_height=11, tx_hashes=tx_hashes,
        )
        blob = report.to_bytes()
        rt = AttesterMempoolReport.from_bytes(blob)
        self.assertEqual(rt.reporter_id, report.reporter_id)
        self.assertEqual(rt.report_height, report.report_height)
        self.assertEqual(rt.tx_hashes, sorted(tx_hashes))
        self.assertTrue(verify_attester_mempool_report(rt, v.public_key))

    def test_domain_tag_separation(self):
        """Verifying an InclusionList hash against the report's signed
        bytes (or vice-versa) must fail — the two domain tags differ."""
        self.assertNotEqual(
            INCLUSION_LIST_DOMAIN_TAG, ATTESTER_MEMPOOL_REPORT_DOMAIN_TAG,
        )

    def test_bad_signature_rejected(self):
        v = _make_validators(2, b"badsig")
        tx_hashes = [_h(b"q")]
        report = build_attester_mempool_report(
            v[0], report_height=5, tx_hashes=tx_hashes,
        )
        # Verify against the WRONG validator's pubkey.
        self.assertFalse(verify_attester_mempool_report(
            report, v[1].public_key,
        ))


# ─────────────────────────────────────────────────────────────────────
# InclusionList — aggregation + quorum verification
# ─────────────────────────────────────────────────────────────────────

class TestInclusionListAggregation(unittest.TestCase):

    def test_aggregate_with_full_quorum(self):
        """All N validators report the same tx — list contains it."""
        validators = _make_validators(4, b"aggfull")
        stakes = _stakes(validators)
        target_tx = _h(b"hot-tx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports,
            stakes=stakes,
            publish_height=11,
        )
        self.assertEqual(len(lst.entries), 1)
        self.assertEqual(lst.entries[0].tx_hash, target_tx)
        self.assertEqual(lst.publish_height, 11)
        self.assertEqual(lst.window_blocks, INCLUSION_LIST_WINDOW)

    def test_aggregate_below_quorum_excludes(self):
        """Only 1 of 4 reports the tx — under the 2/3 threshold."""
        validators = _make_validators(4, b"aggminor")
        stakes = _stakes(validators)
        target_tx = _h(b"sparse-tx")
        reports = [
            build_attester_mempool_report(
                validators[0], report_height=10,
                tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[1], report_height=10, tx_hashes=[],
            ),
            build_attester_mempool_report(
                validators[2], report_height=10, tx_hashes=[],
            ),
            build_attester_mempool_report(
                validators[3], report_height=10, tx_hashes=[],
            ),
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        self.assertEqual(len(lst.entries), 0)

    def test_aggregate_exactly_at_quorum_includes(self):
        """3 of 4 equal validators = 75% > 6667bps — includes the tx."""
        validators = _make_validators(4, b"aggeq")
        stakes = _stakes(validators)
        target_tx = _h(b"quorum-tx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[target_tx],
            )
            for v in validators[:3]
        ] + [
            build_attester_mempool_report(
                validators[3], report_height=10, tx_hashes=[],
            ),
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        self.assertEqual(len(lst.entries), 1)
        self.assertEqual(lst.entries[0].tx_hash, target_tx)

    def test_aggregate_one_big_validator(self):
        """A 70%-stake validator alone meets quorum on its own."""
        validators = _make_validators(3, b"aggbig")
        stakes = {
            validators[0].entity_id: 7_000_000,
            validators[1].entity_id: 1_500_000,
            validators[2].entity_id: 1_500_000,
        }
        target_tx = _h(b"whale-tx")
        reports = [
            build_attester_mempool_report(
                validators[0], report_height=8,
                tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[1], report_height=8, tx_hashes=[],
            ),
            build_attester_mempool_report(
                validators[2], report_height=8, tx_hashes=[],
            ),
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=9,
        )
        self.assertEqual(len(lst.entries), 1)
        self.assertEqual(lst.entries[0].tx_hash, target_tx)

    def test_first_seen_height_is_min(self):
        """An entry's first_seen_height is the MIN report_height across
        the reports that include it."""
        validators = _make_validators(3, b"aggfsh")
        stakes = _stakes(validators)
        target_tx = _h(b"tx-evol")
        reports = [
            build_attester_mempool_report(
                validators[0], report_height=8, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[1], report_height=10, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[2], report_height=9, tx_hashes=[target_tx],
            ),
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        self.assertEqual(len(lst.entries), 1)
        self.assertEqual(lst.entries[0].first_seen_height, 8)

    def test_canonical_entry_order(self):
        """Entries are sorted by tx_hash regardless of report ordering."""
        validators = _make_validators(3, b"aggorder")
        stakes = _stakes(validators)
        h_a, h_b, h_c = _h(b"a"), _h(b"b"), _h(b"c")
        # Sort ascending bytewise: smallest first.
        smallest, middle, largest = sorted([h_a, h_b, h_c])
        reports = [
            build_attester_mempool_report(
                v, report_height=5,
                tx_hashes=[largest, smallest, middle],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=6,
        )
        self.assertEqual(
            [e.tx_hash for e in lst.entries],
            [smallest, middle, largest],
        )


# ─────────────────────────────────────────────────────────────────────
# InclusionList — serialization, hashing, validation
# ─────────────────────────────────────────────────────────────────────

class TestInclusionListSerialization(unittest.TestCase):

    def _build_simple_list(self, publish_height=11):
        validators = _make_validators(3, b"ils")
        stakes = _stakes(validators)
        target_tx = _h(b"hot-tx-il")
        reports = [
            build_attester_mempool_report(
                v, report_height=publish_height - 1,
                tx_hashes=[target_tx],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes,
            publish_height=publish_height,
        )
        return lst, validators, stakes

    def test_dict_roundtrip(self):
        lst, _, _ = self._build_simple_list()
        rt = InclusionList.deserialize(lst.serialize())
        self.assertEqual(rt.list_hash, lst.list_hash)
        self.assertEqual(rt.publish_height, lst.publish_height)
        self.assertEqual(
            [(e.tx_hash, e.first_seen_height) for e in rt.entries],
            [(e.tx_hash, e.first_seen_height) for e in lst.entries],
        )

    def test_binary_roundtrip(self):
        lst, _, _ = self._build_simple_list()
        blob = lst.to_bytes()
        rt = InclusionList.from_bytes(blob)
        self.assertEqual(rt.list_hash, lst.list_hash)
        self.assertEqual(rt.publish_height, lst.publish_height)
        self.assertEqual(len(rt.entries), len(lst.entries))
        self.assertEqual(len(rt.quorum_attestation), len(lst.quorum_attestation))

    def test_canonical_hash_invariant_under_entry_order(self):
        """Two semantically-identical lists with different entry orders
        produce the same list_hash."""
        validators = _make_validators(3, b"chord")
        stakes = _stakes(validators)
        h_a, h_b, h_c = sorted([_h(b"a"), _h(b"b"), _h(b"c")])
        reports = [
            build_attester_mempool_report(
                v, report_height=5,
                tx_hashes=[h_a, h_b, h_c],
            )
            for v in validators
        ]
        lst1 = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=6,
        )
        # Hand-build a second list with the same entries but explicitly
        # in a different order — the canonical-hash code must sort.
        validators2 = _make_validators(3, b"chord2")
        stakes2 = _stakes(validators2)
        reports2 = [
            build_attester_mempool_report(
                v, report_height=5,
                tx_hashes=[h_c, h_a, h_b],  # different input order
            )
            for v in validators2
        ]
        lst2 = aggregate_inclusion_list(
            reports=reports2, stakes=stakes2, publish_height=6,
        )
        # Both lists should have identical list_hashes — they commit
        # to the same (publish_height, sorted-entries, window).  The
        # quorum_attestation is NOT part of the list_hash (otherwise
        # different-but-equivalent witness sets would collide).
        self.assertEqual(lst1.list_hash, lst2.list_hash)


class TestInclusionListQuorumVerification(unittest.TestCase):

    def test_valid_quorum_accepted(self):
        validators = _make_validators(3, b"vq")
        stakes = _stakes(validators)
        target_tx = _h(b"vqtx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            lst, stakes=stakes, public_keys=public_keys,
        )
        self.assertTrue(ok, reason)

    def test_below_quorum_rejected(self):
        """A hand-crafted list claiming an entry that only has 1/4
        stake support must fail verification."""
        validators = _make_validators(4, b"belq")
        stakes = _stakes(validators)
        target_tx = _h(b"belqtx")
        # Only ONE validator's report includes the tx.
        reports = [
            build_attester_mempool_report(
                validators[0], report_height=10, tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[1], report_height=10, tx_hashes=[],
            ),
            build_attester_mempool_report(
                validators[2], report_height=10, tx_hashes=[],
            ),
            build_attester_mempool_report(
                validators[3], report_height=10, tx_hashes=[],
            ),
        ]
        # Hand-build a list that LIES — claims target_tx is included.
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=target_tx, first_seen_height=10,
            )],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)
        self.assertIn("quorum", reason.lower())

    def test_stale_report_rejected(self):
        """A report with report_height older than
        publish_height - INCLUSION_LIST_WAIT_BLOCKS must fail
        verification."""
        validators = _make_validators(3, b"stale")
        stakes = _stakes(validators)
        target_tx = _h(b"staletx")
        # Reports at height 1 with publish_height 100 are far too old.
        reports = [
            build_attester_mempool_report(
                v, report_height=1, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        bad_list = InclusionList(
            publish_height=100,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=target_tx, first_seen_height=1,
            )],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)
        self.assertIn("aged", reason.lower())

    def test_future_report_rejected(self):
        """A report with report_height >= publish_height must fail
        verification — reports must be from earlier blocks."""
        validators = _make_validators(3, b"futr")
        stakes = _stakes(validators)
        target_tx = _h(b"futrtx")
        reports = [
            build_attester_mempool_report(
                v, report_height=11, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=target_tx, first_seen_height=11,
            )],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)

    def test_entries_must_be_sorted(self):
        """A list whose entries aren't in canonical (tx_hash) order
        fails validation."""
        validators = _make_validators(3, b"unsort")
        stakes = _stakes(validators)
        h_a, h_b = sorted([_h(b"sort1"), _h(b"sort2")])
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[h_a, h_b],
            )
            for v in validators
        ]
        # Build the list with entries explicitly REVERSED.
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[
                InclusionListEntry(tx_hash=h_b, first_seen_height=10),
                InclusionListEntry(tx_hash=h_a, first_seen_height=10),
            ],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)
        self.assertIn("sort", reason.lower())

    def test_dedup_required(self):
        """Duplicate entries fail validation."""
        validators = _make_validators(3, b"dup")
        stakes = _stakes(validators)
        h_x = _h(b"dupx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[h_x],
            )
            for v in validators
        ]
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[
                InclusionListEntry(tx_hash=h_x, first_seen_height=10),
                InclusionListEntry(tx_hash=h_x, first_seen_height=10),
            ],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)
        self.assertIn("dup", reason.lower())

    def test_too_many_entries_rejected(self):
        """A list with > MAX_INCLUSION_LIST_ENTRIES is invalid."""
        validators = _make_validators(3, b"toomany")
        stakes = _stakes(validators)
        many_hashes = sorted({
            _h(b"tm-" + str(i).encode())
            for i in range(MAX_INCLUSION_LIST_ENTRIES + 1)
        })
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=many_hashes,
            )
            for v in validators
        ]
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[
                InclusionListEntry(tx_hash=h, first_seen_height=10)
                for h in many_hashes
            ],
            quorum_attestation=reports,
        )
        public_keys = {v.entity_id: v.public_key for v in validators}
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)

    def test_unknown_signer_dropped(self):
        """Reports from non-staked validators contribute zero to the
        quorum tally — a list whose only support comes from such
        signers fails verification."""
        validators = _make_validators(2, b"unkn")
        # Only validator[0] is in stakes/public_keys.
        stakes = {validators[0].entity_id: 1_000_000}
        public_keys = {validators[0].entity_id: validators[0].public_key}
        target_tx = _h(b"unkntx")
        reports = [
            build_attester_mempool_report(
                validators[1], report_height=10,
                tx_hashes=[target_tx],
            ),
            build_attester_mempool_report(
                validators[0], report_height=10, tx_hashes=[],
            ),
        ]
        bad_list = InclusionList(
            publish_height=11,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[InclusionListEntry(
                tx_hash=target_tx, first_seen_height=10,
            )],
            quorum_attestation=reports,
        )
        ok, reason = verify_inclusion_list_quorum(
            bad_list, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok)


class TestInclusionListVersioning(unittest.TestCase):
    """Crypto-agility: future versions can be activated via hard-fork
    by widening the accepted set."""

    def test_unknown_version_rejected_on_deserialize(self):
        from messagechain.consensus.inclusion_list import (
            INCLUSION_LIST_VERSION,
        )
        validators = _make_validators(3, b"ver")
        stakes = _stakes(validators)
        target_tx = _h(b"vertx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        d = lst.serialize()
        # Mutate the version to a value not in the accepted frozenset.
        d["version"] = INCLUSION_LIST_VERSION + 99
        with self.assertRaises(ValueError) as ctx:
            InclusionList.deserialize(d)
        self.assertIn("version", str(ctx.exception).lower())


# ─────────────────────────────────────────────────────────────────────
# Processor lifecycle
# ─────────────────────────────────────────────────────────────────────

class TestInclusionListProcessor(unittest.TestCase):

    def _build_list(self, target_txs, publish_height, validators, stakes):
        reports = [
            build_attester_mempool_report(
                v,
                report_height=publish_height - 1,
                tx_hashes=list(target_txs),
            )
            for v in validators
        ]
        return aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=publish_height,
        )

    def test_register_and_active_lookup(self):
        validators = _make_validators(3, b"prl")
        stakes = _stakes(validators)
        tx_h = _h(b"prl-tx")
        lst = self._build_list([tx_h], 11, validators, stakes)

        proc = InclusionListProcessor()
        proc.register(lst, current_height=11)
        # In the forward window:
        for h in range(12, 12 + INCLUSION_LIST_WINDOW):
            actives = proc.active_lists_at_height(h)
            self.assertEqual(len(actives), 1)
            self.assertEqual(actives[0].list_hash, lst.list_hash)

    def test_observe_block_records_inclusion(self):
        """When a list-mandated tx lands in a later block, the
        processor marks it included so it doesn't show up as a
        violation at expiry."""
        validators = _make_validators(3, b"obs")
        stakes = _stakes(validators)
        tx_h = _h(b"obs-tx")
        lst = self._build_list([tx_h], 11, validators, stakes)

        proc = InclusionListProcessor()
        proc.register(lst, current_height=11)

        # Fake a "block" at height 13 carrying tx_h.
        from types import SimpleNamespace
        included_block = SimpleNamespace(
            header=SimpleNamespace(block_number=13),
            transactions=[SimpleNamespace(tx_hash=tx_h)],
            transfer_transactions=[],
        )
        proc.observe_block(included_block)
        # At expiry, no violation should fire.
        proposers = {12: b"\x01" * 32, 13: b"\x02" * 32}
        violations = proc.expire(
            current_height=11 + INCLUSION_LIST_WINDOW + 1,
            proposers_by_height=proposers,
        )
        self.assertEqual(violations, [])

    def test_expire_emits_violation_for_missed_tx(self):
        validators = _make_validators(3, b"exp")
        stakes = _stakes(validators)
        tx_h = _h(b"exp-tx")
        lst = self._build_list([tx_h], 11, validators, stakes)

        proc = InclusionListProcessor()
        proc.register(lst, current_height=11)

        # No observed inclusion.  At publish_height + WINDOW + 1 the
        # window has passed and a violation must be emitted.
        proposers = {
            h: bytes([h]) * 32
            for h in range(12, 12 + INCLUSION_LIST_WINDOW)
        }
        violations = proc.expire(
            current_height=11 + INCLUSION_LIST_WINDOW + 1,
            proposers_by_height=proposers,
        )
        self.assertEqual(len(violations), 1)
        v = violations[0]
        self.assertIsInstance(v, InclusionViolation)
        self.assertEqual(v.tx_hash, tx_h)
        self.assertEqual(v.list_hash, lst.list_hash)
        # All proposers in the window are accountable — their ids
        # appear in the violation.
        self.assertEqual(
            set(v.accused_proposers),
            set(proposers.values()),
        )

    def test_expire_drops_list_after_window(self):
        validators = _make_validators(3, b"drop")
        stakes = _stakes(validators)
        tx_h = _h(b"drop-tx")
        lst = self._build_list([tx_h], 11, validators, stakes)

        proc = InclusionListProcessor()
        proc.register(lst, current_height=11)
        proc.expire(
            current_height=11 + INCLUSION_LIST_WINDOW + 1,
            proposers_by_height={
                h: bytes([h]) * 32
                for h in range(12, 12 + INCLUSION_LIST_WINDOW)
            },
        )
        # No active list lookups should return it post-expiry.
        self.assertEqual(
            proc.active_lists_at_height(11 + INCLUSION_LIST_WINDOW + 2),
            [],
        )

    def test_snapshot_roundtrip(self):
        validators = _make_validators(3, b"snap")
        stakes = _stakes(validators)
        tx_h = _h(b"snap-tx")
        lst = self._build_list([tx_h], 11, validators, stakes)

        proc = InclusionListProcessor()
        proc.register(lst, current_height=11)
        # Dedup key is (list_hash, tx_hash, proposer_id) — list_hash
        # participates so two overlapping lists mandating the same tx
        # each get their own slash.
        proc.processed_violations.add(
            (lst.list_hash, tx_h, b"\xff" * 32),
        )

        snap = proc.snapshot_dict()
        proc2 = InclusionListProcessor()
        proc2.load_snapshot_dict(snap)

        self.assertEqual(
            proc.processed_violations,
            proc2.processed_violations,
        )
        # Active lists comparison via list_hash.
        self.assertEqual(
            sorted(proc.active_lists.keys()),
            sorted(proc2.active_lists.keys()),
        )
        for k in proc.active_lists:
            self.assertEqual(
                proc.active_lists[k].list_hash,
                proc2.active_lists[k].list_hash,
            )


if __name__ == "__main__":
    unittest.main()
