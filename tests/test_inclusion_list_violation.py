"""Tests for InclusionListViolationEvidenceTx — slashing path.

An InclusionList published in block N applies forward to blocks
N+1..N+INCLUSION_LIST_WINDOW.  After the window closes, any mandated
tx that did not land (and was not excused) is a violation.  Anyone
can submit an InclusionListViolationEvidenceTx naming the omitted tx
+ one of the accused proposers; on admission the chain slashes the
proposer INCLUSION_VIOLATION_SLASH_BPS of stake (burned — no finder
reward, matches the existing evidence types).

Double-slash defense: once a (list_hash, tx_hash, proposer_id) triple
is in the processor's processed_violations set, no second evidence can
be admitted against it.  list_hash is part of the key because two
overlapping inclusion lists can both mandate the same tx — omitting
that tx while both are active is two violations, not one.
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO, MIN_FEE,
    INCLUSION_LIST_WAIT_BLOCKS, INCLUSION_LIST_WINDOW,
    INCLUSION_VIOLATION_SLASH_BPS,
)
from messagechain.identity.identity import Entity
from messagechain.crypto.keys import Signature
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    InclusionListProcessor,
    InclusionListViolationEvidenceTx,
    build_attester_mempool_report,
    aggregate_inclusion_list,
    verify_inclusion_list_violation_evidence_tx,
    compute_violation_slash_amount,
)


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"iv") -> list[Entity]:
    return [
        Entity.create((tag + b"-v" + str(i).encode()).ljust(32, b"\x00"))
        for i in range(n)
    ]


def _stakes(validators: list[Entity], per: int = 1_000_000) -> dict[bytes, int]:
    return {v.entity_id: per for v in validators}


def _sign_violation_evidence(
    submitter: Entity,
    inclusion_list: InclusionList,
    omitted_tx_hash: bytes,
    accused_proposer_id: bytes,
    accused_height: int,
    fee: int = MIN_FEE,
    timestamp: int | None = None,
) -> InclusionListViolationEvidenceTx:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    placeholder = Signature([], 0, [], b"", b"")
    tx = InclusionListViolationEvidenceTx(
        inclusion_list=inclusion_list,
        omitted_tx_hash=omitted_tx_hash,
        accused_proposer_id=accused_proposer_id,
        accused_height=accused_height,
        submitter_id=submitter.entity_id,
        timestamp=ts,
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


# ─────────────────────────────────────────────────────────────────────
# Evidence-tx round-trip + stateless verification
# ─────────────────────────────────────────────────────────────────────

class TestInclusionListViolationEvidenceTx(unittest.TestCase):

    def _build(self):
        validators = _make_validators(3, b"ivrt")
        stakes = _stakes(validators)
        target_tx = _h(b"iv-hot-tx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[target_tx],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        accused = _make_validators(1, b"iv-acc")[0]
        submitter = _make_validators(1, b"iv-sub")[0]
        etx = _sign_violation_evidence(
            submitter, lst, target_tx,
            accused.entity_id, accused_height=12,
        )
        return etx, submitter, accused

    def test_dict_roundtrip(self):
        etx, submitter, _ = self._build()
        rt = InclusionListViolationEvidenceTx.deserialize(etx.serialize())
        self.assertEqual(rt.tx_hash, etx.tx_hash)
        self.assertEqual(rt.evidence_hash, etx.evidence_hash)
        self.assertEqual(rt.omitted_tx_hash, etx.omitted_tx_hash)
        self.assertEqual(rt.accused_proposer_id, etx.accused_proposer_id)

    def test_binary_roundtrip(self):
        etx, submitter, _ = self._build()
        blob = etx.to_bytes()
        rt = InclusionListViolationEvidenceTx.from_bytes(blob)
        self.assertEqual(rt.tx_hash, etx.tx_hash)
        self.assertEqual(rt.evidence_hash, etx.evidence_hash)
        self.assertEqual(rt.accused_height, etx.accused_height)

    def test_verify_accepts_valid(self):
        etx, submitter, _ = self._build()
        ok, reason = verify_inclusion_list_violation_evidence_tx(
            etx, submitter.public_key,
        )
        self.assertTrue(ok, reason)

    def test_verify_rejects_underfee(self):
        validators = _make_validators(3, b"ivfee")
        stakes = _stakes(validators)
        tx_h = _h(b"ivfeetx")
        reports = [
            build_attester_mempool_report(
                v, report_height=10, tx_hashes=[tx_h],
            )
            for v in validators
        ]
        lst = aggregate_inclusion_list(
            reports=reports, stakes=stakes, publish_height=11,
        )
        submitter = _make_validators(1, b"ivfee-sub")[0]
        etx = _sign_violation_evidence(
            submitter, lst, tx_h,
            accused_proposer_id=b"\x33" * 32,
            accused_height=12,
            fee=1,
        )
        ok, reason = verify_inclusion_list_violation_evidence_tx(
            etx, submitter.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("fee", reason.lower())

    def test_verify_rejects_bad_submitter_sig(self):
        etx, submitter, _ = self._build()
        wrong = _make_validators(1, b"iv-wrong")[0]
        ok, reason = verify_inclusion_list_violation_evidence_tx(
            etx, wrong.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("submitter", reason.lower())

    def test_verify_rejects_tx_not_in_list(self):
        """The omitted_tx_hash must actually appear in the list's
        entries — evidence about a tx that was never mandated is
        nonsense."""
        etx, submitter, _ = self._build()
        # Override the omitted_tx_hash and re-sign.
        from messagechain.crypto.keys import Signature
        bogus_tx_hash = _h(b"never-mandated")
        placeholder = Signature([], 0, [], b"", b"")
        tampered = InclusionListViolationEvidenceTx(
            inclusion_list=etx.inclusion_list,
            omitted_tx_hash=bogus_tx_hash,
            accused_proposer_id=etx.accused_proposer_id,
            accused_height=etx.accused_height,
            submitter_id=etx.submitter_id,
            timestamp=etx.timestamp,
            fee=etx.fee,
            signature=placeholder,
        )
        msg_hash = _h(tampered._signable_data())
        tampered.signature = submitter.keypair.sign(msg_hash)
        tampered.tx_hash = tampered._compute_hash()
        ok, reason = verify_inclusion_list_violation_evidence_tx(
            tampered, submitter.public_key,
        )
        self.assertFalse(ok)
        self.assertIn("entries", reason.lower())


# ─────────────────────────────────────────────────────────────────────
# End-to-end blockchain slashing path
# ─────────────────────────────────────────────────────────────────────

class TestInclusionViolationSlashing(unittest.TestCase):

    def setUp(self):
        from messagechain.core.blockchain import Blockchain
        self.submitter = Entity.create(b"iv-submitter".ljust(32, b"\x00"))
        self.accused = Entity.create(b"iv-accused".ljust(32, b"\x00"))
        self.submitter.keypair._next_leaf = 0
        self.accused.keypair._next_leaf = 0

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.submitter)
        register_entity_for_test(self.chain, self.accused)
        self.chain.supply.balances[self.submitter.entity_id] = 1_000_000
        self.chain.supply.balances[self.accused.entity_id] = 1_000_000
        self.chain.supply.staked[self.accused.entity_id] = 100_000

    def _build_list(self, target_txs, publish_height, validators=None):
        if validators is None:
            validators = _make_validators(3, b"iv-sl")
        stakes = _stakes(validators)
        reports = [
            build_attester_mempool_report(
                v, report_height=publish_height - 1,
                tx_hashes=list(target_txs),
            )
            for v in validators
        ]
        return aggregate_inclusion_list(
            reports=reports, stakes=stakes,
            publish_height=publish_height,
        )

    def test_slash_applied_on_admission(self):
        """A valid violation evidence in a block slashes the accused."""
        tx_h = _h(b"slash-tx")
        lst = self._build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            self.submitter, lst, tx_h,
            self.accused.entity_id, accused_height=12,
        )
        # Register the violation directly via the processor as a
        # reference point: the (list_hash, tx_hash, proposer_id)
        # triple hasn't been processed yet.
        proc = self.chain.inclusion_list_processor
        self.assertNotIn(
            (lst.list_hash, tx_h, self.accused.entity_id),
            proc.processed_violations,
        )

        stake_before = self.chain.supply.staked[self.accused.entity_id]
        burned_before = self.chain.supply.total_burned

        # Call process() directly — block-wiring is exercised by a
        # separate test below.
        from messagechain.consensus.inclusion_list import (
            process_inclusion_list_violation,
        )
        result = process_inclusion_list_violation(etx, self.chain)
        self.assertTrue(result.accepted, result.reason)
        self.assertTrue(result.slashed)

        stake_after = self.chain.supply.staked[self.accused.entity_id]
        burned_after = self.chain.supply.total_burned
        expected = compute_violation_slash_amount(stake_before)
        self.assertEqual(stake_before - stake_after, expected)
        self.assertGreaterEqual(burned_after - burned_before, expected)
        self.assertIn(
            (lst.list_hash, tx_h, self.accused.entity_id),
            proc.processed_violations,
        )

    def test_double_slash_prevented(self):
        tx_h = _h(b"dbl-tx")
        lst = self._build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            self.submitter, lst, tx_h,
            self.accused.entity_id, accused_height=12,
        )
        from messagechain.consensus.inclusion_list import (
            process_inclusion_list_violation,
        )
        first = process_inclusion_list_violation(etx, self.chain)
        self.assertTrue(first.accepted)
        self.assertTrue(first.slashed)
        stake_mid = self.chain.supply.staked[self.accused.entity_id]

        second = process_inclusion_list_violation(etx, self.chain)
        self.assertFalse(second.accepted)
        self.assertFalse(second.slashed)
        self.assertEqual(
            self.chain.supply.staked[self.accused.entity_id], stake_mid,
        )

    def test_snapshot_roundtrip_preserves_processor(self):
        """serialize_state + decode_snapshot + load_snapshot_dict
        preserves the processor's processed_violations set bit-for-bit."""
        tx_h = _h(b"sr-tx")
        lst = self._build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            self.submitter, lst, tx_h,
            self.accused.entity_id, accused_height=12,
        )
        from messagechain.consensus.inclusion_list import (
            process_inclusion_list_violation,
        )
        process_inclusion_list_violation(etx, self.chain)
        self.chain.inclusion_list_processor.register(lst, current_height=11)

        from messagechain.storage.state_snapshot import (
            serialize_state, encode_snapshot, decode_snapshot,
        )
        snap = serialize_state(self.chain)
        blob = encode_snapshot(snap)
        restored = decode_snapshot(blob)

        # Processor-state-related keys survive.
        self.assertIn("inclusion_list_processed_violations", restored)
        self.assertIn("inclusion_list_active", restored)
        # processed_violations is encoded as a bytes set whose entries
        # are (list_hash || tx_hash || proposer_id) concatenations —
        # a single 96-byte blob per violation (v12+; pre-v12 used
        # 64-byte entries without list_hash).
        self.assertIn(
            lst.list_hash + tx_h + self.accused.entity_id,
            restored["inclusion_list_processed_violations"],
        )
        self.assertIn(
            lst.publish_height,
            restored["inclusion_list_active"],
        )

        # Round-trip into a fresh blockchain and verify the processor
        # state reconstitutes correctly.
        from messagechain.core.blockchain import Blockchain
        chain2 = Blockchain()
        chain2._install_state_snapshot(restored)
        self.assertIn(
            (lst.list_hash, tx_h, self.accused.entity_id),
            chain2.inclusion_list_processor.processed_violations,
        )
        self.assertIn(
            lst.publish_height,
            chain2.inclusion_list_processor.active_lists,
        )
        self.assertEqual(
            chain2.inclusion_list_processor.active_lists[
                lst.publish_height
            ].list_hash,
            lst.list_hash,
        )


if __name__ == "__main__":
    unittest.main()
