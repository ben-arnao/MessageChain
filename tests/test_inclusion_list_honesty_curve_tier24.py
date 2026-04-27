"""Tier 24: inclusion-list violations route through the honesty curve.

Pre-Tier-24, ``process_inclusion_list_violation`` always slashed at a
flat ``INCLUSION_VIOLATION_SLASH_BPS`` rate, BYPASSING the Tier 23
honesty curve.  That meant a long-tenured validator with a clean
record received the same slash as a fresh-validator first-offender,
contradicting the CLAUDE.md anchor "honest operators are insured
against accidents".

Tier 24 fixes this: at/after ``HONESTY_CURVE_RATE_HEIGHT``, inclusion-
list violations consult ``slashing_severity`` with
``OffenseKind.INCLUSION_LIST_VIOLATION`` + ``Unambiguity.UNAMBIGUOUS``.
Below activation: byte-identical to pre-fork (flat BPS).

Tests pin:
  * Pre-activation: flat BPS path, byte-identical historical replay
  * Post-activation, fresh validator: 100% (UNAMBIGUOUS, no track)
  * Post-activation, long-tenured first offender: capped at
    UNAMBIGUOUS_FIRST_PCT (default 50%)
  * Post-activation, repeat offender: 100% (UNAMBIGUOUS_FIRST_PCT
    only applies on first offense)
  * Post-activation: slash_offense_counts incremented so subsequent
    severity calls see the violation
"""

import hashlib
import time
import unittest

from tests import register_entity_for_test
from messagechain.config import (
    HASH_ALGO,
    HONESTY_CURVE_RATE_HEIGHT,
    HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT,
    HONESTY_CURVE_HONEST_TRACK_THRESHOLD,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_VIOLATION_SLASH_BPS,
    MIN_FEE,
)
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    InclusionListViolationEvidenceTx,
    aggregate_inclusion_list,
    build_attester_mempool_report,
    compute_violation_slash_amount,
    process_inclusion_list_violation,
)
from messagechain.core.blockchain import Blockchain
from messagechain.crypto.keys import Signature
from messagechain.identity.identity import Entity


PRE = HONESTY_CURVE_RATE_HEIGHT - 1
POST = HONESTY_CURVE_RATE_HEIGHT


def _h(data: bytes) -> bytes:
    return hashlib.new(HASH_ALGO, data).digest()


def _make_validators(n: int, tag: bytes = b"il24") -> list[Entity]:
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
) -> InclusionListViolationEvidenceTx:
    placeholder = Signature([], 0, [], b"", b"")
    tx = InclusionListViolationEvidenceTx(
        inclusion_list=inclusion_list,
        omitted_tx_hash=omitted_tx_hash,
        accused_proposer_id=accused_proposer_id,
        accused_height=accused_height,
        submitter_id=submitter.entity_id,
        timestamp=int(time.time()),
        fee=fee,
        signature=placeholder,
    )
    msg_hash = _h(tx._signable_data())
    tx.signature = submitter.keypair.sign(msg_hash)
    tx.tx_hash = tx._compute_hash()
    return tx


class _Setup:
    def __init__(self):
        validators = _make_validators(8, tag=b"il24")
        self.submitter = validators[0]
        self.accused = validators[1]
        self.attesters = validators[2:]
        self.stakes = _stakes(validators)

        self.chain = Blockchain()
        self.chain.initialize_genesis(self.submitter)
        for v in validators[1:]:
            register_entity_for_test(self.chain, v)
        for v in validators:
            self.chain.supply.balances[v.entity_id] = 10_000_000
            self.chain.supply.staked[v.entity_id] = 1_000_000

    def build_list(self, tx_hashes: list[bytes], publish_height: int):
        # Build a quorum of attester reports for the omitted txs.
        for v in self.attesters:
            v.keypair._next_leaf = 0
        target_h = publish_height - 1
        report_h = target_h - INCLUSION_LIST_WAIT_BLOCKS
        reports = [
            build_attester_mempool_report(
                v, report_height=report_h, tx_hashes=tx_hashes,
            )
            for v in self.attesters
        ]
        return aggregate_inclusion_list(
            reports=reports, stakes=self.stakes,
            publish_height=publish_height,
        )


class TestPreActivationFlatBPS(unittest.TestCase):
    """Pre-Tier-24: flat-BPS path, byte-identical to legacy."""

    def test_flat_slash_when_current_height_below_activation(self):
        s = _Setup()
        tx_h = _h(b"pre-tier24")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        stake_before = s.chain.supply.staked[s.accused.entity_id]
        result = process_inclusion_list_violation(
            etx, s.chain, current_height=PRE,
        )
        self.assertTrue(result.slashed)
        # Flat BPS — byte-identical to legacy compute_violation_slash_amount.
        expected = compute_violation_slash_amount(stake_before)
        self.assertEqual(result.slash_amount, expected)

    def test_no_current_height_falls_back_to_legacy(self):
        # Caller that omits current_height entirely (older test code,
        # legacy callers) gets the byte-identical legacy path so
        # historical replay remains stable.
        s = _Setup()
        tx_h = _h(b"no-height")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        stake_before = s.chain.supply.staked[s.accused.entity_id]
        result = process_inclusion_list_violation(etx, s.chain)
        self.assertEqual(
            result.slash_amount,
            compute_violation_slash_amount(stake_before),
        )


class TestPostActivationHonestyCurve(unittest.TestCase):
    """Post-Tier-24: severity is track-record-aware via slashing_severity."""

    def _force_chain_height(self, chain: Blockchain, h: int):
        # The honesty curve reads `blockchain.height` (a property).
        # Patch it to the test value via direct override.
        from unittest.mock import patch
        return patch.object(
            Blockchain, "height",
            new=property(lambda _: h),
        )

    def test_fresh_validator_first_offense_full_burn(self):
        # No track record → UNAMBIGUOUS path → 100% slash.
        s = _Setup()
        tx_h = _h(b"fresh-burn")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        stake_before = s.chain.supply.staked[s.accused.entity_id]
        with self._force_chain_height(s.chain, POST):
            result = process_inclusion_list_violation(
                etx, s.chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        # 100% of stake → entire stake burned.
        self.assertEqual(result.slash_amount, stake_before)
        self.assertEqual(s.chain.supply.staked[s.accused.entity_id], 0)

    def test_long_tenured_first_offender_at_unambiguous_floor(self):
        # Long track record + first offense → UNAMBIGUOUS_FIRST_PCT
        # band (default 50%).  Even a deliberate violation can't drop
        # below half-stake for a perfect-record validator.
        s = _Setup()
        # Give the accused a strong track record — well above
        # HONEST_TRACK_THRESHOLD.
        s.chain.proposer_sig_counts[s.accused.entity_id] = 1_000
        s.chain.reputation[s.accused.entity_id] = 5_000
        tx_h = _h(b"tenured-first")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        stake_before = s.chain.supply.staked[s.accused.entity_id]
        with self._force_chain_height(s.chain, POST):
            result = process_inclusion_list_violation(
                etx, s.chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        # Cap at UNAMBIGUOUS_FIRST_PCT — slash should be exactly that
        # fraction of stake.
        expected = (
            stake_before * HONESTY_CURVE_UNAMBIGUOUS_FIRST_PCT // 100
        )
        self.assertEqual(result.slash_amount, expected)
        # Strictly less than full-burn — track record relief applies.
        self.assertLess(result.slash_amount, stake_before)

    def test_repeat_offender_full_burn(self):
        # Long-tenured validator gets the FIRST_PCT band on offense 1.
        # Offense 2 (same validator) escalates to 100% — anchored
        # "no relief on repeat unambiguous misbehavior".
        s = _Setup()
        s.chain.proposer_sig_counts[s.accused.entity_id] = 1_000
        s.chain.reputation[s.accused.entity_id] = 5_000

        # Pre-bump the slash counter to simulate a prior offense
        # (without going through the full evidence-tx flow twice).
        s.chain.slash_offense_counts[s.accused.entity_id] = 1

        tx_h = _h(b"repeat-burn")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        stake_before = s.chain.supply.staked[s.accused.entity_id]
        with self._force_chain_height(s.chain, POST):
            result = process_inclusion_list_violation(
                etx, s.chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        # Repeat unambiguous offense → 100% slash, full burn.
        self.assertEqual(result.slash_amount, stake_before)

    def test_offense_counter_incremented(self):
        # Post-activation: a successful slash bumps slash_offense_
        # counts so subsequent severity calls see this violation in
        # both the escalation multiplier AND the rate-factor relief
        # erosion.
        s = _Setup()
        tx_h = _h(b"counter-bump")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        before = s.chain.slash_offense_counts.get(s.accused.entity_id, 0)
        with self._force_chain_height(s.chain, POST):
            result = process_inclusion_list_violation(
                etx, s.chain, current_height=POST,
            )
        self.assertTrue(result.slashed)
        after = s.chain.slash_offense_counts.get(s.accused.entity_id, 0)
        self.assertEqual(after - before, 1)

    def test_pre_activation_does_not_bump_offense_counter(self):
        # Byte-identity invariant: pre-activation behavior is
        # unchanged, including not-touching slash_offense_counts.
        s = _Setup()
        tx_h = _h(b"pre-counter")
        lst = s.build_list([tx_h], publish_height=11)
        etx = _sign_violation_evidence(
            s.submitter, lst, tx_h, s.accused.entity_id, 12,
        )
        before = s.chain.slash_offense_counts.get(s.accused.entity_id, 0)
        result = process_inclusion_list_violation(
            etx, s.chain, current_height=PRE,
        )
        self.assertTrue(result.slashed)
        after = s.chain.slash_offense_counts.get(s.accused.entity_id, 0)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
