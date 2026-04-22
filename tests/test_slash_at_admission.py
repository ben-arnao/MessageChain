"""Censorship slash is computed on stake-at-admission, not current stake.

Pre-fix gap: `_apply_censorship_slash` at blockchain.py:2467 read
`self.supply.staked.get(offender_id, 0)` at maturity time.  An
accused validator observing evidence admitted against them could
submit an `UnstakeTransaction` during the EVIDENCE_MATURITY_BLOCKS
window (~2.7h at 600s/block) to drain `staked` down to
VALIDATOR_MIN_STAKE.  At maturity, slash_amount = 10% of the
drained stake — roughly 6 orders of magnitude smaller than
intended.  Founder at 95M stake could reduce a ~9.5M-token slash
to ~10 tokens.

Fix: `_PendingEvidence` now stores `staked_at_admission`, captured
at CensorshipEvidenceTx apply time.  `_apply_censorship_slash` uses
that snapshot, capped at current `staked` (so we don't debit more
than actually exists — the unstaked portion already left `staked`
for `pending_unstakes`, which this slash path deliberately doesn't
touch).

These tests pin the snapshot semantics.
"""

from __future__ import annotations

import unittest

from messagechain.consensus.censorship_evidence import (
    CensorshipEvidenceProcessor,
    _PendingEvidence,
    MaturedEvidence,
    compute_slash_amount,
)


class TestPendingEvidenceSnapshotsStake(unittest.TestCase):
    """_PendingEvidence and the processor must capture admission-time
    stake.  Round-trips through serialize/deserialize."""

    def test_pending_evidence_carries_staked_at_admission(self):
        ev = _PendingEvidence(
            evidence_hash=b"\x01" * 32,
            offender_id=b"\x02" * 32,
            tx_hash=b"\x03" * 32,
            admitted_height=42,
            evidence_tx_hash=b"\x04" * 32,
            staked_at_admission=9_500_000,
        )
        self.assertEqual(ev.staked_at_admission, 9_500_000)

    def test_serialize_deserialize_round_trip_preserves_stake(self):
        ev = _PendingEvidence(
            evidence_hash=b"\xaa" * 32,
            offender_id=b"\xbb" * 32,
            tx_hash=b"\xcc" * 32,
            admitted_height=77,
            evidence_tx_hash=b"\xdd" * 32,
            staked_at_admission=12_345,
        )
        back = _PendingEvidence.deserialize(ev.serialize())
        self.assertEqual(back.staked_at_admission, 12_345)


class TestProcessorSubmitRecordsStake(unittest.TestCase):
    """`processor.submit()` must accept and store stake-at-admission."""

    def test_submit_accepts_and_stores_staked_at_admission(self):
        p = CensorshipEvidenceProcessor()
        ok = p.submit(
            evidence_hash=b"e" * 32,
            offender_id=b"o" * 32,
            tx_hash=b"t" * 32,
            admitted_height=50,
            evidence_tx_hash=b"E" * 32,
            staked_at_admission=1_000_000,
        )
        self.assertTrue(ok)
        self.assertEqual(
            p.pending[b"e" * 32].staked_at_admission, 1_000_000,
        )


class TestMatureCarriesSnapshotStake(unittest.TestCase):
    """`mature()` must propagate the admission-time stake into the
    `MaturedEvidence` so the slash-apply path never needs to look at
    current stake."""

    def test_mature_propagates_staked_at_admission(self):
        from messagechain.config import EVIDENCE_MATURITY_BLOCKS
        p = CensorshipEvidenceProcessor()
        p.submit(
            evidence_hash=b"e" * 32,
            offender_id=b"o" * 32,
            tx_hash=b"t" * 32,
            admitted_height=100,
            evidence_tx_hash=b"E" * 32,
            staked_at_admission=5_000_000,
        )
        # Not matured yet.
        self.assertEqual(
            p.mature(100 + EVIDENCE_MATURITY_BLOCKS - 1), [],
        )
        # Matured at admitted_height + EVIDENCE_MATURITY_BLOCKS.
        matured = p.mature(100 + EVIDENCE_MATURITY_BLOCKS)
        self.assertEqual(len(matured), 1)
        self.assertEqual(matured[0].staked_at_admission, 5_000_000)


class TestSlashUsesAdmissionStake(unittest.TestCase):
    """The attack: admission at stake=S, then unstake to floor,
    then mature.  Slash must equal compute_slash_amount(S), capped
    at current stake (so we don't over-debit)."""

    def test_slash_against_admission_stake_not_current(self):
        from messagechain.core.blockchain import Blockchain
        from messagechain.consensus.censorship_evidence import (
            EVIDENCE_MATURITY_BLOCKS as EMB,
        )
        chain = Blockchain()
        offender = b"off" + b"\x00" * 29
        # Set up the offender with 9.5M staked, then simulate the
        # exploit: a MaturedEvidence whose admission-time snapshot is
        # 9.5M but whose current stake has been unstaked to 100.
        chain.supply.staked[offender] = 100  # drained via unstake
        chain.supply.total_supply = 1_000_000_000
        chain.supply.total_burned = 0

        matured = MaturedEvidence(
            evidence_hash=b"e" * 32,
            offender_id=offender,
            tx_hash=b"t" * 32,
            staked_at_admission=9_500_000,
        )
        # The test invariant: slash_amount = 10% of 9.5M, NOT 10% of 100.
        expected_full = compute_slash_amount(9_500_000)  # 950_000
        expected_current_cap = 100  # min(expected_full, current_stake)

        pre_burned = chain.supply.total_burned
        chain._apply_censorship_slash(matured)
        post_burned = chain.supply.total_burned

        # Post-fix: slash amount debited = min(admission_slash, current_stake).
        # Here current_stake=100 < 950k, so slash is capped at 100.
        # Pre-fix: slash_amount would have been 10% of CURRENT stake =
        # 10 tokens, making the burn 10 instead of 100 — that's the
        # bug this test pins.
        burned = post_burned - pre_burned
        self.assertEqual(
            burned, expected_current_cap,
            f"slash should cap at current_stake when admission-time "
            f"slash exceeds it; burned={burned}, expected={expected_current_cap}",
        )
        # Offender's staked must be drained to 0 in this case.
        self.assertEqual(chain.supply.staked.get(offender, 0), 0)

    def test_slash_uses_admission_stake_when_current_still_intact(self):
        """Common case: no unstake attack, stake unchanged between
        admission and maturity.  Slash = 10% of admission stake."""
        from messagechain.core.blockchain import Blockchain
        chain = Blockchain()
        offender = b"off2" + b"\x00" * 28
        chain.supply.staked[offender] = 1_000_000  # unchanged
        chain.supply.total_supply = 1_000_000_000
        chain.supply.total_burned = 0

        matured = MaturedEvidence(
            evidence_hash=b"e" * 32,
            offender_id=offender,
            tx_hash=b"t" * 32,
            staked_at_admission=1_000_000,
        )
        pre_burned = chain.supply.total_burned
        chain._apply_censorship_slash(matured)
        post_burned = chain.supply.total_burned

        expected = compute_slash_amount(1_000_000)  # 100_000
        self.assertEqual(post_burned - pre_burned, expected)
        self.assertEqual(
            chain.supply.staked.get(offender, 0), 1_000_000 - expected,
        )


if __name__ == "__main__":
    unittest.main()
