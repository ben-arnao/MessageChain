"""Audit r58 #3 (security top-3) -- three pre-r58 holes in the per-
block byte / sig budget compose into a CPU-DoS + permanent-bloat
surface that any proposer can exploit at sub-floor cost:

  * ``_validate_block_list_counts`` caps attestations / validator_
    signatures / governance / authority / censorship_evidence_txs
    -- but NOT non_response_evidence_txs, the per-NRE
    ``witness_observations`` list length, or
    ``inclusion_list.quorum_attestation`` bundle length.
  * ``compute_block_sig_cost`` amortises NRE at a constant ``3 ×
    n_txs`` regardless of observation count -- one NRE tx with
    10 000 ``witness_observations`` is counted as cost 3 even though
    it forces 10 001 WOTS+ verifies.
  * ``verify_inclusion_list_quorum`` silently SKIPs reports outside
    the wait window or with no overlap with any listed entry -- so
    a proposer can pad the bundle with garbage that's pinned forever
    on a chain whose headline promise is "your message can never be
    deleted".

CLAUDE.md anchors at risk:
  * High-Priority Concern: "Running a full node must stay accessible
    for centuries" -- a single crafted block burning minutes of WOTS+
    verification on every node breaks this for hobbyist hardware.
  * Principle #2 Permanence + censorship resistance: the chain-bloat
    lever is anchored as fees-only; padding via uncapped lists
    bypasses the fee market entirely.

Tier 81 (activation height ``NRE_QUORUM_LIST_CAPS_HEIGHT = 24500``):
  * ``MAX_OBSERVATIONS_PER_NRE_TX = 32``
  * ``MAX_NON_RESPONSE_EVIDENCE_TXS_PER_BLOCK = 16``
  * ``MAX_QUORUM_ATTESTATION_REPORTS = 200``
  * ``compute_block_sig_cost(block, current_height=…)`` post-fork
    counts NRE observations explicitly.
  * ``verify_inclusion_list_quorum(..., strict_no_padding=True)``
    hard-rejects stale + intersection-empty reports.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from messagechain.config import (
    MAX_OBSERVATIONS_PER_NRE_TX,
    MAX_NON_RESPONSE_EVIDENCE_TXS_PER_BLOCK,
    MAX_QUORUM_ATTESTATION_REPORTS,
    NRE_QUORUM_LIST_CAPS_HEIGHT,
    MULTI_KEY_RE_VERIFY_HEIGHT,
    INCLUSION_LIST_WAIT_BLOCKS,
    INCLUSION_LIST_WINDOW,
    WITNESS_QUORUM,
)
from messagechain.consensus.inclusion_list import (
    AttesterMempoolReport,
    InclusionList,
    InclusionListEntry,
    verify_inclusion_list_quorum,
)
from messagechain.core.blockchain import Blockchain, compute_block_sig_cost
from messagechain.crypto.keys import Signature


def _make_block_stub(**kwargs):
    """Build a minimal block-like stub with the lists / header that
    the validator + sig-cost functions read."""
    block_number = kwargs.pop("block_number", 0)
    header = SimpleNamespace(block_number=block_number)
    defaults = {
        "header": header,
        "transactions": [],
        "transfer_transactions": [],
        "slash_transactions": [],
        "governance_txs": [],
        "authority_txs": [],
        "stake_transactions": [],
        "unstake_transactions": [],
        "attestations": [],
        "finality_votes": [],
        "validator_signatures": [],
        "censorship_evidence_txs": [],
        "bogus_rejection_evidence_txs": [],
        "non_response_evidence_txs": [],
        "inclusion_list_violation_evidence_txs": [],
        "inclusion_list": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _placeholder_sig():
    return Signature([], 0, [], b"", b"")


def _stub_observation(witness_id_byte: int = 0):
    """Cheap WitnessObservation stub.  ``compute_block_sig_cost`` only
    looks at the LIST LENGTH, so the contents are irrelevant.  The
    per-block validator likewise only counts."""
    return SimpleNamespace(
        request_hash=b"\x00" * 32,
        witness_id=bytes([witness_id_byte]) * 32,
        observed_height=0,
        signature=_placeholder_sig(),
    )


def _stub_nre_tx(n_observations: int = WITNESS_QUORUM):
    return SimpleNamespace(
        witness_observations=[
            _stub_observation(i % 256) for i in range(n_observations)
        ],
    )


class TestTier81Constants(unittest.TestCase):
    def test_activation_height_follows_tier_80_by_cohort(self):
        self.assertEqual(NRE_QUORUM_LIST_CAPS_HEIGHT, 24500)
        self.assertGreater(
            NRE_QUORUM_LIST_CAPS_HEIGHT, MULTI_KEY_RE_VERIFY_HEIGHT,
        )
        self.assertEqual(
            NRE_QUORUM_LIST_CAPS_HEIGHT - MULTI_KEY_RE_VERIFY_HEIGHT,
            2000,
            "Tier 81 must follow Tier 80 by 2000 blocks "
            "(~13.9-day cohort spacing).",
        )

    def test_caps_are_at_anchored_shape(self):
        # NRE bomb defense: MAX_OBSERVATIONS_PER_NRE_TX must be tight
        # enough to make sig-cost bounded but accommodate honest
        # WITNESS_QUORUM-sized observations with redundancy.
        self.assertGreaterEqual(
            MAX_OBSERVATIONS_PER_NRE_TX, WITNESS_QUORUM,
        )
        self.assertLessEqual(
            MAX_OBSERVATIONS_PER_NRE_TX, 128,
            "Bomb defense: per-NRE obs cap must be tight enough that "
            "MAX_NRE_TXS * MAX_OBSERVATIONS doesn't dwarf the "
            "MAX_BLOCK_SIG_COST budget.",
        )
        # Per-block NRE tx count: peer of MAX_CENSORSHIP_EVIDENCE_TXS_PER_BLOCK.
        self.assertGreater(MAX_NON_RESPONSE_EVIDENCE_TXS_PER_BLOCK, 0)
        self.assertGreater(MAX_QUORUM_ATTESTATION_REPORTS, 0)


class TestSigCostCountsObservationsPostFork(unittest.TestCase):
    """Pre-fork (current_height < Tier 81 OR None): NRE amortised at
    constant 3 per tx (legacy).  Post-fork: each observation costs 1
    + 2 (submitter + client) per NRE tx -- a single 10 000-obs bomb
    no longer slips through as cost 3."""

    def test_legacy_path_is_constant_per_tx(self):
        block = _make_block_stub(
            non_response_evidence_txs=[_stub_nre_tx(n_observations=500)],
        )
        cost_legacy = compute_block_sig_cost(block, current_height=None)
        # Legacy: 3 per NRE tx, plus 1 proposer sig.
        self.assertEqual(cost_legacy, 3 + 1)

    def test_post_fork_counts_observations(self):
        block = _make_block_stub(
            non_response_evidence_txs=[_stub_nre_tx(n_observations=10)],
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        cost = compute_block_sig_cost(
            block, current_height=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        # Post-fork: len(obs) + 2 per NRE tx + 1 proposer.
        self.assertEqual(cost, 10 + 2 + 1)

    def test_bomb_attack_no_longer_cost_3(self):
        """The defect: a 10 000-observation bomb counted as cost 3
        pre-fork.  Post-fork it must reflect the real verify cost."""
        block = _make_block_stub(
            non_response_evidence_txs=[_stub_nre_tx(n_observations=10_000)],
        )
        cost_pre = compute_block_sig_cost(block, current_height=None)
        cost_post = compute_block_sig_cost(
            block, current_height=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        self.assertEqual(cost_pre, 3 + 1, "legacy: constant amortisation")
        self.assertEqual(
            cost_post, 10_000 + 2 + 1,
            "post-fork: real verify cost surfaces in the budget",
        )


class TestValidateBlockListCountsTier81(unittest.TestCase):
    """Per-block caps on NRE / observations / quorum_attestation are
    additive post-fork; pre-fork blocks replay byte-identically."""

    def setUp(self):
        self.chain = Blockchain()

    def test_pre_fork_accepts_uncapped_nre(self):
        """Pre-fork: arbitrarily many NRE txs / observations pass --
        documents the byte-identical legacy behaviour."""
        block = _make_block_stub(
            non_response_evidence_txs=[
                _stub_nre_tx(n_observations=1000)
                for _ in range(64)
            ],
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT - 1,
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertTrue(ok, reason)

    def test_post_fork_rejects_too_many_nre_txs(self):
        block = _make_block_stub(
            non_response_evidence_txs=[
                _stub_nre_tx(n_observations=WITNESS_QUORUM)
                for _ in range(MAX_NON_RESPONSE_EVIDENCE_TXS_PER_BLOCK + 1)
            ],
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("non_response_evidence_txs", reason)

    def test_post_fork_rejects_too_many_observations_per_nre(self):
        block = _make_block_stub(
            non_response_evidence_txs=[
                _stub_nre_tx(n_observations=MAX_OBSERVATIONS_PER_NRE_TX + 1),
            ],
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("witness_observations", reason)

    def test_post_fork_rejects_too_many_quorum_attestation_reports(self):
        # Build a stub inclusion_list with too many reports.
        reports = [
            AttesterMempoolReport(
                reporter_id=bytes([i]) * 32,
                report_height=0,
                tx_hashes=[],
                signature=_placeholder_sig(),
            )
            for i in range(MAX_QUORUM_ATTESTATION_REPORTS + 1)
        ]
        il = InclusionList(
            publish_height=1,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[],
            quorum_attestation=reports,
        )
        block = _make_block_stub(
            inclusion_list=il,
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertFalse(ok)
        self.assertIn("quorum_attestation", reason)

    def test_post_fork_at_cap_accepted(self):
        block = _make_block_stub(
            non_response_evidence_txs=[
                _stub_nre_tx(n_observations=MAX_OBSERVATIONS_PER_NRE_TX)
                for _ in range(MAX_NON_RESPONSE_EVIDENCE_TXS_PER_BLOCK)
            ],
            block_number=NRE_QUORUM_LIST_CAPS_HEIGHT + 1,
        )
        ok, reason = self.chain._validate_block_list_counts(block)
        self.assertTrue(ok, reason)


class TestInclusionListStrictNoPadding(unittest.TestCase):
    """``verify_inclusion_list_quorum(..., strict_no_padding=True)``
    rejects stale out-of-window reports AND reports whose tx_hashes
    share nothing with any listed entry."""

    def _build_minimal_list(self, target_tx: bytes, publish_height: int):
        return InclusionList(
            publish_height=publish_height,
            window_blocks=INCLUSION_LIST_WINDOW,
            entries=[
                InclusionListEntry(
                    tx_hash=target_tx, first_seen_height=publish_height - 1,
                ),
            ],
            quorum_attestation=[],
        )

    def test_stale_report_strict_rejects(self):
        """Out-of-window report: legacy silently skips, strict rejects."""
        target_tx = b"\xaa" * 32
        publish_height = 100
        # Out-of-window: report_height < publish_height -
        # INCLUSION_LIST_WAIT_BLOCKS = 96, so 90 is stale.
        stale_report = AttesterMempoolReport(
            reporter_id=b"\x01" * 32,
            report_height=publish_height - INCLUSION_LIST_WAIT_BLOCKS - 10,
            tx_hashes=[target_tx],
            signature=_placeholder_sig(),
        )
        lst = self._build_minimal_list(target_tx, publish_height)
        lst.quorum_attestation = [stale_report]

        stakes = {b"\x01" * 32: 1_000_000}
        public_keys = {b"\x01" * 32: b"\x00" * 32}

        # Legacy path: silently skips the stale report; the tally is
        # zero and the entry fails for quorum (different reason than
        # padding).
        ok_legacy, reason_legacy = verify_inclusion_list_quorum(
            lst, stakes=stakes, public_keys=public_keys,
        )
        self.assertFalse(ok_legacy)
        self.assertIn("quorum", reason_legacy.lower())

        # Strict path: hard rejects on the stale report before
        # tallying.
        ok_strict, reason_strict = verify_inclusion_list_quorum(
            lst, stakes=stakes, public_keys=public_keys,
            strict_no_padding=True,
        )
        self.assertFalse(ok_strict)
        self.assertIn("out-of-window", reason_strict.lower())

    def test_intersection_empty_report_strict_rejects(self):
        """A report whose tx_hashes share NOTHING with any listed
        entry is pure padding -- no honest aggregator emits one."""
        listed_tx = b"\xaa" * 32
        unrelated_tx = b"\xbb" * 32
        publish_height = 100
        padding_report = AttesterMempoolReport(
            reporter_id=b"\x01" * 32,
            report_height=publish_height - 1,
            tx_hashes=[unrelated_tx],
            signature=_placeholder_sig(),
        )
        lst = self._build_minimal_list(listed_tx, publish_height)
        lst.quorum_attestation = [padding_report]

        stakes = {b"\x01" * 32: 1_000_000}
        public_keys = {b"\x01" * 32: b"\x00" * 32}

        ok_strict, reason_strict = verify_inclusion_list_quorum(
            lst, stakes=stakes, public_keys=public_keys,
            strict_no_padding=True,
        )
        self.assertFalse(ok_strict)
        self.assertIn("padding", reason_strict.lower())


if __name__ == "__main__":
    unittest.main()
